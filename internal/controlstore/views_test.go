package controlstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/sessionscope"
)

func TestSessionIdentityIsStablePerExactScopeAndPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.sqlite")
	store, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	key := SessionKey{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	operationID, proof, err := store.Sessions().DeriveSessionTeardownIdentity(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if operationID == "" || len(proof) != sha256.Size {
		t.Fatalf("derived identity = %q, %x", operationID, proof)
	}
	other := key
	other.SessionChannelIDHash = "other-channel"
	otherOperationID, otherProof, err := store.Sessions().DeriveSessionTeardownIdentity(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if operationID == otherOperationID || bytes.Equal(proof, otherProof) {
		t.Fatal("different four-hash scopes derived the same identity")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedOperationID, reopenedProof, err := reopened.Sessions().DeriveSessionTeardownIdentity(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if operationID != reopenedOperationID || !bytes.Equal(proof, reopenedProof) {
		t.Fatal("session identity changed after control DB reopen")
	}
}

func TestSessionIdentityRejectsCorruptHostMetadata(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.db.ExecContext(ctx, `INSERT INTO control_metadata(key,value_json) VALUES(?,?)`, sessionIdentitySecretMetadataKey, `"too-short"`); err != nil {
		t.Fatal(err)
	}
	key := SessionKey{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	if _, _, err := store.Sessions().DeriveSessionTeardownIdentity(ctx, key); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("DeriveSessionTeardownIdentity() error = %v, want ErrStateConflict", err)
	}
}

func TestRegistryViewRejectsExternalInstallPersistenceBypass(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Registry()
	now := time.Unix(100, 0).UTC()
	record := externalControlRecord("plugin", "1.0.0", now)
	if _, err := view.UpdateExternalPackage(ctx, "env", registry.InstallExternalPackageRequest{Intent: registry.ExternalPackageInstall, Record: record, Now: now}); !errors.Is(err, registry.ErrInvalidExternalPackageInstall) {
		t.Fatalf("external install bypass error = %v, want ErrInvalidExternalPackageInstall", err)
	}
	if _, err := view.Get(ctx, "env", "plugin"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("rejected external install persisted state: %v", err)
	}
	var transientTables int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND (name LIKE '%inspection%' OR name LIKE '%receipt%' OR name LIKE '%stage%')`).Scan(&transientTables); err != nil {
		t.Fatal(err)
	}
	if transientTables != 0 {
		t.Fatalf("transient external-package state became durable: %d tables", transientTables)
	}
	var executionRows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM execution WHERE plugin_instance_id=?`, record.PluginInstanceID).Scan(&executionRows); err != nil {
		t.Fatal(err)
	}
	if executionRows != 0 {
		t.Fatalf("rejected external install created an activation execution: %d", executionRows)
	}
}

func TestRegistryViewPreservesCanonicalManifestAcrossDurableMutations(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Unix(100, 0).UTC()
	record := externalControlRecord("plugin", "9.0.0", now)
	manifestJSON := `{
  "schema_version": "redevplugin.manifest.v9",
  "publisher": {"publisher_id": "publisher", "display_name": "Publisher"},
  "plugin": {"plugin_id": "com.example", "display_name": "Example", "version": "9.0.0"},
  "api": {"major": 1, "required_features": ["fs.environment.v1", "net.http.v1"]},
  "permissions": ["fs.environment.read", "network.client"],
  "presentation": {"locales": {"default": "en-US"}},
  "surfaces": [{"surface_id": "main", "kind": "view", "label": "Main", "entry": "ui/index.html"}],
  "workers": [{"worker_id": "worker", "artifact": "workers/main.wasm", "mode": "job", "scope": "environment", "memory_limit_bytes": 16777216}],
  "methods": [{"method": "io.run", "route": {"kind": "worker", "worker_id": "worker"}, "effect": "execute", "execution": "sync", "request_schema": {"type": "object", "additionalProperties": false}, "response_schema": {"type": "object", "additionalProperties": false}}]
}`
	current, err := manifest.Decode(strings.NewReader(manifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := manifest.CanonicalJSON([]byte(manifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	record.Manifest = current
	record.CanonicalManifest = string(canonical)
	wantManifest := record.Manifest
	wantCanonical := record.CanonicalManifest

	shape, err := plugindata.ShapeFromManifest(record.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	shapeHash, err := plugindata.HashShape(shape)
	if err != nil {
		t.Fatal(err)
	}
	binding := plugindata.Binding{
		PluginInstanceID: record.PluginInstanceID,
		GenerationID:     "gen_manifest_projection",
		State:            plugindata.BindingActive,
		Revision:         1,
		ShapeHash:        shapeHash,
	}
	record, err = store.InstallCommit(pluginDataCatalogContext("env", "user"), record, nil, binding, shape, now)
	if err != nil {
		t.Fatal(err)
	}
	assertManifestEqual(t, record, wantManifest, wantCanonical)

	record, err = store.Registry().GetPlugin(ctx, "env", record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	assertManifestEqual(t, record, wantManifest, wantCanonical)
	var persisted string
	if err := store.db.QueryRowContext(ctx, `SELECT record_json FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=?`, "env", record.PluginInstanceID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if strings.Count(persisted, `"manifest":`) != 1 || strings.Contains(persisted, `"canonical_manifest"`) || strings.Contains(persisted, `"version_canonical_manifests"`) {
		t.Fatalf("record_json must persist one canonical manifest source: %s", persisted)
	}

	record, err = store.Registry().SetEnableState(ctx, "env", record.PluginInstanceID, registry.EnableEnabled, "", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	assertManifestEqual(t, record, wantManifest, wantCanonical)

	authorization, err := store.Registry().GetAuthorization(ctx, "env", record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	assertManifestEqual(t, authorization.Plugin, wantManifest, wantCanonical)
}

func TestDecodeRegistryPluginRecordRejectsUnknownCurrentFields(t *testing.T) {
	record := externalControlRecord("plugin_strict", "1.0.0", time.Unix(100, 0).UTC())
	raw, err := encodeRegistryPluginRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["legacy_activation"] = true
	tampered, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRegistryPluginRecord(tampered); err == nil || !strings.Contains(err.Error(), `unknown field "legacy_activation"`) {
		t.Fatalf("decode unknown field error = %v", err)
	}
}

func assertManifestEqual(t *testing.T, record registry.PluginRecord, want manifest.Manifest, wantCanonical string) {
	t.Helper()
	if !reflect.DeepEqual(record.Manifest, want) {
		t.Fatalf("manifest = %#v, want %#v", record.Manifest, want)
	}
	if record.CanonicalManifest != wantCanonical {
		t.Fatalf("canonical manifest = %q, want %q", record.CanonicalManifest, wantCanonical)
	}
}

func TestControlStoreSourceHasNoExternalInstallActivationLifecycle(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "views.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	retiredTypes := map[string]bool{
		"ExternalInstallActivation":        true,
		"ExternalInstallActivationRequest": true,
		"externalInstallActivationPayload": true,
	}
	retiredMethods := map[string]bool{
		"InstallExternalPackageWithActivation":  true,
		"ListPendingExternalInstallActivations": true,
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.TypeSpec:
			if retiredTypes[value.Name.Name] {
				t.Errorf("control store still declares retired type %s", value.Name.Name)
			}
		case *ast.FuncDecl:
			if retiredMethods[value.Name.Name] {
				t.Errorf("control store still declares retired method %s", value.Name.Name)
			}
		case *ast.BasicLit:
			if value.Kind != token.STRING {
				break
			}
			literal, unquoteErr := strconv.Unquote(value.Value)
			if unquoteErr == nil && strings.Contains(literal, "external_install_activation") {
				t.Errorf("control store still persists retired external activation payload %q", literal)
			}
		}
		return true
	})
}

func externalControlRecord(instanceID, version string, now time.Time) registry.PluginRecord {
	currentManifest := manifest.Manifest{
		SchemaVersion: manifest.SchemaVersionV9,
		Publisher:     manifest.Publisher{PublisherID: "publisher", DisplayName: "Publisher"},
		Plugin:        manifest.Plugin{PluginID: "com.example", DisplayName: "Example", Version: version},
		API:           manifest.PublicAPIRequirement{Major: 1, RequiredFeatures: []manifest.FeatureID{}, OptionalFeatures: []manifest.FeatureID{}},
		Permissions:   []manifest.PermissionID{},
		Presentation: manifest.PresentationSpec{
			DefaultLocale: "en-US", Summary: "Example", Description: []string{"Example plugin"},
			Highlights: []string{}, Keywords: []string{"example"}, Localizations: []manifest.PresentationLocalizationSpec{},
		},
		Surfaces: []manifest.SurfaceSpec{{
			SurfaceID: "main", Kind: manifest.SurfaceView, Label: "Main", Entry: "ui/index.html",
		}},
		Workers: []manifest.WorkerSpec{},
		Methods: []manifest.MethodSpec{},
	}
	return registry.PluginRecord{
		PluginInstanceID: instanceID, PublisherID: "publisher", PluginID: "com.example", Version: version,
		ActiveFingerprint: "sha256:fingerprint", PackageHash: "sha256:package", ManifestHash: "sha256:manifest", EntriesHash: "sha256:entries",
		TrustState: registry.TrustUntrusted, EnableState: registry.EnableEnabled,
		Manifest:                currentManifest,
		SignatureAssessment:     registry.SignatureAssessment{Status: registry.SignatureAbsent, PackageSHA256: "sha256:package", ManifestSHA256: "sha256:manifest", EntriesSHA256: "sha256:entries", AssessedHashes: registry.TrustHashSet{PackageSHA256: "sha256:package", ManifestSHA256: "sha256:manifest", EntriesSHA256: "sha256:entries"}},
		PackageSourceProvenance: registry.PackageSourceProvenance{Kind: registry.PackageSourcePackageURL, SourceURL: "https://plugins.example.test/p", FinalURL: "https://plugins.example.test/p", PackageSHA256: "sha256:package", RetrievedAt: now},
		ExecutionApproval:       registry.ExecutionApproval{Status: registry.ExecutionApprovalUserApproved, OwnerEnvHash: "env", PackageSHA256: "sha256:package", ApprovedAt: now, AssessedAt: now},
		UpdateEligibility:       registry.UpdateManualOnly,
	}
}

func TestViewsShareOneControlDatabaseAndGeneration(t *testing.T) {
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry, executions := store.Registry(), store.Executions()
	confirmations, sessions := store.Confirmations(), store.Sessions()
	if registry.store != store || executions.store != store || confirmations.store != store || sessions.store != store {
		t.Fatal("a view does not use the owning control store")
	}
	if registry.store.db != executions.store.db || registry.Generation() != store.Generation() || confirmations.Generation() != store.Generation() || sessions.Generation() != store.Generation() {
		t.Fatal("views do not share one DB handle and generation")
	}
}

func TestRegistryInstallAndGrantsCommitAtomically(t *testing.T) {
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Registry()
	install := PluginInstall{
		Record: PluginRecord{OwnerEnvHash: "env", PluginInstanceID: "plugin", PublisherID: "publisher", PluginID: "com.example", Version: "1.0.0", ActiveFingerprint: "sha256:fingerprint", PackageSHA256: "sha256:package", ManifestSHA256: "sha256:manifest", EntriesSHA256: "sha256:entries", State: "enabled", PolicyRevision: 2, ManagementRevision: 3, RevokeEpoch: 4, InstalledAt: 10, UpdatedAt: 11, RawJSON: json.RawMessage(`{"manifest":{"schema_version":"redevplugin.manifest.v9"},"management_revision":3}`)},
		Grants: []Grant{{CapabilityID: "documents.read", Revision: 2, RawJSON: json.RawMessage(`{"permission_id":"documents.read","effect":"allow"}`)}},
	}
	if err := view.Install(context.Background(), install); err != nil {
		t.Fatal(err)
	}
	got, err := view.Get(context.Background(), "env", "plugin")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, string(got.Record.RawJSON), string(install.Record.RawJSON))
	assertJSONEqual(t, string(got.Grants[0].RawJSON), string(install.Grants[0].RawJSON))

	broken := install
	broken.Record.PluginInstanceID = "broken"
	broken.Grants = []Grant{{CapabilityID: "duplicate", Revision: 2, RawJSON: json.RawMessage(`{"id":1}`)}, {CapabilityID: "duplicate", Revision: 2, RawJSON: json.RawMessage(`{"id":2}`)}}
	if err := view.Install(context.Background(), broken); err == nil {
		t.Fatal("Install() accepted duplicate grants")
	}
	if _, err := view.Get(context.Background(), "env", "broken"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("partial install remained after rollback: %v", err)
	}
}

func TestRegistryAuthorizationCASUpdatesCanonicalRecordAndRelations(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Registry()
	record := PluginRecord{OwnerEnvHash: "env", PluginInstanceID: "plugin", PluginID: "com.example", Version: "1", State: "enabled", PolicyRevision: 1, RawJSON: json.RawMessage(`{"policy_revision":1}`)}
	if err := view.Install(ctx, PluginInstall{Record: record}); err != nil {
		t.Fatal(err)
	}
	record.PolicyRevision = 2
	record.RawJSON = json.RawMessage(`{"policy_revision":2,"permissions":["read"]}`)
	grant := Grant{CapabilityID: "read", Revision: 2, RawJSON: json.RawMessage(`{"permission_id":"read"}`)}
	expected := registry.AuthorizationRevisions{PolicyRevision: 1, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch}
	if err := view.ReplaceAuthorization(ctx, record, expected, []Grant{grant}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := view.Get(ctx, "env", "plugin")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, string(got.Record.RawJSON), string(record.RawJSON))
	if got.Record.PolicyRevision != 2 || len(got.Grants) != 1 || got.Grants[0].Revision != 2 {
		t.Fatalf("authorization snapshot = %#v", got)
	}
	if err := view.ReplaceAuthorization(ctx, record, expected, nil, nil); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale CAS error = %v", err)
	}
}

func TestRegistryAuthorizationCASRejectsConcurrentManagementAndRevokeChanges(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Registry()
	base := PluginRecord{OwnerEnvHash: "env", PluginInstanceID: "plugin", PluginID: "com.example", Version: "1", State: "enabled", PolicyRevision: 1, ManagementRevision: 2, RevokeEpoch: 3, RawJSON: json.RawMessage(`{"policy_revision":1,"management_revision":2,"revoke_epoch":3}`)}
	if err := view.Install(ctx, PluginInstall{Record: base}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		expected registry.AuthorizationRevisions
	}{
		{name: "management", expected: registry.AuthorizationRevisions{PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 3}},
		{name: "revoke", expected: registry.AuthorizationRevisions{PolicyRevision: 1, ManagementRevision: 2, RevokeEpoch: 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := base
			next.PolicyRevision = 2
			next.RawJSON = json.RawMessage(`{"policy_revision":2,"management_revision":2,"revoke_epoch":3}`)
			if err := view.ReplaceAuthorization(ctx, next, test.expected, nil, nil); !errors.Is(err, ErrRevisionConflict) {
				t.Fatalf("ReplaceAuthorization() error = %v, want revision conflict", err)
			}
			got, err := view.Get(ctx, "env", "plugin")
			if err != nil {
				t.Fatal(err)
			}
			if got.Record.PolicyRevision != 1 || got.Record.ManagementRevision != 2 || got.Record.RevokeEpoch != 3 {
				t.Fatalf("stale CAS changed record = %#v", got.Record)
			}
		})
	}
}

func TestExecutionViewPersistsStrictCursorCancelAndTerminal(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Executions()
	now := time.Unix(20, 0).UTC()
	if err := view.Create(ctx, execution.Execution{ID: "invalid", PluginInstanceID: "plugin", Kind: execution.KindOperation, Status: execution.StatusCompleted}); !errors.Is(err, execution.ErrInvalidTransition) {
		t.Fatalf("Create(terminal) error = %v", err)
	}
	if err := view.Create(ctx, execution.Execution{ID: "exec", PluginInstanceID: "plugin", Kind: execution.KindOperation, Status: execution.StatusRunning, Cancelable: true, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := view.RequestCancel(ctx, "exec", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	terminal := execution.Event{ExecutionID: "exec", Sequence: 1, Kind: execution.EventTerminal, Payload: map[string]any{"status": execution.StatusCanceled}}
	if err := view.Append(ctx, terminal); !errors.Is(err, execution.ErrInvalidTransition) {
		t.Fatalf("Append(terminal) error = %v", err)
	}
	if err := view.Finish(ctx, "exec", execution.StatusCanceled, "", terminal, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := view.Append(ctx, execution.Event{ExecutionID: "exec", Sequence: 2, Kind: execution.EventData}); !errors.Is(err, execution.ErrTerminal) {
		t.Fatalf("append after terminal error = %v", err)
	}
	got, err := view.Get(ctx, "exec")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != execution.StatusCanceled || got.Cursor != 1 || got.CancelRequestedAt == nil || got.TerminalAt == nil {
		t.Fatalf("execution = %#v", got)
	}
	events, err := view.EventsAfter(ctx, "exec", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != execution.EventTerminal {
		t.Fatalf("events = %#v", events)
	}
}

func TestReleaseInstallPayloadDefersIdentityStateAndCursorToExecution(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Executions()
	now := time.Unix(20, 0).UTC()
	request := registry.StartReleaseInstallOperationRequest{
		RequestID: "request_install", ExecutionID: "execution_install", PluginInstanceID: "plugin_install",
		ManifestSHA256: "sha256:" + strings.Repeat("c", 64), ContractSetSHA256: "sha256:" + strings.Repeat("b", 64), SummarySHA256: "sha256:" + strings.Repeat("d", 64),
		Release: registry.ReleaseInstallIdentity{
			SourceID: "official", Channel: "stable", ReleaseMetadataRef: "release.json",
			ReleaseMetadataSHA256: strings.Repeat("a", 64), PublisherID: "publisher", PluginID: "plugin", Version: "1.0.0",
			PackageSHA256: "sha256:" + strings.Repeat("b", 64), ManifestSHA256: "sha256:" + strings.Repeat("c", 64), EntriesSHA256: "sha256:" + strings.Repeat("d", 64),
		},
		Now: now,
	}
	request.ReleaseIdentityDigest, err = registry.ReleaseInstallIdentitySHA256(request.Release)
	if err != nil {
		t.Fatal(err)
	}
	owner := ExecutionOwner{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	started, created, err := view.StartReleaseInstall(ctx, owner, request)
	if err != nil || !created {
		t.Fatalf("StartReleaseInstall() = %#v, %t, %v", started, created, err)
	}
	replayed, created, err := view.StartReleaseInstall(ctx, owner, request)
	if err != nil || created || replayed.Execution.ID != started.Execution.ID {
		t.Fatalf("idempotent StartReleaseInstall() = %#v, %t, %v", replayed, created, err)
	}
	conflicting := request
	conflicting.ExecutionID = "execution_install_conflict"
	conflicting.SummarySHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, _, err := view.StartReleaseInstall(ctx, owner, conflicting); !errors.Is(err, registry.ErrReleaseInstallOperationConflict) {
		t.Fatalf("conflicting request replay error = %v", err)
	}
	otherOwner := owner
	otherOwner.OwnerSessionHash = "other_session"
	otherOwner.OwnerUserHash = "other_user"
	otherOwner.OwnerEnvHash = "other_env"
	otherOwner.SessionChannelIDHash = "other_channel"
	otherRequest := request
	otherRequest.ExecutionID = "execution_install_other_owner"
	if _, created, err := view.StartReleaseInstall(ctx, otherOwner, otherRequest); err != nil || !created {
		t.Fatalf("other-owner StartReleaseInstall() created=%t, err=%v", created, err)
	}
	var raw string
	if err := store.db.QueryRowContext(ctx, `SELECT operation_json FROM execution WHERE execution_id=?`, request.ExecutionID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Operation map[string]json.RawMessage `json:"operation"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, `"activation"`) || strings.Contains(raw, `"activation_request"`) {
		t.Errorf("release-install payload still persists activation state: %s", raw)
	}
	for _, retired := range []string{"execution_id", "operation_id", "status", "cursor", "terminal_at", "revision", "created_at", "updated_at"} {
		if _, exists := payload.Operation[retired]; exists {
			t.Errorf("release-install domain payload mirrors execution field %q: %s", retired, raw)
		}
	}
	updated, err := view.UpdateReleaseInstall(ctx, owner.OwnerEnvHash, registry.UpdateReleaseInstallOperationRequest{
		ExecutionID: request.ExecutionID, ExpectedCursor: started.Execution.Cursor, Status: execution.StatusRunning,
		Phase: "download_package", Progress: registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressBytes, Completed: 1, Total: 2},
		Attempt: 1, MutationOutcome: "not_committed", Now: now.Add(time.Second),
	})
	if err != nil || updated.Execution.Cursor != 1 {
		t.Fatalf("UpdateReleaseInstall() = %#v, %v", updated, err)
	}
	_, err = view.UpdateReleaseInstall(ctx, owner.OwnerEnvHash, registry.UpdateReleaseInstallOperationRequest{
		ExecutionID: request.ExecutionID, ExpectedCursor: 0, Status: execution.StatusRunning,
		Phase: "verify_hashes", Progress: registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressIndeterminate},
		Attempt: 1, MutationOutcome: "not_committed", Now: now.Add(2 * time.Second),
	})
	if !errors.Is(err, registry.ErrReleaseInstallOperationConflict) {
		t.Fatalf("stale cursor update error = %v", err)
	}
	record := registry.PluginRecord{PluginInstanceID: request.PluginInstanceID, EnableState: registry.EnableEnabled}
	completed, err := view.UpdateReleaseInstall(ctx, owner.OwnerEnvHash, registry.UpdateReleaseInstallOperationRequest{
		ExecutionID: request.ExecutionID, ExpectedCursor: updated.Execution.Cursor, Status: execution.StatusCompleted,
		Phase: "complete", Progress: registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressItems, Completed: 1, Total: 1},
		Attempt: 1, MutationOutcome: "committed", PluginRecord: &record, Now: now.Add(3 * time.Second),
	})
	if err != nil || completed.Execution.Status != execution.StatusCompleted || completed.PluginRecord == nil || completed.PluginRecord.EnableState != registry.EnableEnabled {
		t.Fatalf("completed release install = %#v, %v", completed, err)
	}
	events, err := view.EventsAfter(ctx, request.ExecutionID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Kind != execution.EventProgress || events[1].Kind != execution.EventTerminal {
		t.Fatalf("release-install event envelope = %#v", events)
	}
}

func TestExecutionViewReconcilesOrphansWithoutChangingTerminalRecords(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Executions()
	createdAt := time.Unix(20, 0).UTC()
	for _, value := range []execution.Execution{
		{ID: "running", PluginInstanceID: "plugin", Kind: execution.KindOperation, Cancelable: true, CreatedAt: createdAt},
		{ID: "cancel-requested", PluginInstanceID: "plugin", Kind: execution.KindSubscription, Cancelable: true, CreatedAt: createdAt},
		{ID: "completed", PluginInstanceID: "plugin", Kind: execution.KindOperation, CreatedAt: createdAt},
	} {
		if err := view.Create(ctx, value); err != nil {
			t.Fatal(err)
		}
	}
	releaseIdentity := registry.ReleaseInstallIdentity{
		SourceID: "official", Channel: "stable", ReleaseMetadataRef: "release.json",
		ReleaseMetadataSHA256: strings.Repeat("a", 64), PublisherID: "publisher", PluginID: "plugin", Version: "1.0.0",
		PackageSHA256: "sha256:" + strings.Repeat("b", 64), ManifestSHA256: "sha256:" + strings.Repeat("c", 64), EntriesSHA256: "sha256:" + strings.Repeat("d", 64),
	}
	releaseDigest, err := registry.ReleaseInstallIdentitySHA256(releaseIdentity)
	if err != nil {
		t.Fatal(err)
	}
	internalOwner := ExecutionOwner{
		OwnerSessionHash: "internal_unowned", OwnerUserHash: "internal_unowned",
		OwnerEnvHash: "internal_unowned", SessionChannelIDHash: "internal_unowned",
	}
	if _, _, err := view.StartReleaseInstall(ctx, internalOwner, registry.StartReleaseInstallOperationRequest{
		RequestID: "request_interrupted", ExecutionID: "release-interrupted", PluginInstanceID: "plugin",
		ReleaseIdentityDigest: releaseDigest, ManifestSHA256: releaseIdentity.ManifestSHA256,
		ContractSetSHA256: "sha256:" + strings.Repeat("e", 64), SummarySHA256: "sha256:" + strings.Repeat("f", 64),
		Release: releaseIdentity, Now: createdAt,
	}); err != nil {
		t.Fatal(err)
	}
	if err := view.RequestCancel(ctx, "cancel-requested", createdAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	completed, err := view.Get(ctx, "completed")
	if err != nil {
		t.Fatal(err)
	}
	completedEvent, err := execution.NewEvent(completed, 1, execution.EventTerminal, map[string]any{"status": execution.StatusCompleted})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Finish(ctx, completed.ID, execution.StatusCompleted, "", completedEvent, createdAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}

	now := createdAt.Add(3 * time.Second)
	result, err := view.ReconcileOrphans(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Orphaned != 1 || result.Canceled != 1 || result.Interrupted != 1 {
		t.Fatalf("ReconcileOrphans() = %#v", result)
	}
	for id, wantStatus := range map[string]string{
		"running": execution.StatusOrphaned, "cancel-requested": execution.StatusCanceled,
		"completed": execution.StatusCompleted, "release-interrupted": execution.StatusFailed,
	} {
		got, err := view.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != wantStatus || got.Cursor != 1 || got.TerminalAt == nil {
			t.Fatalf("execution %s = %#v, want status %s", id, got, wantStatus)
		}
		events, err := view.EventsAfter(ctx, id, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 || events[0].Kind != execution.EventTerminal || events[0].Payload["status"] != wantStatus {
			t.Fatalf("execution %s events = %#v", id, events)
		}
		if id == "release-interrupted" {
			progress, ok := events[0].Payload["install_progress"].(map[string]any)
			if !ok || progress["failure_code"] != string(security.ErrInstallInterrupted) || progress["retryable"] != true {
				t.Fatalf("release install interruption progress = %#v", progress)
			}
		}
	}
	second, err := view.ReconcileOrphans(ctx, now.Add(time.Second))
	if err != nil || second.Orphaned != 0 || second.Canceled != 0 || second.Interrupted != 0 {
		t.Fatalf("ReconcileOrphans(retry) = %#v, %v", second, err)
	}
}

func TestExecutionViewPrunesTerminalRecordsAndEventsByRetention(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Executions()
	base := time.Unix(1_000, 0).UTC()
	finish := func(id, plugin string, terminalAt time.Time) {
		t.Helper()
		if err := view.Create(ctx, execution.Execution{ID: id, PluginInstanceID: plugin, Kind: execution.KindOperation, CreatedAt: terminalAt.Add(-time.Second)}); err != nil {
			t.Fatal(err)
		}
		current, err := view.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		event, err := execution.NewEvent(current, 1, execution.EventTerminal, map[string]any{"status": execution.StatusCompleted})
		if err != nil {
			t.Fatal(err)
		}
		if err := view.Finish(ctx, id, execution.StatusCompleted, "", event, terminalAt); err != nil {
			t.Fatal(err)
		}
	}
	finish("old", "plugin-a", base.Add(-10*time.Hour))
	finish("overflow", "plugin-a", base.Add(-2*time.Hour))
	finish("newest", "plugin-a", base.Add(-time.Hour))
	finish("other-plugin", "plugin-b", base.Add(-2*time.Hour))
	if err := view.Create(ctx, execution.Execution{ID: "running", PluginInstanceID: "plugin-a", Kind: execution.KindOperation, CreatedAt: base}); err != nil {
		t.Fatal(err)
	}

	result, err := view.PruneTerminal(ctx, ExecutionPruneRequest{Before: base.Add(-5 * time.Hour), Limit: 1, MaxTerminalRecordsPerPlugin: 2})
	if err != nil || result.Deleted != 1 {
		t.Fatalf("PruneTerminal(first) = %#v, %v", result, err)
	}
	if _, err := view.Get(ctx, "old"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old execution remains: %v", err)
	}
	var oldEvents int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM execution_events WHERE execution_id='old'`).Scan(&oldEvents); err != nil || oldEvents != 0 {
		t.Fatalf("old execution events = %d, %v", oldEvents, err)
	}
	result, err = view.PruneTerminal(ctx, ExecutionPruneRequest{Before: base.Add(-5 * time.Hour), Limit: 10, MaxTerminalRecordsPerPlugin: 1})
	if err != nil || result.Deleted != 1 {
		t.Fatalf("PruneTerminal(overflow) = %#v, %v", result, err)
	}
	for _, id := range []string{"newest", "other-plugin", "running"} {
		if _, err := view.Get(ctx, id); err != nil {
			t.Fatalf("preserved execution %s error = %v", id, err)
		}
	}
}

func TestExecutionViewReconcileOrphansRollsBackAtomically(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Executions()
	for _, id := range []string{"first", "second"} {
		if err := view.Create(ctx, execution.Execution{ID: id, PluginInstanceID: "plugin", Kind: execution.KindOperation}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_second_reconcile BEFORE UPDATE ON execution WHEN NEW.execution_id='second' BEGIN SELECT RAISE(ABORT, 'injected reconcile failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := view.ReconcileOrphans(ctx, time.Now().UTC()); err == nil {
		t.Fatal("ReconcileOrphans() succeeded despite injected failure")
	}
	for _, id := range []string{"first", "second"} {
		got, err := view.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != execution.StatusRunning || got.Cursor != 0 || got.TerminalAt != nil {
			t.Fatalf("execution %s changed after rollback: %#v", id, got)
		}
		events, err := view.EventsAfter(ctx, id, 0, 10)
		if err != nil || len(events) != 0 {
			t.Fatalf("execution %s events after rollback = %#v, %v", id, events, err)
		}
	}
}

func TestExecutionViewPruneTerminalRollsBackAtomically(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Executions()
	now := time.Now().UTC()
	for _, id := range []string{"first", "second"} {
		if err := view.Create(ctx, execution.Execution{ID: id, PluginInstanceID: "plugin", Kind: execution.KindOperation, CreatedAt: now.Add(-2 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
		current, err := view.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		event, err := execution.NewEvent(current, 1, execution.EventTerminal, map[string]any{"status": execution.StatusCompleted})
		if err != nil {
			t.Fatal(err)
		}
		if err := view.Finish(ctx, id, execution.StatusCompleted, "", event, now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_second_prune BEFORE DELETE ON execution WHEN OLD.execution_id='second' BEGIN SELECT RAISE(ABORT, 'injected prune failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := view.PruneTerminal(ctx, ExecutionPruneRequest{Before: now, Limit: 10, MaxTerminalRecordsPerPlugin: 100}); err == nil {
		t.Fatal("PruneTerminal() succeeded despite injected failure")
	}
	for _, id := range []string{"first", "second"} {
		if _, err := view.Get(ctx, id); err != nil {
			t.Fatalf("execution %s was partially deleted: %v", id, err)
		}
		events, err := view.EventsAfter(ctx, id, 0, 10)
		if err != nil || len(events) != 1 {
			t.Fatalf("execution %s events after rollback = %#v, %v", id, events, err)
		}
	}
}

func TestConfirmationAndSessionViewsRoundTripCanonicalJSON(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	confirmation := Confirmation{ID: "confirm", PluginInstanceID: "plugin", OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel", Status: "pending", ExpiresAt: 30, RawJSON: json.RawMessage(`{"confirmation_id":"confirm","scope":{"policy_revision":7}}`)}
	if err := store.Confirmations().Put(ctx, confirmation); err != nil {
		t.Fatal(err)
	}
	gotConfirmation, err := store.Confirmations().Get(ctx, "confirm")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, string(gotConfirmation.RawJSON), string(confirmation.RawJSON))
	revocation := ConfirmationRevocation{SessionKey: SessionKey{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}, TeardownOperationID: "teardown", RawJSON: json.RawMessage(`{"teardown_operation_id":"teardown"}`)}
	if count, err := store.Confirmations().RevokeSession(ctx, revocation); err != nil || count != 1 {
		t.Fatalf("RevokeSession() = %d, %v", count, err)
	}
	if count, err := store.Confirmations().RevokeSession(ctx, revocation); err != nil || count != 1 {
		t.Fatalf("RevokeSession(replay) = %d, %v", count, err)
	}
	fence := SessionFence{SessionKey: SessionKey{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}, State: "draining", UpdatedAt: 31, RawJSON: json.RawMessage(`{"state":"draining","operations":2}`)}
	if err := store.Sessions().PutFence(ctx, fence); err != nil {
		t.Fatal(err)
	}
	transitioned := fence
	transitioned.State = "incomplete"
	transitioned.RawJSON = json.RawMessage(`{"state":"incomplete","operations":2}`)
	if err := store.Sessions().TransitionFence(ctx, transitioned, "draining"); err != nil {
		t.Fatal(err)
	}
	if err := store.Sessions().TransitionFence(ctx, transitioned, "draining"); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("stale session transition error = %v", err)
	}
	phase := SessionPhase{SessionKey: SessionKey{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}, Phase: "execution", RawJSON: json.RawMessage(`{"phase":"execution","counts_json":{"operations":2}}`)}
	if err := store.Sessions().PutPhase(ctx, phase); err != nil {
		t.Fatal(err)
	}
	gotFence, phases, err := store.Sessions().Get(ctx, SessionKey{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, string(gotFence.RawJSON), string(transitioned.RawJSON))
	if len(phases) != 1 {
		t.Fatalf("phases = %#v", phases)
	}
	assertJSONEqual(t, string(phases[0].RawJSON), string(phase.RawJSON))
}

func TestCurrentConfirmationViewRejectsLegacyScopeJSON(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	expiresAt := time.Unix(200, 0).UTC()
	legacy := `{"confirmation_id":"legacy","confirmation_token_id":"token","plugin_id":"com.example","plugin_instance_id":"plugin","surface_instance_id":"surface","bridge_channel_id":"bridge","method":"example.run","request_hash":"request","plan_hash":"plan","scope_json":"{\"active_fingerprint\":\"sha256:fingerprint\",\"owner_session_hash\":\"session\",\"owner_user_hash\":\"user\",\"owner_env_hash\":\"env\",\"session_channel_id_hash\":\"channel\",\"policy_revision\":1,\"management_revision\":1,\"revoke_epoch\":1,\"target_descriptor_sha256\":\"sha256:target\"}","issued_at":1000000000,"expires_at":200000000000}`
	if _, err := store.db.ExecContext(ctx, `INSERT INTO confirmation_intents(confirmation_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,status,expires_at,confirmation_json) VALUES(?,?,?,?,?,?,'pending',?,?)`, "legacy", "plugin", "session", "user", "env", "channel", expiresAt.UnixNano(), legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirmations().ListConfirmationIntentRecords(ctx, "plugin"); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("ListConfirmationIntentRecords() error = %v, want ErrStateConflict", err)
	}
}

func TestCurrentSessionViewRejectsLegacyFenceAndPhasePayloads(t *testing.T) {
	ctx := context.Background()
	scope := sessionctx.SessionScope{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}

	t.Run("flat fence counts", func(t *testing.T) {
		store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()

		proof := bytes.Repeat([]byte{1}, sha256.Size)
		updatedAt := time.Unix(100, 0).UTC()
		legacy := `{"teardown_operation_id":"teardown","operations":2,"created_at":100000000000,"updated_at":100000000000}`
		if _, err := store.db.ExecContext(ctx, `INSERT INTO session_fences(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,state,fence_json,proof_sha256,updated_at) VALUES(?,?,?,?,?,?,?,?)`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, sessionscope.StateDraining, legacy, proof, updatedAt.UnixNano()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Sessions().GetSessionControlRecord(ctx, scope); !errors.Is(err, sessionscope.ErrInvalidState) {
			t.Fatalf("GetSessionControlRecord() error = %v, want ErrInvalidState", err)
		}
	})

	t.Run("counts_json phase", func(t *testing.T) {
		store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()

		proof := bytes.Repeat([]byte{2}, sha256.Size)
		now := time.Unix(100, 0).UTC()
		if _, err := store.Sessions().BeginSessionControlTeardown(ctx, sessionscope.ControlRecord{Scope: scope, State: sessionscope.StateDraining, TeardownOperationID: "teardown", ProofSHA256: proof, CreatedAt: now, UpdatedAt: now}, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, `INSERT INTO session_teardown_phases(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,phase,phase_json) VALUES(?,?,?,?,?,?)`, scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, sessionscope.PhaseExecution, `{"counts_json":"{\"operations\":2}"}`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Sessions().GetSessionControlRecord(ctx, scope); !errors.Is(err, sessionscope.ErrInvalidCounts) {
			t.Fatalf("GetSessionControlRecord() error = %v, want ErrInvalidCounts", err)
		}
	})
}
