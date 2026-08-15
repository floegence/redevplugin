package controlstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/execution"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/registry"
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

func TestRegistryExternalInstallUsesOneTransactionAndNoDurableInspectionState(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view := store.Registry()
	now := time.Unix(100, 0).UTC()
	record := externalControlRecord("plugin", "1.0.0", now)
	installed, err := view.InstallExternalPackage(ctx, "env", registry.InstallExternalPackageRequest{Intent: registry.ExternalPackageInstall, Record: record, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if installed.ManagementRevision != 1 || installed.EnableState != registry.EnableDisabled {
		t.Fatalf("installed = %#v", installed)
	}
	if _, err := view.InstallExternalPackage(ctx, "env", registry.InstallExternalPackageRequest{Intent: registry.ExternalPackageInstall, Record: record, Now: now.Add(time.Second)}); !errors.Is(err, registry.ErrManagementRevisionConflict) {
		t.Fatalf("duplicate install error = %v", err)
	}
	got, err := view.Get(ctx, "env", "plugin")
	if err != nil {
		t.Fatal(err)
	}
	if got.Record.ManagementRevision != 1 || len(got.Grants) != 0 || got.Policy != nil {
		t.Fatalf("failed transaction changed state: %#v", got)
	}
	var transientTables int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND (name LIKE '%inspection%' OR name LIKE '%receipt%' OR name LIKE '%stage%')`).Scan(&transientTables); err != nil {
		t.Fatal(err)
	}
	if transientTables != 0 {
		t.Fatalf("transient external-package state became durable: %d tables", transientTables)
	}
}

func TestRegistryExternalInstallCommitsActivationExecutionAtomically(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(100, 0).UTC()
	owner := ExecutionOwner{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	record, pending, err := store.Registry().InstallExternalPackageWithActivation(ctx, "env", registry.InstallExternalPackageRequest{
		Intent: registry.ExternalPackageInstall, Record: externalControlRecord("plugin", "1.0.0", now), Now: now,
	}, ExternalInstallActivationRequest{
		ExecutionID: "external_install", Owner: owner, Now: now,
		Activation: registry.ReleaseInstallActivationRequest{Mode: registry.ReleaseInstallActivationAutomatic, ApprovedPermissionIDs: []string{"read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Execution.Status != execution.StatusRunning || pending.PackageSHA256 != record.PackageHash ||
		pending.InstalledManagementRevision != record.ManagementRevision {
		t.Fatalf("pending activation = %#v, record = %#v", pending, record)
	}
	listed, err := store.Executions().ListPendingExternalInstallActivations(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Execution.ID != pending.Execution.ID || listed[0].ActivationRequest.ApprovedPermissionIDs[0] != "read" {
		t.Fatalf("listed activations = %#v", listed)
	}
	var raw string
	if err := store.db.QueryRowContext(ctx, `SELECT operation_json FROM execution WHERE execution_id=?`, pending.Execution.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"execution_id", "status", "cursor", "terminal_at", "created_at", "updated_at"} {
		if strings.Contains(raw, `"`+retired+`"`) {
			t.Errorf("external activation payload mirrors execution field %q: %s", retired, raw)
		}
	}

	badRecord := externalControlRecord("rolled_back", "1.0.0", now)
	_, _, err = store.Registry().InstallExternalPackageWithActivation(ctx, "env", registry.InstallExternalPackageRequest{
		Intent: registry.ExternalPackageInstall, Record: badRecord, Now: now,
	}, ExternalInstallActivationRequest{ExecutionID: "invalid", Owner: owner, Activation: registry.ReleaseInstallActivationRequest{Mode: registry.ReleaseInstallActivationDisabled}})
	if err == nil {
		t.Fatal("invalid activation request was accepted")
	}
	if _, err := store.Registry().Get(ctx, "env", badRecord.PluginInstanceID); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("failed atomic install left plugin state: %v", err)
	}
}

func externalControlRecord(instanceID, version string, now time.Time) registry.PluginRecord {
	return registry.PluginRecord{
		PluginInstanceID: instanceID, PublisherID: "publisher", PluginID: "com.example", Version: version,
		ActiveFingerprint: "sha256:fingerprint", PackageHash: "sha256:package", ManifestHash: "sha256:manifest", EntriesHash: "sha256:entries",
		TrustState: registry.TrustUntrusted, EnableState: registry.EnableDisabled,
		Manifest:                manifest.Manifest{SchemaVersion: manifest.SchemaVersionV8, Plugin: manifest.Plugin{PluginID: "com.example", Version: version}},
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
		Record: PluginRecord{OwnerEnvHash: "env", PluginInstanceID: "plugin", PublisherID: "publisher", PluginID: "com.example", Version: "1.0.0", ActiveFingerprint: "sha256:fingerprint", PackageSHA256: "sha256:package", ManifestSHA256: "sha256:manifest", EntriesSHA256: "sha256:entries", State: "enabled", PolicyRevision: 2, ManagementRevision: 3, RevokeEpoch: 4, InstalledAt: 10, UpdatedAt: 11, RawJSON: json.RawMessage(`{"manifest":{"schema_version":8},"management_revision":3}`)},
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
		Release: registry.ReleaseInstallIdentity{
			SourceID: "official", Channel: "stable", ReleaseMetadataRef: "release.json",
			ReleaseMetadataSHA256: strings.Repeat("a", 64), PublisherID: "publisher", PluginID: "plugin", Version: "1.0.0",
			PackageSHA256: "sha256:" + strings.Repeat("b", 64), ManifestSHA256: "sha256:" + strings.Repeat("c", 64), EntriesSHA256: "sha256:" + strings.Repeat("d", 64),
		},
		Activation: registry.ReleaseInstallActivationRequest{Mode: registry.ReleaseInstallActivationDisabled}, Now: now,
	}
	owner := ExecutionOwner{OwnerSessionHash: "session", OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel"}
	started, created, err := view.StartReleaseInstall(ctx, owner, request)
	if err != nil || !created {
		t.Fatalf("StartReleaseInstall() = %#v, %t, %v", started, created, err)
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
	for _, retired := range []string{"execution_id", "operation_id", "status", "cursor", "terminal_at", "revision", "created_at", "updated_at"} {
		if _, exists := payload.Operation[retired]; exists {
			t.Errorf("release-install domain payload mirrors execution field %q: %s", retired, raw)
		}
	}
	updated, err := view.UpdateReleaseInstall(ctx, owner.OwnerEnvHash, registry.UpdateReleaseInstallOperationRequest{
		ExecutionID: request.ExecutionID, ExpectedCursor: started.Execution.Cursor, Status: execution.StatusRunning,
		Phase: "download_package", Progress: registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressBytes, Completed: 1, Total: 2},
		Attempt: 1, MutationOutcome: "not_committed", Activation: started.Activation, Now: now.Add(time.Second),
	})
	if err != nil || updated.Execution.Cursor != 1 {
		t.Fatalf("UpdateReleaseInstall() = %#v, %v", updated, err)
	}
	_, err = view.UpdateReleaseInstall(ctx, owner.OwnerEnvHash, registry.UpdateReleaseInstallOperationRequest{
		ExecutionID: request.ExecutionID, ExpectedCursor: 0, Status: execution.StatusRunning,
		Phase: "verify_hashes", Progress: registry.ReleaseInstallProgress{Kind: registry.ReleaseInstallProgressIndeterminate},
		Attempt: 1, MutationOutcome: "not_committed", Activation: updated.Activation, Now: now.Add(2 * time.Second),
	})
	if !errors.Is(err, registry.ErrReleaseInstallOperationConflict) {
		t.Fatalf("stale cursor update error = %v", err)
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
	if result.Orphaned != 1 || result.Canceled != 1 {
		t.Fatalf("ReconcileOrphans() = %#v", result)
	}
	for id, wantStatus := range map[string]string{
		"running": execution.StatusOrphaned, "cancel-requested": execution.StatusCanceled, "completed": execution.StatusCompleted,
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
	}
	second, err := view.ReconcileOrphans(ctx, now.Add(time.Second))
	if err != nil || second.Orphaned != 0 || second.Canceled != 0 {
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
