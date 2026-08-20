package controlstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestInstallCommitPersistsEnabledRecordAndBindingInOneRevision(t *testing.T) {
	ctx := pluginDataCatalogContext("env-install", "user-install")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, binding, shape := freshPluginDataCatalogInstall(t, "env-install", "plugini_install")

	stored, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if stored.EnableState != registry.EnableEnabled || stored.ManagementRevision != 1 || stored.RevokeEpoch != 1 {
		t.Fatalf("installed record = %#v", stored)
	}
	persistedBinding, found, err := store.GetBinding(ctx, stored.PluginInstanceID)
	if err != nil || !found || persistedBinding != binding {
		t.Fatalf("installed binding = %#v, found=%v err=%v", persistedBinding, found, err)
	}
}

func TestRegistryViewPutPluginCannotCreateOrUpsert(t *testing.T) {
	ctx := pluginDataCatalogContext("env-update-only", "user-update-only")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, binding, shape := freshPluginDataCatalogInstall(t, "env-update-only", "plugini_update_only")

	if _, err := store.Registry().PutPlugin(ctx, "env-update-only", record, time.Now().UTC()); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("PutPlugin() creation error = %v, want ErrNotFound", err)
	}
	if _, err := store.Registry().GetPlugin(ctx, "env-update-only", record.PluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("GetPlugin() after rejected PutPlugin = %v, want ErrNotFound", err)
	}

	installed, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	installed.Metadata = map[string]string{"updated": "true"}
	updated, err := store.Registry().PutPlugin(ctx, "env-update-only", installed, time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if updated.ManagementRevision != installed.ManagementRevision+1 || updated.Metadata["updated"] != "true" {
		t.Fatalf("updated record = %#v", updated)
	}
}

func TestInstallCommitBindingFailureRollsBackPluginRecord(t *testing.T) {
	ctx := pluginDataCatalogContext("env-install-failure", "user-install-failure")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, binding, shape := freshPluginDataCatalogInstall(t, "env-install-failure", "plugini_install_failure")
	if _, err := store.db.Exec(`
CREATE TRIGGER fail_install_binding
BEFORE INSERT ON plugin_data_bindings
BEGIN
  SELECT RAISE(ABORT, 'injected binding failure');
END`); err != nil {
		t.Fatal(err)
	}

	if _, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now()); err == nil || !strings.Contains(err.Error(), "injected binding failure") {
		t.Fatalf("InstallCommit() error = %v, want injected binding failure", err)
	}
	if _, err := store.Registry().GetPlugin(ctx, "env-install-failure", record.PluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("plugin record after failed binding commit error = %v, want not found", err)
	}
	if _, found, err := store.GetBinding(ctx, record.PluginInstanceID); err != nil || found {
		t.Fatalf("binding after failed install: found=%v err=%v", found, err)
	}
}

func TestInstallCommitReactivatesExactRetainedBindingAtomically(t *testing.T) {
	ctx := pluginDataCatalogContext("env-retained-install", "user-retained-install")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, active, shape := freshPluginDataCatalogInstall(t, "env-retained-install", "plugini_retained_install")
	stored, err := store.InstallCommit(ctx, record, nil, active, shape, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{
		PluginInstanceID:           stored.PluginInstanceID,
		ExpectedManagementRevision: stored.ManagementRevision,
		Now:                        time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	retained, found, err := store.GetBinding(ctx, stored.PluginInstanceID)
	if err != nil || !found || retained.State != plugindata.BindingRetained {
		t.Fatalf("retained binding = %#v, found=%v err=%v", retained, found, err)
	}
	next := retained
	next.State = plugindata.BindingActive
	next.Revision++
	next.RetainedAt = nil
	next.ExpiresAt = nil
	reinstall, _, _ := freshPluginDataCatalogInstall(t, "env-retained-install", stored.PluginInstanceID)

	reinstalled, err := store.InstallCommit(ctx, reinstall, &retained, next, shape, time.Now())
	if err != nil {
		t.Fatalf("InstallCommit() retained reinstall error = %v", err)
	}
	if reinstalled.EnableState != registry.EnableEnabled || reinstalled.ManagementRevision != 1 || reinstalled.RevokeEpoch != 1 {
		t.Fatalf("reinstalled record = %#v", reinstalled)
	}
	actual, found, err := store.GetBinding(ctx, stored.PluginInstanceID)
	if err != nil || !found || actual.GenerationID != retained.GenerationID || actual.State != plugindata.BindingActive || actual.Revision != retained.Revision+1 {
		t.Fatalf("reactivated binding = %#v, found=%v err=%v", actual, found, err)
	}
}

func TestInstallCommitReplacesDeletedTombstoneAfterDeleteDataUninstall(t *testing.T) {
	ctx := pluginDataCatalogContext("env-delete-data-reinstall", "user-delete-data-reinstall")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, binding, shape := freshPluginDataCatalogInstall(t, "env-delete-data-reinstall", "plugini_delete_data_reinstall")
	installed, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		DeleteData:                 true,
		ExpectedManagementRevision: installed.ManagementRevision,
		Now:                        time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.GetBinding(ctx, installed.PluginInstanceID); err != nil || found {
		t.Fatalf("binding after delete-data uninstall: found=%v err=%v", found, err)
	}

	reinstall, next, _ := freshPluginDataCatalogInstall(t, "env-delete-data-reinstall", installed.PluginInstanceID)
	reinstalled, err := store.InstallCommit(ctx, reinstall, nil, next, shape, time.Now().UTC())
	if err != nil {
		t.Fatalf("delete-data reinstall error = %v", err)
	}
	if reinstalled.EnableState != registry.EnableEnabled || reinstalled.ManagementRevision != 1 || reinstalled.RevokeEpoch != 1 {
		t.Fatalf("reinstalled record = %#v", reinstalled)
	}
	active, found, err := store.GetBinding(ctx, installed.PluginInstanceID)
	if err != nil || !found || active.State != plugindata.BindingActive || active.Revision != 1 {
		t.Fatalf("reinstalled binding = %#v, found=%v err=%v", active, found, err)
	}
}

func TestInstallCommitRetainedBindingUpdateFailureRollsBackPluginRecord(t *testing.T) {
	ctx := pluginDataCatalogContext("env-retained-failure", "user-retained-failure")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, active, shape := freshPluginDataCatalogInstall(t, "env-retained-failure", "plugini_retained_failure")
	stored, err := store.InstallCommit(ctx, record, nil, active, shape, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{
		PluginInstanceID:           stored.PluginInstanceID,
		ExpectedManagementRevision: stored.ManagementRevision,
		Now:                        time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	retained, found, err := store.GetBinding(ctx, stored.PluginInstanceID)
	if err != nil || !found {
		t.Fatalf("retained binding = %#v, found=%v err=%v", retained, found, err)
	}
	if _, err := store.db.Exec(`
CREATE TRIGGER fail_retained_install_binding
BEFORE UPDATE ON plugin_data_bindings
BEGIN
  SELECT RAISE(ABORT, 'injected retained binding failure');
END`); err != nil {
		t.Fatal(err)
	}
	next := retained
	next.State = plugindata.BindingActive
	next.Revision++
	next.RetainedAt = nil
	next.ExpiresAt = nil
	reinstall, _, _ := freshPluginDataCatalogInstall(t, "env-retained-failure", stored.PluginInstanceID)

	if _, err := store.InstallCommit(ctx, reinstall, &retained, next, shape, time.Now()); err == nil || !strings.Contains(err.Error(), "injected retained binding failure") {
		t.Fatalf("InstallCommit() error = %v, want injected retained binding failure", err)
	}
	if _, err := store.Registry().GetPlugin(ctx, "env-retained-failure", stored.PluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("plugin record after failed retained commit error = %v, want not found", err)
	}
	actual, found, err := store.GetBinding(ctx, retained.PluginInstanceID)
	if err != nil || !found || !sameControlDataBinding(actual, retained) {
		t.Fatalf("binding after failed retained commit = %#v, found=%v err=%v, want %#v", actual, found, err, retained)
	}
}

func TestInstallCommitRejectsStaleRetainedBindingWithoutMutation(t *testing.T) {
	ctx := pluginDataCatalogContext("env-retained-stale", "user-retained-stale")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, active, shape := freshPluginDataCatalogInstall(t, "env-retained-stale", "plugini_retained_stale")
	stored, err := store.InstallCommit(ctx, record, nil, active, shape, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{
		PluginInstanceID:           stored.PluginInstanceID,
		ExpectedManagementRevision: stored.ManagementRevision,
		Now:                        time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	retained, found, err := store.GetBinding(ctx, stored.PluginInstanceID)
	if err != nil || !found {
		t.Fatalf("retained binding = %#v, found=%v err=%v", retained, found, err)
	}
	stale := retained
	stale.Revision--
	next := retained
	next.State = plugindata.BindingActive
	next.Revision++
	next.RetainedAt = nil
	next.ExpiresAt = nil
	reinstall, _, _ := freshPluginDataCatalogInstall(t, "env-retained-stale", stored.PluginInstanceID)

	if _, err := store.InstallCommit(ctx, reinstall, &stale, next, shape, time.Now()); !errors.Is(err, plugindata.ErrBindingConflict) {
		t.Fatalf("InstallCommit() error = %v, want ErrBindingConflict", err)
	}
	if _, err := store.Registry().GetPlugin(ctx, "env-retained-stale", stored.PluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("plugin record after stale retained commit error = %v, want not found", err)
	}
	actual, found, err := store.GetBinding(ctx, retained.PluginInstanceID)
	if err != nil || !found || !sameControlDataBinding(actual, retained) {
		t.Fatalf("binding after stale retained commit = %#v, found=%v err=%v, want %#v", actual, found, err, retained)
	}
}

func TestPluginRecordReadbackRestoresOwnerEnvironment(t *testing.T) {
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	ctx := pluginDataCatalogContext("env-owner", "user-owner")
	record := putPluginDataCatalogRecord(t, store, ctx, "plugin-owner")
	if record.OwnerEnvHash != "env-owner" {
		t.Fatalf("installed owner = %q", record.OwnerEnvHash)
	}
	read, err := store.Registry().GetPlugin(ctx, "env-owner", record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if read.OwnerEnvHash != "env-owner" {
		t.Fatalf("readback owner = %q, want env-owner", read.OwnerEnvHash)
	}
}

func TestPluginDataCatalogIsOwnerScoped(t *testing.T) {
	ctxA := pluginDataCatalogContext("env-a", "user-a")
	ctxB := pluginDataCatalogContext("env-b", "user-b")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, binding, shape := freshPluginDataCatalogInstall(t, "env-a", "plugini_scoped")
	binding.GenerationID = "gen_scoped"
	if _, err := store.InstallCommit(ctxA, record, nil, binding, shape, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.GetBinding(ctxB, record.PluginInstanceID); err != nil || found {
		t.Fatalf("other owner binding: found=%v err=%v", found, err)
	}
}

func TestPluginDataCatalogCommitUninstallRetainsBindingAndDeletesAuthorization(t *testing.T) {
	ctx := pluginDataCatalogContext("env-a", "user-a")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	record, binding, shape := freshPluginDataCatalogInstall(t, "env-a", "plugini_retained")
	binding.GenerationID = "gen_retained"
	if _, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now()); err != nil {
		t.Fatal(err)
	}
	enabled, err := store.Registry().GetPlugin(ctx, "env-a", record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(24 * time.Hour).UTC()
	result, err := store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision, RetainUntil: &expires, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if result.ManagementRevision != enabled.ManagementRevision+1 || result.RevokeEpoch != enabled.RevokeEpoch+1 {
		t.Fatalf("uninstall result = %#v", result)
	}
	retained, found, err := store.GetBinding(ctx, record.PluginInstanceID)
	if err != nil || !found {
		t.Fatalf("retained binding: found=%v err=%v", found, err)
	}
	if retained.State != plugindata.BindingRetained || retained.Revision != binding.Revision+1 || retained.RetainedAt == nil || retained.ExpiresAt == nil || !retained.ExpiresAt.Equal(expires) {
		t.Fatalf("retained binding = %#v", retained)
	}
}

func TestPluginDataCatalogObjectsUseExactResourceScope(t *testing.T) {
	ctxA := pluginDataCatalogContext("env-a", "user-a")
	ctxB := pluginDataCatalogContext("env-a", "user-b")
	store := openPluginDataCatalogStore(t)
	defer store.Close()
	object := plugindata.Object{PluginInstanceID: "plugini_object", ObjectID: "obj_export", ContentHash: strings.Repeat("a", 64), ShapeHash: strings.Repeat("b", 64), SizeBytes: 1, CreatedAt: time.Now().UTC()}
	if err := store.CreateObject(ctxA, sessionctx.ScopeUser, object); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.GetObject(ctxB, sessionctx.ScopeUser, object.PluginInstanceID, object.ObjectID); err != nil || found {
		t.Fatalf("other user object: found=%v err=%v", found, err)
	}
	if got, found, err := store.GetObject(ctxA, sessionctx.ScopeUser, object.PluginInstanceID, object.ObjectID); err != nil || !found || got.ObjectID != object.ObjectID {
		t.Fatalf("owner object = %#v found=%v err=%v", got, found, err)
	}
}

func TestPluginDataCatalogInterface(t *testing.T) {
	var _ plugindata.Catalog = (*Store)(nil)
}

func openPluginDataCatalogStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func pluginDataCatalogContext(env, user string) context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{OwnerSessionHash: "session", OwnerUserHash: user, OwnerEnvHash: env, SessionChannelIDHash: "channel"})
}

func putPluginDataCatalogRecord(t *testing.T, store *Store, ctx context.Context, instanceID string) registry.PluginRecord {
	t.Helper()
	owner := sessionctxFromTest(t, ctx).OwnerEnvHash
	record, binding, shape := freshPluginDataCatalogInstall(t, owner, instanceID)
	record, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func freshPluginDataCatalogInstall(t *testing.T, ownerEnvHash, instanceID string) (registry.PluginRecord, plugindata.Binding, plugindata.Shape) {
	t.Helper()
	manifestJSON := `{
  "schema_version": "redevplugin.manifest.v9",
  "publisher": {"publisher_id": "example", "display_name": "Example"},
  "plugin": {"plugin_id": "com.example.atomic", "display_name": "Atomic", "version": "1.0.0"},
  "api": {"major": 1, "required_features": [], "optional_features": []},
  "permissions": [],
  "presentation": {"locales": {"default": "en-US"}},
  "surfaces": [{"surface_id": "main", "kind": "view", "label": "Main", "entry": "ui/index.html"}],
  "workers": [],
  "methods": []
}`
	current, err := manifest.Decode(strings.NewReader(manifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := manifest.CanonicalJSON([]byte(manifestJSON))
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(canonical)
	shape, err := plugindata.ShapeFromManifest(current)
	if err != nil {
		t.Fatal(err)
	}
	shapeHash, err := plugindata.HashShape(shape)
	if err != nil {
		t.Fatal(err)
	}
	record := registry.PluginRecord{
		PluginInstanceID:  instanceID,
		PublisherID:       "example",
		PluginID:          "com.example.atomic",
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:fingerprint",
		PackageHash:       "sha256:package",
		ManifestHash:      "sha256:" + hex.EncodeToString(manifestSum[:]),
		EntriesHash:       "sha256:entries",
		TrustState:        registry.TrustVerified,
		TrustAssessment: registry.TrustAssessment{
			TrustState: registry.TrustVerified,
			VerifiedHashes: registry.TrustHashSet{
				PackageSHA256: "sha256:package", ManifestSHA256: "sha256:" + hex.EncodeToString(manifestSum[:]), EntriesSHA256: "sha256:entries",
			},
		},
		SignatureAssessment: registry.SignatureAssessment{
			Status: registry.SignatureAbsent,
			AssessedHashes: registry.TrustHashSet{
				PackageSHA256: "sha256:package", ManifestSHA256: "sha256:" + hex.EncodeToString(manifestSum[:]), EntriesSHA256: "sha256:entries",
			},
			PackageSHA256: "sha256:package", ManifestSHA256: "sha256:" + hex.EncodeToString(manifestSum[:]), EntriesSHA256: "sha256:entries",
		},
		PackageSourceProvenance: registry.PackageSourceProvenance{
			Kind: registry.PackageSourceLocalGenerated, PackageSHA256: "sha256:package",
		},
		ExecutionApproval: registry.ExecutionApproval{
			Status: registry.ExecutionApprovalUserApproved, OwnerEnvHash: ownerEnvHash, PackageSHA256: "sha256:package",
		},
		UpdateEligibility: registry.UpdateManualOnly,
		EnableState:       registry.EnableEnabled,
		Manifest:          current,
		CanonicalManifest: string(canonical),
	}
	binding := plugindata.Binding{
		PluginInstanceID: instanceID,
		GenerationID:     "gen_" + instanceID,
		State:            plugindata.BindingActive,
		Revision:         1,
		ShapeHash:        shapeHash,
	}
	return record, binding, shape
}

func sessionctxFromTest(t *testing.T, ctx context.Context) sessionctx.Context {
	t.Helper()
	value, ok := sessionctx.FromContext(ctx)
	if !ok {
		t.Fatal("session context missing")
	}
	return value
}
