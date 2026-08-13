package controlstore

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestPluginDataCatalogCommitEnableIsAtomicWithPluginRecord(t *testing.T) {
	ctx := pluginDataCatalogContext("env-a", "user-a")
	store := openPluginDataCatalogStore(t)
	defer store.Close()

	record := putPluginDataCatalogRecord(t, store, ctx, "plugini_atomic")
	shape, err := plugindata.ShapeFromManifest(record.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	shapeHash, err := plugindata.HashShape(shape)
	if err != nil {
		t.Fatal(err)
	}
	binding := plugindata.Binding{PluginInstanceID: record.PluginInstanceID, GenerationID: "gen_atomic", State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHash}

	if err := store.CommitEnable(ctx, record.ManagementRevision+1, nil, binding, shape, time.Now()); !errors.Is(err, registry.ErrManagementRevisionConflict) {
		t.Fatalf("stale CommitEnable() error = %v", err)
	}
	if _, found, err := store.GetBinding(ctx, record.PluginInstanceID); err != nil || found {
		t.Fatalf("binding after stale enable: found=%v err=%v", found, err)
	}
	if err := store.CommitEnable(ctx, record.ManagementRevision, nil, binding, shape, time.Now()); err != nil {
		t.Fatal(err)
	}
	enabled, err := store.Registry().GetPlugin(ctx, "env-a", record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if enabled.EnableState != registry.EnableEnabled || enabled.ManagementRevision != record.ManagementRevision+1 || enabled.RevokeEpoch != record.RevokeEpoch+1 {
		t.Fatalf("enabled record = %#v", enabled)
	}
	var state string
	var managementRevision uint64
	var raw string
	if err := store.db.QueryRow(`SELECT state,management_revision,record_json FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=?`, "env-a", record.PluginInstanceID).Scan(&state, &managementRevision, &raw); err != nil {
		t.Fatal(err)
	}
	if state != string(registry.EnableEnabled) || managementRevision != enabled.ManagementRevision || raw == "" {
		t.Fatalf("persisted state=%q management_revision=%d raw=%q", state, managementRevision, raw)
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
	record := putPluginDataCatalogRecord(t, store, ctxA, "plugini_scoped")
	shape, _ := plugindata.ShapeFromManifest(record.Manifest)
	shapeHash, _ := plugindata.HashShape(shape)
	if err := store.CommitEnable(ctxA, record.ManagementRevision, nil, plugindata.Binding{PluginInstanceID: record.PluginInstanceID, GenerationID: "gen_scoped", State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHash}, shape, time.Now()); err != nil {
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
	record := putPluginDataCatalogRecord(t, store, ctx, "plugini_retained")
	shape, _ := plugindata.ShapeFromManifest(record.Manifest)
	shapeHash, _ := plugindata.HashShape(shape)
	binding := plugindata.Binding{PluginInstanceID: record.PluginInstanceID, GenerationID: "gen_retained", State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHash}
	if err := store.CommitEnable(ctx, record.ManagementRevision, nil, binding, shape, time.Now()); err != nil {
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

func TestPluginDataCatalogMigrationPreservesBindingsAndObjects(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "registry.sqlite")
	target := filepath.Join(dir, "control.sqlite")
	ctx := pluginDataCatalogContext("env-a", "user-a")
	legacy, err := registry.NewSQLiteStore(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	quotaFiles := int64(16)
	record, err := legacy.PutPlugin(ctx, registry.PluginRecord{PluginInstanceID: "plugini_migrated", PublisherID: "example", PluginID: "com.example.atomic", Version: "1.0.0", ActiveFingerprint: "sha256:fingerprint", PackageHash: "sha256:package", ManifestHash: "sha256:manifest", EntriesHash: "sha256:entries", TrustState: registry.TrustVerified, EnableState: registry.EnableDisabled, Manifest: manifest.Manifest{SchemaVersion: manifest.SchemaVersionV8, Publisher: manifest.Publisher{PublisherID: "example"}, Plugin: manifest.Plugin{PluginID: "com.example.atomic", Version: "1.0.0"}, Storage: &manifest.StorageSpec{Stores: []manifest.StoreSpec{{StoreID: "files", Kind: "files", Scope: "user", QuotaBytes: 1024, QuotaFiles: &quotaFiles, SchemaVersion: 1}}}}}, registry.PutOptions{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	shape, _ := plugindata.ShapeFromManifest(record.Manifest)
	shapeHash, _ := plugindata.HashShape(shape)
	binding := plugindata.Binding{PluginInstanceID: record.PluginInstanceID, GenerationID: "gen_migrated", State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHash}
	if err := legacy.CommitEnable(ctx, record.ManagementRevision, nil, binding, shape, time.Now()); err != nil {
		t.Fatal(err)
	}
	object := plugindata.Object{PluginInstanceID: record.PluginInstanceID, ObjectID: "obj_migrated", ContentHash: strings.Repeat("c", 64), ShapeHash: strings.Repeat("d", 64), SizeBytes: 9, CreatedAt: time.Now().UTC()}
	if err := legacy.CreateObject(ctx, sessionctx.ScopeUser, object); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Migrate(context.Background(), Config{Path: target, Sources: []Source{{Name: "registry", Path: source, Kind: "registry", Version: sqliteUserVersion(t, source)}}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got, found, err := store.GetBinding(ctx, record.PluginInstanceID); err != nil || !found || got.GenerationID != binding.GenerationID {
		t.Fatalf("migrated binding = %#v found=%v err=%v", got, found, err)
	}
	if got, found, err := store.GetObject(ctx, sessionctx.ScopeUser, object.PluginInstanceID, object.ObjectID); err != nil || !found || got.ContentHash != object.ContentHash {
		t.Fatalf("migrated object = %#v found=%v err=%v", got, found, err)
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
	quotaFiles := int64(16)
	record, err := store.Registry().PutPlugin(ctx, sessionctxFromTest(t, ctx).OwnerEnvHash, registry.PluginRecord{
		PluginInstanceID: instanceID,
		PublisherID:      "example", PluginID: "com.example.atomic", Version: "1.0.0",
		ActiveFingerprint: "sha256:fingerprint", PackageHash: "sha256:package", ManifestHash: "sha256:manifest", EntriesHash: "sha256:entries",
		TrustState: registry.TrustVerified, EnableState: registry.EnableDisabled,
		Manifest: manifest.Manifest{SchemaVersion: manifest.SchemaVersionV8, Publisher: manifest.Publisher{PublisherID: "example"}, Plugin: manifest.Plugin{PluginID: "com.example.atomic", Version: "1.0.0"}, Storage: &manifest.StorageSpec{Stores: []manifest.StoreSpec{{StoreID: "files", Kind: "files", Scope: "user", QuotaBytes: 1024, QuotaFiles: &quotaFiles, SchemaVersion: 1}}}},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func sessionctxFromTest(t *testing.T, ctx context.Context) sessionctx.Context {
	t.Helper()
	value, ok := sessionctx.FromContext(ctx)
	if !ok {
		t.Fatal("session context missing")
	}
	return value
}
