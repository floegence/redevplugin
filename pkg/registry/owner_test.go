package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func registryTestContext() context.Context {
	return registryTestContextFor("owner_user_hash_test", "owner_env_hash_test")
}

func registryTestContextFor(ownerUserHash, ownerEnvHash string) context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "owner_session_hash_test",
		OwnerUserHash:        ownerUserHash,
		OwnerEnvHash:         ownerEnvHash,
		SessionChannelIDHash: "session_channel_id_hash_test",
	})
}

func TestMemoryStoreRequiresAuthenticatedOwner(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.ListPlugins(context.Background()); !errors.Is(err, sessionctx.ErrSessionRequired) {
		t.Fatalf("ListPlugins() error = %v, want authenticated session", err)
	}
}

func TestStoreIsolatesEnvironmentOwners(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			environmentA := registryTestContextFor("owner_user_a", "owner_env_a")
			environmentB := registryTestContextFor("owner_user_b", "owner_env_b")
			record := PluginRecord{
				PluginInstanceID:  "plugini_shared",
				PublisherID:       "example",
				PluginID:          "com.example.shared",
				Version:           "1.0.0",
				ActiveFingerprint: "sha256:shared-a",
				TrustState:        TrustVerified,
				EnableState:       EnableDisabled,
				Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.shared", Version: "1.0.0"}},
			}
			storedA, err := store.PutPlugin(environmentA, record, PutOptions{Now: time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)})
			if err != nil {
				t.Fatal(err)
			}
			record.Version = "2.0.0"
			record.ActiveFingerprint = "sha256:shared-b"
			record.Manifest.Plugin.Version = "2.0.0"
			storedB, err := store.PutPlugin(environmentB, record, PutOptions{Now: time.Date(2026, 7, 18, 0, 0, 1, 0, time.UTC)})
			if err != nil {
				t.Fatal(err)
			}
			if storedA.OwnerEnvHash != "owner_env_a" || storedB.OwnerEnvHash != "owner_env_b" {
				t.Fatalf("stored owners = %q, %q", storedA.OwnerEnvHash, storedB.OwnerEnvHash)
			}
			gotA, err := store.GetPlugin(environmentA, record.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			gotB, err := store.GetPlugin(environmentB, record.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if gotA.Version != "1.0.0" || gotB.Version != "2.0.0" {
				t.Fatalf("isolated versions = %q, %q", gotA.Version, gotB.Version)
			}
			for _, item := range []struct {
				ctx     context.Context
				version string
			}{{environmentA, "1.0.0"}, {environmentB, "2.0.0"}} {
				listed, err := store.ListPlugins(item.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if len(listed) != 1 || listed[0].Version != item.version {
					t.Fatalf("ListPlugins() = %#v, want only %s", listed, item.version)
				}
			}
		})
	}
}

func TestStoreRejectsCallerDefinedEnvironmentOwner(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			_, err := store.PutPlugin(registryTestContextFor("owner_user_a", "owner_env_a"), PluginRecord{
				OwnerEnvHash:     "owner_env_b",
				PluginInstanceID: "plugini_mismatch",
			}, PutOptions{})
			if !errors.Is(err, ErrOwnerScopeMismatch) {
				t.Fatalf("PutPlugin() error = %v, want owner scope mismatch", err)
			}
		})
	}
}

func TestPluginRecordOwnerIsPrivateJSONState(t *testing.T) {
	raw, err := json.Marshal(PluginRecord{OwnerEnvHash: "owner_env_private", PluginInstanceID: "plugini_private"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "owner_env_private") || strings.Contains(string(raw), "owner_env_hash") {
		t.Fatalf("PluginRecord JSON exposed owner: %s", raw)
	}
}

func TestSQLiteStoreRequiresAuthenticatedOwner(t *testing.T) {
	store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for name, call := range map[string]func() error{
		"plugins":       func() error { _, err := store.ListPlugins(context.Background()); return err },
		"authorization": func() error { _, err := store.ListAuthorization(context.Background()); return err },
		"bindings":      func() error { _, _, err := store.ListBindings(context.Background(), "", 10); return err },
		"objects": func() error {
			_, _, err := store.ListObjects(context.Background(), sessionctx.ScopeUser, "plugini_test", "", 10)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, sessionctx.ErrSessionRequired) {
				t.Fatalf("operation error = %v, want authenticated session", err)
			}
		})
	}
}

func TestSQLiteStoreReopenPreservesEnvironmentOwners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	ctxA := registryTestContextFor("owner_user_a", "owner_env_a")
	ctxB := registryTestContextFor("owner_user_b", "owner_env_b")
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	recordA := putOwnerPlugin(t, store, ctxA, "plugini_shared", "1.0.0")
	recordB := putOwnerPlugin(t, store, ctxB, "plugini_shared", "2.0.0")
	grantedA, err := store.GrantPermission(ctxA, permissions.GrantRequest{PluginInstanceID: recordA.PluginInstanceID, PermissionID: "documents.read"}, AuthorizationRevisionsFromRecord(recordA))
	if err != nil {
		t.Fatal(err)
	}
	grantedB, err := store.GrantPermission(ctxB, permissions.GrantRequest{PluginInstanceID: recordB.PluginInstanceID, PermissionID: "documents.write"}, AuthorizationRevisionsFromRecord(recordB))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		ctx         context.Context
		contentHash string
	}{{ctxA, strings.Repeat("a", 64)}, {ctxB, strings.Repeat("b", 64)}} {
		if err := store.CreateObject(item.ctx, sessionctx.ScopeUser, plugindata.Object{PluginInstanceID: "plugini_shared", ObjectID: "object_shared", ContentHash: item.contentHash, ShapeHash: strings.Repeat("c", 64), SizeBytes: 1, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	shapeA, err := plugindata.ShapeFromManifest(recordA.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	shapeHashA, err := plugindata.HashShape(shapeA)
	if err != nil {
		t.Fatal(err)
	}
	shapeB, err := plugindata.ShapeFromManifest(recordB.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	shapeHashB, err := plugindata.HashShape(shapeB)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitEnable(ctxA, grantedA.Plugin.ManagementRevision, nil, plugindata.Binding{PluginInstanceID: "plugini_shared", GenerationID: "generation_a", State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHashA}, shapeA, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitEnable(ctxB, grantedB.Plugin.ManagementRevision, nil, plugindata.Binding{PluginInstanceID: "plugini_shared", GenerationID: "generation_b", State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHashB}, shapeB, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, item := range []struct {
		ctx     context.Context
		owner   string
		version string
		grant   string
		object  string
		binding string
	}{{ctxA, "owner_env_a", "1.0.0", "documents.read", strings.Repeat("a", 64), "generation_a"}, {ctxB, "owner_env_b", "2.0.0", "documents.write", strings.Repeat("b", 64), "generation_b"}} {
		record, err := reopened.GetPlugin(item.ctx, "plugini_shared")
		if err != nil {
			t.Fatal(err)
		}
		if record.OwnerEnvHash != item.owner || record.Version != item.version {
			t.Fatalf("reopened record = %#v", record)
		}
		authorization, err := reopened.GetAuthorization(item.ctx, "plugini_shared")
		if err != nil || len(authorization.Grants) != 1 || authorization.Grants[0].PermissionID != item.grant {
			t.Fatalf("reopened authorization = %#v err=%v", authorization, err)
		}
		object, found, err := reopened.GetObject(item.ctx, sessionctx.ScopeUser, "plugini_shared", "object_shared")
		if err != nil || !found || object.ContentHash != item.object {
			t.Fatalf("reopened object = %#v found=%v err=%v", object, found, err)
		}
		binding, found, err := reopened.GetBinding(item.ctx, "plugini_shared")
		if err != nil || !found || binding.GenerationID != item.binding {
			t.Fatalf("reopened binding = %#v found=%v err=%v", binding, found, err)
		}
	}
}

func TestStoreIsolatesAuthorizationAndBindingsByEnvironment(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			ctxA := registryTestContextFor("owner_user_a", "owner_env_a")
			ctxB := registryTestContextFor("owner_user_b", "owner_env_b")
			recordA := putOwnerPlugin(t, store, ctxA, "plugini_shared", "1.0.0")
			recordB := putOwnerPlugin(t, store, ctxB, "plugini_shared", "2.0.0")
			grantedA, err := store.GrantPermission(ctxA, permissions.GrantRequest{PluginInstanceID: recordA.PluginInstanceID, PermissionID: "documents.read"}, AuthorizationRevisionsFromRecord(recordA))
			if err != nil {
				t.Fatal(err)
			}
			grantedB, err := store.GrantPermission(ctxB, permissions.GrantRequest{PluginInstanceID: recordB.PluginInstanceID, PermissionID: "documents.write"}, AuthorizationRevisionsFromRecord(recordB))
			if err != nil {
				t.Fatal(err)
			}
			currentA, err := store.PutSecurityPolicy(ctxA, security.PutPolicyRequest{PluginInstanceID: recordA.PluginInstanceID, DeniedMethods: []string{"documents.delete"}}, AuthorizationRevisionsFromRecord(grantedA.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			currentB, err := store.PutSecurityPolicy(ctxB, security.PutPolicyRequest{PluginInstanceID: recordB.PluginInstanceID, DeniedMethods: []string{"documents.archive"}}, AuthorizationRevisionsFromRecord(grantedB.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range []struct {
				ctx        context.Context
				permission string
				method     string
			}{{ctxA, "documents.read", "documents.delete"}, {ctxB, "documents.write", "documents.archive"}} {
				snapshot, err := store.GetAuthorization(item.ctx, "plugini_shared")
				if err != nil {
					t.Fatal(err)
				}
				if len(snapshot.Grants) != 1 || snapshot.Grants[0].PermissionID != item.permission {
					t.Fatalf("authorization snapshot = %#v", snapshot)
				}
				if snapshot.Policy == nil || len(snapshot.Policy.DeniedMethods) != 1 || snapshot.Policy.DeniedMethods[0] != item.method {
					t.Fatalf("security policy snapshot = %#v", snapshot.Policy)
				}
			}
			shapeA, err := plugindata.ShapeFromManifest(recordA.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			shapeHashA, err := plugindata.HashShape(shapeA)
			if err != nil {
				t.Fatal(err)
			}
			shapeB, err := plugindata.ShapeFromManifest(recordB.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			shapeHashB, err := plugindata.HashShape(shapeB)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.CommitEnable(ctxA, currentA.Plugin.ManagementRevision, nil, plugindata.Binding{PluginInstanceID: "plugini_shared", GenerationID: "generation_a", State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHashA}, shapeA, time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := store.CommitEnable(ctxB, currentB.Plugin.ManagementRevision, nil, plugindata.Binding{PluginInstanceID: "plugini_shared", GenerationID: "generation_b", State: plugindata.BindingActive, Revision: 1, ShapeHash: shapeHashB}, shapeB, time.Now()); err != nil {
				t.Fatal(err)
			}
			bindingA, found, err := store.GetBinding(ctxA, "plugini_shared")
			if err != nil || !found || bindingA.GenerationID != "generation_a" {
				t.Fatalf("environment A binding = %#v, found=%v err=%v", bindingA, found, err)
			}
			bindingB, found, err := store.GetBinding(ctxB, "plugini_shared")
			if err != nil || !found || bindingB.GenerationID != "generation_b" {
				t.Fatalf("environment B binding = %#v, found=%v err=%v", bindingB, found, err)
			}
			for _, item := range []struct {
				ctx        context.Context
				generation string
			}{{ctxA, "generation_a"}, {ctxB, "generation_b"}} {
				bindings, next, err := store.ListBindings(item.ctx, "", 10)
				if err != nil || next != "" || len(bindings) != 1 || bindings[0].GenerationID != item.generation {
					t.Fatalf("scoped binding list = %#v next=%q err=%v", bindings, next, err)
				}
			}
			maintained, next, err := store.ListAllBindingsForMaintenance(context.Background(), "", 10)
			if err != nil || next != "" || len(maintained) != 2 {
				t.Fatalf("maintenance bindings = %#v next=%q err=%v", maintained, next, err)
			}
			generationByOwner := map[string]string{}
			for _, item := range maintained {
				if item.Scope.Kind != sessionctx.ScopeEnvironment || item.Scope.OwnerUserHash != "" {
					t.Fatalf("maintenance binding scope = %#v", item.Scope)
				}
				generationByOwner[item.Scope.OwnerEnvHash] = item.Binding.GenerationID
			}
			if !reflect.DeepEqual(generationByOwner, map[string]string{"owner_env_a": "generation_a", "owner_env_b": "generation_b"}) {
				t.Fatalf("maintenance binding owners = %#v", generationByOwner)
			}
		})
	}
}

func TestStoreIsolatesObjectsByUserAndEnvironment(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			owners := []struct {
				ctx              context.Context
				pluginInstanceID string
				contentHash      string
			}{
				{registryTestContextFor("owner_user_a", "owner_env_shared"), "plugini_shared", strings.Repeat("a", 64)},
				{registryTestContextFor("owner_user_b", "owner_env_shared"), "plugini_shared", strings.Repeat("b", 64)},
				{registryTestContextFor("owner_user_a", "owner_env_other"), "plugini_shared", strings.Repeat("c", 64)},
				{registryTestContextFor("owner_user_a", "owner_env_shared"), "plugini_other", strings.Repeat("e", 64)},
			}
			for _, owner := range owners {
				if err := store.CreateObject(owner.ctx, sessionctx.ScopeUser, plugindata.Object{PluginInstanceID: owner.pluginInstanceID, ObjectID: "object_shared", ContentHash: owner.contentHash, ShapeHash: strings.Repeat("d", 64), SizeBytes: 1, CreatedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			for _, owner := range owners {
				object, found, err := store.GetObject(owner.ctx, sessionctx.ScopeUser, owner.pluginInstanceID, "object_shared")
				if err != nil || !found || object.ContentHash != owner.contentHash {
					t.Fatalf("scoped object = %#v, found=%v err=%v", object, found, err)
				}
				listed, next, err := store.ListObjects(owner.ctx, sessionctx.ScopeUser, owner.pluginInstanceID, "", 10)
				if err != nil || next != "" || len(listed) != 1 || listed[0].ContentHash != owner.contentHash {
					t.Fatalf("scoped object list = %#v next=%q err=%v", listed, next, err)
				}
			}
			maintained, next, err := store.ListAllObjectsForMaintenance(context.Background(), "", 10)
			if err != nil || next != "" || len(maintained) != len(owners) {
				t.Fatalf("maintenance objects = %#v next=%q err=%v", maintained, next, err)
			}
			contentByOwner := map[string]string{}
			for _, item := range maintained {
				if item.Scope.Kind != sessionctx.ScopeUser {
					t.Fatalf("maintenance object scope = %#v", item.Scope)
				}
				contentByOwner[item.Scope.OwnerEnvHash+"/"+item.Scope.OwnerUserHash+"/"+item.Object.PluginInstanceID] = item.Object.ContentHash
			}
			if !reflect.DeepEqual(contentByOwner, map[string]string{
				"owner_env_shared/owner_user_a/plugini_shared": strings.Repeat("a", 64),
				"owner_env_shared/owner_user_b/plugini_shared": strings.Repeat("b", 64),
				"owner_env_other/owner_user_a/plugini_shared":  strings.Repeat("c", 64),
				"owner_env_shared/owner_user_a/plugini_other":  strings.Repeat("e", 64),
			}) {
				t.Fatalf("maintenance object owners = %#v", contentByOwner)
			}
		})
	}
}

func TestStoreEnvironmentScopedObjectsShareOnlyWithinEnvironment(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			ctxA := registryTestContextFor("owner_user_a", "owner_env_shared")
			ctxB := registryTestContextFor("owner_user_b", "owner_env_shared")
			ctxOther := registryTestContextFor("owner_user_a", "owner_env_other")
			object := plugindata.Object{PluginInstanceID: "plugini_environment", ObjectID: "object_shared", ContentHash: strings.Repeat("a", 64), ShapeHash: strings.Repeat("b", 64), SizeBytes: 1, CreatedAt: time.Now()}
			if err := store.CreateObject(ctxA, sessionctx.ScopeEnvironment, object); err != nil {
				t.Fatal(err)
			}
			got, found, err := store.GetObject(ctxB, sessionctx.ScopeEnvironment, object.PluginInstanceID, object.ObjectID)
			if err != nil || !found || got.ContentHash != object.ContentHash {
				t.Fatalf("same environment object = %#v, found=%v err=%v", got, found, err)
			}
			if _, found, err := store.GetObject(ctxOther, sessionctx.ScopeEnvironment, object.PluginInstanceID, object.ObjectID); err != nil || found {
				t.Fatalf("other environment found=%v err=%v", found, err)
			}
			if _, found, err := store.GetObject(ctxA, sessionctx.ScopeUser, object.PluginInstanceID, object.ObjectID); err != nil || found {
				t.Fatalf("user scope found=%v err=%v", found, err)
			}
			maintained, next, err := store.ListAllObjectsForMaintenance(context.Background(), "", 10)
			if err != nil || next != "" || len(maintained) != 1 || maintained[0].Scope.Kind != sessionctx.ScopeEnvironment {
				t.Fatalf("maintenance objects = %#v next=%q err=%v", maintained, next, err)
			}
		})
	}
}

func TestSQLiteOwnerScopeMigrationFailsClosedForLegacyData(t *testing.T) {
	for _, populatedTable := range []string{"plugin_records", "plugin_permission_grants", "plugin_security_policies", "plugin_data_bindings", "plugin_data_objects"} {
		t.Run(populatedTable, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.sqlite")
			createLegacyOwnerSchema(t, path, populatedTable)
			store, err := NewSQLiteStore(context.Background(), path)
			if store != nil {
				_ = store.Close()
			}
			if !errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired) {
				t.Fatalf("NewSQLiteStore() error = %v, want owner migration required", err)
			}
		})
	}
}

func TestSQLiteObjectPluginScopeMigrationFailsClosedForExistingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE plugin_data_objects (
		owner_env_hash TEXT NOT NULL,
		owner_user_hash TEXT NOT NULL,
		object_id TEXT NOT NULL,
		PRIMARY KEY(owner_env_hash, owner_user_hash, object_id)
	)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO plugin_data_objects VALUES ('owner_env', 'owner_user', 'object_legacy')`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(context.Background(), path)
	if store != nil {
		_ = store.Close()
	}
	if !errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired) {
		t.Fatalf("NewSQLiteStore() error = %v, want owner migration required", err)
	}
}

func TestSQLiteOwnerScopeMigrationRebuildsEmptyLegacyTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	createLegacyOwnerSchema(t, path, "")
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := putOwnerPlugin(t, store, registryTestContextFor("owner_user_a", "owner_env_a"), "plugini_migrated", "1.0.0")
	if record.OwnerEnvHash != "owner_env_a" {
		t.Fatalf("migrated record owner = %q", record.OwnerEnvHash)
	}
}

func TestSQLiteOwnerScopeMigrationRebuildsEmptyLegacyTableBesideOwnedData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	ctx := registryTestContextFor("owner_user_a", "owner_env_a")
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	putOwnerPlugin(t, store, ctx, "plugini_preserved", "1.0.0")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE plugin_data_objects`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE plugin_data_objects (object_id TEXT PRIMARY KEY)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	record, err := reopened.GetPlugin(ctx, "plugini_preserved")
	if err != nil {
		t.Fatal(err)
	}
	if record.OwnerEnvHash != "owner_env_a" {
		t.Fatalf("preserved owner = %q", record.OwnerEnvHash)
	}
	if err := reopened.CreateObject(ctx, sessionctx.ScopeUser, plugindata.Object{PluginInstanceID: "plugini_preserved", ObjectID: "object_owned", ContentHash: strings.Repeat("a", 64), ShapeHash: strings.Repeat("b", 64), SizeBytes: 1, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func putOwnerPlugin(t *testing.T, store Store, ctx context.Context, instanceID, version string) PluginRecord {
	t.Helper()
	record, err := store.PutPlugin(ctx, PluginRecord{
		PluginInstanceID:  instanceID,
		PublisherID:       "example",
		PluginID:          "com.example.owner",
		Version:           version,
		ActiveFingerprint: "sha256:" + version,
		TrustState:        TrustVerified,
		EnableState:       EnableDisabled,
		Manifest: manifest.Manifest{
			Publisher: manifest.Publisher{PublisherID: "example"},
			Plugin:    manifest.Plugin{PluginID: "com.example.owner", Version: version},
		},
	}, PutOptions{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func createLegacyOwnerSchema(t *testing.T, path, populatedTable string) {
	t.Helper()
	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	statements := []string{
		`CREATE TABLE plugin_records (plugin_instance_id TEXT PRIMARY KEY)`,
		`CREATE TABLE plugin_permission_grants (plugin_instance_id TEXT NOT NULL, permission_id TEXT NOT NULL, PRIMARY KEY(plugin_instance_id, permission_id))`,
		`CREATE TABLE plugin_security_policies (plugin_instance_id TEXT PRIMARY KEY)`,
		`CREATE TABLE plugin_data_bindings (plugin_instance_id TEXT PRIMARY KEY)`,
		`CREATE TABLE plugin_data_objects (object_id TEXT PRIMARY KEY)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	inserts := map[string]string{
		"plugin_records":           `INSERT INTO plugin_records VALUES ('plugini_legacy')`,
		"plugin_permission_grants": `INSERT INTO plugin_permission_grants VALUES ('plugini_legacy', 'documents.read')`,
		"plugin_security_policies": `INSERT INTO plugin_security_policies VALUES ('plugini_legacy')`,
		"plugin_data_bindings":     `INSERT INTO plugin_data_bindings VALUES ('plugini_legacy')`,
		"plugin_data_objects":      `INSERT INTO plugin_data_objects VALUES ('object_legacy')`,
	}
	if statement := inserts[populatedTable]; statement != "" {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}
