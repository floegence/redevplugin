package controlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestSelectedResourcesMigratesExactReleasedSchemaAndPreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	sqlBytes, err := os.ReadFile("testdata/schema1.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO control_metadata VALUES('migration-test','preserved')"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	for range 2 {
		store, err := Open(context.Background(), Config{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		var version int
		if err := store.db.QueryRow("SELECT version FROM control_schema WHERE id=1").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version != 2 {
			t.Fatalf("schema version=%d, want 2", version)
		}
		var data string
		if err := store.db.QueryRow("SELECT value_json FROM control_metadata WHERE key='migration-test'").Scan(&data); err != nil || data != "preserved" {
			t.Fatalf("preserved=%q err=%v", data, err)
		}
		var count int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM selected_file_resources").Scan(&count); err != nil || count != 0 {
			t.Fatalf("resource table count=%d err=%v", count, err)
		}
		store.Close()
	}
}

func selectedAuthorityFixture(t *testing.T) (*Store, SelectedResource, registry.AuthorizationRevisions) {
	t.Helper()
	ctx := pluginDataCatalogContext("selected-env", "selected-user")
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	record, binding, shape := freshPluginDataCatalogInstall(t, "selected-env", "plugini_selected")
	if _, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Registry().GetPlugin(ctx, "selected-env", record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	return store, SelectedResource{OwnerEnvHash: "selected-env", OwnerUserHash: "selected-user", PluginInstanceID: record.PluginInstanceID, ResourceID: "selected-one", ActiveFingerprint: snapshot.ActiveFingerprint, RevokeEpoch: snapshot.RevokeEpoch, Revision: 1, ExpiresAt: time.Now().Add(time.Hour).UnixNano(), RawJSON: json.RawMessage(`{"object":"host-only"}`)}, registry.AuthorizationRevisionsFromRecord(snapshot)
}

func TestSelectedRevocationWaitsForAdmittedOperation(t *testing.T) {
	store, resource, revisions := selectedAuthorityFixture(t)
	ctx := context.Background()
	if err := store.CreateSelectedResource(ctx, resource, revisions, time.Now()); err != nil {
		t.Fatal(err)
	}
	started, resume := make(chan struct{}), make(chan struct{})
	used, revoked := make(chan error, 1), make(chan error, 1)
	go func() {
		used <- store.WithSelectedResource(ctx, resource.Key(), time.Now(), func(SelectedResource) error { close(started); <-resume; return nil })
	}()
	<-started
	waitCount := store.db.Stats().WaitCount
	go func() { revoked <- store.RevokeSelectedResource(ctx, resource.Key(), 1, time.Now()) }()
	deadline := time.Now().Add(time.Second)
	for store.db.Stats().WaitCount == waitCount && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if store.db.Stats().WaitCount == waitCount {
		close(resume)
		if err := <-used; err != nil {
			t.Error(err)
		}
		if err := <-revoked; err != nil {
			t.Error(err)
		}
		t.Fatal("revocation did not wait for admitted operation")
	}
	select {
	case err := <-revoked:
		close(resume)
		if err := <-used; err != nil {
			t.Error(err)
		}
		t.Fatalf("revoked during operation: %v", err)
	default:
	}
	close(resume)
	if err := <-used; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if err := store.WithSelectedResource(ctx, resource.Key(), time.Now(), func(SelectedResource) error { t.Error("post-revoke operation admitted"); return nil }); err == nil {
		t.Fatal("revoked resource accepted")
	}
}

func TestSelectedResourceQuotaIsTransactionalAndHistoryBounded(t *testing.T) {
	store, resource, revisions := selectedAuthorityFixture(t)
	ctx, now := context.Background(), time.Now()
	for i := range 128 {
		resource.ResourceID = fmt.Sprintf("selected-%d", i)
		if err := store.CreateSelectedResource(ctx, resource, revisions, now); err != nil {
			t.Fatal(err)
		}
	}
	resource.ResourceID = "selected-overflow"
	if err := store.CreateSelectedResource(ctx, resource, revisions, now); err == nil {
		t.Fatal("129th active resource admitted")
	}
	for i := range 260 {
		resource.ResourceID = fmt.Sprintf("selected-history-%d", i)
		resource.ExpiresAt = now.Add(3 * time.Hour).UnixNano()
		if err := store.CreateSelectedResource(ctx, resource, revisions, now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeSelectedResource(ctx, resource.Key(), 1, now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.ListSelectedResources(ctx, resource.OwnerEnvHash, resource.OwnerUserHash, resource.PluginInstanceID)
	if err != nil || len(rows) > 256 {
		t.Fatalf("unbounded history: %d %v", len(rows), err)
	}
}

func TestSelectedResourceAuthorityIsOwnerBoundAndDoesNotReloadPlugin(t *testing.T) {
	ctx := pluginDataCatalogContext("selected-env", "selected-user")
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record, binding, shape := freshPluginDataCatalogInstall(t, "selected-env", "plugini_selected")
	if _, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Registry().GetPlugin(ctx, "selected-env", record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	expected := registry.AuthorizationRevisionsFromRecord(snapshot)
	resource := SelectedResource{OwnerEnvHash: "selected-env", OwnerUserHash: "selected-user", PluginInstanceID: record.PluginInstanceID, ResourceID: "selected-one", ActiveFingerprint: snapshot.ActiveFingerprint, RevokeEpoch: snapshot.RevokeEpoch, Revision: 1, ExpiresAt: time.Now().Add(time.Hour).UnixNano(), RawJSON: json.RawMessage(`{"object":"host-only"}`)}
	if err := store.CreateSelectedResource(ctx, resource, expected, time.Now()); err != nil {
		t.Fatal(err)
	}
	after, err := store.Registry().GetPlugin(ctx, "selected-env", record.PluginInstanceID)
	if err != nil || registry.AuthorizationRevisionsFromRecord(after) != expected {
		t.Fatalf("approval changed global authority: %+v, %v", after, err)
	}
	if err := store.CreateSelectedResource(ctx, resource, expected, time.Now()); err == nil {
		t.Fatal("duplicate resource accepted")
	}
	key := resource.Key()
	if err := store.WithSelectedResource(ctx, key, time.Now(), func(got SelectedResource) error {
		if got.Revision != 1 {
			t.Fatalf("revision %d", got.Revision)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wrong := key
	wrong.OwnerUserHash = "another-user"
	if err := store.WithSelectedResource(ctx, wrong, time.Now(), func(SelectedResource) error { t.Fatal("cross-owner access"); return nil }); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("cross-owner: %v", err)
	}
	if err := store.WithSelectedResource(ctx, key, time.Now().Add(2*time.Hour), func(SelectedResource) error { t.Fatal("expired access"); return nil }); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("expired: %v", err)
	}
	if err := store.RevokeSelectedResource(ctx, key, 2, time.Now()); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revoke: %v", err)
	}
	if err := store.RevokeSelectedResource(ctx, key, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeSelectedResource(ctx, key, 1, time.Now()); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if err := store.WithSelectedResource(ctx, key, time.Now(), func(SelectedResource) error { t.Fatal("revoked access"); return nil }); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestSelectedResourceMigrationRecoversInterruptedTransaction(t *testing.T) {
	if path := os.Getenv("REDEVPLUGIN_SELECTED_MIGRATION_CRASH"); path != "" {
		db := openControlTestDB(t, path)
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := migrateSelectedResources(context.Background(), tx); err != nil {
			t.Fatal(err)
		}
		os.Exit(73)
	}
	path := filepath.Join(t.TempDir(), "control.sqlite")
	db := openControlTestDB(t, path)
	source, err := os.ReadFile("testdata/schema1.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(source)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSelectedResourceMigrationRecoversInterruptedTransaction$")
	cmd.Env = append(os.Environ(), "REDEVPLUGIN_SELECTED_MIGRATION_CRASH="+path)
	var exited *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &exited) || exited.ExitCode() != 73 {
		t.Fatalf("crash child: %v", err)
	}
	for range 2 {
		store, err := Open(context.Background(), Config{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		var version int
		if err := store.db.QueryRow("SELECT version FROM control_schema WHERE id=1").Scan(&version); err != nil || version != 2 {
			t.Fatalf("recovered version %d: %v", version, err)
		}
		store.Close()
	}
}

func TestSelectedResourceMigrationRejectsDriftWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	db := openControlTestDB(t, path)
	source, err := os.ReadFile("testdata/schema1.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(source)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE selected_file_resources(untrusted TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrIncompatible) {
		if store != nil {
			store.Close()
		}
		t.Fatalf("drift: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected bytes changed: %v", err)
	}
}
