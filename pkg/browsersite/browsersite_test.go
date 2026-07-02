package browsersite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestMemoryStoreRegistersAndRetainsOrigins(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time { return now }})
	ctx := context.Background()

	record, err := store.RegisterOrigin(ctx, RegisterRequest{
		PluginInstanceID:  "plugini_1",
		PluginID:          "com.example.plugin",
		ActiveFingerprint: "sha256:active",
		SurfaceID:         "main",
		SurfaceInstanceID: "surface_1",
		Origin:            "https://plg-active.sandbox.redevplugin.local",
		OwnerSessionHash:  "owner_session",
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.State != StateActive || record.OriginKey == "" || record.LastSeenAt != now {
		t.Fatalf("registered record mismatch: %#v", record)
	}

	result, err := store.CleanupPluginOrigins(ctx, CleanupRequest{PluginInstanceID: "plugini_1", DeleteData: false, Reason: "uninstall_keep_data"})
	if err != nil {
		t.Fatalf("CleanupPluginOrigins(retain) error = %v", err)
	}
	if len(result.Records) != 1 || result.Records[0].State != StateRetained || result.Records[0].RetainedAt == nil {
		t.Fatalf("retained origins mismatch: %#v", result.Records)
	}
}

func TestMemoryStoreCleanupCallsCleanerAndRecordsFailure(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	cleaner := &recordingCleaner{}
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time { return now }, Cleaner: cleaner})
	ctx := context.Background()
	for _, origin := range []string{"https://plg-a.sandbox.redevplugin.local", "https://plg-b.sandbox.redevplugin.local"} {
		if _, err := store.RegisterOrigin(ctx, RegisterRequest{
			PluginInstanceID:  "plugini_1",
			ActiveFingerprint: "sha256:active",
			Origin:            origin,
		}); err != nil {
			t.Fatal(err)
		}
	}

	result, err := store.CleanupPluginOrigins(ctx, CleanupRequest{PluginInstanceID: "plugini_1", DeleteData: true, Reason: "delete_data"})
	if err != nil {
		t.Fatalf("CleanupPluginOrigins(delete) error = %v", err)
	}
	if !reflect.DeepEqual(cleaner.origins, []string{"https://plg-a.sandbox.redevplugin.local", "https://plg-b.sandbox.redevplugin.local"}) {
		t.Fatalf("cleaner origins = %#v", cleaner.origins)
	}
	if len(result.Records) != 2 || result.Records[0].State != StateCleanupComplete || result.Records[1].CleanedAt == nil {
		t.Fatalf("cleanup records mismatch: %#v", result.Records)
	}

	cleaner.err = errors.New("browser profile locked")
	if _, err := store.RegisterOrigin(ctx, RegisterRequest{
		PluginInstanceID:  "plugini_2",
		ActiveFingerprint: "sha256:active",
		Origin:            "https://plg-c.sandbox.redevplugin.local",
	}); err != nil {
		t.Fatal(err)
	}
	failed, err := store.CleanupPluginOrigins(ctx, CleanupRequest{PluginInstanceID: "plugini_2", DeleteData: true})
	if !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("CleanupPluginOrigins(fail) error = %v, want ErrCleanupFailed", err)
	}
	if len(failed.Records) != 1 || failed.Records[0].State != StateCleanupFailed || failed.Records[0].CleanupError == "" {
		t.Fatalf("failed cleanup record mismatch: %#v", failed.Records)
	}
}

func TestMemoryStoreRejectsInvalidOrigins(t *testing.T) {
	store := NewMemoryStore()
	for _, origin := range []string{"", "ftp://example.com", "https://example.com/path", "https://user@example.com"} {
		if _, err := store.RegisterOrigin(context.Background(), RegisterRequest{
			PluginInstanceID:  "plugini_1",
			ActiveFingerprint: "sha256:active",
			Origin:            origin,
		}); !errors.Is(err, ErrInvalidOrigin) {
			t.Fatalf("RegisterOrigin(%q) error = %v, want ErrInvalidOrigin", origin, err)
		}
	}
}

func TestSQLiteStorePersistsOriginsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "browser-site.sqlite")
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)

	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	record, err := store.RegisterOrigin(ctx, RegisterRequest{
		PluginInstanceID:  "plugini_1",
		PluginID:          "com.example.plugin",
		ActiveFingerprint: "sha256:active",
		SurfaceID:         "main",
		SurfaceInstanceID: "surface_1",
		Origin:            "https://plg-active.sandbox.redevplugin.local",
		OwnerSessionHash:  "owner_session",
		OwnerUserHash:     "owner_user",
		Now:               now,
	})
	if err != nil {
		t.Fatalf("RegisterOrigin() error = %v", err)
	}
	if record.State != StateActive || record.OriginKey == "" {
		t.Fatalf("registered record mismatch: %#v", record)
	}
	if _, err := store.CleanupPluginOrigins(ctx, CleanupRequest{
		PluginInstanceID: "plugini_1",
		DeleteData:       false,
		Reason:           "uninstall_keep_data",
		Now:              now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("CleanupPluginOrigins(retain) error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen NewSQLiteStore() error = %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close(reopened) error = %v", err)
		}
	}()
	records, err := reopened.ListOrigins(ctx, ListRequest{PluginInstanceID: "plugini_1"})
	if err != nil {
		t.Fatalf("ListOrigins() error = %v", err)
	}
	if len(records) != 1 ||
		records[0].State != StateRetained ||
		records[0].RetainedAt == nil ||
		records[0].OwnerSessionHash != "owner_session" ||
		records[0].OwnerUserHash != "owner_user" {
		t.Fatalf("reopened records mismatch: %#v", records)
	}
}

func TestSQLiteStoreCleanupCallsCleanerAndPersistsFailure(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "browser-site.sqlite")
	cleaner := &recordingCleaner{}
	store, err := NewSQLiteStore(ctx, path, SQLiteStoreOptions{Cleaner: cleaner})
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	for _, origin := range []string{"https://plg-a.sandbox.redevplugin.local", "https://plg-b.sandbox.redevplugin.local"} {
		if _, err := store.RegisterOrigin(ctx, RegisterRequest{
			PluginInstanceID:  "plugini_1",
			ActiveFingerprint: "sha256:active",
			Origin:            origin,
		}); err != nil {
			t.Fatal(err)
		}
	}

	result, err := store.CleanupPluginOrigins(ctx, CleanupRequest{PluginInstanceID: "plugini_1", DeleteData: true, Reason: "delete_data"})
	if err != nil {
		t.Fatalf("CleanupPluginOrigins(delete) error = %v", err)
	}
	if !reflect.DeepEqual(cleaner.origins, []string{"https://plg-a.sandbox.redevplugin.local", "https://plg-b.sandbox.redevplugin.local"}) {
		t.Fatalf("cleaner origins = %#v", cleaner.origins)
	}
	if len(result.Records) != 2 || result.Records[0].State != StateCleanupComplete || result.Records[1].CleanedAt == nil {
		t.Fatalf("cleanup records mismatch: %#v", result.Records)
	}

	cleaner.err = errors.New("browser profile locked")
	if _, err := store.RegisterOrigin(ctx, RegisterRequest{
		PluginInstanceID:  "plugini_2",
		ActiveFingerprint: "sha256:active",
		Origin:            "https://plg-c.sandbox.redevplugin.local",
	}); err != nil {
		t.Fatal(err)
	}
	failed, err := store.CleanupPluginOrigins(ctx, CleanupRequest{PluginInstanceID: "plugini_2", DeleteData: true})
	if !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("CleanupPluginOrigins(fail) error = %v, want ErrCleanupFailed", err)
	}
	if len(failed.Records) != 1 || failed.Records[0].State != StateCleanupFailed || failed.Records[0].CleanupError == "" {
		t.Fatalf("failed cleanup record mismatch: %#v", failed.Records)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen NewSQLiteStore() error = %v", err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatalf("Close(reopened) error = %v", err)
		}
	}()
	records, err := reopened.ListOrigins(ctx, ListRequest{PluginInstanceID: "plugini_2"})
	if err != nil {
		t.Fatalf("ListOrigins(failed) error = %v", err)
	}
	if len(records) != 1 || records[0].State != StateCleanupFailed || records[0].CleanupError != "browser profile locked" {
		t.Fatalf("persisted failed cleanup mismatch: %#v", records)
	}
}

func TestSQLiteStoreRequireRetainedBeforeDelete(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "browser-site.sqlite"), SQLiteStoreOptions{Cleaner: &recordingCleaner{}})
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()
	if _, err := store.RegisterOrigin(ctx, RegisterRequest{
		PluginInstanceID:  "plugini_1",
		ActiveFingerprint: "sha256:active",
		Origin:            "https://plg-a.sandbox.redevplugin.local",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CleanupPluginOrigins(ctx, CleanupRequest{
		PluginInstanceID: "plugini_1",
		DeleteData:       true,
		RequireRetained:  true,
	}); !errors.Is(err, ErrOriginNotRetained) {
		t.Fatalf("CleanupPluginOrigins(require retained active) error = %v, want ErrOriginNotRetained", err)
	}
}

func TestSQLiteStoreRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser-site.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE plugin_browser_site_schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO plugin_browser_site_schema_migrations(version, applied_at) VALUES(999, 1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = NewSQLiteStore(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("NewSQLiteStore() error = %v, want newer schema", err)
	}
}

type recordingCleaner struct {
	origins []string
	err     error
}

func (c *recordingCleaner) ClearOriginData(_ context.Context, origin string) error {
	c.origins = append(c.origins, origin)
	return c.err
}
