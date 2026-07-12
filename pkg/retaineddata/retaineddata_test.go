package retaineddata

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStoreRetainTouchBindAndDelete(t *testing.T) {
	for _, tc := range storeCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 2, 16, 0, 0, 0, time.UTC)
			record, err := store.Retain(ctx, fixtureRetainRequest("retained_bind", now))
			if err != nil {
				t.Fatalf("Retain() error = %v", err)
			}
			if record.State != StateRetained ||
				!record.StorageRetained ||
				!record.SettingsRetained ||
				record.UsageBytes != 4096 ||
				record.DeleteAfter == nil ||
				!reflect.DeepEqual(record.Metadata, map[string]string{"reason": "uninstall_keep_data"}) {
				t.Fatalf("retained record mismatch: %#v", record)
			}

			touchedAt := now.Add(time.Minute)
			touched, err := store.Touch(ctx, TouchRequest{RetainedID: record.RetainedID, Now: touchedAt})
			if err != nil {
				t.Fatalf("Touch() error = %v", err)
			}
			if touched.LastAccessedAt == nil || !touched.LastAccessedAt.Equal(touchedAt) {
				t.Fatalf("touch mismatch: %#v", touched)
			}

			boundAt := now.Add(2 * time.Minute)
			bound, err := store.MarkBound(ctx, BindRequest{
				RetainedID:            record.RetainedID,
				BoundPluginInstanceID: "plugini_new",
				Now:                   boundAt,
			})
			if err != nil {
				t.Fatalf("MarkBound() error = %v", err)
			}
			if bound.State != StateBound || bound.BoundPluginInstanceID != "plugini_new" || bound.BoundAt == nil || !bound.BoundAt.Equal(boundAt) {
				t.Fatalf("bound record mismatch: %#v", bound)
			}

			again, err := store.MarkDeleted(ctx, DeleteRequest{RetainedID: record.RetainedID, Now: now.Add(3 * time.Minute)})
			if err != nil {
				t.Fatalf("MarkDeleted(bound) error = %v", err)
			}
			if again.State != StateBound || again.DeletedAt != nil {
				t.Fatalf("bound record was deleted: %#v", again)
			}

			listed, err := store.List(ctx, ListRequest{PublisherID: record.PublisherID, PluginID: record.PluginID, State: StateBound})
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if len(listed) != 1 || listed[0].RetainedID != record.RetainedID {
				t.Fatalf("List() mismatch: %#v", listed)
			}
			if err := store.Delete(ctx, record.RetainedID); err != nil {
				t.Fatalf("Delete() error = %v", err)
			}
			if _, err := store.Get(ctx, record.RetainedID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get(after delete) error = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestStoreExpireDeleteFailureAndDeleteSuccess(t *testing.T) {
	for _, tc := range storeCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 2, 17, 0, 0, 0, time.UTC)
			expiring, err := store.Retain(ctx, fixtureRetainRequest("retained_expire", now))
			if err != nil {
				t.Fatal(err)
			}
			nonExpiringReq := fixtureRetainRequest("retained_keep", now)
			nonExpiringReq.DeleteAfter = nil
			nonExpiring, err := store.Retain(ctx, nonExpiringReq)
			if err != nil {
				t.Fatal(err)
			}

			expired, err := store.ExpireBefore(ctx, now.Add(2*time.Hour))
			if err != nil {
				t.Fatalf("ExpireBefore() error = %v", err)
			}
			if len(expired) != 1 || expired[0].RetainedID != expiring.RetainedID || expired[0].State != StateExpired {
				t.Fatalf("ExpireBefore() mismatch: %#v", expired)
			}
			stillExpired, err := store.MarkBound(ctx, BindRequest{
				RetainedID:            expiring.RetainedID,
				BoundPluginInstanceID: "plugini_late",
				Now:                   now.Add(2*time.Hour + time.Minute),
			})
			if err != nil {
				t.Fatalf("MarkBound(expired) error = %v", err)
			}
			if stillExpired.State != StateExpired || stillExpired.BoundPluginInstanceID != "" {
				t.Fatalf("expired record was rebound: %#v", stillExpired)
			}
			stillRetained, err := store.Get(ctx, nonExpiring.RetainedID)
			if err != nil {
				t.Fatal(err)
			}
			if stillRetained.State != StateRetained {
				t.Fatalf("non-expiring record changed: %#v", stillRetained)
			}

			failedAt := now.Add(3 * time.Hour)
			failed, err := store.MarkDeleteFailed(ctx, DeleteFailedRequest{
				RetainedID:  expiring.RetainedID,
				DeleteError: "storage cleanup failed",
				Now:         failedAt,
			})
			if err != nil {
				t.Fatalf("MarkDeleteFailed() error = %v", err)
			}
			if failed.State != StateDeleteFailedRetryable || failed.DeleteError != "storage cleanup failed" || !failed.UpdatedAt.Equal(failedAt) {
				t.Fatalf("delete failed record mismatch: %#v", failed)
			}

			deletedAt := now.Add(4 * time.Hour)
			deleted, err := store.MarkDeleted(ctx, DeleteRequest{RetainedID: expiring.RetainedID, Now: deletedAt})
			if err != nil {
				t.Fatalf("MarkDeleted() error = %v", err)
			}
			if deleted.State != StateDeleted || deleted.DeletedAt == nil || !deleted.DeletedAt.Equal(deletedAt) || deleted.DeleteError != "" {
				t.Fatalf("deleted record mismatch: %#v", deleted)
			}
		})
	}
}

func TestStoreRejectsInvalidRequests(t *testing.T) {
	for _, tc := range storeCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			if _, err := store.Retain(context.Background(), RetainRequest{}); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Retain() error = %v, want ErrInvalidRecord", err)
			}
			now := time.Date(2026, 7, 2, 18, 0, 0, 0, time.UTC)
			req := fixtureRetainRequest("retained_invalid", now)
			req.StorageRetained = false
			req.SettingsRetained = false
			if _, err := store.Retain(context.Background(), req); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Retain(no data) error = %v, want ErrInvalidRecord", err)
			}
			req = fixtureRetainRequest("retained_invalid_usage", now)
			req.UsageBytes = -1
			if _, err := store.Retain(context.Background(), req); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Retain(negative usage) error = %v, want ErrInvalidRecord", err)
			}
			if _, err := store.Get(context.Background(), " "); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Get() error = %v, want ErrInvalidRecord", err)
			}
			if _, err := store.MarkBound(context.Background(), BindRequest{}); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("MarkBound() error = %v, want ErrInvalidRecord", err)
			}
			if _, err := store.List(context.Background(), ListRequest{State: "bad"}); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("List() error = %v, want ErrInvalidRecord", err)
			}
			if err := store.Delete(context.Background(), " "); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Delete() error = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

func TestNewRetainedID(t *testing.T) {
	first, err := NewRetainedID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRetainedID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "retained_") || len(first) != len("retained_")+32 {
		t.Fatalf("unexpected retained ids: %q %q", first, second)
	}
}

func TestSQLiteStorePersistsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "retained-data.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 2, 19, 0, 0, 0, time.UTC)
	record, err := store.Retain(ctx, fixtureRetainRequest("retained_persist", now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Touch(ctx, TouchRequest{RetainedID: record.RetainedID, Now: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	got, err := reopened.Get(ctx, record.RetainedID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateRetained ||
		got.LastAccessedAt == nil ||
		!got.LastAccessedAt.Equal(now.Add(time.Minute)) ||
		!reflect.DeepEqual(got.Metadata, map[string]string{"reason": "uninstall_keep_data"}) {
		t.Fatalf("persisted record mismatch: %#v", got)
	}
}

func TestSQLiteStoreRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "retained-data.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT OR REPLACE INTO plugin_retained_data_schema_migrations(version, applied_at) VALUES(999, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(ctx, path); err == nil {
		t.Fatal("NewSQLiteStore() accepted newer schema version")
	}
}

func TestSQLiteStoreMigratesBrowserSiteRowsToV2(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "retained-data.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacySchema := `
CREATE TABLE plugin_retained_data_schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
INSERT INTO plugin_retained_data_schema_migrations(version, applied_at) VALUES(1, 1);
CREATE TABLE plugin_retained_data_records (
	retained_id TEXT PRIMARY KEY,
	source_plugin_instance_id TEXT NOT NULL,
	bound_plugin_instance_id TEXT NOT NULL,
	publisher_id TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	version TEXT NOT NULL,
	package_hash TEXT NOT NULL,
	manifest_hash TEXT NOT NULL,
	state TEXT NOT NULL,
	storage_retained INTEGER NOT NULL,
	settings_retained INTEGER NOT NULL,
	browser_site_retained INTEGER NOT NULL,
	usage_bytes INTEGER NOT NULL,
	delete_after INTEGER,
	delete_error TEXT NOT NULL,
	metadata_json TEXT NOT NULL,
	retained_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	bound_at INTEGER,
	deleted_at INTEGER,
	last_accessed_at INTEGER
);
INSERT INTO plugin_retained_data_records VALUES
	('retained_mixed','old_mixed','','com.example','com.example.plugin','1.0.0','sha256:p','sha256:m','retained',1,0,1,10,NULL,'','{}',1,1,NULL,NULL,NULL),
	('retained_browser_only','old_browser','','com.example','com.example.plugin','1.0.0','sha256:p','sha256:m','retained',0,0,1,0,NULL,'','{}',1,1,NULL,NULL,NULL);`
	if _, err := db.ExecContext(ctx, legacySchema); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mixed, err := store.Get(ctx, "retained_mixed")
	if err != nil {
		t.Fatal(err)
	}
	if mixed.State != StateRetained || !mixed.StorageRetained || mixed.SettingsRetained {
		t.Fatalf("mixed retained row mismatch after migration: %#v", mixed)
	}
	browserOnly, err := store.Get(ctx, "retained_browser_only")
	if err != nil {
		t.Fatal(err)
	}
	if browserOnly.State != StateDeleted || browserOnly.DeletedAt == nil || browserOnly.StorageRetained || browserOnly.SettingsRetained {
		t.Fatalf("browser-only row was not closed during migration: %#v", browserOnly)
	}
	rows, err := store.db.QueryContext(ctx, `PRAGMA table_info(plugin_retained_data_records)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if name == "browser_site_retained" {
			t.Fatal("browser_site_retained column remained after v2 migration")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

type storeCase struct {
	name string
	open func(t *testing.T) Store
}

func storeCases() []storeCase {
	return []storeCase{
		{
			name: "memory",
			open: func(t *testing.T) Store {
				t.Helper()
				return NewMemoryStore()
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) Store {
				t.Helper()
				store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "retained-data.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = store.Close()
				})
				return store
			},
		},
	}
}

func fixtureRetainRequest(retainedID string, now time.Time) RetainRequest {
	deleteAfter := now.Add(time.Hour)
	return RetainRequest{
		RetainedID:             retainedID,
		SourcePluginInstanceID: "plugini_old",
		PublisherID:            "com.example",
		PluginID:               "com.example.retained",
		Version:                "1.2.3",
		PackageHash:            "sha256:package",
		ManifestHash:           "sha256:manifest",
		StorageRetained:        true,
		SettingsRetained:       true,
		UsageBytes:             4096,
		DeleteAfter:            &deleteAfter,
		Metadata: map[string]string{
			"reason": "uninstall_keep_data",
		},
		Now: now,
	}
}
