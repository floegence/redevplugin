package retaineddata

import (
	"context"
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
				record.BrowserSiteRetained ||
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
			req.BrowserSiteRetained = false
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
