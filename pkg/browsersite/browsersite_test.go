package browsersite

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
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

type recordingCleaner struct {
	origins []string
	err     error
}

func (c *recordingCleaner) ClearOriginData(_ context.Context, origin string) error {
	c.origins = append(c.origins, origin)
	return c.err
}
