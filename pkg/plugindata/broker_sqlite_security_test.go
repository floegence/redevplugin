package plugindata

import (
	"context"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"path/filepath"
	"testing"
)

func TestSQLiteAdmissionBoundsAllNamespaces(t *testing.T) {
	store := &FileStore{sqliteOperations: make(chan struct{}, maxConcurrentSQLiteOperations)}
	releases := make([]func(), 0, maxConcurrentSQLiteOperations)
	for range maxConcurrentSQLiteOperations {
		release, err := store.acquireSQLiteOperation(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.acquireSQLiteOperation(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("full store admission = %v", err)
	}
	for _, release := range releases {
		release()
	}
	release, err := store.acquireSQLiteOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestSQLiteLimitErrorPreservesMutationOutcome(t *testing.T) {
	ctx := context.Background()
	db, err := openSQLiteDatabase(ctx, filepath.Join(t.TempDir(), "test.sqlite"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	var size int
	err = db.QueryRowContext(ctx, "SELECT length(format('%.*c',16777216,'x'))").Scan(&size)
	if err == nil {
		t.Fatal("expression limit was not enforced")
	}
	mapped := sqliteBrokerError(mutation.Unknown(err))
	if !errors.Is(mapped, storage.ErrSQLiteResultTooLarge) {
		t.Fatalf("limit error = %v", mapped)
	}
	if outcome, explicit := mutation.Explicit(mapped); !explicit || outcome != mutation.OutcomeUnknown {
		t.Fatalf("lost commit outcome: %q %v", outcome, explicit)
	}
}
