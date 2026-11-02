package plugindata

import (
	"context"
	"errors"
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
