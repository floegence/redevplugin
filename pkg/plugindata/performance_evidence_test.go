package plugindata

import (
	"os"
	"testing"

	"github.com/floegence/redevplugin/internal/performanceevidence"
)

func TestPerformanceNamespaceDatabaseWarmCacheAllocations(t *testing.T) {
	const samples = 100
	ctx := internalTestContext()
	root := t.TempDir()
	if err := initializeNamespaceDatabase(ctx, root, NamespaceKV); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	store := &FileStore{namespaceDB: map[string]*namespaceDBEntry{}, namespaceDBWake: make(chan struct{})}
	t.Cleanup(func() {
		if err := store.closeNamespaceDatabases(""); err != nil {
			t.Errorf("close namespace databases: %v", err)
		}
	})
	const key = "generation\x00kv\x00kv"
	_, _, release, err := store.acquireNamespaceDatabase(ctx, key, root, rootInfo)
	if err != nil {
		t.Fatal(err)
	}
	release()

	var measuredErr error
	warmAllocs := testing.AllocsPerRun(samples, func() {
		db, _, releaseDB, err := store.acquireNamespaceDatabase(ctx, key, root, rootInfo)
		if err == nil {
			err = db.QueryRowContext(ctx, `SELECT 1`).Scan(new(int))
		}
		releaseDB()
		if err != nil && measuredErr == nil {
			measuredErr = err
		}
	})
	if measuredErr != nil {
		t.Fatal(measuredErr)
	}

	uncachedAllocs := testing.AllocsPerRun(samples, func() {
		db, err := openNamespaceDatabase(ctx, root, false)
		if err == nil {
			err = db.QueryRowContext(ctx, `SELECT 1`).Scan(new(int))
		}
		if db != nil {
			if closeErr := db.Close(); err == nil {
				err = closeErr
			}
		}
		if err != nil && measuredErr == nil {
			measuredErr = err
		}
	})
	if measuredErr != nil {
		t.Fatal(measuredErr)
	}
	relative, err := performanceevidence.RelativeBasisPoints(warmAllocs, uncachedAllocs)
	if err != nil {
		t.Fatal(err)
	}
	if performanceevidence.EnforceThresholds() && relative > 3_000 {
		t.Fatalf("warm namespace allocations %.2f versus uncached %.2f = %.2f basis points, want <= 3000", warmAllocs, uncachedAllocs, relative)
	}
	if err := performanceevidence.Record(os.Getenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"), performanceevidence.Scenario{
		ID:          "plugindata.namespace-cache-warm",
		Gate:        performanceevidence.Gate(),
		SampleCount: samples,
		Metrics: []performanceevidence.Metric{
			{Name: "relative_allocations", Unit: "basis_points", Observed: relative, Limit: 3_000, Comparator: "lte"},
		},
	}); err != nil {
		t.Fatal(err)
	}
}
