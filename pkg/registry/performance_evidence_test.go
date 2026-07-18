package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/performanceevidence"
	"github.com/floegence/redevplugin/pkg/permissions"
)

func TestPerformanceSQLiteAuthorizationGrantScaling(t *testing.T) {
	const samples = 500
	ctx := registryTestContext()
	smallStore, smallRequest := newAuthorizationScalingPerformanceStore(t, 1, "small")
	largeStore, largeRequest := newAuthorizationScalingPerformanceStore(t, 1_000, "large")
	for range 20 {
		assertPerformanceAuthorization(t, ctx, smallStore, smallRequest)
		assertPerformanceAuthorization(t, ctx, largeStore, largeRequest)
	}
	smallDurations := make([]time.Duration, 0, samples)
	largeDurations := make([]time.Duration, 0, samples)
	for range samples {
		started := time.Now()
		assertPerformanceAuthorization(t, ctx, smallStore, smallRequest)
		smallDurations = append(smallDurations, time.Since(started))
		started = time.Now()
		assertPerformanceAuthorization(t, ctx, largeStore, largeRequest)
		largeDurations = append(largeDurations, time.Since(started))
	}
	smallP95 := performanceevidence.P95(smallDurations)
	largeP95 := performanceevidence.P95(largeDurations)
	relative, err := performanceevidence.RelativeBasisPoints(float64(largeP95), float64(smallP95))
	if err != nil {
		t.Fatal(err)
	}
	if performanceevidence.EnforceThresholds() && relative > 20_000 {
		t.Fatalf("1000-grant authorization p95 %s versus 1-grant p95 %s = %.2f basis points, want <= 20000", largeP95, smallP95, relative)
	}
	if err := performanceevidence.Record(os.Getenv("REDEVPLUGIN_PERFORMANCE_MEASUREMENTS"), performanceevidence.Scenario{
		ID:          "registry.sqlite-authorization-scaling",
		Gate:        performanceevidence.Gate(),
		SampleCount: samples,
		Metrics: []performanceevidence.Metric{
			{Name: "p95_1000_grants_relative_to_1", Unit: "basis_points", Observed: relative, Limit: 20_000, Comparator: "lte"},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func newAuthorizationScalingPerformanceStore(t *testing.T, grantCount int, suffix string) (*SQLiteStore, AuthorizeRequest) {
	t.Helper()
	ctx := registryTestContext()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close registry performance store: %v", err)
		}
	})
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	pluginInstanceID := "plugini_authorization_performance_" + suffix
	plugin, err := store.PutPlugin(ctx, authorizationTestPlugin(pluginInstanceID, "com.example.authorization-performance-"+suffix), PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < grantCount; index++ {
		permissionID := fmt.Sprintf("permission.%04d", index)
		if err := upsertSQLitePermissionGrant(ctx, tx, plugin.OwnerEnvHash, permissions.Record{
			PluginInstanceID: plugin.PluginInstanceID,
			PermissionID:     permissionID,
			Effect:           permissions.EffectGrant,
			GrantedBy:        "performance-evidence",
			GrantedAt:        now,
		}); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return store, AuthorizeRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		Method:           "documents.get",
		PermissionIDs:    []string{"permission.0000"},
		Expected:         AuthorizationRevisionsFromRecord(plugin),
		Now:              now.Add(time.Minute),
	}
}

func assertPerformanceAuthorization(t *testing.T, ctx context.Context, store *SQLiteStore, request AuthorizeRequest) {
	t.Helper()
	decision, err := store.Authorize(ctx, request)
	if err != nil || !decision.Allowed {
		t.Fatalf("Authorize() decision=%#v err=%v", decision, err)
	}
}
