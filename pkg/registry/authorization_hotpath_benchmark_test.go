package registry

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/security"
)

func BenchmarkAuthorizationCrossPlugin(b *testing.B) {
	for _, backend := range []string{"memory", "sqlite"} {
		b.Run(backend, func(b *testing.B) {
			b.Run("authorize_sequential", func(b *testing.B) {
				store, snapshots := newAuthorizationBenchmarkStore(b, backend)
				benchmarkAuthorizeSequential(b, store, snapshots)
			})
			b.Run("authorize_parallel", func(b *testing.B) {
				store, snapshots := newAuthorizationBenchmarkStore(b, backend)
				benchmarkAuthorizeParallel(b, store, snapshots)
			})
			b.Run("policy_mutation_sequential", func(b *testing.B) {
				store, snapshots := newAuthorizationBenchmarkStore(b, backend)
				benchmarkPolicyMutationSequential(b, store, snapshots)
			})
			b.Run("policy_mutation_parallel", func(b *testing.B) {
				store, snapshots := newAuthorizationBenchmarkStore(b, backend)
				benchmarkPolicyMutationParallel(b, store, snapshots)
			})
		})
	}
}

func BenchmarkListAuthorizationSQLite(b *testing.B) {
	for _, pluginCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("plugins_%d", pluginCount), func(b *testing.B) {
			ctx := context.Background()
			store, err := NewSQLiteStore(ctx, filepath.Join(b.TempDir(), "registry.sqlite"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = store.Close() })
			now := time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC)
			for index := 0; index < pluginCount; index++ {
				pluginInstanceID := fmt.Sprintf("plugini_list_%04d", index)
				pluginID := fmt.Sprintf("com.example.list-%04d", index)
				plugin, err := store.PutPlugin(ctx, authorizationTestPlugin(pluginInstanceID, pluginID), PutOptions{Now: now})
				if err != nil {
					b.Fatal(err)
				}
				snapshot, err := store.GrantPermission(ctx, permissions.GrantRequest{
					PluginInstanceID: pluginInstanceID,
					PermissionID:     "documents.read",
					GrantedBy:        "benchmark",
					Now:              now.Add(time.Second),
				}, AuthorizationRevisionsFromRecord(plugin))
				if err != nil {
					b.Fatal(err)
				}
				if index%2 == 0 {
					if _, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
						PluginInstanceID:   pluginInstanceID,
						AllowedPermissions: []string{"documents.read"},
						DeniedMethods:      []string{"documents.delete"},
						Now:                now.Add(2 * time.Second),
					}, AuthorizationRevisionsFromRecord(snapshot.Plugin)); err != nil {
						b.Fatal(err)
					}
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				snapshots, err := store.ListAuthorization(ctx)
				if err != nil || len(snapshots) != pluginCount {
					b.Fatalf("ListAuthorization() snapshots=%d err=%v", len(snapshots), err)
				}
			}
		})
	}
}

func newAuthorizationBenchmarkStore(b *testing.B, backend string) (Store, []AuthorizationSnapshot) {
	b.Helper()
	ctx := context.Background()
	var store Store
	if backend == "memory" {
		store = NewMemoryStore()
	} else {
		sqliteStore, err := NewSQLiteStore(ctx, filepath.Join(b.TempDir(), "registry.sqlite"))
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = sqliteStore.Close() })
		store = sqliteStore
	}

	pluginCount := max(16, runtime.GOMAXPROCS(0)*2)
	snapshots := make([]AuthorizationSnapshot, pluginCount)
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	for i := range snapshots {
		pluginInstanceID := fmt.Sprintf("plugini_bench_%03d", i)
		pluginID := fmt.Sprintf("com.example.bench-%03d", i)
		plugin, err := store.PutPlugin(ctx, authorizationTestPlugin(pluginInstanceID, pluginID), PutOptions{Now: now})
		if err != nil {
			b.Fatal(err)
		}
		snapshot, err := store.GrantPermission(ctx, permissions.GrantRequest{
			PluginInstanceID: pluginInstanceID,
			PermissionID:     "documents.read",
			GrantedBy:        "benchmark",
			Now:              now.Add(time.Second),
		}, AuthorizationRevisionsFromRecord(plugin))
		if err != nil {
			b.Fatal(err)
		}
		snapshots[i] = snapshot
	}
	return store, snapshots
}

func benchmarkAuthorizeSequential(b *testing.B, store Store, snapshots []AuthorizationSnapshot) {
	b.Helper()
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 1, 0, 0, time.UTC)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snapshot := snapshots[i%len(snapshots)]
		decision, err := store.Authorize(ctx, AuthorizeRequest{
			PluginInstanceID: snapshot.Plugin.PluginInstanceID,
			Method:           "documents.get",
			PermissionIDs:    []string{"documents.read"},
			Expected:         AuthorizationRevisionsFromRecord(snapshot.Plugin),
			Now:              now,
		})
		if err != nil || !decision.Allowed {
			b.Fatalf("Authorize() decision = %#v, err = %v", decision, err)
		}
	}
}

func benchmarkAuthorizeParallel(b *testing.B, store Store, snapshots []AuthorizationSnapshot) {
	b.Helper()
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 1, 0, 0, time.UTC)
	var workerID atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		id := int(workerID.Add(1)-1) % len(snapshots)
		snapshot := snapshots[id]
		for pb.Next() {
			decision, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: snapshot.Plugin.PluginInstanceID,
				Method:           "documents.get",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(snapshot.Plugin),
				Now:              now,
			})
			if err != nil || !decision.Allowed {
				b.Fatalf("Authorize() decision = %#v, err = %v", decision, err)
			}
		}
	})
}

func benchmarkPolicyMutationSequential(b *testing.B, store Store, snapshots []AuthorizationSnapshot) {
	b.Helper()
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 2, 0, 0, time.UTC)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % len(snapshots)
		snapshot, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
			PluginInstanceID:   snapshots[index].Plugin.PluginInstanceID,
			AllowedPermissions: []string{"documents.read"},
			DeniedMethods:      []string{"documents.delete"},
			Now:                now,
		}, AuthorizationRevisionsFromRecord(snapshots[index].Plugin))
		if err != nil {
			b.Fatal(err)
		}
		snapshots[index] = snapshot
	}
}

func benchmarkPolicyMutationParallel(b *testing.B, store Store, snapshots []AuthorizationSnapshot) {
	b.Helper()
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 2, 0, 0, time.UTC)
	var workerID atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		id := int(workerID.Add(1)-1) % len(snapshots)
		snapshot := snapshots[id]
		for pb.Next() {
			var err error
			snapshot, err = store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
				PluginInstanceID:   snapshot.Plugin.PluginInstanceID,
				AllowedPermissions: []string{"documents.read"},
				DeniedMethods:      []string{"documents.delete"},
				Now:                now,
			}, AuthorizationRevisionsFromRecord(snapshot.Plugin))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
