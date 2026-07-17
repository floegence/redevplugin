package registry

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/security"
)

func TestAuthorizationConcurrentCASMutations(t *testing.T) {
	const contenders = 8
	type mutationCase struct {
		name        string
		prepare     func(context.Context, *testing.T, Store, AuthorizationSnapshot, time.Time) AuthorizationSnapshot
		mutate      func(context.Context, Store, AuthorizationSnapshot, int, time.Time) error
		assertFinal func(*testing.T, AuthorizationSnapshot, AuthorizationSnapshot, int, time.Time)
	}

	mutationTime := func(now time.Time, contender int) time.Time {
		return now.Add(time.Duration(contender+1) * time.Second)
	}
	tests := []mutationCase{
		{
			name: "grant",
			mutate: func(ctx context.Context, store Store, before AuthorizationSnapshot, contender int, now time.Time) error {
				_, err := store.GrantPermission(ctx, permissions.GrantRequest{
					PluginInstanceID: before.Plugin.PluginInstanceID,
					PermissionID:     concurrentPermissionID(contender),
					GrantedBy:        "admin",
					Now:              mutationTime(now, contender),
				}, AuthorizationRevisionsFromRecord(before.Plugin))
				return err
			},
			assertFinal: func(t *testing.T, before AuthorizationSnapshot, final AuthorizationSnapshot, winner int, now time.Time) {
				t.Helper()
				assertConcurrentAuthorizationPlugin(t, before.Plugin, final.Plugin, 0, mutationTime(now, winner))
				grant, err := permissions.NewGrant(permissions.GrantRequest{
					PluginInstanceID: before.Plugin.PluginInstanceID,
					PermissionID:     concurrentPermissionID(winner),
					GrantedBy:        "admin",
					Now:              mutationTime(now, winner),
				})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(final.Grants, []permissions.Record{grant}) || final.Policy != nil {
					t.Fatalf("grant CAS final authorization = %#v, want only winner %#v", final, grant)
				}
			},
		},
		{
			name: "revoke",
			prepare: func(ctx context.Context, t *testing.T, store Store, before AuthorizationSnapshot, now time.Time) AuthorizationSnapshot {
				t.Helper()
				for contender := 0; contender < contenders; contender++ {
					var err error
					before, err = store.GrantPermission(ctx, permissions.GrantRequest{
						PluginInstanceID: before.Plugin.PluginInstanceID,
						PermissionID:     concurrentPermissionID(contender),
						GrantedBy:        "admin",
						Now:              now.Add(-time.Duration(contenders-contender) * time.Second),
					}, AuthorizationRevisionsFromRecord(before.Plugin))
					if err != nil {
						t.Fatal(err)
					}
				}
				return before
			},
			mutate: func(ctx context.Context, store Store, before AuthorizationSnapshot, contender int, now time.Time) error {
				_, err := store.RevokePermission(ctx, permissions.RevokeRequest{
					PluginInstanceID: before.Plugin.PluginInstanceID,
					PermissionID:     concurrentPermissionID(contender),
					RevokedBy:        "admin",
					Reason:           "concurrent revoke",
					Now:              mutationTime(now, contender),
				}, AuthorizationRevisionsFromRecord(before.Plugin))
				return err
			},
			assertFinal: func(t *testing.T, before AuthorizationSnapshot, final AuthorizationSnapshot, winner int, now time.Time) {
				t.Helper()
				assertConcurrentAuthorizationPlugin(t, before.Plugin, final.Plugin, 1, mutationTime(now, winner))
				wantGrants := make([]permissions.Record, len(before.Grants))
				for i, grant := range before.Grants {
					wantGrants[i] = permissions.CloneRecord(grant)
					if grant.PermissionID != concurrentPermissionID(winner) {
						continue
					}
					revoked, err := permissions.Revoke(grant, permissions.RevokeRequest{
						PluginInstanceID: before.Plugin.PluginInstanceID,
						PermissionID:     grant.PermissionID,
						RevokedBy:        "admin",
						Reason:           "concurrent revoke",
						Now:              mutationTime(now, winner),
					})
					if err != nil {
						t.Fatal(err)
					}
					wantGrants[i] = revoked
				}
				if !reflect.DeepEqual(final.Grants, wantGrants) || final.Policy != nil {
					t.Fatalf("revoke CAS final authorization = %#v, want grants %#v", final, wantGrants)
				}
			},
		},
		{
			name: "policy",
			prepare: func(ctx context.Context, t *testing.T, store Store, before AuthorizationSnapshot, now time.Time) AuthorizationSnapshot {
				t.Helper()
				after, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
					PluginInstanceID:   before.Plugin.PluginInstanceID,
					AllowedPermissions: []string{"documents.read"},
					DeniedMethods:      []string{"documents.delete"},
					Now:                now.Add(-time.Second),
				}, AuthorizationRevisionsFromRecord(before.Plugin))
				if err != nil {
					t.Fatal(err)
				}
				return after
			},
			mutate: func(ctx context.Context, store Store, before AuthorizationSnapshot, contender int, now time.Time) error {
				_, err := store.PutSecurityPolicy(ctx, concurrentPolicyRequest(before.Plugin.PluginInstanceID, contender, mutationTime(now, contender)), AuthorizationRevisionsFromRecord(before.Plugin))
				return err
			},
			assertFinal: func(t *testing.T, before AuthorizationSnapshot, final AuthorizationSnapshot, winner int, now time.Time) {
				t.Helper()
				assertConcurrentAuthorizationPlugin(t, before.Plugin, final.Plugin, 1, mutationTime(now, winner))
				wantPolicy, err := security.NewPolicy(concurrentPolicyRequest(before.Plugin.PluginInstanceID, winner, mutationTime(now, winner)))
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(final.Grants, before.Grants) || final.Policy == nil || !reflect.DeepEqual(*final.Policy, wantPolicy) {
					t.Fatalf("policy CAS final authorization = %#v, want policy %#v", final, wantPolicy)
				}
			},
		},
	}

	for _, test := range tests {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(test.name+"/"+backend, func(t *testing.T) {
				ctx := context.Background()
				now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
				store, sqliteStore, sqlitePath := openConcurrentAuthorizationStore(t, ctx, backend)
				plugin := putAuthorizationTestPlugin(t, store, "plugini_concurrent_"+test.name, "com.example.concurrent-"+test.name, now.Add(-time.Hour))
				before, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
				if err != nil {
					t.Fatal(err)
				}
				if test.prepare != nil {
					before = test.prepare(ctx, t, store, before, now.Add(-time.Minute))
				}

				start := make(chan struct{})
				results := make(chan concurrentAuthorizationResult, contenders)
				var writers sync.WaitGroup
				for contender := 0; contender < contenders; contender++ {
					writers.Add(1)
					go func(contender int) {
						defer writers.Done()
						<-start
						results <- concurrentAuthorizationResult{
							contender: contender,
							err:       test.mutate(ctx, store, before, contender, now),
						}
					}(contender)
				}
				close(start)
				writers.Wait()
				close(results)

				winner := -1
				conflicts := 0
				for result := range results {
					switch {
					case result.err == nil:
						if winner != -1 {
							t.Fatalf("multiple concurrent %s mutations succeeded: %d and %d", test.name, winner, result.contender)
						}
						winner = result.contender
					case errors.Is(result.err, ErrAuthorizationRevisionConflict):
						conflicts++
					default:
						t.Fatalf("concurrent %s mutation %d error = %v", test.name, result.contender, result.err)
					}
				}
				if winner == -1 || conflicts != contenders-1 {
					t.Fatalf("concurrent %s results: winner=%d conflicts=%d, want one winner and %d conflicts", test.name, winner, conflicts, contenders-1)
				}

				final, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
				if err != nil {
					t.Fatal(err)
				}
				test.assertFinal(t, before, final, winner, now)
				if sqliteStore != nil {
					if err := sqliteStore.Close(); err != nil {
						t.Fatal(err)
					}
					reopened, err := NewSQLiteStore(ctx, sqlitePath)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = reopened.Close() })
					reopenedSnapshot, err := reopened.GetAuthorization(ctx, plugin.PluginInstanceID)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(reopenedSnapshot, final) {
						t.Fatalf("reopened concurrent %s snapshot = %#v, want %#v", test.name, reopenedSnapshot, final)
					}
				}
			})
		}
	}
}

type concurrentAuthorizationResult struct {
	contender int
	err       error
}

func openConcurrentAuthorizationStore(t *testing.T, ctx context.Context, backend string) (Store, *SQLiteStore, string) {
	t.Helper()
	if backend == "memory" {
		return NewMemoryStore(), nil, ""
	}
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return store, store, path
}

func assertConcurrentAuthorizationPlugin(t *testing.T, before PluginRecord, final PluginRecord, revokeIncrement uint64, updatedAt time.Time) {
	t.Helper()
	want := before
	want.PolicyRevision++
	want.RevokeEpoch += revokeIncrement
	want.UpdatedAt = updatedAt
	if !reflect.DeepEqual(final, want) {
		t.Fatalf("concurrent authorization plugin = %#v, want %#v", final, want)
	}
}

func concurrentPermissionID(contender int) string {
	return fmt.Sprintf("documents.concurrent.%02d", contender)
}

func concurrentPolicyRequest(pluginInstanceID string, contender int, now time.Time) security.PutPolicyRequest {
	return security.PutPolicyRequest{
		PluginInstanceID:   pluginInstanceID,
		AllowedPermissions: []string{"documents.read", concurrentPermissionID(contender)},
		DeniedMethods:      []string{fmt.Sprintf("documents.concurrent.delete.%02d", contender)},
		Now:                now,
	}
}
