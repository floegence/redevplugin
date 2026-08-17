package registry

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func TestAuthorizationStoreContract(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
			plugin := putAuthorizationTestPlugin(t, store, "plugini_authorization", "com.example.authorization", now)

			initial, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if len(initial.Grants) != 0 || initial.Policy != nil {
				t.Fatalf("initial authorization state = %#v", initial)
			}

			granted, err := store.GrantPermission(ctx, permissions.GrantRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				PermissionID:     "documents.read",
				GrantedBy:        "admin",
				Now:              now.Add(time.Second),
			}, AuthorizationRevisionsFromRecord(initial.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if granted.Plugin.PolicyRevision != 2 || granted.Plugin.RevokeEpoch != 0 || len(granted.Grants) != 1 {
				t.Fatalf("grant snapshot = %#v", granted)
			}
			_, err = store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				Method:           "documents.get",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(initial.Plugin),
				Now:              now.Add(2 * time.Second),
			})
			if !errors.Is(err, ErrAuthorizationRevisionConflict) {
				t.Fatalf("Authorize() with stale gateway revisions error = %v, want %v", err, ErrAuthorizationRevisionConflict)
			}

			allowed, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				Method:           "documents.get",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(granted.Plugin),
				Now:              now.Add(2 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if !allowed.Allowed || !allowed.PolicyEvaluation.Allowed || len(allowed.MissingPermissions) != 0 {
				t.Fatalf("authorization decision after grant = %#v", allowed)
			}

			withPolicy, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
				PluginInstanceID:   plugin.PluginInstanceID,
				AllowedPermissions: []string{"documents.read", "documents.read"},
				DeniedMethods:      []string{"documents.delete", "documents.delete"},
				Now:                now.Add(3 * time.Second),
			}, AuthorizationRevisionsFromRecord(granted.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if withPolicy.Plugin.PolicyRevision != 3 || withPolicy.Plugin.RevokeEpoch != 1 || withPolicy.Policy == nil ||
				len(withPolicy.Policy.AllowedPermissions) != 1 || len(withPolicy.Policy.DeniedMethods) != 1 {
				t.Fatalf("policy snapshot = %#v", withPolicy)
			}

			denied, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				Method:           "documents.delete",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(withPolicy.Plugin),
				Now:              now.Add(4 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if denied.Allowed || denied.PolicyEvaluation.Reason != security.PolicyDenyReasonMethodDenied {
				t.Fatalf("denied method decision = %#v", denied)
			}

			revoked, err := store.RevokePermission(ctx, permissions.RevokeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				PermissionID:     "documents.read",
				RevokedBy:        "admin",
				Reason:           "access removed",
				Now:              now.Add(5 * time.Second),
			}, AuthorizationRevisionsFromRecord(withPolicy.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if revoked.Plugin.PolicyRevision != 4 || revoked.Plugin.RevokeEpoch != 2 || revoked.Grants[0].RevokedAt == nil {
				t.Fatalf("revoke snapshot = %#v", revoked)
			}

			missing, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				Method:           "documents.get",
				PermissionIDs:    []string{"documents.read"},
				Expected:         AuthorizationRevisionsFromRecord(revoked.Plugin),
				Now:              now.Add(6 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if missing.Allowed || len(missing.MissingPermissions) != 1 || missing.MissingPermissions[0] != "documents.read" {
				t.Fatalf("revoked permission decision = %#v", missing)
			}

			withoutPolicy, err := store.DeleteSecurityPolicy(ctx, plugin.PluginInstanceID, now.Add(7*time.Second), AuthorizationRevisionsFromRecord(revoked.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if withoutPolicy.Plugin.PolicyRevision != 5 || withoutPolicy.Plugin.RevokeEpoch != 3 || withoutPolicy.Policy != nil {
				t.Fatalf("deleted policy snapshot = %#v", withoutPolicy)
			}

			withoutPolicy.Grants[0].RevokedBy = "mutated"
			withoutPolicy.Plugin.Metadata = map[string]string{"mutated": "true"}
			got, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Grants[0].RevokedBy != "admin" || got.Plugin.Metadata["mutated"] != "" {
				t.Fatalf("authorization snapshot retained caller mutation: %#v", got)
			}
		})
	}
}

func TestExternalPackageAuthorizationStoreContract(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
			req := externalPackageInstallRequest("owner_env_hash_test", now)

			committed, err := store.PutPlugin(ctx, req.Record, PutOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if committed.PluginInstanceID == "" {
				t.Fatal("PutPlugin() returned no record")
			}
			enabled, err := store.SetEnableState(ctx, req.Record.PluginInstanceID, EnableEnabled, "", now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			granted, err := store.GrantPermission(ctx, permissions.GrantRequest{
				PluginInstanceID: req.Record.PluginInstanceID,
				PermissionID:     "containers.read",
				GrantedBy:        "test",
				Now:              now.Add(2 * time.Second),
			}, AuthorizationRevisionsFromRecord(enabled))
			if err != nil {
				t.Fatal(err)
			}

			decision, err := store.Authorize(ctx, AuthorizeRequest{
				PluginInstanceID: req.Record.PluginInstanceID,
				Method:           "containers.status",
				PermissionIDs:    []string{"containers.read"},
				Expected:         AuthorizationRevisionsFromRecord(granted.Plugin),
				Now:              now.Add(3 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if !decision.Allowed {
				t.Fatalf("Authorize() decision = %#v, want allowed", decision)
			}
			if !reflect.DeepEqual(decision.State.SignatureAssessment, req.Record.SignatureAssessment) ||
				decision.State.PackageSourceKind != req.Record.PackageSourceProvenance.Kind ||
				!reflect.DeepEqual(decision.State.ExecutionApproval, req.Record.ExecutionApproval) {
				t.Fatalf("Authorize() external package state = %#v", decision.State)
			}
			if !RunnableAuthorizationState(decision.State) {
				t.Fatalf("RunnableAuthorizationState(%#v) = false", decision.State)
			}
		})
	}
}

func TestAuthorizationMutationsRejectEveryStaleRevision(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
			plugin := putAuthorizationTestPlugin(t, store, "plugini_stale", "com.example.stale", now)
			base := AuthorizationRevisionsFromRecord(plugin)
			for _, test := range []struct {
				name     string
				expected AuthorizationRevisions
			}{
				{name: "policy", expected: AuthorizationRevisions{PolicyRevision: base.PolicyRevision + 1, ManagementRevision: base.ManagementRevision, RevokeEpoch: base.RevokeEpoch}},
				{name: "management", expected: AuthorizationRevisions{PolicyRevision: base.PolicyRevision, ManagementRevision: base.ManagementRevision + 1, RevokeEpoch: base.RevokeEpoch}},
				{name: "revoke", expected: AuthorizationRevisions{PolicyRevision: base.PolicyRevision, ManagementRevision: base.ManagementRevision, RevokeEpoch: base.RevokeEpoch + 1}},
			} {
				t.Run(test.name, func(t *testing.T) {
					_, err := store.GrantPermission(ctx, permissions.GrantRequest{
						PluginInstanceID: plugin.PluginInstanceID,
						PermissionID:     "documents." + test.name,
						Now:              now.Add(time.Second),
					}, test.expected)
					if !errors.Is(err, ErrAuthorizationRevisionConflict) {
						t.Fatalf("GrantPermission() error = %v, want %v", err, ErrAuthorizationRevisionConflict)
					}
					var conflict *AuthorizationRevisionConflictError
					if !errors.As(err, &conflict) || conflict.Expected != test.expected || conflict.Actual != base {
						t.Fatalf("revision conflict details = %#v", conflict)
					}
				})
			}
			got, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if AuthorizationRevisionsFromRecord(got.Plugin) != base || len(got.Grants) != 0 {
				t.Fatalf("stale mutations changed authorization state: %#v", got)
			}
		})
	}
}

func TestAuthorizationMutationConcurrencyCommitsOneSnapshot(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
			plugin := putAuthorizationTestPlugin(t, store, "plugini_concurrent", "com.example.concurrent", now)
			expected := AuthorizationRevisionsFromRecord(plugin)
			const writers = 16
			start := make(chan struct{})
			errs := make(chan error, writers)
			var wg sync.WaitGroup
			for i := 0; i < writers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					_, err := store.GrantPermission(ctx, permissions.GrantRequest{
						PluginInstanceID: plugin.PluginInstanceID,
						PermissionID:     "concurrent." + string(rune('a'+i)),
						Now:              now.Add(time.Duration(i+1) * time.Second),
					}, expected)
					errs <- err
				}(i)
			}
			close(start)
			wg.Wait()
			close(errs)
			succeeded := 0
			conflicted := 0
			for err := range errs {
				switch {
				case err == nil:
					succeeded++
				case errors.Is(err, ErrAuthorizationRevisionConflict):
					conflicted++
				default:
					t.Fatalf("unexpected concurrent mutation error: %v", err)
				}
			}
			if succeeded != 1 || conflicted != writers-1 {
				t.Fatalf("concurrent mutations: succeeded=%d conflicted=%d", succeeded, conflicted)
			}
			got, err := store.GetAuthorization(ctx, plugin.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Plugin.PolicyRevision != plugin.PolicyRevision+1 || len(got.Grants) != 1 {
				t.Fatalf("concurrent mutation state = %#v", got)
			}
		})
	}
}

func TestMarkUninstalledDeletesAuthorizationState(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryTestContext()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 11, 0, 0, 0, time.UTC)
			plugin := putAuthorizationTestPlugin(t, store, "plugini_uninstall_auth", "com.example.uninstall-auth", now)
			granted, err := store.GrantPermission(ctx, permissions.GrantRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				PermissionID:     "documents.read",
				Now:              now.Add(time.Second),
			}, AuthorizationRevisionsFromRecord(plugin))
			if err != nil {
				t.Fatal(err)
			}
			withPolicy, err := store.PutSecurityPolicy(ctx, security.PutPolicyRequest{
				PluginInstanceID: plugin.PluginInstanceID,
				DeniedMethods:    []string{"documents.delete"},
				Now:              now.Add(2 * time.Second),
			}, AuthorizationRevisionsFromRecord(granted.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.CommitUninstall(ctx, plugindata.CommitUninstallRequest{
				PluginInstanceID:           plugin.PluginInstanceID,
				DeleteData:                 true,
				ExpectedManagementRevision: withPolicy.Plugin.ManagementRevision,
				Now:                        now.Add(3 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}

			reinstalled := authorizationTestPlugin(plugin.PluginInstanceID, plugin.PluginID)
			reinstalled, err = store.PutPlugin(ctx, reinstalled, PutOptions{Now: now.Add(4 * time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := store.GetAuthorization(ctx, reinstalled.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Grants) != 0 || snapshot.Policy != nil {
				t.Fatalf("authorization survived uninstall: %#v", snapshot)
			}
		})
	}
}

func putAuthorizationTestPlugin(t *testing.T, store Store, pluginInstanceID string, pluginID string, now time.Time) PluginRecord {
	t.Helper()
	record, err := store.PutPlugin(registryTestContext(), authorizationTestPlugin(pluginInstanceID, pluginID), PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func authorizationTestPlugin(pluginInstanceID string, pluginID string) PluginRecord {
	return PluginRecord{
		PluginInstanceID:  pluginInstanceID,
		PublisherID:       "example",
		PluginID:          pluginID,
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:" + pluginInstanceID,
		TrustState:        TrustVerified,
		PackageSourceProvenance: PackageSourceProvenance{
			Kind: PackageSourceLocalGenerated,
		},
		EnableState: EnableEnabled,
		Manifest:    currentTestManifest(pluginID, "1.0.0"),
	}
}
