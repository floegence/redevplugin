package security

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPolicyStorePutListEvaluateAndDelete(t *testing.T) {
	for _, tc := range policyStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
			record, err := store.PutPolicy(ctx, PutPolicyRequest{
				PluginInstanceID:   "plugini_policy",
				AllowedPermissions: []string{"write", "read", "read", ""},
				DeniedMethods:      []string{"cache.delete", "cache.delete", ""},
				Now:                now,
			})
			if err != nil {
				t.Fatalf("PutPolicy() error = %v", err)
			}
			if !reflect.DeepEqual(record.AllowedPermissions, []string{"read", "write"}) ||
				!reflect.DeepEqual(record.DeniedMethods, []string{"cache.delete"}) ||
				!record.UpdatedAt.Equal(now) {
				t.Fatalf("policy record mismatch: %#v", record)
			}

			allowed, err := store.EvaluatePolicy(ctx, EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_policy",
				Method:              "cache.list",
				RequiredPermissions: []string{"read"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy(allowed) error = %v", err)
			}
			if !allowed.Allowed {
				t.Fatalf("EvaluatePolicy(allowed) denied: %#v", allowed)
			}

			deniedMethod, err := store.EvaluatePolicy(ctx, EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_policy",
				Method:              "cache.delete",
				RequiredPermissions: []string{"write"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy(denied method) error = %v", err)
			}
			if deniedMethod.Allowed ||
				deniedMethod.Reason != PolicyDenyReasonMethodDenied ||
				deniedMethod.DeniedMethod != "cache.delete" {
				t.Fatalf("denied method result mismatch: %#v", deniedMethod)
			}

			deniedPermission, err := store.EvaluatePolicy(ctx, EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_policy",
				Method:              "cache.remove",
				RequiredPermissions: []string{"delete", "write"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy(denied permission) error = %v", err)
			}
			if deniedPermission.Allowed ||
				deniedPermission.Reason != PolicyDenyReasonPermissionNotAllowed ||
				!reflect.DeepEqual(deniedPermission.MissingPermissions, []string{"delete"}) {
				t.Fatalf("denied permission result mismatch: %#v", deniedPermission)
			}

			listed, err := store.ListPolicies(ctx)
			if err != nil {
				t.Fatalf("ListPolicies() error = %v", err)
			}
			if len(listed) != 1 || listed[0].PluginInstanceID != "plugini_policy" {
				t.Fatalf("ListPolicies() mismatch: %#v", listed)
			}
			if err := store.DeletePolicy(ctx, "plugini_policy"); err != nil {
				t.Fatalf("DeletePolicy() error = %v", err)
			}
			afterDelete, err := store.EvaluatePolicy(ctx, EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_policy",
				Method:              "cache.delete",
				RequiredPermissions: []string{"delete"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy(after delete) error = %v", err)
			}
			if !afterDelete.Allowed {
				t.Fatalf("deleted policy still denied: %#v", afterDelete)
			}
			if _, err := store.GetPolicy(ctx, "plugini_policy"); !errors.Is(err, ErrPolicyNotFound) {
				t.Fatalf("GetPolicy(after delete) error = %v, want ErrPolicyNotFound", err)
			}
		})
	}
}

func TestConfirmationIntentStorePutListConsumeAndRevoke(t *testing.T) {
	for _, tc := range confirmationIntentStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
			record, err := store.PutConfirmationIntent(ctx, testPutConfirmationIntentRequest("confirmation_1", "plugini_confirm", now))
			if err != nil {
				t.Fatalf("PutConfirmationIntent() error = %v", err)
			}
			if record.ConfirmationID != "confirmation_1" ||
				record.ConfirmationTokenID != "ct_1" ||
				record.PluginID != "com.example.confirm" ||
				record.RequestHash != "sha256:request" ||
				record.PlanHash != "sha256:plan" ||
				!record.IssuedAt.Equal(now) ||
				!record.ExpiresAt.Equal(now.Add(time.Minute)) {
				t.Fatalf("confirmation intent mismatch: %#v", record)
			}

			listed, err := store.ListConfirmationIntents(ctx, ListConfirmationIntentsRequest{PluginInstanceID: "plugini_confirm"})
			if err != nil {
				t.Fatalf("ListConfirmationIntents() error = %v", err)
			}
			if len(listed) != 1 || listed[0].ConfirmationID != "confirmation_1" {
				t.Fatalf("listed confirmation intents mismatch: %#v", listed)
			}

			consumed, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{
				ConfirmationID: "confirmation_1",
				Now:            now.Add(30 * time.Second),
			})
			if err != nil {
				t.Fatalf("ConsumeConfirmationIntent() error = %v", err)
			}
			if consumed.ConfirmationID != record.ConfirmationID || consumed.ConfirmationTokenID != record.ConfirmationTokenID {
				t.Fatalf("consumed confirmation intent mismatch: %#v", consumed)
			}
			if _, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{ConfirmationID: "confirmation_1", Now: now.Add(31 * time.Second)}); !errors.Is(err, ErrConfirmationIntentNotFound) {
				t.Fatalf("ConsumeConfirmationIntent(replay) error = %v, want ErrConfirmationIntentNotFound", err)
			}

			if _, err := store.PutConfirmationIntent(ctx, testPutConfirmationIntentRequest("confirmation_2", "plugini_confirm", now)); err != nil {
				t.Fatalf("PutConfirmationIntent(second) error = %v", err)
			}
			revoked, err := store.RevokePluginConfirmationIntents(ctx, RevokePluginConfirmationIntentsRequest{PluginInstanceID: "plugini_confirm"})
			if err != nil {
				t.Fatalf("RevokePluginConfirmationIntents() error = %v", err)
			}
			if revoked != 1 {
				t.Fatalf("revoked confirmation intents = %d, want 1", revoked)
			}
			if listed, err := store.ListConfirmationIntents(ctx, ListConfirmationIntentsRequest{PluginInstanceID: "plugini_confirm"}); err != nil || len(listed) != 0 {
				t.Fatalf("ListConfirmationIntents(after revoke) = %#v, err=%v", listed, err)
			}
		})
	}
}

func TestConfirmationIntentStoreRejectsExpiredAndInvalidRequests(t *testing.T) {
	for _, tc := range confirmationIntentStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
			if _, err := store.PutConfirmationIntent(ctx, PutConfirmationIntentRequest{ConfirmationID: "confirmation_invalid", Now: now}); !errors.Is(err, ErrInvalidConfirmationIntent) {
				t.Fatalf("PutConfirmationIntent(invalid) error = %v, want ErrInvalidConfirmationIntent", err)
			}
			if _, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{}); !errors.Is(err, ErrInvalidConfirmationIntent) {
				t.Fatalf("ConsumeConfirmationIntent(invalid) error = %v, want ErrInvalidConfirmationIntent", err)
			}
			if _, err := store.RevokePluginConfirmationIntents(ctx, RevokePluginConfirmationIntentsRequest{}); !errors.Is(err, ErrInvalidConfirmationIntent) {
				t.Fatalf("RevokePluginConfirmationIntents(invalid) error = %v, want ErrInvalidConfirmationIntent", err)
			}
			req := testPutConfirmationIntentRequest("confirmation_expired", "plugini_expired", now)
			req.ExpiresAt = now.Add(time.Second)
			if _, err := store.PutConfirmationIntent(ctx, req); err != nil {
				t.Fatalf("PutConfirmationIntent(expiring) error = %v", err)
			}
			if _, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{
				ConfirmationID: "confirmation_expired",
				Now:            now.Add(2 * time.Second),
			}); !errors.Is(err, ErrConfirmationIntentExpired) {
				t.Fatalf("ConsumeConfirmationIntent(expired) error = %v, want ErrConfirmationIntentExpired", err)
			}
			if _, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{
				ConfirmationID: "confirmation_expired",
				Now:            now.Add(3 * time.Second),
			}); !errors.Is(err, ErrConfirmationIntentNotFound) {
				t.Fatalf("ConsumeConfirmationIntent(expired replay) error = %v, want ErrConfirmationIntentNotFound", err)
			}
		})
	}
}

func TestConfirmationIntentStoreRejectsOnlyMatchingScope(t *testing.T) {
	for _, tc := range confirmationIntentStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
			record, err := store.PutConfirmationIntent(ctx, testPutConfirmationIntentRequest("confirmation_reject", "plugini_confirm", now))
			if err != nil {
				t.Fatal(err)
			}
			reject := RejectConfirmationIntentRequest{
				ConfirmationID:       record.ConfirmationID,
				PluginInstanceID:     record.PluginInstanceID,
				SurfaceInstanceID:    record.SurfaceInstanceID,
				BridgeChannelID:      record.BridgeChannelID,
				ActiveFingerprint:    record.Scope.ActiveFingerprint,
				OwnerSessionHash:     record.Scope.OwnerSessionHash,
				OwnerUserHash:        record.Scope.OwnerUserHash,
				SessionChannelIDHash: record.Scope.SessionChannelIDHash,
				PolicyRevision:       record.Scope.PolicyRevision,
				ManagementRevision:   record.Scope.ManagementRevision,
				RevokeEpoch:          record.Scope.RevokeEpoch,
				Now:                  now.Add(30 * time.Second),
			}
			mismatched := reject
			mismatched.BridgeChannelID = "bridge_other"
			if _, err := store.RejectConfirmationIntent(ctx, mismatched); !errors.Is(err, ErrConfirmationIntentScopeMismatch) {
				t.Fatalf("RejectConfirmationIntent(scope mismatch) error = %v, want ErrConfirmationIntentScopeMismatch", err)
			}
			listed, err := store.ListConfirmationIntents(ctx, ListConfirmationIntentsRequest{PluginInstanceID: record.PluginInstanceID})
			if err != nil || len(listed) != 1 {
				t.Fatalf("scope mismatch consumed confirmation: listed=%#v err=%v", listed, err)
			}

			rejected, err := store.RejectConfirmationIntent(ctx, reject)
			if err != nil {
				t.Fatalf("RejectConfirmationIntent() error = %v", err)
			}
			if rejected.ConfirmationID != record.ConfirmationID || rejected.Method != record.Method {
				t.Fatalf("rejected confirmation mismatch: %#v", rejected)
			}
			if _, err := store.RejectConfirmationIntent(ctx, reject); !errors.Is(err, ErrConfirmationIntentNotFound) {
				t.Fatalf("RejectConfirmationIntent(replay) error = %v, want ErrConfirmationIntentNotFound", err)
			}
		})
	}
}

func TestConfirmationIntentStoreCapsPendingIntentsPerPlugin(t *testing.T) {
	for _, tc := range confirmationIntentStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
			for i := 0; i < 3; i++ {
				req := testPutConfirmationIntentRequest("confirmation_cap_"+string(rune('0'+i)), "plugini_cap", now.Add(time.Duration(i)*time.Second))
				req.MaxPendingPerPlugin = 2
				if _, err := store.PutConfirmationIntent(ctx, req); err != nil {
					t.Fatalf("PutConfirmationIntent(%d) error = %v", i, err)
				}
			}
			listed, err := store.ListConfirmationIntents(ctx, ListConfirmationIntentsRequest{PluginInstanceID: "plugini_cap"})
			if err != nil {
				t.Fatalf("ListConfirmationIntents() error = %v", err)
			}
			if len(listed) != 2 || listed[0].ConfirmationID != "confirmation_cap_1" || listed[1].ConfirmationID != "confirmation_cap_2" {
				t.Fatalf("pending confirmation cap mismatch: %#v", listed)
			}
		})
	}
}

func TestSQLiteConfirmationIntentStorePersistsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "confirmation-intents.sqlite")
	store, err := NewSQLiteConfirmationIntentStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
	record, err := store.PutConfirmationIntent(ctx, testPutConfirmationIntentRequest("confirmation_persist", "plugini_persist", now))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteConfirmationIntentStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	got, err := reopened.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{
		ConfirmationID: "confirmation_persist",
		Now:            now.Add(30 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != record {
		t.Fatalf("persisted confirmation intent mismatch: %#v want %#v", got, record)
	}
}

func TestSQLiteConfirmationIntentStoreRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "confirmation-intents.sqlite")
	store, err := NewSQLiteConfirmationIntentStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT OR REPLACE INTO plugin_confirmation_intent_schema_migrations(version, applied_at) VALUES(999, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteConfirmationIntentStore(ctx, path); err == nil {
		t.Fatal("NewSQLiteConfirmationIntentStore() accepted newer schema version")
	}
}

func TestPolicyStoreNoPolicyAllowsByDefault(t *testing.T) {
	for _, tc := range policyStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := tc.open(t).EvaluatePolicy(context.Background(), EvaluatePolicyRequest{
				PluginInstanceID:    "plugini_missing",
				Method:              "anything.run",
				RequiredPermissions: []string{"admin"},
			})
			if err != nil {
				t.Fatalf("EvaluatePolicy() error = %v", err)
			}
			if !allowed.Allowed {
				t.Fatalf("missing policy denied: %#v", allowed)
			}
		})
	}
}

func TestPolicyStoreRejectsInvalidRequests(t *testing.T) {
	for _, tc := range policyStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			if _, err := store.PutPolicy(context.Background(), PutPolicyRequest{}); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("PutPolicy() error = %v, want ErrInvalidPolicy", err)
			}
			if _, err := store.GetPolicy(context.Background(), " "); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("GetPolicy() error = %v, want ErrInvalidPolicy", err)
			}
			if _, err := store.EvaluatePolicy(context.Background(), EvaluatePolicyRequest{PluginInstanceID: "plugini"}); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("EvaluatePolicy() error = %v, want ErrInvalidPolicy", err)
			}
			if err := store.DeletePolicy(context.Background(), " "); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("DeletePolicy() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestSQLitePolicyStorePersistsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security-policy.sqlite")
	store, err := NewSQLitePolicyStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 2, 11, 0, 0, 0, time.UTC)
	if _, err := store.PutPolicy(ctx, PutPolicyRequest{
		PluginInstanceID:   "plugini_persist",
		AllowedPermissions: []string{"read"},
		DeniedMethods:      []string{"cache.delete"},
		Now:                now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLitePolicyStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	record, err := reopened.GetPolicy(ctx, "plugini_persist")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record.AllowedPermissions, []string{"read"}) ||
		!reflect.DeepEqual(record.DeniedMethods, []string{"cache.delete"}) ||
		!record.UpdatedAt.Equal(now) {
		t.Fatalf("persisted policy mismatch: %#v", record)
	}
}

func TestSQLitePolicyStoreRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security-policy.sqlite")
	store, err := NewSQLitePolicyStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT OR REPLACE INTO plugin_security_policy_schema_migrations(version, applied_at) VALUES(999, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLitePolicyStore(ctx, path); err == nil {
		t.Fatal("NewSQLitePolicyStore() accepted newer schema version")
	}
}

type policyStoreCase struct {
	name string
	open func(t *testing.T) PolicyStore
}

func policyStoreCases() []policyStoreCase {
	return []policyStoreCase{
		{
			name: "memory",
			open: func(t *testing.T) PolicyStore {
				t.Helper()
				return NewMemoryPolicyStore()
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) PolicyStore {
				t.Helper()
				store, err := NewSQLitePolicyStore(context.Background(), filepath.Join(t.TempDir(), "security-policy.sqlite"))
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

func testPutConfirmationIntentRequest(confirmationID string, pluginInstanceID string, now time.Time) PutConfirmationIntentRequest {
	return PutConfirmationIntentRequest{
		ConfirmationID:      confirmationID,
		ConfirmationTokenID: "ct_1",
		PluginID:            "com.example.confirm",
		PluginInstanceID:    pluginInstanceID,
		SurfaceInstanceID:   "surface_1",
		BridgeChannelID:     "bridge_1",
		Method:              "danger.run",
		RequestHash:         "sha256:request",
		PlanHash:            "sha256:plan",
		Scope: ConfirmationScope{
			ActiveFingerprint:      "sha256:active",
			OwnerSessionHash:       "sha256:session",
			OwnerUserHash:          "sha256:user",
			SessionChannelIDHash:   "sha256:channel",
			PolicyRevision:         1,
			ManagementRevision:     1,
			RevokeEpoch:            1,
			TargetDescriptorSHA256: "sha256:target",
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Minute),
		Now:       now,
	}
}

type confirmationIntentStoreCase struct {
	name string
	open func(t *testing.T) ConfirmationIntentStore
}

func confirmationIntentStoreCases() []confirmationIntentStoreCase {
	return []confirmationIntentStoreCase{
		{
			name: "memory",
			open: func(t *testing.T) ConfirmationIntentStore {
				t.Helper()
				return NewMemoryConfirmationIntentStore()
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) ConfirmationIntentStore {
				t.Helper()
				store, err := NewSQLiteConfirmationIntentStore(context.Background(), filepath.Join(t.TempDir(), "confirmation-intents.sqlite"))
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
