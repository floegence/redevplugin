package security

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestNewPolicyNormalizesRecord(t *testing.T) {
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.FixedZone("test", 3600))
	record, err := NewPolicy(PutPolicyRequest{
		PluginInstanceID:   " plugini_policy ",
		AllowedPermissions: []string{"write", "read", "read", ""},
		DeniedMethods:      []string{"cache.delete", "cache.delete", ""},
		Now:                now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.PluginInstanceID != "plugini_policy" ||
		!reflect.DeepEqual(record.AllowedPermissions, []string{"read", "write"}) ||
		!reflect.DeepEqual(record.DeniedMethods, []string{"cache.delete"}) ||
		!record.UpdatedAt.Equal(now) || record.UpdatedAt.Location() != time.UTC {
		t.Fatalf("NewPolicy() = %#v", record)
	}
}

func TestEvaluatePolicy(t *testing.T) {
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	policy, err := NewPolicy(PutPolicyRequest{
		PluginInstanceID:   "plugini_policy",
		AllowedPermissions: []string{"read", "write"},
		DeniedMethods:      []string{"cache.delete"},
		Now:                now,
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := Evaluate(&policy, EvaluatePolicyRequest{
		PluginInstanceID:    "plugini_policy",
		Method:              "cache.list",
		RequiredPermissions: []string{"read"},
	})
	if err != nil || !allowed.Allowed {
		t.Fatalf("Evaluate(allowed) = %#v, %v", allowed, err)
	}
	deniedMethod, err := Evaluate(&policy, EvaluatePolicyRequest{
		PluginInstanceID:    "plugini_policy",
		Method:              " cache.delete ",
		RequiredPermissions: []string{"write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if deniedMethod.Allowed || deniedMethod.Reason != PolicyDenyReasonMethodDenied || deniedMethod.DeniedMethod != "cache.delete" {
		t.Fatalf("Evaluate(denied method) = %#v", deniedMethod)
	}
	deniedPermission, err := Evaluate(&policy, EvaluatePolicyRequest{
		PluginInstanceID:    "plugini_policy",
		Method:              "cache.remove",
		RequiredPermissions: []string{"write", "delete", "delete"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if deniedPermission.Allowed || deniedPermission.Reason != PolicyDenyReasonPermissionNotAllowed || !reflect.DeepEqual(deniedPermission.MissingPermissions, []string{"delete"}) {
		t.Fatalf("Evaluate(denied permission) = %#v", deniedPermission)
	}
}

func TestEvaluateMissingPolicyAllows(t *testing.T) {
	evaluation, err := Evaluate(nil, EvaluatePolicyRequest{PluginInstanceID: "plugini_missing", Method: "anything.run", RequiredPermissions: []string{"admin"}})
	if err != nil || !evaluation.Allowed {
		t.Fatalf("Evaluate(nil) = %#v, %v", evaluation, err)
	}
}

func TestPolicyFunctionsRejectInvalidInput(t *testing.T) {
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	if _, err := NewPolicy(PutPolicyRequest{Now: now}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	if err := ValidatePolicy(PolicyRecord{PluginInstanceID: "plugini"}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("ValidatePolicy() error = %v", err)
	}
	if _, err := Evaluate(nil, EvaluatePolicyRequest{PluginInstanceID: "plugini"}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("Evaluate() error = %v", err)
	}
	other, err := NewPolicy(PutPolicyRequest{PluginInstanceID: "other", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(&other, EvaluatePolicyRequest{PluginInstanceID: "plugini", Method: "read"}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("Evaluate(mismatched plugin) error = %v", err)
	}
}

func TestClonePolicyDoesNotShareSlices(t *testing.T) {
	record := PolicyRecord{AllowedPermissions: []string{"read"}, DeniedMethods: []string{"delete"}}
	cloned := ClonePolicy(record)
	cloned.AllowedPermissions[0] = "write"
	cloned.DeniedMethods[0] = "update"
	if !reflect.DeepEqual(record.AllowedPermissions, []string{"read"}) || !reflect.DeepEqual(record.DeniedMethods, []string{"delete"}) {
		t.Fatalf("ClonePolicy() shared slices: original=%#v clone=%#v", record, cloned)
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
				SessionScope:   confirmationSessionScope(record.Scope),
				Now:            now.Add(30 * time.Second),
			})
			if err != nil {
				t.Fatalf("ConsumeConfirmationIntent() error = %v", err)
			}
			if consumed.ConfirmationID != record.ConfirmationID || consumed.ConfirmationTokenID != record.ConfirmationTokenID {
				t.Fatalf("consumed confirmation intent mismatch: %#v", consumed)
			}
			if _, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{ConfirmationID: "confirmation_1", SessionScope: confirmationSessionScope(record.Scope), Now: now.Add(31 * time.Second)}); !errors.Is(err, ErrConfirmationIntentNotFound) {
				t.Fatalf("ConsumeConfirmationIntent(replay) error = %v, want ErrConfirmationIntentNotFound", err)
			}

			if _, err := store.PutConfirmationIntent(ctx, testPutConfirmationIntentRequest("confirmation_2", "plugini_confirm", now)); err != nil {
				t.Fatalf("PutConfirmationIntent(second) error = %v", err)
			}
			revoked, err := store.RevokePluginConfirmationIntents(ctx, RevokePluginConfirmationIntentsRequest{OwnerEnvHash: "sha256:environment", PluginInstanceID: "plugini_confirm"})
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
				SessionScope:   confirmationSessionScope(req.Scope),
				Now:            now.Add(2 * time.Second),
			}); !errors.Is(err, ErrConfirmationIntentExpired) {
				t.Fatalf("ConsumeConfirmationIntent(expired) error = %v, want ErrConfirmationIntentExpired", err)
			}
			if _, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{
				ConfirmationID: "confirmation_expired",
				SessionScope:   confirmationSessionScope(req.Scope),
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
				OwnerEnvHash:         record.Scope.OwnerEnvHash,
				SessionChannelIDHash: record.Scope.SessionChannelIDHash,
				PolicyRevision:       record.Scope.PolicyRevision,
				ManagementRevision:   record.Scope.ManagementRevision,
				RevokeEpoch:          record.Scope.RevokeEpoch,
				Now:                  now.Add(30 * time.Second),
			}
			mismatched := reject
			mismatched.OwnerEnvHash = "environment_other"
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

func TestConfirmationIntentStoreRejectsCapacityWithoutEviction(t *testing.T) {
	for _, tc := range confirmationIntentStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
			for i := 0; i < DefaultMaxPendingConfirmationIntentsPerOwnerPlugin; i++ {
				req := testPutConfirmationIntentRequest("confirmation_cap_"+string(rune('0'+i)), "plugini_cap", now.Add(time.Duration(i)*time.Second))
				req.Now = now
				req.ExpiresAt = now.Add(2 * time.Hour)
				req.Scope.OwnerSessionHash = "owner_session_" + strconv.Itoa(i)
				req.Scope.SessionChannelIDHash = "session_channel_" + strconv.Itoa(i)
				if _, err := store.PutConfirmationIntent(ctx, req); err != nil {
					t.Fatalf("PutConfirmationIntent(%d) error = %v", i, err)
				}
			}
			overflow := testPutConfirmationIntentRequest("confirmation_cap_overflow", "plugini_cap", now.Add(time.Hour))
			overflow.Now = now
			overflow.ExpiresAt = now.Add(2 * time.Hour)
			if _, err := store.PutConfirmationIntent(ctx, overflow); !errors.Is(err, ErrConfirmationIntentCapacity) {
				t.Fatalf("PutConfirmationIntent(overflow) error = %v, want ErrConfirmationIntentCapacity", err)
			}
			listed, err := store.ListConfirmationIntents(ctx, ListConfirmationIntentsRequest{PluginInstanceID: "plugini_cap"})
			if err != nil {
				t.Fatalf("ListConfirmationIntents() error = %v", err)
			}
			if len(listed) != DefaultMaxPendingConfirmationIntentsPerOwnerPlugin || listed[0].ConfirmationID != "confirmation_cap_0" {
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
		SessionScope:   confirmationSessionScope(record.Scope),
		Now:            now.Add(30 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != record {
		t.Fatalf("persisted confirmation intent mismatch: %#v want %#v", got, record)
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
			OwnerEnvHash:           "sha256:environment",
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
