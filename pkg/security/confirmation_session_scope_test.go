package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
	_ "modernc.org/sqlite"
)

func TestConfirmationConsumeMatchesScopeBeforeDelete(t *testing.T) {
	for _, tc := range confirmationIntentStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Unix(1, 0).UTC()
			record, err := store.PutConfirmationIntent(context.Background(), testScopedConfirmationRequest(now))
			if err != nil {
				t.Fatalf("PutConfirmationIntent() error = %v", err)
			}
			wrong := sessionctx.SessionScope{
				OwnerSessionHash:     "session_other",
				OwnerUserHash:        "user_other",
				OwnerEnvHash:         "env_other",
				SessionChannelIDHash: "channel_other",
			}
			if _, err := store.ConsumeConfirmationIntent(context.Background(), ConsumeConfirmationIntentRequest{
				ConfirmationID: record.ConfirmationID,
				SessionScope:   wrong,
				Now:            now,
			}); !errors.Is(err, ErrConfirmationIntentScopeMismatch) {
				t.Fatalf("ConsumeConfirmationIntent(wrong scope) error = %v", err)
			}
			correct := confirmationSessionScope(record.Scope)
			if _, err := store.ConsumeConfirmationIntent(context.Background(), ConsumeConfirmationIntentRequest{
				ConfirmationID: record.ConfirmationID,
				SessionScope:   correct,
				Now:            now,
			}); err != nil {
				t.Fatalf("ConsumeConfirmationIntent(correct scope) error = %v", err)
			}
		})
	}
}

func TestConfirmationOwnerHashesArePrivateJSONFields(t *testing.T) {
	record := ConfirmationIntentRecord{Scope: testScopedConfirmationRequest(time.Unix(1, 0).UTC()).Scope}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, privateField := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		if string(raw) == "" || json.Valid(raw) == false {
			t.Fatalf("invalid JSON: %s", raw)
		}
		if containsJSONField(raw, privateField) {
			t.Fatalf("confirmation JSON exposed %q: %s", privateField, raw)
		}
	}
}

func containsJSONField(raw []byte, field string) bool {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	scope, _ := value["scope"].(map[string]any)
	_, exists := scope[field]
	return exists
}

func TestConfirmationCapacityIsBoundedWithoutEviction(t *testing.T) {
	store, err := NewMemoryConfirmationIntentStoreWithOptions(ConfirmationIntentStoreOptions{
		MaxTotal:          2,
		MaxPerOwnerPlugin: 1,
		MaxPerSession:     1,
	})
	if err != nil {
		t.Fatalf("NewMemoryConfirmationIntentStoreWithOptions() error = %v", err)
	}
	now := time.Unix(1, 0).UTC()
	first := testScopedConfirmationRequest(now)
	if _, err := store.PutConfirmationIntent(context.Background(), first); err != nil {
		t.Fatalf("PutConfirmationIntent(first) error = %v", err)
	}
	secondSameOwner := testScopedConfirmationRequest(now)
	secondSameOwner.ConfirmationID = "confirmation_same_owner"
	secondSameOwner.ConfirmationTokenID = "confirmation_token_same_owner"
	secondSameOwner.Scope.OwnerSessionHash = "session_other"
	secondSameOwner.Scope.SessionChannelIDHash = "channel_other"
	if _, err := store.PutConfirmationIntent(context.Background(), secondSameOwner); !errors.Is(err, ErrConfirmationIntentCapacity) {
		t.Fatalf("PutConfirmationIntent(same owner/plugin) error = %v, want ErrConfirmationIntentCapacity", err)
	}
	differentOwner := testScopedConfirmationRequest(now)
	differentOwner.ConfirmationID = "confirmation_other_owner"
	differentOwner.ConfirmationTokenID = "confirmation_token_other_owner"
	differentOwner.Scope.OwnerEnvHash = "env_other"
	differentOwner.Scope.OwnerUserHash = "user_other"
	differentOwner.Scope.OwnerSessionHash = "session_other"
	differentOwner.Scope.SessionChannelIDHash = "channel_other"
	if _, err := store.PutConfirmationIntent(context.Background(), differentOwner); err != nil {
		t.Fatalf("PutConfirmationIntent(other owner) error = %v", err)
	}
	third := testScopedConfirmationRequest(now)
	third.ConfirmationID = "confirmation_total_capacity"
	third.ConfirmationTokenID = "confirmation_token_total_capacity"
	third.PluginInstanceID = "plugini_other"
	third.Scope.OwnerEnvHash = "env_third"
	third.Scope.OwnerUserHash = "user_third"
	third.Scope.OwnerSessionHash = "session_third"
	third.Scope.SessionChannelIDHash = "channel_third"
	if _, err := store.PutConfirmationIntent(context.Background(), third); !errors.Is(err, ErrConfirmationIntentCapacity) {
		t.Fatalf("PutConfirmationIntent(total) error = %v, want ErrConfirmationIntentCapacity", err)
	}
	listed, err := store.ListConfirmationIntents(context.Background(), ListConfirmationIntentsRequest{})
	if err != nil {
		t.Fatalf("ListConfirmationIntents() error = %v", err)
	}
	seen := map[string]bool{}
	for _, record := range listed {
		seen[record.ConfirmationID] = true
	}
	if len(listed) != 2 || !seen[first.ConfirmationID] || !seen[differentOwner.ConfirmationID] {
		t.Fatalf("capacity evicted an existing intent: %#v", listed)
	}
}

func TestConfirmationSessionRevokeUsesExactIndex(t *testing.T) {
	for _, tc := range confirmationIntentStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Unix(1, 0).UTC()
			first := testScopedConfirmationRequest(now)
			if _, err := store.PutConfirmationIntent(context.Background(), first); err != nil {
				t.Fatalf("PutConfirmationIntent(first) error = %v", err)
			}
			sibling := testScopedConfirmationRequest(now)
			sibling.ConfirmationID = "confirmation_sibling"
			sibling.ConfirmationTokenID = "confirmation_token_sibling"
			sibling.Scope.SessionChannelIDHash = "channel_sibling"
			if _, err := store.PutConfirmationIntent(context.Background(), sibling); err != nil {
				t.Fatalf("PutConfirmationIntent(sibling) error = %v", err)
			}
			scope := confirmationSessionScope(first.Scope)
			revoked, err := store.RevokeSessionConfirmationIntents(context.Background(), RevokeSessionConfirmationIntentsRequest{
				SessionScope: scope, TeardownOperationID: "teardown_confirmation_scope", Now: now,
			})
			if err != nil {
				t.Fatalf("RevokeSessionConfirmationIntents() error = %v", err)
			}
			if revoked != 1 {
				t.Fatalf("RevokeSessionConfirmationIntents() = %d, want 1", revoked)
			}
			replayed, err := store.RevokeSessionConfirmationIntents(context.Background(), RevokeSessionConfirmationIntentsRequest{
				SessionScope: scope, TeardownOperationID: "teardown_confirmation_scope", Now: now.Add(time.Second),
			})
			if err != nil || replayed != 1 {
				t.Fatalf("RevokeSessionConfirmationIntents(replay) = %d, %v", replayed, err)
			}
			if err := store.FinalizeSessionConfirmationRevocation(context.Background(), FinalizeSessionConfirmationRevocationRequest{
				SessionScope: scope, TeardownOperationID: "teardown_confirmation_scope",
			}); err != nil {
				t.Fatalf("FinalizeSessionConfirmationRevocation() error = %v", err)
			}
			fresh, err := store.RevokeSessionConfirmationIntents(context.Background(), RevokeSessionConfirmationIntentsRequest{
				SessionScope: scope, TeardownOperationID: "teardown_confirmation_scope", Now: now.Add(2 * time.Second),
			})
			if err != nil || fresh != 0 {
				t.Fatalf("RevokeSessionConfirmationIntents(after finalize) = %d, %v", fresh, err)
			}
			listed, err := store.ListConfirmationIntents(context.Background(), ListConfirmationIntentsRequest{})
			if err != nil {
				t.Fatalf("ListConfirmationIntents() error = %v", err)
			}
			if len(listed) != 1 || listed[0].ConfirmationID != sibling.ConfirmationID {
				t.Fatalf("sibling session was affected: %#v", listed)
			}
		})
	}
}

func TestConfirmationSessionRevocationLedgerIsBounded(t *testing.T) {
	store, err := NewMemoryConfirmationIntentStoreWithOptions(ConfirmationIntentStoreOptions{
		MaxTotal: 2, MaxPerOwnerPlugin: 2, MaxPerSession: 1, MaxSessionRevocations: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := confirmationSessionScope(testScopedConfirmationRequest(time.Now().UTC()).Scope)
	if _, err := store.RevokeSessionConfirmationIntents(context.Background(), RevokeSessionConfirmationIntentsRequest{
		SessionScope: first, TeardownOperationID: "first",
	}); err != nil {
		t.Fatal(err)
	}
	second := first
	second.SessionChannelIDHash = "other_channel"
	if _, err := store.RevokeSessionConfirmationIntents(context.Background(), RevokeSessionConfirmationIntentsRequest{
		SessionScope: second, TeardownOperationID: "second",
	}); !errors.Is(err, ErrConfirmationIntentCapacity) {
		t.Fatalf("RevokeSessionConfirmationIntents(over capacity) error = %v", err)
	}
	if err := store.FinalizeSessionConfirmationRevocation(context.Background(), FinalizeSessionConfirmationRevocationRequest{
		SessionScope: first, TeardownOperationID: "first",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeSessionConfirmationIntents(context.Background(), RevokeSessionConfirmationIntentsRequest{
		SessionScope: second, TeardownOperationID: "second",
	}); err != nil {
		t.Fatalf("RevokeSessionConfirmationIntents(after finalize) error = %v", err)
	}
}

func TestSQLiteConfirmationSessionRevocationLedgerCapacitySurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "confirmation-revocations.sqlite")
	options := ConfirmationIntentStoreOptions{
		MaxTotal: 2, MaxPerOwnerPlugin: 2, MaxPerSession: 1, MaxSessionRevocations: 1,
	}
	store, err := NewSQLiteConfirmationIntentStoreWithOptions(ctx, path, options)
	if err != nil {
		t.Fatal(err)
	}
	first := confirmationSessionScope(testScopedConfirmationRequest(time.Now().UTC()).Scope)
	if _, err := store.RevokeSessionConfirmationIntents(ctx, RevokeSessionConfirmationIntentsRequest{
		SessionScope: first, TeardownOperationID: "sqlite_first",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteConfirmationIntentStoreWithOptions(ctx, path, options)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if replayed, err := reopened.RevokeSessionConfirmationIntents(ctx, RevokeSessionConfirmationIntentsRequest{
		SessionScope: first, TeardownOperationID: "sqlite_first",
	}); err != nil || replayed != 0 {
		t.Fatalf("RevokeSessionConfirmationIntents(replay) = %d, %v", replayed, err)
	}
	second := first
	second.SessionChannelIDHash = "sqlite_second_channel"
	if _, err := reopened.RevokeSessionConfirmationIntents(ctx, RevokeSessionConfirmationIntentsRequest{
		SessionScope: second, TeardownOperationID: "sqlite_second",
	}); !errors.Is(err, ErrConfirmationIntentCapacity) {
		t.Fatalf("RevokeSessionConfirmationIntents(over capacity) error = %v", err)
	}
	if err := reopened.FinalizeSessionConfirmationRevocation(ctx, FinalizeSessionConfirmationRevocationRequest{
		SessionScope: first, TeardownOperationID: "sqlite_first",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.RevokeSessionConfirmationIntents(ctx, RevokeSessionConfirmationIntentsRequest{
		SessionScope: second, TeardownOperationID: "sqlite_second",
	}); err != nil {
		t.Fatalf("RevokeSessionConfirmationIntents(after finalize) error = %v", err)
	}
}

func TestSQLiteConfirmationLegacyOwnerMigrationAndMalformedIsolation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy-confirmations.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
CREATE TABLE plugin_confirmation_intents (
	confirmation_id TEXT PRIMARY KEY, confirmation_token_id TEXT NOT NULL,
	plugin_id TEXT NOT NULL, plugin_instance_id TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL, bridge_channel_id TEXT NOT NULL,
	method TEXT NOT NULL, request_hash TEXT NOT NULL, plan_hash TEXT NOT NULL,
	scope_json TEXT NOT NULL DEFAULT '{}', issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX idx_plugin_confirmation_intents_plugin_instance
ON plugin_confirmation_intents(plugin_instance_id, issued_at, confirmation_id)`); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	validScope, err := json.Marshal(persistedConfirmationScopeFrom(testScopedConfirmationRequest(now).Scope))
	if err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO plugin_confirmation_intents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := db.ExecContext(ctx, insert,
		"confirmation_legacy_valid", "token_valid", "com.example.scope", "plugini_scope",
		"surface_scope", "bridge_scope", "scope.test", "sha256:request", "sha256:plan",
		string(validScope), now.UnixNano(), now.Add(time.Hour).UnixNano(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, insert,
		"confirmation_legacy_malformed", "token_malformed", "com.example.scope", "plugini_scope",
		"surface_scope", "bridge_scope", "scope.test", "sha256:request", "sha256:plan",
		`{"owner_env_hash":"env_only"}`, now.UnixNano(), now.Add(time.Hour).UnixNano(),
	); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteConfirmationIntentStore(ctx, path)
	if err != nil {
		t.Fatalf("NewSQLiteConfirmationIntentStore() error = %v", err)
	}
	if _, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{
		ConfirmationID: "confirmation_legacy_valid",
		SessionScope:   confirmationSessionScope(testScopedConfirmationRequest(now).Scope),
		Now:            now,
	}); err != nil {
		t.Fatalf("ConsumeConfirmationIntent(migrated) error = %v", err)
	}
	if _, err := store.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{
		ConfirmationID: "confirmation_legacy_malformed",
		SessionScope:   confirmationSessionScope(testScopedConfirmationRequest(now).Scope),
		Now:            now,
	}); !errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired) {
		t.Fatalf("ConsumeConfirmationIntent(malformed) error = %v, want migration required", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSQLiteConfirmationIntentStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.ConsumeConfirmationIntent(ctx, ConsumeConfirmationIntentRequest{
		ConfirmationID: "confirmation_legacy_malformed",
		SessionScope:   confirmationSessionScope(testScopedConfirmationRequest(now).Scope),
		Now:            now,
	}); !errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired) {
		t.Fatalf("reopen malformed error = %v", err)
	}
}

func TestConfirmationPluginRevokeIsOwnerEnvironmentScoped(t *testing.T) {
	for _, tc := range confirmationIntentStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Unix(1, 0).UTC()
			target := testScopedConfirmationRequest(now)
			if _, err := store.PutConfirmationIntent(context.Background(), target); err != nil {
				t.Fatal(err)
			}
			sibling := testScopedConfirmationRequest(now)
			sibling.ConfirmationID = "confirmation_other_environment"
			sibling.ConfirmationTokenID = "confirmation_token_other_environment"
			sibling.Scope.OwnerSessionHash = "session_other_environment"
			sibling.Scope.OwnerUserHash = "user_other_environment"
			sibling.Scope.OwnerEnvHash = "env_other_environment"
			sibling.Scope.SessionChannelIDHash = "channel_other_environment"
			if _, err := store.PutConfirmationIntent(context.Background(), sibling); err != nil {
				t.Fatal(err)
			}
			revoked, err := store.RevokePluginConfirmationIntents(context.Background(), RevokePluginConfirmationIntentsRequest{
				OwnerEnvHash:     target.Scope.OwnerEnvHash,
				PluginInstanceID: target.PluginInstanceID,
			})
			if err != nil {
				t.Fatalf("RevokePluginConfirmationIntents() error = %v", err)
			}
			if revoked != 1 {
				t.Fatalf("RevokePluginConfirmationIntents() = %d, want 1", revoked)
			}
			listed, err := store.ListConfirmationIntents(context.Background(), ListConfirmationIntentsRequest{PluginInstanceID: target.PluginInstanceID})
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 1 || listed[0].ConfirmationID != sibling.ConfirmationID {
				t.Fatalf("other environment was affected: %#v", listed)
			}
		})
	}
}

func testScopedConfirmationRequest(now time.Time) PutConfirmationIntentRequest {
	return PutConfirmationIntentRequest{
		ConfirmationID:      "confirmation_scope_test",
		ConfirmationTokenID: "confirmation_token_scope_test",
		PluginID:            "com.example.scope",
		PluginInstanceID:    "plugini_scope",
		SurfaceInstanceID:   "surface_scope",
		BridgeChannelID:     "bridge_scope",
		Method:              "scope.test",
		RequestHash:         "sha256:request",
		PlanHash:            "sha256:plan",
		Scope: ConfirmationScope{
			ActiveFingerprint:      "sha256:fingerprint",
			OwnerSessionHash:       "session_scope",
			OwnerUserHash:          "user_scope",
			OwnerEnvHash:           "env_scope",
			SessionChannelIDHash:   "channel_scope",
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
