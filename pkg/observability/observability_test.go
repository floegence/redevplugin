package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

func TestMemoryStoreAppendsAudit(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time { return now }})
	ctx := context.Background()
	details := map[string]any{"method": "plugin.install"}

	if err := store.AppendPluginAudit(ctx, AuditEvent{
		Type:             " plugin.installed ",
		PluginID:         " com.example.a ",
		PluginInstanceID: " plugin_a ",
		Details:          details,
	}); err != nil {
		t.Fatal(err)
	}
	details["method"] = "plugin.mutated"
	store.mu.RLock()
	defer store.mu.RUnlock()
	audits := store.auditEvents.Snapshot()
	if len(audits) != 1 {
		t.Fatalf("stored audit count = %d, want 1", len(audits))
	}
	event := audits[0]
	if event.EventID == "" || event.Type != "plugin.installed" || event.PluginID != "com.example.a" || event.PluginInstanceID != "plugin_a" || event.OccurredAt != now {
		t.Fatalf("stored audit event mismatch: %#v", event)
	}
	if event.Details["method"] != "plugin.install" {
		t.Fatalf("stored audit details were mutated by caller: %#v", event.Details)
	}
}

func TestFailureFromErrorRedactsCause(t *testing.T) {
	causes := []error{
		errors.New("Authorization: Bearer bearer-token-super-secret"),
		errors.New("open /Users/private/plugin.sqlite: permission denied"),
		errors.New("GET https://api.example.com/resource?access_token=query-secret"),
		errors.New("Cookie: session=cookie-secret"),
		errors.New("secret_ref=vault-production-token"),
	}
	for _, cause := range causes {
		failure := FailureFromError(FailureAdapter, FailureComponentSecrets, FailureOperationSecretsAdapter, cause)
		if !failure.Valid() || failure.Code != FailureAdapter || failure.Component != FailureComponentSecrets || failure.Operation != FailureOperationSecretsAdapter {
			t.Fatalf("FailureFromError() = %#v", failure)
		}
		encoded, err := json.Marshal(failure)
		if err != nil {
			t.Fatal(err)
		}
		combined := string(encoded) + " " + failure.Error()
		for _, forbidden := range []string{
			"bearer-token-super-secret",
			"/Users/private",
			"query-secret",
			"cookie-secret",
			"vault-production-token",
		} {
			if strings.Contains(combined, forbidden) {
				t.Fatalf("failure leaked %q from %q: %s", forbidden, cause, combined)
			}
		}
	}
}

func TestFailureFromErrorRejectsUntrustedMetadata(t *testing.T) {
	failure := FailureFromError("unknown", FailureComponentRuntime, FailureOperation("runtime.start?token=secret"), errors.New("secret"))
	if failure.Valid() || failure.Error() != "invalid_diagnostic_failure" {
		t.Fatalf("FailureFromError() = %#v, error = %q", failure, failure.Error())
	}
	if failure := FailureFromError(FailureAdapter, FailureComponentSecrets, FailureOperationSecretsAdapter, nil); failure != (Failure{}) {
		t.Fatalf("FailureFromError(nil) = %#v", failure)
	}
	if failure := FailureFromError(FailureAdapter, FailureComponentRuntime, FailureOperation("runtime.start"), errors.New("secret")); failure.Valid() {
		t.Fatalf("FailureFromError() accepted undeclared operation: %#v", failure)
	}
}

func TestMemoryStoreAuditSinkIsIdempotentByEventID(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	event := AuditEvent{EventID: " security-event-1 ", Type: "plugin.enabled", Details: map[string]any{"policy_revision": 1}}
	if err := store.AppendPluginAudit(ctx, event); err != nil {
		t.Fatal(err)
	}
	event.Details["policy_revision"] = 2
	if err := store.AppendPluginAudit(ctx, event); err != nil {
		t.Fatal(err)
	}
	store.mu.RLock()
	events := store.auditEvents.Snapshot()
	store.mu.RUnlock()
	if len(events) != 1 || events[0].EventID != "security-event-1" || events[0].Details["policy_revision"] != float64(1) {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestMemoryStoreDiagnosticsListFiltersAndDefaults(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time { return now }})
	ctx := context.Background()

	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{
		Type:                 "plugin.csp.violation",
		Severity:             DiagnosticSeverityInfo,
		Message:              "plugin content security policy violation",
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugin_a",
		SurfaceInstanceID:    "surface_a",
		OwnerSessionHash:     "session_a",
		OwnerUserHash:        "user_a",
		OwnerEnvHash:         "env_a",
		SessionChannelIDHash: "channel_a",
		Details:              DiagnosticDetails{Reason: "inline"},
		Failure: FailureFromError(
			FailureAction,
			FailureComponentRuntime,
			FailureOperationRuntimeHostcall,
			errors.New("internal-memory-cause"),
		),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{
		Type:                 "plugin.runtime.warning",
		Severity:             "warning",
		Message:              "runtime warning",
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugin_a",
		SurfaceInstanceID:    "surface_b",
		OwnerSessionHash:     "session_b",
		OwnerUserHash:        "user_b",
		OwnerEnvHash:         "env_b",
		SessionChannelIDHash: "channel_b",
		OccurredAt:           now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	events, err := store.ListPluginDiagnostics(ctx, ListDiagnosticRequest{
		PluginInstanceID:     "plugin_a",
		SurfaceInstanceID:    "surface_a",
		OwnerSessionHash:     "session_a",
		OwnerUserHash:        "user_a",
		OwnerEnvHash:         "env_a",
		SessionChannelIDHash: "channel_a",
		Severity:             "info",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Message != "plugin content security policy violation" || events[0].Details.Reason != "inline" {
		t.Fatalf("ListPluginDiagnostics() = %#v", events)
	}
	if events[0].OwnerSessionHash != "session_a" || events[0].OwnerUserHash != "user_a" || events[0].OwnerEnvHash != "env_a" || events[0].SessionChannelIDHash != "channel_a" {
		t.Fatalf("diagnostic owner scope mismatch: %#v", events[0])
	}
	if !events[0].Failure.Empty() {
		t.Fatalf("memory diagnostic list exposed internal failure: %#v", events[0])
	}
	store.mu.RLock()
	storedFailure := store.diagnosticEvents.Snapshot()[0].Failure
	store.mu.RUnlock()
	if !storedFailure.Valid() || strings.Contains(fmt.Sprint(storedFailure), "internal-memory-cause") {
		t.Fatalf("memory diagnostic sink stored an invalid failure: %#v", storedFailure)
	}
	otherOwner, err := store.ListPluginDiagnostics(ctx, ListDiagnosticRequest{
		OwnerSessionHash: "session_b", OwnerUserHash: "user_b", OwnerEnvHash: "env_b", SessionChannelIDHash: "channel_b", Severity: "info",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(otherOwner) != 0 {
		t.Fatalf("owner-scoped diagnostics leaked events: %#v", otherOwner)
	}

	events, err = store.ListPluginDiagnostics(ctx, ListDiagnosticRequest{
		PluginID: "com.example.plugin", Severity: "warning",
		OwnerSessionHash: "session_b", OwnerUserHash: "user_b", OwnerEnvHash: "env_b", SessionChannelIDHash: "channel_b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "plugin.runtime.warning" {
		t.Fatalf("warning diagnostics mismatch: %#v", events)
	}
}

func TestMemoryStoreRejectsInvalidEvent(t *testing.T) {
	store := NewMemoryStore()
	if err := store.AppendPluginAudit(context.Background(), AuditEvent{}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("AppendPluginAudit() error = %v, want ErrInvalidEvent", err)
	}
	if err := store.AppendPluginDiagnostic(context.Background(), DiagnosticEvent{}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("AppendPluginDiagnostic() error = %v, want ErrInvalidEvent", err)
	}
	if err := store.AppendPluginDiagnostic(context.Background(), DiagnosticEvent{Type: "plugin.runtime.warning", Severity: "critical", Message: "runtime warning"}); !errors.Is(err, ErrInvalidDiagnosticSeverity) {
		t.Fatalf("AppendPluginDiagnostic(invalid severity) error = %v, want ErrInvalidDiagnosticSeverity", err)
	}
	for _, event := range invalidDiagnosticEvents() {
		if err := store.AppendPluginDiagnostic(context.Background(), event); err == nil {
			t.Fatalf("AppendPluginDiagnostic(%#v) error = nil, want rejection", event)
		}
	}
	store.mu.RLock()
	stored := store.diagnosticEvents.Len()
	store.mu.RUnlock()
	if stored != 0 {
		t.Fatalf("invalid diagnostic events persisted in memory: %d", stored)
	}
	request := scopedDiagnosticRequest(10)
	request.Severity = "critical"
	if _, err := store.ListPluginDiagnostics(context.Background(), request); !errors.Is(err, ErrInvalidDiagnosticSeverity) {
		t.Fatalf("ListPluginDiagnostics(invalid severity) error = %v, want ErrInvalidDiagnosticSeverity", err)
	}
}

func TestDiagnosticStoresRoundTripRuntimeProcessFailureCode(t *testing.T) {
	type diagnosticStore interface {
		DiagnosticsSink
		DiagnosticLister
	}
	tests := []struct {
		name string
		open func(*testing.T) (diagnosticStore, func())
	}{
		{
			name: "memory",
			open: func(*testing.T) (diagnosticStore, func()) {
				return NewMemoryStore(), func() {}
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) (diagnosticStore, func()) {
				store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "observability.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				return store, func() {
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, closeStore := test.open(t)
			defer closeStore()
			event := scopedDiagnosticEvent("plugin.runtime.process.exited")
			event.Severity = DiagnosticSeverityWarning
			event.Message = "runtime process exited with error"
			event.Details.RuntimeProcessFailureCode = RuntimeProcessWriterWriteFailed
			if err := store.AppendPluginDiagnostic(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			events, err := store.ListPluginDiagnostics(context.Background(), scopedDiagnosticRequest(1))
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].Details.RuntimeProcessFailureCode != RuntimeProcessWriterWriteFailed {
				t.Fatalf("runtime process failure code round-trip = %#v", events)
			}
		})
	}
}

func TestMemoryStoreTrimsOldestEvents(t *testing.T) {
	store := NewMemoryStore(MemoryStoreOptions{MaxAuditEvents: 2, MaxDiagnosticEvents: 1})
	ctx := context.Background()
	for _, eventType := range []string{"a", "b", "c"} {
		if err := store.AppendPluginAudit(ctx, AuditEvent{Type: eventType}); err != nil {
			t.Fatal(err)
		}
	}
	store.mu.RLock()
	audits := store.auditEvents.Snapshot()
	store.mu.RUnlock()
	if len(audits) != 2 || audits[0].Type != "b" || audits[1].Type != "c" {
		t.Fatalf("trimmed audits mismatch: %#v", audits)
	}

	for _, eventType := range []string{"plugin.runtime.process.started", "plugin.runtime.ipc.handshake"} {
		if err := store.AppendPluginDiagnostic(ctx, scopedDiagnosticEvent(eventType)); err != nil {
			t.Fatal(err)
		}
	}
	diagnostics, err := store.ListPluginDiagnostics(ctx, scopedDiagnosticRequest(10))
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 1 || diagnostics[0].Type != "plugin.runtime.ipc.handshake" {
		t.Fatalf("trimmed diagnostics mismatch: %#v", diagnostics)
	}
}

func TestSQLiteStorePersistsAuditAndDiagnosticsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observability.sqlite")
	now := time.Date(2026, 7, 2, 9, 0, 0, 0, time.UTC)
	store, err := NewSQLiteStore(ctx, path, MemoryStoreOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPluginAudit(ctx, AuditEvent{
		Type:             " plugin.installed ",
		PluginID:         " com.example.plugin ",
		PluginInstanceID: " plugin_1 ",
		SurfaceID:        " activity ",
		RequestID:        " request_1 ",
		Actor:            " user_admin ",
		Details:          map[string]any{"method": "plugin.install"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{
		Type:                 "plugin.csp.violation",
		Severity:             DiagnosticSeverityInfo,
		Message:              "plugin content security policy violation",
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugin_1",
		SurfaceInstanceID:    "surface_1",
		ActiveFingerprint:    "sha256:demo",
		OwnerSessionHash:     "session_1",
		OwnerUserHash:        "user_1",
		OwnerEnvHash:         "env_1",
		SessionChannelIDHash: "channel_1",
		CorrelationID:        "correlation_1",
		MutationOutcome:      mutation.OutcomeUnknown,
		Details:              DiagnosticDetails{Reason: "inline"},
		Failure: FailureFromError(
			FailureAdapter,
			FailureComponentRuntime,
			FailureOperationRuntimeHostcall,
			errors.New("private sqlite path /Users/secret/plugin.sqlite"),
		),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	var auditEventID string
	var auditPluginID string
	var auditOccurredAt int64
	var auditDetailsRaw []byte
	if err := reopened.db.QueryRowContext(ctx, `
SELECT event_id, plugin_id, occurred_at, details_json
FROM plugin_audit_events
WHERE plugin_instance_id = ? AND type = ?`, "plugin_1", "plugin.installed").Scan(&auditEventID, &auditPluginID, &auditOccurredAt, &auditDetailsRaw); err != nil {
		t.Fatal(err)
	}
	auditDetails, err := unmarshalDetails(auditDetailsRaw)
	if err != nil {
		t.Fatal(err)
	}
	if auditEventID != "audit_000000000001" || auditPluginID != "com.example.plugin" || auditOccurredAt != now.UnixNano() || auditDetails["method"] != "plugin.install" {
		t.Fatalf("persisted audit event mismatch: id=%q plugin=%q occurred_at=%d details=%#v", auditEventID, auditPluginID, auditOccurredAt, auditDetails)
	}

	diagnostics, err := reopened.ListPluginDiagnostics(ctx, ListDiagnosticRequest{
		PluginInstanceID: "plugin_1", SurfaceInstanceID: "surface_1", Severity: "info",
		OwnerSessionHash: "session_1", OwnerUserHash: "user_1", OwnerEnvHash: "env_1", SessionChannelIDHash: "channel_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 1 || diagnostics[0].EventID != "diagnostic_000000000001" || diagnostics[0].Message != "plugin content security policy violation" || diagnostics[0].Details.Reason != "inline" {
		t.Fatalf("persisted diagnostic events mismatch: %#v", diagnostics)
	}
	if diagnostics[0].OwnerSessionHash != "session_1" || diagnostics[0].SessionChannelIDHash != "channel_1" {
		t.Fatalf("persisted diagnostic owner scope mismatch: %#v", diagnostics[0])
	}
	if !diagnostics[0].Failure.Empty() {
		t.Fatalf("sqlite diagnostic list exposed internal failure: %#v", diagnostics[0])
	}
	var correlationID string
	var mutationOutcome string
	var failureCode string
	var failureComponent string
	var failureOperation string
	if err := reopened.db.QueryRowContext(ctx, `
SELECT correlation_id, mutation_outcome, failure_code, failure_component, failure_operation
FROM plugin_diagnostic_events
WHERE event_id = ?`, "diagnostic_000000000001").Scan(
		&correlationID,
		&mutationOutcome,
		&failureCode,
		&failureComponent,
		&failureOperation,
	); err != nil {
		t.Fatal(err)
	}
	if correlationID != "correlation_1" || mutationOutcome != string(mutation.OutcomeUnknown) ||
		failureCode != string(FailureAdapter) || failureComponent != string(FailureComponentRuntime) || failureOperation != "runtime.hostcall" {
		t.Fatalf("persisted diagnostic failure mismatch: correlation=%q outcome=%q failure=%q/%q/%q", correlationID, mutationOutcome, failureCode, failureComponent, failureOperation)
	}
	encodedDiagnostic, err := json.Marshal(diagnostics[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedDiagnostic), "private sqlite path") || strings.Contains(string(encodedDiagnostic), "internal_details") {
		t.Fatalf("internal diagnostic details were serialized: %s", encodedDiagnostic)
	}

	if err := reopened.AppendPluginAudit(ctx, AuditEvent{Type: "plugin.enabled"}); err != nil {
		t.Fatal(err)
	}
	var nextAuditEventID string
	if err := reopened.db.QueryRowContext(ctx, `SELECT event_id FROM plugin_audit_events WHERE type = ?`, "plugin.enabled").Scan(&nextAuditEventID); err != nil {
		t.Fatal(err)
	}
	if nextAuditEventID != "audit_000000000002" {
		t.Fatalf("persisted audit sequence = %q, want audit_000000000002", nextAuditEventID)
	}
}

func TestSQLiteStoreTrimsOldestEvents(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "observability.sqlite"), MemoryStoreOptions{
		MaxAuditEvents:      2,
		MaxDiagnosticEvents: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	base := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	for index, eventType := range []string{"a", "b", "c"} {
		if err := store.AppendPluginAudit(ctx, AuditEvent{Type: eventType, OccurredAt: base.Add(time.Duration(index) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.db.QueryContext(ctx, `SELECT type FROM plugin_audit_events ORDER BY seq DESC`)
	if err != nil {
		t.Fatal(err)
	}
	var auditTypes []string
	for rows.Next() {
		var eventType string
		if err := rows.Scan(&eventType); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		auditTypes = append(auditTypes, eventType)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(auditTypes) != 2 || auditTypes[0] != "c" || auditTypes[1] != "b" {
		t.Fatalf("trimmed sqlite audit types mismatch: %#v", auditTypes)
	}

	for index, eventType := range []string{"plugin.runtime.process.started", "plugin.runtime.ipc.handshake"} {
		event := scopedDiagnosticEvent(eventType)
		event.OccurredAt = base.Add(time.Duration(index) * time.Second)
		if err := store.AppendPluginDiagnostic(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	diagnostics, err := store.ListPluginDiagnostics(ctx, scopedDiagnosticRequest(10))
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 1 || diagnostics[0].Type != "plugin.runtime.ipc.handshake" {
		t.Fatalf("trimmed sqlite diagnostics mismatch: %#v", diagnostics)
	}
}

func TestSQLiteStoreAuditSinkIsIdempotentByEventID(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "observability.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	event := AuditEvent{EventID: " security-event-1 ", Type: "plugin.enabled", Details: map[string]any{"policy_revision": 1}}
	if err := store.AppendPluginAudit(ctx, event); err != nil {
		t.Fatal(err)
	}
	event.Details["policy_revision"] = 2
	if err := store.AppendPluginAudit(ctx, event); err != nil {
		t.Fatal(err)
	}
	var count int
	var rawDetails []byte
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*), details_json FROM plugin_audit_events WHERE event_id = ?`, "security-event-1").Scan(&count, &rawDetails); err != nil {
		t.Fatal(err)
	}
	details, err := unmarshalDetails(rawDetails)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || details["policy_revision"] != float64(1) {
		t.Fatalf("count = %d, details = %#v", count, details)
	}
}

func TestDiagnosticStoresRejectIncompleteOwnerScope(t *testing.T) {
	tests := []struct {
		name string
		open func(*testing.T) DiagnosticLister
	}{
		{name: "memory", open: func(*testing.T) DiagnosticLister { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) DiagnosticLister {
			store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "observability.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Error(err)
				}
			})
			return store
		}},
	}
	requests := []ListDiagnosticRequest{
		{},
		{OwnerSessionHash: "session_1"},
		{OwnerSessionHash: "session_1", OwnerUserHash: "user_1", OwnerEnvHash: "env_1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := test.open(t)
			for _, req := range requests {
				if _, err := store.ListPluginDiagnostics(context.Background(), req); !errors.Is(err, ErrDiagnosticScopeRequired) {
					t.Fatalf("ListPluginDiagnostics(%#v) error = %v, want %v", req, err, ErrDiagnosticScopeRequired)
				}
			}
		})
	}
}

func scopedDiagnosticEvent(eventType string) DiagnosticEvent {
	message := map[string]string{
		"plugin.runtime.process.started": "runtime process started",
		"plugin.runtime.ipc.handshake":   "runtime IPC handshake completed",
	}[eventType]
	return DiagnosticEvent{
		Type: eventType, Severity: DiagnosticSeverityInfo, Message: message, OwnerSessionHash: "session_1", OwnerUserHash: "user_1",
		OwnerEnvHash: "env_1", SessionChannelIDHash: "channel_1",
	}
}

func scopedDiagnosticRequest(limit int) ListDiagnosticRequest {
	return ListDiagnosticRequest{
		OwnerSessionHash: "session_1", OwnerUserHash: "user_1", OwnerEnvHash: "env_1",
		SessionChannelIDHash: "channel_1", Limit: limit,
	}
}

func TestSQLiteStoreRejectsInvalidEvent(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "observability.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	if err := store.AppendPluginAudit(ctx, AuditEvent{}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("AppendPluginAudit() error = %v, want ErrInvalidEvent", err)
	}
	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("AppendPluginDiagnostic() error = %v, want ErrInvalidEvent", err)
	}
	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{Type: "plugin.runtime.warning", Severity: "critical", Message: "runtime warning"}); !errors.Is(err, ErrInvalidDiagnosticSeverity) {
		t.Fatalf("AppendPluginDiagnostic(invalid severity) error = %v, want ErrInvalidDiagnosticSeverity", err)
	}
	for _, event := range invalidDiagnosticEvents() {
		if err := store.AppendPluginDiagnostic(ctx, event); err == nil {
			t.Fatalf("AppendPluginDiagnostic(%#v) error = nil, want rejection", event)
		}
	}
	var persisted int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_diagnostic_events`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 0 {
		t.Fatalf("invalid diagnostic events persisted in sqlite: %d", persisted)
	}
	request := scopedDiagnosticRequest(10)
	request.Severity = "critical"
	if _, err := store.ListPluginDiagnostics(ctx, request); !errors.Is(err, ErrInvalidDiagnosticSeverity) {
		t.Fatalf("ListPluginDiagnostics(invalid severity) error = %v, want ErrInvalidDiagnosticSeverity", err)
	}
}

func TestDiagnosticStoresNeverPersistSensitiveFailureCause(t *testing.T) {
	const sensitiveCause = "Authorization: Bearer bearer-token-super-secret; Cookie: session=cookie-secret; secret_ref=vault-production-token; GET https://api.example.com/resource?access_token=query-secret; open /Users/private/plugin.sqlite: permission denied"
	event := DiagnosticEvent{
		Type:                 "plugin.secret.adapter_failed",
		Severity:             DiagnosticSeverityWarning,
		Message:              "secret adapter operation failed",
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugin_1",
		RequestID:            "request_1",
		CorrelationID:        "correlation_1",
		MutationOutcome:      mutation.OutcomeUnknown,
		OwnerSessionHash:     "session_1",
		OwnerUserHash:        "user_1",
		OwnerEnvHash:         "env_1",
		SessionChannelIDHash: "channel_1",
		Details:              DiagnosticDetails{Operation: "secrets.bind", Code: "PLUGIN_ADAPTER_FAILURE"},
		Failure: FailureFromError(
			FailureAdapter,
			FailureComponentSecrets,
			FailureOperationSecretsAdapter,
			errors.New(sensitiveCause),
		),
	}
	for _, test := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "memory", run: func(t *testing.T) {
			store := NewMemoryStore()
			if err := store.AppendPluginDiagnostic(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			store.mu.RLock()
			stored := store.diagnosticEvents.Snapshot()
			store.mu.RUnlock()
			assertStableDiagnosticFailure(t, stored, sensitiveCause)
			listed, err := store.ListPluginDiagnostics(context.Background(), scopedDiagnosticRequest(10))
			if err != nil {
				t.Fatal(err)
			}
			assertPublicDiagnosticFailureHidden(t, listed)
		}},
		{name: "sqlite", run: func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observability.sqlite")
			store, err := NewSQLiteStore(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.AppendPluginDiagnostic(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			var failureCode, failureComponent, failureOperation string
			if err := store.db.QueryRow(`SELECT failure_code, failure_component, failure_operation FROM plugin_diagnostic_events`).Scan(&failureCode, &failureComponent, &failureOperation); err != nil {
				t.Fatal(err)
			}
			if failureCode != string(FailureAdapter) || failureComponent != string(FailureComponentSecrets) || failureOperation != string(FailureOperationSecretsAdapter) {
				t.Fatalf("persisted failure = %q/%q/%q", failureCode, failureComponent, failureOperation)
			}
			listed, err := store.ListPluginDiagnostics(context.Background(), scopedDiagnosticRequest(10))
			if err != nil {
				t.Fatal(err)
			}
			assertPublicDiagnosticFailureHidden(t, listed)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			assertSensitiveValuesAbsent(t, string(raw), sensitiveCause)
		}},
	} {
		t.Run(test.name, test.run)
	}
}

func TestSQLiteStoreRejectsCorruptDiagnosticRowOnReopen(t *testing.T) {
	for _, test := range []struct {
		name    string
		details string
	}{
		{name: "unknown field", details: `{"unknown":"https://example.com/?token=secret"}`},
		{name: "unknown runtime process failure", details: `{"runtime_process_failure_code":"RUNTIME_PROCESS_UNKNOWN"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "observability.sqlite")
			store, err := NewSQLiteStore(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.AppendPluginDiagnostic(ctx, scopedDiagnosticEvent("plugin.runtime.process.started")); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `UPDATE plugin_diagnostic_events SET details_json = ?`, []byte(test.details)); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := NewSQLiteStore(ctx, path); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("NewSQLiteStore(corrupt row) error = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

func TestAuditStoresPersistOnlyStableFailureMetadata(t *testing.T) {
	const sensitiveCause = "Authorization: Bearer bearer-token-super-secret; Cookie: session=cookie-secret; secret_ref=vault-production-token; GET https://api.example.com/resource?access_token=query-secret; open /Users/private/plugin.sqlite: permission denied"
	event := AuditEvent{
		Type:      "plugin.enabled",
		RequestID: "request_1",
		Details: map[string]any{
			"mutation_outcome": string(mutation.OutcomeUnknown),
			"failure": FailureFromError(
				FailureAdapter,
				FailureComponentSecurity,
				FailureOperationSecurityMutationComplete,
				errors.New(sensitiveCause),
			),
		},
	}
	for _, test := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "memory", run: func(t *testing.T) {
			store := NewMemoryStore()
			if err := store.AppendPluginAudit(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			store.mu.RLock()
			stored := store.auditEvents.Snapshot()
			store.mu.RUnlock()
			if len(stored) != 1 {
				t.Fatalf("stored audits = %#v", stored)
			}
			assertSensitiveValuesAbsent(t, fmt.Sprint(stored), sensitiveCause)
		}},
		{name: "sqlite", run: func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observability.sqlite")
			store, err := NewSQLiteStore(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.AppendPluginAudit(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			assertSensitiveValuesAbsent(t, string(raw), sensitiveCause)
		}},
	} {
		t.Run(test.name, test.run)
	}
}

func TestAuditStoresRejectUnsafeDetailsWithoutPersistence(t *testing.T) {
	invalid := []AuditEvent{
		{Type: "plugin.enabled", Details: map[string]any{"reason": "Authorization: Bearer secret"}},
		{Type: "plugin.enabled", Details: map[string]any{"unknown": "value"}},
		{Type: "plugin.enabled", Actor: "/Users/private/plugin.sqlite"},
		{Type: "plugin.enabled", Details: map[string]any{"policy_revision": uint64(maxSafeInteger + 1)}},
	}
	for _, test := range []struct {
		name string
		open func(*testing.T) (*MemoryStore, *SQLiteStore)
	}{
		{name: "memory", open: func(*testing.T) (*MemoryStore, *SQLiteStore) { return NewMemoryStore(), nil }},
		{name: "sqlite", open: func(t *testing.T) (*MemoryStore, *SQLiteStore) {
			store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "observability.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return nil, store
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			memory, sqliteStore := test.open(t)
			for _, event := range invalid {
				var err error
				if memory != nil {
					err = memory.AppendPluginAudit(context.Background(), event)
				} else {
					err = sqliteStore.AppendPluginAudit(context.Background(), event)
				}
				if err == nil {
					t.Fatalf("AppendPluginAudit(%#v) error = nil, want rejection", event)
				}
			}
			if memory != nil {
				memory.mu.RLock()
				count := memory.auditEvents.Len()
				memory.mu.RUnlock()
				if count != 0 {
					t.Fatalf("invalid memory audits persisted: %d", count)
				}
				return
			}
			var count int
			if err := sqliteStore.db.QueryRow(`SELECT COUNT(*) FROM plugin_audit_events`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("invalid sqlite audits persisted: %d", count)
			}
		})
	}
}

func TestSQLiteStoreMigratesOnlyValidLegacyDiagnosticRows(t *testing.T) {
	for _, test := range []struct {
		name        string
		detailsJSON string
		wantErr     bool
	}{
		{name: "valid", detailsJSON: `{"reason":"inline"}`},
		{name: "unsafe", detailsJSON: `{"error":"Authorization: Bearer secret"}`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "observability.sqlite")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `
CREATE TABLE plugin_diagnostic_events (
	seq INTEGER PRIMARY KEY,
	event_id TEXT NOT NULL UNIQUE,
	type TEXT NOT NULL,
	severity TEXT NOT NULL,
	message TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	surface_id TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	active_fingerprint TEXT NOT NULL,
	request_id TEXT NOT NULL,
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	owner_env_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	occurred_at INTEGER NOT NULL,
	details_json BLOB NOT NULL
);
INSERT INTO plugin_diagnostic_events VALUES(1, 'diagnostic_legacy', 'plugin.csp.violation', 'info', 'plugin content security policy violation', 'com.example.plugin', 'plugin_1', '', 'surface_1', 'sha256:demo', 'request_1', 'session_1', 'user_1', 'env_1', 'channel_1', 1, ?);`, []byte(test.detailsJSON)); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := NewSQLiteStore(ctx, path)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidEvent) {
					t.Fatalf("NewSQLiteStore() error = %v, want ErrInvalidEvent", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var correlationID, failureCode string
			if err := store.db.QueryRow(`SELECT correlation_id, failure_code FROM plugin_diagnostic_events WHERE event_id = 'diagnostic_legacy'`).Scan(&correlationID, &failureCode); err != nil {
				t.Fatal(err)
			}
			if correlationID != "" || failureCode != "" {
				t.Fatalf("legacy stable columns = correlation %q failure %q", correlationID, failureCode)
			}
		})
	}
}

func TestSQLiteStoreRejectsCorruptAuditRowsOnReopen(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(context.Context, *SQLiteStore) error
		corrupt string
	}{
		{
			name: "audit event",
			prepare: func(ctx context.Context, store *SQLiteStore) error {
				return store.AppendPluginAudit(ctx, AuditEvent{Type: "plugin.enabled", Details: map[string]any{"method": "plugin.enable"}})
			},
			corrupt: `UPDATE plugin_audit_events SET details_json = '{"unknown":"secret"}'`,
		},
		{
			name: "security audit",
			prepare: func(ctx context.Context, store *SQLiteStore) error {
				_, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.enabled"})
				return err
			},
			corrupt: `UPDATE plugin_security_audit_journal SET details_json = '{"unknown":"secret"}'`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "observability.sqlite")
			store, err := NewSQLiteStore(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.prepare(ctx, store); err != nil {
				store.Close()
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, test.corrupt); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := NewSQLiteStore(ctx, path); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("NewSQLiteStore(corrupt audit) error = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

func invalidDiagnosticEvents() []DiagnosticEvent {
	base := DiagnosticEvent{
		Type:                 "plugin.runtime.warning",
		Severity:             DiagnosticSeverityWarning,
		Message:              "runtime warning",
		OwnerSessionHash:     "session_1",
		OwnerUserHash:        "user_1",
		OwnerEnvHash:         "env_1",
		SessionChannelIDHash: "channel_1",
	}
	withRawMessage := base
	withRawMessage.Message = "runtime warning: Authorization: Bearer secret"
	withUnsafeOperation := base
	withUnsafeOperation.Details.Operation = "runtime.start?token=secret"
	withAbsolutePath := base
	withAbsolutePath.Details.Artifact = "/Users/private/plugin.wasm"
	withInvalidFailure := base
	withInvalidFailure.Failure = Failure{Code: FailureAdapter, Component: FailureComponentRuntime, Operation: "runtime.start?token=secret"}
	withUnsafeCorrelation := base
	withUnsafeCorrelation.CorrelationID = "https://example.com/?token=secret"
	withUnsafeCount := base
	withUnsafeCount.Details.OperationsDeleted = int64(maxSafeInteger) + 1
	withUnknownRuntimeProcessFailure := base
	withUnknownRuntimeProcessFailure.Details.RuntimeProcessFailureCode = "RUNTIME_PROCESS_UNKNOWN"
	return []DiagnosticEvent{
		withRawMessage,
		withUnsafeOperation,
		withAbsolutePath,
		withInvalidFailure,
		withUnsafeCorrelation,
		withUnsafeCount,
		withUnknownRuntimeProcessFailure,
	}
}

func assertStableDiagnosticFailure(t *testing.T, events []DiagnosticEvent, sensitiveCause string) {
	t.Helper()
	if len(events) != 1 || events[0].Failure != (Failure{Code: FailureAdapter, Component: FailureComponentSecrets, Operation: FailureOperationSecretsAdapter}) {
		t.Fatalf("stored diagnostic failure = %#v", events)
	}
	assertSensitiveValuesAbsent(t, fmt.Sprint(events), sensitiveCause)
}

func assertPublicDiagnosticFailureHidden(t *testing.T, events []DiagnosticEvent) {
	t.Helper()
	if len(events) != 1 || !events[0].Failure.Empty() || events[0].RequestID != "request_1" || events[0].CorrelationID != "correlation_1" || events[0].MutationOutcome != mutation.OutcomeUnknown {
		t.Fatalf("public diagnostic projection = %#v", events)
	}
}

func assertSensitiveValuesAbsent(t *testing.T, stored, sensitiveCause string) {
	t.Helper()
	for _, forbidden := range []string{
		sensitiveCause,
		"bearer-token-super-secret",
		"cookie-secret",
		"vault-production-token",
		"query-secret",
		"/Users/private/plugin.sqlite",
	} {
		if strings.Contains(stored, forbidden) {
			t.Fatalf("stored diagnostic leaked %q", forbidden)
		}
	}
}
