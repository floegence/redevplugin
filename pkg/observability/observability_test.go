package observability

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMemoryStoreAppendsAudit(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time { return now }})
	ctx := context.Background()
	details := map[string]any{"phase": "install"}

	if err := store.AppendPluginAudit(ctx, AuditEvent{
		Type:             " plugin.installed ",
		PluginID:         " com.example.a ",
		PluginInstanceID: " plugin_a ",
		Details:          details,
	}); err != nil {
		t.Fatal(err)
	}
	details["phase"] = "mutated"
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
	if event.Details["phase"] != "install" {
		t.Fatalf("stored audit details were mutated by caller: %#v", event.Details)
	}
}

func TestMemoryStoreAuditSinkIsIdempotentByEventID(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	event := AuditEvent{EventID: " security-event-1 ", Type: "plugin.enabled", Details: map[string]any{"attempt": 1}}
	if err := store.AppendPluginAudit(ctx, event); err != nil {
		t.Fatal(err)
	}
	event.Details["attempt"] = 2
	if err := store.AppendPluginAudit(ctx, event); err != nil {
		t.Fatal(err)
	}
	store.mu.RLock()
	events := store.auditEvents.Snapshot()
	store.mu.RUnlock()
	if len(events) != 1 || events[0].EventID != "security-event-1" || events[0].Details["attempt"] != 1 {
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
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugin_a",
		SurfaceInstanceID:    "surface_a",
		OwnerSessionHash:     "session_a",
		OwnerUserHash:        "user_a",
		OwnerEnvHash:         "env_a",
		SessionChannelIDHash: "channel_a",
		Details:              map[string]any{"blocked_uri": "inline"},
		InternalDetails:      map[string]any{"error": "internal-memory-cause"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{
		Type:                 "plugin.runtime.warning",
		Severity:             "warning",
		Message:              "runtime slowed",
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
	if len(events) != 1 || events[0].Message != "plugin.csp.violation" || events[0].Details["blocked_uri"] != "inline" {
		t.Fatalf("ListPluginDiagnostics() = %#v", events)
	}
	if events[0].OwnerSessionHash != "session_a" || events[0].OwnerUserHash != "user_a" || events[0].OwnerEnvHash != "env_a" || events[0].SessionChannelIDHash != "channel_a" {
		t.Fatalf("diagnostic owner scope mismatch: %#v", events[0])
	}
	if events[0].InternalDetails != nil {
		t.Fatalf("memory diagnostic list exposed internal details: %#v", events[0])
	}
	store.mu.RLock()
	storedInternalCause := store.diagnosticEvents.Snapshot()[0].InternalDetails["error"]
	store.mu.RUnlock()
	if storedInternalCause != "internal-memory-cause" {
		t.Fatalf("memory diagnostic sink lost internal cause: %#v", storedInternalCause)
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
	if err := store.AppendPluginDiagnostic(context.Background(), DiagnosticEvent{Type: "plugin.invalid.severity", Severity: "critical"}); !errors.Is(err, ErrInvalidDiagnosticSeverity) {
		t.Fatalf("AppendPluginDiagnostic(invalid severity) error = %v, want ErrInvalidDiagnosticSeverity", err)
	}
	request := scopedDiagnosticRequest(10)
	request.Severity = "critical"
	if _, err := store.ListPluginDiagnostics(context.Background(), request); !errors.Is(err, ErrInvalidDiagnosticSeverity) {
		t.Fatalf("ListPluginDiagnostics(invalid severity) error = %v, want ErrInvalidDiagnosticSeverity", err)
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

	for _, eventType := range []string{"d1", "d2"} {
		if err := store.AppendPluginDiagnostic(ctx, scopedDiagnosticEvent(eventType)); err != nil {
			t.Fatal(err)
		}
	}
	diagnostics, err := store.ListPluginDiagnostics(ctx, scopedDiagnosticRequest(10))
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 1 || diagnostics[0].Type != "d2" {
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
		Details:          map[string]any{"phase": "install"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{
		Type:                 "plugin.csp.violation",
		Severity:             DiagnosticSeverityInfo,
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugin_1",
		SurfaceInstanceID:    "surface_1",
		ActiveFingerprint:    "sha256:demo",
		OwnerSessionHash:     "session_1",
		OwnerUserHash:        "user_1",
		OwnerEnvHash:         "env_1",
		SessionChannelIDHash: "channel_1",
		Details:              map[string]any{"blocked_uri": "inline"},
		InternalDetails:      map[string]any{"error": "private sqlite path /Users/secret/plugin.sqlite"},
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
	if auditEventID != "audit_000000000001" || auditPluginID != "com.example.plugin" || auditOccurredAt != now.UnixNano() || auditDetails["phase"] != "install" {
		t.Fatalf("persisted audit event mismatch: id=%q plugin=%q occurred_at=%d details=%#v", auditEventID, auditPluginID, auditOccurredAt, auditDetails)
	}

	diagnostics, err := reopened.ListPluginDiagnostics(ctx, ListDiagnosticRequest{
		PluginInstanceID: "plugin_1", SurfaceInstanceID: "surface_1", Severity: "info",
		OwnerSessionHash: "session_1", OwnerUserHash: "user_1", OwnerEnvHash: "env_1", SessionChannelIDHash: "channel_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 1 || diagnostics[0].EventID != "diagnostic_000000000001" || diagnostics[0].Message != "plugin.csp.violation" || diagnostics[0].Details["blocked_uri"] != "inline" {
		t.Fatalf("persisted diagnostic events mismatch: %#v", diagnostics)
	}
	if diagnostics[0].OwnerSessionHash != "session_1" || diagnostics[0].SessionChannelIDHash != "channel_1" {
		t.Fatalf("persisted diagnostic owner scope mismatch: %#v", diagnostics[0])
	}
	if diagnostics[0].InternalDetails != nil {
		t.Fatalf("sqlite diagnostic list exposed internal details: %#v", diagnostics[0])
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

	for index, eventType := range []string{"d1", "d2"} {
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
	if len(diagnostics) != 1 || diagnostics[0].Type != "d2" {
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
	event := AuditEvent{EventID: " security-event-1 ", Type: "plugin.enabled", Details: map[string]any{"attempt": 1}}
	if err := store.AppendPluginAudit(ctx, event); err != nil {
		t.Fatal(err)
	}
	event.Details["attempt"] = 2
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
	if count != 1 || details["attempt"] != float64(1) {
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
	return DiagnosticEvent{
		Type: eventType, Severity: DiagnosticSeverityInfo, OwnerSessionHash: "session_1", OwnerUserHash: "user_1",
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
	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{Type: "plugin.invalid.severity", Severity: "critical"}); !errors.Is(err, ErrInvalidDiagnosticSeverity) {
		t.Fatalf("AppendPluginDiagnostic(invalid severity) error = %v, want ErrInvalidDiagnosticSeverity", err)
	}
	request := scopedDiagnosticRequest(10)
	request.Severity = "critical"
	if _, err := store.ListPluginDiagnostics(ctx, request); !errors.Is(err, ErrInvalidDiagnosticSeverity) {
		t.Fatalf("ListPluginDiagnostics(invalid severity) error = %v, want ErrInvalidDiagnosticSeverity", err)
	}
}
