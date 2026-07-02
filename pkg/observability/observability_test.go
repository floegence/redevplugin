package observability

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryStoreAuditListFiltersAndLimit(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time { return now }})
	ctx := context.Background()

	if err := store.AppendPluginAudit(ctx, AuditEvent{
		Type:             "plugin.installed",
		PluginID:         "com.example.a",
		PluginInstanceID: "plugin_a",
		Details:          map[string]any{"phase": "install"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPluginAudit(ctx, AuditEvent{Type: "plugin.enabled", PluginID: "com.example.a", PluginInstanceID: "plugin_a", OccurredAt: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPluginAudit(ctx, AuditEvent{Type: "plugin.installed", PluginID: "com.example.b", PluginInstanceID: "plugin_b", OccurredAt: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}

	events, err := store.ListPluginAudit(ctx, ListAuditRequest{PluginInstanceID: "plugin_a", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "plugin.enabled" || events[0].EventID == "" {
		t.Fatalf("ListPluginAudit() = %#v", events)
	}

	events, err = store.ListPluginAudit(ctx, ListAuditRequest{PluginID: "com.example.a", Type: "plugin.installed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].PluginInstanceID != "plugin_a" {
		t.Fatalf("filtered audit events mismatch: %#v", events)
	}

	events[0].Details = map[string]any{"mutated": true}
	again, err := store.ListPluginAudit(ctx, ListAuditRequest{PluginInstanceID: "plugin_a", Type: "plugin.installed"})
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Details["phase"] != "install" {
		t.Fatalf("ListPluginAudit lost original event details: %#v", again[0].Details)
	}
	if _, ok := again[0].Details["mutated"]; ok {
		t.Fatalf("ListPluginAudit returned mutable event details: %#v", again[0].Details)
	}
}

func TestMemoryStoreDiagnosticsListFiltersAndDefaults(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore(MemoryStoreOptions{Now: func() time.Time { return now }})
	ctx := context.Background()

	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{
		Type:              "plugin.csp.violation",
		PluginID:          "com.example.plugin",
		PluginInstanceID:  "plugin_a",
		SurfaceInstanceID: "surface_a",
		Details:           map[string]any{"blocked_uri": "inline"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{
		Type:              "plugin.runtime.warning",
		Severity:          "warning",
		Message:           "runtime slowed",
		PluginID:          "com.example.plugin",
		PluginInstanceID:  "plugin_a",
		SurfaceInstanceID: "surface_b",
		OccurredAt:        now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	events, err := store.ListPluginDiagnostics(ctx, ListDiagnosticRequest{
		PluginInstanceID:  "plugin_a",
		SurfaceInstanceID: "surface_a",
		Severity:          "info",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Message != "plugin.csp.violation" || events[0].Details["blocked_uri"] != "inline" {
		t.Fatalf("ListPluginDiagnostics() = %#v", events)
	}

	events, err = store.ListPluginDiagnostics(ctx, ListDiagnosticRequest{PluginID: "com.example.plugin", Severity: "warning"})
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
}

func TestMemoryStoreTrimsOldestEvents(t *testing.T) {
	store := NewMemoryStore(MemoryStoreOptions{MaxAuditEvents: 2, MaxDiagnosticEvents: 1})
	ctx := context.Background()
	for _, eventType := range []string{"a", "b", "c"} {
		if err := store.AppendPluginAudit(ctx, AuditEvent{Type: eventType}); err != nil {
			t.Fatal(err)
		}
	}
	audits, err := store.ListPluginAudit(ctx, ListAuditRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 2 || audits[0].Type != "c" || audits[1].Type != "b" {
		t.Fatalf("trimmed audits mismatch: %#v", audits)
	}

	for _, eventType := range []string{"d1", "d2"} {
		if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{Type: eventType}); err != nil {
			t.Fatal(err)
		}
	}
	diagnostics, err := store.ListPluginDiagnostics(ctx, ListDiagnosticRequest{Limit: 10})
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
		Type:              "plugin.csp.violation",
		PluginID:          "com.example.plugin",
		PluginInstanceID:  "plugin_1",
		SurfaceInstanceID: "surface_1",
		ActiveFingerprint: "sha256:demo",
		Details:           map[string]any{"blocked_uri": "inline"},
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

	audits, err := reopened.ListPluginAudit(ctx, ListAuditRequest{PluginInstanceID: "plugin_1", Type: "plugin.installed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 || audits[0].EventID != "audit_000000000001" || audits[0].PluginID != "com.example.plugin" || audits[0].OccurredAt != now || audits[0].Details["phase"] != "install" {
		t.Fatalf("persisted audit events mismatch: %#v", audits)
	}
	audits[0].Details["phase"] = "mutated"
	again, err := reopened.ListPluginAudit(ctx, ListAuditRequest{PluginInstanceID: "plugin_1", Type: "plugin.installed"})
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Details["phase"] != "install" {
		t.Fatalf("persisted audit details were mutable: %#v", again[0].Details)
	}

	diagnostics, err := reopened.ListPluginDiagnostics(ctx, ListDiagnosticRequest{PluginInstanceID: "plugin_1", SurfaceInstanceID: "surface_1", Severity: "info"})
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 1 || diagnostics[0].EventID != "diagnostic_000000000001" || diagnostics[0].Message != "plugin.csp.violation" || diagnostics[0].Details["blocked_uri"] != "inline" {
		t.Fatalf("persisted diagnostic events mismatch: %#v", diagnostics)
	}

	if err := reopened.AppendPluginAudit(ctx, AuditEvent{Type: "plugin.enabled"}); err != nil {
		t.Fatal(err)
	}
	audits, err = reopened.ListPluginAudit(ctx, ListAuditRequest{Type: "plugin.enabled"})
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 || audits[0].EventID != "audit_000000000002" {
		t.Fatalf("persisted audit sequence mismatch: %#v", audits)
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
	audits, err := store.ListPluginAudit(ctx, ListAuditRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 2 || audits[0].Type != "c" || audits[1].Type != "b" {
		t.Fatalf("trimmed sqlite audits mismatch: %#v", audits)
	}

	for index, eventType := range []string{"d1", "d2"} {
		if err := store.AppendPluginDiagnostic(ctx, DiagnosticEvent{Type: eventType, OccurredAt: base.Add(time.Duration(index) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	diagnostics, err := store.ListPluginDiagnostics(ctx, ListDiagnosticRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 1 || diagnostics[0].Type != "d2" {
		t.Fatalf("trimmed sqlite diagnostics mismatch: %#v", diagnostics)
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
}

func TestSQLiteStoreRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observability.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_observability_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteSchemaVersion+1, time.Now().UTC().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("NewSQLiteStore() accepted newer schema version")
	}
}
