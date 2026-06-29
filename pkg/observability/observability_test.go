package observability

import (
	"context"
	"errors"
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
