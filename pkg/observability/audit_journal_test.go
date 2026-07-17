package observability

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

func TestMemorySecurityAuditJournalRequiresCompleteBeforeExport(t *testing.T) {
	ctx := context.Background()
	journal := NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{MaxEntries: 8})
	event, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.enabled", PluginID: "com.example", PluginInstanceID: "instance"})
	if err != nil {
		t.Fatal(err)
	}
	if event.EventID == "" || event.State != SecurityAuditPending {
		t.Fatalf("pending event = %#v", event)
	}
	sink := &recordingAuditSink{}
	exporter := NewSecurityAuditExporter(journal, sink)
	if err := exporter.Export(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 0 {
		t.Fatalf("exported incomplete journal: %#v", sink.events)
	}
	if err := journal.CompleteSecurityAudit(ctx, event.EventID, mutation.OutcomeNotCommitted, map[string]any{"reason": "done"}); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Export(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 || sink.events[0].EventID != event.EventID {
		t.Fatalf("exported events = %#v", sink.events)
	}
	if err := exporter.Export(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("exporter was not idempotent: %#v", sink.events)
	}
}

func TestMemorySecurityAuditJournalReconcilesPendingAsUnknown(t *testing.T) {
	ctx := context.Background()
	journal := NewMemorySecurityAuditJournal()
	event, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.permission.granted", PluginID: "com.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.ReconcilePendingSecurityAudits(ctx); err != nil {
		t.Fatal(err)
	}
	pending, err := journal.ListPendingSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending records after reconcile = %#v", pending)
	}
	completed, err := journal.ListUnexportedSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(completed) != 1 || completed[0].Outcome != mutation.OutcomeUnknown || completed[0].Event.EventID != event.EventID {
		t.Fatalf("reconciled records = %#v", completed)
	}
}

func TestSecurityAuditJournalRejectsInvalidCompletionAndPreservesInput(t *testing.T) {
	ctx := context.Background()
	journal := NewMemorySecurityAuditJournal()
	details := map[string]any{"nested": map[string]any{"value": "before"}}
	event, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.updated", Details: details})
	if err != nil {
		t.Fatal(err)
	}
	details["nested"].(map[string]any)["value"] = "after"
	if err := journal.CompleteSecurityAudit(ctx, event.EventID, "invalid", nil); !errors.Is(err, ErrInvalidMutationOutcome) {
		t.Fatalf("invalid outcome error = %v", err)
	}
	if err := journal.CompleteSecurityAudit(ctx, event.EventID, mutation.OutcomeNotCommitted, nil); err != nil {
		t.Fatal(err)
	}
	completed, err := journal.ListUnexportedSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := completed[0].Event.Details["nested"].(map[string]any)["value"]; got != "before" {
		t.Fatalf("journal details mutated by caller: %#v", completed[0].Event.Details)
	}
}

func TestSQLiteSecurityAuditJournalPersistsAndReconciles(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.sqlite")
	store, err := NewSQLiteStore(ctx, path, MemoryStoreOptions{Now: func() time.Time { return time.Unix(100, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	event, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.installed", PluginID: "com.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pending, err := store.ListPendingSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Event.EventID != event.EventID {
		t.Fatalf("persisted pending records = %#v", pending)
	}
	if err := store.ReconcilePendingSecurityAudits(ctx); err != nil {
		t.Fatal(err)
	}
	unexported, err := store.ListUnexportedSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unexported) != 1 || unexported[0].Outcome != mutation.OutcomeUnknown {
		t.Fatalf("reconciled records = %#v", unexported)
	}
}

func TestMemorySecurityAuditJournalUsesFixedCapacity(t *testing.T) {
	ctx := context.Background()
	journal := NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{MaxEntries: 2})
	for _, typ := range []string{"a", "b", "c"} {
		if _, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: typ}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := journal.ListPendingSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Event.Type != "b" || entries[1].Event.Type != "c" {
		t.Fatalf("ring entries = %#v", entries)
	}
}

type recordingAuditSink struct {
	events []AuditEvent
}

func (s *recordingAuditSink) AppendPluginAudit(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}
