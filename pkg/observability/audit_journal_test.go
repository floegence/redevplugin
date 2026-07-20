package observability

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
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
	if err := journal.CompleteSecurityAudit(ctx, event.EventID, mutation.OutcomeNotCommitted, map[string]any{"reason": "unavailable"}); err != nil {
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
	details := map[string]any{"target_descriptor_hashes": []string{"sha256:before"}}
	event, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.updated", Details: details})
	if err != nil {
		t.Fatal(err)
	}
	details["target_descriptor_hashes"].([]string)[0] = "sha256:after"
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
	if got := completed[0].Event.Details["target_descriptor_hashes"].([]any)[0]; got != "sha256:before" {
		t.Fatalf("journal details mutated by caller: %#v", completed[0].Event.Details)
	}
}

type hostileAuditString string

func (hostileAuditString) MarshalJSON() ([]byte, error) {
	panic("audit cloning invoked caller MarshalJSON")
}

func TestSecurityAuditJournalsDoNotInvokeCallerJSONMarshalers(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		journal func(*testing.T) SecurityAuditJournal
	}{
		{name: "memory", journal: func(*testing.T) SecurityAuditJournal { return NewMemorySecurityAuditJournal() }},
		{name: "sqlite", journal: func(t *testing.T) SecurityAuditJournal {
			store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "audit.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal := test.journal(t)
			record, err := journal.BeginSecurityAudit(ctx, AuditEvent{
				Type: "plugin.enabled",
				Details: map[string]any{
					"method": hostileAuditString("runtime.start"),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.CompleteSecurityAudit(ctx, record.EventID, mutation.OutcomeCommitted, map[string]any{
				"status": hostileAuditString("completed"),
			}); err != nil {
				t.Fatal(err)
			}
			completed, err := journal.ListUnexportedSecurityAudits(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(completed) != 1 {
				t.Fatalf("completed records = %#v", completed)
			}
			if got, ok := completed[0].Event.Details["method"].(string); !ok || got != "runtime.start" {
				t.Fatalf("event method = %#v, want owned string", completed[0].Event.Details["method"])
			}
			if got, ok := completed[0].CompletionDetails["status"].(string); !ok || got != "completed" {
				t.Fatalf("completion status = %#v, want owned string", completed[0].CompletionDetails["status"])
			}
		})
	}
}

func TestSecurityAuditJournalsRejectCanonicalLimitWithoutMutation(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		journal func(*testing.T) SecurityAuditJournal
	}{
		{name: "memory", journal: func(*testing.T) SecurityAuditJournal { return NewMemorySecurityAuditJournal() }},
		{name: "sqlite", journal: func(t *testing.T) SecurityAuditJournal {
			store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "audit.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	}
	hashes := make([]string, jsonvalue.MaxCanonicalNodes+1)
	for index := range hashes {
		hashes[index] = "a"
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal := test.journal(t)
			record, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.enabled"})
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.CompleteSecurityAudit(ctx, record.EventID, mutation.OutcomeCommitted, map[string]any{
				"target_descriptor_hashes": hashes,
			}); !errors.Is(err, ErrInvalidAuditDetails) {
				t.Fatalf("CompleteSecurityAudit() error = %v, want ErrInvalidAuditDetails", err)
			}
			pending, err := journal.ListPendingSecurityAudits(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(pending) != 1 || pending[0].EventID != record.EventID {
				t.Fatalf("failed completion changed journal state: %#v", pending)
			}
		})
	}
}

func TestSecurityAuditJournalsNormalizeNilTargetHashArrays(t *testing.T) {
	ctx := context.Background()
	assertRecord := func(t *testing.T, record SecurityAuditRecord) {
		t.Helper()
		for name, details := range map[string]map[string]any{
			"event":      record.Event.Details,
			"completion": record.CompletionDetails,
		} {
			hashes, ok := details["target_descriptor_hashes"].([]any)
			if !ok || hashes == nil || len(hashes) != 0 {
				t.Fatalf("%s target hashes = %#v, want non-nil empty []any", name, details["target_descriptor_hashes"])
			}
		}
	}

	t.Run("memory", func(t *testing.T) {
		journal := NewMemorySecurityAuditJournal()
		record, err := journal.BeginSecurityAudit(ctx, AuditEvent{
			Type: "plugin.updated", Details: map[string]any{"target_descriptor_hashes": []string(nil)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.CompleteSecurityAudit(ctx, record.EventID, mutation.OutcomeCommitted, map[string]any{
			"target_descriptor_hashes": []any(nil),
		}); err != nil {
			t.Fatal(err)
		}
		listed, err := journal.ListUnexportedSecurityAudits(ctx)
		if err != nil {
			t.Fatal(err)
		}
		assertRecord(t, listed[0])
	})

	t.Run("sqlite reopen", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.sqlite")
		store, err := NewSQLiteStore(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		record, err := store.BeginSecurityAudit(ctx, AuditEvent{
			Type: "plugin.updated", Details: map[string]any{"target_descriptor_hashes": []string(nil)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CompleteSecurityAudit(ctx, record.EventID, mutation.OutcomeCommitted, map[string]any{
			"target_descriptor_hashes": []any(nil),
		}); err != nil {
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
		listed, err := store.ListUnexportedSecurityAudits(ctx)
		if err != nil {
			t.Fatal(err)
		}
		assertRecord(t, listed[0])
	})
}

func TestSecurityAuditJournalsCloneSessionScopeCompletionDetails(t *testing.T) {
	ctx := context.Background()
	details := map[string]any{
		"session_scope_state":          "complete",
		"session_scope_fenced":         true,
		"session_scope_complete":       true,
		"surface_count":                uint64(1),
		"asset_ticket_count":           uint64(2),
		"asset_session_count":          uint64(3),
		"gateway_token_count":          uint64(4),
		"confirmation_token_count":     uint64(5),
		"stream_ticket_count":          uint64(6),
		"handle_grant_count":           uint64(7),
		"confirmation_count":           uint64(8),
		"operation_count":              uint64(9),
		"stream_count":                 uint64(10),
		"runtime_execution_count":      uint64(11),
		"active_network_request_count": uint64(12),
		"socket_count":                 uint64(13),
		"network_stream_count":         uint64(14),
		"storage_hostcall_count":       uint64(15),
	}
	tests := []struct {
		name    string
		journal func(*testing.T) SecurityAuditJournal
	}{
		{name: "memory", journal: func(*testing.T) SecurityAuditJournal { return NewMemorySecurityAuditJournal() }},
		{name: "sqlite", journal: func(t *testing.T) SecurityAuditJournal {
			store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "audit.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal := test.journal(t)
			record, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.session_scope.revoked"})
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.CompleteSecurityAudit(ctx, record.EventID, mutation.OutcomeCommitted, details); err != nil {
				t.Fatal(err)
			}
			details["surface_count"] = uint64(99)
			completed, err := journal.ListUnexportedSecurityAudits(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(completed) != 1 || completed[0].CompletionDetails["surface_count"] != float64(1) {
				t.Fatalf("completion details = %#v", completed)
			}
			details["surface_count"] = uint64(1)
		})
	}
}

func TestMemorySecurityAuditJournalPropagatesSnapshotCloneFailures(t *testing.T) {
	ctx := context.Background()
	journal := NewMemorySecurityAuditJournal()
	record, err := journal.BeginSecurityAudit(ctx, AuditEvent{EventID: "audit_corrupt", Type: "plugin.enabled"})
	if err != nil {
		t.Fatal(err)
	}
	journal.entries[journal.start].Event.Details = map[string]any{"unknown": "sensitive"}
	if _, err := journal.BeginSecurityAudit(ctx, AuditEvent{EventID: record.EventID, Type: "plugin.enabled"}); !errors.Is(err, ErrInvalidAuditDetails) {
		t.Fatalf("duplicate BeginSecurityAudit() error = %v, want ErrInvalidAuditDetails", err)
	}
	if records, err := journal.ListPendingSecurityAudits(ctx); !errors.Is(err, ErrInvalidAuditDetails) || records != nil {
		t.Fatalf("ListPendingSecurityAudits() = %#v, %v", records, err)
	}

	journal.entries[journal.start].Event.Details = nil
	journal.entries[journal.start].State = SecurityAuditCompleted
	journal.entries[journal.start].Outcome = mutation.OutcomeCommitted
	journal.entries[journal.start].CompletionDetails = map[string]any{"unknown": "sensitive"}
	if records, err := journal.ListUnexportedSecurityAudits(ctx); !errors.Is(err, ErrInvalidAuditDetails) || records != nil {
		t.Fatalf("ListUnexportedSecurityAudits() = %#v, %v", records, err)
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
	first, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.CompleteSecurityAudit(ctx, first.EventID, mutation.OutcomeCommitted, nil); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkSecurityAuditExported(ctx, first.EventID); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"b", "c"} {
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

func TestMemorySecurityAuditJournalFailsClosedWhenProtectedRecordsFillCapacity(t *testing.T) {
	ctx := context.Background()
	journal := NewMemorySecurityAuditJournal(MemorySecurityAuditJournalOptions{MaxEntries: 2})
	pending, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	unexported, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "unexported"})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.CompleteSecurityAudit(ctx, unexported.EventID, mutation.OutcomeCommitted, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "must-not-start"}); !errors.Is(err, ErrSecurityAuditCapacity) {
		t.Fatalf("BeginSecurityAudit() error = %v, want ErrSecurityAuditCapacity", err)
	}
	pendingRecords, err := journal.ListPendingSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unexportedRecords, err := journal.ListUnexportedSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pendingRecords) != 1 || pendingRecords[0].EventID != pending.EventID {
		t.Fatalf("pending records = %#v", pendingRecords)
	}
	if len(unexportedRecords) != 1 || unexportedRecords[0].EventID != unexported.EventID {
		t.Fatalf("unexported records = %#v", unexportedRecords)
	}
	if err := journal.MarkSecurityAuditExported(ctx, unexported.EventID); err != nil {
		t.Fatal(err)
	}
	next, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "after-capacity-release"})
	if err != nil {
		t.Fatal(err)
	}
	if next.EventID != "audit_000000000003" {
		t.Fatalf("event ID after failed begin = %q, want audit_000000000003", next.EventID)
	}
}

func TestSQLiteSecurityAuditJournalOnlyTrimsExportedRecords(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "audit.sqlite"), MemoryStoreOptions{MaxAuditEvents: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	first, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "exported"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteSecurityAudit(ctx, first.EventID, mutation.OutcomeCommitted, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkSecurityAuditExported(ctx, first.EventID); err != nil {
		t.Fatal(err)
	}
	second, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	third, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "replacement"})
	if err != nil {
		t.Fatal(err)
	}

	var exportedCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_security_audit_journal WHERE event_id = ?`, first.EventID).Scan(&exportedCount); err != nil {
		t.Fatal(err)
	}
	if exportedCount != 0 {
		t.Fatalf("exported retained record count = %d, want 0", exportedCount)
	}
	pendingRecords, err := store.ListPendingSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pendingRecords) != 2 || pendingRecords[0].EventID != second.EventID || pendingRecords[1].EventID != third.EventID {
		t.Fatalf("pending records = %#v", pendingRecords)
	}
}

func TestSQLiteSecurityAuditJournalFailsClosedWhenProtectedRecordsFillCapacity(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "audit.sqlite"), MemoryStoreOptions{MaxAuditEvents: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	pending, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	unexported, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "unexported"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteSecurityAudit(ctx, unexported.EventID, mutation.OutcomeCommitted, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "must-not-start"}); !errors.Is(err, ErrSecurityAuditCapacity) {
		t.Fatalf("BeginSecurityAudit() error = %v, want ErrSecurityAuditCapacity", err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_security_audit_journal`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("journal count = %d, want 2", count)
	}
	pendingRecords, err := store.ListPendingSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unexportedRecords, err := store.ListUnexportedSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pendingRecords) != 1 || pendingRecords[0].EventID != pending.EventID {
		t.Fatalf("pending records = %#v", pendingRecords)
	}
	if len(unexportedRecords) != 1 || unexportedRecords[0].EventID != unexported.EventID {
		t.Fatalf("unexported records = %#v", unexportedRecords)
	}
	if err := store.MarkSecurityAuditExported(ctx, unexported.EventID); err != nil {
		t.Fatal(err)
	}
	next, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "after-capacity-release"})
	if err != nil {
		t.Fatal(err)
	}
	if next.EventID != "audit_000000000003" {
		t.Fatalf("event ID after failed begin = %q, want audit_000000000003", next.EventID)
	}
}

func TestSecurityAuditExporterRetryAfterMarkFailureDoesNotDuplicateSinkEvent(t *testing.T) {
	ctx := context.Background()
	journal := NewMemorySecurityAuditJournal()
	record, err := journal.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.enabled"})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.CompleteSecurityAudit(ctx, record.EventID, mutation.OutcomeCommitted, nil); err != nil {
		t.Fatal(err)
	}
	failingJournal := &failFirstMarkSecurityAuditJournal{SecurityAuditJournal: journal}
	sink := NewMemoryStore()
	exporter := NewSecurityAuditExporter(failingJournal, sink)
	if err := exporter.Export(ctx); err == nil {
		t.Fatal("first Export() error = nil, want mark failure")
	}
	if err := exporter.Export(ctx); err != nil {
		t.Fatal(err)
	}
	sink.mu.RLock()
	events := sink.auditEvents.Snapshot()
	sink.mu.RUnlock()
	if len(events) != 1 || events[0].EventID != record.EventID {
		t.Fatalf("sink events = %#v", events)
	}
}

func TestSecurityAuditExporterRejectsTypedNilAndInvalidJournalRecords(t *testing.T) {
	ctx := context.Background()
	var nilSink *recordingAuditSink
	if err := NewSecurityAuditExporter(NewMemorySecurityAuditJournal(), nilSink).Export(ctx); err == nil {
		t.Fatal("Export(typed-nil sink) error = nil")
	}
	var nilJournal *MemorySecurityAuditJournal
	if err := NewSecurityAuditExporter(nilJournal, &recordingAuditSink{}).Export(ctx); err == nil {
		t.Fatal("Export(typed-nil journal) error = nil")
	}

	sink := &recordingAuditSink{}
	journal := &invalidListingSecurityAuditJournal{
		SecurityAuditJournal: NewMemorySecurityAuditJournal(),
		records: []SecurityAuditRecord{{
			EventID: "audit_invalid",
			Event: AuditEvent{
				EventID: "audit_invalid", Type: "plugin.enabled", OccurredAt: time.Now().UTC(),
				Details: map[string]any{"unknown": "Authorization: Bearer secret"},
			},
			State: SecurityAuditCompleted, Outcome: mutation.OutcomeCommitted,
		}},
	}
	if err := NewSecurityAuditExporter(journal, sink).Export(ctx); !errors.Is(err, ErrInvalidEvent) || !errors.Is(err, ErrInvalidAuditDetails) {
		t.Fatalf("Export(invalid record) error = %v, want ErrInvalidEvent and ErrInvalidAuditDetails", err)
	}
	if len(sink.events) != 0 {
		t.Fatalf("invalid journal record reached sink: %#v", sink.events)
	}
	if journal.markCalls != 0 {
		t.Fatalf("invalid journal record was marked exported %d times", journal.markCalls)
	}
}

func TestSQLiteSecurityAuditJournalRejectsSensitiveCompletionWithoutPersistence(t *testing.T) {
	const sensitive = "Authorization: Bearer bearer-token-super-secret at /Users/private/plugin.sqlite?access_token=query-secret"
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.BeginSecurityAudit(ctx, AuditEvent{Type: "plugin.enabled"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteSecurityAudit(ctx, record.EventID, mutation.OutcomeUnknown, map[string]any{"reason": sensitive}); !errors.Is(err, ErrInvalidAuditDetails) {
		t.Fatalf("CompleteSecurityAudit(sensitive) error = %v, want ErrInvalidAuditDetails", err)
	}
	pending, err := store.ListPendingSecurityAudits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].EventID != record.EventID {
		t.Fatalf("sensitive completion changed journal state: %#v", pending)
	}
	if err := store.CompleteSecurityAudit(ctx, record.EventID, mutation.OutcomeUnknown, map[string]any{
		"failure": FailureFromError(FailureAdapter, FailureComponentSecurity, FailureOperationSecurityMutationComplete, errors.New(sensitive)),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{sensitive, "bearer-token-super-secret", "/Users/private/plugin.sqlite", "query-secret"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("security audit journal leaked %q", forbidden)
		}
	}
}

type recordingAuditSink struct {
	events []AuditEvent
}

func (s *recordingAuditSink) AppendPluginAudit(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

type failFirstMarkSecurityAuditJournal struct {
	SecurityAuditJournal
	failed bool
}

type invalidListingSecurityAuditJournal struct {
	SecurityAuditJournal
	records   []SecurityAuditRecord
	markCalls int
}

func (j *invalidListingSecurityAuditJournal) ListUnexportedSecurityAudits(context.Context) ([]SecurityAuditRecord, error) {
	return append([]SecurityAuditRecord(nil), j.records...), nil
}

func (j *invalidListingSecurityAuditJournal) MarkSecurityAuditExported(context.Context, string) error {
	j.markCalls++
	return nil
}

func (j *failFirstMarkSecurityAuditJournal) MarkSecurityAuditExported(ctx context.Context, eventID string) error {
	if !j.failed {
		j.failed = true
		return errors.New("injected mark failure")
	}
	return j.SecurityAuditJournal.MarkSecurityAuditExported(ctx, eventID)
}
