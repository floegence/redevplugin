package host

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/registry"
)

func TestEnablePluginDoesNotMutateWhenSecurityAuditBeginFails(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installLifecycleFixture(t, h)
	cause := errors.New("journal unavailable")
	h.securityJournal = &hostFailingSecurityJournal{beginErr: cause}

	_, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if !errors.Is(err, ErrSecurityEventPersistence) {
		t.Fatalf("EnablePlugin() error = %v, want ErrSecurityEventPersistence", err)
	}
	record, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableDisabled || record.ManagementRevision != installed.ManagementRevision {
		t.Fatalf("record mutated after audit begin failure: %#v", record)
	}
}

func TestEnablePluginReturnsUnknownWhenSecurityAuditCompletionFails(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installLifecycleFixture(t, h)
	h.securityJournal = &hostFailingSecurityJournal{completeErr: errors.New("journal commit failed")}

	_, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if outcome := mutation.ForError(err); outcome != mutation.OutcomeUnknown {
		t.Fatalf("EnablePlugin() outcome = %q, want %q: %v", outcome, mutation.OutcomeUnknown, err)
	}
	record, getErr := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if record.EnableState != registry.EnableEnabled {
		t.Fatalf("committed enable state = %q, want enabled", record.EnableState)
	}
}

func TestEnablePluginDoesNotDeliverSecurityAuditOutsideJournalExporter(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installLifecycleFixture(t, h)
	directSink := &auditSink{}
	h.adapters.Audit = directSink

	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	}); err != nil {
		t.Fatal(err)
	}
	directSink.mu.Lock()
	defer directSink.mu.Unlock()
	for _, event := range directSink.events {
		if event.Type == "plugin.enabled" {
			t.Fatalf("journaled security event was also delivered directly: %#v", directSink.events)
		}
	}
}

func TestRunSecurityMutationDoesNotMutateWithoutSecurityAuditJournal(t *testing.T) {
	h := &Host{}
	mutated := false

	err := h.runSecurityMutation(context.Background(), AuditEvent{Type: "plugin.enabled"}, func() error {
		mutated = true
		return nil
	})
	if !errors.Is(err, ErrSecurityEventPersistence) {
		t.Fatalf("runSecurityMutation() error = %v, want ErrSecurityEventPersistence", err)
	}
	if mutated {
		t.Fatal("runSecurityMutation() executed mutation without a security audit journal")
	}
}

func TestRecordSecurityEventUsesDurableJournalWithoutDirectSinkDelivery(t *testing.T) {
	journal := observability.NewMemorySecurityAuditJournal()
	h := &Host{
		adapters:        normalizedAdapters{Audit: failingAuditSink{err: errors.New("direct sink must not be called")}},
		securityJournal: journal,
	}
	if err := h.recordSecurityEvent(context.Background(), AuditEvent{Type: "plugin.method.called", PluginID: "com.example"}); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ListUnexportedSecurityAudits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Event.Type != "plugin.method.called" || records[0].Outcome != mutation.OutcomeCommitted {
		t.Fatalf("durable records = %#v", records)
	}
}

func TestRecordSecurityEventReturnsPersistenceErrorWhenJournalBeginFails(t *testing.T) {
	h := &Host{securityJournal: &hostFailingSecurityJournal{beginErr: errors.New("journal unavailable")}}
	err := h.recordSecurityEvent(context.Background(), AuditEvent{Type: "plugin.method.called"})
	if !errors.Is(err, ErrSecurityEventPersistence) {
		t.Fatalf("recordSecurityEvent() error = %v, want ErrSecurityEventPersistence", err)
	}
}

func TestSecurityAuditMutationPersistsCompletionDetails(t *testing.T) {
	journal := observability.NewMemorySecurityAuditJournal()
	h := &Host{securityJournal: journal}
	audit, err := h.beginSecurityMutation(context.Background(), AuditEvent{Type: "plugin.runtime.stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.completeWithDetails(context.Background(), nil, map[string]any{"revoked_surface_count": 3}); err != nil {
		t.Fatal(err)
	}
	records, err := journal.ListUnexportedSecurityAudits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].CompletionDetails["revoked_surface_count"] != float64(3) {
		t.Fatalf("completion details = %#v", records)
	}
}

func TestOpenDoesNotInferSecurityAuditJournalFromAuditSink(t *testing.T) {
	config := modularTestConfig(t)
	combinedSink := observability.NewMemoryStore()
	config.Core.Audit = combinedSink
	config.Core.SecurityAudit = nil

	_, err := Open(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "security audit journal is required") {
		t.Fatalf("Open() error = %v, want explicit security audit journal requirement", err)
	}
}

func TestRunSecurityMutationDoesNotMutateWithEmptySecurityAuditEventID(t *testing.T) {
	h := &Host{securityJournal: &hostFailingSecurityJournal{emptyEventID: true}}
	mutated := false

	err := h.runSecurityMutation(context.Background(), AuditEvent{Type: "plugin.enabled"}, func() error {
		mutated = true
		return nil
	})
	if !errors.Is(err, ErrSecurityEventPersistence) {
		t.Fatalf("runSecurityMutation() error = %v, want ErrSecurityEventPersistence", err)
	}
	if mutated {
		t.Fatal("runSecurityMutation() executed mutation without a durable audit event id")
	}
}

func installLifecycleFixture(t *testing.T, h *Host) registry.PluginRecord {
	t.Helper()
	pkg := buildVersionedLifecyclePackage(t, "1.0.0", "Audit lifecycle")
	installed, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PackageReader: bytes.NewReader(pkg),
		PackageSize:   int64(len(pkg)),
	})
	if err != nil {
		t.Fatalf("ImportLocalPackage() error = %v", err)
	}
	return installed
}

type hostFailingSecurityJournal struct {
	beginErr     error
	completeErr  error
	emptyEventID bool
}

func (j *hostFailingSecurityJournal) BeginSecurityAudit(_ context.Context, event observability.AuditEvent) (observability.SecurityAuditRecord, error) {
	if j.beginErr != nil {
		return observability.SecurityAuditRecord{}, j.beginErr
	}
	if j.emptyEventID {
		return observability.SecurityAuditRecord{Event: event, State: observability.SecurityAuditPending}, nil
	}
	return observability.SecurityAuditRecord{EventID: "audit_test", Event: event, State: observability.SecurityAuditPending}, nil
}

func (j *hostFailingSecurityJournal) CompleteSecurityAudit(context.Context, string, mutation.Outcome, map[string]any) error {
	return j.completeErr
}

func (*hostFailingSecurityJournal) ListPendingSecurityAudits(context.Context) ([]observability.SecurityAuditRecord, error) {
	return nil, nil
}

func (*hostFailingSecurityJournal) ListUnexportedSecurityAudits(context.Context) ([]observability.SecurityAuditRecord, error) {
	return nil, nil
}

func (*hostFailingSecurityJournal) MarkSecurityAuditExported(context.Context, string) error {
	return nil
}
func (*hostFailingSecurityJournal) ReconcilePendingSecurityAudits(context.Context) error { return nil }
