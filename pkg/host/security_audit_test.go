package host

import (
	"bytes"
	"context"
	"errors"
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
	beginErr    error
	completeErr error
}

func (j *hostFailingSecurityJournal) BeginSecurityAudit(_ context.Context, event observability.AuditEvent) (observability.SecurityAuditRecord, error) {
	if j.beginErr != nil {
		return observability.SecurityAuditRecord{}, j.beginErr
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
