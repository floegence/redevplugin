package host

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/runtimeclient"
	"github.com/floegence/redevplugin/pkg/mutation"
)

func TestNewRuntimeModuleConsumesExecutableOnlyAfterValidation(t *testing.T) {
	executable := newRuntimeModuleTestExecutable(t)
	if _, err := NewRuntimeModule(executable, RuntimeModuleOptions{
		Limits:          runtimeclient.DefaultRuntimeLimits(),
		StartupTimeout:  -time.Second,
		ShutdownTimeout: DefaultRuntimeShutdownTimeout,
	}); !errors.Is(err, ErrRuntimeModuleOptionsInvalid) {
		t.Fatalf("NewRuntimeModule() invalid options error = %v", err)
	}
	if executable.Descriptor().BinarySHA256().String() != strings.Repeat("c", 64) {
		t.Fatal("failed module construction consumed the executable")
	}
	if outcome, err := executable.Close(); err != nil || outcome != MutationOutcomeCommitted {
		t.Fatalf("executable.Close() = %q, %v", outcome, err)
	}
}

func TestRuntimeModuleCloseAndTransferAreLinear(t *testing.T) {
	executable := newRuntimeModuleTestExecutable(t)
	module, err := NewRuntimeModule(executable, RuntimeModuleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if module.Descriptor() != executable.descriptor {
		t.Fatalf("module descriptor = %#v", module.Descriptor())
	}
	if outcome, err := executable.Close(); !errors.Is(err, ErrVerifiedExecutableClosed) || outcome != MutationOutcomeNotCommitted {
		t.Fatalf("consumed executable Close() = %q, %v", outcome, err)
	}

	if _, err := module.claimForHost(); err != nil {
		t.Fatalf("claimForHost() error = %v", err)
	}
	result, err := module.Close(context.Background())
	if !errors.Is(err, ErrRuntimeModuleConsumed) || result.Disposition != RuntimeModuleConsumedAndClosed || result.Outcome != MutationOutcomeNotCommitted {
		t.Fatalf("transferred module Close() = %#v, %v", result, err)
	}
	result, err = module.closeFromHost(context.Background())
	if err != nil || result.Disposition != RuntimeModuleConsumedAndClosed || result.Outcome != MutationOutcomeCommitted {
		t.Fatalf("closeFromHost() = %#v, %v", result, err)
	}
	result, err = module.closeFromHost(context.Background())
	if err != nil || result.Disposition != RuntimeModuleAlreadyClosed || result.Outcome != MutationOutcomeNotCommitted {
		t.Fatalf("repeated closeFromHost() = %#v, %v", result, err)
	}
}

func TestRuntimeModuleCallerCloseWinsBeforeHostTransfer(t *testing.T) {
	module, err := NewRuntimeModule(newRuntimeModuleTestExecutable(t), RuntimeModuleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := module.Close(context.Background())
	if err != nil || result.Disposition != RuntimeModuleAlreadyClosed || result.Outcome != MutationOutcomeCommitted {
		t.Fatalf("module.Close() = %#v, %v", result, err)
	}
	if _, err := module.claimForHost(); !errors.Is(err, ErrRuntimeModuleClosed) {
		t.Fatalf("claim after Close error = %v", err)
	}
}

func TestVerifiedExecutableCloseFailureRequiresJournalReconciliation(t *testing.T) {
	executable := newRuntimeModuleTestExecutable(t)
	journal := &recordingRuntimeExecJournal{}
	executable.journal = journal
	if err := executable.executable.Close(); err != nil {
		t.Fatal(err)
	}

	outcome, err := executable.Close()
	if err == nil || outcome != MutationOutcomeUnknown {
		t.Fatalf("executable.Close() = %q, %v, want unknown failure", outcome, err)
	}
	journal.assertFinal(t, runtimeExecJournalReconcileRequired, runtimeExecContainmentPending, mutation.OutcomeUnknown)
}

func TestRuntimeModuleCloseFailureRequiresJournalReconciliation(t *testing.T) {
	executable := newRuntimeModuleTestExecutable(t)
	journal := &recordingRuntimeExecJournal{}
	executable.journal = journal
	module, err := NewRuntimeModule(executable, RuntimeModuleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := executable.executable.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := module.Close(context.Background())
	if err == nil || result.Outcome != MutationOutcomeUnknown {
		t.Fatalf("module.Close() = %#v, %v, want unknown failure", result, err)
	}
	journal.assertFinal(t, runtimeExecJournalReconcileRequired, runtimeExecContainmentPending, mutation.OutcomeUnknown)
}

func TestRuntimeModuleHostStopFailureRequiresJournalReconciliation(t *testing.T) {
	executable := newRuntimeModuleTestExecutable(t)
	journal := &recordingRuntimeExecJournal{}
	executable.journal = journal
	module, err := NewRuntimeModule(executable, RuntimeModuleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := module.claimForHost()
	if err != nil {
		t.Fatal(err)
	}
	stopFailure := errors.New("runtime stop failed")
	manager := newRecordingRuntimeManager()
	manager.stopErr = stopFailure
	capability.manager = manager
	const containmentID = "linux-runtime-v1:pid=42:pidfd=7"
	if err := module.transitionRuntimeJournal(runtimeExecJournalRunning, containmentID, mutation.OutcomeCommitted); err != nil {
		t.Fatal(err)
	}

	result, err := module.closeFromHost(context.Background())
	if !errors.Is(err, stopFailure) || result.Outcome != MutationOutcomeUnknown {
		t.Fatalf("closeFromHost() = %#v, %v, want unknown stop failure", result, err)
	}
	journal.assertFinal(t, runtimeExecJournalReconcileRequired, containmentID, mutation.OutcomeUnknown)
}

func TestHostValidationFailureLeavesRuntimeModuleCallerOwned(t *testing.T) {
	module, err := NewRuntimeModule(newRuntimeModuleTestExecutable(t), RuntimeModuleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(context.Background(), Config{Core: CoreAdapters{}, Runtime: module})
	var configErr *HostConfigError
	if !errors.As(err, &configErr) || configErr.RuntimeModuleDisposition() != RuntimeModuleCallerOwned {
		t.Fatalf("Open() error = %#v, disposition=%q", err, configErr.RuntimeModuleDisposition())
	}
	result, err := module.Close(context.Background())
	if err != nil || result.Disposition != RuntimeModuleAlreadyClosed || result.Outcome != MutationOutcomeCommitted {
		t.Fatalf("caller close after config failure = %#v, %v", result, err)
	}
}

func TestHostConsumesAndClosesRuntimeModule(t *testing.T) {
	config := modularTestConfig(t)
	executable := newRuntimeModuleTestExecutable(t)
	module, err := NewRuntimeModule(executable, RuntimeModuleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	config.Runtime = module
	h, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Host.Close() error = %v", err)
	}
	if executable.Descriptor() != (RuntimeDescriptor{}) {
		t.Fatal("Host.Close() left the executable alias usable")
	}
	result, err := module.Close(context.Background())
	if err != nil || result.Disposition != RuntimeModuleAlreadyClosed || result.Outcome != MutationOutcomeNotCommitted {
		t.Fatalf("module state after Host.Close() = %#v, %v", result, err)
	}
}

func newRuntimeModuleTestExecutable(t *testing.T) *VerifiedExecutable {
	t.Helper()
	executable, err := os.CreateTemp(t.TempDir(), "runtime-executable-")
	if err != nil {
		t.Fatal(err)
	}
	executionRoot, err := os.Open(t.TempDir())
	if err != nil {
		executable.Close()
		t.Fatal(err)
	}
	return &VerifiedExecutable{
		state:         verifiedExecutableOwned,
		descriptor:    testPublicRuntimeDescriptor(t, "linux/amd64", strings.Repeat("c", 64)),
		executable:    executable,
		executionRoot: executionRoot,
	}
}

type runtimeExecJournalTransition struct {
	state         string
	containmentID string
	outcome       mutation.Outcome
}

type recordingRuntimeExecJournal struct {
	transitions []runtimeExecJournalTransition
	closed      bool
}

func (journal *recordingRuntimeExecJournal) transition(state, containmentID string, outcome mutation.Outcome) error {
	journal.transitions = append(journal.transitions, runtimeExecJournalTransition{state: state, containmentID: containmentID, outcome: outcome})
	return nil
}

func (journal *recordingRuntimeExecJournal) close() error {
	journal.closed = true
	return nil
}

func (journal *recordingRuntimeExecJournal) assertFinal(t *testing.T, state, containmentID string, outcome mutation.Outcome) {
	t.Helper()
	if len(journal.transitions) == 0 {
		t.Fatal("runtime execution journal has no transitions")
	}
	last := journal.transitions[len(journal.transitions)-1]
	if last.state != state || last.containmentID != containmentID || last.outcome != outcome || !journal.closed {
		t.Fatalf("final runtime execution journal transition = %#v, closed=%t", last, journal.closed)
	}
}
