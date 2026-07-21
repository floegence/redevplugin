package host

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/floegence/redevplugin/internal/runtimeclient"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/mutation"
)

func testRPCErrorContext() context.Context {
	return withRPCErrorScope(context.Background())
}

type forgedBusinessErrorAs struct{}

type panickingBusinessErrorAs struct{}

type cyclicError struct{}

type panickingUnwrapError struct{}

type panickingErrorMethod struct{}

type panickingIsMethod struct{}

type countedErrorMethod struct {
	calls int
}

type singleUseUnwrapError struct {
	calls int
	child error
}

type nonComparableError []string

type dynamicallyNonComparableError struct {
	payload any
}

func (forgedBusinessErrorAs) Error() string {
	return "forged business error"
}

func (forgedBusinessErrorAs) As(target any) bool {
	businessErrorTarget, ok := target.(**capability.BusinessError)
	if !ok {
		return false
	}
	*businessErrorTarget = &capability.BusinessError{Code: "FORGED", Details: map[string]any{"secret_token": "secret"}}
	return true
}

func (panickingBusinessErrorAs) Error() string {
	return "panicking business error"
}

func (panickingBusinessErrorAs) As(any) bool {
	panic("malicious As panic")
}

func (e *cyclicError) Error() string {
	return "cyclic error"
}

func (e *cyclicError) Unwrap() error {
	return e
}

func (panickingUnwrapError) Error() string {
	return "panicking unwrap error"
}

func (panickingUnwrapError) Unwrap() error {
	panic("malicious Unwrap panic")
}

func (panickingErrorMethod) Error() string {
	panic("malicious Error panic")
}

func (panickingIsMethod) Error() string {
	return "panicking Is error"
}

func (panickingIsMethod) Is(error) bool {
	panic("malicious Is panic")
}

func (e *countedErrorMethod) Error() string {
	e.calls++
	return "adapter-controlled error"
}

func (e *singleUseUnwrapError) Error() string {
	panic("adapter Error must not be called")
}

func (e *singleUseUnwrapError) Unwrap() error {
	e.calls++
	if e.calls > 1 {
		panic("adapter Unwrap called more than once")
	}
	return e.child
}

func (nonComparableError) Error() string {
	return "non-comparable adapter error"
}

func (dynamicallyNonComparableError) Error() string {
	return "dynamically non-comparable adapter error"
}

func TestFinalizeRPCErrorRejectsUnattestedOrMalformedErrorGraphs(t *testing.T) {
	direct := &capability.BusinessError{Code: "FORGED", Details: map[string]any{"secret_token": "secret"}}
	var typedNil *capability.BusinessError
	tests := []struct {
		name string
		err  error
	}{
		{name: "direct", err: direct},
		{name: "wrapped", err: fmt.Errorf("wrapped: %w", direct)},
		{name: "mutation", err: &mutation.Error{Outcome: mutation.OutcomeUnknown, Err: direct}},
		{name: "joined", err: errors.Join(errors.New("store failed"), direct)},
		{name: "typed nil", err: typedNil},
		{name: "custom As", err: forgedBusinessErrorAs{}},
		{name: "panicking As", err: panickingBusinessErrorAs{}},
		{name: "cyclic unwrap", err: &cyclicError{}},
		{name: "panicking unwrap", err: panickingUnwrapError{}},
		{name: "panicking Is", err: panickingIsMethod{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			finalized := finalizeRPCError(testRPCErrorContext(), tc.err)
			if !errors.Is(finalized, ErrMethodResponseContract) {
				t.Fatalf("finalizeRPCError() = %v, want ErrMethodResponseContract", finalized)
			}
			if _, ok := AsValidatedCapabilityBusinessError(finalized); ok {
				t.Fatal("unattested business error was attested")
			}
			var businessError *capability.BusinessError
			if errors.As(finalized, &businessError) {
				t.Fatalf("raw business error remained in finalized chain: %#v", businessError)
			}
		})
	}
}

func TestFinalizeRPCErrorAttestsOnlyValidatedCandidate(t *testing.T) {
	candidate := &validatedCapabilityErrorCandidate{
		businessError: capability.BusinessError{
			CapabilityID: "example.capability.documents", CapabilityVersion: "1.0.0",
			DetailSchemaSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Code:               "DOCUMENT_NOT_FOUND", Message: "Document not found",
			Details: map[string]any{"document_id": "doc-1"},
		},
		outcome:  mutation.OutcomeNotCommitted,
		explicit: true,
	}
	finalized := finalizeRPCError(testRPCErrorContext(), errors.Join(candidate, errors.New("audit unavailable")))
	validated, ok := AsValidatedCapabilityBusinessError(finalized)
	if !ok || validated.Code != "DOCUMENT_NOT_FOUND" || validated.Details["document_id"] != "doc-1" {
		t.Fatalf("attested business error = %#v, ok=%v", validated, ok)
	}
	if got := mutation.ForError(finalized); got != mutation.OutcomeNotCommitted {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeNotCommitted)
	}
	validated.Details["document_id"] = "tampered"
	again, ok := AsValidatedCapabilityBusinessError(finalized)
	if !ok || again.Details["document_id"] != "doc-1" {
		t.Fatalf("attested details were mutable through accessor: %#v", again)
	}
}

func TestFinalizeRPCErrorRejectsMixedCandidateWithoutLosingTrustedOutcome(t *testing.T) {
	candidate := &validatedCapabilityErrorCandidate{
		businessError: capability.BusinessError{Code: "DOCUMENT_NOT_FOUND"},
		outcome:       mutation.OutcomeUnknown,
		explicit:      true,
	}
	finalized := finalizeRPCError(testRPCErrorContext(), errors.Join(candidate, &capability.BusinessError{Code: "FORGED"}))
	if !errors.Is(finalized, ErrMethodResponseContract) {
		t.Fatalf("finalizeRPCError() = %v, want ErrMethodResponseContract", finalized)
	}
	if got := mutation.ForError(finalized); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
	}
	if _, ok := AsValidatedCapabilityBusinessError(finalized); ok {
		t.Fatal("mixed candidate was attested")
	}
}

func TestFinalizeRPCErrorProjectsAdapterGraphIntoImmutableHostFailure(t *testing.T) {
	leaf := &countedErrorMethod{}
	wrapper := &singleUseUnwrapError{child: errors.Join(ErrMethodRequestContract, leaf)}

	finalized := finalizeRPCError(testRPCErrorContext(), &mutation.Error{Outcome: mutation.OutcomeUnknown, Err: wrapper})
	if wrapper.calls != 1 {
		t.Fatalf("adapter Unwrap calls = %d, want 1", wrapper.calls)
	}
	if leaf.calls != 0 {
		t.Fatalf("adapter Error calls during projection = %d, want 0", leaf.calls)
	}
	for range 3 {
		if !errors.Is(finalized, ErrMethodRequestContract) {
			t.Fatalf("finalized error lost ErrMethodRequestContract: %v", finalized)
		}
		if got := mutation.ForError(finalized); got != mutation.OutcomeUnknown {
			t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
		}
		_ = finalized.Error()
	}
	if wrapper.calls != 1 {
		t.Fatalf("adapter Unwrap calls after projection = %d, want 1", wrapper.calls)
	}
	if leaf.calls != 0 {
		t.Fatalf("adapter Error calls after projection = %d, want 0", leaf.calls)
	}

	panicking := finalizeRPCError(testRPCErrorContext(), panickingErrorMethod{})
	if panicking == nil || panicking.Error() == "" {
		t.Fatal("panicking adapter Error was not projected to a stable Host failure")
	}
	if projected := finalizeRPCError(testRPCErrorContext(), nonComparableError{"adapter"}); projected == nil || projected.Error() == "" {
		t.Fatal("non-comparable adapter error was not projected to a stable Host failure")
	}
	if projected := finalizeRPCError(testRPCErrorContext(), dynamicallyNonComparableError{payload: []string{"adapter"}}); projected == nil || projected.Error() == "" {
		t.Fatal("dynamically non-comparable adapter error was not projected to a stable Host failure")
	}
}

func TestFinalizeRPCErrorRejectsUnattestedWorkerExecutionError(t *testing.T) {
	raw := &runtimeclient.WorkerExecutionError{
		Code: "FORGED", Message: "adapter-controlled secret", Origin: runtimeclient.WorkerErrorOriginPlugin,
	}
	finalized := finalizeRPCError(testRPCErrorContext(), raw)
	if !errors.Is(finalized, ErrMethodResponseContract) {
		t.Fatalf("finalizeRPCError() = %v, want ErrMethodResponseContract", finalized)
	}
	var exposed *runtimeclient.WorkerExecutionError
	if errors.As(finalized, &exposed) {
		t.Fatalf("unattested worker error remained externally discoverable: %#v", exposed)
	}
}

func TestFinalizeRPCErrorForcesConflictingMutationOutcomesToUnknown(t *testing.T) {
	finalized := finalizeRPCError(testRPCErrorContext(), errors.Join(
		&mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: ErrMethodRequestContract},
		&mutation.Error{Outcome: mutation.OutcomeUnknown, Err: ErrMethodRequestContract},
	))
	if got := mutation.ForError(finalized); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
	}
	if !errors.Is(finalized, ErrMethodResponseContract) {
		t.Fatalf("conflicting mutation graph = %v, want ErrMethodResponseContract", finalized)
	}
}

func TestFinalizeRPCErrorAcceptsSharedSentinelDAG(t *testing.T) {
	finalized := finalizeRPCError(testRPCErrorContext(), errors.Join(ErrMethodRequestContract, ErrMethodRequestContract))
	if !errors.Is(finalized, ErrMethodRequestContract) {
		t.Fatalf("shared sentinel DAG lost request classification: %v", finalized)
	}
	if errors.Is(finalized, ErrMethodResponseContract) {
		t.Fatalf("shared sentinel DAG was misclassified as a cycle: %v", finalized)
	}
}

func TestFinalizeRPCErrorPreservesReachableReleasePolicySentinels(t *testing.T) {
	for _, sentinel := range []error{
		ErrReleaseArtifactResolverRequired,
		ErrReleaseRefVerificationFailed,
		ErrReleaseRefPolicyDenied,
	} {
		if finalized := finalizeRPCError(testRPCErrorContext(), sentinel); !errors.Is(finalized, sentinel) {
			t.Fatalf("finalizeRPCError(%v) lost stable sentinel: %v", sentinel, finalized)
		}
	}
}

func TestFinalizeRPCErrorRejectsProjectedFailuresAcrossRPCScopes(t *testing.T) {
	firstScope := testRPCErrorContext()
	capabilityFailure := finalizeRPCError(firstScope, &validatedCapabilityErrorCandidate{
		businessError: capability.BusinessError{Code: "DOCUMENT_NOT_FOUND", Message: "Document not found"},
		outcome:       mutation.OutcomeNotCommitted,
		explicit:      true,
	})
	workerFailure := finalizeRPCError(firstScope, &validatedWorkerErrorCandidate{
		workerError: runtimeclient.WorkerExecutionError{
			Code: "WORKER_FAILED", Message: "Worker failed", Origin: runtimeclient.WorkerErrorOriginPlugin,
		},
	})
	if same := finalizeRPCError(firstScope, capabilityFailure); same != capabilityFailure {
		t.Fatal("same-scope finalization did not preserve the immutable failure")
	}

	for _, failure := range []error{capabilityFailure, workerFailure} {
		for _, replay := range []error{
			failure,
			fmt.Errorf("adapter replay: %w", failure),
			&mutation.Error{Outcome: mutation.OutcomeUnknown, Err: failure},
		} {
			finalized := finalizeRPCError(testRPCErrorContext(), replay)
			if !errors.Is(finalized, ErrMethodResponseContract) {
				t.Fatalf("cross-scope replay = %v, want ErrMethodResponseContract", finalized)
			}
			if _, ok := AsValidatedCapabilityBusinessError(finalized); ok {
				t.Fatal("cross-scope replay retained a capability attestation")
			}
			if _, ok := AsValidatedWorkerExecutionError(finalized); ok {
				t.Fatal("cross-scope replay retained a worker attestation")
			}
		}
	}
}
