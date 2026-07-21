package host

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/stream"
)

const maxRPCErrorGraphNodes = 256

var errRPCUnavailable = errors.New("plugin RPC failed")

// validatedCapabilityErrorCandidate exists only between capability contract
// validation and the public RPC boundary. It never leaves Host.
type validatedCapabilityErrorCandidate struct {
	businessError capability.BusinessError
	outcome       mutation.Outcome
	explicit      bool
}

func (*validatedCapabilityErrorCandidate) Error() string {
	return "validated capability business error"
}

type validatedWorkerErrorCandidate struct {
	workerError runtimeclient.WorkerExecutionError
}

type rpcErrorScope struct {
	marker byte
}

type rpcErrorScopeContextKey struct{}

func withRPCErrorScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, rpcErrorScopeContextKey{}, &rpcErrorScope{marker: 1})
}

func rpcErrorScopeFromContext(ctx context.Context) *rpcErrorScope {
	if ctx == nil {
		return nil
	}
	scope, _ := ctx.Value(rpcErrorScopeContextKey{}).(*rpcErrorScope)
	return scope
}

func (*validatedWorkerErrorCandidate) Error() string {
	return "validated worker execution error"
}

// rpcFailure is the immutable error representation allowed to leave Host RPCs.
// It contains no adapter-owned error objects.
type rpcFailure struct {
	scope         *rpcErrorScope
	sentinels     []error
	businessError *capability.BusinessError
	workerError   *runtimeclient.WorkerExecutionError
}

func (*rpcFailure) Error() string {
	return errRPCUnavailable.Error()
}

func (e *rpcFailure) Is(target error) bool {
	if e == nil || target == nil || !reflect.TypeOf(target).Comparable() {
		return false
	}
	for _, sentinel := range e.sentinels {
		if target == sentinel {
			return true
		}
	}
	return false
}

func (e *rpcFailure) As(target any) bool {
	if e == nil {
		return false
	}
	switch typed := target.(type) {
	case **capability.BusinessError:
		if e.businessError == nil {
			return false
		}
		cloned := cloneCapabilityBusinessError(*e.businessError)
		*typed = &cloned
		return true
	case **runtimeclient.WorkerExecutionError:
		if e.workerError == nil {
			return false
		}
		cloned := *e.workerError
		*typed = &cloned
		return true
	default:
		return false
	}
}

// AsValidatedCapabilityBusinessError returns a copy of a published business error attested by Host.
func AsValidatedCapabilityBusinessError(err error) (capability.BusinessError, bool) {
	failure, _, _, ok := closedRPCFailure(err)
	if !ok || failure.businessError == nil {
		return capability.BusinessError{}, false
	}
	return cloneCapabilityBusinessError(*failure.businessError), true
}

// AsValidatedWorkerExecutionError returns a copy of a worker failure attested by Host.
func AsValidatedWorkerExecutionError(err error) (runtimeclient.WorkerExecutionError, bool) {
	failure, _, _, ok := closedRPCFailure(err)
	if !ok || failure.workerError == nil {
		return runtimeclient.WorkerExecutionError{}, false
	}
	return *failure.workerError, true
}

// HasUnattestedRPCStructuredError reports whether an unprojected error graph
// contains a business- or worker-error claim that did not pass its Host-owned
// attestation boundary.
func HasUnattestedRPCStructuredError(err error) bool {
	if _, _, _, ok := closedRPCFailure(err); ok {
		return false
	}
	analysis := analyzeRPCError(err)
	return len(analysis.rawBusinessErrors) != 0 || len(analysis.rawWorkerErrors) != 0 || analysis.malformed
}

type rpcErrorAnalysis struct {
	candidates        []*validatedCapabilityErrorCandidate
	workerCandidates  []*validatedWorkerErrorCandidate
	rawBusinessErrors []*capability.BusinessError
	rawWorkerErrors   []*runtimeclient.WorkerExecutionError
	projected         []*rpcFailure
	sentinels         []error
	outcome           mutation.Outcome
	explicitOutcome   bool
	malformed         bool
}

func directCapabilityBusinessError(err error) (businessError *capability.BusinessError, outcome mutation.Outcome, explicit bool, ok bool) {
	switch typed := err.(type) {
	case *capability.BusinessError:
		return typed, "", false, true
	case *mutation.Error:
		if typed == nil || typed.Err == nil || (typed.Outcome != mutation.OutcomeNotCommitted && typed.Outcome != mutation.OutcomeUnknown) {
			return nil, "", false, true
		}
		businessError, ok := typed.Err.(*capability.BusinessError)
		if !ok {
			return nil, "", false, false
		}
		return businessError, typed.Outcome, true, true
	default:
		return nil, "", false, false
	}
}

func validateWorkerErrorCandidate(err error) error {
	workerError, ok := err.(*runtimeclient.WorkerExecutionError)
	if !ok {
		return err
	}
	validated, valid := validateWorkerExecutionError(workerError)
	if !valid {
		return methodResponseContractError("invalid worker execution error")
	}
	return &validatedWorkerErrorCandidate{workerError: validated}
}

func analyzeRPCError(err error) rpcErrorAnalysis {
	var analysis rpcErrorAnalysis
	active := map[error]struct{}{}
	completed := map[error]struct{}{}
	nodes := 0
	var visit func(error)
	visit = func(current error) {
		if current == nil || analysis.malformed {
			return
		}
		nodes++
		if nodes > maxRPCErrorGraphNodes {
			analysis.malformed = true
			return
		}
		currentValue := reflect.ValueOf(current)
		if currentValue.Comparable() {
			if _, exists := completed[current]; exists {
				return
			}
			if _, exists := active[current]; exists {
				analysis.malformed = true
				return
			}
			active[current] = struct{}{}
			defer func() {
				delete(active, current)
				completed[current] = struct{}{}
			}()
		}

		switch typed := current.(type) {
		case *validatedCapabilityErrorCandidate:
			if typed == nil {
				analysis.malformed = true
				return
			}
			analysis.candidates = append(analysis.candidates, typed)
			analysis.setOutcome(typed.outcome, typed.explicit)
			return
		case *validatedWorkerErrorCandidate:
			if typed == nil {
				analysis.malformed = true
				return
			}
			analysis.workerCandidates = append(analysis.workerCandidates, typed)
			return
		case *rpcFailure:
			if typed == nil {
				analysis.malformed = true
				return
			}
			analysis.projected = append(analysis.projected, typed)
			return
		case *capability.BusinessError:
			analysis.rawBusinessErrors = append(analysis.rawBusinessErrors, typed)
			return
		case *runtimeclient.WorkerExecutionError:
			analysis.rawWorkerErrors = append(analysis.rawWorkerErrors, typed)
			return
		case *mutation.Error:
			if typed == nil || typed.Err == nil || (typed.Outcome != mutation.OutcomeNotCommitted && typed.Outcome != mutation.OutcomeUnknown) {
				analysis.malformed = true
				return
			}
			analysis.setOutcome(typed.Outcome, true)
			visit(typed.Err)
			return
		}

		if sentinel := stableRPCSentinel(current); sentinel != nil {
			analysis.sentinels = append(analysis.sentinels, sentinel)
			return
		}
		if _, customIs := current.(interface{ Is(error) bool }); customIs {
			analysis.malformed = true
			return
		}
		if _, customAs := current.(interface{ As(any) bool }); customAs {
			analysis.malformed = true
			return
		}

		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			children, ok := safelyUnwrapMany(wrapped)
			if !ok || len(children) == 0 || len(children) > maxRPCErrorGraphNodes {
				analysis.malformed = true
				return
			}
			for _, child := range children {
				if child == nil {
					analysis.malformed = true
					return
				}
				visit(child)
			}
		case interface{ Unwrap() error }:
			child, ok := safelyUnwrapOne(wrapped)
			if !ok || child == nil {
				analysis.malformed = true
				return
			}
			visit(child)
		}
	}
	visit(err)
	return analysis
}

func (a *rpcErrorAnalysis) setOutcome(outcome mutation.Outcome, explicit bool) {
	if !explicit {
		return
	}
	if a.explicitOutcome && a.outcome != outcome {
		a.outcome = mutation.OutcomeUnknown
		a.malformed = true
		return
	}
	a.outcome = outcome
	a.explicitOutcome = true
}

func safelyUnwrapMany(wrapper interface{ Unwrap() []error }) (children []error, ok bool) {
	defer func() {
		if recover() != nil {
			children = nil
			ok = false
		}
	}()
	return wrapper.Unwrap(), true
}

func safelyUnwrapOne(wrapper interface{ Unwrap() error }) (child error, ok bool) {
	defer func() {
		if recover() != nil {
			child = nil
			ok = false
		}
	}()
	return wrapper.Unwrap(), true
}

func finalizeRPCError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	scope := rpcErrorScopeFromContext(ctx)
	if failure, _, _, ok := closedRPCFailure(err); ok && failure.scope == scope {
		return err
	}
	analysis := analyzeRPCError(err)
	for _, projected := range analysis.projected {
		if projected.scope != scope {
			analysis.malformed = true
		}
	}

	if analysis.malformed || len(analysis.rawBusinessErrors) != 0 || len(analysis.rawWorkerErrors) != 0 ||
		len(analysis.candidates) > 1 || len(analysis.workerCandidates) > 1 {
		failure := newRPCFailure(scope, []error{ErrMethodResponseContract}, nil, nil)
		if len(analysis.candidates) == 1 {
			analysis.setOutcome(analysis.candidates[0].outcome, analysis.candidates[0].explicit)
		}
		if analysis.explicitOutcome {
			analysis.outcome = mutation.OutcomeUnknown
		}
		return wrapRPCFailureOutcome(scope, failure, analysis.outcome, analysis.explicitOutcome)
	}

	sentinels := append([]error(nil), analysis.sentinels...)
	var businessError *capability.BusinessError
	if len(analysis.candidates) == 1 {
		cloned := cloneCapabilityBusinessError(analysis.candidates[0].businessError)
		businessError = &cloned
		analysis.setOutcome(analysis.candidates[0].outcome, analysis.candidates[0].explicit)
	}
	var workerError *runtimeclient.WorkerExecutionError
	if len(analysis.workerCandidates) == 1 {
		cloned := analysis.workerCandidates[0].workerError
		workerError = &cloned
		sentinels = append(sentinels, runtimeclient.ErrRuntimeRequestFailed)
	}
	for _, projected := range analysis.projected {
		sentinels = append(sentinels, projected.sentinels...)
		if projected.businessError != nil {
			if businessError != nil {
				return wrapRPCFailureOutcome(scope, newRPCFailure(scope, []error{ErrMethodResponseContract}, nil, nil), mutation.OutcomeUnknown, analysis.explicitOutcome)
			}
			cloned := cloneCapabilityBusinessError(*projected.businessError)
			businessError = &cloned
		}
		if projected.workerError != nil {
			if workerError != nil {
				return wrapRPCFailureOutcome(scope, newRPCFailure(scope, []error{ErrMethodResponseContract}, nil, nil), mutation.OutcomeUnknown, analysis.explicitOutcome)
			}
			cloned := *projected.workerError
			workerError = &cloned
		}
	}
	if len(sentinels) == 0 && businessError == nil && workerError == nil {
		sentinels = append(sentinels, errRPCUnavailable)
	}
	failure := newRPCFailure(scope, sentinels, businessError, workerError)
	return wrapRPCFailureOutcome(scope, failure, analysis.outcome, analysis.explicitOutcome)
}

func mergeRPCFailures(ctx context.Context, primary, secondary error) error {
	if primary == nil {
		return finalizeRPCError(ctx, secondary)
	}
	if secondary == nil {
		return finalizeRPCError(ctx, primary)
	}
	return finalizeRPCError(ctx, errors.Join(finalizeRPCError(ctx, primary), finalizeRPCError(ctx, secondary)))
}

func wrapRPCFailureOutcome(scope *rpcErrorScope, failure *rpcFailure, outcome mutation.Outcome, explicit bool) error {
	if !explicit {
		return failure
	}
	if outcome != mutation.OutcomeNotCommitted && outcome != mutation.OutcomeUnknown {
		return &mutation.Error{Outcome: mutation.OutcomeUnknown, Err: newRPCFailure(scope, []error{ErrMethodResponseContract}, nil, nil)}
	}
	return &mutation.Error{Outcome: outcome, Err: failure}
}

func closedRPCFailure(err error) (failure *rpcFailure, outcome mutation.Outcome, explicit bool, ok bool) {
	switch typed := err.(type) {
	case *rpcFailure:
		if typed == nil {
			return nil, "", false, false
		}
		return typed, "", false, true
	case *mutation.Error:
		if typed == nil || (typed.Outcome != mutation.OutcomeNotCommitted && typed.Outcome != mutation.OutcomeUnknown) {
			return nil, "", false, false
		}
		failure, ok := typed.Err.(*rpcFailure)
		if !ok || failure == nil {
			return nil, "", false, false
		}
		return failure, typed.Outcome, true, true
	default:
		return nil, "", false, false
	}
}

func newRPCFailure(scope *rpcErrorScope, sentinels []error, businessError *capability.BusinessError, workerError *runtimeclient.WorkerExecutionError) *rpcFailure {
	unique := make([]error, 0, len(sentinels))
	for _, sentinel := range sentinels {
		if sentinel == nil {
			continue
		}
		duplicate := false
		for _, existing := range unique {
			if existing == sentinel {
				duplicate = true
				break
			}
		}
		if !duplicate {
			unique = append(unique, sentinel)
		}
	}
	return &rpcFailure{scope: scope, sentinels: unique, businessError: businessError, workerError: workerError}
}

func validateWorkerExecutionError(value *runtimeclient.WorkerExecutionError) (runtimeclient.WorkerExecutionError, bool) {
	if value == nil || value.Code == "" || value.Code != strings.TrimSpace(value.Code) ||
		value.Message == "" || value.Message != strings.TrimSpace(value.Message) || len(value.Message) > 4096 {
		return runtimeclient.WorkerExecutionError{}, false
	}
	if value.Origin != runtimeclient.WorkerErrorOriginRuntime && value.Origin != runtimeclient.WorkerErrorOriginHostcall &&
		value.Origin != runtimeclient.WorkerErrorOriginPlugin {
		return runtimeclient.WorkerExecutionError{}, false
	}
	for index, char := range value.Code {
		if (index == 0 && (char < 'A' || char > 'Z')) ||
			(index > 0 && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_') {
			return runtimeclient.WorkerExecutionError{}, false
		}
	}
	return *value, true
}

func stableRPCSentinel(err error) error {
	for _, sentinel := range []error{
		context.Canceled, context.DeadlineExceeded,
		ErrStreamTicketRequired, ErrPluginDataNotDeclared, ErrPluginStorageNotDeclared, ErrPluginSettingsNotDeclared,
		ErrPluginDataContractChanged, ErrOperationCancelDispatchFailed, ErrMethodRequestContract, ErrMethodResponseContract,
		ErrMethodAdapterPanic, ErrManagementRevisionMismatch, ErrPluginAlreadyInstalled, ErrPluginUIProtocolUnsupported,
		ErrPluginRuntimeNotConfigured, ErrPluginRuntimeIncompatible, ErrActionDenied,
		ErrConfirmationRequired, ErrConfirmationInvalid, ErrConfirmationRejected, ErrSecurityEventPersistence,
		ErrPluginTrustUnavailable, ErrPluginTrustDenied, ErrReleaseRefVerificationFailed, ErrHostClosed,
		ErrSecretStoreRequired, ErrInvalidSecretRef, ErrPackageTrustVerifierRequired, ErrPackageTrustVerificationInvalid,
		ErrReleaseArtifactResolverRequired, ErrReleaseRefPolicyDenied,
		capability.ErrInvalidRegistration, capability.ErrRegistrationMissing, capability.ErrExecutionRevoked,
		capability.ErrInvalidExecutionFailure, capability.ErrQuotaExceeded,
		permissions.ErrInvalidPermission, permissions.ErrPermissionDenied, permissions.ErrGrantNotFound,
		security.ErrInvalidPolicy, security.ErrPolicyNotFound, security.ErrPolicyDenied,
		security.ErrInvalidConfirmationIntent, security.ErrConfirmationIntentNotFound,
		security.ErrConfirmationIntentExpired, security.ErrConfirmationIntentScopeMismatch,
		bridge.ErrTokenInvalid, bridge.ErrTokenExpired, bridge.ErrTokenReplay, bridge.ErrTokenAudience,
		bridge.ErrTokenKind, bridge.ErrTokenRevoked, bridge.ErrTokenAlreadyBound, bridge.ErrMissingTokenAudience,
		bridge.ErrTokenCapacity, bridge.ErrTokenPluginCapacity, bridge.ErrTokenTTLExceeded, bridge.ErrTokenRevokeFloorCapacity,
		bridge.ErrSurfaceSessionNotFound, bridge.ErrSurfaceSessionExpired, bridge.ErrSurfaceSessionAlreadyExists,
		bridge.ErrSurfaceSessionLimitReached, bridge.ErrHandshakeMismatch, bridge.ErrAssetSessionRequired,
		registry.ErrNotFound, registry.ErrInvalidAuthorizationRevisions, registry.ErrAuthorizationRevisionConflict,
		runtimeclient.ErrRuntimePathRequired, runtimeclient.ErrRuntimeNotReady, runtimeclient.ErrRuntimeIPCUnavailable,
		runtimeclient.ErrRuntimeHandshake, runtimeclient.ErrRuntimeRequestFailed, runtimeclient.ErrRuntimeTimingInvalid,
		runtimeclient.ErrRuntimeShardCount, runtimeclient.ErrRuntimeBindingInvalid,
		runtimeclient.ErrManagerLifecycleOutcomeUnknown, runtimeclient.ErrRuntimeHostServicesInvalid,
		runtimeclient.ErrRuntimeHostServicesRequired, runtimeclient.ErrRuntimeHostServicesBound,
		operation.ErrNotFound, operation.ErrInvalidOperation, operation.ErrAlreadyExists, operation.ErrDeleteBlocked,
		operation.ErrNotCancelable,
		stream.ErrNotFound, stream.ErrInvalidStream, stream.ErrAlreadyExists, stream.ErrStreamClosed,
		stream.ErrStoreClosed, stream.ErrStreamInvariant, stream.ErrBackpressure, stream.ErrDeliveryInvalid,
	} {
		if err == sentinel {
			return sentinel
		}
	}
	return nil
}

func methodResponseContractError(reason string) error {
	return fmt.Errorf("%w: %s", ErrMethodResponseContract, reason)
}

func cloneCapabilityBusinessError(value capability.BusinessError) capability.BusinessError {
	value.Details = cloneCanonicalJSONObject(value.Details)
	return value
}

func cloneCanonicalJSONObject(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	cloned := make(map[string]any, len(value))
	for key, item := range value {
		cloned[key] = cloneCanonicalJSONValue(item)
	}
	return cloned
}

func cloneCanonicalJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneCanonicalJSONObject(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneCanonicalJSONValue(item)
		}
		return cloned
	default:
		return typed
	}
}
