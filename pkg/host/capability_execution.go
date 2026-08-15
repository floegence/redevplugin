package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/controlstore"
	"github.com/floegence/redevplugin/internal/jsonvalue"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/execution"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type resolvedCapabilityMethod struct {
	binding      manifest.CapabilityBinding
	pin          capabilitycontract.Pin
	contract     capabilitycontract.KnownContract
	method       capabilitycontract.Method
	registration capability.Registration
}

type methodExecutionAuthorization struct {
	confirmation capability.ConfirmationEvidence
	target       capability.TargetDescriptor
	targetHash   string
}

func (h *Host) resolvePackageCapabilityPins(ctx context.Context, pkg manifest.Manifest, trustInput packageTrustInput) ([]capabilitycontract.Pin, error) {
	if len(pkg.CapabilityBindings) == 0 && !releaseRequiresCapabilities(trustInput.Release) {
		return nil, nil
	}
	if err := h.requireFeature(FeatureCapability); err != nil {
		return nil, err
	}
	pins := make([]capabilitycontract.Pin, 0, len(pkg.CapabilityBindings))
	contracts := make([]capabilitycontract.KnownContract, 0, len(pkg.CapabilityBindings))
	for _, binding := range pkg.CapabilityBindings {
		contract, err := h.adapters.Capabilities.RequireContract(binding.Contract)
		if err != nil {
			return nil, fmt.Errorf("resolve registered capability contract %s@%s: %w", binding.Contract.ContractID, binding.Contract.ContractVersion, err)
		}
		pins = append(pins, contract.Pin)
		contracts = append(contracts, contract)
	}
	if trustInput.Release != nil {
		if err := h.ensureReleaseCapabilityContracts(ctx, *trustInput.Release, contracts); err != nil {
			return nil, err
		}
	}
	if err := h.validateManifestCapabilityContracts(pkg, pins); err != nil {
		return nil, err
	}
	sort.Slice(pins, func(i, j int) bool {
		if pins[i].ContractID == pins[j].ContractID {
			return pins[i].ContractVersion < pins[j].ContractVersion
		}
		return pins[i].ContractID < pins[j].ContractID
	})
	return pins, nil
}

func (h *Host) ensureReleaseCapabilityContracts(ctx context.Context, release PluginPackageRelease, contracts []capabilitycontract.KnownContract) error {
	requirement, err := h.selectHostRequirement(ctx, release)
	if err != nil {
		return err
	}
	if requirement == nil || len(requirement.RequiredCapabilityContracts) == 0 {
		return nil
	}
	for _, required := range requirement.RequiredCapabilityContracts {
		matches := 0
		for _, verified := range contracts {
			if verified.Contract.CapabilityID == required.CapabilityID && verified.Contract.CapabilityVersion == required.CapabilityVersion {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("%w: capability requirement %s@%s must match exactly one manifest-pinned registered contract", ErrReleaseRefVerificationFailed, required.CapabilityID, required.CapabilityVersion)
		}
	}
	return nil
}

func (h *Host) selectHostRequirement(ctx context.Context, release PluginPackageRelease) (*HostRequirement, error) {
	requirements := release.HostRequirements
	if len(requirements) == 0 {
		return nil, nil
	}
	if h.adapters.HostRequirements == nil {
		return nil, fmt.Errorf("%w: host requirement policy is required", ErrReleaseRefVerificationFailed)
	}
	cloned := cloneHostRequirements(requirements)
	selection, err := h.adapters.HostRequirements.SelectHostRequirement(ctx, HostRequirementSelectionRequest{
		SourceID: release.SourceID, PublisherID: release.PublisherID, PluginID: release.PluginID,
		PluginVersion: release.Version, Requirements: cloned,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: host requirement policy rejected the release: %v", ErrReleaseRefVerificationFailed, err)
	}
	hostID := strings.TrimSpace(selection.HostID)
	if hostID == "" {
		return nil, fmt.Errorf("%w: host requirement policy returned an empty host_id", ErrReleaseRefVerificationFailed)
	}
	var selected *HostRequirement
	for index := range requirements {
		if requirements[index].HostID != hostID {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("%w: host requirement is duplicated", ErrReleaseRefVerificationFailed)
		}
		copy := requirements[index]
		selected = &copy
	}
	if selected == nil {
		return nil, fmt.Errorf("%w: host requirement policy selected undeclared host %q", ErrReleaseRefVerificationFailed, hostID)
	}
	return selected, nil
}

func cloneHostRequirements(requirements []HostRequirement) []HostRequirement {
	cloned := make([]HostRequirement, len(requirements))
	for index, requirement := range requirements {
		cloned[index] = requirement
		cloned[index].RequiredCapabilityContracts = append([]HostCapabilityRequirement(nil), requirement.RequiredCapabilityContracts...)
	}
	return cloned
}

func (h *Host) validateManifestCapabilityContracts(plugin manifest.Manifest, pins []capabilitycontract.Pin) error {
	declared := make(map[capabilitycontract.Pin]struct{}, len(plugin.CapabilityBindings))
	for _, binding := range plugin.CapabilityBindings {
		if _, duplicate := declared[binding.Contract]; duplicate {
			return fmt.Errorf("capability contract %s@%s is bound more than once", binding.Contract.ContractID, binding.Contract.ContractVersion)
		}
		declared[binding.Contract] = struct{}{}
		if _, err := h.resolvePinnedCapabilityContract(pins, binding); err != nil {
			return err
		}
	}
	for _, pin := range pins {
		if _, ok := declared[pin]; !ok {
			return fmt.Errorf("verified contract %s@%s is required by the host but not declared by the plugin", pin.ContractID, pin.ContractVersion)
		}
	}
	for _, method := range plugin.Methods {
		if method.Route.Kind != manifest.MethodRouteCapability {
			continue
		}
		binding, ok := manifestBinding(plugin, method.Route.BindingID)
		if !ok {
			return fmt.Errorf("capability binding %q is not declared", method.Route.BindingID)
		}
		verified, err := h.resolvePinnedCapabilityContract(pins, binding)
		if err != nil {
			return err
		}
		_, ok = contractMethod(verified.Contract, method.Route.TargetMethod)
		if !ok {
			return fmt.Errorf("capability target method %q is not published by %s", method.Route.TargetMethod, verified.Contract.ContractID)
		}
		if method.Method != method.Route.TargetMethod {
			return fmt.Errorf("plugin method %q must match signed capability method %q", method.Method, method.Route.TargetMethod)
		}
	}
	return nil
}

func (h *Host) resolveCapabilityMethod(record registry.PluginRecord, method manifest.MethodSpec) (resolvedCapabilityMethod, error) {
	if err := h.requireFeature(FeatureCapability); err != nil {
		return resolvedCapabilityMethod{}, err
	}
	binding, ok := manifestBinding(record.Manifest, method.Route.BindingID)
	if !ok {
		return resolvedCapabilityMethod{}, fmt.Errorf("capability binding %q is not declared", method.Route.BindingID)
	}
	verified, err := h.resolvePinnedCapabilityContract(record.CapabilityContracts, binding)
	if err != nil {
		return resolvedCapabilityMethod{}, err
	}
	contractMethod, ok := contractMethod(verified.Contract, method.Route.TargetMethod)
	if !ok {
		return resolvedCapabilityMethod{}, fmt.Errorf("capability target method %q is not published", method.Route.TargetMethod)
	}
	registration, err := h.adapters.Capabilities.Resolve(verified.Pin)
	if err != nil {
		return resolvedCapabilityMethod{}, err
	}
	return resolvedCapabilityMethod{binding: binding, pin: verified.Pin, contract: verified, method: contractMethod, registration: registration}, nil
}

func (h *Host) effectiveMethod(record registry.PluginRecord, declared manifest.MethodSpec) (manifest.MethodSpec, error) {
	if declared.Route.Kind != manifest.MethodRouteCapability {
		return declared, nil
	}
	resolved, err := h.resolveCapabilityMethod(record, declared)
	if err != nil {
		return manifest.MethodSpec{}, err
	}
	effective := manifest.MethodSpec{
		Method:         declared.Method,
		Effect:         manifest.MethodEffect(resolved.method.Effect),
		Execution:      manifest.MethodExecutionMode(resolved.method.Execution),
		PreflightOnly:  resolved.method.PreflightOnly,
		RequestSchema:  cloneParams(resolved.method.RequestSchema),
		ResponseSchema: cloneParams(resolved.method.ResponseSchema),
		Route:          declared.Route,
	}
	if resolved.method.Confirmation != nil {
		confirmation := resolved.method.Confirmation
		effective.Dangerous = true
		effective.Confirmation = &manifest.ConfirmationSpec{
			Mode:              manifest.ConfirmationMode(confirmation.Mode),
			RequestHashFields: append([]string(nil), confirmation.RequestHashFields...),
			PlanHashRequired:  confirmation.PlanHashRequired,
		}
		if confirmation.PreflightMethod != "" {
			preflight := confirmation.PreflightMethod
			effective.Confirmation.PreflightMethod = &preflight
		}
	}
	if resolved.method.CancelPolicy != nil {
		effective.CancelPolicy = &manifest.CancelPolicySpec{
			Cancelable:        resolved.method.CancelPolicy.Cancelable,
			DisableBehavior:   resolved.method.CancelPolicy.DisableBehavior,
			UninstallBehavior: resolved.method.CancelPolicy.UninstallBehavior,
			AckTimeoutMS:      resolved.method.CancelPolicy.AckTimeoutMS,
		}
	}
	return effective, nil
}

func (h *Host) resolveCapabilityTarget(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest, resolved resolvedCapabilityMethod) (capability.TargetDescriptor, string, error) {
	targetInput, err := extractCapabilityTargetInput(req.Params, resolved.method.TargetFields)
	if err != nil {
		return capability.TargetDescriptor{}, "", err
	}
	target, err := resolved.registration.TargetProjector.ProjectTarget(ctx, capability.TargetResolutionRequest{
		Identity: capability.PluginIdentity{
			PublisherID:       record.PublisherID,
			PluginID:          record.PluginID,
			PluginInstanceID:  record.PluginInstanceID,
			PluginVersion:     record.Version,
			ActiveFingerprint: record.ActiveFingerprint,
		},
		Surface: capability.SurfaceScope{
			SurfaceInstanceID:    req.SurfaceInstanceID,
			OwnerSessionHash:     req.session.OwnerSessionHash,
			OwnerUserHash:        req.session.OwnerUserHash,
			OwnerEnvHash:         req.session.OwnerEnvHash,
			SessionChannelIDHash: req.session.SessionChannelIDHash,
			BridgeChannelID:      req.BridgeChannelID,
		},
		CapabilityID:      resolved.contract.Contract.CapabilityID,
		CapabilityVersion: resolved.contract.Contract.CapabilityVersion,
		BindingID:         resolved.binding.BindingID,
		Contract:          resolved.pin,
		Method:            method.Method,
		TargetMethod:      method.Route.TargetMethod,
		TargetInput:       targetInput,
	})
	if err != nil {
		return capability.TargetDescriptor{}, "", err
	}
	if strings.TrimSpace(target.Kind) == "" || target.Fields == nil {
		return capability.TargetDescriptor{}, "", errors.New("capability adapter returned an invalid target descriptor")
	}
	target, err = capability.CloneTargetDescriptor(target)
	if err != nil {
		return capability.TargetDescriptor{}, "", err
	}
	if err := capabilitycontract.ValidateValue(resolved.method.TargetSchema, target.Fields); err != nil {
		return capability.TargetDescriptor{}, "", fmt.Errorf("capability target descriptor validation failed: %w", err)
	}
	hash, err := canonicalDescriptorHash(target)
	if err != nil {
		return capability.TargetDescriptor{}, "", err
	}
	return target, hash, nil
}

func extractCapabilityTargetInput(params map[string]any, targetFields []string) (map[string]any, error) {
	input := make(map[string]any, len(targetFields))
	for _, field := range targetFields {
		value, ok := params[field]
		if !ok {
			continue
		}
		input[field] = value
	}
	return jsonvalue.CloneCanonicalMap(input)
}

func (h *Host) prepareCapabilityExecution(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest, auth methodExecutionAuthorization, resolved resolvedCapabilityMethod) (capability.Invocation, context.Context, executionFinish, error) {
	target := auth.target
	targetHash := auth.targetHash
	if targetHash == "" {
		var err error
		target, targetHash, err = h.resolveCapabilityTarget(ctx, record, method, req, resolved)
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
	}
	arguments, err := deepCloneParams(req.Params)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	invocationID, err := newCapabilityID("invoke")
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	auditID, err := newCapabilityID("audit")
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	now := lifecycleNow(req.Now)
	quota := capability.QuotaGrant{
		MaxConcurrent:  resolved.method.Quota.MaxConcurrent,
		MaxDurationMS:  resolved.method.Quota.MaxDurationMS,
		MaxStreamBytes: resolved.method.Quota.MaxStreamBytes,
	}
	if quota.MaxDurationMS > 0 {
		quota.ExpiresAt = now.Add(time.Duration(quota.MaxDurationMS) * time.Millisecond)
	}
	binding := capability.ExecutionBinding{
		InvocationID:         invocationID,
		AuditCorrelationID:   auditID,
		PublisherID:          record.PublisherID,
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		PluginVersion:        record.Version,
		ActiveFingerprint:    record.ActiveFingerprint,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.session.OwnerSessionHash,
		OwnerUserHash:        req.session.OwnerUserHash,
		OwnerEnvHash:         req.session.OwnerEnvHash,
		SessionChannelIDHash: req.session.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		RouteKind:            capability.RouteCapability,
		CapabilityID:         resolved.contract.Contract.CapabilityID,
		CapabilityVersion:    resolved.contract.Contract.CapabilityVersion,
		BindingID:            resolved.binding.BindingID,
		Contract:             &resolved.pin,
		Method:               method.Method,
		TargetMethod:         method.Route.TargetMethod,
		Effect:               capability.Effect(method.Effect),
		Execution:            string(method.Execution),
		Permissions: capability.PermissionEvidence{
			Required: normalizeStringSet(resolved.method.RequiredPermissions),
			Granted:  normalizeStringSet(resolved.method.RequiredPermissions),
		},
		Confirmation: auth.confirmation,
		Revision: capability.RevisionEvidence{
			PolicyRevision:     record.PolicyRevision,
			ManagementRevision: record.ManagementRevision,
			RevokeEpoch:        record.RevokeEpoch,
		},
		Quota:                  quota,
		Target:                 target,
		TargetDescriptorSHA256: targetHash,
	}
	var streamContract *capability.StreamContract
	if method.Execution == manifest.MethodExecutionSubscription {
		schemaHash, err := capabilitycontract.SchemaSHA256(resolved.method.EventSchema)
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
		binding.StreamEventTypeName = resolved.method.EventTypeName
		binding.StreamEventSchemaSHA256 = schemaHash
		streamContract = &capability.StreamContract{
			EventTypeName: resolved.method.EventTypeName,
			EventSchema:   cloneParams(resolved.method.EventSchema),
		}
	}
	return h.startMethodExecution(ctx, record, method, binding, arguments, now, streamContract, operationCancelDispatchFor(resolved.registration.Adapter), false)
}

func (h *Host) resolvePinnedCapabilityContract(pins []capabilitycontract.Pin, binding manifest.CapabilityBinding) (capabilitycontract.KnownContract, error) {
	if err := h.requireFeature(FeatureCapability); err != nil {
		return capabilitycontract.KnownContract{}, err
	}
	for _, pin := range pins {
		if pin != binding.Contract {
			continue
		}
		candidate, err := h.adapters.Capabilities.RequireContract(pin)
		if err != nil {
			return capabilitycontract.KnownContract{}, err
		}
		return candidate, nil
	}
	return capabilitycontract.KnownContract{}, fmt.Errorf("known contract %s@%s is required", binding.Contract.ContractID, binding.Contract.ContractVersion)
}

type executionFinish func(bool, error) error

func (h *Host) startMethodExecution(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, binding capability.ExecutionBinding, arguments map[string]any, now time.Time, streamContract *capability.StreamContract, cancelDispatch executionCancelDispatch, completeOnReturn bool) (capability.Invocation, context.Context, executionFinish, error) {
	if err := validateExecutionBindingShape(binding); err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	ownedBinding, err := capability.CloneExecutionBinding(binding)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	binding = ownedBinding
	if err := h.reconcilePendingExecutionSetups(ctx, record.PluginInstanceID); err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	if method.Execution == manifest.MethodExecutionOperation || method.Execution == manifest.MethodExecutionSubscription {
		executionID, err := newCapabilityID("execution")
		if err != nil {
			return capability.Invocation{}, nil, nil, err
		}
		binding.ExecutionID = executionID
	}
	leaseBinding, err := capability.CloneExecutionBinding(binding)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	validationBinding, err := capability.CloneExecutionBinding(binding)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	h.lifecycleMu.RLock()
	if h.closed {
		h.lifecycleMu.RUnlock()
		return capability.Invocation{}, nil, nil, ErrHostClosed
	}
	lifecycleLocked := true
	defer func() {
		if lifecycleLocked {
			h.lifecycleMu.RUnlock()
		}
	}()
	lease, err := h.executions.start(ctx, leaseBinding, func(validateCtx context.Context) error {
		return h.validateExecutionBinding(validateCtx, validationBinding)
	})
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	executionBinding, err := capability.CloneExecutionBinding(binding)
	if err != nil {
		lease.finish()
		return capability.Invocation{}, nil, nil, err
	}
	executionContext := capability.ExecutionContext{ExecutionBinding: executionBinding}
	if method.Execution == manifest.MethodExecutionOperation || method.Execution == manifest.MethodExecutionSubscription {
		if h.controlStore == nil {
			lease.finish()
			return capability.Invocation{}, nil, nil, ErrControlStoreRequired
		}
		cancelable := method.CancelPolicy.Cancelable
		kind := execution.KindOperation
		if method.Execution == manifest.MethodExecutionSubscription {
			kind = execution.KindSubscription
		}
		auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{
			Type:             "plugin.execution.started",
			PluginID:         record.PluginID,
			PluginInstanceID: record.PluginInstanceID,
			Details:          executionStartedAuditDetails(binding, binding.ExecutionID),
		})
		if err != nil {
			lease.finish()
			return capability.Invocation{}, nil, nil, err
		}
		registerErr := h.controlStore.Executions().CreateOwned(ctx, execution.Execution{
			ID: binding.ExecutionID, PluginInstanceID: record.PluginInstanceID,
			Kind: kind, Cancelable: cancelable, CreatedAt: now,
		}, controlstore.ExecutionOwner{
			OwnerSessionHash: binding.OwnerSessionHash, OwnerUserHash: binding.OwnerUserHash,
			OwnerEnvHash: binding.OwnerEnvHash, SessionChannelIDHash: binding.SessionChannelIDHash,
		})
		if err := auditMutation.complete(context.WithoutCancel(ctx), registerErr); err != nil {
			lease.finish()
			return capability.Invocation{}, nil, nil, err
		}
		sink := &hostExecutionSink{
			host: h, lease: lease, executionID: binding.ExecutionID,
			ackTimeout: time.Duration(method.CancelPolicy.AckTimeoutMS) * time.Millisecond,
		}
		if method.Execution == manifest.MethodExecutionSubscription {
			sink.subscription = true
			sink.maxBytes = binding.Quota.MaxStreamBytes
			if streamContract != nil {
				sink.eventTypeName = strings.TrimSpace(streamContract.EventTypeName)
				sink.eventSchema = cloneParams(streamContract.EventSchema)
			}
		}
		lease.setExecution(sink, cancelDispatch)
		executionContext.Events = sink
	}
	h.lifecycleMu.RUnlock()
	lifecycleLocked = false
	lease.armTimeout(h)
	finish := func(success bool, cause error) error {
		terminalCtx := context.WithoutCancel(ctx)
		terminalCause := cause
		if terminalCause == nil {
			terminalCause = context.Cause(lease.ctx)
		}
		switch method.Execution {
		case manifest.MethodExecutionSync:
			if success && terminalCause != nil {
				lease.finish()
				return terminalCause
			}
			lease.finish()
			return nil
		case manifest.MethodExecutionOperation:
			if success && terminalCause == nil {
				if completeOnReturn {
					sink, _ := lease.snapshotExecution()
					if sink != nil {
						return sink.Complete(terminalCtx)
					}
				}
				lease.detachParent()
				return nil
			}
			if sink, _ := lease.snapshotExecution(); sink != nil {
				if err := sink.terminateUnchecked(terminalCtx, executionFailureCode(binding, terminalCause), terminalCause); err != nil {
					if success {
						return errors.Join(terminalCause, err)
					}
					return err
				}
			}
			lease.finish()
			if success {
				return terminalCause
			}
			return nil
		case manifest.MethodExecutionSubscription:
			lease.markDispatchComplete()
			if success && terminalCause == nil {
				if sink, _ := lease.snapshotExecution(); sink != nil {
					if sink.isTerminal() {
						lease.finish()
						return nil
					}
					if completeOnReturn {
						return sink.finishWithStatus(terminalCtx, execution.StatusCompleted, "", "")
					}
				}
				lease.detachParent()
				return nil
			}
			if sink, _ := lease.snapshotExecution(); sink != nil {
				if err := sink.failCauseUnchecked(terminalCtx, executionFailureCode(binding, terminalCause), terminalCause); err != nil {
					if success {
						return errors.Join(terminalCause, err)
					}
					return err
				}
			}
			lease.finish()
			if success {
				return terminalCause
			}
			return nil
		}
		return nil
	}
	return capability.Invocation{Execution: executionContext, Arguments: arguments}, lease.ctx, finish, nil
}

func validateExecutionBindingShape(binding capability.ExecutionBinding) error {
	if strings.TrimSpace(string(binding.RouteKind)) == "" {
		return errors.New("execution route_kind is required")
	}
	switch binding.RouteKind {
	case capability.RouteCapability:
		if binding.Contract == nil {
			return errors.New("capability execution contract is required")
		}
	case capability.RouteWorker, capability.RouteCoreAction:
		if binding.Contract != nil {
			return errors.New("non-capability execution must not contain a capability contract")
		}
	default:
		return fmt.Errorf("execution route_kind %q is invalid", binding.RouteKind)
	}
	if binding.Permissions.Required == nil || binding.Permissions.Granted == nil {
		return errors.New("execution permission evidence must use arrays")
	}
	return nil
}

func executionStartedAuditDetails(binding capability.ExecutionBinding, executionID string) map[string]any {
	details := map[string]any{
		"execution_id":             executionID,
		"route_kind":               binding.RouteKind,
		"invocation_id":            binding.InvocationID,
		"audit_correlation_id":     binding.AuditCorrelationID,
		"target_descriptor_sha256": binding.TargetDescriptorSHA256,
	}
	if binding.Contract != nil {
		details["capability_contract_artifact"] = binding.Contract.ArtifactSHA256
	}
	return details
}

func (h *Host) reconcilePendingExecutionSetups(ctx context.Context, pluginInstanceID string) error {
	leases := h.executions.pendingSetupRollbacks(pluginInstanceID)
	var result error
	for _, lease := range leases {
		sink, _ := lease.snapshotExecution()
		if sink == nil {
			lease.finish()
			continue
		}
		err := sink.failCauseUnchecked(ctx, capability.ExecutionFailurePlatformFailed, lease.setupRollbackCause())
		if err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (h *Host) reconcileDurableExecutionStates(ctx context.Context) error {
	if h.controlStore == nil {
		return ErrControlStoreRequired
	}
	if err := h.reconcileCommittedExternalInstallActivations(ctx); err != nil {
		return err
	}
	if err := h.reconcileCommittedReleaseInstallActivations(ctx); err != nil {
		return err
	}
	result, err := h.controlStore.Executions().ReconcileOrphans(ctx, time.Now().UTC())
	if err != nil {
		return err
	}
	for _, record := range result.Records {
		if auditErr := h.recordSecurityEvent(ctx, AuditEvent{
			Type: "plugin.execution.reconciled", PluginInstanceID: record.PluginInstanceID,
			Details: map[string]any{"execution_id": record.ID, "status": record.Status},
		}); auditErr != nil {
			return mutation.Unknown(auditErr)
		}
	}
	return nil
}

func (h *Host) pruneTerminalExecutionRecords(ctx context.Context, now time.Time) error {
	if h.controlStore == nil {
		return ErrControlStoreRequired
	}
	_, err := h.controlStore.Executions().PruneTerminal(ctx, controlstore.ExecutionPruneRequest{
		Before: now.Add(-executionTerminalRetention), Limit: executionPruneLimit,
		MaxTerminalRecordsPerPlugin: executionMaxTerminalRecordsPerPlugin,
	})
	return err
}

func (h *Host) validateExecutionBinding(ctx context.Context, binding capability.ExecutionBinding) error {
	record, err := h.getPluginRecord(ctx, binding.PluginInstanceID)
	if err != nil {
		return capability.ErrExecutionRevoked
	}
	if err := h.canRun(ctx, record); err != nil {
		return capability.ErrExecutionRevoked
	}
	authorization, err := h.authorizePlugin(ctx, registry.AuthorizeRequest{
		PluginInstanceID: binding.PluginInstanceID,
		Method:           binding.Method,
		PermissionIDs:    binding.Permissions.Required,
		Expected: registry.AuthorizationRevisions{
			PolicyRevision:     binding.Revision.PolicyRevision,
			ManagementRevision: binding.Revision.ManagementRevision,
			RevokeEpoch:        binding.Revision.RevokeEpoch,
		},
	})
	if err != nil {
		return capability.ErrExecutionRevoked
	}
	state := authorization.State
	if state.EnableState != registry.EnableEnabled || !registry.RunnableAuthorizationState(state) ||
		state.ActiveFingerprint != binding.ActiveFingerprint || state.PluginVersion != binding.PluginVersion ||
		state.Revisions.PolicyRevision != binding.Revision.PolicyRevision || state.Revisions.ManagementRevision != binding.Revision.ManagementRevision ||
		state.Revisions.RevokeEpoch != binding.Revision.RevokeEpoch {
		return capability.ErrExecutionRevoked
	}
	if err := authorizationDecisionError(authorization, binding.Method); err != nil {
		return err
	}
	if !binding.Quota.ExpiresAt.IsZero() && !time.Now().UTC().Before(binding.Quota.ExpiresAt) {
		return capability.ErrExecutionRevoked
	}
	return nil
}

func canonicalDescriptorHash(target capability.TargetDescriptor) (string, error) {
	raw, err := json.Marshal(target)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func deepCloneParams(params map[string]any) (map[string]any, error) {
	if params == nil {
		return map[string]any{}, nil
	}
	return jsonvalue.CloneCanonicalMap(params)
}

func newCapabilityID(prefix string) (string, error) {
	raw := make([]byte, 24)
	if _, err := randRead(raw); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

var randRead = func(raw []byte) (int, error) {
	return cryptoRandRead(raw)
}

func cryptoRandRead(raw []byte) (int, error) {
	return rand.Read(raw)
}

func contractMethod(contract capabilitycontract.Contract, targetMethod string) (capabilitycontract.Method, bool) {
	for _, method := range contract.Methods {
		if method.Name == targetMethod {
			return method, true
		}
	}
	return capabilitycontract.Method{}, false
}

func manifestBinding(plugin manifest.Manifest, bindingID string) (manifest.CapabilityBinding, bool) {
	for _, binding := range plugin.CapabilityBindings {
		if binding.BindingID == bindingID {
			return binding, true
		}
	}
	return manifest.CapabilityBinding{}, false
}

const (
	executionFailedReason   = capability.ExecutionFailureMessage
	executionCanceledReason = "operation canceled"
)

func (h *Host) reportExecutionFailure(ctx context.Context, binding capability.ExecutionBinding, code capability.ExecutionFailureCode, cause error) {
	if h == nil || !code.Valid() || cause == nil {
		return
	}
	details := observability.DiagnosticDetails{
		InvocationID: binding.InvocationID,
		Method:       binding.Method,
		FailureCode:  string(code),
	}
	if binding.ExecutionID != "" {
		details.ExecutionID = binding.ExecutionID
	}
	h.diagnostic(ctx, observability.DiagnosticEvent{
		Type:                 "plugin.execution.failed",
		Severity:             observability.DiagnosticSeverityWarning,
		Message:              executionFailedReason,
		PluginID:             binding.PluginID,
		PluginInstanceID:     binding.PluginInstanceID,
		SurfaceInstanceID:    binding.SurfaceInstanceID,
		ActiveFingerprint:    binding.ActiveFingerprint,
		OwnerSessionHash:     binding.OwnerSessionHash,
		OwnerUserHash:        binding.OwnerUserHash,
		OwnerEnvHash:         binding.OwnerEnvHash,
		SessionChannelIDHash: binding.SessionChannelIDHash,
		CorrelationID:        binding.AuditCorrelationID,
		MutationOutcome:      mutation.ForError(cause),
		Details:              details,
		Failure: observability.FailureFromError(
			observability.FailureAction,
			observability.FailureComponentExecution,
			observability.FailureOperationExecutionFail,
			cause,
		),
	})
}

type executionLeaseRegistry struct {
	mu                         sync.Mutex
	leases                     map[string]*executionLease
	leasesByPlugin             map[string]map[string]*executionLease
	leasesBySession            map[sessionctx.SessionScope]map[string]*executionLease
	executions                 map[string]*executionLease
	activeByQuotaKey           map[executionQuotaKey]int
	setupRollbacks             map[string]*executionLease
	pluginGates                map[string]*executionPluginGate
	terminalMaintenanceRunning bool
	terminalMaintenanceNext    time.Time
	sessionCancelScanned       uint64
}

const terminalExecutionMaintenanceInterval = time.Minute

const (
	executionPruneLimit                  = 500
	executionMaxTerminalRecordsPerPlugin = 1000
	executionTerminalRetention           = 7 * 24 * time.Hour
)

type executionQuotaKey struct {
	pluginInstanceID string
	capabilityID     string
	method           string
}

type executionPluginGate struct {
	mu   sync.RWMutex
	refs int
}

type executionLease struct {
	registry         *executionLeaseRegistry
	binding          capability.ExecutionBinding
	ctx              context.Context
	cancel           context.CancelCauseFunc
	done             chan struct{}
	cancelled        chan struct{}
	mu               sync.Mutex
	eventMu          sync.Mutex
	once             sync.Once
	cancelOnce       sync.Once
	cancelAckOnce    sync.Once
	timer            *time.Timer
	cancelAckTimer   *time.Timer
	parentStop       func() bool
	execution        *hostExecutionSink
	cancelDispatch   executionCancelDispatch
	dispatchComplete bool
	setupRollback    error
	validateBinding  func(context.Context) error
}

type executionCancelDispatch func(context.Context, capability.ExecutionCancellation) error

func newExecutionLeaseRegistry() *executionLeaseRegistry {
	return &executionLeaseRegistry{
		leases:           map[string]*executionLease{},
		leasesByPlugin:   map[string]map[string]*executionLease{},
		leasesBySession:  map[sessionctx.SessionScope]map[string]*executionLease{},
		executions:       map[string]*executionLease{},
		activeByQuotaKey: map[executionQuotaKey]int{},
		setupRollbacks:   map[string]*executionLease{},
		pluginGates:      map[string]*executionPluginGate{},
	}
}

func (r *executionLeaseRegistry) beginTerminalMaintenance(now time.Time) bool {
	if r == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.terminalMaintenanceRunning || (!r.terminalMaintenanceNext.IsZero() && now.Before(r.terminalMaintenanceNext)) {
		return false
	}
	r.terminalMaintenanceRunning = true
	r.terminalMaintenanceNext = now.Add(terminalExecutionMaintenanceInterval)
	return true
}

func (r *executionLeaseRegistry) finishTerminalMaintenance() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.terminalMaintenanceRunning = false
	r.mu.Unlock()
}

func (r *executionLeaseRegistry) start(parent context.Context, binding capability.ExecutionBinding, validate func(context.Context) error) (*executionLease, error) {
	releasePlugin := r.lockPlugin(binding.PluginInstanceID, false)
	defer releasePlugin()
	if err := validate(parent); err != nil {
		return nil, err
	}
	quotaKey := executionQuotaKeyFor(binding)
	r.mu.Lock()
	defer r.mu.Unlock()
	if binding.Quota.MaxConcurrent > 0 {
		if r.activeByQuotaKey[quotaKey] >= binding.Quota.MaxConcurrent {
			return nil, capability.ErrQuotaExceeded
		}
	}
	base := parent
	async := binding.Execution == string(manifest.MethodExecutionOperation) || binding.Execution == string(manifest.MethodExecutionSubscription)
	if async {
		base = context.WithoutCancel(parent)
	}
	ctx, cancel := context.WithCancelCause(base)
	lease := &executionLease{
		registry:        r,
		binding:         binding,
		ctx:             ctx,
		cancel:          cancel,
		done:            make(chan struct{}),
		cancelled:       make(chan struct{}),
		validateBinding: validate,
	}
	if async {
		stop := context.AfterFunc(parent, func() {
			lease.requestCancel(context.Cause(parent))
		})
		lease.setParentStop(stop)
	}
	r.leases[binding.InvocationID] = lease
	pluginLeases := r.leasesByPlugin[binding.PluginInstanceID]
	if pluginLeases == nil {
		pluginLeases = map[string]*executionLease{}
		r.leasesByPlugin[binding.PluginInstanceID] = pluginLeases
	}
	pluginLeases[binding.InvocationID] = lease
	if scope, ok := executionBindingSessionScope(binding); ok {
		sessionLeases := r.leasesBySession[scope]
		if sessionLeases == nil {
			sessionLeases = map[string]*executionLease{}
			r.leasesBySession[scope] = sessionLeases
		}
		sessionLeases[binding.InvocationID] = lease
	}
	r.activeByQuotaKey[quotaKey]++
	return lease, nil
}

func (r *executionLeaseRegistry) cancelSession(scope sessionctx.SessionScope, cause error) []*executionLease {
	leasing := r.sessionLeases(scope)
	for _, lease := range leasing {
		lease.requestCancel(cause)
	}
	return leasing
}

func (r *executionLeaseRegistry) sessionLeases(scope sessionctx.SessionScope) []*executionLease {
	if r == nil || scope.Validate() != nil {
		return nil
	}
	r.mu.Lock()
	sessionLeases := r.leasesBySession[scope]
	r.sessionCancelScanned = uint64(len(sessionLeases))
	leasing := make([]*executionLease, 0, len(sessionLeases))
	for _, lease := range sessionLeases {
		leasing = append(leasing, lease)
	}
	r.mu.Unlock()
	return leasing
}

func (r *executionLeaseRegistry) cancelPlugin(pluginInstanceID string, cause error) []*executionLease {
	releasePlugin := r.lockPlugin(pluginInstanceID, true)
	defer releasePlugin()
	r.mu.Lock()
	pluginLeases := r.leasesByPlugin[pluginInstanceID]
	leasing := make([]*executionLease, 0, len(pluginLeases))
	for _, lease := range pluginLeases {
		leasing = append(leasing, lease)
	}
	r.mu.Unlock()
	for _, lease := range leasing {
		lease.requestCancel(cause)
	}
	return leasing
}

func (r *executionLeaseRegistry) cancelAll(cause error) []*executionLease {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	leasing := make([]*executionLease, 0, len(r.leases))
	for _, lease := range r.leases {
		leasing = append(leasing, lease)
	}
	r.mu.Unlock()
	for _, lease := range leasing {
		lease.requestCancel(cause)
	}
	return leasing
}

func (r *executionLeaseRegistry) finishAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	leases := make([]*executionLease, 0, len(r.leases))
	for _, lease := range r.leases {
		leases = append(leases, lease)
	}
	r.mu.Unlock()
	for _, lease := range leases {
		lease.finish()
	}
}

func reconcileRevokedExecutions(ctx context.Context, leases []*executionLease, cause error) {
	for _, lease := range leases {
		sink, _ := lease.snapshotExecution()
		var err error
		if sink != nil {
			err = sink.terminateUnchecked(ctx, capability.ExecutionFailurePlatformFailed, cause)
		}
		if err != nil {
			lease.markSetupRollbackPending(cause)
		}
	}
}

func (r *executionLeaseRegistry) cancelOperation(ctx context.Context, req capability.ExecutionCancellation, cause error) (bool, error) {
	r.mu.Lock()
	matched := r.executions[strings.TrimSpace(req.ExecutionID)]
	r.mu.Unlock()
	if matched == nil {
		return false, nil
	}
	binding, err := capability.CloneExecutionBinding(matched.binding)
	if err != nil {
		return true, err
	}
	req.Execution = capability.ExecutionContext{ExecutionBinding: binding}
	req.ExecutionID = binding.ExecutionID
	matched.requestCancel(cause)
	sink, dispatch := matched.snapshotExecution()
	if sink != nil {
		matched.armCancelAckTimeout(sink.host, sink.ackTimeout)
	}
	if dispatch != nil {
		return true, dispatch(ctx, req)
	}
	return true, nil
}

func (r *executionLeaseRegistry) executionSink(executionID string) (*hostExecutionSink, error) {
	if r == nil || strings.TrimSpace(executionID) == "" {
		return nil, capability.ErrExecutionRevoked
	}
	r.mu.Lock()
	lease := r.executions[strings.TrimSpace(executionID)]
	r.mu.Unlock()
	if lease == nil {
		return nil, capability.ErrExecutionRevoked
	}
	sink, _ := lease.snapshotExecution()
	if sink == nil {
		return nil, capability.ErrExecutionRevoked
	}
	return sink, nil
}

func executionQuotaKeyFor(binding capability.ExecutionBinding) executionQuotaKey {
	return executionQuotaKey{
		pluginInstanceID: binding.PluginInstanceID,
		capabilityID:     binding.CapabilityID,
		method:           binding.Method,
	}
}

func executionBindingSessionScope(binding capability.ExecutionBinding) (sessionctx.SessionScope, bool) {
	scope := sessionctx.SessionScope{
		OwnerSessionHash: binding.OwnerSessionHash, OwnerUserHash: binding.OwnerUserHash,
		OwnerEnvHash: binding.OwnerEnvHash, SessionChannelIDHash: binding.SessionChannelIDHash,
	}
	return scope, scope.Validate() == nil
}

func (r *executionLeaseRegistry) lockPlugin(pluginInstanceID string, write bool) func() {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	r.mu.Lock()
	gate := r.pluginGates[pluginInstanceID]
	if gate == nil {
		gate = &executionPluginGate{}
		r.pluginGates[pluginInstanceID] = gate
	}
	gate.refs++
	r.mu.Unlock()
	if write {
		gate.mu.Lock()
	} else {
		gate.mu.RLock()
	}
	return func() {
		if write {
			gate.mu.Unlock()
		} else {
			gate.mu.RUnlock()
		}
		r.mu.Lock()
		gate.refs--
		if gate.refs == 0 && r.pluginGates[pluginInstanceID] == gate {
			delete(r.pluginGates, pluginInstanceID)
		}
		r.mu.Unlock()
	}
}

func (r *executionLeaseRegistry) indexExecution(lease *executionLease, sink *hostExecutionSink) {
	if r == nil || lease == nil || sink == nil {
		return
	}
	r.mu.Lock()
	if r.leases[lease.binding.InvocationID] == lease {
		r.executions[sink.executionID] = lease
	}
	r.mu.Unlock()
}

func (l *executionLease) validate(ctx context.Context) error {
	select {
	case <-l.done:
		return capability.ErrExecutionRevoked
	default:
	}
	if err := context.Cause(l.ctx); err != nil {
		return capability.ErrExecutionRevoked
	}
	return l.validateBinding(ctx)
}

func (l *executionLease) requestCancel(cause error) {
	if cause == nil {
		cause = capability.ErrExecutionRevoked
	}
	l.cancelOnce.Do(func() {
		close(l.cancelled)
		l.cancel(cause)
	})
}

func (l *executionLease) finish() bool {
	finished := false
	l.once.Do(func() {
		finished = true
		l.mu.Lock()
		timer := l.timer
		l.timer = nil
		cancelAckTimer := l.cancelAckTimer
		l.cancelAckTimer = nil
		parentStop := l.parentStop
		l.parentStop = nil
		sink := l.execution
		l.mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		if cancelAckTimer != nil {
			cancelAckTimer.Stop()
		}
		if parentStop != nil {
			parentStop()
		}
		l.cancel(nil)
		close(l.done)
		l.registry.mu.Lock()
		if l.registry.leases[l.binding.InvocationID] == l {
			delete(l.registry.leases, l.binding.InvocationID)
			pluginLeases := l.registry.leasesByPlugin[l.binding.PluginInstanceID]
			delete(pluginLeases, l.binding.InvocationID)
			if len(pluginLeases) == 0 {
				delete(l.registry.leasesByPlugin, l.binding.PluginInstanceID)
			}
			if scope, ok := executionBindingSessionScope(l.binding); ok {
				sessionLeases := l.registry.leasesBySession[scope]
				delete(sessionLeases, l.binding.InvocationID)
				if len(sessionLeases) == 0 {
					delete(l.registry.leasesBySession, scope)
				}
			}
			quotaKey := executionQuotaKeyFor(l.binding)
			if active := l.registry.activeByQuotaKey[quotaKey]; active <= 1 {
				delete(l.registry.activeByQuotaKey, quotaKey)
			} else {
				l.registry.activeByQuotaKey[quotaKey] = active - 1
			}
			if sink != nil && l.registry.executions[sink.executionID] == l {
				delete(l.registry.executions, sink.executionID)
			}
			delete(l.registry.setupRollbacks, l.binding.InvocationID)
		}
		l.registry.mu.Unlock()
	})
	return finished
}

func (l *executionLease) detachParent() {
	l.mu.Lock()
	parentStop := l.parentStop
	l.parentStop = nil
	l.mu.Unlock()
	if parentStop != nil {
		parentStop()
	}
}

func (l *executionLease) markDispatchComplete() {
	l.mu.Lock()
	l.dispatchComplete = true
	l.mu.Unlock()
}

func (l *executionLease) markSetupRollbackPending(cause error) {
	l.mu.Lock()
	l.setupRollback = cause
	l.registry.mu.Lock()
	if l.registry.leases[l.binding.InvocationID] == l {
		l.registry.setupRollbacks[l.binding.InvocationID] = l
	}
	l.registry.mu.Unlock()
	l.mu.Unlock()
}

func (l *executionLease) setupRollbackCause() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.setupRollback
}

func (l *executionLease) dispatchCompleted() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dispatchComplete
}

func (l *executionLease) armTimeout(host *Host) {
	if host == nil || l.binding.Quota.ExpiresAt.IsZero() {
		return
	}
	delay := time.Until(l.binding.Quota.ExpiresAt)
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	l.mu.Lock()
	select {
	case <-l.done:
		l.mu.Unlock()
		timer.Stop()
		return
	default:
		l.timer = timer
	}
	l.mu.Unlock()
	started := host.startLifecycleJob(func(ctx context.Context) {
		select {
		case <-timer.C:
			l.requestCancel(capability.ErrQuotaExceeded)
			sink, _ := l.snapshotExecution()
			var err error
			if sink != nil {
				err = sink.terminateUnchecked(ctx, capability.ExecutionFailureQuotaExceeded, capability.ErrQuotaExceeded)
			}
			if err != nil {
				host.diagnostic(ctx, observability.DiagnosticEvent{
					Type:                 "plugin.execution.duration_terminal_failed",
					Severity:             observability.DiagnosticSeverityWarning,
					Message:              "duration quota terminal state could not be persisted",
					PluginID:             l.binding.PluginID,
					PluginInstanceID:     l.binding.PluginInstanceID,
					SurfaceInstanceID:    l.binding.SurfaceInstanceID,
					OwnerSessionHash:     l.binding.OwnerSessionHash,
					OwnerUserHash:        l.binding.OwnerUserHash,
					OwnerEnvHash:         l.binding.OwnerEnvHash,
					SessionChannelIDHash: l.binding.SessionChannelIDHash,
					MutationOutcome:      mutation.ForError(err),
					Failure: observability.FailureFromError(
						observability.FailureAdapter,
						observability.FailureComponentExecution,
						observability.FailureOperationExecutionDurationPersist,
						err,
					),
				})
			}
			l.finish()
		case <-l.done:
		case <-ctx.Done():
		}
	})
	if !started {
		timer.Stop()
	}
}

func (l *executionLease) armCancelAckTimeout(host *Host, timeout time.Duration) {
	if host == nil || timeout <= 0 {
		return
	}
	l.cancelAckOnce.Do(func() {
		timer := time.NewTimer(timeout)
		l.mu.Lock()
		select {
		case <-l.done:
			l.mu.Unlock()
			timer.Stop()
			return
		default:
			l.cancelAckTimer = timer
		}
		l.mu.Unlock()
		started := host.startLifecycleJob(func(ctx context.Context) {
			select {
			case <-timer.C:
				sink, _ := l.snapshotExecution()
				var err error
				if sink != nil {
					err = sink.finishWithStatus(ctx, execution.StatusCanceled, "", "cancellation acknowledgement timed out")
				}
				if err != nil {
					l.finish()
				}
			case <-l.done:
			case <-ctx.Done():
			}
		})
		if !started {
			timer.Stop()
		}
	})
}

func (l *executionLease) setExecution(sink *hostExecutionSink, dispatch executionCancelDispatch) {
	l.mu.Lock()
	l.execution = sink
	l.cancelDispatch = dispatch
	l.mu.Unlock()
	l.registry.indexExecution(l, sink)
}

func (l *executionLease) setParentStop(stop func() bool) {
	l.mu.Lock()
	select {
	case <-l.done:
		l.mu.Unlock()
		stop()
		return
	default:
		l.parentStop = stop
		l.mu.Unlock()
	}
}

func (l *executionLease) snapshotExecution() (*hostExecutionSink, executionCancelDispatch) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.execution, l.cancelDispatch
}

func (r *executionLeaseRegistry) pendingSetupRollbacks(pluginInstanceID string) []*executionLease {
	r.mu.Lock()
	leases := make([]*executionLease, 0, len(r.setupRollbacks))
	for _, lease := range r.setupRollbacks {
		if lease.binding.PluginInstanceID == pluginInstanceID {
			leases = append(leases, lease)
		}
	}
	r.mu.Unlock()
	return leases
}

type hostExecutionSink struct {
	host              *Host
	lease             *executionLease
	executionID       string
	ackTimeout        time.Duration
	subscription      bool
	maxBytes          int64
	mu                sync.Mutex
	written           int64
	terminalIntent    *executionTerminalIntent
	terminalCommitted bool
	eventTypeName     string
	eventSchema       map[string]any
}

var errExecutionTerminalConflict = errors.New("execution terminal state conflicts with the first terminal intent")

type executionTerminalIntent struct {
	status      string
	failureCode capability.ExecutionFailureCode
	reason      string
}

func (s *hostExecutionSink) ID() string { return s.executionID }

func (s *hostExecutionSink) ReportProgress(ctx context.Context, progress capability.OperationProgress) error {
	if err := s.lease.validate(ctx); err != nil {
		return err
	}
	payload := map[string]any{"revision": progress.Revision, "phase": progress.Phase}
	if progress.CompletedUnits != nil {
		payload["completed_units"] = *progress.CompletedUnits
	}
	if progress.TotalUnits != nil {
		payload["total_units"] = *progress.TotalUnits
	}
	if progress.Unit != "" {
		payload["unit"] = progress.Unit
	}
	return s.appendEvent(ctx, execution.EventProgress, payload, nil)
}

func (s *hostExecutionSink) Append(ctx context.Context, event any) error {
	if !s.subscription {
		return execution.ErrInvalidTransition
	}
	if err := s.lease.validate(ctx); err != nil {
		return err
	}
	return s.appendSubscriptionEvent(ctx, event)
}

func (s *hostExecutionSink) Complete(ctx context.Context) error {
	if err := s.lease.validate(ctx); err != nil {
		if terminalErr, handled := s.terminalResult(execution.StatusCompleted, "", ""); handled {
			return terminalErr
		}
		return err
	}
	return s.finishWithStatus(ctx, execution.StatusCompleted, "", "")
}

func (s *hostExecutionSink) Close(ctx context.Context) error { return s.Complete(ctx) }

func (s *hostExecutionSink) Cancel(ctx context.Context, reason string) error {
	select {
	case <-s.lease.done:
		if terminalErr, handled := s.terminalResult(execution.StatusCanceled, "", reason); handled {
			return terminalErr
		}
		return capability.ErrExecutionRevoked
	default:
	}
	current, err := s.host.controlStore.Executions().Get(ctx, s.executionID)
	if err != nil {
		return err
	}
	if current.Status != execution.StatusCancelRequested {
		return execution.ErrInvalidTransition
	}
	return s.finishWithStatus(ctx, execution.StatusCanceled, "", reason)
}

func (s *hostExecutionSink) Fail(ctx context.Context, code capability.ExecutionFailureCode, cause error) error {
	if err := validateExecutionFailure(code, cause); err != nil {
		return err
	}
	if err := s.lease.validate(ctx); err != nil {
		if terminalErr, handled := s.terminalResult(execution.StatusFailed, code, ""); handled {
			return terminalErr
		}
		return err
	}
	return s.failCauseUnchecked(ctx, code, cause)
}

func (s *hostExecutionSink) CancelRequested() <-chan struct{} { return s.lease.cancelled }

func (s *hostExecutionSink) failUnchecked(ctx context.Context, code capability.ExecutionFailureCode) error {
	return s.finishWithStatus(ctx, execution.StatusFailed, code, "")
}

func (s *hostExecutionSink) failCauseUnchecked(ctx context.Context, code capability.ExecutionFailureCode, cause error) error {
	if err := validateExecutionFailure(code, cause); err != nil {
		return err
	}
	s.reportFailureCause(ctx, code, cause)
	return s.failUnchecked(ctx, code)
}

func (s *hostExecutionSink) terminateUnchecked(ctx context.Context, code capability.ExecutionFailureCode, cause error) error {
	if err := validateExecutionFailure(code, cause); err != nil {
		return err
	}
	current, err := s.host.controlStore.Executions().Get(ctx, s.executionID)
	if err != nil {
		return err
	}
	if executionTerminal(current.Status) {
		s.lease.finish()
		return nil
	}
	status := execution.StatusFailed
	failureCode := string(code)
	var publicError *execution.PublicError
	if current.Status == execution.StatusCancelRequested {
		status = execution.StatusCanceled
		failureCode = ""
	} else {
		s.reportFailureCause(ctx, code, cause)
		publicError = &execution.PublicError{Code: string(code), Message: executionFailedReason}
	}
	err = s.finishExecution(ctx, status, failureCode, publicError)
	if err == nil && s.lease.finish() {
		if auditErr := s.recordFinished(ctx, status); auditErr != nil {
			err = mutation.Unknown(auditErr)
		}
	}
	return err
}

func (s *hostExecutionSink) appendSubscriptionEvent(ctx context.Context, event any) error {
	if s.eventSchema != nil {
		if err := capabilitycontract.ValidateValue(s.eventSchema, event); err != nil {
			return fmt.Errorf("stream event does not match its signed contract: %w", err)
		}
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode stream event: %w", err)
	}
	kind := s.eventTypeName
	if kind == "" {
		kind = "event"
	}
	return s.appendEncoded(ctx, kind, data)
}

func (s *hostExecutionSink) appendEncoded(ctx context.Context, kind string, data []byte) error {
	if !s.subscription {
		return execution.ErrInvalidTransition
	}
	s.mu.Lock()
	if s.terminalIntent != nil {
		s.mu.Unlock()
		return execution.ErrTerminal
	}
	next := s.written + int64(len(data))
	if s.maxBytes > 0 && next > s.maxBytes {
		s.mu.Unlock()
		return capability.ErrQuotaExceeded
	}
	s.written = next
	s.mu.Unlock()
	err := s.appendEvent(ctx, execution.EventData, map[string]any{
		"event_type": kind,
		"data":       base64.StdEncoding.EncodeToString(data),
	}, nil)
	if err != nil {
		s.mu.Lock()
		s.written -= int64(len(data))
		if s.written < 0 {
			s.written = 0
		}
		s.mu.Unlock()
	}
	return err
}

func (s *hostExecutionSink) appendEvent(ctx context.Context, kind string, payload map[string]any, publicError *execution.PublicError) error {
	s.lease.eventMu.Lock()
	defer s.lease.eventMu.Unlock()
	current, err := s.host.controlStore.Executions().Get(ctx, s.executionID)
	if err != nil {
		return err
	}
	event, err := execution.NewEvent(current, current.Cursor+1, kind, payload)
	if err != nil {
		return err
	}
	event.Error = publicError
	return s.host.controlStore.Executions().Append(ctx, event)
}

func (s *hostExecutionSink) finishExecution(ctx context.Context, status, failureCode string, publicError *execution.PublicError) error {
	s.lease.eventMu.Lock()
	defer s.lease.eventMu.Unlock()
	current, err := s.host.controlStore.Executions().Get(ctx, s.executionID)
	if err != nil {
		return err
	}
	if executionTerminal(current.Status) {
		if current.Status == status && current.FailureCode == failureCode {
			return nil
		}
		return execution.ErrInvalidTransition
	}
	event, err := execution.NewEvent(current, current.Cursor+1, execution.EventTerminal, map[string]any{"status": status})
	if err != nil {
		return err
	}
	event.Error = publicError
	return s.host.controlStore.Executions().Finish(ctx, s.executionID, status, failureCode, event, time.Now().UTC())
}

func (s *hostExecutionSink) recordFinished(ctx context.Context, status string) error {
	return s.host.recordSecurityEvent(ctx, AuditEvent{
		Type: "plugin.execution.finished", PluginID: s.lease.binding.PluginID,
		PluginInstanceID: s.lease.binding.PluginInstanceID,
		Details:          map[string]any{"execution_id": s.executionID, "status": status},
	})
}

func executionTerminal(status string) bool {
	switch status {
	case execution.StatusCompleted, execution.StatusCanceled, execution.StatusFailed, execution.StatusOrphaned:
		return true
	default:
		return false
	}
}

func (s *hostExecutionSink) reportFailureCause(ctx context.Context, code capability.ExecutionFailureCode, cause error) {
	if s == nil || s.host == nil || s.lease == nil || cause == nil {
		return
	}
	s.host.reportExecutionFailure(ctx, s.lease.binding, code, cause)
}

func (s *hostExecutionSink) terminalResult(status string, failureCode capability.ExecutionFailureCode, reason string) (error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminalIntent == nil {
		return nil, false
	}
	requested := executionTerminalIntent{status: status, failureCode: failureCode, reason: reason}
	if *s.terminalIntent != requested {
		return fmt.Errorf("%w: execution %s already selected %s", errExecutionTerminalConflict, s.executionID, s.terminalIntent.status), true
	}
	if s.terminalCommitted {
		return nil, true
	}
	return nil, false
}

func (s *hostExecutionSink) finishWithStatus(ctx context.Context, status string, failureCode capability.ExecutionFailureCode, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	requested := executionTerminalIntent{status: status, failureCode: failureCode, reason: reason}
	if s.terminalIntent != nil && *s.terminalIntent != requested {
		return fmt.Errorf("%w: execution %s already selected %s", errExecutionTerminalConflict, s.executionID, s.terminalIntent.status)
	}
	if s.terminalIntent == nil {
		s.terminalIntent = &requested
	}
	if s.terminalCommitted {
		return nil
	}
	var publicError *execution.PublicError
	switch status {
	case execution.StatusCompleted, execution.StatusCanceled:
	case execution.StatusFailed:
		publicError = &execution.PublicError{Code: string(failureCode), Message: executionFailedReason}
	default:
		return execution.ErrInvalidTransition
	}
	if err := s.finishExecution(ctx, status, string(failureCode), publicError); err != nil {
		s.lease.markSetupRollbackPending(err)
		return err
	}
	s.terminalCommitted = true
	if !s.subscription || s.lease.dispatchCompleted() {
		s.lease.finish()
	}
	if auditErr := s.recordFinished(ctx, status); auditErr != nil {
		return mutation.Unknown(auditErr)
	}
	return nil
}

func validateExecutionFailure(code capability.ExecutionFailureCode, cause error) error {
	if !code.Valid() || cause == nil {
		return capability.ErrInvalidExecutionFailure
	}
	return nil
}

func executionFailureCode(binding capability.ExecutionBinding, cause error) capability.ExecutionFailureCode {
	switch {
	case errors.Is(cause, capability.ErrQuotaExceeded):
		return capability.ExecutionFailureQuotaExceeded
	case errors.Is(cause, ErrMethodResponseContract), errors.Is(cause, ErrMethodRequestContract):
		return capability.ExecutionFailureContractInvalid
	case binding.RouteKind == capability.RouteWorker:
		return capability.ExecutionFailureRuntimeFailed
	case binding.RouteKind == capability.RouteCapability, binding.RouteKind == capability.RouteCoreAction:
		return capability.ExecutionFailureAdapterFailed
	default:
		return capability.ExecutionFailurePlatformFailed
	}
}

func (s *hostExecutionSink) isTerminal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalCommitted
}

func operationCancelDispatchFor(adapter any) executionCancelDispatch {
	canceler, ok := adapter.(capability.ExecutionCanceler)
	if !ok {
		return nil
	}
	return canceler.CancelExecution
}

type hostRuntimeStreamSink struct {
	executions *executionLeaseRegistry
}

func (s hostRuntimeStreamSink) AppendRuntimeStream(ctx context.Context, streamID, kind string, data []byte) error {
	sink, err := s.executions.executionSink(streamID)
	if err != nil {
		return err
	}
	if err := sink.lease.validate(ctx); err != nil {
		return err
	}
	if sink.eventSchema == nil {
		return sink.appendEncoded(ctx, kind, data)
	}
	if kind != sink.eventTypeName {
		return errors.New("runtime stream event type does not match its signed contract")
	}
	var event any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return fmt.Errorf("decode runtime stream event: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("runtime stream event must contain exactly one JSON value")
	}
	return sink.appendSubscriptionEvent(ctx, event)
}

func (s hostRuntimeStreamSink) CloseRuntimeStream(ctx context.Context, streamID string) error {
	sink, err := s.executions.executionSink(streamID)
	if err != nil {
		return err
	}
	return sink.Close(ctx)
}

func (s hostRuntimeStreamSink) FailRuntimeStream(ctx context.Context, streamID string, code capability.ExecutionFailureCode, cause error) error {
	sink, err := s.executions.executionSink(streamID)
	if err != nil {
		return err
	}
	return sink.Fail(ctx, code, cause)
}
