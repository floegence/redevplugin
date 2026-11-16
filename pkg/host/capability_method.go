package host

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// CapabilityMethodRequest targets a native method in the originating plugin.
// The trusted capability adapter must also enforce its own declared method
// selection. A plugin must never supply the retained ExecutionBinding itself.
type CapabilityMethodRequest struct {
	Method         string
	Params         map[string]any
	ConfirmationID string
}

// DescribeCapabilityMethods resolves selected native methods from the current
// installed manifest. Schemas are copied, so callers cannot mutate platform
// state. Discovery conveys no execution grant and never returns sibling plugins.
func (h *Host) DescribeCapabilityMethods(ctx context.Context, source capability.ExecutionBinding, names []string) ([]manifest.MethodSpec, error) {
	if len(names) > 128 {
		return nil, ErrMethodRequestContract
	}
	scope, err := requireUserSession(ctx)
	if err != nil {
		return nil, err
	}
	if !scope.CanRead {
		return nil, ErrActionDenied
	}
	if !sameSurfaceOwner(scope, sessionctx.Context{OwnerSessionHash: source.OwnerSessionHash, OwnerUserHash: source.OwnerUserHash, OwnerEnvHash: source.OwnerEnvHash, SessionChannelIDHash: source.SessionChannelIDHash}) {
		return nil, capability.ErrExecutionRevoked
	}
	if err = h.ValidateCapabilityContinuation(ctx, source); err != nil {
		return nil, err
	}
	record, err := h.getPluginRecord(ctx, source.PluginInstanceID)
	if err != nil {
		return nil, err
	}
	methods := make([]manifest.MethodSpec, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		method, ok := manifestMethod(record.Manifest, name)
		if !ok || seen[name] || record.Manifest.IsDataUpgradeMethod(name) || method.PreflightOnly || (method.Route.Kind != manifest.MethodRouteWorker && method.Route.Kind != manifest.MethodRouteSurface) {
			return nil, ErrMethodRequestContract
		}
		seen[name] = true
		methods = append(methods, method)
	}
	raw, err := json.Marshal(methods)
	if err != nil {
		return nil, err
	}
	var cloned []manifest.MethodSpec
	if err = json.Unmarshal(raw, &cloned); err != nil {
		return nil, err
	}
	if err = h.ValidateCapabilityContinuation(ctx, source); err != nil {
		return nil, err
	}
	return cloned, nil
}

// InvokeCapabilityMethod continues a trusted capability invocation into a
// native plugin method. It does not mint a gateway token, replace a session,
// bypass confirmation, or dispatch into another capability recursively.
func (h *Host) InvokeCapabilityMethod(ctx context.Context, source capability.ExecutionBinding, input CapabilityMethodRequest) (result CallMethodResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	defer func() { resultErr = finalizeRPCError(ctx, resultErr) }()
	ctx, call, req, release, err := h.resolveCapabilityMethodContinuation(ctx, source, input)
	if err != nil {
		return result, err
	}
	defer release()
	if methodRequiresConfirmation(call.method) && req.ConfirmationID == "" {
		hash, err := methodRequestHash(call.method, req.Params)
		if err != nil {
			return result, err
		}
		return CallMethodResult{ConfirmationRequired: true, RequestHash: hash}, ErrConfirmationRequired
	}
	req, err = h.consumeMethodConfirmation(ctx, call, req)
	if err != nil {
		return result, err
	}
	// Confirmation preflight may do I/O. Revalidate the original authority at
	// dispatch as well as the destination's ordinary execution checks.
	if err = h.ValidateCapabilityContinuation(ctx, source); err != nil {
		return result, err
	}
	result, err = h.dispatchMethod(ctx, call.record, call.method, req)
	if err != nil {
		return result, err
	}
	if err = h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.capability.method.called", PluginID: call.record.PluginID, PluginInstanceID: call.record.PluginInstanceID, Details: map[string]any{"method": req.Method, "invocation_id": source.InvocationID}}); err != nil {
		return result, mutation.Unknown(err)
	}
	return result, nil
}

// PrepareCapabilityMethodConfirmation uses the same request, target, plan and
// single-use intent as a direct plugin method. Hosts present this intent in
// their trusted confirmation UI; a model response cannot approve it.
func (h *Host) PrepareCapabilityMethodConfirmation(ctx context.Context, source capability.ExecutionBinding, input CapabilityMethodRequest) (result PrepareMethodConfirmationResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	defer func() { resultErr = finalizeRPCError(ctx, resultErr) }()
	ctx, call, req, release, err := h.resolveCapabilityMethodContinuation(ctx, source, input)
	if err != nil {
		return result, err
	}
	defer release()
	if source.SurfaceInstanceID == "" {
		return result, ErrConfirmationRequired
	}
	return h.prepareResolvedMethodConfirmation(ctx, call, req)
}

func (h *Host) resolveCapabilityMethodContinuation(ctx context.Context, source capability.ExecutionBinding, input CapabilityMethodRequest) (context.Context, resolvedMethodCall, CallMethodRequest, func(), error) {
	var call resolvedMethodCall
	var req CallMethodRequest
	noop := func() {}
	scope, err := requireUserSession(ctx)
	if err != nil {
		return ctx, call, req, noop, err
	}
	if !sameSurfaceOwner(scope, sessionctx.Context{OwnerSessionHash: source.OwnerSessionHash, OwnerUserHash: source.OwnerUserHash, OwnerEnvHash: source.OwnerEnvHash, SessionChannelIDHash: source.SessionChannelIDHash}) {
		return ctx, call, req, noop, capability.ErrExecutionRevoked
	}
	if err = h.ValidateCapabilityContinuation(ctx, source); err != nil {
		return ctx, call, req, noop, err
	}
	methodName := strings.TrimSpace(input.Method)
	authorization, err := h.authorizeManagementSession(ctx, scope, ManagementActionCallPluginMethod,
		authorizationTarget(ResourceMethod, methodName), authorizationTarget(ResourcePlugin, source.PluginInstanceID), authorizationTarget(ResourceSurface, source.SurfaceInstanceID), authorizationTarget(ResourceBridgeChannel, source.BridgeChannelID))
	if err != nil {
		return ctx, call, req, noop, err
	}
	ctx, release, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return ctx, call, req, noop, err
	}
	fail := func(err error) (context.Context, resolvedMethodCall, CallMethodRequest, func(), error) {
		release()
		return ctx, call, req, noop, err
	}
	call.record, err = h.getPluginRecord(ctx, source.PluginInstanceID)
	if err != nil {
		return fail(err)
	}
	var ok bool
	call.method, ok = manifestMethod(call.record.Manifest, methodName)
	if !ok || call.record.Manifest.IsDataUpgradeMethod(methodName) || call.method.PreflightOnly || (call.method.Route.Kind != manifest.MethodRouteWorker && call.method.Route.Kind != manifest.MethodRouteSurface) {
		return fail(ErrMethodRequestContract)
	}
	if call.method.Effect == manifest.MethodEffectRead {
		if !scope.CanRead {
			return fail(ErrActionDenied)
		}
	} else if !scope.CanWrite || source.Effect != capability.EffectExecute {
		return fail(ErrActionDenied)
	}
	if err = h.authorizeHeadlessMethod(ctx, scope, call.record, call.method, req.Now); err != nil {
		return fail(err)
	}
	permissions, err := h.requiredPermissionsForMethod(call.record, call.method)
	if err != nil {
		return fail(err)
	}
	if err = h.requireCurrentPermissionGrants(ctx, source.PluginInstanceID, permissions); err != nil {
		return fail(err)
	}
	req = CallMethodRequest{PluginInstanceID: source.PluginInstanceID, SurfaceInstanceID: source.SurfaceInstanceID, BridgeChannelID: source.BridgeChannelID, Method: methodName, ConfirmationID: input.ConfirmationID, session: scope}
	req.Params, err = deepCloneParams(input.Params)
	if err != nil {
		return fail(err)
	}
	if err = h.validateMethodRequest(call.method, req.Params); err != nil {
		return fail(err)
	}
	call.revision = bridge.RevisionBinding{PolicyRevision: source.Revision.PolicyRevision, ManagementRevision: source.Revision.ManagementRevision, RevokeEpoch: source.Revision.RevokeEpoch}
	if source.SurfaceInstanceID != "" {
		bound, err := h.surfaceTokens.InspectBoundSurface(bridge.InspectBoundSurfaceRequest{SurfaceInstanceID: source.SurfaceInstanceID, BridgeChannelID: source.BridgeChannelID, OwnerSessionHash: scope.OwnerSessionHash, OwnerUserHash: scope.OwnerUserHash, OwnerEnvHash: scope.OwnerEnvHash, SessionChannelIDHash: scope.SessionChannelIDHash})
		if err != nil {
			return fail(err)
		}
		if bound.PluginInstanceID != source.PluginInstanceID || bound.ActiveFingerprint != source.ActiveFingerprint || bound.Revision != call.revision {
			return fail(capability.ErrExecutionRevoked)
		}
		if err = h.requireSurfaceGeneration(bound.Audience.SurfaceInstanceID, bound.Audience.RuntimeGenerationID, req.Now); err != nil {
			return fail(err)
		}
		call.audience = bound.Audience
	} else if call.method.Route.Kind == manifest.MethodRouteSurface {
		return fail(ErrSurfaceMethodUnavailable)
	}
	if call.method.Route.Kind == manifest.MethodRouteSurface {
		_, bound, err := h.resolveSurfaceMethodTarget(ctx, call.record, call.method, req)
		if err != nil {
			return fail(err)
		}
		if bound.Audience.BridgeChannelID != source.BridgeChannelID {
			return fail(capability.ErrExecutionRevoked)
		}
	}
	req.executionAuthorization.target, req.executionAuthorization.targetHash, err = h.resolveMethodConfirmationTarget(ctx, call.record, call.method, req)
	if err != nil {
		return fail(err)
	}
	if !source.Quota.ExpiresAt.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, source.Quota.ExpiresAt)
		prior := release
		release = func() { cancel(); prior() }
	}
	return ctx, call, req, release, nil
}
