package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

var (
	ErrSurfaceMethodUnavailable = errors.New("application method receiver is unavailable")
	ErrSurfaceMethodConflict    = errors.New("application method receiver changed")
	ErrSurfaceMethodAmbiguous   = errors.New("application method requires an explicit surface target")
	ErrSurfaceMethodFailed      = errors.New("application method did not return a valid result")
)

const maxSurfaceMethodCalls = 32
const maxSurfaceMethodBytes = 1024 * 1024
const surfaceMethodTimeout = 30 * time.Second

// SurfaceMethodsRequest is the parent SDK control plane. The application never
// receives its gateway credential or selects its authenticated owner.
type SurfaceMethodsRequest struct {
	PluginInstanceID  string    `json:"plugin_instance_id"`
	SurfaceInstanceID string    `json:"surface_instance_id"`
	BridgeChannelID   string    `json:"bridge_channel_id"`
	GatewayToken      string    `json:"plugin_gateway_token"`
	Operation         string    `json:"operation"`
	ReceiverID        string    `json:"receiver_id,omitempty"`
	Methods           []string  `json:"methods,omitempty"`
	InvocationID      string    `json:"invocation_id,omitempty"`
	ActiveInvocations []string  `json:"active_invocations,omitempty"`
	Data              any       `json:"data,omitempty"`
	Failed            bool      `json:"failed,omitempty"`
	Now               time.Time `json:"-"`
}

// UnmarshalJSON rejects fields belonging to another operation even when their
// values are empty. The public control plane has one closed operation shape.
func (r *SurfaceMethodsRequest) UnmarshalJSON(raw []byte) error {
	type wire SurfaceMethodsRequest
	var value wire
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	allowed := map[string]bool{"plugin_instance_id": true, "surface_instance_id": true, "bridge_channel_id": true, "plugin_gateway_token": true, "operation": true, "receiver_id": true}
	switch value.Operation {
	case "register", "configure":
		allowed["methods"] = true
	case "claim":
		allowed["active_invocations"] = true
	case "complete":
		allowed["invocation_id"] = true
		allowed["data"] = true
		allowed["failed"] = true
	case "close":
	default:
		return ErrMethodRequestContract
	}
	for key, data := range fields {
		if !allowed[key] || (string(data) == "null" && key != "data") {
			return ErrMethodRequestContract
		}
	}
	if err := validateSurfaceMethodsRequest(SurfaceMethodsRequest(value)); err != nil {
		return err
	}
	*r = SurfaceMethodsRequest(value)
	return nil
}

func validateSurfaceMethodsRequest(req SurfaceMethodsRequest) error {
	if req.PluginInstanceID == "" || req.SurfaceInstanceID == "" || req.BridgeChannelID == "" || req.GatewayToken == "" || (req.Operation != "register" && req.ReceiverID == "") {
		return ErrMethodRequestContract
	}
	if req.Operation != "register" && req.Operation != "configure" && len(req.Methods) != 0 {
		return ErrMethodRequestContract
	}
	if req.Operation != "claim" && len(req.ActiveInvocations) != 0 {
		return ErrMethodRequestContract
	}
	if req.Operation != "complete" && (req.InvocationID != "" || req.Data != nil || req.Failed) {
		return ErrMethodRequestContract
	}
	if req.Operation == "complete" && (req.InvocationID == "" || (req.Failed && req.Data != nil)) {
		return ErrMethodRequestContract
	}
	switch req.Operation {
	case "register", "configure", "claim", "complete", "close":
	default:
		return ErrMethodRequestContract
	}
	if len(req.ActiveInvocations) > maxSurfaceMethodCalls || len(req.Methods) > 128 {
		return ErrMethodRequestContract
	}
	seen := map[string]bool{}
	for _, id := range req.ActiveInvocations {
		if id == "" || seen[id] {
			return ErrMethodRequestContract
		}
		seen[id] = true
	}
	return nil
}

type SurfaceMethodInvocation struct {
	InvocationID string         `json:"invocation_id"`
	Method       string         `json:"method"`
	Params       map[string]any `json:"params"`
	Deadline     time.Time      `json:"deadline"`
}
type SurfaceMethodsResult struct {
	ReceiverID string                   `json:"receiver_id"`
	Invocation *SurfaceMethodInvocation `json:"invocation,omitempty"`
	Cancelled  []string                 `json:"cancelled"`
}
type surfaceMethodReceiver struct {
	mu      sync.Mutex
	id      string
	channel string
	ctx     context.Context
	cancel  context.CancelFunc
	closed  bool
	methods map[string]bool
	calls   map[string]*surfaceMethodCall
	queue   []string
	wake    chan struct{}
}
type surfaceMethodCall struct {
	invocation SurfaceMethodInvocation
	ctx        context.Context
	claimed    bool
	result     chan surfaceMethodResult
}
type surfaceMethodResult struct {
	data       any
	err        error
	dispatched bool
}

func (h *Host) SurfaceMethods(ctx context.Context, req SurfaceMethodsRequest) (response SurfaceMethodsResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	defer func() { resultErr = finalizeRPCError(ctx, resultErr) }()
	authorization, err := h.authorizeManagement(ctx, ManagementActionSurfaceMethods, authorizationTarget(ResourceSurface, req.SurfaceInstanceID), authorizationTarget(ResourcePlugin, req.PluginInstanceID), authorizationTarget(ResourceBridgeChannel, req.BridgeChannelID))
	if err != nil {
		return SurfaceMethodsResult{}, err
	}
	ctx, release, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return SurfaceMethodsResult{}, err
	}
	defer release()
	record, err := h.getPluginRecord(ctx, req.PluginInstanceID)
	if err != nil {
		return SurfaceMethodsResult{}, err
	}
	if err = h.canRun(ctx, record); err != nil {
		return SurfaceMethodsResult{}, err
	}
	session := authorization.session
	token, err := h.surfaceTokens.ValidateSurfaceGatewayToken(bridge.ValidateSurfaceGatewayTokenRequest{GatewayToken: req.GatewayToken, PluginInstanceID: req.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, BridgeChannelID: req.BridgeChannelID, OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash, Revision: bridge.RevisionBinding{PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch}, Now: req.Now})
	if err != nil {
		return SurfaceMethodsResult{}, err
	}
	if err = h.requireSurfaceGeneration(req.SurfaceInstanceID, token.Audience.RuntimeGenerationID, req.Now); err != nil {
		return SurfaceMethodsResult{}, err
	}
	if err := validateSurfaceMethodsRequest(req); err != nil {
		return SurfaceMethodsResult{}, err
	}
	raw, err := json.Marshal(req)
	if err != nil || len(raw) > maxSurfaceMethodBytes {
		return SurfaceMethodsResult{}, ErrMethodRequestContract
	}
	var methods map[string]bool
	if req.Operation == "register" || req.Operation == "configure" {
		methods = map[string]bool{}
		for _, name := range req.Methods {
			method, ok := manifestMethod(record.Manifest, name)
			if !ok || method.Route.Kind != manifest.MethodRouteSurface || method.Route.SurfaceID != token.Audience.SurfaceID || methods[name] {
				return SurfaceMethodsResult{}, ErrMethodRequestContract
			}
			methods[name] = true
		}
	}
	h.webSurfaces.mu.Lock()
	var live *webSurfaceBinding
	for _, candidate := range h.webSurfaces.byOrigin {
		if candidate.request.SurfaceInstanceID == req.SurfaceInstanceID && candidate.pluginInstanceID == req.PluginInstanceID {
			live = candidate
			break
		}
	}
	if live == nil || live.ctx.Err() != nil || !live.gatewayReady {
		h.webSurfaces.mu.Unlock()
		return SurfaceMethodsResult{}, ErrSurfaceMethodUnavailable
	}
	receiver := live.methodReceiver
	if req.Operation == "register" {
		if (receiver == nil && req.ReceiverID != "") || (receiver != nil && receiver.id != req.ReceiverID) {
			h.webSurfaces.mu.Unlock()
			return SurfaceMethodsResult{}, ErrSurfaceMethodConflict
		}
		id, idErr := newCapabilityID("receiver")
		if idErr != nil {
			h.webSurfaces.mu.Unlock()
			return SurfaceMethodsResult{}, idErr
		}
		if receiver != nil {
			receiver.mu.Lock()
			receiver.closed = true
			receiver.cancel()
			receiver.mu.Unlock()
		}
		receiverCtx, cancel := context.WithCancel(live.ctx)
		receiver = &surfaceMethodReceiver{id: id, channel: req.BridgeChannelID, ctx: receiverCtx, cancel: cancel, methods: methods, calls: map[string]*surfaceMethodCall{}, wake: make(chan struct{}, 1)}
		live.methodReceiver = receiver
		h.webSurfaces.mu.Unlock()
		return SurfaceMethodsResult{ReceiverID: id, Cancelled: []string{}}, nil
	}
	h.webSurfaces.mu.Unlock()
	if receiver == nil || receiver.id != req.ReceiverID || receiver.channel != req.BridgeChannelID {
		return SurfaceMethodsResult{}, ErrSurfaceMethodConflict
	}
	receiver.mu.Lock()
	if req.Operation == "configure" {
		if receiver.closed || receiver.ctx.Err() != nil {
			receiver.mu.Unlock()
			return SurfaceMethodsResult{}, ErrSurfaceMethodUnavailable
		}
		receiver.methods = methods
		for id, call := range receiver.calls {
			if !call.claimed && !methods[call.invocation.Method] {
				delete(receiver.calls, id)
				call.result <- surfaceMethodResult{err: &mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: ErrSurfaceMethodUnavailable}}
			}
		}
		receiver.mu.Unlock()
		return SurfaceMethodsResult{ReceiverID: receiver.id, Cancelled: []string{}}, nil
	}
	if req.Operation == "close" {
		receiver.closed = true
		receiver.cancel()
		receiver.mu.Unlock()
		return SurfaceMethodsResult{ReceiverID: receiver.id, Cancelled: []string{}}, nil
	}
	if receiver.closed || receiver.ctx.Err() != nil {
		receiver.mu.Unlock()
		return SurfaceMethodsResult{}, ErrSurfaceMethodUnavailable
	}
	if req.Operation == "complete" {
		call := receiver.calls[req.InvocationID]
		if call == nil || !call.claimed || call.ctx.Err() != nil {
			receiver.mu.Unlock()
			return SurfaceMethodsResult{}, ErrSurfaceMethodConflict
		}
		data, prepareErr := capability.PrepareResponseData(req.Data)
		if prepareErr != nil {
			receiver.mu.Unlock()
			return SurfaceMethodsResult{}, ErrMethodResponseContract
		}
		result := surfaceMethodResult{data: data, dispatched: true}
		if req.Failed {
			result.err = ErrSurfaceMethodFailed
		}
		delete(receiver.calls, req.InvocationID)
		call.result <- result
		receiver.mu.Unlock()
		return SurfaceMethodsResult{ReceiverID: receiver.id, Cancelled: []string{}}, nil
	}
	receiver.mu.Unlock()
	if req.Operation != "claim" {
		return SurfaceMethodsResult{}, ErrMethodRequestContract
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return SurfaceMethodsResult{}, ctx.Err()
		}
		receiver.mu.Lock()
		if receiver.closed || receiver.ctx.Err() != nil {
			receiver.mu.Unlock()
			return SurfaceMethodsResult{}, ErrSurfaceMethodUnavailable
		}
		result := SurfaceMethodsResult{ReceiverID: receiver.id, Cancelled: []string{}}
		for _, id := range req.ActiveInvocations {
			if call := receiver.calls[id]; call == nil || call.ctx.Err() != nil {
				result.Cancelled = append(result.Cancelled, id)
			}
		}
		for len(receiver.queue) > 0 {
			id := receiver.queue[0]
			receiver.queue = receiver.queue[1:]
			call := receiver.calls[id]
			if call == nil || call.ctx.Err() != nil || call.claimed {
				continue
			}
			call.claimed = true
			invocation := call.invocation
			invocation.Params, err = deepCloneParams(invocation.Params)
			if err != nil {
				receiver.mu.Unlock()
				return SurfaceMethodsResult{}, err
			}
			result.Invocation = &invocation
			break
		}
		receiver.mu.Unlock()
		if result.Invocation != nil || len(result.Cancelled) > 0 {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return SurfaceMethodsResult{}, ctx.Err()
		case <-receiver.ctx.Done():
			return SurfaceMethodsResult{}, ErrSurfaceMethodUnavailable
		case <-timer.C:
			return result, nil
		case <-receiver.wake:
		}
	}
}

func sameSurfaceOwner(a, b sessionctx.Context) bool {
	return a.OwnerSessionHash == b.OwnerSessionHash && a.OwnerUserHash == b.OwnerUserHash && a.OwnerEnvHash == b.OwnerEnvHash && a.SessionChannelIDHash == b.SessionChannelIDHash
}

func (h *Host) resolveSurfaceMethodTarget(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (*surfaceMethodReceiver, bridge.BoundSurfaceSession, error) {
	if method.Effect == manifest.MethodEffectRead && !req.session.CanRead || method.Effect != manifest.MethodEffectRead && !req.session.CanWrite {
		return nil, bridge.BoundSurfaceSession{}, ErrActionDenied
	}
	h.webSurfaces.mu.Lock()
	var matches []*webSurfaceBinding
	for _, live := range h.webSurfaces.byOrigin {
		if live.pluginInstanceID != record.PluginInstanceID || live.surface.SurfaceID != method.Route.SurfaceID || !sameSurfaceOwner(live.owner, req.session) || live.ctx.Err() != nil || !live.gatewayReady {
			continue
		}
		if req.SurfaceInstanceID != "" && live.request.SurfaceInstanceID != req.SurfaceInstanceID {
			continue
		}
		receiver := live.methodReceiver
		if receiver == nil {
			continue
		}
		receiver.mu.Lock()
		available := !receiver.closed && receiver.ctx.Err() == nil && receiver.methods[method.Method]
		receiver.mu.Unlock()
		if available {
			snapshot := *live
			matches = append(matches, &snapshot)
		}
	}
	h.webSurfaces.mu.Unlock()
	if len(matches) == 0 {
		return nil, bridge.BoundSurfaceSession{}, ErrSurfaceMethodUnavailable
	}
	if len(matches) > 1 {
		return nil, bridge.BoundSurfaceSession{}, ErrSurfaceMethodAmbiguous
	}
	live := matches[0]
	receiver := live.methodReceiver
	bound, err := h.surfaceTokens.InspectBoundSurface(bridge.InspectBoundSurfaceRequest{SurfaceInstanceID: live.request.SurfaceInstanceID, BridgeChannelID: receiver.channel, OwnerSessionHash: req.session.OwnerSessionHash, OwnerUserHash: req.session.OwnerUserHash, OwnerEnvHash: req.session.OwnerEnvHash, SessionChannelIDHash: req.session.SessionChannelIDHash, Now: req.Now})
	if err != nil {
		return nil, bridge.BoundSurfaceSession{}, err
	}
	if bound.PluginInstanceID != record.PluginInstanceID || bound.ActiveFingerprint != record.ActiveFingerprint || bound.PluginVersion != record.Version || bound.Revision != (bridge.RevisionBinding{PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch}) {
		return nil, bridge.BoundSurfaceSession{}, bridge.ErrTokenRevoked
	}
	if err = h.requireSurfaceGeneration(bound.Audience.SurfaceInstanceID, bound.Audience.RuntimeGenerationID, req.Now); err != nil {
		return nil, bridge.BoundSurfaceSession{}, err
	}
	return receiver, bound, nil
}

func surfaceMethodTarget(receiver *surfaceMethodReceiver, bound bridge.BoundSurfaceSession) (capability.TargetDescriptor, string, error) {
	target := capability.TargetDescriptor{Kind: "surface", Fields: map[string]any{"surface_instance_id": bound.Audience.SurfaceInstanceID, "surface_id": bound.Audience.SurfaceID, "receiver_id": receiver.id}}
	hash, err := canonicalDescriptorHash(target)
	return target, hash, err
}

func (h *Host) invokeSurfaceMethod(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (workerMethodDispatch, error) {
	receiver, bound, err := h.resolveSurfaceMethodTarget(ctx, record, method, req)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	target, targetHash, err := surfaceMethodTarget(receiver, bound)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	if req.executionAuthorization.targetHash != "" && req.executionAuthorization.targetHash != targetHash {
		return workerMethodDispatch{}, ErrConfirmationInvalid
	}
	invocationID, err := newCapabilityID("invoke")
	if err != nil {
		return workerMethodDispatch{}, err
	}
	auditID, err := newCapabilityID("audit")
	if err != nil {
		return workerMethodDispatch{}, err
	}
	arguments, err := deepCloneParams(req.Params)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	if arguments == nil {
		arguments = map[string]any{}
	}
	raw, err := json.Marshal(arguments)
	if err != nil || len(raw) > maxSurfaceMethodBytes {
		return workerMethodDispatch{}, ErrMethodRequestContract
	}
	now := time.Now().UTC()
	deadline := now.Add(surfaceMethodTimeout)
	binding := capability.ExecutionBinding{InvocationID: invocationID, AuditCorrelationID: auditID, PublisherID: record.PublisherID, PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, PluginVersion: record.Version, ActiveFingerprint: record.ActiveFingerprint, SurfaceInstanceID: bound.Audience.SurfaceInstanceID, OwnerSessionHash: req.session.OwnerSessionHash, OwnerUserHash: req.session.OwnerUserHash, OwnerEnvHash: req.session.OwnerEnvHash, SessionChannelIDHash: req.session.SessionChannelIDHash, BridgeChannelID: receiver.channel, RouteKind: capability.RouteSurface, CapabilityID: "redevplugin.surface", CapabilityVersion: "1", BindingID: receiver.id, Method: method.Method, TargetMethod: method.Method, Effect: capability.Effect(method.Effect), Execution: string(method.Execution), Permissions: capability.PermissionEvidence{Required: []string{}, Granted: []string{}}, Confirmation: req.executionAuthorization.confirmation, Revision: capability.RevisionEvidence{PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch}, Quota: capability.QuotaGrant{MaxConcurrent: maxSurfaceMethodCalls, MaxDurationMS: int(surfaceMethodTimeout / time.Millisecond), ExpiresAt: deadline}, Target: target, TargetDescriptorSHA256: targetHash}
	invocation, executionCtx, finish, err := h.startMethodExecution(ctx, record, method, binding, arguments, now, nil, func(context.Context, capability.ExecutionCancellation) error { return nil }, true)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	dispatch := workerMethodDispatch{finish: finish}
	if invocation.Execution.Events != nil {
		dispatch.executionID = invocation.Execution.Events.ID()
	}
	callCtx, cancel := context.WithDeadline(executionCtx, deadline)
	defer cancel()
	stop := context.AfterFunc(receiver.ctx, cancel)
	defer stop()
	call := &surfaceMethodCall{invocation: SurfaceMethodInvocation{InvocationID: invocationID, Method: method.Method, Params: arguments, Deadline: deadline}, ctx: callCtx, result: make(chan surfaceMethodResult, 1)}
	receiver.mu.Lock()
	if receiver.closed || receiver.ctx.Err() != nil || !receiver.methods[method.Method] {
		receiver.mu.Unlock()
		return dispatch, ErrSurfaceMethodUnavailable
	}
	if len(receiver.calls) >= maxSurfaceMethodCalls {
		receiver.mu.Unlock()
		return dispatch, capability.ErrQuotaExceeded
	}
	receiver.calls[invocationID] = call
	receiver.queue = append(receiver.queue, invocationID)
	receiver.mu.Unlock()
	select {
	case receiver.wake <- struct{}{}:
	default:
	}
	defer func() {
		receiver.mu.Lock()
		delete(receiver.calls, invocationID)
		for i, id := range receiver.queue {
			if id == invocationID {
				receiver.queue = append(receiver.queue[:i], receiver.queue[i+1:]...)
				break
			}
		}
		receiver.mu.Unlock()
	}()
	select {
	case result := <-call.result:
		dispatch.dispatched = result.dispatched
		dispatch.result = capability.Result{Data: result.data}
		return dispatch, result.err
	case <-callCtx.Done():
		receiver.mu.Lock()
		dispatch.dispatched = call.claimed
		delete(receiver.calls, invocationID)
		receiver.mu.Unlock()
		if !dispatch.dispatched {
			return dispatch, &mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: callCtx.Err()}
		}
		return dispatch, callCtx.Err()
	}
}

// PrepareIntentConfirmation resolves an already open application and uses the
// same one-shot confirmation store as bridge method calls.
func (h *Host) PrepareIntentConfirmation(ctx context.Context, req InvokeIntentRequest) (response PrepareMethodConfirmationResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	defer func() { resultErr = finalizeRPCError(ctx, resultErr) }()
	authorization, err := h.authorizeManagement(ctx, ManagementActionPrepareIntentConfirmation, authorizationTarget(ResourceIntent, req.IntentID), authorizationTarget(ResourcePlugin, req.PluginInstanceID))
	if err != nil {
		return response, err
	}
	ctx, release, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return response, err
	}
	defer release()
	req.session = authorization.session
	req.Params, err = deepCloneParams(req.Params)
	if err != nil {
		return response, err
	}
	resolved, err := h.resolveIntentIdentity(ctx, req)
	if err != nil {
		return response, err
	}
	if resolved.method.Route.Kind != manifest.MethodRouteSurface {
		return response, ErrMethodRequestContract
	}
	if err = h.authorizeResolvedIntent(ctx, req, resolved); err != nil {
		return response, err
	}
	callReq := CallMethodRequest{PluginInstanceID: resolved.record.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, Method: resolved.method.Method, Params: req.Params, Now: req.Now, session: req.session}
	_, bound, err := h.resolveSurfaceMethodTarget(ctx, resolved.record, resolved.method, callReq)
	if err != nil {
		return response, err
	}
	callReq.SurfaceInstanceID = bound.Audience.SurfaceInstanceID
	callReq.BridgeChannelID = bound.Audience.BridgeChannelID
	return h.prepareResolvedMethodConfirmation(ctx, resolvedMethodCall{record: resolved.record, method: resolved.method, audience: bound.Audience, revision: bound.Revision}, callReq)
}
