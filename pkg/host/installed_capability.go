package host

import (
	"context"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

// InstalledCapabilityRequest is a host-owned invocation of an exact capability
// method already declared by an installed plugin. It carries no surface token,
// caller-supplied execution binding or confirmation override.
type InstalledCapabilityRequest struct {
	PluginInstanceID string
	Method           string
	Params           map[string]any
}

// CallInstalledCapability lets trusted host UI and services invoke a declared
// capability under the current authenticated user and local policy. Host owns
// the request's target projection, quota, source binding and execution envelope.
// The host product must authorize its user action before calling this Go-only
// API. It must never expose it as a replacement for the plugin surface bridge.
// Native routes and methods requiring confirmation cannot use this entry point.
func (h *Host) CallInstalledCapability(ctx context.Context, request InstalledCapabilityRequest) (response CallMethodResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	defer func() { resultErr = finalizeRPCError(ctx, resultErr) }()
	request.PluginInstanceID = strings.TrimSpace(request.PluginInstanceID)
	request.Method = strings.TrimSpace(request.Method)
	authorization, err := h.authorizeManagement(ctx, ManagementActionCallPluginMethod,
		authorizationTarget(ResourceMethod, request.Method), authorizationTarget(ResourcePlugin, request.PluginInstanceID))
	if err != nil {
		return response, err
	}
	ctx, release, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return response, err
	}
	defer release()
	record, err := h.getPluginRecord(ctx, request.PluginInstanceID)
	if err != nil {
		return response, err
	}
	if record.EnableState != registry.EnableEnabled {
		return response, ErrActionDenied
	}
	if err := h.canRun(ctx, record); err != nil {
		return response, err
	}
	method, ok := manifestMethod(record.Manifest, request.Method)
	if !ok || method.Route.Kind != manifest.MethodRouteCapability {
		return response, ErrActionDenied
	}
	method, err = h.effectiveMethod(record, method)
	if err != nil {
		return response, err
	}
	if methodRequiresConfirmation(method) {
		return response, ErrConfirmationRequired
	}
	if err := h.authorizeHeadlessMethod(ctx, authorization.session, record, method, time.Time{}); err != nil {
		return response, err
	}
	params, err := deepCloneParams(request.Params)
	if err != nil {
		return response, err
	}
	response, err = h.dispatchMethod(ctx, record, method, CallMethodRequest{PluginInstanceID: record.PluginInstanceID, Method: method.Method, Params: params, session: authorization.session})
	if err != nil {
		return response, err
	}
	if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.capability.called", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID}); err != nil {
		return response, mutation.Unknown(err)
	}
	return response, nil
}
