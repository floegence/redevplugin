package host

import (
	"context"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// ValidateCapabilityContinuation rechecks a binding retained by a trusted host
// adapter against the original installed instance, fingerprint, revisions,
// permissions and quota expiry. It does not create an execution, extend a grant,
// mint session credentials, or authorize a different method or target. Hosts
// must retain the exact platform-supplied binding, never a plugin-supplied copy.
func (h *Host) ValidateCapabilityContinuation(ctx context.Context, binding capability.ExecutionBinding) error {
	if h == nil {
		return ErrHostClosed
	}
	if err := capability.ValidateExecutionBinding(binding); err != nil {
		return err
	}
	h.lifecycleMu.RLock()
	defer h.lifecycleMu.RUnlock()
	if h.closed {
		return ErrHostClosed
	}
	if binding.RouteKind != capability.RouteCapability {
		return capability.ErrExecutionRevoked
	}
	ctx = sessionctx.WithContext(ctx, sessionctx.Context{OwnerSessionHash: binding.OwnerSessionHash, OwnerUserHash: binding.OwnerUserHash, OwnerEnvHash: binding.OwnerEnvHash, SessionChannelIDHash: binding.SessionChannelIDHash})
	return h.validateExecutionBinding(ctx, binding)
}

// AllowsCapabilityRead checks an optional read route on the same declared
// binding with live registry policy. It does not authorize a method call or
// waive confirmation, and returns false for missing or ungranted routes.
func (h *Host) AllowsCapabilityRead(ctx context.Context, source capability.ExecutionBinding, targetMethod string) (bool, error) {
	if err := h.ValidateCapabilityContinuation(ctx, source); err != nil {
		return false, err
	}
	scope, err := requireUserSession(ctx)
	if err != nil {
		return false, err
	}
	if !scope.CanRead || !sameSurfaceOwner(scope, sessionctx.Context{OwnerSessionHash: source.OwnerSessionHash, OwnerUserHash: source.OwnerUserHash, OwnerEnvHash: source.OwnerEnvHash, SessionChannelIDHash: source.SessionChannelIDHash}) {
		return false, capability.ErrExecutionRevoked
	}
	record, err := h.getPluginRecord(ctx, source.PluginInstanceID)
	if err != nil {
		return false, err
	}
	for _, m := range record.Manifest.Methods {
		if m.Route.Kind != manifest.MethodRouteCapability || m.Route.BindingID != source.BindingID || m.Route.TargetMethod != targetMethod {
			continue
		}
		resolved, err := h.resolveCapabilityMethod(record, m)
		if err != nil {
			return false, err
		}
		if resolved.method.Effect != "read" || resolved.method.Confirmation != nil {
			return false, nil
		}
		decision, err := h.authorizePlugin(ctx, registry.AuthorizeRequest{PluginInstanceID: source.PluginInstanceID, Method: m.Method, PermissionIDs: resolved.method.RequiredPermissions, Expected: registry.AuthorizationRevisions{PolicyRevision: source.Revision.PolicyRevision, ManagementRevision: source.Revision.ManagementRevision, RevokeEpoch: source.Revision.RevokeEpoch}})
		if err != nil {
			return false, err
		}
		err = authorizationDecisionError(decision, m.Method)
		if errors.Is(err, permissions.ErrPermissionDenied) || errors.Is(err, security.ErrPolicyDenied) {
			continue
		}
		if err != nil {
			return false, err
		}
		return true, h.ValidateCapabilityContinuation(ctx, source)
	}
	return false, nil
}
