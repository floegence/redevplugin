package host

import (
	"context"
	"github.com/floegence/redevplugin/v3/pkg/capability"
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
