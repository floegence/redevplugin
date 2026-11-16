package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// OpenCapabilityHTTP sends one request for a trusted capability adapter through
// the installed connector, current network.client grant, connection review,
// secret resolver, target classifier and network executor. It is not a plugin
// HTTP bridge: the adapter must retain the original platform-issued source and
// enforce its own reviewed component/method selection before calling this API.
// No redirects or uncertain requests are replayed. The caller owns the returned
// body and must close it; cancellation, expiry and revocation close it as well.
func (h *Host) OpenCapabilityHTTP(ctx context.Context, source capability.ExecutionBinding, connectorID string, request *http.Request) (*http.Response, error) {
	if h == nil || request == nil || request.URL == nil || request.URL.User != nil || request.URL.Fragment != "" || request.Host != "" && request.Host != request.URL.Host || !slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, request.Method) {
		return nil, ErrActionDenied
	}
	source, err := capability.CloneExecutionBinding(source)
	if err != nil {
		return nil, err
	}
	validate := func(ctx context.Context) error { return h.validateCapabilityResourceSource(ctx, source) }
	if err := validate(ctx); err != nil {
		return nil, err
	}
	record, err := h.connectionCeiling(ctx, source.PluginInstanceID)
	if err != nil {
		return nil, err
	}
	connector, err := connectorByID(record.Manifest, connectorID)
	if err != nil || connector.Transport != "http" {
		return nil, connectivity.ErrConnectorDenied
	}
	owner, err := requireUserSession(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := owner.ResourceScope(sessionctx.ScopeKind(connector.Scope))
	if err != nil {
		return nil, err
	}
	session, err := owner.SessionScope()
	if err != nil {
		return nil, err
	}
	done, err := h.ensureOpen()
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	if !source.Quota.ExpiresAt.IsZero() {
		cancel()
		lifetime, cancel = context.WithDeadline(ctx, source.Quota.ExpiresAt)
	}
	stopRequest := context.AfterFunc(request.Context(), cancel)
	stopHost := context.AfterFunc(h.lifecycleCtx, cancel)
	var once sync.Once
	cleanup := func() { once.Do(func() { stopRequest(); stopHost(); cancel(); done() }) }
	// An idle streaming response still loses authority when its originating
	// surface or capability lease expires. No future read is needed to trigger it.
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
				if validate(lifetime) != nil {
					cancel()
					return
				}
			}
		}
	}()
	invocation := resourceio.Invocation{Owner: resourceio.Owner{PluginInstanceID: source.PluginInstanceID, ActiveFingerprint: source.ActiveFingerprint, ManagementRevision: source.Revision.ManagementRevision, RevokeEpoch: source.Revision.RevokeEpoch, Scope: scope, Session: session, InvocationID: source.InvocationID, RuntimeGeneration: source.InvocationID, Lifetime: resourceio.LifetimeInvocation}, Plugin: resourceio.Plugin{ID: source.PluginID, InstanceID: source.PluginInstanceID, Version: source.PluginVersion}, PolicyRevision: source.Revision.PolicyRevision, CanRead: owner.CanRead, CanWrite: owner.CanWrite, Permissions: map[string]bool{resourceio.PermissionNetworkClient: true}, Network: []resourceio.NetworkAccess{{ConnectorID: connectorID, Transport: "http", Scope: connector.Scope, Operations: []string{"http_stream"}, HTTPMethods: []string{request.Method}}}}
	transport := &runtimeHTTPTransport{broker: h.runtimeIO, invocation: invocation, connector: connectorID}
	response, err := transport.RoundTrip(request.Clone(lifetime))
	if err != nil {
		cleanup()
		return nil, mutation.Unknown(err)
	}
	if err := validate(lifetime); err != nil {
		_ = response.Body.Close()
		cleanup()
		return nil, mutation.Unknown(err)
	}
	if response.StatusCode >= 300 && response.StatusCode <= 399 && response.Header.Get("Location") != "" {
		_ = response.Body.Close()
		cleanup()
		return nil, mutation.Unknown(fmt.Errorf("%w: connection redirects require an explicit new request", connectivity.ErrTargetDenied))
	}
	body := &capabilityHTTPBody{body: response.Body, cleanup: cleanup, validate: func() error { return validate(lifetime) }}
	context.AfterFunc(lifetime, func() { _ = body.Close() })
	response.Body = body
	if err := lifetime.Err(); err != nil {
		_ = response.Body.Close()
		return nil, mutation.Unknown(err)
	}
	return response, nil
}

type capabilityHTTPBody struct {
	body     io.ReadCloser
	cleanup  func()
	validate func() error
	once     sync.Once
	err      error
}

func (b *capabilityHTTPBody) Read(data []byte) (int, error) {
	if err := b.validate(); err != nil {
		_ = b.Close()
		return 0, err
	}
	n, err := b.body.Read(data)
	if validation := b.validate(); validation != nil {
		_ = b.Close()
		return 0, validation
	}
	if err != nil {
		_ = b.Close()
	}
	return n, err
}
func (b *capabilityHTTPBody) Close() error {
	b.once.Do(func() { b.err = b.body.Close(); b.cleanup() })
	return b.err
}

func (h *Host) validateCapabilityResourceSource(ctx context.Context, source capability.ExecutionBinding) error {
	owner, err := requireUserSession(ctx)
	if err != nil || !owner.CanWrite || source.Effect != capability.EffectExecute || !sameSurfaceOwner(owner, sessionctx.Context{OwnerSessionHash: source.OwnerSessionHash, OwnerUserHash: source.OwnerUserHash, OwnerEnvHash: source.OwnerEnvHash, SessionChannelIDHash: source.SessionChannelIDHash}) {
		return ErrActionDenied
	}
	if err := h.ValidateCapabilityContinuation(ctx, source); err != nil {
		return err
	}
	if err := h.validateCapabilitySurface(source); err != nil {
		return errors.Join(capability.ErrExecutionRevoked, err)
	}
	return ctx.Err()
}
