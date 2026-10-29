package host

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// WebConnectionRequest selects only a connector declared by this exact surface.
// DestinationIndex selects an authored fixed target; configurable connectors use 0.
type WebConnectionRequest struct {
	WebSurfaceRequest
	ConnectorID      string
	DestinationIndex int
}
type WebConnection struct {
	ConnectorID  string
	ConnectionID string
	BasePath     string
	HTTPMethods  []string
}
type WebConnectionHTTPRequest struct {
	WebConnectionRequest
	ConnectionID string
	Method       string
	RequestURI   string
	Headers      http.Header
	Body         io.ReadCloser
}

func (h *Host) webNetworkInvocation(ctx context.Context, req WebConnectionRequest) (resourceio.Invocation, manifest.NetworkConnectorSpec, context.Context, func(), error) {
	binding, ctx, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		return resourceio.Invocation{}, manifest.NetworkConnectorSpec{}, ctx, nil, err
	}
	if !binding.gatewayReady || binding.ctx == nil {
		return resourceio.Invocation{}, manifest.NetworkConnectorSpec{}, ctx, nil, bridge.ErrAssetSessionRequired
	}
	record, err := h.connectionCeiling(ctx, binding.pluginInstanceID)
	if err != nil {
		return resourceio.Invocation{}, manifest.NetworkConnectorSpec{}, ctx, nil, err
	}
	connector, err := connectorByID(record.Manifest, req.ConnectorID)
	if err != nil || connector.Transport != "http" {
		return resourceio.Invocation{}, connector, ctx, nil, connectivity.ErrConnectorDenied
	}
	var declared *manifest.NetworkBrokerAccessSpec
	for i := range binding.surface.Web.Network {
		if binding.surface.Web.Network[i].ConnectorID == req.ConnectorID {
			declared = &binding.surface.Web.Network[i]
			break
		}
	}
	if declared == nil {
		return resourceio.Invocation{}, connector, ctx, nil, permissions.ErrPermissionDenied
	}
	scope, err := binding.owner.ResourceScope(sessionctx.ScopeKind(connector.Scope))
	if err != nil {
		return resourceio.Invocation{}, connector, ctx, nil, err
	}
	owner, err := binding.owner.SessionScope()
	if err != nil {
		return resourceio.Invocation{}, connector, ctx, nil, err
	}
	invocation := resourceio.Invocation{Owner: resourceio.Owner{PluginInstanceID: record.PluginInstanceID, ActiveFingerprint: record.ActiveFingerprint, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, Scope: scope, Session: owner, InvocationID: "surface-network:" + binding.request.SurfaceInstanceID, RuntimeGeneration: binding.request.AssetSessionID, Lifetime: resourceio.LifetimeInvocation}, Plugin: resourceio.Plugin{ID: record.PluginID, InstanceID: record.PluginInstanceID, Version: record.Version}, PolicyRevision: record.PolicyRevision, CanRead: binding.owner.CanRead, CanWrite: binding.owner.CanWrite, Permissions: map[string]bool{resourceio.PermissionNetworkClient: true}, Network: []resourceio.NetworkAccess{{ConnectorID: declared.ConnectorID, Transport: declared.Transport, Scope: connector.Scope, Operations: append([]string(nil), declared.Operations...), HTTPMethods: append([]string(nil), declared.HTTPMethods...)}}}
	request, cancel := context.WithDeadline(ctx, binding.expiresAt)
	stop := context.AfterFunc(binding.ctx, cancel)
	if binding.ctx.Err() != nil {
		cancel()
	}
	return invocation, connector, request, func() { stop(); cancel() }, nil
}
func (h *Host) webConnectionTarget(ctx context.Context, inv resourceio.Invocation, connector manifest.NetworkConnectorSpec, index int, method string) (string, string, error) {
	if index < 0 {
		return "", "", connectivity.ErrConnectorDenied
	}
	lease, err := h.connections.acquire(ctx, inv, connector.ConnectorID, method)
	if err != nil {
		return "", "", err
	}
	defer lease.release()
	if connector.Configurable {
		if index != 0 || lease.binding == nil {
			return "", "", connectivity.ErrConnectorDenied
		}
		return lease.binding.Destination, lease.binding.ConnectionID, nil
	}
	if index >= len(connector.Destinations) {
		return "", "", connectivity.ErrConnectorDenied
	}
	return connector.Destinations[index], "fixed-" + strconv.Itoa(index), nil
}
func (h *Host) GetWebConnection(ctx context.Context, req WebConnectionRequest) (WebConnection, error) {
	done, err := h.ensureOpen()
	if err != nil {
		return WebConnection{}, err
	}
	defer done()
	inv, connector, ctx, cancel, err := h.webNetworkInvocation(ctx, req)
	if err != nil {
		return WebConnection{}, err
	}
	defer cancel()
	// Selection does not issue a bearer credential. Requests recheck every method.
	methods := inv.Network[0].HTTPMethods
	var id string
	allowed := []string{}
	for _, method := range methods {
		_, current, err := h.webConnectionTarget(ctx, inv, connector, req.DestinationIndex, method)
		if err == nil {
			id = current
			allowed = append(allowed, method)
		}
	}
	if id == "" || len(allowed) == 0 {
		return WebConnection{}, ErrConnectionUnavailable
	}
	return WebConnection{ConnectorID: connector.ConnectorID, ConnectionID: id, BasePath: WebSurfacePlatformPath + "connections/" + url.PathEscape(connector.ConnectorID) + "/" + id + "/", HTTPMethods: allowed}, nil
}
func (h *Host) OpenWebConnectionHTTP(ctx context.Context, req WebConnectionHTTPRequest) (*http.Response, error) {
	done, err := h.ensureOpen()
	if err != nil {
		return nil, err
	}
	inv, connector, ctx, cancel, err := h.webNetworkInvocation(ctx, req.WebConnectionRequest)
	if err != nil {
		done()
		return nil, err
	}
	var once sync.Once
	cleanup := func() { once.Do(func() { cancel(); done() }) }
	target, id, err := h.webConnectionTarget(ctx, inv, connector, req.DestinationIndex, req.Method)
	if err != nil || id != req.ConnectionID {
		cleanup()
		return nil, ErrConnectionUnavailable
	}
	path, err := url.ParseRequestURI(req.RequestURI)
	if err != nil || !strings.HasPrefix(req.RequestURI, "/") || strings.HasPrefix(req.RequestURI, "//") || path.IsAbs() || path.Host != "" || path.Fragment != "" {
		cleanup()
		return nil, connectivity.ErrInvalidConnector
	}
	destination, err := connectivity.ParseDestination(connectivity.TransportHTTP, target)
	if err != nil {
		cleanup()
		return nil, err
	}
	outbound, err := http.NewRequestWithContext(ctx, req.Method, (&url.URL{Scheme: destination.Scheme, Host: net.JoinHostPort(destination.Host, strconv.Itoa(destination.Port))}).String()+req.RequestURI, req.Body)
	if err != nil {
		cleanup()
		return nil, err
	}
	outbound.Header = req.Headers.Clone()
	transport := &runtimeHTTPTransport{broker: h.runtimeIO, invocation: inv, connector: connector.ConnectorID}
	if connector.Configurable {
		transport.expectedConnectionID = req.ConnectionID
	}
	response, err := transport.RoundTrip(outbound)
	if err != nil {
		cleanup()
		return nil, err
	}
	// A redirect is surfaced as a failed data request. It cannot navigate the
	// child origin or replay an already dispatched mutation.
	if response.StatusCode >= 300 && response.StatusCode <= 399 && response.Header.Get("Location") != "" {
		_ = response.Body.Close()
		cleanup()
		return nil, fmt.Errorf("%w: connection redirects require an explicit new request", connectivity.ErrTargetDenied)
	}
	response.Body = &networkLeaseBody{ReadCloser: response.Body, release: cleanup}
	return response, nil
}
