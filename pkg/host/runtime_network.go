package host

import (
	"context"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func (b *hostRuntimeIOBroker) AuthorizeNetwork(ctx context.Context, request resourceio.NetworkAuthorization) error {
	if request.Listen {
		if b.networkPolicy == nil {
			return os.ErrPermission
		}
		return (hostNetworkAuthorizer{adapter: b.networkPolicy}).AuthorizeNetwork(ctx, request)
	}
	if b.networkBroker == nil || b.networkExecutor == nil || request.Destination == nil || request.ConnectorID == "" {
		return os.ErrPermission
	}
	var declared *resourceio.NetworkAccess
	for i := range request.Invocation.Network {
		if request.Invocation.Network[i].ConnectorID == request.ConnectorID {
			declared = &request.Invocation.Network[i]
			break
		}
	}
	if declared == nil {
		return os.ErrPermission
	}
	switch request.Operation {
	case "net.http.begin":
		if declared.Transport != "http" || !slices.Contains(declared.HTTPMethods, request.HTTPMethod) || (!slices.Contains(declared.Operations, "http") && !slices.Contains(declared.Operations, "http_stream")) {
			return os.ErrPermission
		}
	case "net.websocket.open":
		if declared.Transport != "websocket" || !slices.Contains(declared.Operations, "websocket") {
			return os.ErrPermission
		}
	case "net.tcp.connect":
		if declared.Transport != "tcp" || !slices.Contains(declared.Operations, "tcp") {
			return os.ErrPermission
		}
	case "net.udp.connect":
		if declared.Transport != "udp" || !slices.Contains(declared.Operations, "udp") {
			return os.ErrPermission
		}
	default:
		return os.ErrPermission
	}
	if b.networkPolicy != nil {
		return (hostNetworkAuthorizer{adapter: b.networkPolicy}).AuthorizeNetwork(ctx, request)
	}
	return nil
}

func (b *hostRuntimeIOBroker) HTTPTransport(invocation resourceio.Invocation, connector string) http.RoundTripper {
	return &runtimeHTTPTransport{broker: b, invocation: invocation, connector: connector}
}

type runtimeHTTPTransport struct {
	expectedConnectionID string
	broker               *hostRuntimeIOBroker
	invocation           resourceio.Invocation
	connector            string
	firstOrigin          string
	crossedOrigin        bool
}

func (t *runtimeHTTPTransport) RoundTrip(request *http.Request) (result *http.Response, retErr error) {
	defer func() {
		if retErr != nil && request.Body != nil {
			_ = request.Body.Close()
		}
	}()
	if err := t.broker.AuthorizeNetwork(request.Context(), resourceio.NetworkAuthorization{Invocation: t.invocation, ConnectorID: t.connector, Operation: "net.http.begin", Destination: request.URL, HTTPMethod: request.Method}); err != nil {
		return nil, err
	}
	grant, lease, err := t.broker.admitNetwork(request.Context(), t.invocation, t.connector, connectivity.TransportHTTP, request.URL.String(), request.Method)
	if err != nil {
		return nil, err
	}
	if t.expectedConnectionID != "" && (lease.binding == nil || lease.binding.ConnectionID != t.expectedConnectionID) {
		lease.release()
		return nil, ErrConnectionUnavailable
	}
	ctx := lease.ctx
	origin := (&url.URL{Scheme: request.URL.Scheme, Host: request.URL.Host}).String()
	if t.firstOrigin == "" {
		t.firstOrigin = origin
	}
	headers := request.Header.Clone()
	if origin != t.firstOrigin {
		t.crossedOrigin = true
	}
	if t.crossedOrigin {
		headers.Del("Authorization")
		headers.Del("Cookie")
	} else if lease.secretRef != "" {
		if t.broker.connections == nil || t.broker.connections.host.networkSecrets == nil {
			lease.release()
			return nil, os.ErrPermission
		}
		credentials, err := t.broker.connections.host.networkSecrets.ResolveNetworkSecret(ctx, NetworkSecretRequest{Session: resourceInvocationSession(t.invocation), Plugin: resourceInvocationPlugin(t.invocation), ConnectorID: t.connector, SecretRef: lease.secretRef, Destination: grant.Destination})
		if err != nil {
			lease.release()
			return nil, os.ErrPermission
		}
		if err := validateCredentialHeaders(credentials); err != nil {
			lease.release()
			return nil, err
		}
		for name, values := range credentials {
			headers.Del(name)
			for _, value := range values {
				headers.Add(name, value)
			}
		}
	}
	tlsConfig, err := t.broker.resolveNetworkTLS(ctx, t.invocation, t.connector, grant, lease)
	if err != nil {
		lease.release()
		return nil, err
	}
	if t.crossedOrigin && tlsConfig != nil {
		lease.release()
		return nil, os.ErrPermission
	}
	response, err := t.broker.networkExecutor.OpenHTTP(ctx, connectivity.HTTPRequest{TLSConfig: tlsConfig, Grant: grant, Method: request.Method, RequestURI: request.URL.RequestURI(), Headers: headers, BodyReader: request.Body})
	if err != nil {
		lease.release()
		return nil, err
	}
	return &http.Response{StatusCode: response.StatusCode, Header: response.Headers, Body: &networkLeaseBody{ReadCloser: response.Body, release: lease.release}, Request: request}, nil
}

func (b *hostRuntimeIOBroker) admitNetwork(ctx context.Context, inv resourceio.Invocation, connector string, transport connectivity.Transport, target, method string) (connectivity.ConnectionGrant, connectionLease, error) {
	lease := connectionLease{ctx: ctx, release: func() {}}
	if b.connections != nil {
		var err error
		lease, err = b.connections.acquire(ctx, inv, connector, method)
		if err != nil {
			return connectivity.ConnectionGrant{}, lease, normalizeNetworkPermission(err)
		}
	}
	if lease.binding != nil && len(lease.binding.PrivatePrefixes) > 0 {
		h := b.connections.host
		session := resourceInvocationSession(inv)
		record, err := h.getPluginRecord(sessionctx.WithContext(ctx, session), inv.Plugin.InstanceID)
		if err != nil {
			lease.release()
			return connectivity.ConnectionGrant{}, lease, err
		}
		declared, err := connectorByID(record.Manifest, connector)
		if err != nil {
			lease.release()
			return connectivity.ConnectionGrant{}, lease, err
		}
		destination, err := connectivity.ParseDestination(transport, lease.binding.Destination)
		if err != nil {
			lease.release()
			return connectivity.ConnectionGrant{}, lease, err
		}
		if err := h.authorizePrivateConnection(lease.ctx, session, record, declared, destination, lease.binding.PrivatePrefixes); err != nil {
			lease.release()
			return connectivity.ConnectionGrant{}, lease, err
		}
	}
	grant, err := b.networkGrant(lease.ctx, inv, connector, transport, target, method, lease.binding)
	if err != nil {
		lease.release()
		return grant, lease, err
	}
	if err := lease.ctx.Err(); err != nil {
		lease.release()
		return grant, lease, err
	}
	return grant, lease, nil
}
func (b *hostRuntimeIOBroker) networkGrant(ctx context.Context, inv resourceio.Invocation, connector string, transport connectivity.Transport, target, method string, binding *connectivity.ApprovedBinding) (connectivity.ConnectionGrant, error) {
	if transport == connectivity.TransportHTTP || transport == connectivity.TransportWebSocket {
		parsed, err := url.Parse(target)
		if err != nil || parsed.User != nil || parsed.Fragment != "" {
			return connectivity.ConnectionGrant{}, os.ErrPermission
		}
		target = (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String()
	}
	var scope sessionctx.ResourceScope
	session := resourceInvocationSession(inv)
	for _, access := range inv.Network {
		if access.ConnectorID == connector {
			var err error
			scope, err = session.ResourceScope(sessionctx.ScopeKind(access.Scope))
			if err != nil {
				return connectivity.ConnectionGrant{}, err
			}
			break
		}
	}
	if !scope.Valid() {
		return connectivity.ConnectionGrant{}, os.ErrPermission
	}
	grant, err := b.networkBroker.MintConnectionGrant(sessionctx.WithContext(ctx, session), connectivity.GrantRequest{Binding: binding, HTTPMethod: method, PluginInstanceID: inv.Plugin.InstanceID, ActiveFingerprint: inv.Owner.ActiveFingerprint, ResourceScope: scope, PolicyRevision: inv.PolicyRevision, ManagementRevision: inv.Owner.ManagementRevision, RevokeEpoch: inv.Owner.RevokeEpoch, ConnectorID: connector, Transport: transport, Destination: target, RuntimeGenerationID: inv.Owner.RuntimeGeneration})
	if err != nil {
		return connectivity.ConnectionGrant{}, err
	}
	destination, err := connectivity.ParseDestination(transport, target)
	if err != nil || grant.PluginInstanceID != inv.Plugin.InstanceID || grant.ActiveFingerprint != inv.Owner.ActiveFingerprint || !grant.ResourceScope.Matches(scope) || grant.PolicyRevision != inv.PolicyRevision || grant.ManagementRevision != inv.Owner.ManagementRevision || grant.RevokeEpoch != inv.Owner.RevokeEpoch || grant.ConnectorID != connector || grant.Transport != transport || grant.Destination != destination || grant.RuntimeGenerationID != inv.Owner.RuntimeGeneration {
		return connectivity.ConnectionGrant{}, os.ErrPermission
	}
	if binding != nil && (grant.ConnectionID != binding.ConnectionID || grant.ConnectionRevision != binding.Revision || !slices.Equal(grant.HTTPMethods, binding.HTTPMethods) || !slices.Equal(grant.PrivatePrefixes, binding.PrivatePrefixes) || grant.ExpiresAt.After(binding.ExpiresAt)) {
		return connectivity.ConnectionGrant{}, os.ErrPermission
	}
	if binding == nil && (grant.ConnectionID != "" || grant.ConnectionRevision != 0 || len(grant.PrivatePrefixes) != 0 || len(grant.HTTPMethods) != 0) {
		return connectivity.ConnectionGrant{}, os.ErrPermission
	}
	return grant, nil
}
func (b *hostRuntimeIOBroker) socketGrant(ctx context.Context, inv resourceio.Invocation, connector string, transport connectivity.Transport, target, operation string) (connectivity.ConnectionGrant, connectionLease, error) {
	destination, err := url.Parse(target)
	if err != nil {
		return connectivity.ConnectionGrant{}, connectionLease{}, err
	}
	if err := b.AuthorizeNetwork(ctx, resourceio.NetworkAuthorization{Invocation: inv, ConnectorID: connector, Operation: operation, Destination: destination}); err != nil {
		return connectivity.ConnectionGrant{}, connectionLease{}, err
	}
	return b.admitNetwork(ctx, inv, connector, transport, target, "")
}

// An open call may be canceled until it returns. A successful resource then
// belongs to the invocation lifetime, not to the completed control operation.
func networkOpenContext(ctx context.Context, inv resourceio.Invocation) (context.Context, func(bool)) {
	parent := ctx
	if inv.Lifetime != nil {
		parent = inv.Lifetime.Context()
	}
	opened, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ctx, cancel)
	return opened, func(success bool) {
		stop()
		if !success || ctx.Err() != nil {
			cancel()
		}
	}
}
func (b *hostRuntimeIOBroker) OpenTCP(ctx context.Context, inv resourceio.Invocation, connector string, options resourceio.TCPConnectOptions) (net.Conn, error) {
	opened, finish := networkOpenContext(ctx, inv)
	grant, lease, err := b.socketGrant(opened, inv, connector, connectivity.TransportTCP, "tcp://"+options.Address, "net.tcp.connect")
	if err != nil {
		finish(false)
		return nil, err
	}
	tlsConfig, err := b.resolveNetworkTLS(lease.ctx, inv, connector, grant, lease)
	if err != nil {
		lease.release()
		finish(false)
		return nil, err
	}
	conn, err := b.networkExecutor.OpenTCP(lease.ctx, connectivity.SocketRequest{TLSConfig: tlsConfig, Grant: grant, Timeout: options.Timeout, NoDelay: options.NoDelay, KeepAlive: options.KeepAlive})
	finish(err == nil)
	if err != nil {
		lease.release()
		return nil, err
	}
	return &networkLeaseConn{Conn: conn, release: func() { lease.release(); finish(false) }}, nil
}
func (b *hostRuntimeIOBroker) OpenUDP(ctx context.Context, inv resourceio.Invocation, connector, address string, timeout time.Duration) (resourceio.DatagramConnection, error) {
	opened, finish := networkOpenContext(ctx, inv)
	grant, lease, err := b.socketGrant(opened, inv, connector, connectivity.TransportUDP, "udp://"+address, "net.udp.connect")
	if err != nil {
		finish(false)
		return nil, err
	}
	conn, err := b.networkExecutor.OpenUDP(lease.ctx, connectivity.SocketRequest{Grant: grant, Timeout: timeout})
	finish(err == nil)
	if err != nil {
		lease.release()
		return nil, err
	}
	return &networkLeaseDatagram{DatagramConnection: conn, release: func() { lease.release(); finish(false) }}, nil
}
func (b *hostRuntimeIOBroker) OpenWebSocket(ctx context.Context, inv resourceio.Invocation, connector string, options resourceio.WebSocketOpen) (resourceio.WebSocketStream, http.Header, func() error, error) {
	opened, finish := networkOpenContext(ctx, inv)
	grant, lease, err := b.socketGrant(opened, inv, connector, connectivity.TransportWebSocket, options.URL, "net.websocket.open")
	if err != nil {
		finish(false)
		return nil, nil, nil, err
	}
	headers := make(http.Header)
	for _, h := range options.Headers {
		headers.Add(h.Name, h.Value)
	}
	if lease.secretRef != "" {
		if b.connections == nil || b.connections.host.networkSecrets == nil {
			lease.release()
			finish(false)
			return nil, nil, nil, os.ErrPermission
		}
		credentials, err := b.connections.host.networkSecrets.ResolveNetworkSecret(lease.ctx, NetworkSecretRequest{Session: resourceInvocationSession(inv), Plugin: resourceInvocationPlugin(inv), ConnectorID: connector, SecretRef: lease.secretRef, Destination: grant.Destination})
		if err != nil {
			lease.release()
			finish(false)
			return nil, nil, nil, os.ErrPermission
		}
		if err := validateCredentialHeaders(credentials); err != nil {
			lease.release()
			finish(false)
			return nil, nil, nil, err
		}
		for name, values := range credentials {
			headers.Del(name)
			for _, v := range values {
				headers.Add(name, v)
			}
		}
	}
	tlsConfig, err := b.resolveNetworkTLS(lease.ctx, inv, connector, grant, lease)
	if err != nil {
		lease.release()
		finish(false)
		return nil, nil, nil, err
	}
	result, err := b.networkExecutor.OpenWebSocket(lease.ctx, connectivity.WebSocketOpenRequest{SocketRequest: connectivity.SocketRequest{TLSConfig: tlsConfig, Grant: grant, Timeout: options.Timeout}, URL: options.URL, Headers: headers, Subprotocols: options.Subprotocols})
	finish(err == nil)
	if err != nil {
		lease.release()
		return nil, nil, nil, err
	}
	return result.Connection, result.Headers, func() error { err := result.Close(); lease.release(); finish(false); return err }, nil
}

type networkLeaseConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *networkLeaseConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *networkLeaseConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return resourceio.ErrInvalidHandle
}
func (c *networkLeaseConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return resourceio.ErrInvalidHandle
}

type networkLeaseDatagram struct {
	connectivity.DatagramConnection
	release func()
	once    sync.Once
}

func (c *networkLeaseDatagram) Close() error {
	err := c.DatagramConnection.Close()
	c.once.Do(c.release)
	return err
}

func validRuntimeNetworkAccess(access workerNetworkBrokerAccess) bool {
	if access.ConnectorID == "" || (access.Scope != "user" && access.Scope != "environment") || len(access.Operations) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, operation := range access.Operations {
		if seen[operation] {
			return false
		}
		seen[operation] = true
		switch access.Transport {
		case "http":
			if operation != "http" && operation != "http_stream" {
				return false
			}
		case "websocket", "tcp", "udp":
			if operation != access.Transport {
				return false
			}
		default:
			return false
		}
	}
	if access.Transport != "http" {
		return len(access.HTTPMethods) == 0
	}
	if len(access.HTTPMethods) == 0 {
		return false
	}
	seen = map[string]bool{}
	for _, method := range access.HTTPMethods {
		if seen[method] {
			return false
		}
		seen[method] = true
		switch method {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		default:
			return false
		}
	}
	return true
}

type networkLeaseBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (b *networkLeaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}
func (b *networkLeaseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		_ = b.Close()
	}
	return n, err
}

func normalizeNetworkPermission(err error) error {
	if errors.Is(err, permissions.ErrPermissionDenied) {
		return errors.Join(os.ErrPermission, err)
	}
	return err
}
