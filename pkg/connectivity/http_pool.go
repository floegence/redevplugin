package connectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

const (
	maxHTTPConnectionPools     = 128
	maxHTTPIdleConnsPerHost    = 2
	maxHTTPConnectionsPerHost  = 8
	httpConnectionIdleTimeout  = 30 * time.Second
	httpConnectionProxyMode    = "direct"
	httpConnectionTLSModePlain = "plain"
	httpConnectionTLSModeTLS12 = "tls12+"
)

type httpPoolScope struct {
	pluginInstanceID string
	resourceScope    sessionctx.ResourceScope
	connectorID      string
	destination      Destination
}

type httpPoolKey struct {
	connectionID            string
	connectionRevision      uint64
	privatePrefixes         string
	pluginInstanceID        string
	activeFingerprint       string
	resourceScope           sessionctx.ResourceScope
	connectorID             string
	destination             Destination
	policyRevision          uint64
	managementRevision      uint64
	revokeEpoch             uint64
	runtimeGenerationID     string
	targetClassifierVersion string
	tlsMode                 string
	proxyMode               string
	resolvedAddressSet      string
}

type httpPoolBinding struct {
	scope     httpPoolScope
	key       httpPoolKey
	addresses []netip.Addr
}

type httpConnectionPool struct {
	key       httpPoolKey
	scope     httpPoolScope
	client    *http.Client
	transport HTTPTransport
	active    int
	lastUsed  uint64
	draining  bool
}

type httpConnectionPools struct {
	mu          sync.Mutex
	byKey       map[httpPoolKey]*httpConnectionPool
	draining    map[*httpConnectionPool]struct{}
	sequence    uint64
	closed      bool
	closeDone   chan struct{}
	closeDoneDo sync.Once
}

func (p *httpConnectionPools) init() {
	p.byKey = make(map[httpPoolKey]*httpConnectionPool)
	p.draining = make(map[*httpConnectionPool]struct{})
	p.closeDone = make(chan struct{})
}

func (e *Executor) resolveHTTPPoolBinding(ctx context.Context, grant ConnectionGrant) (httpPoolBinding, error) {
	scope := httpPoolScope{
		pluginInstanceID: grant.PluginInstanceID,
		resourceScope:    grant.ResourceScope,
		connectorID:      grant.ConnectorID,
		destination:      grant.Destination,
	}
	var addresses []netip.Addr
	var err error
	proxyMode := httpConnectionProxyMode
	_, literalError := netip.ParseAddr(grant.Destination.Host)
	hostRouted := e.hostHTTPTransport != nil && grant.Destination.Scheme == "https" && literalError != nil && len(grant.PrivatePrefixes) == 0
	if hostRouted {
		proxyMode = "host"
	} else {
		addresses, err = e.resolveAddresses(grantNetworkContext(ctx, grant), "tcp", grantEndpoint(grant))
	}
	if err != nil {
		if errors.Is(err, ErrTargetDenied) {
			e.retireHTTPPoolScope(scope)
		}
		return httpPoolBinding{}, err
	}
	if len(addresses) == 0 && !hostRouted {
		e.retireHTTPPoolScope(scope)
		return httpPoolBinding{}, fmt.Errorf("%w: destination resolved to no addresses", ErrTargetDenied)
	}
	addressSet := append([]netip.Addr(nil), addresses...)
	sort.Slice(addressSet, func(i, j int) bool {
		return addressSet[i].Compare(addressSet[j]) < 0
	})
	addressParts := make([]string, len(addressSet))
	for index, address := range addressSet {
		addressParts[index] = address.String()
	}
	tlsMode := httpConnectionTLSModePlain
	if grant.Destination.Scheme == "https" {
		tlsMode = httpConnectionTLSModeTLS12
	}
	return httpPoolBinding{
		scope: scope,
		key: httpPoolKey{
			connectionID:            grant.ConnectionID,
			connectionRevision:      grant.ConnectionRevision,
			privatePrefixes:         strings.Join(grant.PrivatePrefixes, ","),
			pluginInstanceID:        grant.PluginInstanceID,
			activeFingerprint:       grant.ActiveFingerprint,
			resourceScope:           grant.ResourceScope,
			connectorID:             grant.ConnectorID,
			destination:             grant.Destination,
			policyRevision:          grant.PolicyRevision,
			managementRevision:      grant.ManagementRevision,
			revokeEpoch:             grant.RevokeEpoch,
			runtimeGenerationID:     grant.RuntimeGenerationID,
			targetClassifierVersion: grant.TargetClassifierVersion,
			tlsMode:                 tlsMode,
			proxyMode:               proxyMode,
			resolvedAddressSet:      strings.Join(addressParts, ","),
		},
		addresses: append([]netip.Addr(nil), addresses...),
	}, nil
}

func (e *Executor) acquireHTTPPool(binding httpPoolBinding) (*httpConnectionPool, func(), error) {
	pools := &e.httpPools
	pools.mu.Lock()
	defer pools.mu.Unlock()
	if pools.closed {
		return nil, nil, ErrConnectionClosed
	}

	for _, pool := range pools.byKey {
		if pool.scope == binding.scope && pool.key != binding.key {
			pools.retireLocked(pool)
		}
	}
	if pool := pools.byKey[binding.key]; pool != nil {
		pools.sequence++
		pool.lastUsed = pools.sequence
		pool.active++
		return pool, pools.releaseFuncLocked(pool), nil
	}
	for pools.totalLocked() >= maxHTTPConnectionPools {
		candidate := pools.oldestIdleLocked()
		if candidate == nil {
			return nil, nil, fmt.Errorf("%w: http connection pool capacity reached", ErrRateLimited)
		}
		pools.retireLocked(candidate)
	}

	transport, err := e.newHTTPTransport(binding, nil)
	if err != nil {
		return nil, nil, err
	}
	pools.sequence++
	pool := &httpConnectionPool{
		key:       binding.key,
		scope:     binding.scope,
		transport: transport,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		active:   1,
		lastUsed: pools.sequence,
	}
	pools.byKey[binding.key] = pool
	return pool, pools.releaseFuncLocked(pool), nil
}

func newHTTPPoolTransport(binding httpPoolBinding, dialResolved func(context.Context, string, string, []netip.Addr) (net.Conn, error)) *http.Transport {
	destination := binding.key.destination
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			if err := validateHTTPPoolDial(destination, network, address); err != nil {
				return nil, err
			}
			return dialResolved(ctx, network, address, binding.addresses)
		},
		DisableKeepAlives:   false,
		MaxIdleConns:        maxHTTPIdleConnsPerHost,
		MaxIdleConnsPerHost: maxHTTPIdleConnsPerHost,
		MaxConnsPerHost:     maxHTTPConnectionsPerHost,
		IdleConnTimeout:     httpConnectionIdleTimeout,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

func validateHTTPPoolDial(destination Destination, network string, address string) error {
	if !strings.HasPrefix(strings.ToLower(network), "tcp") {
		return fmt.Errorf("%w: http transport requested non-tcp network", ErrConnectorDenied)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: http transport destination is invalid", ErrConnectorDenied)
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host != destination.Host || portText != strconv.Itoa(destination.Port) {
		return fmt.Errorf("%w: http transport destination changed", ErrConnectorDenied)
	}
	return nil
}

func (p *httpConnectionPools) releaseFuncLocked(pool *httpConnectionPool) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if pool.active <= 0 {
				return
			}
			pool.active--
			if pool.draining && pool.active == 0 {
				pool.transport.CloseIdleConnections()
				delete(p.draining, pool)
			}
			p.finishCloseLocked()
		})
	}
}

func (p *httpConnectionPools) retireLocked(pool *httpConnectionPool) {
	if pool == nil || pool.draining {
		return
	}
	if current := p.byKey[pool.key]; current == pool {
		delete(p.byKey, pool.key)
	}
	pool.draining = true
	pool.transport.CloseIdleConnections()
	if pool.active > 0 {
		p.draining[pool] = struct{}{}
	}
}

func (p *httpConnectionPools) oldestIdleLocked() *httpConnectionPool {
	var oldest *httpConnectionPool
	for _, pool := range p.byKey {
		if pool.active != 0 {
			continue
		}
		if oldest == nil || pool.lastUsed < oldest.lastUsed {
			oldest = pool
		}
	}
	return oldest
}

func (p *httpConnectionPools) totalLocked() int {
	return len(p.byKey) + len(p.draining)
}

func (p *httpConnectionPools) finishCloseLocked() {
	if p.closed && p.totalLocked() == 0 {
		p.closeDoneDo.Do(func() { close(p.closeDone) })
	}
}

func (e *Executor) retireHTTPPoolScope(scope httpPoolScope) {
	if e == nil {
		return
	}
	pools := &e.httpPools
	pools.mu.Lock()
	defer pools.mu.Unlock()
	for _, pool := range pools.byKey {
		if pool.scope == scope {
			pools.retireLocked(pool)
		}
	}
	pools.finishCloseLocked()
}

// Close rejects new requests, closes idle HTTP connections, and waits for in-flight responses to release their pools.
func (e *Executor) Close(ctx context.Context) error {
	if e == nil {
		return errors.New("network executor is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pools := &e.httpPools
	pools.mu.Lock()
	if !pools.closed {
		pools.closed = true
		for _, pool := range pools.byKey {
			pools.retireLocked(pool)
		}
		pools.finishCloseLocked()
	}
	done := pools.closeDone
	pools.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type httpPoolResponseBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (b *httpPoolResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

// Custom credentials use a dedicated transport so no TLS session can outlive
// its exact connection approval or be reused with another credential identity.
func (e *Executor) acquireHTTPPoolForTLS(binding httpPoolBinding, config *tls.Config) (*httpConnectionPool, func(), error) {
	if config == nil {
		return e.acquireHTTPPool(binding)
	}
	validated, err := validatedTLSConfig(config, binding.key.destination)
	if err != nil {
		return nil, nil, err
	}
	pools := &e.httpPools
	pools.mu.Lock()
	defer pools.mu.Unlock()
	if pools.closed {
		return nil, nil, ErrConnectionClosed
	}
	for pools.totalLocked() >= maxHTTPConnectionPools {
		candidate := pools.oldestIdleLocked()
		if candidate == nil {
			return nil, nil, ErrRateLimited
		}
		pools.retireLocked(candidate)
	}
	transport, err := e.newHTTPTransport(binding, validated)
	if err != nil {
		return nil, nil, err
	}
	pool := &httpConnectionPool{active: 1, draining: true, transport: transport, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	pools.draining[pool] = struct{}{}
	return pool, pools.releaseFuncLocked(pool), nil
}

// newHTTPTransport preserves the existing grant-keyed pool and retirement path
// for both host-routed HTTPS and address-pinned connections.
func (e *Executor) newHTTPTransport(binding httpPoolBinding, config *tls.Config) (HTTPTransport, error) {
	if binding.key.proxyMode == "host" {
		transport, err := e.hostHTTPTransport(binding.key.destination, config)
		if err != nil {
			return nil, err
		}
		if transport == nil {
			return nil, ErrConnectorDenied
		}
		value := reflect.ValueOf(transport)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				return nil, ErrConnectorDenied
			}
		}
		if base, ok := transport.(*http.Transport); ok {
			cloned := base.Clone()
			tlsConfig := cloned.TLSClientConfig
			if config != nil {
				tlsConfig = config
			}
			if tlsConfig == nil {
				tlsConfig = &tls.Config{}
			}
			checked, err := validatedTLSConfig(tlsConfig, binding.key.destination)
			if err != nil {
				return nil, err
			}
			cloned.TLSClientConfig = checked
			cloned.MaxIdleConns = maxHTTPIdleConnsPerHost
			cloned.MaxIdleConnsPerHost = maxHTTPIdleConnsPerHost
			cloned.MaxConnsPerHost = maxHTTPConnectionsPerHost
			cloned.IdleConnTimeout = httpConnectionIdleTimeout
			if config != nil {
				cloned.DisableKeepAlives = true
			}
			return cloned, nil
		}
		return transport, nil
	}
	transport := newHTTPPoolTransport(binding, e.dialResolved)
	if config != nil {
		transport.TLSClientConfig = config
		transport.DisableKeepAlives = true
	}
	return transport, nil
}
