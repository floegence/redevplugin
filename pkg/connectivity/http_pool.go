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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
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
	transport *http.Transport
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
	addresses, err := e.resolveAddresses(ctx, "tcp", grantEndpoint(grant))
	if err != nil {
		if errors.Is(err, ErrTargetDenied) {
			e.retireHTTPPoolScope(scope)
		}
		return httpPoolBinding{}, err
	}
	if len(addresses) == 0 {
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
			proxyMode:               httpConnectionProxyMode,
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

	transport := newHTTPPoolTransport(binding, e.dialResolved)
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
