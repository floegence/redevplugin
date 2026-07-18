package connectivity

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/version"
	"golang.org/x/net/http/httpguts"
)

type Transport string

const (
	TransportHTTP      Transport = "http"
	TransportWebSocket Transport = "websocket"
	TransportTCP       Transport = "tcp"
	TransportUDP       Transport = "udp"
)

type Scope string

const (
	ScopeUser        Scope = "user"
	ScopeEnvironment Scope = "environment"
)

const (
	DefaultGrantTTL = time.Minute
	MaxGrantTTL     = 5 * time.Minute
)

var (
	ErrInvalidConnector      = errors.New("network connector is invalid")
	ErrTargetDenied          = errors.New("network target denied")
	ErrConnectorDenied       = errors.New("network connector denied")
	ErrResourceScopeMismatch = errors.New("network resource scope mismatch")
	ErrGrantExpired          = errors.New("network grant expired")
	ErrRequestTooLarge       = errors.New("network request too large")
	ErrResponseTooLarge      = errors.New("network response too large")
	ErrRateLimited           = errors.New("network rate limited")
	ErrConnectionClosed      = errors.New("network connection closed")
	ErrWebSocketFailed       = errors.New("websocket handshake failed")
)

type Broker interface {
	InstallPolicy(ctx context.Context, policy PolicySet) error
	RemovePolicy(ctx context.Context, pluginInstanceID string) error
	MintConnectionGrant(ctx context.Context, req GrantRequest) (ConnectionGrant, error)
}

type Destination struct {
	Transport Transport `json:"transport"`
	Scheme    string    `json:"scheme,omitempty"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
}

func (d Destination) Canonical() string {
	if d.Scheme != "" {
		return string(d.Transport) + "://" + d.Host + ":" + strconv.Itoa(d.Port) + "#" + d.Scheme
	}
	return string(d.Transport) + "://" + d.Host + ":" + strconv.Itoa(d.Port)
}

type ConnectorPolicy struct {
	ConnectorID  string        `json:"connector_id"`
	Transport    Transport     `json:"transport"`
	Scope        Scope         `json:"scope"`
	Destinations []Destination `json:"destinations"`
	SecretRef    string        `json:"secret_ref,omitempty"`
}

type PolicySet struct {
	PluginInstanceID        string            `json:"plugin_instance_id"`
	PluginID                string            `json:"plugin_id"`
	ActiveFingerprint       string            `json:"active_fingerprint"`
	PolicyRevision          uint64            `json:"policy_revision"`
	ManagementRevision      uint64            `json:"management_revision"`
	RevokeEpoch             uint64            `json:"revoke_epoch"`
	TargetClassifierVersion string            `json:"target_classifier_version"`
	Connectors              []ConnectorPolicy `json:"connectors"`
}

type MemoryBroker struct {
	mu       sync.RWMutex
	policies map[policyOwnerKey]PolicySet
}

func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{policies: map[policyOwnerKey]PolicySet{}}
}

type policyOwnerKey struct {
	ownerEnvHash     string
	pluginInstanceID string
}

func authenticatedPolicyOwner(ctx context.Context, pluginInstanceID string) (sessionctx.Context, policyOwnerKey, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return sessionctx.Context{}, policyOwnerKey{}, fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidConnector)
	}
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return sessionctx.Context{}, policyOwnerKey{}, err
	}
	return session, policyOwnerKey{ownerEnvHash: session.OwnerEnvHash, pluginInstanceID: pluginInstanceID}, nil
}

func (b *MemoryBroker) InstallPolicy(ctx context.Context, policy PolicySet) error {
	if b == nil {
		return errors.New("connectivity broker is nil")
	}
	_, key, err := authenticatedPolicyOwner(ctx, policy.PluginInstanceID)
	if err != nil {
		return err
	}
	if !validActiveRevisionBinding(policy.PolicyRevision, policy.ManagementRevision, policy.RevokeEpoch) {
		return fmt.Errorf("%w: policy revision binding is invalid", ErrInvalidConnector)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.policies[key] = policy
	return nil
}

func (b *MemoryBroker) RemovePolicy(ctx context.Context, pluginInstanceID string) error {
	if b == nil {
		return errors.New("connectivity broker is nil")
	}
	_, key, err := authenticatedPolicyOwner(ctx, pluginInstanceID)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.policies, key)
	return nil
}

func (b *MemoryBroker) MintConnectionGrant(ctx context.Context, req GrantRequest) (ConnectionGrant, error) {
	if b == nil {
		return ConnectionGrant{}, errors.New("connectivity broker is nil")
	}
	session, key, err := authenticatedPolicyOwner(ctx, req.PluginInstanceID)
	if err != nil {
		return ConnectionGrant{}, err
	}
	b.mu.RLock()
	policy, ok := b.policies[key]
	b.mu.RUnlock()
	if !ok {
		return ConnectionGrant{}, fmt.Errorf("%w: policy is not installed for plugin instance %q", ErrConnectorDenied, req.PluginInstanceID)
	}
	return mintConnectionGrant(session, policy, req)
}

type CompileRequest struct {
	PluginInstanceID   string
	PluginID           string
	ActiveFingerprint  string
	PolicyRevision     uint64
	ManagementRevision uint64
	RevokeEpoch        uint64
	Manifest           manifest.Manifest
}

type Classifier struct {
	blockedRanges []netip.Prefix
	specialHosts  map[string]struct{}
}

var defaultBlockedIPRanges = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"192.175.48.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/96",
	"::1/128",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"3fff::/20",
	"5f00::/16",
	"2620:4f:8000::/48",
	"fc00::/7",
	"fe80::/10",
	"fec0::/10",
	"ff00::/8",
}

var defaultSpecialHosts = []string{
	"localhost",
	"metadata.google.internal",
	"metadata.goog",
	"instance-data",
	"instance-data.ec2.internal",
	"metadata.azure.internal",
	"169.254.169.254",
}

func DefaultClassifier() Classifier {
	ranges := make([]netip.Prefix, 0, len(defaultBlockedIPRanges))
	for _, cidr := range defaultBlockedIPRanges {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			panic(err)
		}
		ranges = append(ranges, prefix)
	}
	specialHosts := make(map[string]struct{}, len(defaultSpecialHosts))
	for _, host := range defaultSpecialHosts {
		specialHosts[host] = struct{}{}
	}
	return Classifier{blockedRanges: ranges, specialHosts: specialHosts}
}

func CompilePolicy(req CompileRequest) (PolicySet, error) {
	if !validStoredRevisionValues(req.PolicyRevision, req.ManagementRevision, req.RevokeEpoch) {
		return PolicySet{}, fmt.Errorf("%w: policy revision binding is invalid", ErrInvalidConnector)
	}
	classifier := DefaultClassifier()
	policy := PolicySet{
		PluginInstanceID:        strings.TrimSpace(req.PluginInstanceID),
		PluginID:                strings.TrimSpace(req.PluginID),
		ActiveFingerprint:       strings.TrimSpace(req.ActiveFingerprint),
		PolicyRevision:          req.PolicyRevision,
		ManagementRevision:      req.ManagementRevision,
		RevokeEpoch:             req.RevokeEpoch,
		TargetClassifierVersion: version.TargetClassifierVersion,
	}
	if req.Manifest.NetworkAccess == nil || len(req.Manifest.NetworkAccess.Connectors) == 0 {
		return policy, nil
	}
	seenConnectors := map[string]struct{}{}
	for i, connector := range req.Manifest.NetworkAccess.Connectors {
		compiled, err := compileConnector(classifier, connector)
		if err != nil {
			return PolicySet{}, fmt.Errorf("network_access.connectors[%d]: %w", i, err)
		}
		if _, ok := seenConnectors[compiled.ConnectorID]; ok {
			return PolicySet{}, fmt.Errorf("%w: connector_id %q must be unique", ErrInvalidConnector, compiled.ConnectorID)
		}
		seenConnectors[compiled.ConnectorID] = struct{}{}
		policy.Connectors = append(policy.Connectors, compiled)
	}
	sort.Slice(policy.Connectors, func(i, j int) bool {
		return policy.Connectors[i].ConnectorID < policy.Connectors[j].ConnectorID
	})
	return policy, nil
}

func compileConnector(classifier Classifier, connector manifest.NetworkConnectorSpec) (ConnectorPolicy, error) {
	connectorID := strings.TrimSpace(connector.ConnectorID)
	if connectorID == "" {
		return ConnectorPolicy{}, fmt.Errorf("%w: connector_id is required", ErrInvalidConnector)
	}
	transport := Transport(strings.TrimSpace(connector.Transport))
	if !ValidTransport(transport) {
		return ConnectorPolicy{}, fmt.Errorf("%w: transport %q is unsupported", ErrInvalidConnector, connector.Transport)
	}
	scope := Scope(strings.TrimSpace(connector.Scope))
	if scope != ScopeUser && scope != ScopeEnvironment {
		return ConnectorPolicy{}, fmt.Errorf("%w: scope must be user or environment", ErrInvalidConnector)
	}
	if len(connector.Destinations) == 0 {
		return ConnectorPolicy{}, fmt.Errorf("%w: destinations are required", ErrInvalidConnector)
	}
	destinations := make([]Destination, 0, len(connector.Destinations))
	seenDestinations := map[string]struct{}{}
	for i, raw := range connector.Destinations {
		destination, err := ParseDestination(transport, raw)
		if err != nil {
			return ConnectorPolicy{}, fmt.Errorf("destinations[%d]: %w", i, err)
		}
		if err := classifier.Evaluate(destination); err != nil {
			return ConnectorPolicy{}, fmt.Errorf("destinations[%d]: %w", i, err)
		}
		key := destination.Canonical()
		if _, ok := seenDestinations[key]; ok {
			continue
		}
		seenDestinations[key] = struct{}{}
		destinations = append(destinations, destination)
	}
	sort.Slice(destinations, func(i, j int) bool {
		return destinations[i].Canonical() < destinations[j].Canonical()
	})
	return ConnectorPolicy{
		ConnectorID:  connectorID,
		Transport:    transport,
		Scope:        scope,
		Destinations: destinations,
		SecretRef:    authSecretRef(connector.Auth),
	}, nil
}

func ValidTransport(transport Transport) bool {
	switch transport {
	case TransportHTTP, TransportWebSocket, TransportTCP, TransportUDP:
		return true
	default:
		return false
	}
}

func ParseDestination(transport Transport, raw string) (Destination, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Destination{}, fmt.Errorf("%w: destination is required", ErrInvalidConnector)
	}
	switch transport {
	case TransportHTTP:
		return parseURLDestination(transport, raw, "https", map[string]struct{}{"http": {}, "https": {}})
	case TransportWebSocket:
		return parseURLDestination(transport, raw, "wss", map[string]struct{}{"ws": {}, "wss": {}})
	case TransportTCP, TransportUDP:
		return parseEndpointDestination(transport, raw)
	default:
		return Destination{}, fmt.Errorf("%w: transport %q is unsupported", ErrInvalidConnector, transport)
	}
}

func parseURLDestination(transport Transport, raw string, defaultScheme string, allowedSchemes map[string]struct{}) (Destination, error) {
	value := raw
	if !strings.Contains(value, "://") {
		value = defaultScheme + "://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return Destination{}, fmt.Errorf("%w: parse destination: %v", ErrInvalidConnector, err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if _, ok := allowedSchemes[scheme]; !ok {
		return Destination{}, fmt.Errorf("%w: scheme %q is not allowed for %s", ErrInvalidConnector, parsed.Scheme, transport)
	}
	if parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Destination{}, fmt.Errorf("%w: destination must be an origin, not a URL with credentials, path, query, or fragment", ErrInvalidConnector)
	}
	host, err := normalizeHost(parsed.Hostname())
	if err != nil {
		return Destination{}, err
	}
	port, err := normalizePort(parsed.Port(), defaultPortForScheme(scheme))
	if err != nil {
		return Destination{}, err
	}
	return Destination{Transport: transport, Scheme: scheme, Host: host, Port: port}, nil
}

func parseEndpointDestination(transport Transport, raw string) (Destination, error) {
	value := raw
	expectedScheme := string(transport)
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return Destination{}, fmt.Errorf("%w: parse destination: %v", ErrInvalidConnector, err)
		}
		if !strings.EqualFold(parsed.Scheme, expectedScheme) {
			return Destination{}, fmt.Errorf("%w: scheme %q is not allowed for %s", ErrInvalidConnector, parsed.Scheme, transport)
		}
		if parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return Destination{}, fmt.Errorf("%w: destination must be a host:port endpoint", ErrInvalidConnector)
		}
		value = parsed.Host
	}
	hostPart, portPart, err := net.SplitHostPort(value)
	if err != nil {
		return Destination{}, fmt.Errorf("%w: tcp/udp destination must include host and port", ErrInvalidConnector)
	}
	host, err := normalizeHost(hostPart)
	if err != nil {
		return Destination{}, err
	}
	port, err := normalizePort(portPart, 0)
	if err != nil {
		return Destination{}, err
	}
	return Destination{Transport: transport, Host: host, Port: port}, nil
}

func normalizeHost(raw string) (string, error) {
	host := strings.TrimSpace(strings.TrimSuffix(raw, "."))
	if host == "" {
		return "", fmt.Errorf("%w: host is required", ErrInvalidConnector)
	}
	if strings.ContainsAny(host, "/?#@") {
		return "", fmt.Errorf("%w: host contains invalid characters", ErrInvalidConnector)
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return addr.String(), nil
	}
	ascii := strings.ToLower(host)
	if len(ascii) > 253 {
		return "", fmt.Errorf("%w: host is too long", ErrInvalidConnector)
	}
	labels := strings.Split(ascii, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("%w: host label is invalid", ErrInvalidConnector)
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", fmt.Errorf("%w: host must be ASCII DNS or IP literal", ErrInvalidConnector)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%w: host label cannot start or end with hyphen", ErrInvalidConnector)
		}
	}
	return ascii, nil
}

func normalizePort(raw string, defaultPort int) (int, error) {
	if raw == "" {
		if defaultPort <= 0 {
			return 0, fmt.Errorf("%w: port is required", ErrInvalidConnector)
		}
		return defaultPort, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: port is invalid", ErrInvalidConnector)
	}
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("%w: port is out of range", ErrInvalidConnector)
	}
	return port, nil
}

func defaultPortForScheme(scheme string) int {
	switch scheme {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	default:
		return 0
	}
}

func (c Classifier) Evaluate(destination Destination) error {
	host := strings.ToLower(destination.Host)
	if _, ok := c.specialHosts[host]; ok {
		return fmt.Errorf("%w: destination is blocked", ErrTargetDenied)
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return c.EvaluateResolvedAddress(destination, addr)
	}
	return nil
}

func (c Classifier) EvaluateResolvedAddress(destination Destination, addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: resolved address is invalid", ErrInvalidConnector)
	}
	addr = addr.Unmap()
	for _, prefix := range c.blockedRanges {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: resolved destination is blocked", ErrTargetDenied)
		}
	}
	return nil
}

type GrantRequest struct {
	PluginInstanceID    string
	ActiveFingerprint   string
	ResourceScope       sessionctx.ResourceScope
	PolicyRevision      uint64
	ManagementRevision  uint64
	RevokeEpoch         uint64
	ConnectorID         string
	Transport           Transport
	Destination         string
	RuntimeGenerationID string
	Now                 time.Time `json:"-"`
	TTL                 time.Duration
}

type ConnectionGrant struct {
	GrantID                 string                   `json:"grant_id"`
	PluginInstanceID        string                   `json:"plugin_instance_id"`
	ActiveFingerprint       string                   `json:"active_fingerprint"`
	ResourceScope           sessionctx.ResourceScope `json:"resource_scope"`
	PolicyRevision          uint64                   `json:"policy_revision"`
	ManagementRevision      uint64                   `json:"management_revision"`
	RevokeEpoch             uint64                   `json:"revoke_epoch"`
	ConnectorID             string                   `json:"connector_id"`
	Transport               Transport                `json:"transport"`
	Destination             Destination              `json:"destination"`
	RuntimeGenerationID     string                   `json:"runtime_generation_id,omitempty"`
	TargetClassifierVersion string                   `json:"target_classifier_version"`
	ExpiresAt               time.Time                `json:"expires_at"`
}

type HTTPRequest struct {
	Grant            ConnectionGrant `json:"grant"`
	Method           string          `json:"method"`
	Path             string          `json:"path,omitempty"`
	Query            url.Values      `json:"query,omitempty"`
	Headers          http.Header     `json:"headers,omitempty"`
	Body             []byte          `json:"-"`
	MaxRequestBytes  int64           `json:"max_request_bytes,omitempty"`
	MaxResponseBytes int64           `json:"max_response_bytes,omitempty"`
	MaxChunkBytes    int64           `json:"max_chunk_bytes,omitempty"`
	Timeout          time.Duration   `json:"timeout,omitempty"`
	Now              time.Time       `json:"-"`
}

type HTTPResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       []byte      `json:"-"`
}

type HTTPResponseChunk struct {
	Index int    `json:"index"`
	Data  []byte `json:"-"`
}

type HTTPStreamResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers,omitempty"`
	BytesRead  int64       `json:"bytes_read"`
	ChunkCount int         `json:"chunk_count"`
}

type TCPRoundTripRequest struct {
	Grant           ConnectionGrant `json:"grant"`
	Payload         []byte          `json:"-"`
	MaxRequestBytes int64           `json:"max_request_bytes,omitempty"`
	MaxReadBytes    int64           `json:"max_read_bytes,omitempty"`
	Timeout         time.Duration   `json:"timeout,omitempty"`
	Now             time.Time       `json:"-"`
}

type TCPRoundTripResponse struct {
	Payload []byte `json:"-"`
}

type UDPRoundTripRequest struct {
	Grant        ConnectionGrant `json:"grant"`
	Payload      []byte          `json:"-"`
	MaxReadBytes int64           `json:"max_read_bytes,omitempty"`
	Timeout      time.Duration   `json:"timeout,omitempty"`
	Now          time.Time       `json:"-"`
}

type UDPRoundTripResponse struct {
	Payload []byte `json:"-"`
}

type WebSocketMessageType string

const (
	WebSocketMessageText   WebSocketMessageType = "text"
	WebSocketMessageBinary WebSocketMessageType = "binary"
)

type WebSocketRoundTripRequest struct {
	Grant            ConnectionGrant      `json:"grant"`
	Path             string               `json:"path,omitempty"`
	Headers          http.Header          `json:"headers,omitempty"`
	MessageType      WebSocketMessageType `json:"message_type,omitempty"`
	Payload          []byte               `json:"-"`
	MaxRequestBytes  int64                `json:"max_request_bytes,omitempty"`
	MaxResponseBytes int64                `json:"max_response_bytes,omitempty"`
	Timeout          time.Duration        `json:"timeout,omitempty"`
	Now              time.Time            `json:"-"`
}

type WebSocketRoundTripResponse struct {
	MessageType WebSocketMessageType `json:"message_type"`
	Payload     []byte               `json:"-"`
}

type NetworkExecutor interface {
	DoHTTP(ctx context.Context, req HTTPRequest) (HTTPResponse, error)
	StreamHTTP(ctx context.Context, req HTTPRequest, onChunk func(HTTPResponseChunk) error) (HTTPStreamResponse, error)
	WebSocketRoundTrip(ctx context.Context, req WebSocketRoundTripRequest) (WebSocketRoundTripResponse, error)
	TCPRoundTrip(ctx context.Context, req TCPRoundTripRequest) (TCPRoundTripResponse, error)
	UDPRoundTrip(ctx context.Context, req UDPRoundTripRequest) (UDPRoundTripResponse, error)
}

type ExecutorOptions struct {
	Dialer           *net.Dialer
	LookupIPAddr     func(ctx context.Context, host string) ([]net.IPAddr, error)
	UDPRateLimiter   UDPRateLimiter
	MaxRequestBytes  int64
	MaxResponseBytes int64
	DefaultTimeout   time.Duration
	Now              func() time.Time
}

type Executor struct {
	dialContext      func(ctx context.Context, network string, address string) (net.Conn, error)
	resolveAddresses func(ctx context.Context, network string, address string) ([]netip.Addr, error)
	dialResolved     func(ctx context.Context, network string, address string, addresses []netip.Addr) (net.Conn, error)
	udpRateLimiter   UDPRateLimiter
	maxRequestBytes  int64
	maxResponseBytes int64
	defaultTimeout   time.Duration
	now              func() time.Time
	httpPools        httpConnectionPools
}

type executorNetworkOptions struct {
	dialContext      func(ctx context.Context, network string, address string) (net.Conn, error)
	resolveAddresses func(ctx context.Context, network string, address string) ([]netip.Addr, error)
	dialResolved     func(ctx context.Context, network string, address string, addresses []netip.Addr) (net.Conn, error)
}

const (
	DefaultMaxNetworkRequestBytes  = 1 << 20
	DefaultMaxNetworkResponseBytes = 1 << 20
	DefaultHTTPStreamChunkBytes    = 32 << 10
	DefaultNetworkTimeout          = 10 * time.Second
	DefaultUDPRateLimitRoundTrips  = 120
	DefaultUDPRateLimitWindow      = time.Second
	maxMemoryUDPRateLimitBuckets   = 65_536
)

type UDPRateLimitKey struct {
	PluginInstanceID  string      `json:"plugin_instance_id"`
	ActiveFingerprint string      `json:"active_fingerprint"`
	ConnectorID       string      `json:"connector_id"`
	GrantID           string      `json:"grant_id"`
	Destination       Destination `json:"destination"`
}

type UDPRateLimiter interface {
	AllowUDPRoundTrip(now time.Time, key UDPRateLimitKey) bool
}

type UDPRateLimiterFunc func(now time.Time, key UDPRateLimitKey) bool

func (f UDPRateLimiterFunc) AllowUDPRoundTrip(now time.Time, key UDPRateLimitKey) bool {
	if f == nil {
		return true
	}
	return f(now, key)
}

type UDPRateLimit struct {
	MaxRoundTrips int
	Window        time.Duration
}

type MemoryUDPRateLimiter struct {
	mu          sync.Mutex
	limit       UDPRateLimit
	maxBuckets  int
	windows     map[string]udpRateWindow
	expirations udpRateExpiryHeap
	nextVersion uint64
}

type udpRateWindow struct {
	startedAt time.Time
	lastSeen  time.Time
	count     int
	version   uint64
}

type udpRateExpiry struct {
	expiresAt time.Time
	version   uint64
	bucket    string
}

type udpRateExpiryHeap []udpRateExpiry

func (h udpRateExpiryHeap) Len() int { return len(h) }
func (h udpRateExpiryHeap) Less(i, j int) bool {
	if h[i].expiresAt.Equal(h[j].expiresAt) {
		if h[i].version == h[j].version {
			return h[i].bucket < h[j].bucket
		}
		return h[i].version < h[j].version
	}
	return h[i].expiresAt.Before(h[j].expiresAt)
}
func (h udpRateExpiryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *udpRateExpiryHeap) Push(value any) {
	*h = append(*h, value.(udpRateExpiry))
}
func (h *udpRateExpiryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = udpRateExpiry{}
	*h = old[:last]
	return value
}

func NewMemoryUDPRateLimiter(limit UDPRateLimit) *MemoryUDPRateLimiter {
	return &MemoryUDPRateLimiter{
		limit:      normalizeUDPRateLimit(limit),
		maxBuckets: maxMemoryUDPRateLimitBuckets,
		windows:    map[string]udpRateWindow{},
	}
}

func (l *MemoryUDPRateLimiter) AllowUDPRoundTrip(now time.Time, key UDPRateLimitKey) bool {
	if l == nil {
		return true
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	bucket := key.udpRateBucketKey()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	window, exists := l.windows[bucket]
	if !exists && len(l.windows) >= l.maxBuckets {
		return false
	}
	if window.startedAt.IsZero() || !now.Before(window.startedAt.Add(l.limit.Window)) {
		window = udpRateWindow{startedAt: now}
	}
	if !window.lastSeen.After(now) {
		window.lastSeen = now
	}
	version, ok := nextUDPWindowVersion(l.nextVersion)
	if !ok {
		return false
	}
	l.nextVersion = version
	window.version = version
	if window.count >= l.limit.MaxRoundTrips {
		l.windows[bucket] = window
		l.pushExpiryLocked(bucket, window)
		return false
	}
	window.count++
	l.windows[bucket] = window
	l.pushExpiryLocked(bucket, window)
	return true
}

func normalizeUDPRateLimit(limit UDPRateLimit) UDPRateLimit {
	if limit.MaxRoundTrips <= 0 {
		limit.MaxRoundTrips = DefaultUDPRateLimitRoundTrips
	}
	if limit.Window <= 0 {
		limit.Window = DefaultUDPRateLimitWindow
	}
	return limit
}

func (l *MemoryUDPRateLimiter) pruneLocked(now time.Time) {
	for l.expirations.Len() > 0 && l.expirations[0].expiresAt.Before(now) {
		expiry := heap.Pop(&l.expirations).(udpRateExpiry)
		if window, ok := l.windows[expiry.bucket]; ok && window.version == expiry.version {
			delete(l.windows, expiry.bucket)
		}
	}
}

func (l *MemoryUDPRateLimiter) pushExpiryLocked(bucket string, window udpRateWindow) {
	heap.Push(&l.expirations, udpRateExpiry{
		expiresAt: window.lastSeen.Add(2 * l.limit.Window),
		version:   window.version,
		bucket:    bucket,
	})
	if l.expirations.Len() > 4*len(l.windows)+64 {
		l.expirations = make(udpRateExpiryHeap, 0, len(l.windows))
		for bucket, window := range l.windows {
			l.expirations = append(l.expirations, udpRateExpiry{
				expiresAt: window.lastSeen.Add(2 * l.limit.Window),
				version:   window.version,
				bucket:    bucket,
			})
		}
		heap.Init(&l.expirations)
	}
}

func nextUDPWindowVersion(current uint64) (uint64, bool) {
	if current == ^uint64(0) {
		return 0, false
	}
	return current + 1, true
}

func (key UDPRateLimitKey) udpRateBucketKey() string {
	// GrantID stays available to custom limiters, but the default bucket omits it so fresh grants cannot bypass endpoint throttling.
	return key.PluginInstanceID + "\x00" + key.ActiveFingerprint + "\x00" + key.ConnectorID + "\x00" + key.Destination.Canonical()
}

func NewExecutor(options ExecutorOptions) *Executor {
	return newExecutor(options, executorNetworkOptions{})
}

func newExecutor(options ExecutorOptions, networkOptions executorNetworkOptions) *Executor {
	dialer := options.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	resolveAddresses := networkOptions.resolveAddresses
	if resolveAddresses == nil {
		resolveAddresses = guardedResolveAddresses(options.LookupIPAddr)
	}
	dialResolved := networkOptions.dialResolved
	if dialResolved == nil {
		dialResolved = func(ctx context.Context, network string, address string, addresses []netip.Addr) (net.Conn, error) {
			return dialResolvedAddresses(ctx, dialer, network, address, addresses)
		}
	}
	dialContext := networkOptions.dialContext
	if dialContext == nil {
		dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
			addresses, err := resolveAddresses(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return dialResolved(ctx, network, address, addresses)
		}
	}
	maxRequestBytes := options.MaxRequestBytes
	if maxRequestBytes <= 0 {
		maxRequestBytes = DefaultMaxNetworkRequestBytes
	}
	maxResponseBytes := options.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = DefaultMaxNetworkResponseBytes
	}
	udpRateLimiter := options.UDPRateLimiter
	if udpRateLimiter == nil {
		udpRateLimiter = NewMemoryUDPRateLimiter(UDPRateLimit{})
	}
	defaultTimeout := options.DefaultTimeout
	if defaultTimeout <= 0 {
		defaultTimeout = DefaultNetworkTimeout
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	executor := &Executor{
		dialContext:      dialContext,
		resolveAddresses: resolveAddresses,
		dialResolved:     dialResolved,
		udpRateLimiter:   udpRateLimiter,
		maxRequestBytes:  maxRequestBytes,
		maxResponseBytes: maxResponseBytes,
		defaultTimeout:   defaultTimeout,
		now:              now,
	}
	executor.httpPools.init()
	return executor
}

var _ NetworkExecutor = (*Executor)(nil)

func MintConnectionGrant(ctx context.Context, policy PolicySet, req GrantRequest) (ConnectionGrant, error) {
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return ConnectionGrant{}, err
	}
	return mintConnectionGrant(session, policy, req)
}

func mintConnectionGrant(session sessionctx.Context, policy PolicySet, req GrantRequest) (ConnectionGrant, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultGrantTTL
	}
	if ttl > MaxGrantTTL {
		ttl = MaxGrantTTL
	}
	if policy.PluginInstanceID == "" || policy.PluginInstanceID != req.PluginInstanceID {
		return ConnectionGrant{}, fmt.Errorf("%w: plugin_instance_id mismatch", ErrConnectorDenied)
	}
	if policy.ActiveFingerprint == "" || policy.ActiveFingerprint != req.ActiveFingerprint {
		return ConnectionGrant{}, fmt.Errorf("%w: active_fingerprint mismatch", ErrConnectorDenied)
	}
	if !validActiveRevisionBinding(policy.PolicyRevision, policy.ManagementRevision, policy.RevokeEpoch) ||
		!validActiveRevisionBinding(req.PolicyRevision, req.ManagementRevision, req.RevokeEpoch) {
		return ConnectionGrant{}, fmt.Errorf("%w: revision binding is invalid", ErrConnectorDenied)
	}
	if policy.PolicyRevision != req.PolicyRevision || policy.ManagementRevision != req.ManagementRevision || policy.RevokeEpoch != req.RevokeEpoch {
		return ConnectionGrant{}, fmt.Errorf("%w: stale policy revision", ErrConnectorDenied)
	}
	connector, ok := policy.connector(req.ConnectorID)
	if !ok {
		return ConnectionGrant{}, fmt.Errorf("%w: connector %q is not declared", ErrConnectorDenied, req.ConnectorID)
	}
	if connector.Transport != req.Transport {
		return ConnectionGrant{}, fmt.Errorf("%w: transport mismatch for connector %q", ErrConnectorDenied, req.ConnectorID)
	}
	expectedScope, err := session.ResourceScope(sessionctx.ScopeKind(connector.Scope))
	if err != nil {
		return ConnectionGrant{}, fmt.Errorf("%w: %w for connector %q", ErrConnectorDenied, ErrResourceScopeMismatch, req.ConnectorID)
	}
	if !req.ResourceScope.Matches(expectedScope) {
		return ConnectionGrant{}, fmt.Errorf("%w: %w for connector %q", ErrConnectorDenied, ErrResourceScopeMismatch, req.ConnectorID)
	}
	destination, err := ParseDestination(req.Transport, req.Destination)
	if err != nil {
		return ConnectionGrant{}, err
	}
	if err := DefaultClassifier().Evaluate(destination); err != nil {
		return ConnectionGrant{}, err
	}
	if !connector.allows(destination) {
		return ConnectionGrant{}, fmt.Errorf("%w: destination %s is not declared by connector %q", ErrTargetDenied, destination.Canonical(), req.ConnectorID)
	}
	grant := ConnectionGrant{
		PluginInstanceID:        policy.PluginInstanceID,
		ActiveFingerprint:       policy.ActiveFingerprint,
		ResourceScope:           expectedScope,
		PolicyRevision:          policy.PolicyRevision,
		ManagementRevision:      policy.ManagementRevision,
		RevokeEpoch:             policy.RevokeEpoch,
		ConnectorID:             connector.ConnectorID,
		Transport:               connector.Transport,
		Destination:             destination,
		RuntimeGenerationID:     req.RuntimeGenerationID,
		TargetClassifierVersion: policy.TargetClassifierVersion,
		ExpiresAt:               now.Add(ttl),
	}
	grantID, err := randomGrantID()
	if err != nil {
		return ConnectionGrant{}, err
	}
	grant.GrantID = grantID
	return grant, nil
}

func (e *Executor) DoHTTP(ctx context.Context, req HTTPRequest) (HTTPResponse, error) {
	if e == nil {
		return HTTPResponse{}, errors.New("network executor is nil")
	}
	resp, cancel, err := e.openHTTP(ctx, req)
	if err != nil {
		return HTTPResponse{}, err
	}
	defer cancel()
	defer resp.Body.Close()
	body, err := readBounded(resp.Body, responseLimit(req.MaxResponseBytes, e.maxResponseBytes))
	if err != nil {
		return HTTPResponse{}, err
	}
	return HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    cloneHTTPHeader(resp.Header),
		Body:       body,
	}, nil
}

func (e *Executor) StreamHTTP(ctx context.Context, req HTTPRequest, onChunk func(HTTPResponseChunk) error) (HTTPStreamResponse, error) {
	if e == nil {
		return HTTPStreamResponse{}, errors.New("network executor is nil")
	}
	if onChunk == nil {
		return HTTPStreamResponse{}, fmt.Errorf("%w: http response chunk handler is required", ErrInvalidConnector)
	}
	resp, cancel, err := e.openHTTP(ctx, req)
	if err != nil {
		return HTTPStreamResponse{}, err
	}
	defer cancel()
	defer resp.Body.Close()
	stats, err := streamBounded(resp.Body, responseLimit(req.MaxResponseBytes, e.maxResponseBytes), req.MaxChunkBytes, onChunk)
	if err != nil {
		return HTTPStreamResponse{}, contextOrNetworkError(ctx, err)
	}
	return HTTPStreamResponse{
		StatusCode: resp.StatusCode,
		Headers:    cloneHTTPHeader(resp.Header),
		BytesRead:  stats.bytesRead,
		ChunkCount: stats.chunkCount,
	}, nil
}

func (e *Executor) openHTTP(ctx context.Context, req HTTPRequest) (*http.Response, context.CancelFunc, error) {
	if e == nil {
		return nil, nil, errors.New("network executor is nil")
	}
	if err := validateGrantForTransport(req.Grant, TransportHTTP, req.Now, e.now); err != nil {
		return nil, nil, err
	}
	if err := checkSize(int64(len(req.Body)), e.maxRequestBytes, req.MaxRequestBytes, ErrRequestTooLarge); err != nil {
		return nil, nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method == http.MethodConnect {
		return nil, nil, fmt.Errorf("%w: HTTP CONNECT is disabled", ErrInvalidConnector)
	}
	path, err := cleanHTTPPath(req.Path)
	if err != nil {
		return nil, nil, err
	}
	headers, err := validateForwardHeaders(req.Headers)
	if err != nil {
		return nil, nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeoutOrDefault(req.Timeout, e.defaultTimeout))
	poolBinding, err := e.resolveHTTPPoolBinding(requestCtx, req.Grant)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	pool, releasePool, err := e.acquireHTTPPool(poolBinding)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	target := url.URL{
		Scheme:   req.Grant.Destination.Scheme,
		Host:     net.JoinHostPort(req.Grant.Destination.Host, strconv.Itoa(req.Grant.Destination.Port)),
		Path:     path,
		RawQuery: req.Query.Encode(),
	}
	httpReq, err := http.NewRequestWithContext(requestCtx, method, target.String(), bytes.NewReader(req.Body))
	if err != nil {
		releasePool()
		cancel()
		return nil, nil, err
	}
	httpReq.Host = hostHeader(req.Grant.Destination)
	for key, values := range headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}
	resp, err := pool.client.Do(httpReq)
	if err != nil {
		releasePool()
		cancel()
		return nil, nil, err
	}
	resp.Body = &httpPoolResponseBody{ReadCloser: resp.Body, release: releasePool}
	return resp, cancel, nil
}

func (e *Executor) WebSocketRoundTrip(ctx context.Context, req WebSocketRoundTripRequest) (WebSocketRoundTripResponse, error) {
	if e == nil {
		return WebSocketRoundTripResponse{}, errors.New("network executor is nil")
	}
	if err := validateGrantForTransport(req.Grant, TransportWebSocket, req.Now, e.now); err != nil {
		return WebSocketRoundTripResponse{}, err
	}
	if err := checkSize(int64(len(req.Payload)), e.maxRequestBytes, req.MaxRequestBytes, ErrRequestTooLarge); err != nil {
		return WebSocketRoundTripResponse{}, err
	}
	messageType := req.MessageType
	if messageType == "" {
		messageType = WebSocketMessageText
	}
	opcode, err := websocketOpcodeForMessageType(messageType)
	if err != nil {
		return WebSocketRoundTripResponse{}, err
	}
	path, err := cleanHTTPPath(req.Path)
	if err != nil {
		return WebSocketRoundTripResponse{}, err
	}
	headers, err := validateForwardHeaders(req.Headers)
	if err != nil {
		return WebSocketRoundTripResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeoutOrDefault(req.Timeout, e.defaultTimeout))
	defer cancel()
	conn, err := e.dialWebSocket(ctx, req.Grant)
	if err != nil {
		return WebSocketRoundTripResponse{}, err
	}
	defer conn.Close()
	stopCancelWatch := closeConnectionOnContextDone(ctx, conn)
	defer stopCancelWatch()
	deadline, _ := ctx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}
	reader := bufio.NewReader(conn)
	key, err := randomWebSocketKey()
	if err != nil {
		return WebSocketRoundTripResponse{}, err
	}
	if err := writeWebSocketHandshake(conn, req.Grant, path, key, headers); err != nil {
		return WebSocketRoundTripResponse{}, contextOrNetworkError(ctx, err)
	}
	if err := readWebSocketHandshake(reader, key); err != nil {
		return WebSocketRoundTripResponse{}, contextOrNetworkError(ctx, err)
	}
	if err := writeWebSocketFrame(conn, opcode, req.Payload); err != nil {
		return WebSocketRoundTripResponse{}, contextOrNetworkError(ctx, err)
	}
	responseOpcode, payload, err := readWebSocketDataFrame(reader, responseLimit(req.MaxResponseBytes, e.maxResponseBytes))
	if err != nil {
		return WebSocketRoundTripResponse{}, contextOrNetworkError(ctx, err)
	}
	responseType, err := websocketMessageTypeForOpcode(responseOpcode)
	if err != nil {
		return WebSocketRoundTripResponse{}, err
	}
	_ = writeWebSocketFrame(conn, 0x8, []byte{})
	return WebSocketRoundTripResponse{MessageType: responseType, Payload: payload}, nil
}

func (e *Executor) TCPRoundTrip(ctx context.Context, req TCPRoundTripRequest) (TCPRoundTripResponse, error) {
	if e == nil {
		return TCPRoundTripResponse{}, errors.New("network executor is nil")
	}
	if err := validateGrantForTransport(req.Grant, TransportTCP, req.Now, e.now); err != nil {
		return TCPRoundTripResponse{}, err
	}
	if err := checkSize(int64(len(req.Payload)), e.maxRequestBytes, req.MaxRequestBytes, ErrRequestTooLarge); err != nil {
		return TCPRoundTripResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeoutOrDefault(req.Timeout, e.defaultTimeout))
	defer cancel()
	conn, err := e.dialContext(ctx, "tcp", grantEndpoint(req.Grant))
	if err != nil {
		return TCPRoundTripResponse{}, err
	}
	defer conn.Close()
	stopCancelWatch := closeConnectionOnContextDone(ctx, conn)
	defer stopCancelWatch()
	deadline, _ := ctx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}
	if len(req.Payload) > 0 {
		if _, err := conn.Write(req.Payload); err != nil {
			return TCPRoundTripResponse{}, contextOrNetworkError(ctx, err)
		}
	}
	payload, err := readBounded(conn, responseLimit(req.MaxReadBytes, e.maxResponseBytes))
	if err != nil {
		return TCPRoundTripResponse{}, contextOrNetworkError(ctx, err)
	}
	return TCPRoundTripResponse{Payload: payload}, nil
}

func (e *Executor) UDPRoundTrip(ctx context.Context, req UDPRoundTripRequest) (UDPRoundTripResponse, error) {
	if e == nil {
		return UDPRoundTripResponse{}, errors.New("network executor is nil")
	}
	if err := validateGrantForTransport(req.Grant, TransportUDP, req.Now, e.now); err != nil {
		return UDPRoundTripResponse{}, err
	}
	if err := checkSize(int64(len(req.Payload)), e.maxRequestBytes, 0, ErrRequestTooLarge); err != nil {
		return UDPRoundTripResponse{}, err
	}
	limit := responseLimit(req.MaxReadBytes, e.maxResponseBytes)
	if limit <= 0 {
		return UDPRoundTripResponse{}, fmt.Errorf("%w: max_read_bytes must be positive", ErrResponseTooLarge)
	}
	now := req.Now
	if now.IsZero() {
		now = e.now()
	}
	if e.udpRateLimiter != nil && !e.udpRateLimiter.AllowUDPRoundTrip(now, udpRateLimitKey(req.Grant)) {
		return UDPRoundTripResponse{}, fmt.Errorf("%w: udp connector %q destination %s", ErrRateLimited, req.Grant.ConnectorID, req.Grant.Destination.Canonical())
	}
	ctx, cancel := context.WithTimeout(ctx, timeoutOrDefault(req.Timeout, e.defaultTimeout))
	defer cancel()
	conn, err := e.dialContext(ctx, "udp", grantEndpoint(req.Grant))
	if err != nil {
		return UDPRoundTripResponse{}, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}
	if len(req.Payload) > 0 {
		if _, err := conn.Write(req.Payload); err != nil {
			return UDPRoundTripResponse{}, err
		}
	}
	buf := make([]byte, limit)
	n, err := conn.Read(buf)
	if err != nil {
		return UDPRoundTripResponse{}, err
	}
	return UDPRoundTripResponse{Payload: append([]byte(nil), buf[:n]...)}, nil
}

func udpRateLimitKey(grant ConnectionGrant) UDPRateLimitKey {
	return UDPRateLimitKey{
		PluginInstanceID:  grant.PluginInstanceID,
		ActiveFingerprint: grant.ActiveFingerprint,
		ConnectorID:       grant.ConnectorID,
		GrantID:           grant.GrantID,
		Destination:       grant.Destination,
	}
}

func validateGrantForTransport(grant ConnectionGrant, transport Transport, now time.Time, nowFunc func() time.Time) error {
	if strings.TrimSpace(grant.GrantID) == "" ||
		strings.TrimSpace(grant.PluginInstanceID) == "" ||
		strings.TrimSpace(grant.ActiveFingerprint) == "" ||
		strings.TrimSpace(grant.ConnectorID) == "" {
		return fmt.Errorf("%w: grant identity is incomplete", ErrConnectorDenied)
	}
	if err := grant.ResourceScope.Validate(); err != nil {
		return fmt.Errorf("%w: %w: grant resource scope is invalid", ErrConnectorDenied, ErrResourceScopeMismatch)
	}
	if !validActiveRevisionBinding(grant.PolicyRevision, grant.ManagementRevision, grant.RevokeEpoch) {
		return fmt.Errorf("%w: grant revision binding is invalid", ErrConnectorDenied)
	}
	if strings.TrimSpace(grant.TargetClassifierVersion) != version.TargetClassifierVersion {
		return fmt.Errorf("%w: target classifier version mismatch", ErrConnectorDenied)
	}
	if grant.Transport != transport || grant.Destination.Transport != transport {
		return fmt.Errorf("%w: grant transport mismatch", ErrConnectorDenied)
	}
	if grant.Destination.Host == "" || grant.Destination.Port <= 0 {
		return fmt.Errorf("%w: grant destination is incomplete", ErrConnectorDenied)
	}
	if now.IsZero() {
		now = nowFunc()
	}
	if grant.ExpiresAt.IsZero() || !grant.ExpiresAt.After(now) {
		return ErrGrantExpired
	}
	return DefaultClassifier().Evaluate(grant.Destination)
}

func validStoredRevisionValues(policyRevision, managementRevision, revokeEpoch uint64) bool {
	return jsonvalue.IsSafeUnsignedInteger(policyRevision) &&
		jsonvalue.IsSafeUnsignedInteger(managementRevision) &&
		jsonvalue.IsSafeUnsignedInteger(revokeEpoch)
}

func validActiveRevisionBinding(policyRevision, managementRevision, revokeEpoch uint64) bool {
	return validStoredRevisionValues(policyRevision, managementRevision, revokeEpoch) && revokeEpoch > 0
}

func cleanHTTPPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/", nil
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("%w: http path must start with /", ErrInvalidConnector)
	}
	if strings.Contains(path, "://") || strings.ContainsAny(path, "?#\r\n") {
		return "", fmt.Errorf("%w: http path is invalid", ErrInvalidConnector)
	}
	return path, nil
}

func validateForwardHeaders(headers http.Header) (http.Header, error) {
	validated := make(http.Header, len(headers))
	for name, values := range headers {
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("%w: HTTP header name is invalid", ErrInvalidConnector)
		}
		lowerName := strings.ToLower(name)
		if forbiddenForwardHeader(lowerName) || strings.HasPrefix(lowerName, "sec-websocket-") {
			return nil, fmt.Errorf("%w: HTTP header is not allowed", ErrInvalidConnector)
		}
		canonicalName := http.CanonicalHeaderKey(name)
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, fmt.Errorf("%w: HTTP header value is invalid", ErrInvalidConnector)
			}
			validated[canonicalName] = append(validated[canonicalName], value)
		}
	}
	return validated, nil
}

func forbiddenForwardHeader(lowerName string) bool {
	switch lowerName {
	case "host",
		"connection",
		"upgrade",
		"transfer-encoding",
		"content-length",
		"te",
		"trailer",
		"keep-alive",
		"proxy-connection",
		"proxy-authorization",
		"proxy-authenticate",
		"alt-svc",
		"http2-settings":
		return true
	default:
		return false
	}
}

func checkSize(size int64, defaultLimit int64, overrideLimit int64, err error) error {
	limit := defaultLimit
	if overrideLimit > 0 && overrideLimit < limit {
		limit = overrideLimit
	}
	if limit > 0 && size > limit {
		return fmt.Errorf("%w: %d > %d", err, size, limit)
	}
	return nil
}

func responseLimit(overrideLimit int64, defaultLimit int64) int64 {
	if overrideLimit > 0 && overrideLimit < defaultLimit {
		return overrideLimit
	}
	return defaultLimit
}

func timeoutOrDefault(timeout time.Duration, defaultTimeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return defaultTimeout
}

func grantEndpoint(grant ConnectionGrant) string {
	return net.JoinHostPort(grant.Destination.Host, strconv.Itoa(grant.Destination.Port))
}

func closeConnectionOnContextDone(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}

func contextOrNetworkError(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func guardedDialContext(dialer *net.Dialer, lookupIPAddr func(context.Context, string) ([]net.IPAddr, error)) func(context.Context, string, string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	resolveAddresses := guardedResolveAddresses(lookupIPAddr)
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		addresses, err := resolveAddresses(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return dialResolvedAddresses(ctx, dialer, network, address, addresses)
	}
}

func guardedResolveAddresses(lookupIPAddr func(context.Context, string) ([]net.IPAddr, error)) func(context.Context, string, string) ([]netip.Addr, error) {
	if lookupIPAddr == nil {
		lookupIPAddr = net.DefaultResolver.LookupIPAddr
	}
	classifier := DefaultClassifier()
	return func(ctx context.Context, network string, address string) ([]netip.Addr, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, fmt.Errorf("%w: port is invalid", ErrInvalidConnector)
		}
		transport := TransportTCP
		if strings.HasPrefix(strings.ToLower(network), "udp") {
			transport = TransportUDP
		}
		destination := Destination{Transport: transport, Host: strings.Trim(host, "[]"), Port: port}
		var addresses []net.IPAddr
		if literal, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
			addresses = []net.IPAddr{{IP: net.IP(literal.AsSlice())}}
		} else {
			addresses, err = lookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("%w: destination resolved to no addresses", ErrTargetDenied)
		}
		resolvedAddresses := make([]netip.Addr, 0, len(addresses))
		seen := make(map[netip.Addr]struct{}, len(addresses))
		for _, resolved := range addresses {
			addr, ok := netip.AddrFromSlice(resolved.IP)
			if !ok {
				return nil, fmt.Errorf("%w: resolved address is invalid", ErrInvalidConnector)
			}
			addr = addr.Unmap()
			if err := classifier.EvaluateResolvedAddress(destination, addr); err != nil {
				return nil, err
			}
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			resolvedAddresses = append(resolvedAddresses, addr)
		}
		return resolvedAddresses, nil
	}
}

func dialResolvedAddresses(ctx context.Context, dialer *net.Dialer, network string, address string, resolvedAddresses []netip.Addr) (net.Conn, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var dialErrors []error
	for _, addr := range resolvedAddresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), portText))
		if err == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, err)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if len(dialErrors) == 0 {
		return nil, fmt.Errorf("%w: destination resolved to no addresses", ErrTargetDenied)
	}
	return nil, errors.Join(dialErrors...)
}

func (e *Executor) dialWebSocket(ctx context.Context, grant ConnectionGrant) (net.Conn, error) {
	address := grantEndpoint(grant)
	if grant.Destination.Scheme == "wss" {
		rawConn, err := e.dialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(rawConn, &tls.Config{ServerName: grant.Destination.Host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return e.dialContext(ctx, "tcp", address)
}

func randomWebSocketKey() (string, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func writeWebSocketHandshake(conn net.Conn, grant ConnectionGrant, path string, key string, headers http.Header) error {
	host := websocketHostHeader(grant.Destination)
	var request bytes.Buffer
	fmt.Fprintf(&request, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&request, "Host: %s\r\n", host)
	request.WriteString("Upgrade: websocket\r\n")
	request.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&request, "Sec-WebSocket-Key: %s\r\n", key)
	request.WriteString("Sec-WebSocket-Version: 13\r\n")
	for name, values := range headers {
		for _, value := range values {
			fmt.Fprintf(&request, "%s: %s\r\n", name, value)
		}
	}
	request.WriteString("\r\n")
	_, err := conn.Write(request.Bytes())
	return err
}

func readWebSocketHandshake(reader *bufio.Reader, key string) error {
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return fmt.Errorf("%w: read handshake response: %v", ErrWebSocketFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("%w: status %d", ErrWebSocketFailed, resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return fmt.Errorf("%w: missing websocket upgrade", ErrWebSocketFailed)
	}
	if !headerTokenContains(resp.Header.Values("Connection"), "upgrade") {
		return fmt.Errorf("%w: missing connection upgrade", ErrWebSocketFailed)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), websocketAcceptKey(key); got != want {
		return fmt.Errorf("%w: invalid accept key", ErrWebSocketFailed)
	}
	return nil
}

func websocketAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeWebSocketFrame(writer io.Writer, opcode byte, payload []byte) error {
	if opcode > 0xf {
		return fmt.Errorf("%w: websocket opcode is invalid", ErrInvalidConnector)
	}
	var header [14]byte
	header[0] = 0x80 | opcode
	maskKey := header[10:14]
	if _, err := rand.Read(maskKey); err != nil {
		return err
	}
	payloadLen := len(payload)
	switch {
	case payloadLen < 126:
		header[1] = 0x80 | byte(payloadLen)
		header = websocketHeaderWithMask(header, 2)
		if _, err := writer.Write(header[:6]); err != nil {
			return err
		}
	case payloadLen <= 65535:
		header[1] = 0x80 | 126
		binary.BigEndian.PutUint16(header[2:4], uint16(payloadLen))
		header = websocketHeaderWithMask(header, 4)
		if _, err := writer.Write(header[:8]); err != nil {
			return err
		}
	default:
		header[1] = 0x80 | 127
		binary.BigEndian.PutUint64(header[2:10], uint64(payloadLen))
		header = websocketHeaderWithMask(header, 10)
		if _, err := writer.Write(header[:14]); err != nil {
			return err
		}
	}
	masked := append([]byte(nil), payload...)
	for i := range masked {
		masked[i] ^= maskKey[i%4]
	}
	if len(masked) == 0 {
		return nil
	}
	_, err := writer.Write(masked)
	return err
}

func websocketHeaderWithMask(header [14]byte, maskOffset int) [14]byte {
	copy(header[maskOffset:maskOffset+4], header[10:14])
	return header
}

func readWebSocketDataFrame(reader *bufio.Reader, maxBytes int64) (byte, []byte, error) {
	if maxBytes <= 0 {
		return 0, nil, fmt.Errorf("%w: response limit must be positive", ErrResponseTooLarge)
	}
	for {
		opcode, payload, err := readWebSocketFrame(reader, maxBytes)
		if err != nil {
			return 0, nil, err
		}
		switch opcode {
		case 0x1, 0x2:
			return opcode, payload, nil
		case 0x8:
			return 0, nil, ErrConnectionClosed
		case 0x9:
			continue
		case 0xa:
			continue
		default:
			return 0, nil, fmt.Errorf("%w: unsupported websocket opcode %d", ErrWebSocketFailed, opcode)
		}
	}
}

func readWebSocketFrame(reader *bufio.Reader, maxBytes int64) (byte, []byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	if first&0x80 == 0 {
		return 0, nil, fmt.Errorf("%w: fragmented frames are not supported", ErrWebSocketFailed)
	}
	opcode := first & 0x0f
	masked := second&0x80 != 0
	length := uint64(second & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		if length > uint64(^uint(0)>>1) {
			return 0, nil, fmt.Errorf("%w: websocket payload length overflows", ErrResponseTooLarge)
		}
	}
	if length > uint64(maxBytes) {
		return 0, nil, fmt.Errorf("%w: response exceeded %d bytes", ErrResponseTooLarge, maxBytes)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func websocketOpcodeForMessageType(messageType WebSocketMessageType) (byte, error) {
	switch messageType {
	case WebSocketMessageText:
		return 0x1, nil
	case WebSocketMessageBinary:
		return 0x2, nil
	default:
		return 0, fmt.Errorf("%w: websocket message_type must be text or binary", ErrInvalidConnector)
	}
}

func websocketMessageTypeForOpcode(opcode byte) (WebSocketMessageType, error) {
	switch opcode {
	case 0x1:
		return WebSocketMessageText, nil
	case 0x2:
		return WebSocketMessageBinary, nil
	default:
		return "", fmt.Errorf("%w: unsupported websocket opcode %d", ErrWebSocketFailed, opcode)
	}
}

func hostHeader(destination Destination) string {
	host := strings.Trim(destination.Host, "[]")
	defaultAuthority := host
	if strings.Contains(host, ":") {
		defaultAuthority = "[" + host + "]"
	}
	if destination.Scheme == "ws" && destination.Port == 80 || destination.Scheme == "wss" && destination.Port == 443 {
		return defaultAuthority
	}
	if destination.Scheme == "http" && destination.Port == 80 || destination.Scheme == "https" && destination.Port == 443 {
		return defaultAuthority
	}
	return net.JoinHostPort(host, strconv.Itoa(destination.Port))
}

func websocketHostHeader(destination Destination) string {
	return hostHeader(destination)
}

func headerTokenContains(values []string, token string) bool {
	token = strings.ToLower(token)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.ToLower(strings.TrimSpace(part)) == token {
				return true
			}
		}
	}
	return false
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: response limit must be positive", ErrResponseTooLarge)
	}
	limited := io.LimitReader(reader, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%w: response exceeded %d bytes", ErrResponseTooLarge, maxBytes)
	}
	return body, nil
}

type httpStreamStats struct {
	bytesRead  int64
	chunkCount int
}

func streamBounded(reader io.Reader, maxBytes int64, maxChunkBytes int64, onChunk func(HTTPResponseChunk) error) (httpStreamStats, error) {
	if maxBytes <= 0 {
		return httpStreamStats{}, fmt.Errorf("%w: response limit must be positive", ErrResponseTooLarge)
	}
	if onChunk == nil {
		return httpStreamStats{}, fmt.Errorf("%w: http response chunk handler is required", ErrInvalidConnector)
	}
	buf := make([]byte, httpStreamChunkSize(maxChunkBytes))
	var stats httpStreamStats
	for {
		remaining := maxBytes - stats.bytesRead
		readSize := len(buf)
		if remaining < int64(readSize) {
			readSize = int(remaining + 1)
		}
		n, err := reader.Read(buf[:readSize])
		if n > 0 {
			if stats.bytesRead+int64(n) > maxBytes {
				return stats, fmt.Errorf("%w: response exceeded %d bytes", ErrResponseTooLarge, maxBytes)
			}
			chunk := append([]byte(nil), buf[:n]...)
			if err := onChunk(HTTPResponseChunk{Index: stats.chunkCount, Data: chunk}); err != nil {
				return stats, err
			}
			stats.bytesRead += int64(n)
			stats.chunkCount++
		}
		if errors.Is(err, io.EOF) {
			return stats, nil
		}
		if err != nil {
			return stats, err
		}
	}
}

func httpStreamChunkSize(maxChunkBytes int64) int {
	if maxChunkBytes <= 0 || maxChunkBytes > DefaultHTTPStreamChunkBytes {
		return DefaultHTTPStreamChunkBytes
	}
	return int(maxChunkBytes)
}

func cloneHTTPHeader(header http.Header) http.Header {
	cloned := http.Header{}
	for key, values := range header {
		for _, value := range values {
			cloned.Add(key, value)
		}
	}
	return cloned
}

func (p PolicySet) connector(connectorID string) (ConnectorPolicy, bool) {
	for _, connector := range p.Connectors {
		if connector.ConnectorID == connectorID {
			return connector, true
		}
	}
	return ConnectorPolicy{}, false
}

func (c ConnectorPolicy) allows(destination Destination) bool {
	for _, allowed := range c.Destinations {
		if allowed == destination {
			return true
		}
	}
	return false
}

func randomGrantID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "netgrant_" + hex.EncodeToString(raw[:]), nil
}

func authSecretRef(auth map[string]any) string {
	if auth == nil {
		return ""
	}
	value, _ := auth["secret_ref"].(string)
	return strings.TrimSpace(value)
}
