package connectivity

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/version"
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
	ErrInvalidConnector = errors.New("network connector is invalid")
	ErrTargetDenied     = errors.New("network target denied")
	ErrConnectorDenied  = errors.New("network connector denied")
	ErrGrantExpired     = errors.New("network grant expired")
	ErrRequestTooLarge  = errors.New("network request too large")
	ErrResponseTooLarge = errors.New("network response too large")
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
	policies map[string]PolicySet
}

func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{policies: map[string]PolicySet{}}
}

func (b *MemoryBroker) InstallPolicy(_ context.Context, policy PolicySet) error {
	if b == nil {
		return errors.New("connectivity broker is nil")
	}
	if strings.TrimSpace(policy.PluginInstanceID) == "" {
		return fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidConnector)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.policies[policy.PluginInstanceID] = policy
	return nil
}

func (b *MemoryBroker) RemovePolicy(_ context.Context, pluginInstanceID string) error {
	if b == nil {
		return errors.New("connectivity broker is nil")
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidConnector)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.policies, pluginInstanceID)
	return nil
}

func (b *MemoryBroker) MintConnectionGrant(ctx context.Context, req GrantRequest) (ConnectionGrant, error) {
	if b == nil {
		return ConnectionGrant{}, errors.New("connectivity broker is nil")
	}
	b.mu.RLock()
	policy, ok := b.policies[req.PluginInstanceID]
	b.mu.RUnlock()
	if !ok {
		return ConnectionGrant{}, fmt.Errorf("%w: policy is not installed for plugin instance %q", ErrConnectorDenied, req.PluginInstanceID)
	}
	return MintConnectionGrant(ctx, policy, req)
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

func DefaultClassifier() Classifier {
	cidrs := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	ranges := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			panic(err)
		}
		ranges = append(ranges, prefix)
	}
	return Classifier{
		blockedRanges: ranges,
		specialHosts: map[string]struct{}{
			"localhost":                {},
			"metadata.google.internal": {},
			"169.254.169.254":          {},
		},
	}
}

func CompilePolicy(req CompileRequest) (PolicySet, error) {
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
		return fmt.Errorf("%w: special host %q is blocked", ErrTargetDenied, destination.Host)
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
	for _, prefix := range c.blockedRanges {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: host %q resolved to blocked address %s in range %s", ErrTargetDenied, destination.Host, addr, prefix)
		}
	}
	return nil
}

type GrantRequest struct {
	PluginInstanceID    string
	ActiveFingerprint   string
	PolicyRevision      uint64
	ManagementRevision  uint64
	RevokeEpoch         uint64
	ConnectorID         string
	Transport           Transport
	Destination         string
	RuntimeGenerationID string
	Now                 time.Time
	TTL                 time.Duration
}

type ConnectionGrant struct {
	GrantID                 string      `json:"grant_id"`
	PluginInstanceID        string      `json:"plugin_instance_id"`
	ActiveFingerprint       string      `json:"active_fingerprint"`
	PolicyRevision          uint64      `json:"policy_revision"`
	ManagementRevision      uint64      `json:"management_revision"`
	RevokeEpoch             uint64      `json:"revoke_epoch"`
	ConnectorID             string      `json:"connector_id"`
	Transport               Transport   `json:"transport"`
	Destination             Destination `json:"destination"`
	RuntimeGenerationID     string      `json:"runtime_generation_id,omitempty"`
	TargetClassifierVersion string      `json:"target_classifier_version"`
	ExpiresAt               time.Time   `json:"expires_at"`
}

type HTTPRequest struct {
	Grant            ConnectionGrant `json:"grant"`
	Method           string          `json:"method"`
	Path             string          `json:"path,omitempty"`
	Headers          http.Header     `json:"headers,omitempty"`
	Body             []byte          `json:"-"`
	MaxRequestBytes  int64           `json:"max_request_bytes,omitempty"`
	MaxResponseBytes int64           `json:"max_response_bytes,omitempty"`
	Timeout          time.Duration   `json:"timeout,omitempty"`
	Now              time.Time       `json:"now,omitempty"`
}

type HTTPResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       []byte      `json:"-"`
}

type TCPRoundTripRequest struct {
	Grant        ConnectionGrant `json:"grant"`
	Payload      []byte          `json:"-"`
	MaxReadBytes int64           `json:"max_read_bytes,omitempty"`
	Timeout      time.Duration   `json:"timeout,omitempty"`
	Now          time.Time       `json:"now,omitempty"`
}

type TCPRoundTripResponse struct {
	Payload []byte `json:"-"`
}

type UDPRoundTripRequest struct {
	Grant        ConnectionGrant `json:"grant"`
	Payload      []byte          `json:"-"`
	MaxReadBytes int64           `json:"max_read_bytes,omitempty"`
	Timeout      time.Duration   `json:"timeout,omitempty"`
	Now          time.Time       `json:"now,omitempty"`
}

type UDPRoundTripResponse struct {
	Payload []byte `json:"-"`
}

type NetworkExecutor interface {
	DoHTTP(ctx context.Context, req HTTPRequest) (HTTPResponse, error)
	TCPRoundTrip(ctx context.Context, req TCPRoundTripRequest) (TCPRoundTripResponse, error)
	UDPRoundTrip(ctx context.Context, req UDPRoundTripRequest) (UDPRoundTripResponse, error)
}

type ExecutorOptions struct {
	HTTPClient       *http.Client
	Dialer           *net.Dialer
	DialContext      func(ctx context.Context, network string, address string) (net.Conn, error)
	MaxRequestBytes  int64
	MaxResponseBytes int64
	DefaultTimeout   time.Duration
	Now              func() time.Time
}

type Executor struct {
	httpClient       *http.Client
	dialContext      func(ctx context.Context, network string, address string) (net.Conn, error)
	maxRequestBytes  int64
	maxResponseBytes int64
	defaultTimeout   time.Duration
	now              func() time.Time
}

const (
	DefaultMaxNetworkRequestBytes  = 1 << 20
	DefaultMaxNetworkResponseBytes = 1 << 20
	DefaultNetworkTimeout          = 10 * time.Second
)

func NewExecutor(options ExecutorOptions) *Executor {
	dialer := options.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	dialContext := options.DialContext
	if dialContext == nil {
		dialContext = dialer.DialContext
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				Proxy:             nil,
				DialContext:       dialContext,
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
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
	defaultTimeout := options.DefaultTimeout
	if defaultTimeout <= 0 {
		defaultTimeout = DefaultNetworkTimeout
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Executor{
		httpClient:       httpClient,
		dialContext:      dialContext,
		maxRequestBytes:  maxRequestBytes,
		maxResponseBytes: maxResponseBytes,
		defaultTimeout:   defaultTimeout,
		now:              now,
	}
}

var _ NetworkExecutor = (*Executor)(nil)

func MintConnectionGrant(_ context.Context, policy PolicySet, req GrantRequest) (ConnectionGrant, error) {
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
	if err := validateGrantForTransport(req.Grant, TransportHTTP, req.Now, e.now); err != nil {
		return HTTPResponse{}, err
	}
	if err := checkSize(int64(len(req.Body)), e.maxRequestBytes, req.MaxRequestBytes, ErrRequestTooLarge); err != nil {
		return HTTPResponse{}, err
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method == http.MethodConnect {
		return HTTPResponse{}, fmt.Errorf("%w: HTTP CONNECT is disabled", ErrInvalidConnector)
	}
	path, err := cleanHTTPPath(req.Path)
	if err != nil {
		return HTTPResponse{}, err
	}
	target := url.URL{
		Scheme: req.Grant.Destination.Scheme,
		Host:   net.JoinHostPort(req.Grant.Destination.Host, strconv.Itoa(req.Grant.Destination.Port)),
		Path:   path,
	}
	ctx, cancel := context.WithTimeout(ctx, timeoutOrDefault(req.Timeout, e.defaultTimeout))
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(req.Body))
	if err != nil {
		return HTTPResponse{}, err
	}
	httpReq.Host = req.Grant.Destination.Host
	for key, values := range req.Headers {
		if !safeForwardHeader(key) {
			continue
		}
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}
	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return HTTPResponse{}, err
	}
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

func (e *Executor) TCPRoundTrip(ctx context.Context, req TCPRoundTripRequest) (TCPRoundTripResponse, error) {
	if e == nil {
		return TCPRoundTripResponse{}, errors.New("network executor is nil")
	}
	if err := validateGrantForTransport(req.Grant, TransportTCP, req.Now, e.now); err != nil {
		return TCPRoundTripResponse{}, err
	}
	if err := checkSize(int64(len(req.Payload)), e.maxRequestBytes, 0, ErrRequestTooLarge); err != nil {
		return TCPRoundTripResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeoutOrDefault(req.Timeout, e.defaultTimeout))
	defer cancel()
	conn, err := e.dialContext(ctx, "tcp", grantEndpoint(req.Grant))
	if err != nil {
		return TCPRoundTripResponse{}, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}
	if len(req.Payload) > 0 {
		if _, err := conn.Write(req.Payload); err != nil {
			return TCPRoundTripResponse{}, err
		}
	}
	payload, err := readBounded(conn, responseLimit(req.MaxReadBytes, e.maxResponseBytes))
	if err != nil {
		return TCPRoundTripResponse{}, err
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
	limit := responseLimit(req.MaxReadBytes, e.maxResponseBytes)
	if limit <= 0 {
		return UDPRoundTripResponse{}, fmt.Errorf("%w: max_read_bytes must be positive", ErrResponseTooLarge)
	}
	buf := make([]byte, limit)
	n, err := conn.Read(buf)
	if err != nil {
		return UDPRoundTripResponse{}, err
	}
	return UDPRoundTripResponse{Payload: append([]byte(nil), buf[:n]...)}, nil
}

func validateGrantForTransport(grant ConnectionGrant, transport Transport, now time.Time, nowFunc func() time.Time) error {
	if strings.TrimSpace(grant.GrantID) == "" ||
		strings.TrimSpace(grant.PluginInstanceID) == "" ||
		strings.TrimSpace(grant.ActiveFingerprint) == "" ||
		strings.TrimSpace(grant.ConnectorID) == "" {
		return fmt.Errorf("%w: grant identity is incomplete", ErrConnectorDenied)
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

func cleanHTTPPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/", nil
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("%w: http path must start with /", ErrInvalidConnector)
	}
	if strings.Contains(path, "://") || strings.ContainsAny(path, "\r\n") {
		return "", fmt.Errorf("%w: http path is invalid", ErrInvalidConnector)
	}
	return path, nil
}

func safeForwardHeader(key string) bool {
	key = http.CanonicalHeaderKey(strings.TrimSpace(key))
	switch key {
	case "", "Host", "Connection", "Proxy-Authorization", "Proxy-Authenticate", "Upgrade", "Alt-Svc":
		return false
	default:
		return true
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

func timeoutOrDefault(timeout time.Duration, fallback time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return fallback
}

func grantEndpoint(grant ConnectionGrant) string {
	return net.JoinHostPort(grant.Destination.Host, strconv.Itoa(grant.Destination.Port))
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
