package connectivity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
