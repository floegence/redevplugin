package connectivity

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestCompilePolicyNormalizesDeclaredTransports(t *testing.T) {
	policy, err := CompilePolicy(CompileRequest{
		PluginInstanceID:   "plugini_test",
		PluginID:           "com.example.net",
		ActiveFingerprint:  "sha256:fingerprint",
		PolicyRevision:     7,
		ManagementRevision: 11,
		RevokeEpoch:        3,
		Manifest: manifest.Manifest{
			NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{
				{ConnectorID: "http_api", Transport: "http", Scope: "user", Destinations: []string{"api.example.com", "https://api.example.com:8443"}},
				{ConnectorID: "socket", Transport: "websocket", Scope: "environment", Destinations: []string{"wss://stream.example.com"}},
				{ConnectorID: "mysql", Transport: "tcp", Scope: "environment", Destinations: []string{"db.example.com:3306"}},
				{ConnectorID: "metrics", Transport: "udp", Scope: "environment", Destinations: []string{"udp://metrics.example.com:8125"}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("CompilePolicy() error = %v", err)
	}
	if policy.TargetClassifierVersion != version.TargetClassifierVersion {
		t.Fatalf("classifier version = %q", policy.TargetClassifierVersion)
	}
	if len(policy.Connectors) != 4 {
		t.Fatalf("connector count = %d, want 4: %#v", len(policy.Connectors), policy.Connectors)
	}
	httpConnector := policy.Connectors[0]
	if httpConnector.ConnectorID != "http_api" || httpConnector.Destinations[0].Scheme != "https" || httpConnector.Destinations[0].Port != 443 {
		t.Fatalf("http connector mismatch: %#v", httpConnector)
	}
	if policy.Connectors[1].ConnectorID != "metrics" || policy.Connectors[1].Destinations[0].Transport != TransportUDP {
		t.Fatalf("udp connector mismatch: %#v", policy.Connectors[1])
	}
	if policy.Connectors[2].ConnectorID != "mysql" || policy.Connectors[2].Destinations[0].Port != 3306 {
		t.Fatalf("tcp connector mismatch: %#v", policy.Connectors[2])
	}
	if policy.Connectors[3].ConnectorID != "socket" || policy.Connectors[3].Destinations[0].Scheme != "wss" {
		t.Fatalf("websocket connector mismatch: %#v", policy.Connectors[3])
	}
}

func TestCompilePolicyRejectsBlockedTargets(t *testing.T) {
	cases := []struct {
		name        string
		transport   string
		destination string
	}{
		{name: "localhost", transport: "http", destination: "http://localhost"},
		{name: "private-ip", transport: "tcp", destination: "10.0.0.1:5432"},
		{name: "link-local-metadata", transport: "udp", destination: "169.254.169.254:53"},
		{name: "ipv6-localhost", transport: "tcp", destination: "[::1]:443"},
		{name: "metadata-host", transport: "websocket", destination: "wss://metadata.google.internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompilePolicy(CompileRequest{Manifest: manifest.Manifest{
				NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{{
					ConnectorID:  "blocked",
					Transport:    tc.transport,
					Scope:        "user",
					Destinations: []string{tc.destination},
				}}},
			}})
			if !errors.Is(err, ErrTargetDenied) {
				t.Fatalf("CompilePolicy() error = %v, want ErrTargetDenied", err)
			}
		})
	}
}

func TestParseDestinationRejectsURLDetails(t *testing.T) {
	if _, err := ParseDestination(TransportHTTP, "https://api.example.com/path"); !errors.Is(err, ErrInvalidConnector) {
		t.Fatalf("ParseDestination(path) error = %v, want ErrInvalidConnector", err)
	}
	if _, err := ParseDestination(TransportTCP, "db.example.com"); !errors.Is(err, ErrInvalidConnector) {
		t.Fatalf("ParseDestination(tcp without port) error = %v, want ErrInvalidConnector", err)
	}
}

func TestClassifierEvaluatesResolvedAddress(t *testing.T) {
	classifier := DefaultClassifier()
	destination := Destination{Transport: TransportTCP, Host: "db.example.com", Port: 5432}
	if err := classifier.EvaluateResolvedAddress(destination, netip.MustParseAddr("10.0.0.10")); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("EvaluateResolvedAddress(private) error = %v, want ErrTargetDenied", err)
	}
	if err := classifier.EvaluateResolvedAddress(destination, netip.MustParseAddr("8.8.8.8")); err != nil {
		t.Fatalf("EvaluateResolvedAddress(public) error = %v", err)
	}
}

func TestMemoryBrokerMintsBoundedConnectionGrant(t *testing.T) {
	policy, err := CompilePolicy(CompileRequest{
		PluginInstanceID:   "plugini_test",
		PluginID:           "com.example.net",
		ActiveFingerprint:  "sha256:fingerprint",
		PolicyRevision:     7,
		ManagementRevision: 11,
		RevokeEpoch:        3,
		Manifest: manifest.Manifest{
			NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{{
				ConnectorID:  "mysql",
				Transport:    "tcp",
				Scope:        "environment",
				Destinations: []string{"db.example.com:3306"},
			}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := NewMemoryBroker()
	if err := broker.InstallPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	grant, err := broker.MintConnectionGrant(context.Background(), GrantRequest{
		PluginInstanceID:    "plugini_test",
		ActiveFingerprint:   "sha256:fingerprint",
		PolicyRevision:      7,
		ManagementRevision:  11,
		RevokeEpoch:         3,
		ConnectorID:         "mysql",
		Transport:           TransportTCP,
		Destination:         "tcp://db.example.com:3306",
		RuntimeGenerationID: "runtime_gen_1",
		Now:                 now,
		TTL:                 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("MintConnectionGrant() error = %v", err)
	}
	if grant.GrantID == "" || grant.Destination.Host != "db.example.com" || grant.ExpiresAt != now.Add(MaxGrantTTL) {
		t.Fatalf("grant mismatch: %#v", grant)
	}
	if _, err := broker.MintConnectionGrant(context.Background(), GrantRequest{
		PluginInstanceID:   "plugini_test",
		ActiveFingerprint:  "sha256:fingerprint",
		PolicyRevision:     7,
		ManagementRevision: 11,
		RevokeEpoch:        3,
		ConnectorID:        "mysql",
		Transport:          TransportTCP,
		Destination:        "other.example.com:3306",
	}); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("MintConnectionGrant(undeclared) error = %v, want ErrTargetDenied", err)
	}
	if _, err := broker.MintConnectionGrant(context.Background(), GrantRequest{
		PluginInstanceID:   "plugini_test",
		ActiveFingerprint:  "sha256:fingerprint",
		PolicyRevision:     7,
		ManagementRevision: 11,
		RevokeEpoch:        4,
		ConnectorID:        "mysql",
		Transport:          TransportTCP,
		Destination:        "db.example.com:3306",
	}); !errors.Is(err, ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(stale) error = %v, want ErrConnectorDenied", err)
	}
}
