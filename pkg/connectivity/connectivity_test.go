package connectivity

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
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

func TestExecutorPerformsBoundedHTTPWithGrant(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.example.com" {
			t.Errorf("Host header = %q, want grant host", r.Host)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
		}
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(r.Method + " " + r.URL.Path + " " + string(body)))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	executor := NewExecutor(ExecutorOptions{MaxResponseBytes: 128, DialContext: mapDialer(listener.Addr().String())})
	response, err := executor.DoHTTP(context.Background(), HTTPRequest{
		Grant:  grant,
		Method: http.MethodPost,
		Path:   "/v1/resource",
		Body:   []byte("payload"),
		Now:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("DoHTTP() error = %v", err)
	}
	if response.StatusCode != http.StatusCreated ||
		response.Headers.Get("X-Test") != "ok" ||
		string(response.Body) != "POST /v1/resource payload" {
		t.Fatalf("HTTP response mismatch: %#v body=%q", response, response.Body)
	}
}

func TestExecutorRejectsHTTPRedirectAndOversizedResponse(t *testing.T) {
	redirectListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	redirectServer := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example.com/", http.StatusFound)
	})}
	go func() {
		_ = redirectServer.Serve(redirectListener)
	}()
	defer redirectServer.Close()
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	response, err := NewExecutor(ExecutorOptions{DialContext: mapDialer(redirectListener.Addr().String())}).DoHTTP(context.Background(), HTTPRequest{Grant: grant})
	if err != nil {
		t.Fatalf("DoHTTP(redirect) error = %v", err)
	}
	if response.StatusCode != http.StatusFound || len(response.Body) == 0 {
		t.Fatalf("redirect response mismatch: %#v body=%q", response, response.Body)
	}

	largeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	largeServer := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("too-large"))
	})}
	go func() {
		_ = largeServer.Serve(largeListener)
	}()
	defer largeServer.Close()
	largeGrant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	if _, err := NewExecutor(ExecutorOptions{MaxResponseBytes: 4, DialContext: mapDialer(largeListener.Addr().String())}).DoHTTP(context.Background(), HTTPRequest{Grant: largeGrant}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("DoHTTP(large) error = %v, want ErrResponseTooLarge", err)
	}
}

func TestExecutorTCPRoundTripUsesGrantEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		_, _ = conn.Write([]byte("tcp:" + string(buf[:n])))
	}()
	grant := testGrant(t, TransportTCP, "tcp://db.example.com:5432", time.Minute)
	response, err := NewExecutor(ExecutorOptions{DialContext: mapDialer(listener.Addr().String())}).TCPRoundTrip(context.Background(), TCPRoundTripRequest{
		Grant:        grant,
		Payload:      []byte("hello"),
		MaxReadBytes: 32,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatalf("TCPRoundTrip() error = %v", err)
	}
	if string(response.Payload) != "tcp:hello" {
		t.Fatalf("TCP payload = %q", response.Payload)
	}
	<-done
}

func TestExecutorUDPRoundTripUsesConnectedDestination(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = conn.WriteTo([]byte("udp:"+string(buf[:n])), addr)
	}()
	grant := testGrant(t, TransportUDP, "udp://metrics.example.com:8125", time.Minute)
	response, err := NewExecutor(ExecutorOptions{DialContext: mapDialer(conn.LocalAddr().String())}).UDPRoundTrip(context.Background(), UDPRoundTripRequest{
		Grant:        grant,
		Payload:      []byte("hello"),
		MaxReadBytes: 32,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatalf("UDPRoundTrip() error = %v", err)
	}
	if string(response.Payload) != "udp:hello" {
		t.Fatalf("UDP payload = %q", response.Payload)
	}
	<-done
}

func TestExecutorRejectsExpiredAndMismatchedGrants(t *testing.T) {
	grant := testGrant(t, TransportTCP, "127.0.0.1:443", -time.Second)
	if _, err := NewExecutor(ExecutorOptions{}).TCPRoundTrip(context.Background(), TCPRoundTripRequest{Grant: grant}); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("TCPRoundTrip(expired) error = %v, want ErrGrantExpired", err)
	}
	httpGrant := testGrant(t, TransportHTTP, "http://127.0.0.1", time.Minute)
	if _, err := NewExecutor(ExecutorOptions{}).TCPRoundTrip(context.Background(), TCPRoundTripRequest{Grant: httpGrant}); !errors.Is(err, ErrConnectorDenied) {
		t.Fatalf("TCPRoundTrip(http grant) error = %v, want ErrConnectorDenied", err)
	}
}

func testGrant(t *testing.T, transport Transport, rawDestination string, ttl time.Duration) ConnectionGrant {
	t.Helper()
	destination, err := ParseDestination(transport, rawDestination)
	if err != nil {
		t.Fatal(err)
	}
	return ConnectionGrant{
		GrantID:                 "netgrant_0123456789abcdef0123456789abcdef",
		PluginInstanceID:        "plugini_test",
		ActiveFingerprint:       "sha256:fingerprint",
		PolicyRevision:          1,
		ManagementRevision:      2,
		RevokeEpoch:             3,
		ConnectorID:             "test",
		Transport:               transport,
		Destination:             destination,
		RuntimeGenerationID:     "runtime_gen_1",
		TargetClassifierVersion: version.TargetClassifierVersion,
		ExpiresAt:               time.Now().UTC().Add(ttl),
	}
}

func TestParseDestinationAcceptsLoopbackForExecutorTestHelper(t *testing.T) {
	destination, err := ParseDestination(TransportTCP, net.JoinHostPort("127.0.0.1", strconv.Itoa(443)))
	if err != nil {
		t.Fatal(err)
	}
	if destination.Host != "127.0.0.1" || destination.Port != 443 {
		t.Fatalf("destination mismatch: %#v", destination)
	}
}

func mapDialer(target string) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network string, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, target)
	}
}
