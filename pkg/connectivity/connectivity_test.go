package connectivity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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

func TestExecutorHTTPHostHeaderIncludesNonDefaultPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.example.com:8080" {
			t.Errorf("Host header = %q, want grant host with port", r.Host)
		}
		_, _ = w.Write([]byte("ok"))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()
	grant := testGrant(t, TransportHTTP, "http://api.example.com:8080", time.Minute)
	response, err := NewExecutor(ExecutorOptions{DialContext: mapDialer(listener.Addr().String())}).DoHTTP(context.Background(), HTTPRequest{Grant: grant})
	if err != nil {
		t.Fatalf("DoHTTP() error = %v", err)
	}
	if string(response.Body) != "ok" {
		t.Fatalf("HTTP response body = %q", response.Body)
	}
}

func TestExecutorHTTPDisablesProxyConnectAndHopHeaders(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/proxy-check" || r.URL.IsAbs() {
			t.Errorf("request URI = %q absolute=%v; environment proxy may have been used", r.RequestURI, r.URL.IsAbs())
		}
		if r.Header.Get("Alt-Svc") != "" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Proxy-Authenticate") != "" {
			t.Errorf("proxy/alt-svc headers leaked: %#v", r.Header)
		}
		if r.Header.Get("X-Test") != "ok" {
			t.Errorf("X-Test header = %q, want forwarded safe header", r.Header.Get("X-Test"))
		}
		_, _ = w.Write([]byte("ok"))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	response, err := NewExecutor(ExecutorOptions{DialContext: mapDialer(listener.Addr().String())}).DoHTTP(context.Background(), HTTPRequest{
		Grant: grant,
		Path:  "/proxy-check",
		Headers: http.Header{
			"Alt-Svc":             []string{`h3=":443"`},
			"Connection":          []string{"keep-alive"},
			"Proxy-Authorization": []string{"Bearer secret"},
			"Proxy-Authenticate":  []string{"Basic realm=test"},
			"X-Test":              []string{"ok"},
		},
	})
	if err != nil {
		t.Fatalf("DoHTTP(proxy/header check) error = %v", err)
	}
	if string(response.Body) != "ok" {
		t.Fatalf("DoHTTP(proxy/header check) body = %q", response.Body)
	}

	dialed := false
	_, err = NewExecutor(ExecutorOptions{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dial should not be called for CONNECT")
	}}).DoHTTP(context.Background(), HTTPRequest{Grant: grant, Method: http.MethodConnect})
	if !errors.Is(err, ErrInvalidConnector) {
		t.Fatalf("DoHTTP(CONNECT) error = %v, want ErrInvalidConnector", err)
	}
	if dialed {
		t.Fatal("DoHTTP(CONNECT) dialed before rejecting method")
	}
}

func TestExecutorRejectsHTTPRedirectAndOversizedResponse(t *testing.T) {
	redirectListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var redirectRequests int
	redirectServer := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectRequests++
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
	if redirectRequests != 1 || response.Headers.Get("Location") != "https://other.example.com/" {
		t.Fatalf("redirect handling mismatch: requests=%d location=%q", redirectRequests, response.Headers.Get("Location"))
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

func TestExecutorRejectsDNSRebindingResolvedAddresses(t *testing.T) {
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	executor := NewExecutor(ExecutorOptions{
		Dialer: &net.Dialer{Timeout: time.Millisecond},
		LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("203.0.113.10")},
				{IP: net.ParseIP("10.0.0.10")},
			}, nil
		},
	})
	_, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant, Timeout: time.Millisecond})
	if !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("DoHTTP(rebinding DNS) error = %v, want ErrTargetDenied", err)
	}
}

func TestExecutorWebSocketRoundTripUsesGrantEndpoint(t *testing.T) {
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
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			t.Errorf("ReadRequest() error = %v", err)
			return
		}
		if req.Host != "stream.example.com" || req.URL.Path != "/events" || req.Header.Get("X-Test") != "ok" {
			t.Errorf("websocket request mismatch: host=%q path=%q x-test=%q", req.Host, req.URL.Path, req.Header.Get("X-Test"))
		}
		if req.Header.Get("Sec-WebSocket-Protocol") != "" {
			t.Errorf("Sec-WebSocket-Protocol should not be forwarded")
		}
		if err := writeTestWebSocketHandshake(conn, req.Header.Get("Sec-WebSocket-Key")); err != nil {
			t.Errorf("write handshake error = %v", err)
			return
		}
		opcode, payload, err := readWebSocketFrame(reader, 64)
		if err != nil {
			t.Errorf("read frame error = %v", err)
			return
		}
		if opcode != 0x1 || string(payload) != "hello" {
			t.Errorf("frame mismatch: opcode=%d payload=%q", opcode, payload)
			return
		}
		if err := writeTestWebSocketFrame(conn, 0x1, []byte("ws:"+string(payload))); err != nil {
			t.Errorf("write frame error = %v", err)
		}
	}()
	grant := testGrant(t, TransportWebSocket, "ws://stream.example.com", time.Minute)
	response, err := NewExecutor(ExecutorOptions{DialContext: mapDialer(listener.Addr().String())}).WebSocketRoundTrip(context.Background(), WebSocketRoundTripRequest{
		Grant:            grant,
		Path:             "/events",
		Headers:          http.Header{"X-Test": []string{"ok"}, "Sec-WebSocket-Protocol": []string{"blocked"}},
		MessageType:      WebSocketMessageText,
		Payload:          []byte("hello"),
		MaxResponseBytes: 32,
		Timeout:          time.Second,
	})
	if err != nil {
		t.Fatalf("WebSocketRoundTrip() error = %v", err)
	}
	if response.MessageType != WebSocketMessageText || string(response.Payload) != "ws:hello" {
		t.Fatalf("websocket response mismatch: %#v payload=%q", response, response.Payload)
	}
	<-done
}

func TestExecutorWebSocketRoundTripRejectsOversizedResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if err := writeTestWebSocketHandshake(conn, req.Header.Get("Sec-WebSocket-Key")); err != nil {
			return
		}
		if _, _, err := readWebSocketFrame(reader, 64); err != nil {
			return
		}
		_ = writeTestWebSocketFrame(conn, 0x2, []byte("too-large"))
	}()
	grant := testGrant(t, TransportWebSocket, "ws://stream.example.com", time.Minute)
	_, err = NewExecutor(ExecutorOptions{DialContext: mapDialer(listener.Addr().String())}).WebSocketRoundTrip(context.Background(), WebSocketRoundTripRequest{
		Grant:            grant,
		MessageType:      WebSocketMessageBinary,
		Payload:          []byte("ping"),
		MaxResponseBytes: 4,
		Timeout:          time.Second,
	})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("WebSocketRoundTrip(large) error = %v, want ErrResponseTooLarge", err)
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

func TestExecutorUDPRoundTripIgnoresMismatchedSource(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf[:n]) != "hello" {
			done <- fmt.Errorf("request payload = %q", buf[:n])
			return
		}
		attacker, err := net.Dial("udp", addr.String())
		if err != nil {
			done <- err
			return
		}
		if _, err := attacker.Write([]byte("udp:spoofed")); err != nil {
			_ = attacker.Close()
			done <- err
			return
		}
		_ = attacker.Close()
		time.Sleep(20 * time.Millisecond)
		if _, err := conn.WriteTo([]byte("udp:pinned"), addr); err != nil {
			done <- err
			return
		}
		done <- nil
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
	if string(response.Payload) != "udp:pinned" {
		t.Fatalf("UDP payload = %q, want pinned source response", response.Payload)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
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

func TestExecutorDefaultDialerRejectsBlockedResolvedAddress(t *testing.T) {
	grant := testGrant(t, TransportTCP, "db.example.com:443", time.Minute)
	executor := NewExecutor(ExecutorOptions{
		LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.12")}}, nil
		},
	})
	_, err := executor.TCPRoundTrip(context.Background(), TCPRoundTripRequest{Grant: grant, Timeout: time.Millisecond})
	if !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("TCPRoundTrip(resolved private address) error = %v, want %v", err, ErrTargetDenied)
	}
}

func TestExecutorDefaultDialerAllowsPublicResolvedAddress(t *testing.T) {
	grant := testGrant(t, TransportTCP, "db.example.com:443", time.Minute)
	executor := NewExecutor(ExecutorOptions{
		Dialer: &net.Dialer{Timeout: time.Millisecond},
		LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := executor.TCPRoundTrip(ctx, TCPRoundTripRequest{Grant: grant, Timeout: time.Millisecond})
	if errors.Is(err, ErrTargetDenied) {
		t.Fatalf("TCPRoundTrip(public resolved address) error = %v, want non-classifier dial failure", err)
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

func writeTestWebSocketHandshake(writer io.Writer, key string) error {
	_, err := fmt.Fprintf(writer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", websocketAcceptKey(key))
	return err
}

func writeTestWebSocketFrame(writer io.Writer, opcode byte, payload []byte) error {
	var header bytes.Buffer
	header.WriteByte(0x80 | opcode)
	switch {
	case len(payload) < 126:
		header.WriteByte(byte(len(payload)))
	case len(payload) <= 65535:
		header.WriteByte(126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		header.Write(ext[:])
	default:
		header.WriteByte(127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		header.Write(ext[:])
	}
	if _, err := writer.Write(header.Bytes()); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}
