package stress_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/httpadapter"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

type stressSummary struct {
	Category string         `json:"category"`
	Counters map[string]int `json:"counters"`
}

var stressEvidenceMu sync.Mutex

func TestMain(m *testing.M) {
	if os.Getenv("REDEVPLUGIN_STRESS_RUNTIME_HELPER") == "1" {
		runStressRuntimeHelper()
		return
	}
	os.Exit(m.Run())
}

func TestStressGateStreamBackpressureKeepsOperationStoreResponsive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	streams := stream.NewMemoryStore()
	operations := operation.NewMemoryStore()
	payload := make([]byte, 64)
	var backpressure atomic.Int64

	const workerCount = 24
	var wg sync.WaitGroup
	errs := make(chan error, workerCount+1)
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			streamID := fmt.Sprintf("stream_%02d", worker)
			if _, err := streams.Register(ctx, stream.RegisterRequest{
				StreamID:         streamID,
				PluginInstanceID: "plugini_stress_stream",
				Method:           "stress.logs.tail",
				Execution:        "stream",
				Direction:        stream.DirectionRead,
				MaxBufferedBytes: 256,
			}); err != nil {
				errs <- err
				return
			}
			for {
				if err := ctx.Err(); err != nil {
					errs <- err
					return
				}
				_, err := streams.Append(ctx, stream.AppendRequest{StreamID: streamID, Data: payload})
				if errors.Is(err, stream.ErrBackpressure) {
					backpressure.Add(1)
					return
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}(worker)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 96; i++ {
			if err := ctx.Err(); err != nil {
				errs <- err
				return
			}
			operationID := fmt.Sprintf("core_operation_%03d", i)
			if _, err := operations.Register(ctx, operation.RegisterRequest{
				OperationID:       operationID,
				PluginInstanceID:  "plugini_core_control",
				Method:            "core.diagnostics.ping",
				Execution:         "sync",
				DisableBehavior:   operation.DisableBehaviorCancel,
				UninstallBehavior: operation.UninstallBehaviorForceCleanupAllowed,
			}); err != nil {
				errs <- err
				return
			}
			if _, err := operations.Get(ctx, operationID); err != nil {
				errs <- err
				return
			}
			if _, err := operations.List(ctx, operation.ListRequest{PluginInstanceID: "plugini_core_control"}); err != nil {
				errs <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := backpressure.Load(); got != workerCount {
		t.Fatalf("backpressure count = %d, want %d", got, workerCount)
	}
	records, err := operations.List(ctx, operation.ListRequest{PluginInstanceID: "plugini_core_control"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 96 {
		t.Fatalf("operation records = %d, want 96", len(records))
	}
	logStressSummary(t, stressSummary{
		Category: "stream_backpressure",
		Counters: map[string]int{
			"workers":               workerCount,
			"backpressure_denials":  int(backpressure.Load()),
			"core_operation_checks": len(records),
		},
	})
}

func TestStressGateConnectivityGrantClassifierFlood(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	policy, err := connectivity.CompilePolicy(connectivity.CompileRequest{
		PluginInstanceID:   "plugini_stress_net",
		PluginID:           "com.example.stress.net",
		ActiveFingerprint:  "sha256:stress",
		PolicyRevision:     7,
		ManagementRevision: 11,
		RevokeEpoch:        3,
		Manifest: manifest.Manifest{
			NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{
				{ConnectorID: "api", Transport: "http", Scope: "user", Destinations: []string{"https://api.example.com"}},
				{ConnectorID: "api_plain", Transport: "http", Scope: "user", Destinations: []string{"http://api.example.com"}},
				{ConnectorID: "stream", Transport: "websocket", Scope: "user", Destinations: []string{"wss://stream.example.com"}},
				{ConnectorID: "stream_plain", Transport: "websocket", Scope: "user", Destinations: []string{"ws://stream.example.com"}},
				{ConnectorID: "mysql", Transport: "tcp", Scope: "environment", Destinations: []string{"db.example.com:3306"}},
				{ConnectorID: "metrics", Transport: "udp", Scope: "environment", Destinations: []string{"metrics.example.com:8125"}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := connectivity.NewMemoryBroker()
	if err := broker.InstallPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}

	requests := []connectivity.GrantRequest{
		grantRequest("api", connectivity.TransportHTTP, "https://api.example.com"),
		grantRequest("api_plain", connectivity.TransportHTTP, "http://api.example.com"),
		grantRequest("stream", connectivity.TransportWebSocket, "wss://stream.example.com"),
		grantRequest("stream_plain", connectivity.TransportWebSocket, "ws://stream.example.com"),
		grantRequest("mysql", connectivity.TransportTCP, "db.example.com:3306"),
		grantRequest("metrics", connectivity.TransportUDP, "metrics.example.com:8125"),
	}

	var minted atomic.Int64
	var denied atomic.Int64
	errs := make(chan error, len(requests)*64)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		for _, req := range requests {
			wg.Add(1)
			go func(i int, req connectivity.GrantRequest) {
				defer wg.Done()
				req.Now = time.Date(2026, 6, 30, 12, 0, i%60, 0, time.UTC)
				if i%5 == 0 {
					req.RevokeEpoch = 4
				}
				_, err := broker.MintConnectionGrant(ctx, req)
				if err == nil {
					minted.Add(1)
					return
				}
				if errors.Is(err, connectivity.ErrConnectorDenied) {
					denied.Add(1)
					return
				}
				errs <- err
			}(i, req)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	classifier := connectivity.DefaultClassifier()
	var blocked atomic.Int64
	for i := 0; i < 128; i++ {
		addr := netip.MustParseAddr("10.0.0.1")
		if i%2 == 1 {
			addr = netip.MustParseAddr("169.254.169.254")
		}
		err := classifier.EvaluateResolvedAddress(connectivity.Destination{Transport: connectivity.TransportTCP, Host: "db.example.com", Port: 3306}, addr)
		if !errors.Is(err, connectivity.ErrTargetDenied) {
			t.Fatalf("EvaluateResolvedAddress(%s) error = %v, want ErrTargetDenied", addr, err)
		}
		blocked.Add(1)
	}
	if minted.Load() == 0 || denied.Load() == 0 || blocked.Load() != 128 {
		t.Fatalf("unexpected grant/classifier counters: minted=%d denied=%d blocked=%d", minted.Load(), denied.Load(), blocked.Load())
	}
	udpCounters := stressUDPSourcePinCounters(t, ctx, broker)
	httpCounters := stressHTTPProxyDefenseCounters(t, ctx, broker)
	dnsRedirectCounters := stressDNSRedirectCounters(t, ctx, broker)
	httpStreamCounters := stressHTTPStreamingCounters(t, ctx, broker)
	tcpCounters := stressTCPDatabaseProtocolCounters(t, ctx, broker)
	webSocketCounters := stressWebSocketPressureCounters(t, ctx, broker)
	logStressSummary(t, stressSummary{
		Category: "connectivity_classifier",
		Counters: map[string]int{
			"minted_grants":                int(minted.Load()),
			"stale_grant_denials":          int(denied.Load()),
			"blocked_resolved_ips":         int(blocked.Load()),
			"connector_policy_count":       len(policy.Connectors),
			"http_redirects_not_followed":  dnsRedirectCounters.redirectsNotFollowed,
			"dns_rebinding_denials":        dnsRedirectCounters.rebindingDenials,
			"http_proxy_env_ignored":       httpCounters.proxyEnvIgnored,
			"http_connect_denials":         httpCounters.connectDenials,
			"alt_svc_headers_dropped":      httpCounters.altSvcHeadersDropped,
			"proxy_auth_headers_dropped":   httpCounters.proxyAuthHeadersDropped,
			"http_stream_cancelled_reads":  httpStreamCounters.cancelledReads,
			"http_stream_chunks":           httpStreamCounters.chunks,
			"http_stream_request_denials":  httpStreamCounters.requestDenials,
			"http_stream_response_denials": httpStreamCounters.responseDenials,
			"http_stream_round_trips":      httpStreamCounters.roundTrips,
			"tcp_cancelled_reads":          tcpCounters.cancelledReads,
			"tcp_database_round_trips":     tcpCounters.databaseRoundTrips,
			"tcp_request_denials":          tcpCounters.requestDenials,
			"tcp_response_denials":         tcpCounters.responseDenials,
			"udp_round_trips":              udpCounters.roundTrips,
			"udp_source_mismatch_dropped":  udpCounters.sourceMismatchDropped,
			"udp_rate_limit_denials":       udpCounters.rateLimitDenials,
			"websocket_round_trips":        webSocketCounters.roundTrips,
			"websocket_request_denials":    webSocketCounters.requestDenials,
			"websocket_response_denials":   webSocketCounters.responseDenials,
			"websocket_cancelled_reads":    webSocketCounters.cancelledReads,
		},
	})
}

type dnsRedirectCounters struct {
	redirectsNotFollowed int
	rebindingDenials     int
}

func stressDNSRedirectCounters(t *testing.T, ctx context.Context, broker connectivity.Broker) dnsRedirectCounters {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var redirectRequests atomic.Int64
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectRequests.Add(1)
		http.Redirect(w, r, "https://other.example.com/", http.StatusFound)
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()
	grant, err := broker.MintConnectionGrant(ctx, grantRequest("api_plain", connectivity.TransportHTTP, "http://api.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: stressMappedDialer(listener.Addr().String()),
	}).DoHTTP(ctx, connectivity.HTTPRequest{Grant: grant, Timeout: time.Second})
	if err != nil {
		t.Fatalf("DoHTTP(redirect evidence) error = %v", err)
	}
	if response.StatusCode != http.StatusFound || response.Headers.Get("Location") != "https://other.example.com/" || redirectRequests.Load() != 1 {
		t.Fatalf("redirect evidence mismatch: status=%d location=%q requests=%d", response.StatusCode, response.Headers.Get("Location"), redirectRequests.Load())
	}
	_, err = connectivity.NewExecutor(connectivity.ExecutorOptions{
		Dialer: &net.Dialer{Timeout: time.Millisecond},
		LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("203.0.113.10")},
				{IP: net.ParseIP("10.0.0.10")},
			}, nil
		},
	}).DoHTTP(ctx, connectivity.HTTPRequest{Grant: grant, Timeout: time.Millisecond})
	if !errors.Is(err, connectivity.ErrTargetDenied) {
		t.Fatalf("DoHTTP(DNS rebinding evidence) error = %v, want ErrTargetDenied", err)
	}
	return dnsRedirectCounters{redirectsNotFollowed: 1, rebindingDenials: 1}
}

type httpProxyDefenseCounters struct {
	proxyEnvIgnored         int
	connectDenials          int
	altSvcHeadersDropped    int
	proxyAuthHeadersDropped int
}

func stressHTTPProxyDefenseCounters(t *testing.T, ctx context.Context, broker connectivity.Broker) httpProxyDefenseCounters {
	t.Helper()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	type observation struct {
		proxyEnvIgnored         bool
		altSvcHeadersDropped    bool
		proxyAuthHeadersDropped bool
	}
	observed := make(chan observation, 1)
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- observation{
			proxyEnvIgnored:         r.RequestURI == "/proxy-check" && !r.URL.IsAbs(),
			altSvcHeadersDropped:    r.Header.Get("Alt-Svc") == "",
			proxyAuthHeadersDropped: r.Header.Get("Proxy-Authorization") == "" && r.Header.Get("Proxy-Authenticate") == "",
		}
		_, _ = w.Write([]byte("ok"))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()
	grant, err := broker.MintConnectionGrant(ctx, grantRequest("api_plain", connectivity.TransportHTTP, "http://api.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: stressMappedDialer(listener.Addr().String()),
	}).DoHTTP(ctx, connectivity.HTTPRequest{
		Grant: grant,
		Path:  "/proxy-check",
		Headers: http.Header{
			"Alt-Svc":             []string{`h3=":443"`},
			"Connection":          []string{"keep-alive"},
			"Proxy-Authorization": []string{"Bearer secret"},
			"Proxy-Authenticate":  []string{"Basic realm=test"},
			"X-Test":              []string{"ok"},
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("DoHTTP(proxy defense) error = %v", err)
	}
	if string(response.Body) != "ok" {
		t.Fatalf("DoHTTP(proxy defense) body = %q", response.Body)
	}
	var result httpProxyDefenseCounters
	select {
	case got := <-observed:
		if !got.proxyEnvIgnored || !got.altSvcHeadersDropped || !got.proxyAuthHeadersDropped {
			t.Fatalf("proxy defense observation mismatch: %#v", got)
		}
		result.proxyEnvIgnored = 1
		result.altSvcHeadersDropped = 1
		result.proxyAuthHeadersDropped = 1
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	dialed := false
	_, err = connectivity.NewExecutor(connectivity.ExecutorOptions{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dial should not be called for CONNECT")
	}}).DoHTTP(ctx, connectivity.HTTPRequest{Grant: grant, Method: http.MethodConnect})
	if !errors.Is(err, connectivity.ErrInvalidConnector) {
		t.Fatalf("DoHTTP(CONNECT) error = %v, want ErrInvalidConnector", err)
	}
	if dialed {
		t.Fatal("DoHTTP(CONNECT) dialed before rejecting method")
	}
	result.connectDenials = 1
	return result
}

type httpStreamingCounters struct {
	roundTrips      int
	chunks          int
	requestDenials  int
	responseDenials int
	cancelledReads  int
}

func stressHTTPStreamingCounters(t *testing.T, ctx context.Context, broker connectivity.Broker) httpStreamingCounters {
	t.Helper()
	grant, err := broker.MintConnectionGrant(ctx, grantRequest("api_plain", connectivity.TransportHTTP, "http://api.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	counters := httpStreamingCounters{}

	successAddr, stopSuccess := startStressHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/stream" {
			t.Errorf("http stream path = %q, want /v1/stream", r.URL.Path)
		}
		w.Header().Set("X-Stress", "stream")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("one"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("two"))
	}))
	var streamed bytes.Buffer
	response, err := connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: stressMappedDialer(successAddr),
	}).StreamHTTP(ctx, connectivity.HTTPRequest{
		Grant:            grant,
		Path:             "/v1/stream",
		MaxResponseBytes: 16,
		MaxChunkBytes:    3,
		Timeout:          time.Second,
	}, func(chunk connectivity.HTTPResponseChunk) error {
		_, _ = streamed.Write(chunk.Data)
		counters.chunks++
		return nil
	})
	stopSuccess()
	if err != nil {
		t.Fatalf("StreamHTTP(stress success) error = %v", err)
	}
	if response.StatusCode != http.StatusAccepted || response.Headers.Get("X-Stress") != "stream" || response.BytesRead != 6 || response.ChunkCount != counters.chunks || streamed.String() != "onetwo" {
		t.Fatalf("StreamHTTP(stress success) response=%#v chunks=%d body=%q", response, counters.chunks, streamed.String())
	}
	counters.roundTrips = 1

	dialed := false
	_, err = connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("dial should not be called for oversized http stream request")
		},
	}).StreamHTTP(ctx, connectivity.HTTPRequest{
		Grant:           grant,
		Body:            []byte("too-large"),
		MaxRequestBytes: 4,
		Timeout:         time.Second,
	}, func(connectivity.HTTPResponseChunk) error {
		return nil
	})
	if !errors.Is(err, connectivity.ErrRequestTooLarge) {
		t.Fatalf("StreamHTTP(stress request limit) error = %v, want ErrRequestTooLarge", err)
	}
	if dialed {
		t.Fatal("StreamHTTP(stress request limit) dialed before rejecting oversized request")
	}
	counters.requestDenials = 1

	largeAddr, stopLarge := startStressHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("too-large"))
	}))
	_, err = connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: stressMappedDialer(largeAddr),
	}).StreamHTTP(ctx, connectivity.HTTPRequest{
		Grant:            grant,
		MaxResponseBytes: 4,
		MaxChunkBytes:    4,
		Timeout:          time.Second,
	}, func(connectivity.HTTPResponseChunk) error {
		return nil
	})
	stopLarge()
	if !errors.Is(err, connectivity.ErrResponseTooLarge) {
		t.Fatalf("StreamHTTP(stress response limit) error = %v, want ErrResponseTooLarge", err)
	}
	counters.responseDenials = 1

	headersSent := make(chan struct{})
	releaseBlockedServer := make(chan struct{})
	var releaseOnce sync.Once
	releaseServer := func() {
		releaseOnce.Do(func() {
			close(releaseBlockedServer)
		})
	}
	blockedAddr, stopBlocked := startStressHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		close(headersSent)
		<-releaseBlockedServer
	}))
	cancelCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		_, err := connectivity.NewExecutor(connectivity.ExecutorOptions{
			DialContext: stressMappedDialer(blockedAddr),
		}).StreamHTTP(cancelCtx, connectivity.HTTPRequest{
			Grant:            grant,
			MaxResponseBytes: 32,
			Timeout:          5 * time.Second,
		}, func(connectivity.HTTPResponseChunk) error {
			return nil
		})
		errCh <- err
	}()
	select {
	case <-headersSent:
	case <-time.After(time.Second):
		cancel()
		releaseServer()
		stopBlocked()
		t.Fatal("StreamHTTP(stress cancel) server did not send headers")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			releaseServer()
			stopBlocked()
			t.Fatalf("StreamHTTP(stress cancel) error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		releaseServer()
		stopBlocked()
		t.Fatal("StreamHTTP(stress cancel) did not stop promptly")
	}
	releaseServer()
	stopBlocked()
	counters.cancelledReads = 1

	return counters
}

func startStressHTTPServer(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: handler}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- err
		}
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = server.Close()
			select {
			case err, ok := <-done:
				if ok && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("http stress server did not stop")
			}
		})
	}
	return listener.Addr().String(), stop
}

type tcpDatabaseProtocolCounters struct {
	databaseRoundTrips int
	requestDenials     int
	responseDenials    int
	cancelledReads     int
}

func stressTCPDatabaseProtocolCounters(t *testing.T, ctx context.Context, broker connectivity.Broker) tcpDatabaseProtocolCounters {
	t.Helper()
	grant, err := broker.MintConnectionGrant(ctx, grantRequest("mysql", connectivity.TransportTCP, "db.example.com:3306"))
	if err != nil {
		t.Fatal(err)
	}
	counters := tcpDatabaseProtocolCounters{}

	successAddr, stopSuccess := startStressTCPServer(t, func(reader *bufio.Reader, conn net.Conn) error {
		query, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if query != "QUERY users\n" {
			return fmt.Errorf("tcp mock database query = %q", query)
		}
		_, err = conn.Write([]byte("RESULT rows=1\n"))
		return err
	})
	response, err := connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: stressMappedDialer(successAddr),
	}).TCPRoundTrip(ctx, connectivity.TCPRoundTripRequest{
		Grant:           grant,
		Payload:         []byte("QUERY users\n"),
		MaxRequestBytes: 64,
		MaxReadBytes:    32,
		Timeout:         time.Second,
	})
	stopSuccess()
	if err != nil {
		t.Fatalf("TCPRoundTrip(mock database) error = %v", err)
	}
	if string(response.Payload) != "RESULT rows=1\n" {
		t.Fatalf("TCPRoundTrip(mock database) payload = %q", response.Payload)
	}
	counters.databaseRoundTrips = 1

	dialed := false
	_, err = connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("dial should not be called for oversized tcp request")
		},
	}).TCPRoundTrip(ctx, connectivity.TCPRoundTripRequest{
		Grant:           grant,
		Payload:         []byte("QUERY oversized\n"),
		MaxRequestBytes: 4,
		Timeout:         time.Second,
	})
	if !errors.Is(err, connectivity.ErrRequestTooLarge) {
		t.Fatalf("TCPRoundTrip(stress request limit) error = %v, want ErrRequestTooLarge", err)
	}
	if dialed {
		t.Fatal("TCPRoundTrip(stress request limit) dialed before rejecting oversized request")
	}
	counters.requestDenials = 1

	largeAddr, stopLarge := startStressTCPServer(t, func(reader *bufio.Reader, conn net.Conn) error {
		if _, err := reader.ReadString('\n'); err != nil {
			return err
		}
		_, err := conn.Write([]byte("RESULT too-large\n"))
		return err
	})
	_, err = connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: stressMappedDialer(largeAddr),
	}).TCPRoundTrip(ctx, connectivity.TCPRoundTripRequest{
		Grant:        grant,
		Payload:      []byte("QUERY users\n"),
		MaxReadBytes: 4,
		Timeout:      time.Second,
	})
	stopLarge()
	if !errors.Is(err, connectivity.ErrResponseTooLarge) {
		t.Fatalf("TCPRoundTrip(stress response limit) error = %v, want ErrResponseTooLarge", err)
	}
	counters.responseDenials = 1

	requestRead := make(chan struct{})
	releaseBlockedServer := make(chan struct{})
	var releaseOnce sync.Once
	releaseServer := func() {
		releaseOnce.Do(func() {
			close(releaseBlockedServer)
		})
	}
	blockedAddr, stopBlocked := startStressTCPServer(t, func(reader *bufio.Reader, _ net.Conn) error {
		if _, err := reader.ReadString('\n'); err != nil {
			return err
		}
		close(requestRead)
		<-releaseBlockedServer
		return nil
	})
	cancelCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		_, err := connectivity.NewExecutor(connectivity.ExecutorOptions{
			DialContext: stressMappedDialer(blockedAddr),
		}).TCPRoundTrip(cancelCtx, connectivity.TCPRoundTripRequest{
			Grant:        grant,
			Payload:      []byte("QUERY cancel\n"),
			MaxReadBytes: 32,
			Timeout:      5 * time.Second,
		})
		errCh <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		cancel()
		releaseServer()
		stopBlocked()
		t.Fatal("TCPRoundTrip(stress cancel) server did not receive query")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			releaseServer()
			stopBlocked()
			t.Fatalf("TCPRoundTrip(stress cancel) error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		releaseServer()
		stopBlocked()
		t.Fatal("TCPRoundTrip(stress cancel) did not stop promptly")
	}
	releaseServer()
	stopBlocked()
	counters.cancelledReads = 1

	return counters
}

func startStressTCPServer(t *testing.T, handler func(*bufio.Reader, net.Conn) error) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			done <- err
			return
		}
		defer conn.Close()
		if err := handler(bufio.NewReader(conn), conn); err != nil {
			done <- err
			return
		}
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = listener.Close()
			select {
			case err, ok := <-done:
				if ok && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("tcp stress server did not stop")
			}
		})
	}
	return listener.Addr().String(), stop
}

type webSocketPressureCounters struct {
	roundTrips      int
	requestDenials  int
	responseDenials int
	cancelledReads  int
}

func stressWebSocketPressureCounters(t *testing.T, ctx context.Context, broker connectivity.Broker) webSocketPressureCounters {
	t.Helper()
	grant, err := broker.MintConnectionGrant(ctx, grantRequest("stream_plain", connectivity.TransportWebSocket, "ws://stream.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	counters := webSocketPressureCounters{}

	successAddr, stopSuccess := startStressWebSocketServer(t, func(reader *bufio.Reader, conn net.Conn) error {
		opcode, payload, err := readStressWebSocketFrame(reader, 64)
		if err != nil {
			return err
		}
		if opcode != 0x1 || string(payload) != "hello" {
			return fmt.Errorf("websocket round trip frame opcode=%d payload=%q", opcode, payload)
		}
		return writeStressWebSocketFrame(conn, 0x1, []byte("ws:hello"))
	})
	response, err := connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: stressMappedDialer(successAddr),
	}).WebSocketRoundTrip(ctx, connectivity.WebSocketRoundTripRequest{
		Grant:            grant,
		Payload:          []byte("hello"),
		MaxResponseBytes: 32,
		Timeout:          time.Second,
	})
	stopSuccess()
	if err != nil {
		t.Fatalf("WebSocketRoundTrip(stress success) error = %v", err)
	}
	if response.MessageType != connectivity.WebSocketMessageText || string(response.Payload) != "ws:hello" {
		t.Fatalf("WebSocketRoundTrip(stress success) response = %#v payload=%q", response, response.Payload)
	}
	counters.roundTrips = 1

	dialed := false
	_, err = connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("dial should not be called for oversized websocket request")
		},
	}).WebSocketRoundTrip(ctx, connectivity.WebSocketRoundTripRequest{
		Grant:           grant,
		Payload:         []byte("too-large"),
		MaxRequestBytes: 4,
		Timeout:         time.Second,
	})
	if !errors.Is(err, connectivity.ErrRequestTooLarge) {
		t.Fatalf("WebSocketRoundTrip(stress request limit) error = %v, want ErrRequestTooLarge", err)
	}
	if dialed {
		t.Fatal("WebSocketRoundTrip(stress request limit) dialed before rejecting oversized request")
	}
	counters.requestDenials = 1

	largeAddr, stopLarge := startStressWebSocketServer(t, func(reader *bufio.Reader, conn net.Conn) error {
		if _, _, err := readStressWebSocketFrame(reader, 64); err != nil {
			return err
		}
		return writeStressWebSocketFrame(conn, 0x2, []byte("too-large"))
	})
	_, err = connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext: stressMappedDialer(largeAddr),
	}).WebSocketRoundTrip(ctx, connectivity.WebSocketRoundTripRequest{
		Grant:            grant,
		MessageType:      connectivity.WebSocketMessageBinary,
		Payload:          []byte("ping"),
		MaxResponseBytes: 4,
		Timeout:          time.Second,
	})
	stopLarge()
	if !errors.Is(err, connectivity.ErrResponseTooLarge) {
		t.Fatalf("WebSocketRoundTrip(stress response limit) error = %v, want ErrResponseTooLarge", err)
	}
	counters.responseDenials = 1

	requestRead := make(chan struct{})
	releaseBlockedServer := make(chan struct{})
	var releaseOnce sync.Once
	releaseServer := func() {
		releaseOnce.Do(func() {
			close(releaseBlockedServer)
		})
	}
	blockedAddr, stopBlocked := startStressWebSocketServer(t, func(reader *bufio.Reader, _ net.Conn) error {
		if _, _, err := readStressWebSocketFrame(reader, 64); err != nil {
			return err
		}
		close(requestRead)
		<-releaseBlockedServer
		return nil
	})
	cancelCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		_, err := connectivity.NewExecutor(connectivity.ExecutorOptions{
			DialContext: stressMappedDialer(blockedAddr),
		}).WebSocketRoundTrip(cancelCtx, connectivity.WebSocketRoundTripRequest{
			Grant:            grant,
			Payload:          []byte("cancel-me"),
			MaxResponseBytes: 32,
			Timeout:          5 * time.Second,
		})
		errCh <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		cancel()
		releaseServer()
		stopBlocked()
		t.Fatal("WebSocketRoundTrip(stress cancel) server did not receive request frame")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			releaseServer()
			stopBlocked()
			t.Fatalf("WebSocketRoundTrip(stress cancel) error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		releaseServer()
		stopBlocked()
		t.Fatal("WebSocketRoundTrip(stress cancel) did not stop promptly")
	}
	releaseServer()
	stopBlocked()
	counters.cancelledReads = 1

	return counters
}

func startStressWebSocketServer(t *testing.T, handler func(*bufio.Reader, net.Conn) error) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			done <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			done <- err
			return
		}
		key := req.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			done <- errors.New("websocket handshake missing Sec-WebSocket-Key")
			return
		}
		if err := writeStressWebSocketHandshake(conn, key); err != nil {
			done <- err
			return
		}
		if err := handler(reader, conn); err != nil {
			done <- err
			return
		}
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = listener.Close()
			select {
			case err, ok := <-done:
				if ok && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("websocket stress server did not stop")
			}
		})
	}
	return listener.Addr().String(), stop
}

func writeStressWebSocketHandshake(writer io.Writer, key string) error {
	_, err := fmt.Fprintf(writer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", stressWebSocketAcceptKey(key))
	return err
}

func stressWebSocketAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeStressWebSocketFrame(writer io.Writer, opcode byte, payload []byte) error {
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

func readStressWebSocketFrame(reader *bufio.Reader, maxBytes int64) (byte, []byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	if first&0x80 == 0 {
		return 0, nil, errors.New("fragmented websocket stress frames are not supported")
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
	}
	if length > uint64(maxBytes) {
		return 0, nil, fmt.Errorf("websocket stress frame exceeded %d bytes", maxBytes)
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

type udpSourcePinCounters struct {
	roundTrips            int
	sourceMismatchDropped int
	rateLimitDenials      int
}

func stressUDPSourcePinCounters(t *testing.T, ctx context.Context, broker connectivity.Broker) udpSourcePinCounters {
	t.Helper()
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
			done <- fmt.Errorf("udp source-pin request payload = %q", buf[:n])
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
	grant, err := broker.MintConnectionGrant(ctx, grantRequest("metrics", connectivity.TransportUDP, "metrics.example.com:8125"))
	if err != nil {
		t.Fatal(err)
	}
	executor := connectivity.NewExecutor(connectivity.ExecutorOptions{
		DialContext:    stressMappedDialer(conn.LocalAddr().String()),
		UDPRateLimiter: connectivity.NewMemoryUDPRateLimiter(connectivity.UDPRateLimit{MaxRoundTrips: 1, Window: time.Minute}),
	})
	response, err := executor.UDPRoundTrip(ctx, connectivity.UDPRoundTripRequest{
		Grant:        grant,
		Payload:      []byte("hello"),
		MaxReadBytes: 32,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatalf("UDPRoundTrip(source-pin) error = %v", err)
	}
	if string(response.Payload) != "udp:pinned" {
		t.Fatalf("UDPRoundTrip(source-pin) payload = %q, want pinned source response", response.Payload)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_, err = executor.UDPRoundTrip(ctx, connectivity.UDPRoundTripRequest{
		Grant:        grant,
		Payload:      []byte("again"),
		MaxReadBytes: 32,
		Timeout:      time.Second,
	})
	if !errors.Is(err, connectivity.ErrRateLimited) {
		t.Fatalf("UDPRoundTrip(rate limit) error = %v, want ErrRateLimited", err)
	}
	return udpSourcePinCounters{roundTrips: 1, sourceMismatchDropped: 1, rateLimitDenials: 1}
}

func TestStressGateRuntimeRevokeACKP95(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		RuntimePath:           os.Args[0],
		Args:                  []string{"-test.run=TestMain"},
		Env:                   append(os.Environ(), "REDEVPLUGIN_STRESS_RUNTIME_HELPER=1"),
		HeartbeatInterval:     250 * time.Millisecond,
		MaxHeartbeatStaleness: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(ctx, runtimeclient.Target{OS: "stress-os", Arch: "stress-arch"}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		if err := supervisor.Stop(stopCtx); err != nil {
			t.Fatalf("Stop() error = %v", err)
		}
	}()

	const iterations = 64
	const p95Threshold = 500 * time.Millisecond
	const hardTimeout = 2 * time.Second
	durations := make([]time.Duration, 0, iterations)
	for i := 0; i < iterations; i++ {
		revokeCtx, revokeCancel := context.WithTimeout(ctx, hardTimeout)
		start := time.Now()
		result, err := supervisor.Revoke(revokeCtx, "plugini_stress_runtime", uint64(i+1))
		elapsed := time.Since(start)
		revokeCancel()
		if err != nil {
			t.Fatalf("Revoke(%d) error = %v", i+1, err)
		}
		if result.PluginInstanceID != "plugini_stress_runtime" ||
			result.RevokeEpoch != uint64(i+1) ||
			result.ClosedActorCount != 1 ||
			result.ClosedSocketCount != 2 ||
			result.ClosedStreamCount != 3 ||
			result.ClosedStorageHandleCount != 4 {
			t.Fatalf("Revoke(%d) result mismatch: %#v", i+1, result)
		}
		if elapsed >= hardTimeout {
			t.Fatalf("Revoke(%d) elapsed = %s, exceeded hard timeout %s", i+1, elapsed, hardTimeout)
		}
		durations = append(durations, elapsed)
	}
	sort.Slice(durations, func(i int, j int) bool { return durations[i] < durations[j] })
	p95 := percentileDuration(durations, 95)
	if p95 > p95Threshold {
		t.Fatalf("runtime revoke ACK p95 = %s, want <= %s", p95, p95Threshold)
	}
	logStressSummary(t, stressSummary{
		Category: "runtime_revoke_ack",
		Counters: map[string]int{
			"attempts":        iterations,
			"p95_ms":          durationMillisCeil(p95),
			"max_ms":          durationMillisCeil(durations[len(durations)-1]),
			"threshold_ms":    durationMillisCeil(p95Threshold),
			"hard_timeout_ms": durationMillisCeil(hardTimeout),
			"closed_actor":    1,
			"closed_socket":   2,
			"closed_stream":   3,
			"closed_storage":  4,
		},
	})
}

func TestStressGateStorageQuotaExportImportUnderLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	broker := storage.NewMemoryBroker()
	ns := storage.Namespace{
		PluginInstanceID: "plugini_stress_storage",
		StoreID:          "settings",
		Kind:             storage.StoreKV,
		QuotaBytes:       4096,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}

	value := make([]byte, 128)
	var writes atomic.Int64
	var quotaDenials atomic.Int64
	errs := make(chan error, 128)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 16; i++ {
				_, err := broker.PutKV(ctx, storage.KVPutRequest{
					PluginInstanceID: ns.PluginInstanceID,
					StoreID:          ns.StoreID,
					Key:              fmt.Sprintf("worker/%02d/%02d", worker, i),
					Value:            value,
				})
				if err == nil {
					writes.Add(1)
					continue
				}
				if errors.Is(err, storage.ErrQuotaExceeded) {
					quotaDenials.Add(1)
					continue
				}
				errs <- err
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	usage, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageBytes > ns.QuotaBytes {
		t.Fatalf("usage = %d, exceeds quota %d", usage.UsageBytes, ns.QuotaBytes)
	}
	if writes.Load() == 0 || quotaDenials.Load() == 0 {
		t.Fatalf("unexpected storage counters: writes=%d quota_denials=%d", writes.Load(), quotaDenials.Load())
	}
	archiveRef, err := broker.ExportData(ctx, storage.ExportRequest{PluginInstanceID: ns.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.ImportData(ctx, storage.ImportRequest{
		PluginInstanceID: "plugini_stress_storage_imported",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
		TargetNamespaces: []storage.Namespace{{
			StoreID:    ns.StoreID,
			Kind:       ns.Kind,
			QuotaBytes: ns.QuotaBytes,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	imported, err := broker.ListKV(ctx, storage.KVListRequest{
		PluginInstanceID: "plugini_stress_storage_imported",
		StoreID:          ns.StoreID,
		MaxEntries:       1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Entries) != int(writes.Load()) {
		t.Fatalf("imported entries = %d, want %d", len(imported.Entries), writes.Load())
	}
	fileCounters := stressFileCountQuotaCounters(t, ctx)
	sqliteCounters := stressSQLiteQuotaBypassCounters(t, ctx)
	logStressSummary(t, stressSummary{
		Category: "storage_quota",
		Counters: map[string]int{
			"writes":                      int(writes.Load()),
			"quota_denials":               int(quotaDenials.Load()),
			"imported":                    len(imported.Entries),
			"usage_bytes":                 int(usage.UsageBytes),
			"file_quota_denials":          fileCounters.quotaDenials,
			"file_usage_files":            fileCounters.usageFiles,
			"file_quota_files":            fileCounters.quotaFiles,
			"sqlite_quota_denials":        sqliteCounters.quotaDenials,
			"sqlite_rollback_checks":      sqliteCounters.rollbackChecks,
			"sqlite_page_count":           sqliteCounters.pageCount,
			"sqlite_sidecar_files":        sqliteCounters.sidecarFiles,
			"sqlite_sidecar_bytes":        sqliteCounters.sidecarBytes,
			"sqlite_sparse_logical_bytes": sqliteCounters.sparseLogicalBytes,
		},
	})
}

type fileCountQuotaCounters struct {
	quotaDenials int
	usageFiles   int
	quotaFiles   int
}

func stressFileCountQuotaCounters(t *testing.T, ctx context.Context) fileCountQuotaCounters {
	t.Helper()

	broker, err := storage.NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ns := storage.Namespace{
		PluginInstanceID: "plugini_stress_files",
		StoreID:          "workspace",
		Kind:             storage.StoreFiles,
		QuotaBytes:       1024,
		QuotaFiles:       1,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.WriteFile(ctx, storage.FileWriteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "one.txt",
		Data:             []byte("one"),
	}); err != nil {
		t.Fatal(err)
	}
	quotaDenials := 0
	if _, err := broker.WriteFile(ctx, storage.FileWriteRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		Path:             "two.txt",
		Data:             []byte("two"),
	}); errors.Is(err, storage.ErrQuotaExceeded) {
		quotaDenials++
	} else {
		t.Fatalf("WriteFile(file count quota) error = %v, want ErrQuotaExceeded", err)
	}
	usage, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageFiles != ns.QuotaFiles {
		t.Fatalf("file quota usage = %#v, want usage_files=%d", usage, ns.QuotaFiles)
	}
	return fileCountQuotaCounters{
		quotaDenials: quotaDenials,
		usageFiles:   int(usage.UsageFiles),
		quotaFiles:   int(usage.QuotaFiles),
	}
}

type sqliteQuotaBypassCounters struct {
	quotaDenials       int
	rollbackChecks     int
	pageCount          int
	sidecarFiles       int
	sidecarBytes       int
	sparseLogicalBytes int
}

func stressSQLiteQuotaBypassCounters(t *testing.T, ctx context.Context) sqliteQuotaBypassCounters {
	t.Helper()

	broker, err := storage.NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ns := storage.Namespace{
		PluginInstanceID: "plugini_stress_sqlite",
		StoreID:          "db",
		Kind:             storage.StoreSQLite,
		QuotaBytes:       16 * 1024,
	}
	if err := broker.EnsureNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecSQLite(ctx, storage.SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "CREATE TABLE items (body TEXT)",
	}); err != nil {
		t.Fatal(err)
	}
	pageCount := sqliteSingleInt(t, broker, ctx, storage.SQLiteQueryRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "PRAGMA page_count",
	})
	before, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", 128*1024)
	quotaDenials := 0
	if _, err := broker.ExecSQLite(ctx, storage.SQLiteExecRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "INSERT INTO items (body) VALUES (?)",
		Args:             []storage.SQLiteValue{{Text: &body}},
	}); errors.Is(err, storage.ErrQuotaExceeded) {
		quotaDenials++
	} else {
		t.Fatalf("ExecSQLite(quota body) error = %v, want ErrQuotaExceeded", err)
	}
	after, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	rollbackChecks := 0
	if after.UsageBytes == before.UsageBytes && sqliteSingleInt(t, broker, ctx, storage.SQLiteQueryRequest{
		PluginInstanceID: ns.PluginInstanceID,
		StoreID:          ns.StoreID,
		SQL:              "SELECT COUNT(*) FROM items",
	}) == 0 {
		rollbackChecks = 1
	}
	if rollbackChecks != 1 {
		t.Fatalf("sqlite quota rollback mismatch: before=%#v after=%#v", before, after)
	}

	dataPath, err := broker.NamespacePath(ctx, ns.PluginInstanceID, ns.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	sidecars := map[string]int64{
		"plugin.sqlite-wal": 512,
		"plugin.sqlite-shm": 512,
		"plugin.sqlite-tmp": 512,
	}
	sidecarBytes := int64(0)
	for name, size := range sidecars {
		if err := os.WriteFile(filepath.Join(dataPath, name), make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		sidecarBytes += size
	}
	sparseLogicalBytes := ns.QuotaBytes - before.UsageBytes + 1
	sparseFile, err := os.OpenFile(filepath.Join(dataPath, "plugin.sqlite-hole"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := sparseFile.Truncate(sparseLogicalBytes); err != nil {
		_ = sparseFile.Close()
		t.Fatal(err)
	}
	if err := sparseFile.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Usage(ctx, ns.PluginInstanceID, ns.StoreID); errors.Is(err, storage.ErrQuotaExceeded) {
		quotaDenials++
	} else {
		t.Fatalf("Usage(sqlite sidecars) error = %v, want ErrQuotaExceeded", err)
	}

	return sqliteQuotaBypassCounters{
		quotaDenials:       quotaDenials,
		rollbackChecks:     rollbackChecks,
		pageCount:          int(pageCount),
		sidecarFiles:       len(sidecars) + 1,
		sidecarBytes:       int(sidecarBytes + sparseLogicalBytes),
		sparseLogicalBytes: int(sparseLogicalBytes),
	}
}

func sqliteSingleInt(t *testing.T, broker storage.SQLiteBroker, ctx context.Context, req storage.SQLiteQueryRequest) int64 {
	t.Helper()

	result, err := broker.QuerySQLite(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0].Int == nil {
		t.Fatalf("sqlite single int result mismatch: %#v", result.Rows)
	}
	return *result.Rows[0][0].Int
}

func TestStressGateCSPReportFloodRateLimitsWithoutManagementSideEffects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := observability.NewMemoryStore()
	pluginHost, err := host.New(host.Adapters{
		SessionResolver: stressSessionResolver{},
		Policy:          stressPolicy{},
		Audit:           events,
		Diagnostics:     events,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := httpadapter.Handler{
		Host:             pluginHost,
		CSPReportLimiter: httpadapter.NewMemoryCSPReportLimiter(3, time.Minute),
	}
	body := []byte(`{
		"plugin_id": "com.example.stress.csp",
		"plugin_instance_id": "plugini_csp_flood",
		"surface_id": "stress.activity",
		"surface_instance_id": "surface_csp_flood",
		"sandbox_origin": "https://plg-csp-flood.sandbox.redevplugin.local",
		"active_fingerprint": "sha256:csp-flood",
		"csp-report": {
			"document-uri": "https://plg-csp-flood.sandbox.redevplugin.local/ui/index.html",
			"blocked-uri": "inline",
			"effective-directive": "script-src",
			"violated-directive": "script-src",
			"source-file": "https://plg-csp-flood.sandbox.redevplugin.local/ui/index.html",
			"line-number": 7
		}
	}`)

	const attempts = 64
	var accepted int
	var rateLimited int
	for i := 0; i < attempts; i++ {
		req := httptest.NewRequest(http.MethodPost, "/_redevplugin/csp-report", bytes.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/csp-report")
		req.RemoteAddr = fmt.Sprintf("203.0.113.7:%d", 51000+i)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		switch rec.Code {
		case http.StatusOK:
			accepted++
		case http.StatusTooManyRequests:
			rateLimited++
			var envelope httpadapter.Envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.ErrorCode != string(security.ErrNetworkRateLimited) {
				t.Fatalf("rate limit envelope mismatch: %#v", envelope)
			}
		default:
			t.Fatalf("CSP flood attempt %d status = %d body = %s", i, rec.Code, rec.Body.String())
		}
	}
	if accepted != 3 || rateLimited != attempts-3 {
		t.Fatalf("CSP flood counters accepted=%d rate_limited=%d", accepted, rateLimited)
	}
	diagnostics, err := events.ListPluginDiagnostics(ctx, observability.ListDiagnosticRequest{
		PluginInstanceID: "plugini_csp_flood",
		Type:             "plugin.csp.violation",
		Limit:            attempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != accepted {
		t.Fatalf("diagnostic events = %d, want %d", len(diagnostics), accepted)
	}
	for _, event := range diagnostics {
		if event.PluginID != "com.example.stress.csp" ||
			event.SurfaceInstanceID != "surface_csp_flood" ||
			event.ActiveFingerprint != "sha256:csp-flood" ||
			event.Details["sandbox_origin"] != "https://plg-csp-flood.sandbox.redevplugin.local" ||
			event.Details["blocked_uri"] != "inline" ||
			event.Details["source_ip"] != nil {
			t.Fatalf("diagnostic event carries unexpected CSP flood fields: %#v", event)
		}
	}
	auditEvents, err := events.ListPluginAudit(ctx, observability.ListAuditRequest{Limit: attempts})
	if err != nil {
		t.Fatal(err)
	}
	if len(auditEvents) != 0 {
		t.Fatalf("CSP report flood wrote audit events: %#v", auditEvents)
	}
	logStressSummary(t, stressSummary{
		Category: "csp_report_flood",
		Counters: map[string]int{
			"attempts":                   attempts,
			"accepted_reports":           accepted,
			"rate_limited_reports":       rateLimited,
			"diagnostic_events":          len(diagnostics),
			"audit_events":               len(auditEvents),
			"unique_sandbox_origins":     1,
			"unique_active_fingerprints": 1,
		},
	})
}

func percentileDuration(sorted []time.Duration, percentile int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := (len(sorted)*percentile + 99) / 100
	if index <= 0 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
}

func durationMillisCeil(duration time.Duration) int {
	if duration <= 0 {
		return 0
	}
	return int((duration + time.Millisecond - 1) / time.Millisecond)
}

func grantRequest(connectorID string, transport connectivity.Transport, destination string) connectivity.GrantRequest {
	return connectivity.GrantRequest{
		PluginInstanceID:    "plugini_stress_net",
		ActiveFingerprint:   "sha256:stress",
		PolicyRevision:      7,
		ManagementRevision:  11,
		RevokeEpoch:         3,
		ConnectorID:         connectorID,
		Transport:           transport,
		Destination:         destination,
		RuntimeGenerationID: "runtime_gen_stress",
		TTL:                 30 * time.Second,
	}
}

func stressMappedDialer(target string) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network string, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, target)
	}
}

type stressSessionResolver struct{}

func (stressSessionResolver) ResolveSession(context.Context, string) (sessionctx.Context, error) {
	return sessionctx.Context{}, nil
}

type stressPolicy struct{}

func (stressPolicy) EvaluateLocalPolicy(context.Context, sessionctx.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error) {
	return host.PolicyAllow, nil
}

func (stressPolicy) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}

func (stressPolicy) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return true, nil
}

type stressIPCFrame struct {
	IPCVersion          string          `json:"ipc_version"`
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type stressHelloPayload struct {
	ChannelNonce string `json:"channel_nonce"`
}

type stressHeartbeatPayload struct {
	SentUnixNano       int64 `json:"sent_unix_nano"`
	MaxStalenessMillis int64 `json:"max_staleness_ms"`
}

type stressRevokePayload struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	RevokeEpoch      uint64 `json:"revoke_epoch"`
}

type stressRuntimeResponsePayload struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Code   string          `json:"code,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func runStressRuntimeHelper() {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		os.Exit(2)
	}
	var frame stressIPCFrame
	if err := json.Unmarshal(line, &frame); err != nil {
		os.Exit(3)
	}
	if frame.IPCVersion != version.RustIPCVersion ||
		frame.FrameType != "hello" ||
		strings.TrimSpace(frame.RequestID) == "" ||
		strings.TrimSpace(frame.RuntimeGenerationID) == "" {
		os.Exit(4)
	}
	var hello stressHelloPayload
	if err := json.Unmarshal(frame.Payload, &hello); err != nil || strings.TrimSpace(hello.ChannelNonce) == "" {
		os.Exit(5)
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(stressIPCFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           "hello_ack",
		RequestID:           frame.RequestID,
		RuntimeGenerationID: frame.RuntimeGenerationID,
		Payload: stressRawJSON(map[string]any{
			"runtime_version":  version.RuntimeVersion,
			"rust_ipc_version": version.RustIPCVersion,
			"wasm_abi_version": version.WASMABIVersion,
			"channel_nonce":    hello.ChannelNonce,
		}),
	}); err != nil {
		os.Exit(6)
	}
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request stressIPCFrame
		if err := json.Unmarshal(line, &request); err != nil {
			os.Exit(7)
		}
		switch request.FrameType {
		case "heartbeat":
			var heartbeat stressHeartbeatPayload
			_ = json.Unmarshal(request.Payload, &heartbeat)
			respondStressRuntime(encoder, request, "heartbeat", stressRawJSON(stressRuntimeResponsePayload{
				OK: true,
				Result: stressRawJSON(map[string]any{
					"runtime_generation_id": request.RuntimeGenerationID,
					"runtime_unix_nano":     time.Now().UnixNano(),
					"max_staleness_ms":      heartbeat.MaxStalenessMillis,
					"host_sent_unix_nano":   heartbeat.SentUnixNano,
				}),
			}))
		case "revoke_epoch":
			var revoke stressRevokePayload
			_ = json.Unmarshal(request.Payload, &revoke)
			respondStressRuntime(encoder, request, "revoke_epoch_ack", stressRawJSON(stressRuntimeResponsePayload{
				OK: true,
				Result: stressRawJSON(map[string]any{
					"plugin_instance_id":          revoke.PluginInstanceID,
					"revoke_epoch":                revoke.RevokeEpoch,
					"closed_actor_count":          1,
					"closed_socket_count":         2,
					"closed_stream_count":         3,
					"closed_storage_handle_count": 4,
				}),
			}))
		default:
			respondStressRuntime(encoder, request, "diagnostic", stressRawJSON(stressRuntimeResponsePayload{
				OK:    false,
				Code:  "UNSUPPORTED_FRAME",
				Error: "unsupported stress runtime frame",
			}))
		}
	}
}

func respondStressRuntime(encoder *json.Encoder, request stressIPCFrame, frameType string, payload json.RawMessage) {
	if err := encoder.Encode(stressIPCFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           frameType,
		RequestID:           request.RequestID,
		RuntimeGenerationID: request.RuntimeGenerationID,
		Payload:             payload,
	}); err != nil {
		os.Exit(8)
	}
}

func stressRawJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		os.Exit(9)
	}
	return raw
}

func logStressSummary(t *testing.T, summary stressSummary) {
	t.Helper()
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
	if evidencePath := os.Getenv("REDEVPLUGIN_STRESS_EVIDENCE_PATH"); evidencePath != "" {
		stressEvidenceMu.Lock()
		defer stressEvidenceMu.Unlock()
		file, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatalf("open stress evidence file: %v", err)
		}
		if _, err := file.Write(append(data, '\n')); err != nil {
			_ = file.Close()
			t.Fatalf("write stress evidence file: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close stress evidence file: %v", err)
		}
	}
}
