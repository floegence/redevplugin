package connectivity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
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
		{name: "ipv6-ula", transport: "tcp", destination: "[fd00::10]:443"},
		{name: "ipv4-mapped-loopback", transport: "tcp", destination: "[::ffff:127.0.0.1]:443"},
		{name: "metadata-host", transport: "websocket", destination: "wss://metadata.google.internal"},
		{name: "metadata-host-trailing-dot", transport: "websocket", destination: "wss://metadata.google.internal."},
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

func TestTargetClassifierFixtureContract(t *testing.T) {
	contract := readTargetClassifierContract(t)
	if contract.Version != version.TargetClassifierVersion {
		t.Fatalf("fixture version = %q, want %q", contract.Version, version.TargetClassifierVersion)
	}

	classifier := DefaultClassifier()
	gotRanges := make([]string, 0, len(classifier.blockedRanges))
	for _, prefix := range classifier.blockedRanges {
		gotRanges = append(gotRanges, prefix.String())
	}
	if !sameStrings(gotRanges, contract.BlockedIPRanges) {
		t.Fatalf("blocked ranges = %#v, want %#v", gotRanges, contract.BlockedIPRanges)
	}

	gotHosts := make([]string, 0, len(classifier.specialHosts))
	for host := range classifier.specialHosts {
		gotHosts = append(gotHosts, host)
	}
	if !sameStrings(gotHosts, contract.SpecialHosts) {
		t.Fatalf("special hosts = %#v, want %#v", gotHosts, contract.SpecialHosts)
	}
	if len(contract.Fixtures) == 0 {
		t.Fatal("target classifier fixture contract must include decision fixtures")
	}

	for _, fixture := range contract.Fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			destination, err := ParseDestination(Transport(fixture.Transport), fixture.Destination)
			if err != nil {
				t.Fatalf("ParseDestination(%q) error = %v", fixture.Destination, err)
			}
			err = classifier.Evaluate(destination)
			if fixture.ResolvedAddress != "" && err == nil {
				addr, parseErr := netip.ParseAddr(fixture.ResolvedAddress)
				if parseErr != nil {
					t.Fatalf("fixture resolved_address %q parse error = %v", fixture.ResolvedAddress, parseErr)
				}
				err = classifier.EvaluateResolvedAddress(destination, addr)
			}
			switch fixture.Decision {
			case "allow":
				if err != nil {
					t.Fatalf("classifier denied fixture %#v: %v", fixture, err)
				}
			case "deny":
				if !errors.Is(err, ErrTargetDenied) {
					t.Fatalf("classifier error for fixture %#v = %v, want ErrTargetDenied", fixture, err)
				}
			default:
				t.Fatalf("unsupported fixture decision %q", fixture.Decision)
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
	if err := classifier.EvaluateResolvedAddress(destination, netip.MustParseAddr("::ffff:10.0.0.10")); !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("EvaluateResolvedAddress(ipv4-mapped private) error = %v, want ErrTargetDenied", err)
	}
	if err := classifier.EvaluateResolvedAddress(destination, netip.MustParseAddr("8.8.8.8")); err != nil {
		t.Fatalf("EvaluateResolvedAddress(public) error = %v", err)
	}
}

func TestHostHeaderBracketsPublicIPv6Authorities(t *testing.T) {
	const publicIPv6 = "2606:4700:4700::1111"
	for _, tc := range []struct {
		name        string
		destination Destination
		want        string
	}{
		{name: "https default", destination: Destination{Scheme: "https", Host: publicIPv6, Port: 443}, want: "[2606:4700:4700::1111]"},
		{name: "wss default", destination: Destination{Scheme: "wss", Host: publicIPv6, Port: 443}, want: "[2606:4700:4700::1111]"},
		{name: "https custom", destination: Destination{Scheme: "https", Host: publicIPv6, Port: 8443}, want: "[2606:4700:4700::1111]:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostHeader(tc.destination); got != tc.want {
				t.Fatalf("hostHeader() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifierDenialDoesNotExposeResolvedAddressDetails(t *testing.T) {
	destination := Destination{Transport: TransportTCP, Host: "sensitive.internal.example", Port: 443}
	err := DefaultClassifier().EvaluateResolvedAddress(destination, netip.MustParseAddr("100.64.1.2"))
	if !errors.Is(err, ErrTargetDenied) {
		t.Fatalf("EvaluateResolvedAddress() error = %v, want ErrTargetDenied", err)
	}
	message := err.Error()
	for _, secret := range []string{destination.Host, "100.64.1.2", "100.64.0.0/10"} {
		if strings.Contains(message, secret) {
			t.Fatalf("target denial %q exposed %q", message, secret)
		}
	}
}

type targetClassifierContract struct {
	Version         string                    `json:"version"`
	BlockedIPRanges []string                  `json:"blocked_ip_ranges"`
	SpecialHosts    []string                  `json:"special_hosts"`
	Fixtures        []targetClassifierFixture `json:"fixtures"`
}

type targetClassifierFixture struct {
	Name            string `json:"name"`
	Transport       string `json:"transport"`
	Destination     string `json:"destination"`
	ResolvedAddress string `json:"resolved_address,omitempty"`
	Decision        string `json:"decision"`
}

func readTargetClassifierContract(t *testing.T) targetClassifierContract {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "plugin", "target-classifier-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract targetClassifierContract
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	return contract
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]string(nil), a...)
	right := append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
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

func TestExecutorPublicOptionsExposeOnlyGuardedNetworkConfiguration(t *testing.T) {
	optionsType := reflect.TypeOf(ExecutorOptions{})
	gotFields := make([]string, optionsType.NumField())
	for i := range gotFields {
		gotFields[i] = optionsType.Field(i).Name
	}
	wantFields := []string{"Dialer", "LookupIPAddr", "UDPRateLimiter", "MaxRequestBytes", "MaxResponseBytes", "DefaultTimeout", "Now"}
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("ExecutorOptions fields = %#v, want %#v", gotFields, wantFields)
	}
	executor := NewExecutor(ExecutorOptions{})
	transport, ok := executor.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("executor transport = %T, want *http.Transport", executor.httpClient.Transport)
	}
	if transport.Proxy != nil || transport.DialContext == nil || !transport.DisableKeepAlives {
		t.Fatalf("executor transport safety settings are incomplete")
	}
	if executor.httpClient.CheckRedirect == nil {
		t.Fatal("executor redirect policy is unset")
	}
	request, err := http.NewRequest(http.MethodGet, "https://other.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.httpClient.CheckRedirect(request, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v, want http.ErrUseLastResponse", err)
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
	executor := newTestExecutor(ExecutorOptions{MaxResponseBytes: 128}, mapDialer(listener.Addr().String()))
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

func TestExecutorCanonicalizesStructuredHTTPQuery(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.RawQuery))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).DoHTTP(context.Background(), HTTPRequest{
		Grant: grant,
		Path:  "/v1/forecast",
		Query: url.Values{
			"current":   []string{"temperature_2m", "weather_code"},
			"latitude":  []string{"52.52"},
			"longitude": []string{"13.41"},
		},
	})
	if err != nil {
		t.Fatalf("DoHTTP() error = %v", err)
	}
	const want = "current=temperature_2m&current=weather_code&latitude=52.52&longitude=13.41"
	if string(response.Body) != want {
		t.Fatalf("query = %q, want %q", response.Body, want)
	}
}

func TestExecutorRejectsHTTPPathWithEmbeddedQueryOrFragmentBeforeDial(t *testing.T) {
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	for _, path := range []string{"/v1/forecast?latitude=52.52", "/v1/forecast#current"} {
		t.Run(path, func(t *testing.T) {
			dialed := false
			_, err := newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("dial should not be called for an invalid path")
			}).DoHTTP(context.Background(), HTTPRequest{Grant: grant, Path: path})
			if !errors.Is(err, ErrInvalidConnector) {
				t.Fatalf("DoHTTP(%q) error = %v, want ErrInvalidConnector", path, err)
			}
			if dialed {
				t.Fatalf("DoHTTP(%q) dialed before rejecting the path", path)
			}
		})
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
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).DoHTTP(context.Background(), HTTPRequest{Grant: grant})
	if err != nil {
		t.Fatalf("DoHTTP() error = %v", err)
	}
	if string(response.Body) != "ok" {
		t.Fatalf("HTTP response body = %q", response.Body)
	}
}

func TestExecutorHTTPStreamResponseChunks(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/stream" {
			t.Errorf("request = %s %s, want POST /v1/stream", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
		}
		if string(body) != "payload" {
			t.Errorf("request body = %q, want payload", body)
		}
		w.Header().Set("X-Test", "stream")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("one"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("two"))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	var chunks []HTTPResponseChunk
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).StreamHTTP(context.Background(), HTTPRequest{
		Grant:            grant,
		Method:           http.MethodPost,
		Path:             "/v1/stream",
		Body:             []byte("payload"),
		MaxResponseBytes: 16,
		MaxChunkBytes:    3,
	}, func(chunk HTTPResponseChunk) error {
		chunks = append(chunks, HTTPResponseChunk{Index: chunk.Index, Data: append([]byte(nil), chunk.Data...)})
		return nil
	})
	if err != nil {
		t.Fatalf("StreamHTTP() error = %v", err)
	}
	if response.StatusCode != http.StatusAccepted || response.Headers.Get("X-Test") != "stream" || response.BytesRead != 6 || response.ChunkCount != 2 {
		t.Fatalf("stream response mismatch: %#v", response)
	}
	if len(chunks) != 2 || chunks[0].Index != 0 || chunks[1].Index != 1 || string(chunks[0].Data)+string(chunks[1].Data) != "onetwo" {
		t.Fatalf("stream chunks mismatch: %#v", chunks)
	}
}

func TestExecutorHTTPStreamRejectsOversizedRequestBeforeDial(t *testing.T) {
	dialed := false
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	_, err := newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dial should not be called for oversized http stream request")
	}).StreamHTTP(context.Background(), HTTPRequest{
		Grant:           grant,
		Body:            []byte("too-large"),
		MaxRequestBytes: 4,
	}, func(HTTPResponseChunk) error {
		return nil
	})
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("StreamHTTP(large request) error = %v, want ErrRequestTooLarge", err)
	}
	if dialed {
		t.Fatal("StreamHTTP dialed before rejecting oversized request")
	}
}

func TestExecutorHTTPStreamRejectsOversizedResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("too-large"))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	var delivered bytes.Buffer
	_, err = newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).StreamHTTP(context.Background(), HTTPRequest{
		Grant:            grant,
		MaxResponseBytes: 4,
		MaxChunkBytes:    4,
	}, func(chunk HTTPResponseChunk) error {
		_, _ = delivered.Write(chunk.Data)
		return nil
	})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("StreamHTTP(large response) error = %v, want ErrResponseTooLarge", err)
	}
	if delivered.Len() > 4 {
		t.Fatalf("StreamHTTP delivered %d bytes, want <= 4", delivered.Len())
	}
}

func TestExecutorHTTPStreamStopsWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	headersSent := make(chan struct{})
	releaseBlockedServer := make(chan struct{})
	var releaseOnce sync.Once
	releaseServer := func() {
		releaseOnce.Do(func() {
			close(releaseBlockedServer)
		})
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		close(headersSent)
		<-releaseBlockedServer
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() {
		releaseServer()
		_ = server.Close()
	}()
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	cancelCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).StreamHTTP(cancelCtx, HTTPRequest{
			Grant:            grant,
			MaxResponseBytes: 32,
			Timeout:          5 * time.Second,
		}, func(HTTPResponseChunk) error {
			return nil
		})
		errCh <- err
	}()
	select {
	case <-headersSent:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("StreamHTTP server did not send headers")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamHTTP(canceled) error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("StreamHTTP did not stop promptly after context cancellation")
	}
}

func TestExecutorHTTPDisablesProxyAndConnect(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/proxy-check" || r.URL.IsAbs() {
			t.Errorf("request URI = %q absolute=%v; environment proxy may have been used", r.RequestURI, r.URL.IsAbs())
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
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).DoHTTP(context.Background(), HTTPRequest{
		Grant: grant,
		Path:  "/proxy-check",
		Headers: http.Header{
			"X-Test": []string{"ok"},
		},
	})
	if err != nil {
		t.Fatalf("DoHTTP(proxy/header check) error = %v", err)
	}
	if string(response.Body) != "ok" {
		t.Fatalf("DoHTTP(proxy/header check) body = %q", response.Body)
	}

	dialed := false
	_, err = newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dial should not be called for CONNECT")
	}).DoHTTP(context.Background(), HTTPRequest{Grant: grant, Method: http.MethodConnect})
	if !errors.Is(err, ErrInvalidConnector) {
		t.Fatalf("DoHTTP(CONNECT) error = %v, want ErrInvalidConnector", err)
	}
	if dialed {
		t.Fatal("DoHTTP(CONNECT) dialed before rejecting method")
	}
}

func TestValidateForwardHeadersRejectsInvalidAndReservedHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
	}{
		{name: "newline in name", headers: http.Header{"X-Test\r\nHost": []string{"evil.example"}}},
		{name: "colon in name", headers: http.Header{"X-Test:Other": []string{"value"}}},
		{name: "space in name", headers: http.Header{"X Test": []string{"value"}}},
		{name: "control in name", headers: http.Header{"X-Test\x7f": []string{"value"}}},
		{name: "newline in value", headers: http.Header{"X-Test": []string{"value\r\nHost: evil.example"}}},
		{name: "host", headers: http.Header{"Host": []string{"evil.example"}}},
		{name: "connection", headers: http.Header{"Connection": []string{"keep-alive"}}},
		{name: "upgrade", headers: http.Header{"Upgrade": []string{"websocket"}}},
		{name: "transfer encoding", headers: http.Header{"Transfer-Encoding": []string{"chunked"}}},
		{name: "content length", headers: http.Header{"Content-Length": []string{"10"}}},
		{name: "te", headers: http.Header{"TE": []string{"trailers"}}},
		{name: "trailer", headers: http.Header{"Trailer": []string{"X-Checksum"}}},
		{name: "keep alive", headers: http.Header{"Keep-Alive": []string{"timeout=5"}}},
		{name: "proxy connection", headers: http.Header{"Proxy-Connection": []string{"keep-alive"}}},
		{name: "proxy authorization", headers: http.Header{"Proxy-Authorization": []string{"Bearer secret"}}},
		{name: "proxy authenticate", headers: http.Header{"Proxy-Authenticate": []string{"Basic"}}},
		{name: "alt svc", headers: http.Header{"Alt-Svc": []string{`h3=":443"`}}},
		{name: "http2 settings", headers: http.Header{"HTTP2-Settings": []string{"settings"}}},
		{name: "websocket protocol", headers: http.Header{"Sec-WebSocket-Protocol": []string{"chat"}}},
		{name: "websocket extension", headers: http.Header{"sEc-WeBsOcKeT-Extensions": []string{"permessage-deflate"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateForwardHeaders(tc.headers); !errors.Is(err, ErrInvalidConnector) {
				t.Fatalf("validateForwardHeaders() error = %v, want ErrInvalidConnector", err)
			}
		})
	}

	validated, err := validateForwardHeaders(http.Header{"x-request-id": []string{"request-1", "request-2"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := validated.Values("X-Request-Id"); !reflect.DeepEqual(got, []string{"request-1", "request-2"}) {
		t.Fatalf("validated header values = %#v", got)
	}
}

func TestExecutorRejectsUnsafeForwardHeadersBeforeDial(t *testing.T) {
	for _, tc := range []struct {
		name        string
		transport   Transport
		destination string
		execute     func(*Executor, ConnectionGrant) error
	}{
		{
			name:        "http framing header",
			transport:   TransportHTTP,
			destination: "https://api.example.com",
			execute: func(executor *Executor, grant ConnectionGrant) error {
				_, err := executor.DoHTTP(context.Background(), HTTPRequest{
					Grant: grant,
					Headers: http.Header{
						"Content-Length": []string{"128"},
					},
				})
				return err
			},
		},
		{
			name:        "websocket injected header name",
			transport:   TransportWebSocket,
			destination: "wss://stream.example.com",
			execute: func(executor *Executor, grant ConnectionGrant) error {
				_, err := executor.WebSocketRoundTrip(context.Background(), WebSocketRoundTripRequest{
					Grant: grant,
					Headers: http.Header{
						"X-Test\r\nHost": []string{"evil.example"},
					},
				})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialed := false
			executor := newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("unexpected dial")
			})
			grant := testGrant(t, tc.transport, tc.destination, time.Minute)
			if err := tc.execute(executor, grant); !errors.Is(err, ErrInvalidConnector) {
				t.Fatalf("execute() error = %v, want ErrInvalidConnector", err)
			}
			if dialed {
				t.Fatal("unsafe headers reached the dialer")
			}
		})
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
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(redirectListener.Addr().String())).DoHTTP(context.Background(), HTTPRequest{Grant: grant})
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
	if _, err := newTestExecutor(ExecutorOptions{MaxResponseBytes: 4}, mapDialer(largeListener.Addr().String())).DoHTTP(context.Background(), HTTPRequest{Grant: largeGrant}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("DoHTTP(large) error = %v, want ErrResponseTooLarge", err)
	}
}

func TestExecutorRejectsDNSRebindingResolvedAddresses(t *testing.T) {
	grant := testGrant(t, TransportHTTP, "http://api.example.com", time.Minute)
	executor := NewExecutor(ExecutorOptions{
		Dialer: &net.Dialer{Timeout: time.Millisecond},
		LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("93.184.216.34")},
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
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).WebSocketRoundTrip(context.Background(), WebSocketRoundTripRequest{
		Grant:            grant,
		Path:             "/events",
		Headers:          http.Header{"X-Test": []string{"ok"}},
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
	_, err = newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).WebSocketRoundTrip(context.Background(), WebSocketRoundTripRequest{
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

func TestExecutorWebSocketRoundTripRejectsOversizedRequestBeforeDial(t *testing.T) {
	var dialed bool
	grant := testGrant(t, TransportWebSocket, "ws://stream.example.com", time.Minute)
	_, err := newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dial should not be called")
	}).WebSocketRoundTrip(context.Background(), WebSocketRoundTripRequest{
		Grant:           grant,
		Payload:         []byte("too-large"),
		MaxRequestBytes: 4,
		Timeout:         time.Second,
	})
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("WebSocketRoundTrip(large request) error = %v, want ErrRequestTooLarge", err)
	}
	if dialed {
		t.Fatal("WebSocketRoundTrip dialed before rejecting oversized request")
	}
}

func TestExecutorWebSocketRoundTripStopsWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestRead := make(chan struct{})
	releaseServer := make(chan struct{})
	serverReleased := false
	release := func() {
		if !serverReleased {
			close(releaseServer)
			serverReleased = true
		}
	}
	defer release()
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
		if err := writeTestWebSocketHandshake(conn, req.Header.Get("Sec-WebSocket-Key")); err != nil {
			t.Errorf("write handshake error = %v", err)
			return
		}
		if _, _, err := readWebSocketFrame(reader, 64); err != nil {
			t.Errorf("read frame error = %v", err)
			return
		}
		close(requestRead)
		<-releaseServer
	}()

	grant := testGrant(t, TransportWebSocket, "ws://stream.example.com", time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).WebSocketRoundTrip(ctx, WebSocketRoundTripRequest{
			Grant:            grant,
			Payload:          []byte("hello"),
			MaxResponseBytes: 32,
			Timeout:          5 * time.Second,
		})
		errCh <- err
	}()

	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive websocket request frame")
	}
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WebSocketRoundTrip(canceled) error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("WebSocketRoundTrip did not stop promptly after context cancellation")
	}
	release()
	<-done
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
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).TCPRoundTrip(context.Background(), TCPRoundTripRequest{
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

func TestExecutorTCPRoundTripRejectsOversizedRequestBeforeDial(t *testing.T) {
	var dialed bool
	grant := testGrant(t, TransportTCP, "tcp://db.example.com:5432", time.Minute)
	_, err := newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dial should not be called")
	}).TCPRoundTrip(context.Background(), TCPRoundTripRequest{
		Grant:           grant,
		Payload:         []byte("SELECT too_large"),
		MaxRequestBytes: 4,
		Timeout:         time.Second,
	})
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("TCPRoundTrip(large request) error = %v, want ErrRequestTooLarge", err)
	}
	if dialed {
		t.Fatal("TCPRoundTrip dialed before rejecting oversized request")
	}
}

func TestExecutorTCPRoundTripRejectsOversizedResponse(t *testing.T) {
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
		buf := make([]byte, 32)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("too-large"))
	}()
	grant := testGrant(t, TransportTCP, "tcp://db.example.com:5432", time.Minute)
	_, err = newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).TCPRoundTrip(context.Background(), TCPRoundTripRequest{
		Grant:        grant,
		Payload:      []byte("query"),
		MaxReadBytes: 4,
		Timeout:      time.Second,
	})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("TCPRoundTrip(large response) error = %v, want ErrResponseTooLarge", err)
	}
}

func TestExecutorTCPRoundTripStopsWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestRead := make(chan struct{})
	releaseServer := make(chan struct{})
	serverReleased := false
	release := func() {
		if !serverReleased {
			close(releaseServer)
			serverReleased = true
		}
	}
	defer release()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 32)
		if _, err := conn.Read(buf); err != nil {
			t.Errorf("Read() error = %v", err)
			return
		}
		close(requestRead)
		<-releaseServer
	}()

	grant := testGrant(t, TransportTCP, "tcp://db.example.com:5432", time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := newTestExecutor(ExecutorOptions{}, mapDialer(listener.Addr().String())).TCPRoundTrip(ctx, TCPRoundTripRequest{
			Grant:        grant,
			Payload:      []byte("query"),
			MaxReadBytes: 32,
			Timeout:      5 * time.Second,
		})
		errCh <- err
	}()

	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive tcp request payload")
	}
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("TCPRoundTrip(canceled) error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TCPRoundTrip did not stop promptly after context cancellation")
	}
	release()
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
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(conn.LocalAddr().String())).UDPRoundTrip(context.Background(), UDPRoundTripRequest{
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
	response, err := newTestExecutor(ExecutorOptions{}, mapDialer(conn.LocalAddr().String())).UDPRoundTrip(context.Background(), UDPRoundTripRequest{
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

func TestExecutorUDPRoundTripRateLimitsEndpointBeforeDial(t *testing.T) {
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
		_, err = conn.WriteTo([]byte("udp:hello"), addr)
		done <- err
	}()
	now := time.Now().UTC()
	dials := 0
	executor := newTestExecutor(ExecutorOptions{
		UDPRateLimiter: NewMemoryUDPRateLimiter(UDPRateLimit{MaxRoundTrips: 1, Window: time.Minute}),
		Now:            func() time.Time { return now },
	}, func(ctx context.Context, network string, address string) (net.Conn, error) {
		dials++
		return mapDialer(conn.LocalAddr().String())(ctx, network, address)
	})
	grant := testGrant(t, TransportUDP, "udp://metrics.example.com:8125", time.Minute)
	response, err := executor.UDPRoundTrip(context.Background(), UDPRoundTripRequest{
		Grant:        grant,
		Payload:      []byte("hello"),
		MaxReadBytes: 32,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatalf("UDPRoundTrip(first) error = %v", err)
	}
	if string(response.Payload) != "udp:hello" {
		t.Fatalf("UDP payload = %q", response.Payload)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	secondGrant := grant
	secondGrant.GrantID = "netgrant_ffeeddccbbaa99887766554433221100"
	_, err = executor.UDPRoundTrip(context.Background(), UDPRoundTripRequest{
		Grant:        secondGrant,
		Payload:      []byte("again"),
		MaxReadBytes: 32,
		Timeout:      time.Second,
		Now:          now.Add(time.Second),
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("UDPRoundTrip(second) error = %v, want ErrRateLimited", err)
	}
	if dials != 1 {
		t.Fatalf("UDP dials = %d, want rate-limited request to stop before dial", dials)
	}
}

func TestMemoryUDPRateLimiterFailsClosedAtBucketCapacityAndRecoversAfterExpiry(t *testing.T) {
	limiter := NewMemoryUDPRateLimiter(UDPRateLimit{MaxRoundTrips: 2, Window: time.Second})
	limiter.maxBuckets = 2
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	first := udpLimiterTestKey("first.example")
	second := udpLimiterTestKey("second.example")
	third := udpLimiterTestKey("third.example")
	if !limiter.AllowUDPRoundTrip(now, first) || !limiter.AllowUDPRoundTrip(now, second) {
		t.Fatal("initial UDP limiter buckets were rejected")
	}
	if limiter.AllowUDPRoundTrip(now, third) {
		t.Fatal("UDP limiter accepted a new bucket beyond its fixed capacity")
	}
	if !limiter.AllowUDPRoundTrip(now.Add(time.Millisecond), first) {
		t.Fatal("UDP limiter rejected an existing bucket at capacity")
	}
	if !limiter.AllowUDPRoundTrip(now.Add(2*time.Second+2*time.Millisecond), third) {
		t.Fatal("UDP limiter did not admit a bucket after inactive entries expired")
	}
	if len(limiter.windows) != 1 {
		t.Fatalf("UDP limiter windows = %d, want 1", len(limiter.windows))
	}
}

func TestMemoryUDPRateLimiterBoundsStaleExpiryEntries(t *testing.T) {
	limiter := NewMemoryUDPRateLimiter(UDPRateLimit{MaxRoundTrips: 20_000, Window: time.Minute})
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	key := udpLimiterTestKey("metrics.example")
	for index := 0; index < 10_000; index++ {
		if !limiter.AllowUDPRoundTrip(now.Add(time.Duration(index)), key) {
			t.Fatalf("UDP limiter rejected update %d", index)
		}
	}
	if got, limit := limiter.expirations.Len(), 4*len(limiter.windows)+64; got > limit {
		t.Fatalf("UDP expiry heap entries = %d, want <= %d", got, limit)
	}
}

func BenchmarkMemoryUDPRateLimiterHighCardinality(b *testing.B) {
	limiter := NewMemoryUDPRateLimiter(UDPRateLimit{MaxRoundTrips: 1_000_000, Window: time.Minute})
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		key := udpLimiterTestKey(fmt.Sprintf("endpoint-%05d.example", index%maxMemoryUDPRateLimitBuckets))
		_ = limiter.AllowUDPRoundTrip(now.Add(time.Duration(index%1000)), key)
	}
}

func udpLimiterTestKey(host string) UDPRateLimitKey {
	return UDPRateLimitKey{
		PluginInstanceID:  "plugini_udp_limiter",
		ActiveFingerprint: "sha256:udp-limiter",
		ConnectorID:       "metrics",
		Destination: Destination{
			Transport: TransportUDP,
			Host:      host,
			Port:      8125,
		},
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

func TestExecutorRejectsGrantClassifierVersionMismatchBeforeDial(t *testing.T) {
	cases := []struct {
		name      string
		transport Transport
		raw       string
		execute   func(*Executor, ConnectionGrant) error
	}{
		{
			name:      "http",
			transport: TransportHTTP,
			raw:       "https://api.example.com",
			execute: func(executor *Executor, grant ConnectionGrant) error {
				_, err := executor.DoHTTP(context.Background(), HTTPRequest{Grant: grant})
				return err
			},
		},
		{
			name:      "http-stream",
			transport: TransportHTTP,
			raw:       "https://api.example.com",
			execute: func(executor *Executor, grant ConnectionGrant) error {
				_, err := executor.StreamHTTP(context.Background(), HTTPRequest{Grant: grant}, func(HTTPResponseChunk) error {
					return nil
				})
				return err
			},
		},
		{
			name:      "websocket",
			transport: TransportWebSocket,
			raw:       "wss://stream.example.com",
			execute: func(executor *Executor, grant ConnectionGrant) error {
				_, err := executor.WebSocketRoundTrip(context.Background(), WebSocketRoundTripRequest{Grant: grant})
				return err
			},
		},
		{
			name:      "tcp",
			transport: TransportTCP,
			raw:       "db.example.com:443",
			execute: func(executor *Executor, grant ConnectionGrant) error {
				_, err := executor.TCPRoundTrip(context.Background(), TCPRoundTripRequest{Grant: grant})
				return err
			},
		},
		{
			name:      "udp",
			transport: TransportUDP,
			raw:       "metrics.example.com:8125",
			execute: func(executor *Executor, grant ConnectionGrant) error {
				_, err := executor.UDPRoundTrip(context.Background(), UDPRoundTripRequest{Grant: grant, MaxReadBytes: 32})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialed := false
			grant := testGrant(t, tc.transport, tc.raw, time.Minute)
			grant.TargetClassifierVersion = "target-classifier-invalid"
			executor := newTestExecutor(ExecutorOptions{}, func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("dial should not run for classifier mismatch")
			})
			if err := tc.execute(executor, grant); !errors.Is(err, ErrConnectorDenied) {
				t.Fatalf("execute() error = %v, want ErrConnectorDenied", err)
			}
			if dialed {
				t.Fatal("executor dialed before rejecting classifier version mismatch")
			}
		})
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
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := executor.TCPRoundTrip(ctx, TCPRoundTripRequest{Grant: grant, Timeout: time.Millisecond})
	if errors.Is(err, ErrTargetDenied) {
		t.Fatalf("TCPRoundTrip(public resolved address) error = %v, want non-classifier dial failure", err)
	}
}

func TestGuardedDialerPinsValidatedAddressWithoutSecondDNSLookup(t *testing.T) {
	resolverDialed := false
	dialer := &net.Dialer{
		Timeout: time.Millisecond,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(context.Context, string, string) (net.Conn, error) {
				resolverDialed = true
				return nil, errors.New("unexpected second DNS lookup")
			},
		},
	}
	dial := guardedDialContext(dialer, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, _ = dial(ctx, "tcp", "weather.example.com:443")
	if resolverDialed {
		t.Fatal("validated hostname was resolved again during dial")
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

func newTestExecutor(options ExecutorOptions, dialContext func(context.Context, string, string) (net.Conn, error)) *Executor {
	return newExecutor(options, executorNetworkOptions{dialContext: dialContext})
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
