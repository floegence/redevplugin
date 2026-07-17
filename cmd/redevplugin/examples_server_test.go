package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/version"
	"golang.org/x/net/dns/dnsmessage"
)

func TestExamplesPublicResolverUsesConfiguredDNSService(t *testing.T) {
	dnsAddress, queries := startExamplesTestDNSServer(t, [4]byte{93, 184, 216, 34})
	resolver := newExamplesPublicResolver(dnsAddress)

	addresses, err := resolver.LookupIPAddr(context.Background(), "weather.example")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	want := net.ParseIP("93.184.216.34")
	if len(addresses) != 1 || !addresses[0].IP.Equal(want) {
		t.Fatalf("LookupIPAddr() addresses = %#v, want %s", addresses, want)
	}
	select {
	case query := <-queries:
		if query != "weather.example." {
			t.Fatalf("DNS query = %q, want weather.example.", query)
		}
	case <-time.After(time.Second):
		t.Fatal("configured DNS service did not receive a query")
	}
}

func TestExamplesNetworkExecutorRejectsBlockedResolvedAddress(t *testing.T) {
	dnsAddress, _ := startExamplesTestDNSServer(t, [4]byte{127, 0, 0, 1})
	executor := newExamplesNetworkExecutor(dnsAddress)
	grant := connectivity.ConnectionGrant{
		GrantID:                 "netgrant_examples_test",
		PluginInstanceID:        "plugini_examples_weather",
		ActiveFingerprint:       "sha256:examples",
		ConnectorID:             "geocoding",
		Transport:               connectivity.TransportHTTP,
		Destination:             connectivity.Destination{Transport: connectivity.TransportHTTP, Scheme: "http", Host: "weather.example", Port: 80},
		TargetClassifierVersion: version.TargetClassifierVersion,
		ExpiresAt:               time.Now().UTC().Add(time.Minute),
	}

	_, err := executor.DoHTTP(context.Background(), connectivity.HTTPRequest{Grant: grant, Timeout: time.Second})
	if !errors.Is(err, connectivity.ErrTargetDenied) {
		t.Fatalf("DoHTTP(loopback DNS answer) error = %v, want ErrTargetDenied", err)
	}
}

func TestExamplesNetworkExecutorFetchesOpenMeteo(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_RUN_LIVE_EXAMPLES_NETWORK") != "1" {
		t.Skip("set REDEVPLUGIN_RUN_LIVE_EXAMPLES_NETWORK=1 to run the live Open-Meteo check")
	}
	now := time.Now().UTC()
	executor := newExamplesNetworkExecutor(examplesPublicDNSServer)
	response, err := executor.DoHTTP(context.Background(), connectivity.HTTPRequest{
		Grant: connectivity.ConnectionGrant{
			GrantID:                 "netgrant_examples_open_meteo",
			PluginInstanceID:        "plugini_examples_weather",
			ActiveFingerprint:       "sha256:examples",
			ConnectorID:             "forecast",
			Transport:               connectivity.TransportHTTP,
			Destination:             connectivity.Destination{Transport: connectivity.TransportHTTP, Scheme: "https", Host: "api.open-meteo.com", Port: 443},
			TargetClassifierVersion: version.TargetClassifierVersion,
			ExpiresAt:               now.Add(time.Minute),
		},
		Method: http.MethodGet,
		Path:   "/v1/forecast",
		Query: url.Values{
			"latitude":      []string{"52.52"},
			"longitude":     []string{"13.41"},
			"timezone":      []string{"Europe/Berlin"},
			"forecast_days": []string{"1"},
			"current":       []string{"temperature_2m"},
		},
		MaxResponseBytes: 64 << 10,
		Timeout:          10 * time.Second,
		Now:              now,
	})
	if err != nil {
		t.Fatalf("DoHTTP(Open-Meteo) error = %v", err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(response.Body), `"temperature_2m"`) {
		t.Fatalf("Open-Meteo response = HTTP %d %s", response.StatusCode, response.Body)
	}
}

func TestExamplesWeatherPluginFetchesLiveForecast(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_RUN_LIVE_EXAMPLES_NETWORK") != "1" {
		t.Skip("set REDEVPLUGIN_RUN_LIVE_EXAMPLES_NETWORK=1 to run the live Weather plugin check")
	}
	repositoryRoot := cliRepoRoot(t)
	runtimePath := buildExamplesRuntime(t, repositoryRoot)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverResult := make(chan error, 1)
	hostReady := make(chan *host.Host, 1)
	go func() {
		serverResult <- examplesServerWithOptions(ctx, t.TempDir(), runtimePath, examplesServerOptions{
			Listener:       listener,
			Output:         io.Discard,
			RepositoryRoot: repositoryRoot,
			OnReady:        func(pluginHost *host.Host) { hostReady <- pluginHost },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case serverErr := <-serverResult:
			if serverErr != nil && !errors.Is(serverErr, context.Canceled) {
				t.Errorf("examples server shutdown error = %v", serverErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("examples server did not stop")
		}
	})

	var pluginHost *host.Host
	select {
	case pluginHost = <-hostReady:
	case <-time.After(20 * time.Second):
		t.Fatal("examples Host did not become ready")
	}
	records, err := pluginHost.ListPlugins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var weatherRecord hostPluginRecord
	for _, record := range records {
		if record.PluginID == "dev.redevplugin.examples.weather" {
			weatherRecord = hostPluginRecord{instanceID: record.PluginInstanceID, stateVersion: record.ManagementRevision}
			break
		}
	}
	if weatherRecord.instanceID == "" {
		t.Fatal("Weather example plugin is not installed")
	}
	now := time.Now().UTC()
	bootstrap, err := pluginHost.OpenSurface(context.Background(), host.OpenSurfaceRequest{
		PluginInstanceID:           weatherRecord.instanceID,
		ExpectedManagementRevision: weatherRecord.stateVersion,
		SurfaceID:                  "weather.view",
		SurfaceInstanceID:          "surface_examples_weather_live_test",

		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pluginHost.PrepareSurface(context.Background(), host.ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,

		Now: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	handshake := bridge.Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		ManagementRevision: bootstrap.ManagementRevision,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v4",
	}
	bridgeChannelID := "bridge_examples_weather_live_test"
	gateway, err := pluginHost.MintBridgeToken(context.Background(), host.MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           bridgeChannelID,
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, bridgeChannelID),

		Now: now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := pluginHost.CallPluginMethod(context.Background(), host.CallMethodRequest{
		PluginInstanceID:  weatherRecord.instanceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,

		BridgeChannelID: bridgeChannelID,
		GatewayToken:    gateway.GatewayToken,
		Method:          "weather.forecast",
		Params: map[string]any{
			"latitude":  52.52,
			"longitude": 13.41,
			"timezone":  "Europe/Berlin",
		},
		Now: now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("CallPluginMethod(weather.forecast) error = %v", err)
	}
	if fmt.Sprint(result.Data) == "" {
		t.Fatal("Weather forecast result is empty")
	}
}

type hostPluginRecord struct {
	instanceID   string
	stateVersion uint64
}

func TestExamplesHealthHandlerReadsLiveRuntimeHealth(t *testing.T) {
	runtimeHealth := &examplesRuntimeHealthStub{health: runtimeclient.ManagerHealth{
		Ready: true,
		Shards: []runtimeclient.ShardHealth{{
			RuntimeShardID: "runtime_shard_00",
			Health: runtimeclient.Health{
				Ready:               true,
				RuntimeGenerationID: "runtime_generation_1",
			},
		}},
	}}
	handler := examplesHealthHandler(runtimeHealth, 3)

	first := httptest.NewRecorder()
	handler(first, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"ready":true`) || !strings.Contains(first.Body.String(), `"runtime_shard_id":"runtime_shard_00"`) || !strings.Contains(first.Body.String(), `"runtime_generation_id":"runtime_generation_1"`) {
		t.Fatalf("first health response = HTTP %d %s", first.Code, first.Body.String())
	}

	runtimeHealth.health.Ready = false
	second := httptest.NewRecorder()
	handler(second, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), `"ready":false`) {
		t.Fatalf("live health response = HTTP %d %s", second.Code, second.Body.String())
	}
}

func TestValidateExamplesJSONMutationRequestRequiresExactOriginAndJSON(t *testing.T) {
	origin := "http://127.0.0.1:4175"
	tests := []struct {
		name    string
		request *http.Request
		wantErr error
	}{
		{
			name: "same origin JSON",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, origin+"/api/open", strings.NewReader(`{"slug":"weather"}`))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json; charset=utf-8")
				return r
			}(),
		},
		{
			name: "missing origin",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, origin+"/api/open", strings.NewReader(`{"slug":"weather"}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			wantErr: errExamplesOriginDenied,
		},
		{
			name: "foreign origin",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, origin+"/api/open", strings.NewReader(`{"slug":"weather"}`))
				r.Header.Set("Origin", "https://attacker.example")
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			wantErr: errExamplesOriginDenied,
		},
		{
			name: "simple text body",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, origin+"/api/open", strings.NewReader(`{"slug":"weather"}`))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "text/plain")
				return r
			}(),
			wantErr: errExamplesContentTypeInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExamplesJSONMutationRequest(tt.request, origin)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateExamplesJSONMutationRequest() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestExamplesServerBrowserSmoke(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_RUN_BROWSER_SMOKE") != "1" {
		t.Skip("set REDEVPLUGIN_RUN_BROWSER_SMOKE=1 to run the browser acceptance suite")
	}
	repositoryRoot := cliRepoRoot(t)
	runtimePath := buildExamplesRuntime(t, repositoryRoot)
	stateRoot := t.TempDir()
	primeExamplesPersistentState(t, stateRoot, runtimePath, repositoryRoot)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverResult := make(chan error, 1)
	hostReady := make(chan *host.Host, 1)
	events := newExamplesRecordingEvents()
	go func() {
		serverResult <- examplesServerWithOptions(ctx, stateRoot, runtimePath, examplesServerOptions{
			Listener:          listener,
			NetworkExecutor:   examplesFixtureNetworkExecutor{},
			Events:            events,
			Output:            io.Discard,
			RepositoryRoot:    repositoryRoot,
			RuntimeShardCount: 1,
			OnReady:           func(pluginHost *host.Host) { hostReady <- pluginHost },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serverResult:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("examples server shutdown error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("examples server did not stop")
		}
	})

	origin := "http://" + listener.Addr().String()
	var pluginHost *host.Host
	select {
	case pluginHost = <-hostReady:
	case <-time.After(20 * time.Second):
		t.Fatal("examples Host did not become ready")
	}
	waitForExamplesHealth(t, origin)
	evidenceDir := strings.TrimSpace(os.Getenv("REDEVPLUGIN_EXAMPLES_EVIDENCE_DIR"))
	if evidenceDir == "" {
		evidenceDir = filepath.Join(t.TempDir(), "evidence")
	}
	command := exec.Command("node", "internal/browserharness/examples-server-smoke.mjs")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(),
		"REDEVPLUGIN_EXAMPLES_URL="+origin,
		"REDEVPLUGIN_EXAMPLES_EVIDENCE_DIR="+evidenceDir,
	)
	if output, err := command.CombinedOutput(); err != nil {
		health, healthErr := pluginHost.RuntimeHealth(context.Background())
		diagnostics, diagnosticErr := pluginHost.ListDiagnosticEvents(examplesContext(context.Background()), host.ListDiagnosticEventsRequest{Limit: 50})
		t.Fatalf("examples browser smoke failed: %v\n%s\nruntime health: %#v (error=%v)\ndiagnostics: %#v (error=%v)\ninternal diagnostics: %#v", err, output, health, healthErr, diagnostics, diagnosticErr, events.snapshotDiagnostics())
	}
}

func primeExamplesPersistentState(t *testing.T, stateRoot string, runtimePath string, repositoryRoot string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	ready := make(chan struct{}, 1)
	go func() {
		result <- examplesServerWithOptions(ctx, stateRoot, runtimePath, examplesServerOptions{
			Listener:          listener,
			NetworkExecutor:   examplesFixtureNetworkExecutor{},
			Output:            io.Discard,
			RepositoryRoot:    repositoryRoot,
			RuntimeShardCount: 1,
			OnReady:           func(*host.Host) { ready <- struct{}{} },
		})
	}()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("first examples Host did not become ready")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("first examples server shutdown error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first examples server did not stop")
	}
}

func buildExamplesRuntime(t *testing.T, repositoryRoot string) string {
	t.Helper()
	cargo := "cargo"
	if _, err := exec.LookPath(cargo); err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			t.Fatal(homeErr)
		}
		cargo = filepath.Join(home, ".cargo", "bin", "cargo")
		if _, err := os.Stat(cargo); err != nil {
			t.Fatalf("cargo is unavailable: %v", err)
		}
	}
	command := exec.Command(cargo, "build", "-p", "redevplugin-runtime")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cargo build -p redevplugin-runtime failed: %v\n%s", err, output)
	}
	runtimePath := filepath.Join(repositoryRoot, "target", "debug", "redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}
	return runtimePath
}

func waitForExamplesHealth(t *testing.T, origin string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		response, err := client.Get(origin + "/api/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("health returned HTTP %d", response.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("examples server did not become ready: %v", lastErr)
}

type examplesFixtureNetworkExecutor struct{}

type examplesRuntimeHealthStub struct {
	health runtimeclient.ManagerHealth
	err    error
}

func (s *examplesRuntimeHealthStub) RuntimeHealth(context.Context) (runtimeclient.ManagerHealth, error) {
	return s.health, s.err
}

func (examplesFixtureNetworkExecutor) DoHTTP(_ context.Context, request connectivity.HTTPRequest) (connectivity.HTTPResponse, error) {
	if request.Method != http.MethodGet {
		return connectivity.HTTPResponse{}, fmt.Errorf("fixture only supports GET requests")
	}
	var body string
	switch request.Grant.ConnectorID {
	case "geocoding":
		if request.Path != "/v1/search" || strings.TrimSpace(request.Query.Get("name")) == "" {
			return connectivity.HTTPResponse{}, fmt.Errorf("invalid geocoding fixture request")
		}
		if strings.Contains(strings.ToLower(request.Query.Get("name")), "paris") {
			body = `{"results":[{"id":2988507,"name":"Paris","latitude":48.8566,"longitude":2.3522,"country":"France","admin1":"Ile-de-France","timezone":"Europe/Paris"}]}`
		} else {
			body = `{"results":[{"id":2950159,"name":"Berlin","latitude":52.52,"longitude":13.41,"country":"Germany","admin1":"Berlin","timezone":"Europe/Berlin"}]}`
		}
	case "forecast":
		if request.Path != "/v1/forecast" || request.Query.Get("forecast_days") != "7" {
			return connectivity.HTTPResponse{}, fmt.Errorf("invalid forecast fixture request")
		}
		if strings.HasPrefix(request.Query.Get("latitude"), "48.8566") {
			body = `{"timezone":"Europe/Paris","timezone_abbreviation":"CEST","current":{"time":"2026-07-14T14:00","temperature_2m":25.6,"relative_humidity_2m":47,"apparent_temperature":26.1,"is_day":1,"weather_code":0,"wind_speed_10m":8.4},"daily":{"time":["2026-07-14","2026-07-15","2026-07-16","2026-07-17","2026-07-18","2026-07-19","2026-07-20"],"weather_code":[0,1,2,3,61,1,0],"temperature_2m_max":[28,29,27,25,22,27,30],"temperature_2m_min":[18,19,18,17,16,18,20],"precipitation_probability_max":[5,5,15,25,65,10,5],"sunrise":["2026-07-14T06:02","2026-07-15T06:03","2026-07-16T06:04","2026-07-17T06:05","2026-07-18T06:06","2026-07-19T06:08","2026-07-20T06:09"],"sunset":["2026-07-14T21:50","2026-07-15T21:49","2026-07-16T21:48","2026-07-17T21:47","2026-07-18T21:46","2026-07-19T21:45","2026-07-20T21:44"]}}`
		} else {
			body = `{"timezone":"Europe/Berlin","timezone_abbreviation":"CEST","current":{"time":"2026-07-14T14:00","temperature_2m":21.4,"relative_humidity_2m":52,"apparent_temperature":21.1,"is_day":1,"weather_code":1,"wind_speed_10m":12.7},"daily":{"time":["2026-07-14","2026-07-15","2026-07-16","2026-07-17","2026-07-18","2026-07-19","2026-07-20"],"weather_code":[1,2,3,61,2,1,0],"temperature_2m_max":[24,25,23,19,22,26,27],"temperature_2m_min":[15,16,14,13,14,16,17],"precipitation_probability_max":[10,15,25,70,20,5,5],"sunrise":["2026-07-14T05:00","2026-07-15T05:02","2026-07-16T05:03","2026-07-17T05:04","2026-07-18T05:06","2026-07-19T05:07","2026-07-20T05:09"],"sunset":["2026-07-14T21:22","2026-07-15T21:21","2026-07-16T21:20","2026-07-17T21:19","2026-07-18T21:18","2026-07-19T21:17","2026-07-20T21:15"]}}`
		}
	default:
		return connectivity.HTTPResponse{}, fmt.Errorf("unexpected connector %q", request.Grant.ConnectorID)
	}
	return connectivity.HTTPResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       []byte(body),
	}, nil
}

func (examplesFixtureNetworkExecutor) StreamHTTP(context.Context, connectivity.HTTPRequest, func(connectivity.HTTPResponseChunk) error) (connectivity.HTTPStreamResponse, error) {
	return connectivity.HTTPStreamResponse{}, errors.New("fixture HTTP streaming is unsupported")
}

func (examplesFixtureNetworkExecutor) WebSocketRoundTrip(context.Context, connectivity.WebSocketRoundTripRequest) (connectivity.WebSocketRoundTripResponse, error) {
	return connectivity.WebSocketRoundTripResponse{}, errors.New("fixture WebSocket is unsupported")
}

func (examplesFixtureNetworkExecutor) TCPRoundTrip(context.Context, connectivity.TCPRoundTripRequest) (connectivity.TCPRoundTripResponse, error) {
	return connectivity.TCPRoundTripResponse{}, errors.New("fixture TCP is unsupported")
}

func (examplesFixtureNetworkExecutor) UDPRoundTrip(context.Context, connectivity.UDPRoundTripRequest) (connectivity.UDPRoundTripResponse, error) {
	return connectivity.UDPRoundTripResponse{}, errors.New("fixture UDP is unsupported")
}

type examplesRecordingEvents struct {
	store       *observability.MemoryStore
	mu          sync.Mutex
	diagnostics []observability.DiagnosticEvent
}

func newExamplesRecordingEvents() *examplesRecordingEvents {
	return &examplesRecordingEvents{store: observability.NewMemoryStore()}
}

func (s *examplesRecordingEvents) AppendPluginAudit(ctx context.Context, event observability.AuditEvent) error {
	return s.store.AppendPluginAudit(ctx, event)
}

func (s *examplesRecordingEvents) AppendPluginDiagnostic(ctx context.Context, event observability.DiagnosticEvent) error {
	s.mu.Lock()
	s.diagnostics = append(s.diagnostics, event)
	s.mu.Unlock()
	return s.store.AppendPluginDiagnostic(ctx, event)
}

func (s *examplesRecordingEvents) ListPluginDiagnostics(ctx context.Context, req observability.ListDiagnosticRequest) ([]observability.DiagnosticEvent, error) {
	return s.store.ListPluginDiagnostics(ctx, req)
}

func (s *examplesRecordingEvents) snapshotDiagnostics() []observability.DiagnosticEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]observability.DiagnosticEvent(nil), s.diagnostics...)
}

func startExamplesTestDNSServer(t *testing.T, answer [4]byte) (string, <-chan string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	queries := make(chan string, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 1232)
		for {
			n, client, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			var parser dnsmessage.Parser
			header, parseErr := parser.Start(buffer[:n])
			if parseErr != nil {
				continue
			}
			question, parseErr := parser.Question()
			if parseErr != nil {
				continue
			}
			select {
			case queries <- question.Name.String():
			default:
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID:                 header.ID,
				Response:           true,
				RecursionDesired:   header.RecursionDesired,
				RecursionAvailable: true,
			})
			builder.EnableCompression()
			if builder.StartQuestions() != nil || builder.Question(question) != nil || builder.StartAnswers() != nil {
				continue
			}
			if question.Type == dnsmessage.TypeA {
				if builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: answer}) != nil {
					continue
				}
			}
			response, buildErr := builder.Finish()
			if buildErr == nil {
				_, _ = conn.WriteToUDP(response, client)
			}
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	return conn.LocalAddr().String(), queries
}
