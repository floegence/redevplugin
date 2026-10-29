package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/version"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
)

type blockingNetworkPolicy struct {
	entered chan struct{}
	unblock chan struct{}
}

func (p blockingNetworkPolicy) AuthorizeNetwork(ctx context.Context, _ NetworkAuthorizationRequest) error {
	close(p.entered)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.unblock:
		return context.Canceled
	}
}

func TestRuntimeNetworkRevocationCancelsAdmissionWithoutGlobalLock(t *testing.T) {
	policy := blockingNetworkPolicy{entered: make(chan struct{}), unblock: make(chan struct{})}
	defer close(policy.unblock)
	b, err := newHostRuntimeIOBroker(normalizedAdapters{Connectivity: connectivity.NewMemoryBroker(), NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{}), NetworkPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	inv := runtimeIOTestInvocation("blocked-network", "network-session", "network-channel")
	inv.Permissions[resourceio.PermissionNetworkClient] = true
	r, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{Network: []workerNetworkBrokerAccess{{ConnectorID: "forecast", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.register(context.Background(), inv.Owner.InvocationID, r); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = b.Control(context.Background(), inv.Owner.InvocationID, []byte(`{"plugin_api":1,"operation":"net.http.begin","arguments":{"connector_id":"forecast","method":"GET","url":"https://api.example.com","timeout_ms":30000}}`))
	}()
	select {
	case <-policy.entered:
	case <-time.After(time.Second):
		t.Fatal("policy not entered")
	}
	revoked := make(chan struct{})
	go func() { defer close(revoked); _ = b.release(inv.Owner.InvocationID) }()
	select {
	case <-revoked:
	case <-time.After(time.Second):
		t.Fatal("revocation waited for global read lock instead of canceling the request")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled admission did not finish")
	}
}

func TestRuntimeNetworkRequiresExplicitConnectorBeforeOutbound(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			var received atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			broker, err := newHostRuntimeIOBroker(normalizedAdapters{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = broker.closeAll() }()
			invocation := runtimeIOTestInvocation("network-read", "network-session", "network-channel")
			invocation.Permissions[resourceio.PermissionNetworkClient] = true
			registration, err := newHostRuntimeIORegistration(invocation, workerBrokerAccess{Network: []workerNetworkBrokerAccess{{ConnectorID: "forecast", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := broker.register(context.Background(), invocation.Owner.InvocationID, registration); err != nil {
				t.Fatal(err)
			}
			rawResponse, err := broker.Control(context.Background(), invocation.Owner.InvocationID, []byte(fmt.Sprintf(`{"plugin_api":1,"operation":"net.http.begin","arguments":{"method":%q,"url":%q,"headers":[],"redirect":"error","timeout_ms":1000}}`, method, server.URL)))
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				OK     bool `json:"ok"`
				Result struct {
					UploadHandle uint64 `json:"upload_handle"`
				} `json:"result"`
			}
			if err := json.Unmarshal(rawResponse, &response); err != nil {
				t.Fatal(err)
			}
			if response.OK {
				raw, _ := json.Marshal(map[string]any{"plugin_api": 1, "operation": "net.http.finish", "arguments": map[string]any{"handle": response.Result.UploadHandle}})
				_, _ = broker.Control(context.Background(), invocation.Owner.InvocationID, raw)
				t.Errorf("request without a connector was admitted: %v", response)
			}
			if count := received.Load(); count != 0 {
				t.Errorf("unauthorized request reached the real receiver: %d", count)
			}
		})
	}
}

func TestRuntimeNetworkRejectsUndeclaredHTTPMethodBeforePolicy(t *testing.T) {
	policy := &recordingHostNetworkAdapter{}
	b, err := newHostRuntimeIOBroker(normalizedAdapters{Connectivity: connectivity.NewMemoryBroker(), NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{}), NetworkPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.closeAll() }()
	inv := runtimeIOTestInvocation("read-only-network", "network-session", "network-channel")
	inv.Permissions[resourceio.PermissionNetworkClient] = true
	r, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{Network: []workerNetworkBrokerAccess{{ConnectorID: "forecast", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.register(context.Background(), inv.Owner.InvocationID, r); err != nil {
		t.Fatal(err)
	}
	response := runtimeIOControl(t, b, inv.Owner.InvocationID, `{"plugin_api":1,"operation":"net.http.begin","arguments":{"connector_id":"forecast","method":"POST","url":"https://api.example.com/"}}`)
	if response["ok"] == true || policy.request.Operation != "" {
		t.Fatalf("undeclared POST reached product policy: %v %+v", response, policy.request)
	}
}

func TestRuntimeNetworkShutdownRejectsNewInvocations(t *testing.T) {
	b, err := newHostRuntimeIOBroker(normalizedAdapters{})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.closeAll(); err != nil {
		t.Fatal(err)
	}
	inv := runtimeIOTestInvocation("after-close", "network-session", "network-channel")
	r, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.register(context.Background(), inv.Owner.InvocationID, r); err == nil {
		t.Fatal("closed broker admitted a new invocation")
	}
}

func TestRuntimeNetworkRegistrationReplacesCallerSuppliedAccess(t *testing.T) {
	inv := runtimeIOTestInvocation("declarations", "network-session", "network-channel")
	inv.Permissions[resourceio.PermissionNetworkClient] = true
	inv.Network = []resourceio.NetworkAccess{{ConnectorID: "injected", HTTPMethods: []string{"POST"}}}
	access := workerBrokerAccess{Network: []workerNetworkBrokerAccess{{ConnectorID: "forecast", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}}}
	r, err := newHostRuntimeIORegistration(inv, access, nil)
	if err != nil {
		t.Fatal(err)
	}
	access.Network[0].HTTPMethods[0] = "POST"
	if len(r.resource.Network) != 1 || r.resource.Network[0].ConnectorID != "forecast" || r.resource.Network[0].HTTPMethods[0] != "GET" {
		t.Fatalf("registration did not own immutable declarations: %+v", r.resource.Network)
	}
}

type networkGrantFixture struct {
	connectivity.Broker
	mutate func(*connectivity.ConnectionGrant)
}

func (f networkGrantFixture) MintConnectionGrant(ctx context.Context, req connectivity.GrantRequest) (connectivity.ConnectionGrant, error) {
	grant, err := f.Broker.MintConnectionGrant(ctx, req)
	if err == nil && f.mutate != nil {
		f.mutate(&grant)
	}
	return grant, err
}

type networkExecutorObserver struct {
	connectivity.NetworkExecutor
	opened atomic.Int32
}

func (e *networkExecutorObserver) OpenHTTP(ctx context.Context, req connectivity.HTTPRequest) (connectivity.HTTPBodyResponse, error) {
	e.opened.Add(1)
	return connectivity.HTTPBodyResponse{StatusCode: 200, Headers: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func TestRuntimeNetworkBindsGrantToExactInvocationBeforeExecutor(t *testing.T) {
	for _, name := range []string{"valid", "owner", "fingerprint", "connector", "target", "policy", "management", "epoch", "generation", "private", "methods"} {
		t.Run(name, func(t *testing.T) {
			inv := runtimeIOTestInvocation("network-grant", "network-session", "network-channel")
			inv.PolicyRevision = 3
			inv.Permissions[resourceio.PermissionNetworkClient] = true
			memory := connectivity.NewMemoryBroker()
			session := resourceInvocationSession(inv)
			destination, err := connectivity.ParseDestination(connectivity.TransportHTTP, "https://api.example.com")
			if err != nil {
				t.Fatal(err)
			}
			policy := connectivity.PolicySet{PluginInstanceID: inv.Plugin.InstanceID, ActiveFingerprint: inv.Owner.ActiveFingerprint, PolicyRevision: inv.PolicyRevision, ManagementRevision: inv.Owner.ManagementRevision, RevokeEpoch: inv.Owner.RevokeEpoch, TargetClassifierVersion: version.TargetClassifierVersion, Connectors: []connectivity.ConnectorPolicy{{ConnectorID: "api", Transport: connectivity.TransportHTTP, Scope: connectivity.ScopeUser, Destinations: []connectivity.Destination{destination}}}}
			if err := memory.InstallPolicy(sessionctx.WithContext(context.Background(), session), policy); err != nil {
				t.Fatal(err)
			}
			fixture := networkGrantFixture{Broker: memory, mutate: func(g *connectivity.ConnectionGrant) {
				switch name {
				case "owner":
					g.ResourceScope.OwnerUserHash = "other"
				case "fingerprint":
					g.ActiveFingerprint = "other"
				case "connector":
					g.ConnectorID = "other"
				case "target":
					g.Destination.Host = "other.example.com"
				case "policy":
					g.PolicyRevision++
				case "management":
					g.ManagementRevision++
				case "epoch":
					g.RevokeEpoch++
				case "generation":
					g.RuntimeGenerationID = "other"
				case "private":
					g.PrivatePrefixes = []string{"127.0.0.1/32"}
				case "methods":
					g.HTTPMethods = []string{"POST"}
				}
			}}
			executor := &networkExecutorObserver{}
			broker, err := newHostRuntimeIOBroker(normalizedAdapters{Connectivity: fixture, NetworkExecutor: executor})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = broker.closeAll() }()
			registration, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{Network: []workerNetworkBrokerAccess{{ConnectorID: "api", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/a%2fb?signature=a%2fb", nil)
			response, err := broker.HTTPTransport(registration.resource, "api").RoundTrip(request)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if executor.opened.Load() != 1 {
					t.Fatal("valid grant never reached executor")
				}
			} else if err == nil || executor.opened.Load() != 0 {
				t.Fatalf("substituted grant reached executor: %v, %d", err, executor.opened.Load())
			}
		})
	}
}

func TestRuntimeNetworkExecutionCancellationStopsAdmission(t *testing.T) {
	b, err := newHostRuntimeIOBroker(normalizedAdapters{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.closeAll() }()
	inv := runtimeIOTestInvocation("cancel-before-open", "session", "channel")
	registration, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := b.register(ctx, inv.Owner.InvocationID, registration); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := b.Control(context.Background(), inv.Owner.InvocationID, []byte("{}")); !errors.Is(err, resourceio.ErrResourceClosed) {
		t.Fatalf("canceled execution admitted I/O: %v", err)
	}
}

func TestRuntimeNetworkRejectsUnknownTargetBeforeAnyReceiver(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	inv := runtimeIOTestInvocation("unknown-target", "network-session", "network-channel")
	inv.Permissions[resourceio.PermissionNetworkClient] = true
	memory := connectivity.NewMemoryBroker()
	session := resourceInvocationSession(inv)
	target, _ := connectivity.ParseDestination(connectivity.TransportHTTP, "https://api.example.com")
	policy := connectivity.PolicySet{PluginInstanceID: inv.Plugin.InstanceID, ActiveFingerprint: inv.Owner.ActiveFingerprint, PolicyRevision: inv.PolicyRevision, ManagementRevision: inv.Owner.ManagementRevision, RevokeEpoch: inv.Owner.RevokeEpoch, TargetClassifierVersion: version.TargetClassifierVersion, Connectors: []connectivity.ConnectorPolicy{{ConnectorID: "api", Transport: connectivity.TransportHTTP, Scope: connectivity.ScopeUser, Destinations: []connectivity.Destination{target}}}}
	if err := memory.InstallPolicy(sessionctx.WithContext(context.Background(), session), policy); err != nil {
		t.Fatal(err)
	}
	b, err := newHostRuntimeIOBroker(normalizedAdapters{Connectivity: memory, NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.closeAll() }()
	registration, err := newHostRuntimeIORegistration(inv, workerBrokerAccess{Network: []workerNetworkBrokerAccess{{ConnectorID: "api", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"api", "unknown"} {
		request, _ := http.NewRequest("GET", server.URL+"/must-not-arrive", nil)
		if response, err := b.HTTPTransport(registration.resource, connector).RoundTrip(request); err == nil {
			response.Body.Close()
			t.Fatalf("%s reached unauthorized destination", connector)
		}
	}
	if received.Load() != 0 {
		t.Fatalf("receiver observed %d unauthorized requests", received.Load())
	}
}

type networkSecretFixture struct {
	calls   int
	headers http.Header
}

func (s *networkSecretFixture) ResolveNetworkSecret(_ context.Context, _ NetworkSecretRequest) (http.Header, error) {
	s.calls++
	return s.headers, nil
}
func credentialNetworkFixture(t *testing.T) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(workerNetworkFixtureManifestJSON()), &m); err != nil {
		t.Fatal(err)
	}
	c := m["network_access"].(map[string]any)["connectors"].([]any)[0].(map[string]any)
	c["destinations"] = []string{"https://api.example.com", "https://other.example.com"}
	c["auth"] = map[string]any{"secret_ref": "api-secret"}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Credentials")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var out bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &out, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestRuntimeNetworkCredentialsStayOutOfRedirectRequests(t *testing.T) {
	h, ctx, _, inv := connectionFixture(t, credentialNetworkFixture(t))
	observer := &webNetworkObserver{}
	h.runtimeIO.networkExecutor = observer
	resolver := &networkSecretFixture{headers: http.Header{"Authorization": {"Bearer private"}, "X-API-Key": {"private-key"}}}
	h.networkSecrets = resolver
	inv.Network = []resourceio.NetworkAccess{{ConnectorID: "api", Transport: "http", Scope: "user", Operations: []string{"http"}, HTTPMethods: []string{"GET"}}}
	transport := &runtimeHTTPTransport{broker: h.runtimeIO, invocation: inv, connector: "api"}
	original := http.Header{"X-App": {"keep"}}
	for _, address := range []string{"https://api.example.com/start", "https://other.example.com/next", "https://api.example.com/return"} {
		req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = original
		response, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if req.Header.Get("Authorization") != "" || req.Header.Get("X-API-Key") != "" {
			t.Fatal("credential contaminated caller request")
		}
	}
	if resolver.calls != 1 || len(observer.requests) != 3 {
		t.Fatalf("calls=%d requests=%d", resolver.calls, len(observer.requests))
	}
	for i, request := range observer.requests {
		if i == 0 {
			if request.Headers.Get("X-API-Key") != "private-key" {
				t.Fatal("credential missing")
			}
		} else if request.Headers.Get("Authorization") != "" || request.Headers.Get("X-API-Key") != "" {
			t.Fatal("credential crossed origin")
		}
	}
}
func TestRuntimeNetworkRejectsCredentialTransportOverrides(t *testing.T) {
	for _, header := range []http.Header{{"Host": {"evil.example"}}, {"Sec-Fetch-Site": {"same-origin"}}, {"Authorization": {"invalid\r\nvalue"}}, {"Proxy-Authorization": {"private"}}, {"X-Key": {strings.Repeat("x", 16<<10)}}} {
		if validateCredentialHeaders(header) == nil {
			t.Fatalf("accepted credential header %v", header)
		}
	}
}
