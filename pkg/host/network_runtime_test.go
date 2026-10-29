package host

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type allowNetworkFixture struct{}

func (allowNetworkFixture) AuthorizePrivateNetwork(context.Context, PrivateNetworkRequest) error {
	return nil
}
func TestControlledNetworkThroughBuiltRustWorker(t *testing.T) {
	root := findRepoRootForHostTest(t)
	for _, args := range [][]string{{"build", "-p", "redevplugin-runtime"}, {"build", "-p", "redevplugin-network-test-worker", "--target", "wasm32-unknown-unknown", "--release"}} {
		cmd := exec.Command("cargo", args...)
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/ws" {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = c.CloseNow() }()
			kind, body, err := c.Read(r.Context())
			if err == nil {
				_ = c.Write(r.Context(), kind, body)
				_ = c.Close(websocket.StatusNormalClosure, "done")
			}
			return
		}
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))
	defer server.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				body, _ := io.ReadAll(c)
				_, _ = c.Write(body)
			}()
		}
	}()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 64)
		for {
			n, peer, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(buffer[:n], peer)
		}
	}()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, networkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})})
	h.privateNetworkPolicy = allowNetworkFixture{}
	runtimePath := filepath.Join(root, "target/debug/redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{
		Limits: runtimeclient.DefaultRuntimeLimits(), HeartbeatInterval: 2 * time.Second, MaxHeartbeatStaleness: 5 * time.Second,
		RuntimePath: runtimePath, ArtifactIdentity: hostRuntimeTestDescriptor(t, runtimePath), Diagnostics: h.adapters.Diagnostics,
		Artifacts: runtimeArtifactProvider{assets: h.adapters.Assets}, StreamSink: hostRuntimeStreamSink{executions: h.executions},
		IOBroker: h.runtimeIO, HandshakeTimeout: hostRuntimeProcessHandshakeTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeManager = testProcessManager{ProcessSupervisor: supervisor}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = supervisor.Stop(ctx)
	})
	ctx := hostRuntimeWritableTestContext()
	if err := supervisor.Start(ctx, hostRuntimeTestTarget(t)); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	var m map[string]any
	if err := json.Unmarshal([]byte(workerNetworkFixtureManifestJSON()), &m); err != nil {
		t.Fatal(err)
	}
	method := m["methods"].([]any)[0].(map[string]any)
	method["request_schema"] = map[string]any{"type": "object", "properties": map[string]any{"transport": map[string]any{"type": "string"}, "connector": map[string]any{"type": "string"}, "url": map[string]any{"type": "string"}, "method": map[string]any{"type": "string"}, "host": map[string]any{"type": "string"}, "port": map[string]any{"type": "integer"}}, "additionalProperties": false}
	method["response_schema"] = map[string]any{"type": "object", "properties": map[string]any{"body": map[string]any{"type": "string"}, "code": map[string]any{"type": "string"}, "message": map[string]any{"type": "string"}}, "additionalProperties": false}
	connectors := []any{}
	access := []any{}
	for _, protocol := range []string{"http", "websocket", "tcp", "udp"} {
		connectors = append(connectors, map[string]any{"connector_id": protocol, "transport": protocol, "scope": "user", "configurable": true})
		item := map[string]any{"connector_id": protocol, "transport": protocol, "operations": []string{protocol}}
		if protocol == "http" {
			item["http_methods"] = []string{"GET"}
		}
		access = append(access, item)
	}
	m["network_access"] = map[string]any{"connectors": connectors}
	method["broker_access"] = map[string]any{"network": access}
	raw, _ := json.Marshal(m)
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Network worker")
	wasm, err := os.ReadFile(filepath.Join(root, "target/wasm32-unknown-unknown/release/redevplugin_network_test_worker.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	writeBytes(t, filepath.Join(dir, "workers/echo.wasm"), wasm)
	var pkg bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, dir, &pkg, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	installed := installAndEnablePlugin(t, h, pkg.Bytes())
	if _, err := h.GrantPermission(ctx, GrantPermissionRequest{PluginInstanceID: installed.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: installed.PolicyRevision, ExpectedManagementRevision: installed.ManagementRevision, ExpectedRevokeEpoch: installed.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "worker.view")
	call := func(params map[string]any) map[string]any {
		t.Helper()
		result, err := h.CallPluginMethod(ctx, CallMethodRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "worker.echo", Params: params})
		if err != nil {
			t.Fatalf("params=%v error=%#v", params, err)
		}
		value, ok := result.Data.(map[string]any)
		if !ok {
			t.Fatalf("result: %#v", result.Data)
		}
		return value
	}
	if result := call(map[string]any{"transport": "http", "connector": "http", "url": server.URL}); result["code"] != "PERMISSION_DENIED" {
		t.Fatalf("unapproved network succeeded: %v", result)
	}
	destinations := map[string]string{"http": server.URL, "websocket": "ws" + strings.TrimPrefix(server.URL, "http"), "tcp": "tcp://" + tcp.Addr().String(), "udp": "udp://" + udp.LocalAddr().String()}
	infos := map[string]ConnectionInfo{}
	for protocol, destination := range destinations {
		req := ReviewConnectionRequest{PluginInstanceID: installed.PluginInstanceID, ConnectorID: protocol, Destination: destination, PrivatePrefixes: []string{"127.0.0.1/32"}}
		if protocol == "http" {
			req.HTTPMethods = []string{"GET"}
		}
		review, err := h.ReviewConnection(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		info, err := h.ApproveConnection(ctx, ConnectionReviewRequest{PluginInstanceID: installed.PluginInstanceID, ReviewID: review.ReviewID})
		if err != nil {
			t.Fatal(err)
		}
		infos[protocol] = info
	}
	for _, protocol := range []string{"http", "websocket", "tcp", "udp"} {
		params := map[string]any{"transport": protocol, "connector": protocol}
		expected := "hello"
		switch protocol {
		case "http":
			params["url"] = server.URL + "/signed%2fpath?x=%2f"
			expected = "/signed%2fpath?x=%2f"
		case "websocket":
			params["url"] = destinations[protocol] + "/ws"
		case "tcp":
			params["host"] = "127.0.0.1"
			params["port"] = float64(tcp.Addr().(*net.TCPAddr).Port)
		case "udp":
			params["host"] = "127.0.0.1"
			params["port"] = float64(udp.LocalAddr().(*net.UDPAddr).Port)
		}
		if result := call(params); result["body"] != expected {
			t.Fatalf("%s result: %v", protocol, result)
		}
	}
	before := hits.Load()
	for _, params := range []map[string]any{{"transport": "http", "connector": "http", "url": server.URL, "method": "POST"}, {"transport": "http", "connector": "unknown", "url": server.URL}} {
		if result := call(params); result["code"] != "PERMISSION_DENIED" {
			t.Fatalf("undeclared network succeeded: %v", result)
		}
	}
	if err := h.RevokeConnection(ctx, RevokeConnectionRequest{PluginInstanceID: installed.PluginInstanceID, ConnectorID: "http", ExpectedRevision: infos["http"].Revision}); err != nil {
		t.Fatal(err)
	}
	if result := call(map[string]any{"transport": "http", "connector": "http", "url": server.URL}); result["code"] != "PERMISSION_DENIED" {
		t.Fatalf("revoked network succeeded: %v", result)
	}
	if hits.Load() != before {
		t.Fatal("denied request reached receiver")
	}
}
