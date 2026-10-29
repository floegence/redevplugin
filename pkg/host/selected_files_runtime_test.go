package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

func TestSelectedFilesThroughBuiltRustWorker(t *testing.T) {
	root := findRepoRootForHostTest(t)
	for _, args := range [][]string{
		{"build", "-p", "redevplugin-runtime"},
		{"build", "-p", "redevplugin-selected-file-test-worker", "--target", "wasm32-unknown-unknown", "--release"},
	} {
		cmd := exec.Command("cargo", args...)
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
	}
	path := filepath.Join(t.TempDir(), "worker.txt")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, filePicker: selectedPickerFixture{path: path}})
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
	var declaration map[string]any
	if err := json.Unmarshal([]byte(workerFixtureManifestJSON()), &declaration); err != nil {
		t.Fatal(err)
	}
	declaration["permissions"] = []string{"fs.selected.read", "fs.selected.write"}
	declaration["api"] = map[string]any{"major": 1, "required_features": []string{"authorization.scoped.v1", "fs.selected.v1"}, "optional_features": []string{}}
	method := declaration["methods"].([]any)[0].(map[string]any)
	method["effect"] = "write"
	method["permissions"] = []string{"fs.selected.read", "fs.selected.write"}
	method["request_schema"] = map[string]any{"type": "object", "required": []string{"uri", "text"}, "properties": map[string]any{"uri": map[string]any{"type": "string"}, "text": map[string]any{"type": "string"}}, "additionalProperties": false}
	method["response_schema"] = map[string]any{"type": "object", "properties": map[string]any{"code": map[string]any{"type": "string"}, "before": map[string]any{"type": "string"}, "after": map[string]any{"type": "string"}}, "additionalProperties": false}
	raw, _ := json.Marshal(declaration)
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Selected file worker")
	wasm, err := os.ReadFile(filepath.Join(root, "target/wasm32-unknown-unknown/release/redevplugin_selected_file_test_worker.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	writeBytes(t, filepath.Join(dir, "workers/echo.wasm"), wasm)
	var pkg bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, dir, &pkg, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	installed := installAndEnablePlugin(t, h, pkg.Bytes())
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "worker.view")
	call := func(uri string) map[string]any {
		t.Helper()
		result, err := h.CallPluginMethod(ctx, CallMethodRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "worker.echo", Params: map[string]any{"uri": uri, "text": "Saved 中文"}})
		if err != nil {
			t.Fatal(err)
		}
		resultMap, ok := result.Data.(map[string]any)
		if !ok {
			t.Fatalf("worker data: %#v", result.Data)
		}
		return resultMap
	}
	if result := call("redevfs://selected-" + strings.Repeat("a", 64) + "/"); result["code"] != "PERMISSION_DENIED" {
		t.Fatalf("missing authority: %v", result)
	}
	review, err := h.SelectFileResource(ctx, SelectFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, Kind: "file", Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := h.ApproveFileResource(ctx, ApproveFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, ReviewID: review.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	if result := call(resource.URI); result["before"] != "before" || result["after"] != "Saved 中文" {
		t.Fatalf("worker I/O: %v", result)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "Saved 中文" {
		t.Fatalf("disk: %q %v", data, err)
	}
	if result := call("redevfs://home/private"); result["code"] != "PERMISSION_DENIED" {
		t.Fatalf("root authority widened: %v", result)
	}
	if err := h.RevokeFileResource(ctx, RevokeFileResourceRequest{PluginInstanceID: installed.PluginInstanceID, ResourceID: resource.ResourceID, ExpectedRevision: resource.Revision}); err != nil {
		t.Fatal(err)
	}
	if result := call(resource.URI); result["code"] != "PERMISSION_DENIED" {
		t.Fatalf("revoked authority: %v", result)
	}
}
