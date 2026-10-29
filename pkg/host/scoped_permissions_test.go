package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

func TestScopedWorkerPermissionsReachRuntimeBroker(t *testing.T) {
	runtime := &permissionInspectingRuntimeManager{recordingRuntimeManager: newRecordingRuntimeManager(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime})
	record := installAndEnablePlugin(t, h, buildScopedWorkerFixturePackage(t))
	revisions := mustAuthorizationRevisions(t, h, record.PluginInstanceID)
	if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "fs.environment.read", ExpectedPolicyRevision: revisions.PolicyRevision, ExpectedManagementRevision: revisions.ManagementRevision, ExpectedRevokeEpoch: revisions.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	_, gateway := openSurfaceAndMintGateway(t, h, record.PluginInstanceID, "worker.view")
	call := CallMethodRequest{PluginInstanceID: record.PluginInstanceID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "worker.write", Params: map[string]any{"message": "hello"}}
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("write without grant: %v", err)
	}
	call.Method = "worker.echo"
	done := make(chan error, 1)
	go func() { _, err := h.CallPluginMethod(hostTestContext(), call); done <- err }()
	select {
	case <-runtime.entered:
	case err := <-done:
		t.Fatalf("read rejected before runtime: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not start")
	}
	h.runtimeIO.mu.RLock()
	var actual []map[string]bool
	var invocationID string
	for _, invocation := range h.runtimeIO.invocations {
		invocationID = invocation.resource.Owner.InvocationID
		copied := map[string]bool{}
		for key, granted := range invocation.resource.Permissions {
			copied[key] = granted
		}
		actual = append(actual, copied)
	}
	h.runtimeIO.mu.RUnlock()
	response, err := h.runtimeIO.Control(hostTestContext(), invocationID, []byte(`{"plugin_api":1,"operation":"net.http.begin","arguments":{"method":"GET","url":"https://example.test/","headers":[],"redirect":"error","timeout_ms":1000}}`))
	if err != nil || !bytes.Contains(response, []byte(`"code":"PERMISSION_DENIED"`)) {
		close(runtime.release)
		if callErr := <-done; callErr != nil {
			t.Logf("worker cleanup: %v", callErr)
		}
		t.Fatalf("ungranted network broker response=%s err=%v", response, err)
	}
	close(runtime.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, []map[string]bool{{"fs.environment.read": true}}) {
		t.Fatalf("runtime authority = %#v; must exclude package write/network permissions", actual)
	}
	revisions = mustAuthorizationRevisions(t, h, record.PluginInstanceID)
	if _, err := h.RevokePermission(hostTestContext(), RevokePermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "fs.environment.read", ExpectedPolicyRevision: revisions.PolicyRevision, ExpectedManagementRevision: revisions.ManagementRevision, ExpectedRevokeEpoch: revisions.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("stale gateway after revoke: %v", err)
	}
	_, gateway = openSurfaceAndMintGateway(t, h, record.PluginInstanceID, "worker.view")
	call.GatewayToken = gateway.GatewayToken
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("fresh gateway must retain revoked ceiling: %v", err)
	}
}

func TestScopedSurfaceOpensWithoutUnrelatedPermissions(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	record := installAndEnablePlugin(t, h, buildScopedWorkerFixturePackage(t))
	inventory, err := h.ListPluginInventory(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 1 || !inventory[0].ActionState.CanOpen {
		t.Fatalf("inventory = %#v", inventory)
	}
	want := []PluginSurfaceActionState{{SurfaceID: "worker.view", CanOpen: true}, {SurfaceID: "worker.protected", BlockedReason: PluginActionBlockedPermission}}
	if !reflect.DeepEqual(inventory[0].ActionState.Surfaces, want) {
		t.Fatalf("surface projection = %#v", inventory[0].ActionState.Surfaces)
	}
	requirements, err := h.GetPermissionRequirements(hostTestContext(), GetPermissionRequirementsRequest{PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(requirements.Methods, []PermissionRequirementMethod{{Method: "worker.echo", RequiredPermissions: []string{"fs.environment.read"}}, {Method: "worker.write", RequiredPermissions: []string{"fs.environment.write"}}}) {
		t.Fatalf("method projection = %#v", requirements.Methods)
	}
	openSurfaceAndMintGateway(t, h, record.PluginInstanceID, "worker.view")
	revisions := mustAuthorizationRevisions(t, h, record.PluginInstanceID)
	if _, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{PluginInstanceID: record.PluginInstanceID, SurfaceID: "worker.protected", ExpectedManagementRevision: revisions.ManagementRevision}); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("protected surface without grant: %v", err)
	}
}

func buildScopedWorkerFixturePackage(t *testing.T) []byte {
	return buildScopedWorkerFixtureWith(t, func(map[string]any) {})
}

func buildScopedWorkerFixtureWith(t *testing.T, transform func(map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(workerFixtureManifestJSON()), &doc); err != nil {
		t.Fatal(err)
	}
	doc["api"].(map[string]any)["required_features"] = []string{"authorization.scoped.v1"}
	doc["permissions"] = []string{"fs.environment.read", "fs.environment.write", "network.client"}
	method := doc["methods"].([]any)[0].(map[string]any)
	method["permissions"] = []string{"fs.environment.read"}
	other := map[string]any{}
	for key, value := range method {
		other[key] = value
	}
	other["method"] = "worker.write"
	other["permissions"] = []string{"fs.environment.write"}
	doc["methods"] = []any{method, other}
	surface := doc["surfaces"].([]any)[0].(map[string]any)
	surface["required_methods"] = []string{}
	protected := map[string]any{}
	for key, value := range surface {
		protected[key] = value
	}
	protected["surface_id"] = "worker.protected"
	protected["required_methods"] = []string{"worker.write"}
	doc["surfaces"] = []any{surface, protected}
	transform(doc)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Scoped worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var output bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &output, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestScopedSurfaceDoesNotStartUnrelatedBackground(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, backgroundRunnerFactory: NewBackgroundWorkerRunner})
	record := installAndEnablePlugin(t, h, buildScopedWorkerFixtureWith(t, func(doc map[string]any) {
		doc["api"].(map[string]any)["required_features"] = []string{"authorization.scoped.v1", "background.method.v1"}
		doc["workers"].([]any)[0].(map[string]any)["scope"] = "environment"
		doc["background"] = map[string]any{"strategy": "on_demand", "worker_id": "echo_worker", "method": "worker.write", "params": map[string]any{"message": "refresh"}}
	}))
	openSurfaceAndMintGateway(t, h, record.PluginInstanceID, "worker.view")
	revisions := mustAuthorizationRevisions(t, h, record.PluginInstanceID)
	if _, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{PluginInstanceID: record.PluginInstanceID, SurfaceID: "worker.protected", ExpectedManagementRevision: revisions.ManagementRevision}); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("dependent surface without background grant: %v", err)
	}
}

func TestScopedSurfaceBackgroundSelection(t *testing.T) {
	m := manifest.Manifest{Background: &manifest.BackgroundSpec{Strategy: manifest.BackgroundOnDemand, WorkerID: "worker", Method: "refresh"}, Methods: []manifest.MethodSpec{{Method: "refresh", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "worker"}}}}
	for _, tc := range []struct {
		name    string
		methods manifest.MethodNames
		want    bool
	}{
		{"existing aggregate surface", nil, true},
		{"independent surface", manifest.MethodNames{}, false},
		{"unrelated method", manifest.MethodNames{"local"}, false},
		{"dependent surface", manifest.MethodNames{"refresh"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := surfaceStartsBackground(m, manifest.SurfaceSpec{RequiredMethods: tc.methods}); got != tc.want {
				t.Fatalf("starts background = %v, want %v", got, tc.want)
			}
		})
	}
}
