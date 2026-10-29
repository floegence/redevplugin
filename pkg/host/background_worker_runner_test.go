package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/background"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func TestBackgroundWorkerRunnerSelectsDeclaredWorkerMethod(t *testing.T) {
	pluginManifest := manifest.Manifest{
		Methods: []manifest.MethodSpec{
			{Method: "worker.echo", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "echo"}},
			{Method: "worker.other", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "other"}},
		},
	}

	method, ok := backgroundWorkerMethod(pluginManifest, "echo")
	if !ok || method.Method != "worker.echo" {
		t.Fatalf("selected method = %#v, ok = %v", method, ok)
	}
	if _, ok := backgroundWorkerMethod(pluginManifest, "missing"); ok {
		t.Fatal("selected an undeclared background worker method")
	}
}

func TestBackgroundWorkerRunnerCancelsWorkerInvocation(t *testing.T) {
	runtime := &backgroundBlockingRuntimeManager{
		recordingRuntimeManager: newRecordingRuntimeManager(),
		entered:                 make(chan struct{}),
		canceled:                make(chan struct{}),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: runtime,
		backgroundRunnerFactory: NewBackgroundWorkerRunner,
	})
	record := installAndEnablePlugin(t, h, buildBackgroundWorkerFixturePackage(t))
	runner, err := NewBackgroundWorkerRunner(h)
	if err != nil {
		t.Fatal(err)
	}
	owner := background.Owner{PluginInstanceID: record.PluginInstanceID, UserScope: "background", EnvironmentScope: record.OwnerEnvHash}
	session, err := runner.Start(context.Background(), owner, "echo_worker")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.entered:
	case <-time.After(time.Second):
		t.Fatal("background worker invocation did not start")
	}
	if err := runner.Stop(context.Background(), session); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case <-runtime.canceled:
	case <-time.After(time.Second):
		t.Fatal("background worker invocation did not observe cancellation")
	}
}

func TestBackgroundWorkerRunnerReportsInvocationFailure(t *testing.T) {
	diagnostics := observability.NewMemoryStore()
	runtime := newRecordingRuntimeManager()
	runtime.err = errors.New("worker fixture failed")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: runtime, diagnostics: diagnostics,
		backgroundRunnerFactory: NewBackgroundWorkerRunner,
	})
	record := installAndEnablePlugin(t, h, buildBackgroundWorkerFixturePackage(t))
	runner, err := NewBackgroundWorkerRunner(h)
	if err != nil {
		t.Fatal(err)
	}
	owner := background.Owner{PluginInstanceID: record.PluginInstanceID, UserScope: "background", EnvironmentScope: record.OwnerEnvHash}
	if _, err := runner.Start(context.Background(), owner, "echo_worker"); err != nil {
		t.Fatal(err)
	}
	waitForBackgroundDiagnostic(t, diagnostics, record.PluginInstanceID, record.OwnerEnvHash)
}

type backgroundBlockingRuntimeManager struct {
	*recordingRuntimeManager
	entered  chan struct{}
	canceled chan struct{}
	once     sync.Once
}

func (runtime *backgroundBlockingRuntimeManager) InvokeWorker(ctx context.Context, binding runtimeclient.RuntimeBinding, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
	runtime.invokeContext = ctx
	runtime.once.Do(func() { close(runtime.entered) })
	<-ctx.Done()
	close(runtime.canceled)
	return nil, ctx.Err()
}

func waitForBackgroundDiagnostic(t *testing.T, diagnostics *observability.MemoryStore, pluginInstanceID, environmentScope string) {
	t.Helper()
	owner := background.Owner{PluginInstanceID: pluginInstanceID, UserScope: "background", EnvironmentScope: environmentScope}
	session := backgroundSessionContext(owner)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events, err := diagnostics.ListPluginDiagnostics(context.Background(), observability.ListDiagnosticRequest{
			PluginInstanceID:     pluginInstanceID,
			OwnerSessionHash:     session.OwnerSessionHash,
			OwnerUserHash:        session.OwnerUserHash,
			OwnerEnvHash:         session.OwnerEnvHash,
			SessionChannelIDHash: session.SessionChannelIDHash,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.Type == "plugin.background.failed" {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("background failure diagnostic was not recorded")
}

var _ runtimeclient.Manager = (*backgroundBlockingRuntimeManager)(nil)

func buildBackgroundWorkerFixturePackage(t *testing.T) []byte {
	return buildBackgroundWorkerFixtureWith(t, func(value string) string { return value })
}

func buildBackgroundWorkerFixtureWith(t *testing.T, transform func(string) string) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerFixtureManifestJSON(), `"permissions": [],`, `"permissions": [],
		"background": {"strategy": "on_demand", "worker_id": "echo_worker"},`, 1)
	manifestJSON = strings.Replace(manifestJSON, `"scope": "user"`, `"scope": "environment"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), transform(manifestJSON))
	writeSurfaceFixture(t, dir, "Background Worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var buffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestBackgroundWorkerRunnerDoesNotBypassConfirmation(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, backgroundRunnerFactory: NewBackgroundWorkerRunner})
	record := installAndEnablePlugin(t, h, buildBackgroundWorkerFixtureWith(t, func(value string) string {
		return strings.Replace(value, `"execution": "sync",`, `"execution": "sync", "dangerous": true, "confirmation": {"mode": "required", "request_hash_fields": ["message"]},`, 1)
	}))
	runner, err := NewBackgroundWorkerRunner(h)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.Start(context.Background(), background.Owner{PluginInstanceID: record.PluginInstanceID, UserScope: "background", EnvironmentScope: record.OwnerEnvHash}, "echo_worker")
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("background confirmation error=%v", err)
	}
}

func TestBackgroundWorkerRunnerValidatesRequest(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, backgroundRunnerFactory: NewBackgroundWorkerRunner})
	record := installAndEnablePlugin(t, h, buildBackgroundWorkerFixtureWith(t, func(value string) string {
		return strings.Replace(value, `"request_schema": {`, `"request_schema": {"required": ["message"],`, 1)
	}))
	runner, err := NewBackgroundWorkerRunner(h)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.Start(context.Background(), background.Owner{PluginInstanceID: record.PluginInstanceID, UserScope: "background", EnvironmentScope: record.OwnerEnvHash}, "echo_worker")
	if !errors.Is(err, ErrMethodRequestContract) {
		t.Fatalf("background request error=%v", err)
	}
}

func TestBackgroundWorkerRunnerUsesExplicitMethodAndNormalExecution(t *testing.T) {
	runtime := &permissionInspectingRuntimeManager{recordingRuntimeManager: newRecordingRuntimeManager(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner})
	record := installAndEnablePlugin(t, h, buildBackgroundWorkerFixtureWith(t, func(value string) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(value), &doc); err != nil {
			t.Fatal(err)
		}
		doc["api"].(map[string]any)["required_features"] = []string{"background.method.v1"}
		entry := doc["background"].(map[string]any)
		entry["method"] = "worker.selected"
		entry["params"] = map[string]any{"message": "background"}
		first := doc["methods"].([]any)[0].(map[string]any)
		selected := map[string]any{}
		for key, val := range first {
			selected[key] = val
		}
		selected["method"] = "worker.selected"
		doc["methods"] = []any{first, selected}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}))
	runner, err := NewBackgroundWorkerRunner(h)
	if err != nil {
		t.Fatal(err)
	}
	session, err := runner.Start(context.Background(), backgroundOwner(record), "echo_worker")
	if err != nil {
		t.Fatal(err)
	}
	done := runner.(background.CompletionWatcher).Done(session)
	select {
	case <-runtime.entered:
	case <-time.After(time.Second):
		t.Fatal("background did not dispatch")
	}
	close(runtime.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background did not finish")
	}
	var payload workerInvocationPayload
	if err := json.Unmarshal(runtime.lastPayload, &payload); err != nil {
		t.Fatal(err)
	}
	if runtime.lastMethod != "worker.selected" || payload.Execution != "sync" || payload.Params["message"] != "background" {
		t.Fatalf("dispatch method=%s payload=%#v", runtime.lastMethod, payload)
	}
}

func TestBackgroundWorkerRunnerHonorsHostPolicy(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, backgroundRunnerFactory: NewBackgroundWorkerRunner})
	record := installAndEnablePlugin(t, h, buildBackgroundWorkerFixturePackage(t))
	h.adapters.Policy = policyAdapter{developerMode: true, localGenerated: true, decision: PolicyDeny}
	runner, err := NewBackgroundWorkerRunner(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Start(context.Background(), backgroundOwner(record), "echo_worker"); !errors.Is(err, security.ErrPolicyDenied) {
		t.Fatalf("background policy=%v", err)
	}
}
