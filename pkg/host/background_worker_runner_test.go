package host

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/background"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
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
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerFixtureManifestJSON(), `"permissions": [],`, `"permissions": [],
		"background": {"strategy": "on_demand", "worker_id": "echo_worker"},`, 1)
	manifestJSON = strings.Replace(manifestJSON, `"scope": "user"`, `"scope": "environment"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Background Worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var buffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
