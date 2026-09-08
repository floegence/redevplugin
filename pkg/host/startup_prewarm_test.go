package host

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
)

func TestHostWithoutSessionPrewarmsBeforeAnyUIRequest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	first, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: root, developerMode: true, localGenerated: true})
	installed := installAndEnablePlugin(t, first, buildWorkerFixturePackage(t))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	manager := newRecordingRuntimeManager()
	manager.prewarmStarted = make(chan runtimeclient.PrewarmWorkerRequest, 1)
	surfaces := &startupSurfaceSink{published: make(chan SurfaceSnapshot, 1)}
	second, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: root, openContext: context.Background(), runtimeManager: manager, surfaceCatalog: surfaces})
	select {
	case request := <-manager.prewarmStarted:
		if request.PluginInstanceID != installed.PluginInstanceID || request.WorkerID != "echo_worker" {
			t.Fatalf("prewarm request: %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("sessionless Host startup waited for a UI request before compilation")
	}
	second.lifecycleWG.Wait()
	if manager.calls != 0 || manager.startCalls != 1 {
		t.Fatalf("invocations=%d starts=%d", manager.calls, manager.startCalls)
	}
	if second.recoverySnapshot != nil {
		t.Fatal("compilation created an authorized recovery snapshot")
	}
	second.workerPreparations.Range(func(_, _ any) bool { t.Error("compilation created an execution preparation binding"); return true })
	if len(surfaces.published) != 0 {
		t.Fatal("sessionless compilation published surfaces")
	}
	if _, err := second.ListPlugins(context.Background()); err == nil {
		t.Fatal("compilation authorized an unauthenticated inventory read")
	}
	if _, err := second.RecoverEnabled(context.Background()); err == nil {
		t.Fatal("compilation authorized unauthenticated recovery")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHostWithoutSessionDoesNotStartRuntimeForEmptyOrDisabledCatalog(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "disabled"}[installed], func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			first, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: root, developerMode: true, localGenerated: true})
			if installed {
				record := installAndEnablePlugin(t, first, buildWorkerFixturePackage(t))
				if _, err := first.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision}); err != nil {
					t.Fatal(err)
				}
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			manager := newRecordingRuntimeManager()
			second, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: root, openContext: context.Background(), runtimeManager: manager})
			second.lifecycleWG.Wait()
			if manager.startCalls != 0 || manager.prewarmCalls != 0 {
				t.Fatal("empty or disabled inventory started runtime work")
			}
			if err := second.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type startupCompilationBlocker struct {
	*recordingRuntimeManager
	started  chan struct{}
	canceled chan struct{}
}

func (manager *startupCompilationBlocker) PrewarmWorker(ctx context.Context, _ runtimeclient.PrewarmWorkerRequest) error {
	close(manager.started)
	<-ctx.Done()
	close(manager.canceled)
	return ctx.Err()
}

func TestHostCloseCancelsSessionlessStartupCompilation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	first, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: root, developerMode: true, localGenerated: true})
	installAndEnablePlugin(t, first, buildWorkerFixturePackage(t))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	manager := &startupCompilationBlocker{recordingRuntimeManager: newRecordingRuntimeManager(), started: make(chan struct{}), canceled: make(chan struct{})}
	second, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: root, openContext: context.Background(), runtimeManager: manager})
	select {
	case <-manager.started:
	case <-time.After(time.Second):
		t.Fatal("startup compilation did not begin")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.canceled:
	default:
		t.Fatal("Host.Close did not await compilation cancellation")
	}
	if manager.calls != 0 {
		t.Fatal("startup invoked a worker")
	}
}

type startupStartGate struct {
	*recordingRuntimeManager
	started chan struct{}
	release chan struct{}
}

func (manager *startupStartGate) Start(ctx context.Context, target runtimetarget.Target) (runtimeclient.ManagerHealth, error) {
	close(manager.started)
	select {
	case <-manager.release:
	case <-ctx.Done():
		return runtimeclient.ManagerHealth{}, ctx.Err()
	}
	return manager.recordingRuntimeManager.Start(ctx, target)
}

func TestStartupCompilationRechecksDisableAfterCatalogRead(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	first, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: root, developerMode: true, localGenerated: true})
	installed := installAndEnablePlugin(t, first, buildWorkerFixturePackage(t))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	manager := &startupStartGate{recordingRuntimeManager: newRecordingRuntimeManager(), started: make(chan struct{}), release: make(chan struct{})}
	second, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: root, openContext: context.Background(), runtimeManager: manager, developerMode: true, localGenerated: true})
	select {
	case <-manager.started:
	case <-time.After(time.Second):
		t.Fatal("startup did not read its catalog")
	}
	if _, err := second.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	close(manager.release)
	second.lifecycleWG.Wait()
	if manager.prewarmCalls != 0 || manager.calls != 0 {
		t.Fatal("disabled snapshot reached worker compilation or execution")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
