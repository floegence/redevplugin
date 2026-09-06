package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/capability"
)

type invocationPreparationManager struct {
	*recordingRuntimeManager
	prewarmErr error
	started    chan struct{}
	release    chan struct{}
}

func (manager *invocationPreparationManager) PrewarmWorker(ctx context.Context, req runtimeclient.PrewarmWorkerRequest) error {
	if manager.started != nil {
		close(manager.started)
		select {
		case <-manager.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if manager.prewarmErr != nil {
		return manager.prewarmErr
	}
	return manager.recordingRuntimeManager.PrewarmWorker(ctx, req)
}

func TestWorkerCallReusesPreparationUntilRuntimeGenerationChanges(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: manager,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	manager.prewarmCalls = 0
	manager.result = capability.Result{Data: map[string]any{}}
	request := CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "worker.echo", Params: map[string]any{"message": "load"},
	}
	for range 3 {
		if _, err := h.CallPluginMethod(hostTestContext(), request); err != nil {
			t.Fatal(err)
		}
	}
	if manager.prewarmCalls != 0 || manager.calls != 3 || manager.startCalls != 0 {
		t.Fatalf("warm calls: prewarm=%d invoke=%d start=%d", manager.prewarmCalls, manager.calls, manager.startCalls)
	}
	manager.health.RuntimeGenerationID = "runtime_generation_restarted"
	if _, err := h.CallPluginMethod(hostTestContext(), request); err != nil {
		t.Fatal(err)
	}
	if manager.prewarmCalls != 1 || manager.calls != 4 {
		t.Fatalf("restart: prewarm=%d invoke=%d", manager.prewarmCalls, manager.calls)
	}
	manager.err = runtimeclient.ErrRuntimeNotReady
	if _, err := h.CallPluginMethod(hostTestContext(), request); err == nil {
		t.Fatal("dispatched failure unexpectedly succeeded")
	}
	if manager.calls != 5 || manager.prewarmCalls != 1 {
		t.Fatalf("dispatched failure was retried: invoke=%d prewarm=%d", manager.calls, manager.prewarmCalls)
	}
}

func TestWorkerCallWaitsForPreparationAndCancelsQueuedWaiter(t *testing.T) {
	manager := &invocationPreparationManager{recordingRuntimeManager: newRecordingRuntimeManager()}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: manager,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	manager.started = make(chan struct{})
	manager.release = make(chan struct{})
	manager.health.RuntimeGenerationID = "runtime_generation_cold"
	manager.result = capability.Result{Data: map[string]any{}}
	request := CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "worker.echo", Params: map[string]any{"message": "first load"},
	}
	ctx, cancel := context.WithTimeout(hostTestContext(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.CallPluginMethod(ctx, request)
		done <- err
	}()
	select {
	case <-manager.started:
	case <-ctx.Done():
		t.Fatal("preparation did not start")
	}
	if manager.calls != 0 {
		t.Fatal("worker dispatched before preparation completed")
	}
	waitCtx, cancelWait := context.WithTimeout(hostTestContext(), 30*time.Millisecond)
	defer cancelWait()
	if _, err := h.CallPluginMethod(waitCtx, request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued call = %v, want deadline exceeded", err)
	}
	close(manager.release)
	if err := <-done; err != nil {
		t.Fatalf("first call after preparation: %v", err)
	}
	if manager.calls != 1 {
		t.Fatalf("dispatched %d calls, want only the uncanceled call", manager.calls)
	}
}

func TestWorkerCallPreparesColdRuntimeBeforeDispatch(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: manager,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	manager.health.Ready = false
	manager.health.RuntimeGenerationID = "runtime_generation_cold"
	manager.startHealthReady = true
	manager.prewarmCalls = 0
	manager.result = capability.Result{Data: map[string]any{}}

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "worker.echo", Params: map[string]any{"message": "first load"},
	})
	if err != nil {
		t.Fatalf("first worker call with a cold runtime: %v", err)
	}
	if manager.startCalls != 1 || manager.prewarmCalls != 1 || manager.calls != 1 {
		t.Fatalf("start=%d prewarm=%d invoke=%d; want one of each", manager.startCalls, manager.prewarmCalls, manager.calls)
	}
}

func TestWorkerCallPreparationFailureDoesNotDispatch(t *testing.T) {
	for _, failure := range []error{context.Canceled, runtimeclient.ErrRuntimeNotReady} {
		t.Run(failure.Error(), func(t *testing.T) {
			manager := &invocationPreparationManager{recordingRuntimeManager: newRecordingRuntimeManager()}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode: true, localGenerated: true, runtimeManager: manager,
			})
			installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
			manager.prewarmErr = failure
			manager.health.RuntimeGenerationID = "runtime_generation_cold"
			manager.result = capability.Result{Data: map[string]any{}}
			request := CallMethodRequest{
				PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
				BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
				Method: "worker.echo", Params: map[string]any{"message": "first load"},
			}
			if _, err := h.CallPluginMethod(hostTestContext(), request); !errors.Is(err, failure) {
				t.Fatalf("preparation failure = %v, want %v", err, failure)
			}
			if manager.calls != 0 {
				t.Fatalf("preparation failure dispatched %d calls", manager.calls)
			}
			manager.prewarmErr = nil
			manager.result = capability.Result{Data: map[string]any{}}
			if _, err := h.CallPluginMethod(hostTestContext(), request); err != nil {
				t.Fatalf("explicit retry after preparation recovers: %v", err)
			}
			if manager.calls != 1 {
				t.Fatalf("explicit retry dispatched %d calls, want 1", manager.calls)
			}
		})
	}
}
