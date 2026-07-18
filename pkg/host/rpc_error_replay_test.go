package host

import (
	"errors"
	"fmt"
	"testing"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
)

type rpcErrorReplaySink struct {
	name     string
	setError func(error)
	call     func() error
}

func TestCallPluginMethodRejectsProjectedErrorReplayAcrossAdapterBoundaries(t *testing.T) {
	sources := []struct {
		name   string
		obtain func(*testing.T) error
	}{
		{name: "capability", obtain: obtainAttestedCapabilityRPCError},
		{name: "worker", obtain: obtainAttestedWorkerRPCError},
	}
	replays := []struct {
		name                string
		wrap                func(error) error
		wantUnknownMutation bool
	}{
		{name: "direct", wrap: func(err error) error { return err }},
		{name: "wrapped", wrap: func(err error) error { return fmt.Errorf("replayed projected error: %w", err) }},
		{
			name: "mutation wrapped",
			wrap: func(err error) error {
				return &mutation.Error{Outcome: mutation.OutcomeUnknown, Err: err}
			},
			wantUnknownMutation: true,
		},
	}

	for _, source := range sources {
		t.Run(source.name, func(t *testing.T) {
			attested := source.obtain(t)
			for _, sink := range newRPCErrorReplaySinks(t) {
				t.Run(sink.name, func(t *testing.T) {
					for _, replay := range replays {
						t.Run(replay.name, func(t *testing.T) {
							sink.setError(replay.wrap(attested))
							assertRPCErrorReplayRejected(t, sink.call(), replay.wantUnknownMutation)
						})
					}
				})
			}
		})
	}
}

func obtainAttestedCapabilityRPCError(t *testing.T) error {
	t.Helper()
	contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
	contract.Errors = []capabilitycontract.BusinessError{{
		Code:    "DOCUMENT_NOT_FOUND",
		Message: "Document not found",
		DetailsSchema: fixtureClosedObject(map[string]any{
			"document_id": map[string]any{"type": "string", "minLength": 1},
		}, []string{"document_id"}),
	}}
	verified := verifyFixtureCapabilityContract(t, contract)
	adapter := &recordingCapabilityAdapter{err: mustCapabilityBusinessError(t,
		"DOCUMENT_NOT_FOUND", "adapter detail", map[string]any{"document_id": "doc-1"},
	)}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true,
		capabilityContract: &verified, capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t, rpcFixtureManifestJSON("1.0.0", "RPC"), "RPC", "echo", verified.Pin,
	), "rpc.view")

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "echo.ping", Params: map[string]any{"message": "hello"},
	})
	validated, ok := AsValidatedCapabilityBusinessError(err)
	if !ok || validated.Code != "DOCUMENT_NOT_FOUND" {
		t.Fatalf("source capability error was not attested: value=%#v ok=%v err=%v", validated, ok, err)
	}
	var raw *capability.BusinessError
	if !errors.As(err, &raw) || raw.Code != "DOCUMENT_NOT_FOUND" {
		t.Fatalf("source capability error is not publicly projected: %#v, err=%v", raw, err)
	}
	return err
}

func obtainAttestedWorkerRPCError(t *testing.T) error {
	t.Helper()
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{
		RuntimeInstanceID: "runtime_source", RuntimeGenerationID: "runtime_gen_source",
		IPCChannelID: "ipc_source", ConnectionNonce: "connection_nonce_source_1234567890", Ready: true,
	})
	runtime.err = &runtimeclient.WorkerExecutionError{
		Code: "WORKER_FAILED", Message: "Worker failed", Origin: runtimeclient.WorkerErrorOriginPlugin,
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: runtime,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "worker.echo", Params: map[string]any{"message": "hello"},
	})
	validated, ok := AsValidatedWorkerExecutionError(err)
	if !ok || validated.Code != "WORKER_FAILED" {
		t.Fatalf("source worker error was not attested: value=%#v ok=%v err=%v", validated, ok, err)
	}
	var raw *runtimeclient.WorkerExecutionError
	if !errors.As(err, &raw) || raw.Code != "WORKER_FAILED" {
		t.Fatalf("source worker error is not publicly projected: %#v, err=%v", raw, err)
	}
	return err
}

func newRPCErrorReplaySinks(t *testing.T) []rpcErrorReplaySink {
	t.Helper()

	coreAdapter := &recordingCoreActionAdapter{}
	coreHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, coreActions: coreAdapter,
	})
	coreInstalled, coreGateway := installEnableAndMintGateway(t, coreHost, buildCoreActionFixturePackage(t), "core.view")

	capabilityAdapter := &recordingCapabilityAdapter{}
	capabilityHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true,
		capabilityID: "example.capability.tasks", capabilityAdapter: capabilityAdapter,
	})
	capabilityInstalled, capabilityGateway := installEnableAndMintGateway(
		t, capabilityHost, buildMethodContractFixturePackage(t), "method_contract.view",
	)

	targetAdapter := &recordingCapabilityAdapter{}
	targetHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true,
		capabilityID: "example.capability.echo", capabilityAdapter: targetAdapter,
	})
	targetInstalled, targetGateway := installEnableAndMintGateway(t, targetHost, buildRPCFixturePackage(t), "rpc.view")

	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{
		RuntimeInstanceID: "runtime_sink", RuntimeGenerationID: "runtime_gen_sink",
		IPCChannelID: "ipc_sink", ConnectionNonce: "connection_nonce_sink_1234567890", Ready: true,
	})
	runtimeHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: runtime,
	})
	runtimeInstalled, runtimeGateway := installEnableAndMintGateway(t, runtimeHost, buildWorkerFixturePackage(t), "worker.view")

	return []rpcErrorReplaySink{
		{
			name:     "core action adapter",
			setError: func(err error) { coreAdapter.err = err },
			call: func() error {
				_, err := coreHost.CallPluginMethod(hostTestContext(), CallMethodRequest{
					PluginInstanceID: coreInstalled.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
					BridgeChannelID: "bridge_rpc", GatewayToken: coreGateway.GatewayToken,
					Method: "core.open", Params: map[string]any{"target": "settings"},
				})
				return err
			},
		},
		{
			name:     "different capability adapter",
			setError: func(err error) { capabilityAdapter.err = err },
			call: func() error {
				_, err := capabilityHost.CallPluginMethod(hostTestContext(), CallMethodRequest{
					PluginInstanceID: capabilityInstalled.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
					BridgeChannelID: "bridge_rpc", GatewayToken: capabilityGateway.GatewayToken,
					Method: "tasks.list",
				})
				return err
			},
		},
		{
			name:     "target projector",
			setError: func(err error) { targetAdapter.targetError = err },
			call: func() error {
				_, err := targetHost.CallPluginMethod(hostTestContext(), CallMethodRequest{
					PluginInstanceID: targetInstalled.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
					BridgeChannelID: "bridge_rpc", GatewayToken: targetGateway.GatewayToken,
					Method: "echo.ping", Params: map[string]any{"message": "hello"},
				})
				return err
			},
		},
		{
			name:     "runtime manager",
			setError: func(err error) { runtime.err = err },
			call: func() error {
				_, err := runtimeHost.CallPluginMethod(hostTestContext(), CallMethodRequest{
					PluginInstanceID: runtimeInstalled.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
					BridgeChannelID: "bridge_rpc", GatewayToken: runtimeGateway.GatewayToken,
					Method: "worker.echo", Params: map[string]any{"message": "hello"},
				})
				return err
			},
		},
	}
}

func assertRPCErrorReplayRejected(t *testing.T, err error, wantUnknownMutation bool) {
	t.Helper()
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("replayed projected error = %v, want ErrMethodResponseContract", err)
	}
	if _, ok := AsValidatedCapabilityBusinessError(err); ok {
		t.Fatal("replayed projected error retained a capability attestation")
	}
	if _, ok := AsValidatedWorkerExecutionError(err); ok {
		t.Fatal("replayed projected error retained a worker attestation")
	}
	var businessError *capability.BusinessError
	if errors.As(err, &businessError) {
		t.Fatalf("replayed projected error exposed a raw capability error: %#v", businessError)
	}
	var workerError *runtimeclient.WorkerExecutionError
	if errors.As(err, &workerError) {
		t.Fatalf("replayed projected error exposed a raw worker error: %#v", workerError)
	}
	if wantUnknownMutation && mutation.ForError(err) != mutation.OutcomeUnknown {
		t.Fatalf("mutation outcome = %q, want %q", mutation.ForError(err), mutation.OutcomeUnknown)
	}
}
