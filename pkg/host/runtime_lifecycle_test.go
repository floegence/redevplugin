package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/runtimeclient"
	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestRuntimeLifecycleUsesInjectedSupervisor(t *testing.T) {
	supervisor := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: supervisor,
	})

	target := hostTestRuntimeDescriptor().Target()
	health, err := h.StartRuntime(hostTestContext(), StartRuntimeRequest{Target: target})
	if err != nil {
		t.Fatalf("StartRuntime() error = %v", err)
	}
	if len(health.Shards) != 1 || health.Shards[0].RuntimeInstanceID != "runtime_1" || supervisor.startedTarget != target {
		t.Fatalf("runtime start mismatch: health=%#v supervisor=%#v", health, supervisor)
	}
	if !audits.hasEvent("plugin.runtime.started") {
		t.Fatalf("missing runtime started audit: %#v", audits.events)
	}

	if err := h.StopRuntime(hostTestContext()); err != nil {
		t.Fatalf("StopRuntime() error = %v", err)
	}
	if supervisor.stopCalls != 1 || !audits.hasEvent("plugin.runtime.stopped") {
		t.Fatalf("runtime stop mismatch: stopCalls=%d audits=%#v", supervisor.stopCalls, audits.events)
	}
}

func TestStartRuntimeStopsManagerWhenStartedHealthIsInvalid(t *testing.T) {
	manager := newRecordingRuntimeManager()
	manager.health.Ready = false
	h, _, _ := newTestHostWithOptions(t, testHostOptions{runtimeManager: manager})

	if _, err := h.StartRuntime(hostTestContext(), StartRuntimeRequest{Target: hostTestRuntimeDescriptor().Target()}); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("StartRuntime() error = %v, want %v", err, ErrPluginRuntimeIncompatible)
	}
	if manager.startCalls != 1 || manager.stopCalls != 1 {
		t.Fatalf("invalid started runtime lifecycle calls = start %d stop %d, want 1 each", manager.startCalls, manager.stopCalls)
	}
}

func TestHostCloseStopsRuntimeWithBoundedDeadlineAndWaitsForCompletion(t *testing.T) {
	manager := &blockingCloseRuntimeManager{
		recordingRuntimeManager: *newRecordingRuntimeManager(),
		stopStarted:             make(chan struct{}),
		stopRelease:             make(chan struct{}),
		deadline:                make(chan time.Time, 1),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{runtimeManager: manager})
	pluginData := &recordingClosePluginData{PluginData: h.adapters.PluginData}
	h.adapters.PluginData = pluginData
	target := hostTestRuntimeDescriptor().Target()
	if _, err := h.StartRuntime(hostTestContext(), StartRuntimeRequest{Target: target}); err != nil {
		t.Fatalf("StartRuntime() error = %v", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case <-manager.stopStarted:
	case <-time.After(time.Second):
		t.Fatal("Host.Close() did not stop the bound runtime manager")
	}
	select {
	case err := <-closed:
		t.Fatalf("Host.Close() returned before runtime shutdown completed: %v", err)
	default:
	}
	select {
	case deadline := <-manager.deadline:
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > hostRuntimeShutdownTimeout {
			t.Fatalf("runtime shutdown deadline remaining = %v, want (0, %v]", remaining, hostRuntimeShutdownTimeout)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime Stop context did not carry a deadline")
	}
	close(manager.stopRelease)
	if err := <-closed; err != nil {
		t.Fatalf("Host.Close() error = %v", err)
	}
	if got := manager.stopCallCount(); got != 1 {
		t.Fatalf("runtime Stop() calls = %d, want 1", got)
	}
	if pluginData.closeCalls != 1 {
		t.Fatalf("PluginData.Close() calls = %d, want 1", pluginData.closeCalls)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Host.Close() error = %v", err)
	}
	if got := manager.stopCallCount(); got != 1 || pluginData.closeCalls != 1 {
		t.Fatalf("repeated Host.Close() repeated cleanup: runtime=%d plugin_data=%d", got, pluginData.closeCalls)
	}
}

func TestHostCloseJoinsRuntimeAndPluginDataFailures(t *testing.T) {
	runtimeFailure := errors.New("runtime shutdown failed")
	pluginDataFailure := errors.New("plugin data close failed")
	manager := &blockingCloseRuntimeManager{recordingRuntimeManager: *newRecordingRuntimeManager(), stopErr: runtimeFailure}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{runtimeManager: manager, expectCloseErr: true})
	pluginData := &recordingClosePluginData{PluginData: h.adapters.PluginData, err: pluginDataFailure}
	h.adapters.PluginData = pluginData

	closeErr := h.Close()
	if !errors.Is(closeErr, runtimeFailure) || !errors.Is(closeErr, pluginDataFailure) {
		t.Fatalf("Host.Close() error = %v, want joined runtime and plugin data failures", closeErr)
	}
	secondErr := h.Close()
	if !errors.Is(secondErr, runtimeFailure) || !errors.Is(secondErr, pluginDataFailure) {
		t.Fatalf("second Host.Close() error = %v, want same joined failures", secondErr)
	}
	if got := manager.stopCallCount(); got != 1 || pluginData.closeCalls != 1 {
		t.Fatalf("repeated Host.Close() repeated cleanup: runtime=%d plugin_data=%d", got, pluginData.closeCalls)
	}
}

func TestHostRuntimeLifecycleRejectsCallsAfterClose(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Host) error
	}{
		{
			name: "start",
			run: func(h *Host) error {
				_, err := h.StartRuntime(hostTestContext(), StartRuntimeRequest{})
				return err
			},
		},
		{
			name: "stop",
			run: func(h *Host) error {
				return h.StopRuntime(hostTestContext())
			},
		},
		{
			name: "health",
			run: func(h *Host) error {
				_, err := h.RuntimeHealth(hostTestContext())
				return err
			},
		},
		{
			name: "refresh enabled plugins",
			run: func(h *Host) error {
				_, err := h.RefreshEnabledPlugins(hostTestContext())
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := newRecordingRuntimeManager()
			h, _, _ := newTestHostWithOptions(t, testHostOptions{runtimeManager: manager})
			if err := h.Close(); err != nil {
				t.Fatalf("Host.Close() error = %v", err)
			}
			if err := tc.run(h); !errors.Is(err, ErrHostClosed) {
				t.Fatalf("runtime lifecycle call after Host.Close() error = %v, want %v", err, ErrHostClosed)
			}
			if manager.startCalls != 0 {
				t.Fatalf("RuntimeManager.Start() calls after Host.Close() = %d, want 0", manager.startCalls)
			}
			if manager.stopCalls != 1 {
				t.Fatalf("RuntimeManager.Stop() calls including Host.Close() = %d, want 1", manager.stopCalls)
			}
		})
	}
}

func TestStopRuntimeRevokesSurfacesWhenManagerStopFails(t *testing.T) {
	stopFailure := errors.New("runtime stop failed at /Users/secret/runtime with vault-token-super-secret")
	manager := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	manager.stopErr = stopFailure
	manager.stopErrOnce = true
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: manager,
		capabilityID: "example.capability.echo", capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"echo": "hello"}}},
		diagnostics: diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	err := h.StopRuntime(hostTestContext())
	if !errors.Is(err, stopFailure) || mutation.ForError(err) != mutation.OutcomeUnknown {
		t.Fatalf("StopRuntime() error = %v", err)
	}
	stopAudit, ok := audits.lastEvent("plugin.runtime.stopped")
	if !ok {
		t.Fatalf("missing runtime stopped audit: %#v", audits.events)
	}
	assertAuditDetail(t, stopAudit, "revoked_surface_count", 1)
	assertAuditDetail(t, stopAudit, "mutation_outcome", string(mutation.OutcomeUnknown))
	auditFailure, ok := stopAudit.Details["failure"].(map[string]any)
	if !ok || auditFailure["code"] != string(observability.FailureAction) || auditFailure["component"] != string(observability.FailureComponentSecurity) || auditFailure["operation"] != "security_mutation.complete" || strings.Contains(fmt.Sprint(stopAudit.Details), stopFailure.Error()) {
		t.Fatalf("runtime stop audit failure was not redacted: %#v", stopAudit.Details)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Type != "plugin.runtime.stop_failed" || diagnostics.events[0].Message != "plugin runtime stop failed" {
		t.Fatalf("runtime stop diagnostic mismatch: %#v", diagnostics.events)
	}
	failure := diagnostics.events[0].Failure
	if failure.Code != observability.FailureAdapter || failure.Component != observability.FailureComponentRuntime || failure.Operation != "runtime.stop" {
		t.Fatalf("runtime stop diagnostic failure = %#v", failure)
	}
	if strings.Contains(fmt.Sprint(diagnostics.events[0]), stopFailure.Error()) {
		t.Fatalf("runtime stop diagnostic retained raw cause: %#v", diagnostics.events[0])
	}
	if diagnostics.events[0].OwnerSessionHash != "session_hash" || diagnostics.events[0].OwnerUserHash != "user_hash" || diagnostics.events[0].OwnerEnvHash != "env_hash" || diagnostics.events[0].SessionChannelIDHash != "channel_hash" {
		t.Fatalf("runtime stop diagnostic owner scope mismatch: %#v", diagnostics.events[0])
	}
	_, callErr := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",
		BridgeChannelID:   "bridge_rpc",
		GatewayToken:      gateway.GatewayToken,
		Method:            "worker.echo",
		Params:            map[string]any{"message": "hello"},
	})
	if !errors.Is(callErr, bridge.ErrTokenRevoked) {
		t.Fatalf("CallPluginMethod() after failed stop error = %v, want %v", callErr, bridge.ErrTokenRevoked)
	}
}

type blockingCloseRuntimeManager struct {
	recordingRuntimeManager
	mu          sync.Mutex
	stopStarted chan struct{}
	stopRelease chan struct{}
	deadline    chan time.Time
	stopOnce    sync.Once
	stopCalls   int
	stopErr     error
}

func (m *blockingCloseRuntimeManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	m.stopCalls++
	m.mu.Unlock()
	if m.deadline != nil {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("runtime shutdown context is missing a deadline")
		}
		m.deadline <- deadline
	}
	if m.stopStarted != nil {
		m.stopOnce.Do(func() { close(m.stopStarted) })
	}
	if m.stopRelease != nil {
		select {
		case <-m.stopRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.stopErr
}

func (m *blockingCloseRuntimeManager) stopCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopCalls
}

type recordingClosePluginData struct {
	PluginData
	closeCalls int
	err        error
}

func (d *recordingClosePluginData) Close() error {
	d.closeCalls++
	return errors.Join(d.PluginData.Close(), d.err)
}

func TestRuntimeArtifactProviderReadsBoundPackageAsset(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	pkg, err := pluginPackageFromBytesForRuntimeTest(buildWorkerFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.adapters.Assets.PutOwnedPackage(hostTestContext(), &pkg); err != nil {
		t.Fatal(err)
	}
	asset, err := h.adapters.Assets.ReadAsset(hostTestContext(), pkg.PackageHash, "workers/echo.wasm")
	if err != nil {
		t.Fatal(err)
	}
	provider := runtimeArtifactProvider{assets: h.adapters.Assets}
	result, err := provider.ReadArtifact(hostTestContext(), runtimeclient.ArtifactRequest{
		PackageHash:    pkg.PackageHash,
		Artifact:       "workers/echo.wasm",
		ArtifactSHA256: asset.Entry.SHA256,
	})
	if err != nil {
		t.Fatalf("ReadArtifact() error = %v", err)
	}
	sum := sha256.Sum256(result.Content)
	if result.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("artifact sha mismatch: %#v", result)
	}
	if _, err := provider.ReadArtifact(hostTestContext(), runtimeclient.ArtifactRequest{
		PackageHash:    pkg.PackageHash,
		Artifact:       "workers/echo.wasm",
		ArtifactSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}); err == nil {
		t.Fatal("ReadArtifact() expected sha mismatch error")
	}
}

type recordingHostNetworkExecutor struct {
	httpCalls      int
	streamCalls    int
	websocketCalls int
	tcpCalls       int
	udpCalls       int
	lastHTTP       connectivity.HTTPRequest
	lastStreamHTTP connectivity.HTTPRequest
	lastWebSocket  connectivity.WebSocketRoundTripRequest
	lastTCP        connectivity.TCPRoundTripRequest
	lastUDP        connectivity.UDPRoundTripRequest
	httpStatus     int
	httpBody       []byte
	streamChunks   [][]byte
	wsResponse     connectivity.WebSocketRoundTripResponse
	tcpResponse    connectivity.TCPRoundTripResponse
	udpResponse    connectivity.UDPRoundTripResponse
}

func (e *recordingHostNetworkExecutor) DoHTTP(_ context.Context, req connectivity.HTTPRequest) (connectivity.HTTPResponse, error) {
	e.httpCalls++
	e.lastHTTP = req
	status := e.httpStatus
	if status == 0 {
		status = http.StatusOK
	}
	return connectivity.HTTPResponse{StatusCode: status, Body: append([]byte(nil), e.httpBody...)}, nil
}

func (e *recordingHostNetworkExecutor) StreamHTTP(_ context.Context, req connectivity.HTTPRequest, onChunk func(connectivity.HTTPResponseChunk) error) (connectivity.HTTPStreamResponse, error) {
	e.streamCalls++
	e.lastStreamHTTP = req
	status := e.httpStatus
	if status == 0 {
		status = http.StatusOK
	}
	chunks := e.streamChunks
	if len(chunks) == 0 && len(e.httpBody) > 0 {
		chunks = [][]byte{e.httpBody}
	}
	var bytesRead int64
	for index, chunk := range chunks {
		if err := onChunk(connectivity.HTTPResponseChunk{Index: index, Data: append([]byte(nil), chunk...)}); err != nil {
			return connectivity.HTTPStreamResponse{}, err
		}
		bytesRead += int64(len(chunk))
	}
	return connectivity.HTTPStreamResponse{StatusCode: status, BytesRead: bytesRead, ChunkCount: len(chunks)}, nil
}

func (e *recordingHostNetworkExecutor) WebSocketRoundTrip(_ context.Context, req connectivity.WebSocketRoundTripRequest) (connectivity.WebSocketRoundTripResponse, error) {
	e.websocketCalls++
	e.lastWebSocket = req
	return e.wsResponse, nil
}

func (e *recordingHostNetworkExecutor) TCPRoundTrip(_ context.Context, req connectivity.TCPRoundTripRequest) (connectivity.TCPRoundTripResponse, error) {
	e.tcpCalls++
	e.lastTCP = req
	return e.tcpResponse, nil
}

func (e *recordingHostNetworkExecutor) UDPRoundTrip(_ context.Context, req connectivity.UDPRoundTripRequest) (connectivity.UDPRoundTripResponse, error) {
	e.udpCalls++
	e.lastUDP = req
	return e.udpResponse, nil
}

func TestRuntimeHandleGrantValidatorUsesSurfaceTokens(t *testing.T) {
	now := time.Now().UTC()
	service := bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{})
	revision := bridge.RevisionBinding{PolicyRevision: 1, ManagementRevision: 2, RevokeEpoch: 3}
	minted, err := service.MintHandleGrant(bridge.MintHandleGrantRequest{
		PluginInstanceID:     "plugini_1",
		ActiveFingerprint:    "sha256:active",
		RuntimeInstanceID:    "runtime_1",
		RuntimeGenerationID:  "runtime_gen_1",
		RuntimeShardID:       "runtime_shard_1",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
		HandleID:             "storage:db",
		Method:               "storage.sqlite",
		ResourceScope:        sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
		Revision:             revision,
		Limits:               bridge.Limits{MaxTotalBytes: 4096},
		Now:                  now,
	})
	if err != nil {
		t.Fatal(err)
	}
	validator := runtimeHandleGrantValidator{tokens: service}
	result, err := validator.ValidateHandleGrant(hostTestContext(), runtimeclient.HandleGrantValidationRequest{
		HandleGrantToken:     minted.HandleGrantToken,
		PluginInstanceID:     "plugini_1",
		ActiveFingerprint:    "sha256:active",
		RuntimeInstanceID:    "runtime_1",
		RuntimeGenerationID:  "runtime_gen_1",
		RuntimeShardID:       "runtime_shard_1",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
		HandleID:             "storage:db",
		Method:               "storage.sqlite",
		ResourceScope:        sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
		PolicyRevision:       1,
		ManagementRevision:   2,
		RevokeEpoch:          3,
	})
	if err != nil {
		t.Fatalf("ValidateHandleGrant() error = %v", err)
	}
	if result.HandleGrantID != minted.HandleGrantID || result.HandleID != "storage:db" || result.Method != "storage.sqlite" || result.MaxTotalBytes != 4096 {
		t.Fatalf("handle grant result mismatch: %#v", result)
	}
	if _, err := validator.ValidateHandleGrant(hostTestContext(), runtimeclient.HandleGrantValidationRequest{
		HandleGrantToken:     minted.HandleGrantToken,
		PluginInstanceID:     "plugini_1",
		ActiveFingerprint:    "sha256:active",
		RuntimeGenerationID:  "runtime_gen_1",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
		HandleID:             "storage:other",
		Method:               "storage.sqlite",
		ResourceScope:        sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
		PolicyRevision:       1,
		ManagementRevision:   2,
		RevokeEpoch:          3,
	}); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("ValidateHandleGrant(wrong handle) error = %v, want ErrTokenAudience", err)
	}
}

func pluginPackageFromBytesForRuntimeTest(raw []byte) (pluginpkg.Package, error) {
	return pluginpkg.Read(hostTestContext(), bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadLimits())
}
