package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
)

func TestRuntimeLifecycleUsesInjectedSupervisor(t *testing.T) {
	supervisor := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", Ready: true},
	}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		runtimeSupervisor: supervisor,
	})

	health, err := h.StartRuntime(context.Background(), StartRuntimeRequest{Target: RuntimeTarget{OS: "test-os", Arch: "test-arch"}})
	if err != nil {
		t.Fatalf("StartRuntime() error = %v", err)
	}
	if health.RuntimeInstanceID != "runtime_1" || supervisor.startedTarget.OS != "test-os" || supervisor.startedTarget.Arch != "test-arch" {
		t.Fatalf("runtime start mismatch: health=%#v supervisor=%#v", health, supervisor)
	}
	if !audits.hasEvent("plugin.runtime.started") {
		t.Fatalf("missing runtime started audit: %#v", audits.events)
	}

	if err := h.StopRuntime(context.Background()); err != nil {
		t.Fatalf("StopRuntime() error = %v", err)
	}
	if supervisor.stopCalls != 1 || !audits.hasEvent("plugin.runtime.stopped") {
		t.Fatalf("runtime stop mismatch: stopCalls=%d audits=%#v", supervisor.stopCalls, audits.events)
	}
}

func TestStartRuntimeRequiresResolverWhenSupervisorMissing(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	if _, err := h.StartRuntime(context.Background(), StartRuntimeRequest{}); err == nil {
		t.Fatal("StartRuntime() expected resolver error")
	}
}

func TestStartRuntimeUsesArtifactResolver(t *testing.T) {
	resolver := &recordingRuntimeArtifactResolver{path: filepath.Join(t.TempDir(), "missing-runtime")}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		runtimeArtifactResolver: resolver,
	})
	health, err := h.RuntimeHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("RuntimeHealth() should be not ready before start: %#v", health)
	}
	if _, err := h.StartRuntime(context.Background(), StartRuntimeRequest{}); err == nil {
		t.Fatal("StartRuntime() expected missing runtime binary error")
	}
	if resolver.calls != 1 || resolver.target.OS == "" || resolver.target.Arch == "" {
		t.Fatalf("resolver call mismatch: %#v", resolver)
	}
}

func TestProcessSupervisorOptionsInjectsConnectivityRuntimeHostcalls(t *testing.T) {
	broker := connectivity.NewMemoryBroker()
	executor := &recordingHostNetworkExecutor{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: broker,
		networkExecutor:    executor,
	})

	options := h.processSupervisorOptions("/tmp/redevplugin-runtime")
	if options.RuntimePath != "/tmp/redevplugin-runtime" ||
		options.Artifacts == nil ||
		options.HandleGrants == nil ||
		options.Connectivity != broker ||
		options.NetworkExecutor != executor {
		t.Fatalf("process supervisor options mismatch: %#v", options)
	}
}

func TestNewHostProvidesDefaultNetworkExecutor(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	options := h.processSupervisorOptions("/tmp/redevplugin-runtime")
	if options.Connectivity == nil || options.NetworkExecutor == nil {
		t.Fatalf("default runtime network hostcalls missing: %#v", options)
	}
}

func TestRuntimeArtifactProviderReadsBoundPackageAsset(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	pkg, err := pluginPackageFromBytesForRuntimeTest(buildWorkerFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.adapters.Assets.PutPackage(context.Background(), pkg); err != nil {
		t.Fatal(err)
	}
	asset, err := h.adapters.Assets.ReadAsset(context.Background(), pkg.PackageHash, "workers/echo.wasm")
	if err != nil {
		t.Fatal(err)
	}
	provider := runtimeArtifactProvider{assets: h.adapters.Assets}
	result, err := provider.ReadArtifact(context.Background(), runtimeclient.ArtifactRequest{
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
	if _, err := provider.ReadArtifact(context.Background(), runtimeclient.ArtifactRequest{
		PackageHash:    pkg.PackageHash,
		Artifact:       "workers/echo.wasm",
		ArtifactSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}); err == nil {
		t.Fatal("ReadArtifact() expected sha mismatch error")
	}
}

type recordingHostNetworkExecutor struct {
	httpCalls  int
	lastHTTP   connectivity.HTTPRequest
	httpStatus int
	httpBody   []byte
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

func (e *recordingHostNetworkExecutor) WebSocketRoundTrip(context.Context, connectivity.WebSocketRoundTripRequest) (connectivity.WebSocketRoundTripResponse, error) {
	return connectivity.WebSocketRoundTripResponse{}, nil
}

func (e *recordingHostNetworkExecutor) TCPRoundTrip(context.Context, connectivity.TCPRoundTripRequest) (connectivity.TCPRoundTripResponse, error) {
	return connectivity.TCPRoundTripResponse{}, nil
}

func (e *recordingHostNetworkExecutor) UDPRoundTrip(context.Context, connectivity.UDPRoundTripRequest) (connectivity.UDPRoundTripResponse, error) {
	return connectivity.UDPRoundTripResponse{}, nil
}

func TestRuntimeHandleGrantValidatorUsesSurfaceTokens(t *testing.T) {
	now := time.Now().UTC()
	service := bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{})
	revision := bridge.RevisionBinding{PolicyRevision: 1, ManagementRevision: 2, RevokeEpoch: 3}
	minted, err := service.MintHandleGrant(bridge.MintHandleGrantRequest{
		PluginInstanceID:    "plugini_1",
		ActiveFingerprint:   "sha256:active",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_1",
		HandleID:            "storage:db",
		Method:              "storage.sqlite",
		Revision:            revision,
		Limits:              bridge.Limits{MaxTotalBytes: 4096},
		Now:                 now,
	})
	if err != nil {
		t.Fatal(err)
	}
	validator := runtimeHandleGrantValidator{tokens: service}
	result, err := validator.ValidateHandleGrant(context.Background(), runtimeclient.HandleGrantValidationRequest{
		HandleGrantToken:    minted.HandleGrantToken,
		PluginInstanceID:    "plugini_1",
		ActiveFingerprint:   "sha256:active",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_1",
		HandleID:            "storage:db",
		Method:              "storage.sqlite",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	})
	if err != nil {
		t.Fatalf("ValidateHandleGrant() error = %v", err)
	}
	if result.HandleGrantID != minted.HandleGrantID || result.HandleID != "storage:db" || result.Method != "storage.sqlite" || result.MaxTotalBytes != 4096 {
		t.Fatalf("handle grant result mismatch: %#v", result)
	}
	if _, err := validator.ValidateHandleGrant(context.Background(), runtimeclient.HandleGrantValidationRequest{
		HandleGrantToken:    minted.HandleGrantToken,
		PluginInstanceID:    "plugini_1",
		ActiveFingerprint:   "sha256:active",
		RuntimeGenerationID: "runtime_gen_1",
		HandleID:            "storage:other",
		Method:              "storage.sqlite",
		PolicyRevision:      1,
		ManagementRevision:  2,
		RevokeEpoch:         3,
	}); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("ValidateHandleGrant(wrong handle) error = %v, want ErrTokenAudience", err)
	}
}

func pluginPackageFromBytesForRuntimeTest(raw []byte) (pluginpkg.Package, error) {
	return pluginpkg.Read(context.Background(), bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadOptions())
}
