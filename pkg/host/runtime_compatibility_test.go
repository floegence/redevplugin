package host

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

func TestUIOnlyLifecycleDoesNotRequireRuntimeManager(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:         true,
		localGenerated:        true,
		withoutRuntimeManager: true,
	})
	packageBytes := buildFixturePackage(t)
	installed, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: nextTestPluginInstanceID(t),
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
	})
	if err != nil {
		t.Fatalf("InstallLocalPackage() error = %v", err)
	}
	enabled, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:           enabled.PluginInstanceID,
		ExpectedManagementRevision: enabled.ManagementRevision,
		SurfaceID:                  "lifecycle.view",
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if bootstrap.RuntimeGenerationID != h.surfaceGenerationID {
		t.Fatalf("UI-only runtime generation = %q, want host generation %q", bootstrap.RuntimeGenerationID, h.surfaceGenerationID)
	}
}

func TestFirstWorkerInstallStartsAndPrewarmsUnreadyRuntime(t *testing.T) {
	manager := newRecordingRuntimeManager()
	manager.health.Ready = false
	manager.startHealthReady = true
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: manager,
	})
	defer h.Close()

	installed := installAndEnablePlugin(t, h, buildWorkerFixturePackage(t))
	if manager.startCalls != 1 || manager.startedTarget != manager.descriptor.Target() {
		t.Fatalf("runtime start calls = %d, target = %s", manager.startCalls, manager.startedTarget)
	}
	if manager.prewarmCalls != 1 || len(manager.prewarmRequests) != 1 {
		t.Fatalf("runtime prewarm calls = %d, requests = %#v", manager.prewarmCalls, manager.prewarmRequests)
	}
	request := manager.prewarmRequests[0]
	entry, ok := packageEntryByPath(installed.PackageEntries, request.Artifact.Artifact)
	if !ok || request.PluginInstanceID != installed.PluginInstanceID || request.WorkerID != "echo_worker" ||
		request.Artifact.PackageHash != installed.PackageHash || request.Artifact.ArtifactSHA256 != entry.SHA256 {
		t.Fatalf("runtime prewarm request = %#v", request)
	}

	if _, err := h.RecoverEnabled(hostTestContext()); err != nil {
		t.Fatalf("RecoverEnabled() error = %v", err)
	}
	if manager.startCalls != 1 {
		t.Fatalf("ready runtime start calls after recovery = %d, want 1", manager.startCalls)
	}
}

func TestWorkerInstallKeepsCommittedEnabledIntentWhenRuntimeStartFails(t *testing.T) {
	manager := newRecordingRuntimeManager()
	manager.health.Ready = false
	manager.startHealthReady = true
	manager.startErr = errors.New("runtime start failed")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: manager,
	})
	defer h.Close()

	packageBytes := buildWorkerFixturePackage(t)
	pluginInstanceID := nextTestPluginInstanceID(t)
	installed, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: pluginInstanceID,
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
	})
	if err == nil {
		t.Fatal("ImportLocalPackage() succeeded with an unavailable runtime")
	}
	if installed.PluginInstanceID != pluginInstanceID || installed.EnableState != registry.EnableEnabled {
		t.Fatalf("committed install = %#v", installed)
	}
	stored, getErr := h.getPluginRecord(hostTestContext(), pluginInstanceID)
	if getErr != nil || stored.EnableState != registry.EnableEnabled {
		t.Fatalf("stored install = %#v, %v", stored, getErr)
	}
	if manager.startCalls != 1 || manager.prewarmCalls != 0 {
		t.Fatalf("runtime calls after failed start: start=%d prewarm=%d", manager.startCalls, manager.prewarmCalls)
	}
}

func TestUIOnlyDisableDoesNotRevokeRuntime(t *testing.T) {
	manager := newRecordingRuntimeManager()
	manager.revokeErr = errors.New("runtime must not be called")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	packageBytes := buildFixturePackage(t)
	installed, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: nextTestPluginInstanceID(t),
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           enabled.PluginInstanceID,
		ExpectedManagementRevision: enabled.ManagementRevision,
		Reason:                     "test",
	}); err != nil {
		t.Fatalf("DisablePlugin() queried runtime for UI-only plugin: %v", err)
	}
	if manager.revokeCalls != 0 {
		t.Fatalf("UI-only runtime revoke calls = %d, want 0", manager.revokeCalls)
	}
}

func TestWorkerFailSafeLifecycleDoesNotRestartStoppedRuntime(t *testing.T) {
	for _, action := range []string{"disable", "uninstall"} {
		t.Run(action, func(t *testing.T) {
			installManager := newRecordingRuntimeManager()
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode:  true,
				localGenerated: true,
				runtimeManager: installManager,
			})
			enabled, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
			preflightCalls := installManager.preflightCalls
			startCalls := installManager.startCalls
			h.adapters.RuntimeManager = newNeverStartedProcessManagerForHost(t, h)

			var err error
			switch action {
			case "disable":
				_, err = h.DisablePlugin(hostTestContext(), DisableRequest{
					PluginInstanceID: enabled.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision,
				})
			case "uninstall":
				_, err = h.UninstallPlugin(hostTestContext(), UninstallRequest{
					PluginInstanceID: enabled.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision, DeleteData: true,
				})
			}
			if err != nil {
				t.Fatalf("%s stopped worker runtime: %v", action, err)
			}
			if installManager.preflightCalls != preflightCalls || installManager.startCalls != startCalls {
				t.Fatalf("runtime installation manager was reused after %s: preflight=%d start=%d", action, installManager.preflightCalls, installManager.startCalls)
			}
			if _, err := h.surfaceTokens.ValidateGatewayToken(gateway.GatewayToken, bridge.Audience{
				PluginInstanceID:     enabled.PluginInstanceID,
				ActiveFingerprint:    enabled.ActiveFingerprint,
				SurfaceInstanceID:    "surface_rpc",
				OwnerSessionHash:     "session_hash",
				OwnerUserHash:        "user_hash",
				SessionChannelIDHash: "channel_hash",
				BridgeChannelID:      "bridge_rpc",
			}, bridge.RevisionBinding{
				PolicyRevision: enabled.PolicyRevision, ManagementRevision: enabled.ManagementRevision, RevokeEpoch: enabled.RevokeEpoch,
			}, time.Now().UTC()); !errors.Is(err, bridge.ErrTokenRevoked) {
				t.Fatalf("ValidateGatewayToken() after %s error = %v, want %v", action, err, bridge.ErrTokenRevoked)
			}
		})
	}
}

func newNeverStartedProcessManager(t *testing.T) *runtimeclient.ProcessManager {
	t.Helper()
	manager, err := runtimeclient.NewProcessManager(runtimeclient.ProcessManagerOptions{
		ShardCount: 1,
		Supervisor: runtimeclient.ProcessSupervisorOptions{
			RuntimePath:           filepath.Join(t.TempDir(), "missing-redevplugin-runtime"),
			ArtifactIdentity:      hostTestRuntimeArtifactIdentity(),
			Limits:                runtimeclient.DefaultRuntimeLimits(),
			HandshakeTimeout:      5 * time.Second,
			HeartbeatInterval:     2 * time.Second,
			MaxHeartbeatStaleness: 5 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func newNeverStartedProcessManagerForHost(t *testing.T, h *Host) *runtimeclient.ProcessManager {
	t.Helper()
	manager := newNeverStartedProcessManager(t)
	if err := manager.BindHostServices(runtimeclient.RuntimeHostServices{StreamSink: hostRuntimeStreamSink{executions: h.executions}, IOBroker: h.runtimeIO}); err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestWorkerInstallRejectsMissingRuntimeBeforeMutation(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:         true,
		localGenerated:        true,
		withoutRuntimeManager: true,
	})
	packageBytes := buildWorkerFixturePackage(t)
	_, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: nextTestPluginInstanceID(t),
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
	})
	if !errors.Is(err, ErrFeatureNotConfigured) {
		t.Fatalf("InstallLocalPackage() error = %v, want ErrFeatureNotConfigured", err)
	}
	var missing FeatureNotConfiguredError
	if !errors.As(err, &missing) || len(missing.MissingFeatures()) != 1 || missing.MissingFeatures()[0] != FeatureRuntime {
		t.Fatalf("InstallLocalPackage() missing features = %#v, want runtime", missing.MissingFeatures())
	}
	records, listErr := h.ListPlugins(hostTestContext())
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(records) != 0 {
		t.Fatalf("worker install mutated registry: %#v", records)
	}
}

func TestWorkerInstallPreservesRuntimeAvailabilityFailures(t *testing.T) {
	for _, test := range []struct {
		name         string
		healthErr    error
		preflightErr error
		want         error
	}{
		{name: "health not ready", healthErr: runtimeclient.ErrRuntimeNotReady, want: runtimeclient.ErrRuntimeNotReady},
		{name: "health ipc unavailable", healthErr: runtimeclient.ErrRuntimeIPCUnavailable, want: runtimeclient.ErrRuntimeIPCUnavailable},
		{name: "preflight request failed", preflightErr: runtimeclient.ErrRuntimeRequestFailed, want: runtimeclient.ErrRuntimeRequestFailed},
		{name: "preflight handshake", preflightErr: runtimeclient.ErrRuntimeHandshake, want: runtimeclient.ErrRuntimeHandshake},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := recordingRuntimeManagerForDescriptor(hostTestRuntimeArtifactIdentity())
			manager.healthErr = test.healthErr
			manager.preflightErr = test.preflightErr
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode: true, localGenerated: true, runtimeManager: manager,
			})
			packageBytes := buildWorkerFixturePackage(t)
			_, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
				PluginInstanceID: nextTestPluginInstanceID(t), PackageReader: bytes.NewReader(packageBytes), PackageSize: int64(len(packageBytes)),
			})
			if !errors.Is(err, test.want) || errors.Is(err, ErrPluginRuntimeIncompatible) {
				t.Fatalf("InstallLocalPackage() error = %v, want %v without runtime incompatibility", err, test.want)
			}
			records, listErr := h.ListPlugins(hostTestContext())
			if listErr != nil {
				t.Fatal(listErr)
			}
			if len(records) != 0 {
				t.Fatalf("runtime availability failure mutated registry: %#v", records)
			}
		})
	}
}

func TestWorkerInstallRejectsIncompatibleRuntimeVersionBeforeMutation(t *testing.T) {
	runtimeVersion, err := version.ParseSemVer("0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := runtimeclient.NewRuntimeArtifactIdentity(runtimeclient.RuntimeArtifactIdentityOptions{
		PlatformVersion: runtimeVersion, Target: hostTestRuntimeArtifactIdentity().Target(),
		BinarySHA256: strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := recordingRuntimeManagerForDescriptor(descriptor)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	packageBytes := buildWorkerFixturePackageVersion(t, "1.0.0")
	_, err = h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: nextTestPluginInstanceID(t),
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
	})
	if !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("InstallLocalPackage() error = %v, want ErrPluginRuntimeIncompatible", err)
	}
	if manager.preflightCalls != 1 {
		t.Fatalf("runtime preflight calls = %d, want 1", manager.preflightCalls)
	}
	records, listErr := h.ListPlugins(hostTestContext())
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(records) != 0 {
		t.Fatalf("incompatible worker install mutated registry: %#v", records)
	}
}

func TestValidateWorkerRuntimeArtifactIdentityRejectsUnexpectedTarget(t *testing.T) {
	descriptor := hostTestRuntimeArtifactIdentity()
	expectedTarget := descriptor.Target()
	otherArch := "arm64"
	if expectedTarget.Arch() == "arm64" {
		otherArch = "amd64"
	}
	expectedTarget, err := runtimetarget.FromParts(expectedTarget.OS(), otherArch)
	if err != nil {
		t.Fatal(err)
	}
	record := registry.PluginRecord{Manifest: manifest.Manifest{Workers: []manifest.WorkerSpec{{WorkerID: "worker"}}}}
	if err := validateWorkerRuntimeArtifactIdentity(record, descriptor, expectedTarget); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("validateWorkerRuntimeArtifactIdentity() error = %v, want ErrPluginRuntimeIncompatible", err)
	}
}

func TestStartRuntimeRequiresExplicitCanonicalTarget(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{runtimeManager: manager})
	if _, err := h.StartRuntime(hostTestContext(), StartRuntimeRequest{}); !errors.Is(err, runtimetarget.ErrUnsupported) {
		t.Fatalf("StartRuntime() error = %v, want runtimetarget.ErrUnsupported", err)
	}
	if manager.preflightCalls != 0 || manager.startCalls != 0 {
		t.Fatalf("invalid target reached manager: preflight=%d start=%d", manager.preflightCalls, manager.startCalls)
	}
}

func TestWorkerEnableRuntimeFailureKeepsEnabled(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	installed := importWorkerVersion(t, h, "1.0.0")
	disabled, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		Reason:                     "test runtime readiness",
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.bindErr = runtimeclient.ErrRuntimeNotReady

	_, err = h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: disabled.ManagementRevision,
	})
	if !errors.Is(err, runtimeclient.ErrRuntimeNotReady) {
		t.Fatalf("EnablePlugin() error = %v, want ErrRuntimeNotReady", err)
	}
	stored, getErr := h.getPluginRecord(hostTestContext(), installed.PluginInstanceID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if stored.EnableState != registry.EnableEnabled || stored.ManagementRevision != disabled.ManagementRevision+1 {
		t.Fatalf("runtime readiness failure rewrote lifecycle state: %#v", stored)
	}
}

func TestWorkerUpdateReusesRuntimeAndPrewarmsCommittedPackage(t *testing.T) {
	manager := newRecordingRuntimeManager()
	manager.health.Ready = false
	manager.startHealthReady = true
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: manager,
	})
	defer h.Close()
	installed := importWorkerVersion(t, h, "1.0.0")
	packageBytes := buildWorkerFixturePackageVersion(t, "2.0.0")

	updated, err := h.UpdateLocalPackage(hostTestContext(), UpdateLocalPackageRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		PackageReader:              bytes.NewReader(packageBytes),
		PackageSize:                int64(len(packageBytes)),
	})
	if err != nil {
		t.Fatalf("UpdateLocalPackage() error = %v", err)
	}
	if updated.Version != "2.0.0" || manager.startCalls != 1 || manager.prewarmCalls != 2 {
		t.Fatalf("updated plugin = %#v, runtime start=%d prewarm=%d", updated, manager.startCalls, manager.prewarmCalls)
	}
	request := manager.prewarmRequests[len(manager.prewarmRequests)-1]
	entry, ok := packageEntryByPath(updated.PackageEntries, request.Artifact.Artifact)
	if !ok || request.Artifact.PackageHash != updated.PackageHash || request.Artifact.ArtifactSHA256 != entry.SHA256 {
		t.Fatalf("updated runtime prewarm request = %#v", request)
	}
}

func TestWorkerUpdateRejectsPreflightFailureBeforeMutation(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	installed := importWorkerVersion(t, h, "1.0.0")
	manager.preflightErr = errors.New("runtime artifact unavailable")
	packageBytes := buildWorkerFixturePackageVersion(t, "2.0.0")

	_, err := h.UpdateLocalPackage(hostTestContext(), UpdateLocalPackageRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		PackageReader:              bytes.NewReader(packageBytes),
		PackageSize:                int64(len(packageBytes)),
	})
	if !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("UpdateLocalPackage() error = %v, want ErrPluginRuntimeIncompatible", err)
	}
	stored, getErr := h.getPluginRecord(hostTestContext(), installed.PluginInstanceID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if stored.Version != installed.Version || stored.ManagementRevision != installed.ManagementRevision || len(stored.VersionHistory) != 0 {
		t.Fatalf("failed update mutated record: %#v", stored)
	}
}

func TestWorkerDowngradeRejectsPreflightFailureBeforeMutation(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	installed := importWorkerVersion(t, h, "1.0.0")
	packageBytes := buildWorkerFixturePackageVersion(t, "2.0.0")
	updated, err := h.UpdateLocalPackage(hostTestContext(), UpdateLocalPackageRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		PackageReader:              bytes.NewReader(packageBytes),
		PackageSize:                int64(len(packageBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.preflightErr = errors.New("runtime artifact unavailable")

	_, err = h.DowngradePlugin(hostTestContext(), DowngradeRequest{
		PluginInstanceID:           updated.PluginInstanceID,
		ExpectedManagementRevision: updated.ManagementRevision,
		Version:                    "1.0.0",
	})
	if !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("DowngradePlugin() error = %v, want ErrPluginRuntimeIncompatible", err)
	}
	stored, getErr := h.getPluginRecord(hostTestContext(), updated.PluginInstanceID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if stored.Version != updated.Version || stored.ManagementRevision != updated.ManagementRevision {
		t.Fatalf("failed downgrade mutated record: %#v", stored)
	}
}

func TestWorkerInvocationRejectsStaleBindingDescriptorBeforeDispatch(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	staleVersion, err := version.ParseSemVer("0.0.0-dev+replaced")
	if err != nil {
		t.Fatal(err)
	}
	manager.bindingDescriptor, err = runtimeclient.NewRuntimeArtifactIdentity(runtimeclient.RuntimeArtifactIdentityOptions{
		PlatformVersion: staleVersion, Target: manager.descriptor.Target(),
		BinarySHA256: strings.Repeat("c", 64),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",
		BridgeChannelID:   "bridge_rpc",
		GatewayToken:      gateway.GatewayToken,
		Method:            "worker.echo",
		Params:            map[string]any{"message": "hello"},
	})
	if err == nil {
		t.Fatal("CallPluginMethod() accepted stale runtime binding descriptor")
	}
	if manager.calls != 0 {
		t.Fatalf("stale binding dispatched %d worker calls", manager.calls)
	}
	executions, _, listErr := h.ListExecutions(hostTestContext(), installed.PluginInstanceID, 0, 100)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(executions) != 0 {
		t.Fatalf("stale binding created executions: %#v", executions)
	}
}

func TestWorkerOpenSurfaceIgnoresIncompatibleRuntimeHealth(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	installed := installAndEnablePlugin(t, h, buildWorkerFixturePackage(t))
	staleVersion, err := version.ParseSemVer("0.0.0-alpha")
	if err != nil {
		t.Fatal(err)
	}
	manager.health.ArtifactIdentity, err = runtimeclient.NewRuntimeArtifactIdentity(runtimeclient.RuntimeArtifactIdentityOptions{
		PlatformVersion: staleVersion, Target: manager.descriptor.Target(),
		BinarySHA256: strings.Repeat("d", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID),
		SurfaceID:                  "worker.view",
	})
	if err != nil || bootstrap.RuntimeGenerationID != h.surfaceGenerationID {
		t.Fatalf("OpenSurface() with incompatible runtime = %#v, %v", bootstrap, err)
	}
}

func TestStopRuntimePreservesUIOnlySurface(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	packageBytes := buildFixturePackage(t)
	installed, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: nextTestPluginInstanceID(t),
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	bootstrap, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:           enabled.PluginInstanceID,
		ExpectedManagementRevision: enabled.ManagementRevision,
		SurfaceID:                  "lifecycle.view",
		Now:                        now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.StopRuntime(hostTestContext()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.surfaceTokens.ExchangeAssetTicket(bridge.ExchangeAssetTicketRequest{
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		AssetTicket:          bootstrap.AssetTicket,
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
		Now:                  now.Add(time.Second),
	}); err != nil {
		t.Fatalf("UI-only surface was revoked by runtime stop: %v", err)
	}
}

func recordingRuntimeManagerForDescriptor(descriptor runtimeclient.RuntimeArtifactIdentity) *recordingRuntimeManager {
	return &recordingRuntimeManager{
		descriptor: descriptor,
		health: runtimeclient.Health{
			RuntimeInstanceID:   "runtime_test",
			RuntimeGenerationID: "runtime_gen_test",
			IPCChannelID:        "ipc_test",
			ConnectionNonce:     "connection_nonce_test_1234567890",
			ArtifactIdentity:    descriptor,
			Ready:               true,
		},
	}
}

func buildWorkerFixturePackageVersion(t *testing.T, pluginVersion string) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerFixtureManifestJSON(), `"version": "1.0.0"`, `"version": "`+pluginVersion+`"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var buffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func importWorkerVersion(t *testing.T, h *Host, pluginVersion string) registry.PluginRecord {
	t.Helper()
	packageBytes := buildWorkerFixturePackageVersion(t, pluginVersion)
	installed, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: nextTestPluginInstanceID(t),
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return installed
}

var _ runtimeclient.Manager = (*recordingRuntimeManager)(nil)
