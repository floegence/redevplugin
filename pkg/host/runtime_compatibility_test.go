package host

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/runtimeclient"
	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/version"
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
			Descriptor:            hostTestRuntimeDescriptor(),
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
	if err := manager.BindHostServices(runtimeclient.RuntimeHostServices{StreamSink: hostRuntimeStreamSink{executions: h.executions}}); err != nil {
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

func TestWorkerInstallRejectsIncompatibleRuntimeVersionBeforeMutation(t *testing.T) {
	runtimeVersion, err := version.ParseSemVer("0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := runtimeclient.NewRuntimeDescriptor(runtimeclient.RuntimeDescriptorOptions{
		PlatformVersion: runtimeVersion, Target: hostTestRuntimeDescriptor().Target(),
		RustIPCVersion: version.RustIPCVersion, WASMABIVersion: version.WASMABIVersion,
		ContractSetSHA256: version.ContractSetSHA256, BinarySHA256: strings.Repeat("b", 64),
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
	packageBytes := buildWorkerFixturePackageWithMinRuntime(t, "0.1.0")
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

func TestValidateWorkerRuntimeDescriptorRejectsUnexpectedTarget(t *testing.T) {
	descriptor := hostTestRuntimeDescriptor()
	expectedTarget := descriptor.Target()
	otherArch := "arm64"
	if expectedTarget.Arch() == "arm64" {
		otherArch = "amd64"
	}
	expectedTarget, err := runtimetarget.FromParts(expectedTarget.OS(), otherArch)
	if err != nil {
		t.Fatal(err)
	}
	record := registry.PluginRecord{
		Manifest: manifest.Manifest{Workers: []manifest.WorkerSpec{{WorkerID: "worker", ABI: version.WASMABIVersion}}},
		RuntimeRequirement: &registry.RuntimeRequirement{
			MinVersion: descriptor.PlatformVersion().String(),
		},
	}
	if err := validateWorkerRuntimeDescriptor(record, descriptor, expectedTarget); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("validateWorkerRuntimeDescriptor() error = %v, want ErrPluginRuntimeIncompatible", err)
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

func TestWorkerEnableRejectsPreflightFailureBeforeMutation(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	installed := importWorkerVersion(t, h, "1.0.0", "0.0.0-dev")
	preflightFailure := errors.New("runtime artifact unavailable")
	manager.preflightErr = preflightFailure

	_, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("EnablePlugin() error = %v, want ErrPluginRuntimeIncompatible", err)
	}
	stored, getErr := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if stored.EnableState != registry.EnableDisabled || stored.ManagementRevision != installed.ManagementRevision {
		t.Fatalf("failed enable mutated record: %#v", stored)
	}
}

func TestWorkerUpdateRejectsPreflightFailureBeforeMutation(t *testing.T) {
	manager := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: manager,
	})
	installed := importWorkerVersion(t, h, "1.0.0", "0.0.0-dev")
	manager.preflightErr = errors.New("runtime artifact unavailable")
	packageBytes := buildWorkerFixturePackageVersion(t, "2.0.0", "0.0.0-dev")

	_, err := h.UpdateLocalPackage(hostTestContext(), UpdateLocalPackageRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		PackageReader:              bytes.NewReader(packageBytes),
		PackageSize:                int64(len(packageBytes)),
	})
	if !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("UpdateLocalPackage() error = %v, want ErrPluginRuntimeIncompatible", err)
	}
	stored, getErr := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
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
	installed := importWorkerVersion(t, h, "1.0.0", "0.0.0-dev")
	packageBytes := buildWorkerFixturePackageVersion(t, "2.0.0", "0.0.0-dev")
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
	stored, getErr := h.adapters.Registry.GetPlugin(hostTestContext(), updated.PluginInstanceID)
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
	manager.bindingDescriptor, err = runtimeclient.NewRuntimeDescriptor(runtimeclient.RuntimeDescriptorOptions{
		PlatformVersion: staleVersion, Target: manager.descriptor.Target(),
		RustIPCVersion: manager.descriptor.RustIPCVersion(), WASMABIVersion: manager.descriptor.WASMABIVersion(),
		ContractSetSHA256: manager.descriptor.ContractSetSHA256(), BinarySHA256: strings.Repeat("c", 64),
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
	operations, listErr := h.ListOperations(hostTestContext(), ListOperationsRequest{PluginInstanceID: installed.PluginInstanceID})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(operations.Operations) != 0 {
		t.Fatalf("stale binding created operations: %#v", operations.Operations)
	}
}

func TestWorkerOpenSurfaceRejectsIncompatibleRuntimeHealth(t *testing.T) {
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
	manager.health.Descriptor, err = runtimeclient.NewRuntimeDescriptor(runtimeclient.RuntimeDescriptorOptions{
		PlatformVersion: staleVersion, Target: manager.descriptor.Target(),
		RustIPCVersion: manager.descriptor.RustIPCVersion(), WASMABIVersion: manager.descriptor.WASMABIVersion(),
		ContractSetSHA256: manager.descriptor.ContractSetSHA256(), BinarySHA256: strings.Repeat("d", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID),
		SurfaceID:                  "worker.view",
	}); !errors.Is(err, ErrPluginRuntimeIncompatible) {
		t.Fatalf("OpenSurface() error = %v, want ErrPluginRuntimeIncompatible", err)
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

func recordingRuntimeManagerForDescriptor(descriptor runtimeclient.RuntimeDescriptor) *recordingRuntimeManager {
	return &recordingRuntimeManager{
		descriptor: descriptor,
		health: runtimeclient.Health{
			RuntimeInstanceID:   "runtime_test",
			RuntimeGenerationID: "runtime_gen_test",
			IPCChannelID:        "ipc_test",
			ConnectionNonce:     "connection_nonce_test_1234567890",
			Descriptor:          descriptor,
			Ready:               true,
		},
	}
}

func buildWorkerFixturePackageWithMinRuntime(t *testing.T, minimumVersion string) []byte {
	return buildWorkerFixturePackageVersion(t, "1.0.0", minimumVersion)
}

func buildWorkerFixturePackageVersion(t *testing.T, pluginVersion string, minimumVersion string) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(
		workerFixtureManifestJSON(),
		`"min_runtime_version": "0.0.0-dev"`,
		`"min_runtime_version": "`+minimumVersion+`"`,
		1,
	)
	manifestJSON = strings.Replace(manifestJSON, `"version": "1.0.0"`, `"version": "`+pluginVersion+`"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var buffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func importWorkerVersion(t *testing.T, h *Host, pluginVersion string, minimumVersion string) registry.PluginRecord {
	t.Helper()
	packageBytes := buildWorkerFixturePackageVersion(t, pluginVersion, minimumVersion)
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
