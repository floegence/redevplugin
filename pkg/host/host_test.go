package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
)

func TestLifecycleInstallEnableDisableUninstall(t *testing.T) {
	host, surfaces, audits := newTestHost(t, true, true)
	packageBytes := buildFixturePackage(t)

	installed, err := InstallPackageBytes(context.Background(), host, packageBytes, registry.TrustVerified)
	if err != nil {
		t.Fatalf("InstallPackageBytes() error = %v", err)
	}
	if installed.EnableState != registry.EnableDisabled {
		t.Fatalf("install EnableState = %s", installed.EnableState)
	}
	if installed.PolicyRevision == 0 || installed.ManagementRevision == 0 {
		t.Fatalf("revision fields not initialized: %#v", installed)
	}

	enabled, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable EnableState = %s", enabled.EnableState)
	}
	if len(surfaces.snapshots) != 1 || len(surfaces.snapshots[0].Surfaces) != 1 {
		t.Fatalf("surface publish mismatch: %#v", surfaces.snapshots)
	}

	disabled, err := host.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test"})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if disabled.EnableState != registry.EnableDisabled {
		t.Fatalf("disable EnableState = %s", disabled.EnableState)
	}
	if len(surfaces.snapshots) != 2 || len(surfaces.snapshots[1].Surfaces) != 0 {
		t.Fatalf("disable did not clear surfaces: %#v", surfaces.snapshots)
	}

	uninstalled, err := host.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true})
	if err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	if uninstalled.RetainedDataState != registry.RetainedDataDeleted {
		t.Fatalf("RetainedDataState = %s", uninstalled.RetainedDataState)
	}
	if _, err := host.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID); err != registry.ErrNotFound {
		t.Fatalf("GetPlugin after uninstall error = %v", err)
	}
	if len(audits.events) != 4 {
		t.Fatalf("audit count = %d", len(audits.events))
	}
}

func TestUpdateAndDowngradeRefreshEnabledPluginAndRevokeOldTokens(t *testing.T) {
	ctx := context.Background()
	h, surfaces, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	v1 := buildVersionedRPCPackage(t, "1.0.0", "RPC")
	v2 := buildVersionedRPCPackage(t, "2.0.0", "RPC v2")
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	installed, err := InstallPackageBytes(ctx, h, v1, registry.TrustVerified)
	if err != nil {
		t.Fatalf("InstallPackageBytes() error = %v", err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "rpc.activity",
		SurfaceInstanceID:    "surface_update",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if _, err := h.ExchangeAssetTicket(ctx, ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("ExchangeAssetTicket() error = %v", err)
	}
	gateway, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake: bridge.Handshake{
			PluginID:          bootstrap.PluginID,
			SurfaceID:         bootstrap.SurfaceID,
			SurfaceInstanceID: bootstrap.SurfaceInstanceID,
			ActiveFingerprint: bootstrap.ActiveFingerprint,
			BridgeNonce:       bootstrap.BridgeNonce,
			UIProtocolVersion: "plugin-ui-v1",
		},
		BridgeChannelID: "bridge_update",
		Now:             now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}

	updated, err := h.UpdatePlugin(ctx, UpdateRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(v2),
		PackageSize:      int64(len(v2)),
		Now:              now.Add(4 * time.Second),
	})
	if err != nil {
		t.Fatalf("UpdatePlugin() error = %v", err)
	}
	if updated.Version != "2.0.0" || updated.EnableState != registry.EnableEnabled || len(updated.VersionHistory) != 1 || updated.VersionHistory[0].Version != "1.0.0" {
		t.Fatalf("updated record mismatch: %#v", updated)
	}
	if updated.ManagementRevision <= installed.ManagementRevision || updated.RevokeEpoch <= installed.RevokeEpoch {
		t.Fatalf("update did not bump revision/revoke epoch: before=%#v after=%#v", installed, updated)
	}
	if len(surfaces.snapshots) < 2 || surfaces.snapshots[len(surfaces.snapshots)-1].ActiveFingerprint != updated.ActiveFingerprint {
		t.Fatalf("surface catalog was not refreshed: %#v", surfaces.snapshots)
	}
	if _, err := h.surfaceTokens.ValidateGatewayToken(gateway.GatewayToken, bridge.Audience{
		PluginInstanceID:     updated.PluginInstanceID,
		ActiveFingerprint:    bootstrap.ActiveFingerprint,
		SurfaceInstanceID:    "surface_update",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_update",
	}, bridge.RevisionBinding{
		PolicyRevision:     updated.PolicyRevision,
		ManagementRevision: updated.ManagementRevision,
		RevokeEpoch:        updated.RevokeEpoch,
	}, now.Add(5*time.Second)); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() old token error = %v, want ErrTokenRevoked", err)
	}

	downgraded, err := h.DowngradePlugin(ctx, DowngradeRequest{
		PluginInstanceID: updated.PluginInstanceID,
		Version:          "1.0.0",
		Now:              now.Add(6 * time.Second),
	})
	if err != nil {
		t.Fatalf("DowngradePlugin() error = %v", err)
	}
	if downgraded.Version != "1.0.0" || downgraded.ActiveFingerprint != installed.ActiveFingerprint || len(downgraded.VersionHistory) != 1 || downgraded.VersionHistory[0].Version != "2.0.0" {
		t.Fatalf("downgraded record mismatch: %#v", downgraded)
	}
	if !audits.hasEvent("plugin.updated") || !audits.hasEvent("plugin.downgraded") {
		t.Fatalf("missing update/downgrade audit events: %#v", audits.events)
	}
}

func TestUpdateRejectsDifferentPluginIdentity(t *testing.T) {
	ctx := context.Background()
	h, _, _ := newTestHost(t, true, true)
	installed, err := InstallPackageBytes(ctx, h, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	other := buildStorageFixturePackage(t)
	if _, err := h.UpdatePlugin(ctx, UpdateRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(other),
		PackageSize:      int64(len(other)),
	}); err == nil {
		t.Fatal("UpdatePlugin() expected identity mismatch error")
	}
}

func TestEnableRejectsUntrusted(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	installed, err := InstallPackageBytes(context.Background(), host, buildFixturePackage(t), registry.TrustUntrusted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err == nil {
		t.Fatal("EnablePlugin() expected untrusted error")
	}
}

func TestEnableUnsignedLocalRequiresPolicy(t *testing.T) {
	host, _, _ := newTestHost(t, false, true)
	installed, err := InstallPackageBytes(context.Background(), host, buildFixturePackage(t), registry.TrustUnsignedLocal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err == nil {
		t.Fatal("EnablePlugin() expected policy error")
	}
	record, err := host.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s", record.EnableState)
	}
}

func TestSurfaceBridgeLifecycle(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := InstallPackageBytes(context.Background(), host, buildFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatal(err)
	}

	bootstrap, err := host.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.activity",
		SurfaceInstanceID:    "surface_lifecycle",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if bootstrap.AssetTicket == "" || bootstrap.BridgeNonce == "" {
		t.Fatalf("bootstrap missing ticket/nonce: %#v", bootstrap)
	}

	if _, err := host.ExchangeAssetTicket(context.Background(), ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("ExchangeAssetTicket() error = %v", err)
	}

	gateway, err := host.MintBridgeToken(context.Background(), MintBridgeTokenRequest{
		Handshake: bridge.Handshake{
			PluginID:          bootstrap.PluginID,
			SurfaceID:         bootstrap.SurfaceID,
			SurfaceInstanceID: bootstrap.SurfaceInstanceID,
			ActiveFingerprint: bootstrap.ActiveFingerprint,
			BridgeNonce:       bootstrap.BridgeNonce,
			UIProtocolVersion: "plugin-ui-v1",
		},
		BridgeChannelID: "bridge_channel",
		Now:             now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}
	if gateway.GatewayToken == "" {
		t.Fatalf("gateway token is empty: %#v", gateway)
	}
}

func TestReadSurfaceAssetRequiresAssetSession(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := InstallPackageBytes(context.Background(), h, buildFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.activity",
		SurfaceInstanceID:    "surface_asset",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession: "not-a-session",
		AssetPath:    "ui/index.html",
		Now:          now.Add(2 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenInvalid) {
		t.Fatalf("ReadSurfaceAsset() error = %v, want ErrTokenInvalid", err)
	}
	session, err := h.ExchangeAssetTicket(context.Background(), ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession: session.AssetSession,
		AssetPath:    "ui/index.html",
		Now:          now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("ReadSurfaceAsset() error = %v", err)
	}
	if string(asset.Content) != "<!doctype html><title>Plugin</title>" || asset.Session.SurfaceInstanceID != bootstrap.SurfaceInstanceID {
		t.Fatalf("asset mismatch: session=%#v entry=%#v content=%q", asset.Session, asset.Entry, string(asset.Content))
	}
}

func TestOpenSurfaceRequiresEnabledPlugin(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	installed, err := InstallPackageBytes(context.Background(), host, buildFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SurfaceID:        "lifecycle.activity",
	}); err == nil {
		t.Fatal("OpenSurface() expected disabled plugin error")
	}
}

func TestCallPluginMethodDispatchesCapability(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
		Params:               map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.Data == nil {
		t.Fatalf("CallPluginMethod() result missing data: %#v", result)
	}
	if capabilityAdapter.last.CapabilityID != "example.capability.echo" ||
		capabilityAdapter.last.BindingID != "echo" ||
		capabilityAdapter.last.Method != "echo.ping" ||
		capabilityAdapter.last.TargetMethod != "echo.ping" ||
		capabilityAdapter.last.PluginInstanceID != installed.PluginInstanceID ||
		capabilityAdapter.last.BridgeChannelID != "bridge_rpc" {
		t.Fatalf("capability invocation mismatch: %#v", capabilityAdapter.last)
	}
	if !audits.hasEvent("plugin.method.called") {
		t.Fatalf("missing method audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodRegistersOperation(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{OperationID: "op_pull_1"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "images.pull",
		Params:               map[string]any{"image": "alpine:latest"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.OperationID != "op_pull_1" {
		t.Fatalf("operation id mismatch: %#v", result)
	}
	registered, err := h.GetOperation(context.Background(), "op_pull_1")
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if registered.PluginInstanceID != installed.PluginInstanceID ||
		registered.Method != "images.pull" ||
		registered.Effect != "execute" ||
		registered.Execution != string(manifest.MethodExecutionOperation) ||
		registered.DisableBehavior != operation.DisableBehaviorCancel ||
		registered.UninstallBehavior != operation.UninstallBehaviorCancelThenBlockDelete {
		t.Fatalf("registered operation mismatch: %#v", registered)
	}
	if !audits.hasEvent("plugin.operation.started") {
		t.Fatalf("missing operation audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodRegistersStream(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{StreamID: "stream_logs_1"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "logs.tail",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.StreamID != "stream_logs_1" {
		t.Fatalf("CallPluginMethod() stream result mismatch: %#v", result)
	}
	if _, err := h.AppendStreamEvent(context.Background(), AppendStreamEventRequest{
		StreamID: "stream_logs_1",
		Data:     []byte("line 1"),
	}); err != nil {
		t.Fatalf("AppendStreamEvent() error = %v", err)
	}
	streamResult, err := h.ReadStream(context.Background(), ReadStreamRequest{StreamID: "stream_logs_1"})
	if err != nil {
		t.Fatalf("ReadStream() error = %v", err)
	}
	if streamResult.Record.Method != "logs.tail" || len(streamResult.Events) != 1 || string(streamResult.Events[0].Data) != "line 1" {
		t.Fatalf("stream read mismatch: %#v", streamResult)
	}
	if !audits.hasEvent("plugin.stream.started") {
		t.Fatalf("missing stream audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodDispatchesWorkerRoute(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", Ready: true},
		result: capability.Result{Data: map[string]any{"from_worker": true}},
	}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeSupervisor:  runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params:               map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() worker error = %v", err)
	}
	if result.Data == nil || runtime.calls != 1 {
		t.Fatalf("worker result/calls mismatch: result=%#v calls=%d", result, runtime.calls)
	}
	if runtime.lastLease.LeaseToken == "" ||
		runtime.lastLease.RuntimeGenerationID != "runtime_gen_1" ||
		runtime.lastLease.PolicyRevision != installed.PolicyRevision ||
		runtime.lastMethod != "worker.echo" {
		t.Fatalf("runtime lease/method mismatch: lease=%#v method=%s", runtime.lastLease, runtime.lastMethod)
	}
	var payload WorkerInvocationPayload
	if err := json.Unmarshal(runtime.lastPayload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.WorkerID != "echo_worker" ||
		payload.Export != "redeven_worker_invoke" ||
		payload.Artifact != "workers/echo.wasm" ||
		payload.Params["message"] != "hello" ||
		payload.PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("worker payload mismatch: %#v", payload)
	}
	if !audits.hasEvent("plugin.method.called") {
		t.Fatalf("missing method audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodWorkerRouteRequiresRuntimeSupervisor(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.activity")

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected runtime supervisor error")
	}
}

func TestCallPluginMethodValidatesExecutionResultContract(t *testing.T) {
	cases := []struct {
		name         string
		packageBytes []byte
		method       string
		result       capability.Result
	}{
		{
			name:         "operation requires operation id",
			packageBytes: buildOperationRPCFixturePackage(t),
			method:       "images.pull",
			result:       capability.Result{Data: map[string]any{"started": true}},
		},
		{
			name:         "sync rejects async handle",
			packageBytes: buildRPCFixturePackage(t),
			method:       "echo.ping",
			result:       capability.Result{OperationID: "op_unexpected"},
		},
		{
			name:         "subscription requires stream or operation id",
			packageBytes: buildSubscriptionRPCFixturePackage(t),
			method:       "logs.tail",
			result:       capability.Result{Data: map[string]any{"started": true}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capabilityAdapter := &recordingCapabilityAdapter{result: tc.result}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode:     true,
				localGenerated:    true,
				capabilityID:      "example.capability.echo",
				capabilityAdapter: capabilityAdapter,
			})
			installed, gateway := installEnableAndMintGateway(t, h, tc.packageBytes, surfaceIDForMethod(tc.method))
			if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
				PluginInstanceID:     installed.PluginInstanceID,
				SurfaceInstanceID:    "surface_rpc",
				SessionChannelIDHash: "channel_hash",
				OwnerSessionHash:     "session_hash",
				OwnerUserHash:        "user_hash",
				BridgeChannelID:      "bridge_rpc",
				GatewayToken:         gateway.GatewayToken,
				Method:               tc.method,
			}); err == nil {
				t.Fatal("CallPluginMethod() expected execution contract error")
			}
		})
	}
}

func TestCancelOperationRequestsCancel(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{OperationID: "op_cancel_1"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.activity")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "images.pull",
	}); err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}

	canceled, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: "op_cancel_1", Reason: "user"})
	if err != nil {
		t.Fatalf("CancelOperation() error = %v", err)
	}
	if canceled.Status != operation.StatusCancelRequested || canceled.Reason != "user" {
		t.Fatalf("cancel operation mismatch: %#v", canceled)
	}
	if !audits.hasEvent("plugin.operation.cancel_requested") {
		t.Fatalf("missing cancel audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodRejectsInvalidGatewayToken(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "unreachable"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, _ := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         "plugin_gateway_token.invalid",
		Method:               "echo.ping",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected token error")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestCallPluginMethodHonorsLocalPolicyDeny(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "unreachable"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		policyDecision:    PolicyDeny,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected local policy deny")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestCallPluginMethodRequiresConfirmationForDangerousMethod(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db"},
	}

	result, err := h.CallPluginMethod(context.Background(), call)
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrConfirmationRequired", err)
	}
	if !result.ConfirmationRequired || result.RequestHash == "" {
		t.Fatalf("confirmation response mismatch: %#v", result)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}

	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	if confirmation.ConfirmationToken == "" || confirmation.RequestHash != result.RequestHash {
		t.Fatalf("confirmation result mismatch: %#v vs request hash %q", confirmation, result.RequestHash)
	}
	if !audits.hasEvent("plugin.confirmation.issued") {
		t.Fatalf("missing confirmation audit event: %#v", audits.events)
	}

	call.ConfirmationToken = confirmation.ConfirmationToken
	confirmed, err := h.CallPluginMethod(context.Background(), call)
	if err != nil {
		t.Fatalf("CallPluginMethod() with confirmation error = %v", err)
	}
	if confirmed.Data == nil || capabilityAdapter.calls != 1 {
		t.Fatalf("confirmed call mismatch: result=%#v calls=%d", confirmed, capabilityAdapter.calls)
	}
}

func TestConfirmationTokenCannotBeReusedForDifferentParams(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.Params = map[string]any{"target": "other"}
	call.ConfirmationToken = confirmation.ConfirmationToken
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() expected confirmation audience error")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestConfirmationTokenBindsFullParamsBeyondManifestHashFieldHints(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db", "ui_note": "original"},
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.Params = map[string]any{"target": "db", "ui_note": "changed"}
	call.ConfirmationToken = confirmation.ConfirmationToken
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() expected confirmation token to bind full params")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestEnableEnsuresManifestStorageNamespaces(t *testing.T) {
	storageBroker := storage.NewMemoryBroker()
	host, _, _ := newTestHostWithStorage(t, true, true, storageBroker)
	installed, err := InstallPackageBytes(context.Background(), host, buildStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	namespaces, err := storageBroker.ListNamespaces(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 2 {
		t.Fatalf("namespace count = %d, want 2: %#v", len(namespaces), namespaces)
	}
	if namespaces[0].StoreID != "cache" || namespaces[0].Kind != storage.StoreKV || namespaces[0].Scope != "user" {
		t.Fatalf("first namespace mismatch: %#v", namespaces[0])
	}
	if namespaces[1].StoreID != "db" || namespaces[1].Kind != storage.StoreSQLite || namespaces[1].Scope != "environment" {
		t.Fatalf("second namespace mismatch: %#v", namespaces[1])
	}
}

func TestEnableInstallsConnectivityPolicyAndMintsGrant(t *testing.T) {
	connectivityBroker := connectivity.NewMemoryBroker()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storage.NewMemoryBroker(),
		connectivityBroker: connectivityBroker,
	})
	installed, err := InstallPackageBytes(context.Background(), h, buildNetworkFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if !audits.hasEvent("plugin.connectivity.policy_installed") {
		t.Fatalf("missing connectivity policy audit event: %#v", audits.events)
	}
	grant, err := h.MintConnectionGrant(context.Background(), MintConnectionGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		ConnectorID:         "mysql",
		Transport:           connectivity.TransportTCP,
		Destination:         "db.example.com:3306",
		RuntimeGenerationID: "runtime_gen_1",
		TTL:                 time.Minute,
	})
	if err != nil {
		t.Fatalf("MintConnectionGrant() error = %v", err)
	}
	if grant.GrantID == "" || grant.PluginInstanceID != installed.PluginInstanceID || grant.Destination.Port != 3306 {
		t.Fatalf("grant mismatch: %#v", grant)
	}
	if !audits.hasEvent("plugin.connectivity.grant_minted") {
		t.Fatalf("missing connectivity grant audit event: %#v", audits.events)
	}

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test"}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(context.Background(), connectivity.GrantRequest{
		PluginInstanceID:   installed.PluginInstanceID,
		ActiveFingerprint:  installed.ActiveFingerprint,
		PolicyRevision:     installed.PolicyRevision,
		ManagementRevision: installed.ManagementRevision,
		RevokeEpoch:        installed.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant() after disable error = %v, want ErrConnectorDenied", err)
	}
}

func TestEnableRejectsBlockedNetworkTargetBeforeStorageSideEffects(t *testing.T) {
	ctx := context.Background()
	storageBroker := storage.NewMemoryBroker()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storageBroker,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, err := InstallPackageBytes(ctx, h, buildBlockedNetworkFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); !errors.Is(err, connectivity.ErrTargetDenied) {
		t.Fatalf("EnablePlugin() error = %v, want ErrTargetDenied", err)
	}
	namespaces, err := storageBroker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("storage namespaces created despite blocked network target: %#v", namespaces)
	}
}

func TestUninstallRetainsOrDeletesStorageNamespaces(t *testing.T) {
	ctx := context.Background()
	retainBroker := storage.NewMemoryBroker()
	retainHost, _, _ := newTestHostWithStorage(t, true, true, retainBroker)
	retainedPlugin, err := InstallPackageBytes(ctx, retainHost, buildStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retainHost.EnablePlugin(ctx, EnableRequest{PluginInstanceID: retainedPlugin.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := retainHost.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: retainedPlugin.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatalf("UninstallPlugin(retain) error = %v", err)
	}
	retained, err := retainBroker.ListNamespaces(ctx, retainedPlugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 2 || retained[0].State != storage.NamespaceRetained || retained[1].State != storage.NamespaceRetained {
		t.Fatalf("retained namespaces mismatch: %#v", retained)
	}

	deleteBroker := storage.NewMemoryBroker()
	deleteHost, _, _ := newTestHostWithStorage(t, true, true, deleteBroker)
	deletedPlugin, err := InstallPackageBytes(ctx, deleteHost, buildStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deleteHost.EnablePlugin(ctx, EnableRequest{PluginInstanceID: deletedPlugin.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := deleteHost.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: deletedPlugin.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin(delete) error = %v", err)
	}
	deleted, err := deleteBroker.ListNamespaces(ctx, deletedPlugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted namespaces still present: %#v", deleted)
	}
}

func TestDisableTransitionsOperations(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed, err := InstallPackageBytes(context.Background(), h, buildFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	cancelOp, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{
		OperationID:      "op_disable_cancel",
		PluginID:         installed.PluginID,
		PluginInstanceID: installed.PluginInstanceID,
		Method:           "images.pull",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitOp, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{
		OperationID:      "op_disable_wait",
		PluginID:         installed.PluginID,
		PluginInstanceID: installed.PluginInstanceID,
		Method:           "sync.wait",
		DisableBehavior:  operation.DisableBehaviorWait,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy"}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	assertHostOperationStatus(t, h, cancelOp.OperationID, operation.StatusCancelRequested)
	assertHostOperationStatus(t, h, waitOp.OperationID, operation.StatusRunning)
}

func TestUninstallDeleteDataBlockedByRunningOperation(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, audits := newTestHostWithStorage(t, true, true, broker)
	installed, err := InstallPackageBytes(ctx, h, buildStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:      "op_blocks_delete",
		PluginID:         installed.PluginID,
		PluginInstanceID: installed.PluginInstanceID,
		Method:           "images.pull",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() error = %v, want ErrDeleteBlocked", err)
	}
	assertHostOperationStatus(t, h, "op_blocks_delete", operation.StatusCancelRequested)
	namespaces, err := broker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) == 0 {
		t.Fatal("storage namespaces were deleted despite blocked operation")
	}
	if !audits.hasEvent("plugin.operations.delete_blocked") {
		t.Fatalf("missing blocked audit event: %#v", audits.events)
	}
}

func TestUninstallDeleteDataSucceedsAfterOperationCancelAck(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, _ := newTestHostWithStorage(t, true, true, broker)
	installed, err := InstallPackageBytes(ctx, h, buildStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:      "op_cancel_then_delete",
		PluginID:         installed.PluginID,
		PluginInstanceID: installed.PluginInstanceID,
		Method:           "images.pull",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() first error = %v, want ErrDeleteBlocked", err)
	}
	if _, err := h.FinishOperation(ctx, FinishOperationRequest{
		OperationID: "op_cancel_then_delete",
		Status:      operation.StatusCanceled,
		Reason:      "runtime ack",
	}); err != nil {
		t.Fatalf("FinishOperation() error = %v", err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin() retry error = %v", err)
	}
	namespaces, err := broker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("storage namespaces still present: %#v", namespaces)
	}
}

func TestUninstallForceCleanupOperationAllowsDeleteData(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, _ := newTestHostWithStorage(t, true, true, broker)
	installed, err := InstallPackageBytes(ctx, h, buildStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:       "op_force_cleanup",
		PluginID:          installed.PluginID,
		PluginInstanceID:  installed.PluginInstanceID,
		Method:            "cleanup.force",
		UninstallBehavior: operation.UninstallBehaviorForceCleanupAllowed,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	assertHostOperationStatus(t, h, "op_force_cleanup", operation.StatusOrphanedAfterUninstall)
	namespaces, err := broker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("storage namespaces still present: %#v", namespaces)
	}
}

func TestExportImportPluginData(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, audits := newTestHostWithStorage(t, true, true, broker)
	source, err := InstallPackageBytes(ctx, h, buildStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if err := broker.SetUsage(ctx, source.PluginInstanceID, "db", 2048); err != nil {
		t.Fatal(err)
	}

	exported, err := h.ExportPluginData(ctx, ExportDataRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatalf("ExportPluginData() error = %v", err)
	}
	if err := broker.SetUsage(ctx, source.PluginInstanceID, "db", 0); err != nil {
		t.Fatal(err)
	}
	if err := h.ImportPluginData(ctx, ImportDataRequest{
		PluginInstanceID: source.PluginInstanceID,
		ArchiveRef:       exported.ArchiveRef,
		DeleteExisting:   true,
	}); err != nil {
		t.Fatalf("ImportPluginData() error = %v", err)
	}
	usage, err := broker.Usage(ctx, source.PluginInstanceID, "db")
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageBytes != 2048 {
		t.Fatalf("imported usage = %d, want 2048", usage.UsageBytes)
	}
	if !audits.hasEvent("plugin.data.exported") || !audits.hasEvent("plugin.data.imported") {
		t.Fatalf("missing data audit events: %#v", audits.events)
	}
}

func TestImportPluginDataRequiresStorageDeclaration(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, _ := newTestHostWithStorage(t, true, true, broker)
	source, err := InstallPackageBytes(ctx, h, buildStorageFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	exported, err := h.ExportPluginData(ctx, ExportDataRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}

	target, err := InstallPackageBytes(ctx, h, buildFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.ImportPluginData(ctx, ImportDataRequest{
		PluginInstanceID: target.PluginInstanceID,
		ArchiveRef:       exported.ArchiveRef,
		DeleteExisting:   true,
	}); err == nil {
		t.Fatal("ImportPluginData() expected storage declaration error")
	}
}

func TestSecretLifecycleUsesAdapter(t *testing.T) {
	secrets := &recordingSecretStore{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		secrets:        secrets,
	})
	installed, err := InstallPackageBytes(context.Background(), h, buildFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	req := SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        " api_token ",
		Scope:            "user",
	}
	if err := h.BindSecretRef(context.Background(), req); err != nil {
		t.Fatalf("BindSecretRef() error = %v", err)
	}
	if err := h.TestSecretRef(context.Background(), SecretTestRequest(req)); err != nil {
		t.Fatalf("TestSecretRef() error = %v", err)
	}
	if err := h.DeleteSecretRef(context.Background(), SecretDeleteRequest(req)); err != nil {
		t.Fatalf("DeleteSecretRef() error = %v", err)
	}
	if secrets.bind.PluginInstanceID != installed.PluginInstanceID || secrets.bind.SecretRef != "api_token" || secrets.bind.Scope != "user" {
		t.Fatalf("bind request was not normalized: %#v", secrets.bind)
	}
	if secrets.test.SecretRef != "api_token" || secrets.delete.SecretRef != "api_token" {
		t.Fatalf("secret calls mismatch: test=%#v delete=%#v", secrets.test, secrets.delete)
	}
	if !audits.hasEvent("plugin.secret.bound") || !audits.hasEvent("plugin.secret.tested") || !audits.hasEvent("plugin.secret.deleted") {
		t.Fatalf("missing secret audit events: %#v", audits.events)
	}
}

func TestSecretLifecycleValidatesRequestAndAdapter(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed, err := InstallPackageBytes(context.Background(), h, buildFixturePackage(t), registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	withSecrets, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		secrets:        &recordingSecretStore{},
	})
	if err := withSecrets.BindSecretRef(context.Background(), SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        "token",
		Scope:            "global",
	}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("BindSecretRef() error = %v, want ErrInvalidSecretRef", err)
	}

	if err := h.BindSecretRef(context.Background(), SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        "token",
		Scope:            "user",
	}); !errors.Is(err, ErrSecretStoreRequired) {
		t.Fatalf("BindSecretRef() error = %v, want ErrSecretStoreRequired", err)
	}
}

func TestReportCSPViolationAppendsDiagnostic(t *testing.T) {
	diagnostics := &diagnosticSink{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		diagnostics:    diagnostics,
	})
	err := h.ReportCSPViolation(context.Background(), CSPViolationReport{
		PluginID:           "com.example.plugin",
		PluginInstanceID:   "plugin_instance",
		SurfaceID:          "activity",
		SurfaceInstanceID:  "surface_instance",
		ActiveFingerprint:  "sha256:fingerprint",
		BlockedURI:         "inline",
		EffectiveDirective: "script-src",
		LineNumber:         12,
	})
	if err != nil {
		t.Fatalf("ReportCSPViolation() error = %v", err)
	}
	if len(diagnostics.events) != 1 {
		t.Fatalf("diagnostic events = %#v", diagnostics.events)
	}
	event := diagnostics.events[0]
	if event.Type != "plugin.csp.violation" || event.Severity != "warning" || event.Message != "script-src" || event.PluginInstanceID != "plugin_instance" || event.Details["blocked_uri"] != "inline" {
		t.Fatalf("diagnostic event mismatch: %#v", event)
	}
}

func newTestHost(t *testing.T, developerMode bool, localGenerated bool) (*Host, *surfaceSink, *auditSink) {
	return newTestHostWithOptions(t, testHostOptions{developerMode: developerMode, localGenerated: localGenerated})
}

func newTestHostWithStorage(t *testing.T, developerMode bool, localGenerated bool, storageBroker storage.Broker) (*Host, *surfaceSink, *auditSink) {
	return newTestHostWithOptions(t, testHostOptions{developerMode: developerMode, localGenerated: localGenerated, storageBroker: storageBroker})
}

type testHostOptions struct {
	developerMode      bool
	localGenerated     bool
	policyDecision     PolicyDecision
	storageBroker      storage.Broker
	connectivityBroker connectivity.Broker
	runtimeSupervisor  runtimeclient.Supervisor
	secrets            SecretStoreAdapter
	diagnostics        DiagnosticsSink
	capabilityID       string
	capabilityAdapter  capability.Adapter
}

func newTestHostWithOptions(t *testing.T, opts testHostOptions) (*Host, *surfaceSink, *auditSink) {
	t.Helper()
	surfaces := &surfaceSink{}
	audits := &auditSink{}
	capabilities := capability.NewRegistry()
	if opts.capabilityID != "" && opts.capabilityAdapter != nil {
		capabilities.Register(opts.capabilityID, opts.capabilityAdapter)
	}
	decision := opts.policyDecision
	if decision == "" {
		decision = PolicyAllow
	}
	host, err := New(Adapters{
		SessionResolver: fakeSessionResolver{},
		Policy: policyAdapter{
			developerMode:  opts.developerMode,
			localGenerated: opts.localGenerated,
			decision:       decision,
		},
		SurfaceCatalog:    surfaces,
		Audit:             audits,
		Diagnostics:       opts.diagnostics,
		Storage:           opts.storageBroker,
		Connectivity:      opts.connectivityBroker,
		RuntimeSupervisor: opts.runtimeSupervisor,
		Secrets:           opts.secrets,
		Capabilities:      capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	return host, surfaces, audits
}

func buildFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), fixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Plugin</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildVersionedLifecyclePackage(t *testing.T, version string, title string) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), lifecycleManifestJSON(version, title))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>"+title+"</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildStorageFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), storageFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Storage</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	return buildVersionedRPCPackage(t, "1.0.0", "RPC")
}

func buildVersionedRPCPackage(t *testing.T, version string, title string) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), rpcFixtureManifestJSON(version, title))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>"+title+"</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildDangerousRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), dangerousRPCFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Danger</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildOperationRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), operationRPCFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Operation</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildSubscriptionRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), subscriptionRPCFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Subscription</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker</title>")
	writeFile(t, filepath.Join(dir, "workers", "echo.wasm"), "wasm-placeholder")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildNetworkFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), networkFixtureManifestJSON(false))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Network</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildBlockedNetworkFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), networkFixtureManifestJSON(true))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Network</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeFile(t *testing.T, filename string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixtureManifestJSON() string {
	return lifecycleManifestJSON("1.0.0", "Lifecycle")
}

func lifecycleManifestJSON(version string, title string) string {
	if title == "" {
		title = "Lifecycle"
	}
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.lifecycle",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "lifecycle.activity", "kind": "activity", "label": "Lifecycle", "entry": "ui/index.html"}
		]
	}`
}

func storageFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.storage",
			"display_name": "Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "storage.activity", "kind": "activity", "label": "Storage", "entry": "ui/index.html"}
		],
		"storage": {
			"stores": [
				{
					"store_id": "cache",
					"kind": "kv",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": 1,
					"migration": {
						"from_version": 1,
						"to_version": 1,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				},
				{
					"store_id": "db",
					"kind": "sqlite",
					"scope": "environment",
					"quota_bytes": 8192,
					"schema_version": 2,
					"migration": {
						"from_version": 1,
						"to_version": 2,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				}
			]
		}
	}`
}

func rpcFixtureManifestJSON(version string, title string) string {
	if title == "" {
		title = "RPC"
	}
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.rpc",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "rpc.activity", "kind": "activity", "label": "RPC", "entry": "ui/index.html", "method": "echo.ping"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["read"]}
		],
		"methods": [
			{
				"method": "echo.ping",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "echo.ping"}
			}
		]
	}`
}

func dangerousRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.danger",
			"display_name": "Danger",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "danger.activity", "kind": "activity", "label": "Danger", "entry": "ui/index.html", "method": "danger.run"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["execute"]}
		],
		"methods": [
			{
				"method": "danger.run",
				"effect": "execute",
				"execution": "sync",
				"dangerous": true,
				"confirmation": {"mode": "required", "request_hash_fields": ["target"]},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "danger.run"}
			}
		]
	}`
}

func operationRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.operation",
			"display_name": "Operation",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "operation.activity", "kind": "activity", "label": "Operation", "entry": "ui/index.html", "method": "images.pull"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["execute"]}
		],
		"methods": [
			{
				"method": "images.pull",
				"effect": "execute",
				"execution": "operation",
				"cancel_policy": {
					"cancelable": true,
					"disable_behavior": "cancel",
					"uninstall_behavior": "cancel_then_block_delete",
					"ack_timeout_ms": 2000
				},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "images.pull"}
			}
		]
	}`
}

func subscriptionRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.subscription",
			"display_name": "Subscription",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "subscription.activity", "kind": "activity", "label": "Subscription", "entry": "ui/index.html", "method": "logs.tail"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["read"]}
		],
		"methods": [
			{
				"method": "logs.tail",
				"effect": "read",
				"execution": "subscription",
				"cancel_policy": {
					"cancelable": true,
					"disable_behavior": "orphan",
					"uninstall_behavior": "force_cleanup_allowed",
					"ack_timeout_ms": 2000
				},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "logs.tail"}
			}
		]
	}`
}

func workerFixtureManifestJSON() string {
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker",
			"display_name": "Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "worker.activity", "kind": "activity", "label": "Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redeven-wasm-worker-v1",
				"mode": "job",
				"scope": "user",
				"memory_limit_bytes": 16777216,
				"idle_timeout_ms": 0
			}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redeven_worker_invoke"}
			}
		]
	}`
}

func networkFixtureManifestJSON(blocked bool) string {
	httpDestination := "https://api.example.com"
	if blocked {
		httpDestination = "http://localhost"
	}
	return `{
		"schema_version": "redeven.plugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.network",
			"display_name": "Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "network.activity", "kind": "activity", "label": "Network", "entry": "ui/index.html"}
		],
		"storage": {
			"stores": [
				{
					"store_id": "cache",
					"kind": "kv",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": 1,
					"migration": {
						"from_version": 1,
						"to_version": 1,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				}
			]
		},
		"network_access": {
			"connectors": [
				{"connector_id": "api", "transport": "http", "scope": "user", "destinations": [` + strconv.Quote(httpDestination) + `]},
				{"connector_id": "stream", "transport": "websocket", "scope": "user", "destinations": ["wss://stream.example.com"]},
				{"connector_id": "mysql", "transport": "tcp", "scope": "environment", "destinations": ["db.example.com:3306"]},
				{"connector_id": "metrics", "transport": "udp", "scope": "environment", "destinations": ["metrics.example.com:8125"]}
			]
		}
	}`
}

func installEnableAndMintGateway(t *testing.T, h *Host, packageBytes []byte, surfaceID string) (registry.PluginRecord, bridge.GatewayTokenResult) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	installed, err := InstallPackageBytes(ctx, h, packageBytes, registry.TrustVerified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            surfaceID,
		SurfaceInstanceID:    "surface_rpc",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ExchangeAssetTicket(ctx, ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	gateway, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake: bridge.Handshake{
			PluginID:          bootstrap.PluginID,
			SurfaceID:         bootstrap.SurfaceID,
			SurfaceInstanceID: bootstrap.SurfaceInstanceID,
			ActiveFingerprint: bootstrap.ActiveFingerprint,
			BridgeNonce:       bootstrap.BridgeNonce,
			UIProtocolVersion: "plugin-ui-v1",
		},
		BridgeChannelID: "bridge_rpc",
		Now:             now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return installed, gateway
}

type fakeSessionResolver struct{}

func (fakeSessionResolver) ResolveSession(context.Context, string) (sessionctx.Context, error) {
	return sessionctx.Context{}, nil
}

type policyAdapter struct {
	developerMode  bool
	localGenerated bool
	decision       PolicyDecision
}

func (p policyAdapter) EvaluateLocalPolicy(context.Context, sessionctx.Context, PluginRef, manifest.MethodSpec) (PolicyDecision, error) {
	if p.decision == "" {
		return PolicyAllow, nil
	}
	return p.decision, nil
}

func (p policyAdapter) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return p.developerMode, nil
}

func (p policyAdapter) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return p.localGenerated, nil
}

type surfaceSink struct {
	snapshots []SurfaceSnapshot
}

func (s *surfaceSink) PublishSurfaces(_ context.Context, snapshot SurfaceSnapshot) error {
	s.snapshots = append(s.snapshots, snapshot)
	return nil
}

type auditSink struct {
	events []AuditEvent
}

func (s *auditSink) AppendPluginAudit(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func (s *auditSink) hasEvent(eventType string) bool {
	for _, event := range s.events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

type diagnosticSink struct {
	events []DiagnosticEvent
}

func (s *diagnosticSink) AppendPluginDiagnostic(_ context.Context, event DiagnosticEvent) error {
	s.events = append(s.events, event)
	return nil
}

type recordingCapabilityAdapter struct {
	calls  int
	last   capability.Invocation
	result capability.Result
	err    error
}

type recordingSecretStore struct {
	bind   SecretBindRequest
	test   SecretTestRequest
	delete SecretDeleteRequest
}

type recordingRuntimeSupervisor struct {
	calls       int
	health      runtimeclient.Health
	result      capability.Result
	err         error
	lastLease   runtimeclient.Lease
	lastMethod  string
	lastPayload []byte
}

func surfaceIDForMethod(method string) string {
	if method == "images.pull" {
		return "operation.activity"
	}
	if method == "logs.tail" {
		return "subscription.activity"
	}
	return "rpc.activity"
}

func assertHostOperationStatus(t *testing.T, h *Host, operationID string, want operation.Status) {
	t.Helper()
	record, err := h.GetOperation(context.Background(), operationID)
	if err != nil {
		t.Fatalf("GetOperation(%s) error = %v", operationID, err)
	}
	if record.Status != want {
		t.Fatalf("operation %s status = %s, want %s: %#v", operationID, record.Status, want, record)
	}
}

func (a *recordingCapabilityAdapter) InvokeCapability(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.calls++
	a.last = req
	if a.err != nil {
		return capability.Result{}, a.err
	}
	return a.result, nil
}

func (s *recordingSecretStore) BindSecretRef(_ context.Context, req SecretBindRequest) error {
	s.bind = req
	return nil
}

func (s *recordingSecretStore) TestSecretRef(_ context.Context, req SecretTestRequest) error {
	s.test = req
	return nil
}

func (s *recordingSecretStore) DeleteSecretRef(_ context.Context, req SecretDeleteRequest) error {
	s.delete = req
	return nil
}

func (r *recordingRuntimeSupervisor) Start(context.Context, runtimeclient.Target) error {
	return nil
}

func (r *recordingRuntimeSupervisor) Stop(context.Context) error {
	return nil
}

func (r *recordingRuntimeSupervisor) Health(context.Context) (runtimeclient.Health, error) {
	if r.health == (runtimeclient.Health{}) {
		r.health = runtimeclient.Health{RuntimeInstanceID: "runtime_test", RuntimeGenerationID: "runtime_gen_test", Ready: true}
	}
	return r.health, nil
}

func (r *recordingRuntimeSupervisor) InvokeWorker(_ context.Context, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
	r.calls++
	r.lastLease = lease
	r.lastMethod = method
	r.lastPayload = append([]byte(nil), payload...)
	if r.err != nil {
		return nil, r.err
	}
	return json.Marshal(r.result)
}

func (r *recordingRuntimeSupervisor) Revoke(context.Context, string, uint64) error {
	return nil
}
