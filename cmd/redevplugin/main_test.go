package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/trust"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestCLIKeygenSignAndValidatePackage(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "plugin")
	writeCLITestFile(t, filepath.Join(srcDir, "manifest.json"), `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.cli",
			"display_name": "CLI",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "cli.activity", "kind": "activity", "label": "CLI", "entry": "ui/index.html"}
		]
	}`)
	writeCLITestFile(t, filepath.Join(srcDir, "ui", "index.html"), "<!doctype html><title>CLI</title>")

	unsignedPackage := filepath.Join(dir, "unsigned.redevplugin")
	signedPackage := filepath.Join(dir, "signed.redevplugin")
	privateKeyFile := filepath.Join(dir, "private.json")
	publicKeyFile := filepath.Join(dir, "public.json")

	if _, err := captureCLIOutput(t, "package", srcDir, unsignedPackage); err != nil {
		t.Fatalf("package command error = %v", err)
	}
	if _, err := captureCLIOutput(t, "keygen", "test-key", privateKeyFile, publicKeyFile); err != nil {
		t.Fatalf("keygen command error = %v", err)
	}
	signOutput, err := captureCLIOutput(t, "sign", unsignedPackage, privateKeyFile, signedPackage)
	if err != nil {
		t.Fatalf("sign command error = %v", err)
	}
	var signSummary validateSummary
	if err := json.Unmarshal(signOutput, &signSummary); err != nil {
		t.Fatalf("sign output decode error = %v: %s", err, signOutput)
	}
	if !signSummary.Signed || signSummary.SignatureKey != "test-key" || signSummary.SignatureAlgo != trust.AlgorithmEd25519 {
		t.Fatalf("sign summary mismatch: %#v", signSummary)
	}

	validateOutput, err := captureCLIOutput(t, "validate", signedPackage)
	if err != nil {
		t.Fatalf("validate command error = %v", err)
	}
	var validateResult validateSummary
	if err := json.Unmarshal(validateOutput, &validateResult); err != nil {
		t.Fatalf("validate output decode error = %v: %s", err, validateOutput)
	}
	if !validateResult.Signed || validateResult.PackageHash != signSummary.PackageHash {
		t.Fatalf("validate summary mismatch: %#v sign=%#v", validateResult, signSummary)
	}

	signedPkg, err := pluginpkg.ReadFile(context.Background(), signedPackage, pluginpkg.DefaultReadOptions())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	publicKey := readCLITestPublicKey(t, publicKeyFile)
	verifier := trust.Ed25519Verifier{
		Keyring: trust.StaticKeyring{Keys: []trust.SigningKey{{
			Algorithm: trust.AlgorithmEd25519,
			KeyID:     "test-key",
			PublicKey: publicKey,
		}}},
		Now: func() time.Time {
			return time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
		},
	}
	if _, err := verifier.VerifyPackageTrust(context.Background(), host.PackageTrustVerificationRequest{
		Package:             signedPkg,
		RequestedTrustState: registry.TrustVerified,
	}); err != nil {
		t.Fatalf("VerifyPackageTrust() error = %v", err)
	}

	installOutput, err := captureCLIOutput(t, "install-verified", signedPackage, publicKeyFile)
	if err != nil {
		t.Fatalf("install-verified command error = %v", err)
	}
	var installSummary lifecycleSummary
	if err := json.Unmarshal(installOutput, &installSummary); err != nil {
		t.Fatalf("install-verified output decode error = %v: %s", err, installOutput)
	}
	if installSummary.TrustState != registry.TrustVerified || installSummary.EnableState != registry.EnableDisabled {
		t.Fatalf("install-verified summary mismatch: %#v", installSummary)
	}
}

func TestCLIScaffoldProducesPackageablePlugin(t *testing.T) {
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	output, err := captureCLIOutput(t, "scaffold", "com.example.generated", "Generated Plugin", scaffoldDir)
	if err != nil {
		t.Fatalf("scaffold command error = %v", err)
	}
	var summary scaffoldSummary
	if err := json.Unmarshal(output, &summary); err != nil {
		t.Fatalf("scaffold output decode error = %v: %s", err, output)
	}
	if summary.PluginID != "com.example.generated" || len(summary.Files) != 9 {
		t.Fatalf("scaffold summary mismatch: %#v", summary)
	}

	if _, err := captureCLIOutput(t, "validate", filepath.Join(scaffoldDir, "manifest.json")); err != nil {
		t.Fatalf("validate scaffold manifest error = %v", err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"workers"`,
		`"backend"`,
		`"broker_backend"`,
		`"worker.echo"`,
		`"worker.brokerDemo"`,
		`"storage"`,
		`"workspace"`,
		`"settings"`,
		`"kv"`,
		`"db"`,
		`"sqlite"`,
		`"network_access"`,
		`"api"`,
	} {
		if !bytes.Contains(manifestRaw, []byte(want)) {
			t.Fatalf("scaffold manifest missing %q: %s", want, manifestRaw)
		}
	}
	if !bytes.Contains(manifestRaw, []byte(`"workers"`)) || !bytes.Contains(manifestRaw, []byte(`"worker.echo"`)) {
		t.Fatalf("scaffold manifest missing worker contract: %s", manifestRaw)
	}
	indexRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "ui", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(indexRaw, []byte(`data-plugin-id="com.example.generated"`)) || !bytes.Contains(indexRaw, []byte(`data-surface-id="com.example.generated.activity"`)) {
		t.Fatalf("scaffold index missing plugin bootstrap data: %s", indexRaw)
	}
	if !bytes.Contains(indexRaw, []byte(`Storage + network`)) {
		t.Fatalf("scaffold index missing brokered backend control: %s", indexRaw)
	}
	appRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "ui", "assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"redevplugin.bridge.handshake", "redevplugin.bridge.call", "parent_origin", "worker.echo", "worker.brokerDemo", "invoke-broker", "storage_sqlite_handle_grant_token", "tokenLeakCheck"} {
		if !bytes.Contains(appRaw, []byte(want)) {
			t.Fatalf("scaffold app.js missing %q: %s", want, appRaw)
		}
	}
	wasmRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "workers", "backend.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(wasmRaw) < 8 || !bytes.Equal(wasmRaw[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		t.Fatalf("scaffold wasm artifact is invalid: %x", wasmRaw[:prefixLen(len(wasmRaw), 8)])
	}
	brokerWASMRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "workers", "broker.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(brokerWASMRaw) < 8 || !bytes.Equal(brokerWASMRaw[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		t.Fatalf("scaffold broker wasm artifact is invalid: %x", brokerWASMRaw[:prefixLen(len(brokerWASMRaw), 8)])
	}
	brokerWATRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "workers", "broker.wat"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"files"`, `"kv"`, `"sqlite"`, `"http_request"`, `(memory (export "memory") 1)`} {
		if !bytes.Contains(brokerWATRaw, []byte(want)) {
			t.Fatalf("scaffold broker wat missing %q: %s", want, brokerWATRaw)
		}
	}
	for _, legacy := range []string{"files_write_demo", "kv_put_demo", "sqlite_exec_demo", "http_request_demo"} {
		if bytes.Contains(brokerWATRaw, []byte(legacy)) || bytes.Contains(brokerWASMRaw, []byte(legacy)) {
			t.Fatalf("scaffold broker worker still references legacy hostcall %q", legacy)
		}
	}
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "package", scaffoldDir, packageFile); err != nil {
		t.Fatalf("package scaffold error = %v", err)
	}
	if _, err := captureCLIOutput(t, "install-local", packageFile); err != nil {
		t.Fatalf("install-local scaffold package error = %v", err)
	}

	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated", "Generated Plugin", scaffoldDir); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("scaffold non-empty dir error = %v, want not empty", err)
	}
}

func TestCLIScaffoldRunsGeneratedWorkerThroughBuiltRustRuntime(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping scaffold Rust runtime integration")
	}
	repoRoot := cliRepoRoot(t)
	build := exec.Command("cargo", "build", "-p", "redevplugin-runtime")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build -p redevplugin-runtime failed: %v\n%s", err, output)
	}
	runtimePath := filepath.Join(repoRoot, "target", "debug", "redevplugin-runtime")
	if goruntime.GOOS == "windows" {
		runtimePath += ".exe"
	}

	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated-runtime")
	packageFile := filepath.Join(dir, "generated-runtime.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.runtime", "Generated Runtime Plugin", scaffoldDir); err != nil {
		t.Fatalf("scaffold command error = %v", err)
	}
	if _, err := captureCLIOutput(t, "package", scaffoldDir, packageFile); err != nil {
		t.Fatalf("package command error = %v", err)
	}
	packageBytes, err := os.ReadFile(packageFile)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	storageBroker, err := storage.NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	connectivityBroker := connectivity.NewMemoryBroker()
	networkExecutor := &cliRecordingNetworkExecutor{
		httpStatus: http.StatusAccepted,
		httpBody:   []byte(`{"ok":true,"source":"cli-scaffold"}`),
		wsPayload:  []byte("websocket:generated websocket round trip"),
		tcpPayload: []byte("tcp:generated tcp round trip"),
		udpPayload: []byte("udp:generated udp round trip"),
	}
	h, err := host.New(host.Adapters{
		SessionResolver:         staticSessionResolver{},
		Policy:                  staticPolicyAdapter{},
		RuntimeArtifactResolver: cliRuntimeResolver{path: runtimePath},
		Storage:                 storageBroker,
		Connectivity:            connectivityBroker,
		NetworkExecutor:         networkExecutor,
	})
	if err != nil {
		t.Fatal(err)
	}
	health, err := h.StartRuntime(ctx, host.StartRuntimeRequest{
		Target: host.RuntimeTarget{OS: goruntime.GOOS, Arch: goruntime.GOARCH},
	})
	if err != nil {
		t.Fatalf("StartRuntime() error = %v", err)
	}
	if !health.Ready || health.RuntimeGenerationID == "" {
		t.Fatalf("runtime health mismatch: %#v", health)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := h.StopRuntime(stopCtx); err != nil {
			t.Errorf("StopRuntime() error = %v", err)
		}
	})

	installed, err := host.InstallPackageBytes(ctx, h, packageBytes, registry.TrustUnsignedLocal)
	if err != nil {
		t.Fatalf("InstallPackageBytes() error = %v", err)
	}
	now := time.Now().UTC()
	if _, err := h.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(ctx, host.OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "com.example.generated.runtime.activity",
		SurfaceInstanceID:    "surface_generated_runtime",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if _, err := h.ExchangeAssetTicket(ctx, host.ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("ExchangeAssetTicket() error = %v", err)
	}
	gateway, err := h.MintBridgeToken(ctx, host.MintBridgeTokenRequest{
		Handshake: bridge.Handshake{
			PluginID:          bootstrap.PluginID,
			SurfaceID:         bootstrap.SurfaceID,
			SurfaceInstanceID: bootstrap.SurfaceInstanceID,
			ActiveFingerprint: bootstrap.ActiveFingerprint,
			BridgeNonce:       bootstrap.BridgeNonce,
			UIProtocolVersion: "plugin-ui-v1",
		},
		BridgeChannelID: "bridge_generated_runtime",
		Now:             now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}

	result, err := h.CallPluginMethod(ctx, host.CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		SessionChannelIDHash: "session_channel_hash",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		BridgeChannelID:      "bridge_generated_runtime",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params:               map[string]any{"message": "hello from scaffold"},
		Now:                  now.Add(4 * time.Second),
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with generated scaffold error = %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("worker result data = %#v, want map", result.Data)
	}
	if data["backend"] != "executed wasm worker scaffold" ||
		data["transport"] != "rust runtime ipc" ||
		data["method"] != "worker.echo" ||
		data["worker_id"] != "backend" {
		t.Fatalf("generated scaffold runtime result mismatch: %#v", data)
	}

	storageGrant, err := h.MintStorageHandleGrant(ctx, host.MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "workspace",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		Now:                 now.Add(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant(workspace) error = %v", err)
	}
	kvGrant, err := h.MintStorageHandleGrant(ctx, host.MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "settings",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		Now:                 now.Add(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant(settings) error = %v", err)
	}
	sqliteGrant, err := h.MintStorageHandleGrant(ctx, host.MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "db",
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		Now:                 now.Add(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant(db) error = %v", err)
	}

	brokerResult, err := h.CallPluginMethod(ctx, host.CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		SessionChannelIDHash: "session_channel_hash",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		BridgeChannelID:      "bridge_generated_runtime",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.brokerDemo",
		Params: map[string]any{
			"storage_handle_grant_token":        storageGrant.HandleGrant.HandleGrantToken,
			"storage_kv_handle_grant_token":     kvGrant.HandleGrant.HandleGrantToken,
			"storage_sqlite_handle_grant_token": sqliteGrant.HandleGrant.HandleGrantToken,
		},
		Now: now.Add(6 * time.Second),
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() with generated broker worker error = %v", err)
	}
	brokerData, ok := brokerResult.Data.(map[string]any)
	if !ok {
		t.Fatalf("broker worker result data = %#v, want map", brokerResult.Data)
	}
	storageFile, ok := brokerData["storage_file"].(map[string]any)
	if !ok {
		t.Fatalf("broker storage_file result missing: %#v", brokerData)
	}
	storageFileUsage, ok := storageFile["usage"].(map[string]any)
	if !ok {
		t.Fatalf("broker storage_file usage missing: %#v", storageFile)
	}
	if storageFile["ok"] != true ||
		storageFile["path"] != "notes/generated-broker-demo.txt" ||
		storageFile["size_bytes"] != float64(31) ||
		storageFileUsage["store_id"] != "workspace" ||
		storageFileUsage["usage_bytes"] != float64(31) {
		t.Fatalf("broker storage_file result mismatch: %#v", storageFile)
	}
	storageKV, ok := brokerData["storage_kv"].(map[string]any)
	if !ok {
		t.Fatalf("broker storage_kv result missing: %#v", brokerData)
	}
	storageKVUsage, ok := storageKV["usage"].(map[string]any)
	if !ok {
		t.Fatalf("broker storage_kv usage missing: %#v", storageKV)
	}
	if storageKV["ok"] != true ||
		storageKV["key"] != "demo/last_broker_run" ||
		storageKV["size_bytes"] != float64(27) ||
		storageKVUsage["store_id"] != "settings" ||
		storageKVUsage["usage_bytes"] != float64(27) {
		t.Fatalf("broker storage_kv result mismatch: %#v", storageKV)
	}
	storageSQLite, ok := brokerData["storage_sqlite"].(map[string]any)
	if !ok {
		t.Fatalf("broker storage_sqlite result missing: %#v", brokerData)
	}
	storageSQLiteUsage, ok := storageSQLite["usage"].(map[string]any)
	if !ok {
		t.Fatalf("broker storage_sqlite usage missing: %#v", storageSQLite)
	}
	if storageSQLite["ok"] != true ||
		storageSQLite["database"] != "plugin.sqlite" ||
		storageSQLiteUsage["store_id"] != "db" {
		t.Fatalf("broker storage_sqlite result mismatch: %#v", storageSQLite)
	}
	networkExecute, ok := brokerData["network_execute"].(map[string]any)
	if !ok {
		t.Fatalf("broker network_execute result missing: %#v", brokerData)
	}
	if networkExecute["ok"] != true ||
		networkExecute["connector_id"] != "api" ||
		networkExecute["transport"] != "http" ||
		networkExecute["status_code"] != float64(http.StatusAccepted) {
		t.Fatalf("broker network_execute result mismatch: %#v", networkExecute)
	}
	if networkExecutor.httpCalls != 1 ||
		networkExecutor.lastHTTP.Grant.PluginInstanceID != installed.PluginInstanceID ||
		networkExecutor.lastHTTP.Grant.ConnectorID != "api" ||
		networkExecutor.lastHTTP.Grant.Destination.Host != "api.example.com" ||
		networkExecutor.lastHTTP.Method != http.MethodPost ||
		networkExecutor.lastHTTP.Path != "/v1/worker" ||
		string(networkExecutor.lastHTTP.Body) != "generated brokered http request" {
		t.Fatalf("broker network executor call mismatch: calls=%d req=%#v", networkExecutor.httpCalls, networkExecutor.lastHTTP)
	}
	if networkWebSocket, ok := brokerData["network_execute_websocket"].(map[string]any); !ok ||
		networkWebSocket["ok"] != true ||
		networkWebSocket["connector_id"] != "stream" ||
		networkWebSocket["transport"] != "websocket" ||
		networkWebSocket["message_type"] != "text" {
		t.Fatalf("broker websocket network result mismatch: %#v", brokerData["network_execute_websocket"])
	}
	if networkTCP, ok := brokerData["network_execute_tcp"].(map[string]any); !ok ||
		networkTCP["ok"] != true ||
		networkTCP["connector_id"] != "mysql" ||
		networkTCP["transport"] != "tcp" {
		t.Fatalf("broker tcp network result mismatch: %#v", brokerData["network_execute_tcp"])
	}
	if networkUDP, ok := brokerData["network_execute_udp"].(map[string]any); !ok ||
		networkUDP["ok"] != true ||
		networkUDP["connector_id"] != "metrics" ||
		networkUDP["transport"] != "udp" {
		t.Fatalf("broker udp network result mismatch: %#v", brokerData["network_execute_udp"])
	}
	if networkExecutor.wsCalls != 1 ||
		networkExecutor.lastWS.Grant.ConnectorID != "stream" ||
		string(networkExecutor.lastWS.Payload) != "generated websocket round trip" {
		t.Fatalf("broker websocket executor call mismatch: calls=%d req=%#v", networkExecutor.wsCalls, networkExecutor.lastWS)
	}
	if networkExecutor.tcpCalls != 1 ||
		networkExecutor.lastTCP.Grant.ConnectorID != "mysql" ||
		string(networkExecutor.lastTCP.Payload) != "generated tcp round trip" {
		t.Fatalf("broker tcp executor call mismatch: calls=%d req=%#v", networkExecutor.tcpCalls, networkExecutor.lastTCP)
	}
	if networkExecutor.udpCalls != 1 ||
		networkExecutor.lastUDP.Grant.ConnectorID != "metrics" ||
		string(networkExecutor.lastUDP.Payload) != "generated udp round trip" {
		t.Fatalf("broker udp executor call mismatch: calls=%d req=%#v", networkExecutor.udpCalls, networkExecutor.lastUDP)
	}
	rawBrokerData, err := json.Marshal(brokerData)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{gateway.GatewayToken, storageGrant.HandleGrant.HandleGrantToken, kvGrant.HandleGrant.HandleGrantToken, sqliteGrant.HandleGrant.HandleGrantToken} {
		if secret != "" && bytes.Contains(rawBrokerData, []byte(secret)) {
			t.Fatalf("broker result leaked token %q in %s", secret, rawBrokerData)
		}
	}
}

func TestCLIDevLifecyclePersistsGeneratedPluginState(t *testing.T) {
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.lifecycle", "Generated Lifecycle Plugin", scaffoldDir); err != nil {
		t.Fatalf("scaffold command error = %v", err)
	}
	addLifecycleStorageToManifest(t, filepath.Join(scaffoldDir, "manifest.json"))
	if _, err := captureCLIOutput(t, "package", scaffoldDir, packageFile); err != nil {
		t.Fatalf("package command error = %v", err)
	}

	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); !errors.Is(err, errDevStateNotInstalled) {
		t.Fatalf("dev-enable before install error = %v, want %v", err, errDevStateNotInstalled)
	}
	if _, err := captureCLIOutput(t, "dev-open", stateRoot, "com.example.generated.lifecycle.activity"); !errors.Is(err, errDevStateNotInstalled) {
		t.Fatalf("dev-open before install error = %v, want %v", err, errDevStateNotInstalled)
	}

	installOutput, err := captureCLIOutput(t, "dev-install", stateRoot, packageFile)
	if err != nil {
		t.Fatalf("dev-install error = %v", err)
	}
	var installSummary devLifecycleSummary
	if err := json.Unmarshal(installOutput, &installSummary); err != nil {
		t.Fatalf("dev-install output decode error = %v: %s", err, installOutput)
	}
	if installSummary.EnableState != registry.EnableDisabled || !installSummary.PackageRetained || installSummary.StateRoot != stateRoot {
		t.Fatalf("dev-install summary mismatch: %#v", installSummary)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, devPackageFile)); err != nil {
		t.Fatalf("dev package copy missing: %v", err)
	}

	if _, err := captureCLIOutput(t, "dev-open", stateRoot, "com.example.generated.lifecycle.activity"); err == nil || !strings.Contains(err.Error(), "must be enabled") {
		t.Fatalf("dev-open disabled error = %v, want must be enabled", err)
	}

	enableOutput, err := captureCLIOutput(t, "dev-enable", stateRoot)
	if err != nil {
		t.Fatalf("dev-enable error = %v", err)
	}
	var enableSummary devLifecycleSummary
	if err := json.Unmarshal(enableOutput, &enableSummary); err != nil {
		t.Fatalf("dev-enable output decode error = %v: %s", err, enableOutput)
	}
	if enableSummary.PluginInstanceID != installSummary.PluginInstanceID || enableSummary.EnableState != registry.EnableEnabled {
		t.Fatalf("dev-enable summary mismatch: %#v install=%#v", enableSummary, installSummary)
	}

	inspectOutput, err := captureCLIOutput(t, "inspect-storage", filepath.Join(stateRoot, devStorageDir), installSummary.PluginInstanceID)
	if err != nil {
		t.Fatalf("inspect-storage after enable error = %v", err)
	}
	var inspectSummary storageInspectSummary
	if err := json.Unmarshal(inspectOutput, &inspectSummary); err != nil {
		t.Fatalf("inspect-storage output decode error = %v: %s", err, inspectOutput)
	}
	if inspectSummary.NamespaceCount != 3 {
		t.Fatalf("storage namespace mismatch after enable: %#v", inspectSummary)
	}
	namespacesByStoreID := map[string]storage.NamespaceRecord{}
	for _, ns := range inspectSummary.Namespaces {
		namespacesByStoreID[ns.StoreID] = ns
	}
	if namespacesByStoreID["workspace"].State != storage.NamespaceActive || namespacesByStoreID["workspace"].Kind != storage.StoreFiles {
		t.Fatalf("workspace storage namespace mismatch after enable: %#v", inspectSummary)
	}
	if namespacesByStoreID["settings"].State != storage.NamespaceActive || namespacesByStoreID["settings"].Kind != storage.StoreKV {
		t.Fatalf("settings storage namespace mismatch after enable: %#v", inspectSummary)
	}
	if namespacesByStoreID["db"].State != storage.NamespaceActive || namespacesByStoreID["db"].Kind != storage.StoreSQLite {
		t.Fatalf("db storage namespace mismatch after enable: %#v", inspectSummary)
	}
	storageBroker, err := storage.NewFileBroker(filepath.Join(stateRoot, devStorageDir))
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	if _, err := storageBroker.WriteFile(context.Background(), storage.FileWriteRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		StoreID:          "workspace",
		Path:             "notes/generated.txt",
		Data:             []byte("generated plugin data"),
	}); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	openOutput, err := captureCLIOutput(t, "dev-open", stateRoot, "com.example.generated.lifecycle.activity", "http://127.0.0.1:4999")
	if err != nil {
		t.Fatalf("dev-open error = %v", err)
	}
	var openSummary devOpenSurfaceSummary
	if err := json.Unmarshal(openOutput, &openSummary); err != nil {
		t.Fatalf("dev-open output decode error = %v: %s", err, openOutput)
	}
	if !openSummary.OK ||
		openSummary.PluginInstanceID != installSummary.PluginInstanceID ||
		openSummary.SurfaceID != "com.example.generated.lifecycle.activity" ||
		openSummary.BridgeNonce == "" ||
		openSummary.AssetTicketID == "" ||
		openSummary.BrowserOriginCount != 1 {
		t.Fatalf("dev-open summary mismatch: %#v", openSummary)
	}

	disableOutput, err := captureCLIOutput(t, "dev-disable", stateRoot)
	if err != nil {
		t.Fatalf("dev-disable error = %v", err)
	}
	var disableSummary devLifecycleSummary
	if err := json.Unmarshal(disableOutput, &disableSummary); err != nil {
		t.Fatalf("dev-disable output decode error = %v: %s", err, disableOutput)
	}
	if disableSummary.EnableState != registry.EnableDisabled || disableSummary.BrowserOriginCount != 1 {
		t.Fatalf("dev-disable summary mismatch: %#v", disableSummary)
	}
	if _, err := captureCLIOutput(t, "dev-open", stateRoot, "com.example.generated.lifecycle.activity"); err == nil || !strings.Contains(err.Error(), "must be enabled") {
		t.Fatalf("dev-open after disable error = %v, want must be enabled", err)
	}

	uninstallOutput, err := captureCLIOutput(t, "dev-uninstall", stateRoot, "--delete-data")
	if err != nil {
		t.Fatalf("dev-uninstall error = %v", err)
	}
	var uninstallSummary devLifecycleSummary
	if err := json.Unmarshal(uninstallOutput, &uninstallSummary); err != nil {
		t.Fatalf("dev-uninstall output decode error = %v: %s", err, uninstallOutput)
	}
	if uninstallSummary.RetainedDataState != registry.RetainedDataDeleted ||
		uninstallSummary.PackageRetained ||
		uninstallSummary.BrowserOriginCount != 1 {
		t.Fatalf("dev-uninstall summary mismatch: %#v", uninstallSummary)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, devPackageFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dev package copy still exists after uninstall: %v", err)
	}
	afterDelete, err := storageBroker.ListNamespaces(context.Background(), installSummary.PluginInstanceID)
	if err != nil {
		t.Fatalf("ListNamespaces() after delete error = %v", err)
	}
	if len(afterDelete) != 0 {
		t.Fatalf("storage namespaces remained after delete: %#v", afterDelete)
	}

	statusOutput, err := captureCLIOutput(t, "dev-status", stateRoot)
	if err != nil {
		t.Fatalf("dev-status error = %v", err)
	}
	var statusSummary devLifecycleSummary
	if err := json.Unmarshal(statusOutput, &statusSummary); err != nil {
		t.Fatalf("dev-status output decode error = %v: %s", err, statusOutput)
	}
	if statusSummary.RetainedDataState != registry.RetainedDataDeleted || statusSummary.PackageRetained {
		t.Fatalf("dev-status summary mismatch: %#v", statusSummary)
	}
	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); !errors.Is(err, errDevStateNotInstalled) {
		t.Fatalf("dev-enable after uninstall error = %v, want %v", err, errDevStateNotInstalled)
	}
}

func TestCLIDevLifecyclePersistsPluginSettingsState(t *testing.T) {
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.settings", "Generated Settings Plugin", scaffoldDir); err != nil {
		t.Fatalf("scaffold command error = %v", err)
	}
	addLifecycleSettingsToManifest(t, filepath.Join(scaffoldDir, "manifest.json"))
	if _, err := captureCLIOutput(t, "package", scaffoldDir, packageFile); err != nil {
		t.Fatalf("package command error = %v", err)
	}
	installOutput, err := captureCLIOutput(t, "dev-install", stateRoot, packageFile)
	if err != nil {
		t.Fatalf("dev-install error = %v", err)
	}
	var installSummary devLifecycleSummary
	if err := json.Unmarshal(installOutput, &installSummary); err != nil {
		t.Fatalf("dev-install output decode error = %v: %s", err, installOutput)
	}
	if len(loadDevStateForTest(t, stateRoot).Settings.Records) != 0 {
		t.Fatal("dev-install should not create settings before enable")
	}

	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); err != nil {
		t.Fatalf("dev-enable error = %v", err)
	}
	state := loadDevStateForTest(t, stateRoot)
	record, ok := state.Settings.Records[installSummary.PluginInstanceID]
	if !ok || record.State != settings.StateActive {
		t.Fatalf("settings record missing after enable: %#v", state.Settings.Records)
	}
	if record.SettingsRevision != 1 || record.Values["accent_mode"] != "teal" || record.Values["sync_enabled"] != true {
		t.Fatalf("settings defaults mismatch after enable: %#v", record)
	}

	bindOutput, err := captureCLIOutput(t, "dev-secret-bind", stateRoot, " api_token ")
	if err != nil {
		t.Fatalf("dev-secret-bind error = %v", err)
	}
	var bindSummary devSecretSummary
	if err := json.Unmarshal(bindOutput, &bindSummary); err != nil {
		t.Fatalf("dev-secret-bind output decode error = %v: %s", err, bindOutput)
	}
	if !bindSummary.OK ||
		bindSummary.PluginInstanceID != installSummary.PluginInstanceID ||
		bindSummary.SecretRef != "api_token" ||
		bindSummary.Scope != "user" ||
		!bindSummary.Bound {
		t.Fatalf("dev-secret-bind summary mismatch: %#v", bindSummary)
	}
	boundState := loadDevStateForTest(t, stateRoot)
	boundSecret := boundState.Secrets.Records[devSecretKey(host.SecretBindRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		SecretRef:        "api_token",
		Scope:            "user",
	})]
	if !boundSecret.Bound || boundSecret.BoundAt == nil || boundSecret.LastTestStatus != "" {
		t.Fatalf("secret state not bound: %#v", boundSecret)
	}
	boundSettings := boundState.Settings.Records[installSummary.PluginInstanceID].Secrets["api_token"]
	if !boundSettings.Set || boundSettings.LastTestStatus != "" {
		t.Fatalf("settings secret state not marked bound: %#v", boundSettings)
	}
	if raw, err := os.ReadFile(filepath.Join(stateRoot, devStateFile)); err != nil {
		t.Fatal(err)
	} else if bytes.Contains(raw, []byte("plaintext")) || bytes.Contains(raw, []byte("token_value")) {
		t.Fatalf("dev secret state leaked a secret value: %s", raw)
	}

	testOutput, err := captureCLIOutput(t, "dev-secret-test", stateRoot, "api_token")
	if err != nil {
		t.Fatalf("dev-secret-test error = %v", err)
	}
	var testSummary devSecretSummary
	if err := json.Unmarshal(testOutput, &testSummary); err != nil {
		t.Fatalf("dev-secret-test output decode error = %v: %s", err, testOutput)
	}
	if !testSummary.Bound || testSummary.LastTestStatus != "passed" {
		t.Fatalf("dev-secret-test summary mismatch: %#v", testSummary)
	}
	testedSettings := loadDevStateForTest(t, stateRoot).Settings.Records[installSummary.PluginInstanceID].Secrets["api_token"]
	if !testedSettings.Set || testedSettings.LastTestStatus != "passed" {
		t.Fatalf("settings secret state not marked tested: %#v", testedSettings)
	}

	deleteOutput, err := captureCLIOutput(t, "dev-secret-delete", stateRoot, "api_token")
	if err != nil {
		t.Fatalf("dev-secret-delete error = %v", err)
	}
	var deleteSummary devSecretSummary
	if err := json.Unmarshal(deleteOutput, &deleteSummary); err != nil {
		t.Fatalf("dev-secret-delete output decode error = %v: %s", err, deleteOutput)
	}
	if deleteSummary.Bound || deleteSummary.LastTestStatus != "" {
		t.Fatalf("dev-secret-delete summary mismatch: %#v", deleteSummary)
	}
	deletedState := loadDevStateForTest(t, stateRoot)
	deletedSecret := deletedState.Secrets.Records[devSecretKey(host.SecretBindRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		SecretRef:        "api_token",
		Scope:            "user",
	})]
	if deletedSecret.Bound || deletedSecret.DeletedAt == nil {
		t.Fatalf("secret state not deleted: %#v", deletedSecret)
	}
	deletedSettings := deletedState.Settings.Records[installSummary.PluginInstanceID].Secrets["api_token"]
	if deletedSettings.Set || deletedSettings.LastTestStatus != "" {
		t.Fatalf("settings secret state not cleared: %#v", deletedSettings)
	}

	if _, err := captureCLIOutput(t, "dev-secret-bind", stateRoot, "api_token", "environment"); err != nil {
		t.Fatalf("dev-secret-bind environment error = %v", err)
	}
	if _, err := captureCLIOutput(t, "dev-secret-bind", stateRoot, "undeclared_token"); err == nil || !strings.Contains(err.Error(), "secret_ref") {
		t.Fatalf("dev-secret-bind undeclared error = %v, want invalid secret_ref", err)
	}

	state = loadDevStateForTest(t, stateRoot)
	restoredSettings := settings.NewMemoryStoreFromState(state.Settings)
	patched, err := restoredSettings.Patch(context.Background(), settings.PatchRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		Values:           map[string]any{"accent_mode": "amber", "sync_enabled": false},
	})
	if err != nil {
		t.Fatalf("Patch() restored settings error = %v", err)
	}
	state.Settings = restoredSettings.State()
	saveDevStateForTest(t, stateRoot, state)

	if _, err := captureCLIOutput(t, "dev-open", stateRoot, "com.example.generated.settings.activity", "http://127.0.0.1:4999"); err != nil {
		t.Fatalf("dev-open error = %v", err)
	}
	openedState := loadDevStateForTest(t, stateRoot)
	openedSnapshot, err := settings.NewMemoryStoreFromState(openedState.Settings).Get(context.Background(), settings.GetRequest{PluginInstanceID: installSummary.PluginInstanceID})
	if err != nil {
		t.Fatalf("Get() after dev-open error = %v", err)
	}
	if openedSnapshot.SettingsRevision != patched.SettingsRevision ||
		openedSnapshot.Values["accent_mode"] != "amber" ||
		openedSnapshot.Values["sync_enabled"] != false {
		t.Fatalf("settings did not persist across dev-open: %#v patched=%#v", openedSnapshot, patched)
	}

	if _, err := captureCLIOutput(t, "dev-disable", stateRoot); err != nil {
		t.Fatalf("dev-disable error = %v", err)
	}
	disabledSnapshot, err := settings.NewMemoryStoreFromState(loadDevStateForTest(t, stateRoot).Settings).Get(context.Background(), settings.GetRequest{PluginInstanceID: installSummary.PluginInstanceID})
	if err != nil {
		t.Fatalf("Get() after dev-disable error = %v", err)
	}
	if disabledSnapshot.Values["accent_mode"] != "amber" {
		t.Fatalf("settings were not retained across disable: %#v", disabledSnapshot)
	}

	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); err != nil {
		t.Fatalf("dev-enable after disable error = %v", err)
	}
	reenabledRecord := loadDevStateForTest(t, stateRoot).Settings.Records[installSummary.PluginInstanceID]
	if reenabledRecord.State != settings.StateActive || reenabledRecord.Values["accent_mode"] != "amber" {
		t.Fatalf("settings were not reactivated with existing values: %#v", reenabledRecord)
	}

	if _, err := captureCLIOutput(t, "dev-uninstall", stateRoot, "--keep-data"); err != nil {
		t.Fatalf("dev-uninstall keep data error = %v", err)
	}
	retainedState := loadDevStateForTest(t, stateRoot)
	retainedRecord := retainedState.Settings.Records[installSummary.PluginInstanceID]
	if retainedRecord.State != settings.StateRetained || retainedRecord.Values["accent_mode"] != "amber" {
		t.Fatalf("settings should be retained after keep-data uninstall: %#v", retainedRecord)
	}
	if len(retainedState.Secrets.Records) != 2 {
		t.Fatalf("secret refs should be retained after keep-data uninstall: %#v", retainedState.Secrets.Records)
	}

	secondStateRoot := filepath.Join(dir, "state-delete")
	secondInstallOutput, err := captureCLIOutput(t, "dev-install", secondStateRoot, packageFile)
	if err != nil {
		t.Fatalf("second dev-install error = %v", err)
	}
	var secondInstallSummary devLifecycleSummary
	if err := json.Unmarshal(secondInstallOutput, &secondInstallSummary); err != nil {
		t.Fatalf("second dev-install output decode error = %v: %s", err, secondInstallOutput)
	}
	if _, err := captureCLIOutput(t, "dev-enable", secondStateRoot); err != nil {
		t.Fatalf("second dev-enable error = %v", err)
	}
	if _, err := captureCLIOutput(t, "dev-secret-test", secondStateRoot, "api_token"); err == nil || !strings.Contains(err.Error(), "must be bound") {
		t.Fatalf("second dev-secret-test before bind error = %v, want must be bound", err)
	}
	if _, err := captureCLIOutput(t, "dev-secret-bind", secondStateRoot, "api_token"); err != nil {
		t.Fatalf("second dev-secret-bind error = %v", err)
	}
	if len(loadDevStateForTest(t, secondStateRoot).Settings.Records) != 1 {
		t.Fatal("second dev-enable should create settings")
	}
	if _, err := captureCLIOutput(t, "dev-uninstall", secondStateRoot, "--delete-data"); err != nil {
		t.Fatalf("second dev-uninstall delete data error = %v", err)
	}
	secondDeletedState := loadDevStateForTest(t, secondStateRoot)
	if _, ok := secondDeletedState.Settings.Records[secondInstallSummary.PluginInstanceID]; ok {
		t.Fatalf("settings remained after delete-data uninstall: %#v", secondDeletedState.Settings.Records)
	}
	if len(secondDeletedState.Secrets.Records) != 0 {
		t.Fatalf("secret refs remained after delete-data uninstall: %#v", secondDeletedState.Secrets.Records)
	}
}

func TestCLIDevLifecycleExportsAndImportsPluginData(t *testing.T) {
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.data", "Generated Data Plugin", scaffoldDir); err != nil {
		t.Fatalf("scaffold command error = %v", err)
	}
	addLifecycleStorageToManifest(t, filepath.Join(scaffoldDir, "manifest.json"))
	addLifecycleSettingsToManifest(t, filepath.Join(scaffoldDir, "manifest.json"))
	if _, err := captureCLIOutput(t, "package", scaffoldDir, packageFile); err != nil {
		t.Fatalf("package command error = %v", err)
	}
	installOutput, err := captureCLIOutput(t, "dev-install", stateRoot, packageFile)
	if err != nil {
		t.Fatalf("dev-install error = %v", err)
	}
	var installSummary devLifecycleSummary
	if err := json.Unmarshal(installOutput, &installSummary); err != nil {
		t.Fatalf("dev-install output decode error = %v: %s", err, installOutput)
	}
	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); err != nil {
		t.Fatalf("dev-enable error = %v", err)
	}

	broker, err := storage.NewFileBroker(filepath.Join(stateRoot, devStorageDir))
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	if _, err := broker.WriteFile(context.Background(), storage.FileWriteRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		StoreID:          "workspace",
		Path:             "notes/exported.txt",
		Data:             []byte("original data"),
	}); err != nil {
		t.Fatalf("WriteFile(original) error = %v", err)
	}
	state := loadDevStateForTest(t, stateRoot)
	store := settings.NewMemoryStoreFromState(state.Settings)
	exportedSettings, err := store.Patch(context.Background(), settings.PatchRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		Values:           map[string]any{"accent_mode": "amber", "sync_enabled": false},
	})
	if err != nil {
		t.Fatalf("Patch(exported settings) error = %v", err)
	}
	state.Settings = store.State()
	saveDevStateForTest(t, stateRoot, state)

	exportOutput, err := captureCLIOutput(t, "dev-export-data", stateRoot)
	if err != nil {
		t.Fatalf("dev-export-data error = %v", err)
	}
	var exportSummary devDataSummary
	if err := json.Unmarshal(exportOutput, &exportSummary); err != nil {
		t.Fatalf("dev-export-data output decode error = %v: %s", err, exportOutput)
	}
	if !exportSummary.OK ||
		exportSummary.PluginInstanceID != installSummary.PluginInstanceID ||
		exportSummary.ArchiveRef == "" ||
		exportSummary.SettingsArchiveRef == "" ||
		exportSummary.IncludeSecrets {
		t.Fatalf("dev-export-data summary mismatch: %#v", exportSummary)
	}
	afterExport := loadDevStateForTest(t, stateRoot)
	if _, ok := afterExport.Settings.Archives[exportSummary.SettingsArchiveRef]; !ok {
		t.Fatalf("settings archive was not persisted in dev state: %#v", afterExport.Settings.Archives)
	}

	if _, err := broker.WriteFile(context.Background(), storage.FileWriteRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		StoreID:          "workspace",
		Path:             "notes/exported.txt",
		Data:             []byte("mutated data"),
	}); err != nil {
		t.Fatalf("WriteFile(mutated) error = %v", err)
	}
	state = loadDevStateForTest(t, stateRoot)
	store = settings.NewMemoryStoreFromState(state.Settings)
	if _, err := store.Patch(context.Background(), settings.PatchRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		Values:           map[string]any{"accent_mode": "indigo", "sync_enabled": true},
	}); err != nil {
		t.Fatalf("Patch(mutated settings) error = %v", err)
	}
	state.Settings = store.State()
	saveDevStateForTest(t, stateRoot, state)

	importOutput, err := captureCLIOutput(
		t,
		"dev-import-data",
		stateRoot,
		"--archive-ref",
		exportSummary.ArchiveRef,
		"--settings-archive-ref",
		exportSummary.SettingsArchiveRef,
		"--delete-existing",
	)
	if err != nil {
		t.Fatalf("dev-import-data error = %v", err)
	}
	var importSummary devDataSummary
	if err := json.Unmarshal(importOutput, &importSummary); err != nil {
		t.Fatalf("dev-import-data output decode error = %v: %s", err, importOutput)
	}
	if !importSummary.Imported ||
		!importSummary.DeleteExisting ||
		importSummary.ArchiveRef != exportSummary.ArchiveRef ||
		importSummary.SettingsArchiveRef != exportSummary.SettingsArchiveRef {
		t.Fatalf("dev-import-data summary mismatch: %#v export=%#v", importSummary, exportSummary)
	}
	read, err := broker.ReadFile(context.Background(), storage.FileReadRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		StoreID:          "workspace",
		Path:             "notes/exported.txt",
		MaxBytes:         1024,
	})
	if err != nil {
		t.Fatalf("ReadFile(restored) error = %v", err)
	}
	if string(read.Data) != "original data" {
		t.Fatalf("import did not restore storage data: %q", read.Data)
	}
	importedSettings, err := settings.NewMemoryStoreFromState(loadDevStateForTest(t, stateRoot).Settings).Get(context.Background(), settings.GetRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
	})
	if err != nil {
		t.Fatalf("Get(imported settings) error = %v", err)
	}
	if importedSettings.Values["accent_mode"] != exportedSettings.Values["accent_mode"] ||
		importedSettings.Values["sync_enabled"] != exportedSettings.Values["sync_enabled"] {
		t.Fatalf("import did not restore settings: %#v want %#v", importedSettings, exportedSettings)
	}
	if _, err := captureCLIOutput(t, "dev-import-data", stateRoot); err == nil {
		t.Fatal("dev-import-data accepted missing archive refs")
	}
}

func TestCLIDevLifecyclePersistsPermissionGrants(t *testing.T) {
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.permissions", "Generated Permissions Plugin", scaffoldDir); err != nil {
		t.Fatalf("scaffold command error = %v", err)
	}
	addLifecyclePermissionBindingToManifest(t, filepath.Join(scaffoldDir, "manifest.json"))
	if _, err := captureCLIOutput(t, "package", scaffoldDir, packageFile); err != nil {
		t.Fatalf("package command error = %v", err)
	}

	installOutput, err := captureCLIOutput(t, "dev-install", stateRoot, packageFile)
	if err != nil {
		t.Fatalf("dev-install error = %v", err)
	}
	var installSummary devLifecycleSummary
	if err := json.Unmarshal(installOutput, &installSummary); err != nil {
		t.Fatalf("dev-install output decode error = %v: %s", err, installOutput)
	}
	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); err != nil {
		t.Fatalf("dev-enable error = %v", err)
	}
	if len(loadDevStateForTest(t, stateRoot).Permissions.Records) != 0 {
		t.Fatal("dev-enable should not auto-grant manifest permissions")
	}

	grantOutput, err := captureCLIOutput(t, "dev-permission-grant", stateRoot, "demo.execute", "alice")
	if err != nil {
		t.Fatalf("dev-permission-grant error = %v", err)
	}
	var grantSummary devPermissionSummary
	if err := json.Unmarshal(grantOutput, &grantSummary); err != nil {
		t.Fatalf("dev-permission-grant output decode error = %v: %s", err, grantOutput)
	}
	if !grantSummary.OK ||
		grantSummary.PluginInstanceID != installSummary.PluginInstanceID ||
		grantSummary.Permission.PermissionID != "demo.execute" ||
		grantSummary.Permission.GrantedBy != "alice" ||
		grantSummary.Permission.Effect != permissions.EffectGrant {
		t.Fatalf("dev-permission-grant summary mismatch: %#v", grantSummary)
	}
	grantedState := loadDevStateForTest(t, stateRoot)
	if len(grantedState.Permissions.Records) != 1 ||
		grantedState.Permissions.Records[0].PermissionID != "demo.execute" ||
		grantedState.Record.PolicyRevision <= installSummary.PolicyRevision {
		t.Fatalf("permission state not persisted after grant: %#v install=%#v", grantedState.Permissions, installSummary)
	}

	listOutput, err := captureCLIOutput(t, "dev-permission-list", stateRoot, "--active-only")
	if err != nil {
		t.Fatalf("dev-permission-list error = %v", err)
	}
	var listSummary devPermissionSummary
	if err := json.Unmarshal(listOutput, &listSummary); err != nil {
		t.Fatalf("dev-permission-list output decode error = %v: %s", err, listOutput)
	}
	if !listSummary.ActiveOnly || len(listSummary.Permissions) != 1 || listSummary.Permissions[0].PermissionID != "demo.execute" {
		t.Fatalf("dev-permission-list summary mismatch: %#v", listSummary)
	}

	if _, err := captureCLIOutput(t, "dev-open", stateRoot, "com.example.generated.permissions.activity", "http://127.0.0.1:4999"); err != nil {
		t.Fatalf("dev-open error = %v", err)
	}
	if len(loadDevStateForTest(t, stateRoot).Permissions.Records) != 1 {
		t.Fatal("permission grant should persist across dev-open")
	}
	if _, err := captureCLIOutput(t, "dev-disable", stateRoot); err != nil {
		t.Fatalf("dev-disable error = %v", err)
	}
	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); err != nil {
		t.Fatalf("dev-enable after disable error = %v", err)
	}
	if len(loadDevStateForTest(t, stateRoot).Permissions.Records) != 1 {
		t.Fatal("permission grant should persist across disable and re-enable")
	}

	revokeOutput, err := captureCLIOutput(t, "dev-permission-revoke", stateRoot, "demo.execute", "reviewed")
	if err != nil {
		t.Fatalf("dev-permission-revoke error = %v", err)
	}
	var revokeSummary devPermissionSummary
	if err := json.Unmarshal(revokeOutput, &revokeSummary); err != nil {
		t.Fatalf("dev-permission-revoke output decode error = %v: %s", err, revokeOutput)
	}
	if revokeSummary.Permission.RevokedAt == nil || revokeSummary.Permission.RevokedReason != "reviewed" {
		t.Fatalf("dev-permission-revoke summary mismatch: %#v", revokeSummary)
	}
	revokedState := loadDevStateForTest(t, stateRoot)
	if len(revokedState.Permissions.Records) != 1 ||
		revokedState.Permissions.Records[0].RevokedAt == nil ||
		revokedState.Record.RevokeEpoch <= grantedState.Record.RevokeEpoch {
		t.Fatalf("permission revoke state mismatch: %#v before=%#v", revokedState.Permissions, grantedState.Record)
	}

	activeOutput, err := captureCLIOutput(t, "dev-permission-list", stateRoot, "--active-only")
	if err != nil {
		t.Fatalf("dev-permission-list active after revoke error = %v", err)
	}
	var activeSummary devPermissionSummary
	if err := json.Unmarshal(activeOutput, &activeSummary); err != nil {
		t.Fatalf("dev-permission-list active output decode error = %v: %s", err, activeOutput)
	}
	if len(activeSummary.Permissions) != 0 {
		t.Fatalf("revoked grant should not be active: %#v", activeSummary)
	}
	fullOutput, err := captureCLIOutput(t, "dev-permission-list", stateRoot)
	if err != nil {
		t.Fatalf("dev-permission-list full after revoke error = %v", err)
	}
	var fullSummary devPermissionSummary
	if err := json.Unmarshal(fullOutput, &fullSummary); err != nil {
		t.Fatalf("dev-permission-list full output decode error = %v: %s", err, fullOutput)
	}
	if len(fullSummary.Permissions) != 1 || fullSummary.Permissions[0].RevokedAt == nil {
		t.Fatalf("full grant list should include revoked record: %#v", fullSummary)
	}

	if _, err := captureCLIOutput(t, "dev-permission-revoke", stateRoot, "missing.permission"); !errors.Is(err, permissions.ErrGrantNotFound) {
		t.Fatalf("dev-permission-revoke missing error = %v, want ErrGrantNotFound", err)
	}
	if _, err := captureCLIOutput(t, "dev-uninstall", stateRoot, "--keep-data"); err != nil {
		t.Fatalf("dev-uninstall keep data error = %v", err)
	}
	uninstalledState := loadDevStateForTest(t, stateRoot)
	if len(uninstalledState.Permissions.Records) != 0 {
		t.Fatalf("permission grants remained after uninstall: %#v", uninstalledState.Permissions)
	}
}

func TestCLIVersionPrintsCompatibilityManifest(t *testing.T) {
	output, err := captureCLIOutput(t, "version")
	if err != nil {
		t.Fatalf("version command error = %v", err)
	}
	var manifest version.CompatibilityManifest
	if err := json.Unmarshal(output, &manifest); err != nil {
		t.Fatalf("version output decode error = %v: %s", err, output)
	}
	if manifest.SchemaVersion != version.CompatibilityManifestVersion {
		t.Fatalf("schema_version = %q, want %q", manifest.SchemaVersion, version.CompatibilityManifestVersion)
	}
	if manifest.Matrix.BridgeSchemaVersion != version.BridgeSchemaVersion {
		t.Fatalf("bridge schema version = %q, want %q", manifest.Matrix.BridgeSchemaVersion, version.BridgeSchemaVersion)
	}
	contracts := map[string]version.ContractArtifact{}
	for _, contract := range manifest.Contracts {
		contracts[contract.ID] = contract
	}
	bridge := contracts["iframe-bridge-schema"]
	if bridge.Path != "spec/plugin/bridge-v1.schema.json" || bridge.Version != version.BridgeSchemaVersion || bridge.SHA256 == "" {
		t.Fatalf("bridge contract mismatch: %#v", bridge)
	}
	openapi := contracts["plugin-platform-openapi"]
	if openapi.Version != version.PluginPlatformOpenAPIVersion || openapi.SHA256 == "" {
		t.Fatalf("openapi contract mismatch: %#v", openapi)
	}
}

func TestCLIVerifyCompatibilityManifest(t *testing.T) {
	dir := t.TempDir()
	versionOutput, err := captureCLIOutput(t, "version")
	if err != nil {
		t.Fatalf("version command error = %v", err)
	}
	manifestFile := filepath.Join(dir, "compatibility.json")
	if err := os.WriteFile(manifestFile, versionOutput, 0o644); err != nil {
		t.Fatal(err)
	}

	verifyOutput, err := captureCLIOutput(t, "verify-compatibility", manifestFile, cliRepoRoot(t))
	if err != nil {
		t.Fatalf("verify-compatibility command error = %v", err)
	}
	var summary compatibilityVerifySummary
	if err := json.Unmarshal(verifyOutput, &summary); err != nil {
		t.Fatalf("verify-compatibility output decode error = %v: %s", err, verifyOutput)
	}
	if !summary.OK || summary.SchemaVersion != version.CompatibilityManifestVersion || summary.Contracts == 0 {
		t.Fatalf("verify-compatibility summary mismatch: %#v", summary)
	}

	var manifest version.CompatibilityManifest
	if err := json.Unmarshal(versionOutput, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Matrix.PluginHostProtocolVersion = "plugin-host-v2"
	tamperedFile := filepath.Join(dir, "tampered.json")
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedFile, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "verify-compatibility", tamperedFile, cliRepoRoot(t)); err == nil {
		t.Fatal("verify-compatibility accepted tampered manifest")
	}
}

func TestCLIInspectStorageReportsNamespacesWithoutFileContents(t *testing.T) {
	dir := t.TempDir()
	storageRoot := filepath.Join(dir, "storage")
	broker, err := storage.NewFileBroker(storageRoot)
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	if err := broker.EnsureNamespace(context.Background(), storage.Namespace{
		PluginInstanceID: "plugini_cli",
		StoreID:          "workspace",
		Kind:             storage.StoreFiles,
		QuotaBytes:       4096,
		SchemaVersion:    1,
	}); err != nil {
		t.Fatalf("EnsureNamespace() error = %v", err)
	}
	if _, err := broker.WriteFile(context.Background(), storage.FileWriteRequest{
		PluginInstanceID: "plugini_cli",
		StoreID:          "workspace",
		Path:             "notes/private.txt",
		Data:             []byte("secret contents"),
	}); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := captureCLIOutput(t, "inspect-storage", storageRoot, "plugini_cli")
	if err != nil {
		t.Fatalf("inspect-storage command error = %v", err)
	}
	var summary storageInspectSummary
	if err := json.Unmarshal(output, &summary); err != nil {
		t.Fatalf("inspect-storage output decode error = %v: %s", err, output)
	}
	if !summary.OK || summary.NamespaceCount != 1 || summary.TotalUsageBytes != int64(len("secret contents")) {
		t.Fatalf("inspect-storage summary mismatch: %#v", summary)
	}
	if summary.Namespaces[0].PluginInstanceID != "plugini_cli" ||
		summary.Namespaces[0].StoreID != "workspace" ||
		summary.Namespaces[0].Kind != storage.StoreFiles ||
		summary.Namespaces[0].UsageBytes != int64(len("secret contents")) {
		t.Fatalf("inspect-storage namespace mismatch: %#v", summary.Namespaces)
	}
	if bytes.Contains(output, []byte("secret contents")) {
		t.Fatalf("inspect-storage leaked file contents: %s", output)
	}

	allOutput, err := captureCLIOutput(t, "inspect-storage", storageRoot)
	if err != nil {
		t.Fatalf("inspect-storage all command error = %v", err)
	}
	var allSummary storageInspectSummary
	if err := json.Unmarshal(allOutput, &allSummary); err != nil {
		t.Fatalf("inspect-storage all output decode error = %v: %s", err, allOutput)
	}
	if allSummary.NamespaceCount != 1 || allSummary.PluginInstanceID != "" {
		t.Fatalf("inspect-storage all summary mismatch: %#v", allSummary)
	}
}

func captureCLIOutput(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	runErr := run(context.Background(), args)
	closeErr := writer.Close()
	os.Stdout = originalStdout
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		return buf.Bytes(), runErr
	}
	if closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
		return buf.Bytes(), closeErr
	}
	return buf.Bytes(), nil
}

func cliRepoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Clean(filepath.Join("..", ".."))
}

func readCLITestPublicKey(t *testing.T, filename string) ed25519.PublicKey {
	t.Helper()
	_, publicKey, err := readSigningPublicKey(filename)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

type cliRuntimeResolver struct {
	path string
}

func (r cliRuntimeResolver) RuntimePath(context.Context, host.RuntimeTarget) (string, error) {
	return r.path, nil
}

type cliRecordingNetworkExecutor struct {
	httpCalls  int
	wsCalls    int
	tcpCalls   int
	udpCalls   int
	lastHTTP   connectivity.HTTPRequest
	lastWS     connectivity.WebSocketRoundTripRequest
	lastTCP    connectivity.TCPRoundTripRequest
	lastUDP    connectivity.UDPRoundTripRequest
	httpStatus int
	httpBody   []byte
	wsPayload  []byte
	tcpPayload []byte
	udpPayload []byte
}

func (e *cliRecordingNetworkExecutor) DoHTTP(_ context.Context, req connectivity.HTTPRequest) (connectivity.HTTPResponse, error) {
	e.httpCalls++
	e.lastHTTP = req
	status := e.httpStatus
	if status == 0 {
		status = http.StatusOK
	}
	return connectivity.HTTPResponse{StatusCode: status, Body: append([]byte(nil), e.httpBody...)}, nil
}

func (e *cliRecordingNetworkExecutor) WebSocketRoundTrip(_ context.Context, req connectivity.WebSocketRoundTripRequest) (connectivity.WebSocketRoundTripResponse, error) {
	e.wsCalls++
	e.lastWS = req
	messageType := req.MessageType
	if messageType == "" {
		messageType = connectivity.WebSocketMessageText
	}
	return connectivity.WebSocketRoundTripResponse{MessageType: messageType, Payload: append([]byte(nil), e.wsPayload...)}, nil
}

func (e *cliRecordingNetworkExecutor) TCPRoundTrip(_ context.Context, req connectivity.TCPRoundTripRequest) (connectivity.TCPRoundTripResponse, error) {
	e.tcpCalls++
	e.lastTCP = req
	return connectivity.TCPRoundTripResponse{Payload: append([]byte(nil), e.tcpPayload...)}, nil
}

func (e *cliRecordingNetworkExecutor) UDPRoundTrip(_ context.Context, req connectivity.UDPRoundTripRequest) (connectivity.UDPRoundTripResponse, error) {
	e.udpCalls++
	e.lastUDP = req
	return connectivity.UDPRoundTripResponse{Payload: append([]byte(nil), e.udpPayload...)}, nil
}

func writeCLITestFile(t *testing.T, filename string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func addLifecycleStorageToManifest(t *testing.T, filename string) {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["storage"]; ok {
		return
	}
	doc["storage"] = map[string]any{
		"stores": []map[string]any{{
			"store_id":       "workspace",
			"kind":           string(storage.StoreFiles),
			"scope":          "user",
			"quota_bytes":    4096,
			"schema_version": 1,
			"migration": map[string]any{
				"from_version":    0,
				"to_version":      1,
				"reversible":      true,
				"requires_worker": false,
				"estimated_bytes": 0,
				"max_duration_ms": 1000,
				"data_loss_risk":  false,
				"steps_hash":      "sha256:dev-lifecycle",
			},
		}},
	}
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(updated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func addLifecycleSettingsToManifest(t *testing.T, filename string) {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["settings"] = map[string]any{
		"schema_version": 1,
		"migration": map[string]any{
			"from_version":    0,
			"to_version":      1,
			"reversible":      true,
			"requires_worker": false,
			"estimated_bytes": 0,
			"max_duration_ms": 1000,
			"data_loss_risk":  false,
			"steps_hash":      "sha256:dev-settings",
		},
		"fields": []map[string]any{{
			"key":     "accent_mode",
			"type":    settings.FieldSelect,
			"scope":   "user",
			"label":   "Accent mode",
			"default": "teal",
			"options": []string{"teal", "amber", "indigo"},
		}, {
			"key":     "sync_enabled",
			"type":    settings.FieldBoolean,
			"scope":   "user",
			"label":   "Sync enabled",
			"default": true,
		}, {
			"key":        "api_token",
			"type":       settings.FieldSecret,
			"scope":      "user",
			"label":      "API token",
			"secret_ref": "api_token",
		}},
	}
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(updated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func addLifecyclePermissionBindingToManifest(t *testing.T, filename string) {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["capability_bindings"] = []map[string]any{{
		"binding_id":             "demo",
		"capability_id":          "example.capability.demo",
		"min_capability_version": "1.0.0",
		"required_permissions":   []string{"demo.execute"},
	}}
	methods, ok := doc["methods"].([]any)
	if !ok || len(methods) == 0 {
		t.Fatalf("manifest missing methods: %s", raw)
	}
	method, ok := methods[0].(map[string]any)
	if !ok {
		t.Fatalf("manifest method has unexpected shape: %#v", methods[0])
	}
	method["route"] = map[string]any{
		"kind":          "capability",
		"binding_id":    "demo",
		"target_method": "worker.echo",
	}
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(updated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func loadDevStateForTest(t *testing.T, stateRoot string) devLifecycleState {
	t.Helper()
	state, err := loadDevState(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func saveDevStateForTest(t *testing.T, stateRoot string, state devLifecycleState) {
	t.Helper()
	if err := saveDevState(stateRoot, state); err != nil {
		t.Fatal(err)
	}
}

func prefixLen(length int, maxLength int) int {
	if length < maxLength {
		return length
	}
	return maxLength
}
