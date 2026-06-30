package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
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
	for _, want := range []string{"redevplugin.bridge.handshake", "redevplugin.bridge.call", "parent_origin", "worker.echo", "worker.brokerDemo", "invoke-broker", "tokenLeakCheck"} {
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
	h, err := host.New(host.Adapters{
		SessionResolver:         staticSessionResolver{},
		Policy:                  staticPolicyAdapter{},
		RuntimeArtifactResolver: cliRuntimeResolver{path: runtimePath},
		Storage:                 storage.NewMemoryBroker(),
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
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
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
	if inspectSummary.NamespaceCount != 2 {
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

func prefixLen(length int, maxLength int) int {
	if length < maxLength {
		return length
	}
	return maxLength
}
