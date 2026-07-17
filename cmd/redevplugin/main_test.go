package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/trust"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestScaffoldEchoResponseSchemaIsClosedAndMinimal(t *testing.T) {
	compiled, err := manifest.CompileMethodSchemas(manifest.MethodSpec{
		Method:         "worker.echo",
		RequestSchema:  closedMethodObjectSchema(nil),
		ResponseSchema: scaffoldEchoResponseSchema(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.ValidateResponse(map[string]any{
		"method":    "worker.echo",
		"worker_id": "backend",
		"backend":   "executed wasm worker scaffold",
		"transport": "rust runtime ipc",
		"wasm_abi":  "redevplugin-wasm-worker-v2",
		"message":   "hello",
	}); err != nil {
		t.Fatalf("scaffold echo response schema rejected valid data: %v", err)
	}
	if err := compiled.ValidateResponse(map[string]any{
		"method":          "worker.echo",
		"worker_id":       "backend",
		"backend":         "executed wasm worker scaffold",
		"transport":       "rust runtime ipc",
		"wasm_abi":        "redevplugin-wasm-worker-v2",
		"message":         "hello",
		"network_execute": map[string]any{},
	}); err == nil {
		t.Fatal("scaffold echo response schema accepted undeclared network data")
	}
}

func TestCLIKeygenSignAndValidatePackage(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "plugin")
	writeCLITestFile(t, filepath.Join(srcDir, "manifest.json"), `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.cli",
			"display_name": "CLI",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "cli.view", "kind": "view", "label": "CLI", "entry": "ui/index.html"}
		]
	}`)
	writeCLITestFile(t, filepath.Join(srcDir, "ui", "index.html"), `<!doctype html><title>CLI</title><body><main>CLI</main><script type="text/redevplugin-worker" src="assets/app.js"></script></body>`)
	writeCLITestFile(t, filepath.Join(srcDir, "ui", "assets", "app.js"), "void 0;")

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
		Package:     signedPkg,
		LocalImport: true,
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
	if summary.PluginID != "com.example.generated" || len(summary.Files) != 14 {
		t.Fatalf("scaffold summary mismatch: %#v", summary)
	}

	if _, err := captureCLIOutput(t, "validate", filepath.Join(scaffoldDir, "dist", "manifest.json")); err != nil {
		t.Fatalf("validate scaffold manifest error = %v", err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"workers"`, `"backend"`, `"worker.echo"`} {
		if !bytes.Contains(manifestRaw, []byte(want)) {
			t.Fatalf("scaffold manifest missing %q: %s", want, manifestRaw)
		}
	}
	for _, forbidden := range []string{`"worker.brokerSample"`, `"broker_access"`, `"storage"`, `"network_access"`, `"sqlite_bootstrap"`, `"storage_handle_grant_token"`} {
		if bytes.Contains(manifestRaw, []byte(forbidden)) {
			t.Fatalf("minimal scaffold manifest retained forbidden capability %q: %s", forbidden, manifestRaw)
		}
	}
	distManifestRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "dist", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestRaw, distManifestRaw) {
		t.Fatal("editable and distributable scaffold manifests differ")
	}
	indexRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "dist", "ui", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(indexRaw, []byte(`<title>Generated Plugin</title>`)) || !bytes.Contains(indexRaw, []byte(`type="text/redevplugin-worker"`)) {
		t.Fatalf("scaffold index missing opaque worker declaration: %s", indexRaw)
	}
	for _, forbidden := range []string{`data-plugin-id`, `data-surface-id`, `parent_origin`, `surface_instance_id`, `active_fingerprint`, `bridge_nonce`, `allow-same-origin`} {
		if bytes.Contains(indexRaw, []byte(forbidden)) {
			t.Fatalf("scaffold index retained browser bootstrap field %q: %s", forbidden, indexRaw)
		}
	}
	appRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "dist", "ui", "assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PluginBridgeClient", "redevplugin.bridge.call", "worker.echo", "echo-message", "Generated Plugin"} {
		if !bytes.Contains(appRaw, []byte(want)) {
			t.Fatalf("scaffold app.js missing %q: %s", want, appRaw)
		}
	}
	for _, forbidden := range []string{"window.parent.postMessage", "parent_origin", "redevplugin.bridge.handshake", "asset_ticket", "plugin_gateway_token", "stream_ticket", "worker.brokerSample"} {
		if bytes.Contains(appRaw, []byte(forbidden)) {
			t.Fatalf("scaffold app.js retained parent-only or hand-written bridge field %q", forbidden)
		}
	}
	for _, sourcePath := range []string{"ui/src/app.ts", "worker/src/lib.rs", "worker/Cargo.toml", "package.json", "scripts/build.mjs", "README.md"} {
		if _, err := os.Stat(filepath.Join(scaffoldDir, filepath.FromSlash(sourcePath))); err != nil {
			t.Fatalf("editable scaffold source %s is missing: %v", sourcePath, err)
		}
	}
	wasmRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "dist", "workers", "backend.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(wasmRaw) < 8 || !bytes.Equal(wasmRaw[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		t.Fatalf("scaffold wasm artifact is invalid: %x", wasmRaw[:prefixLen(len(wasmRaw), 8)])
	}
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
		t.Fatalf("package scaffold error = %v", err)
	}
	generatedPackage, err := pluginpkg.ReadFile(context.Background(), packageFile, pluginpkg.DefaultReadOptions())
	if err != nil {
		t.Fatalf("ReadFile(scaffold) error = %v", err)
	}
	entries := make(map[string]pluginpkg.Entry, len(generatedPackage.Entries))
	for _, entry := range generatedPackage.Entries {
		entries[entry.Path] = entry
	}
	document, err := pluginpkg.BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (pluginpkg.Asset, error) {
		entry, ok := entries[assetPath]
		if !ok {
			return pluginpkg.Asset{}, fmt.Errorf("missing scaffold asset %s", assetPath)
		}
		return pluginpkg.Asset{Entry: entry, Content: generatedPackage.Files[assetPath]}, nil
	})
	if err != nil {
		t.Fatalf("BuildOpaqueSurfaceDocument(scaffold) error = %v", err)
	}
	if document.Worker.Type != pluginpkg.OpaqueSurfaceWorkerClassic || document.Worker.Path != "ui/assets/app.js" {
		t.Fatalf("scaffold opaque worker = %#v", document.Worker)
	}
	if _, err := captureCLIOutput(t, "install-local", packageFile); err != nil {
		t.Fatalf("install-local scaffold package error = %v", err)
	}
	for _, action := range []string{"enable", "disable", "uninstall"} {
		if _, err := captureCLIOutput(t, action, packageFile); err != nil {
			t.Fatalf("%s scaffold package error = %v", action, err)
		}
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
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
		t.Fatalf("package command error = %v", err)
	}
	packageBytes, err := os.ReadFile(packageFile)
	if err != nil {
		t.Fatal(err)
	}

	ctx := cliContext(context.Background())
	registryStore := registry.NewMemoryStore()
	pluginData, err := plugindata.Open(ctx, filepath.Join(dir, "plugin-data"), registryStore)
	if err != nil {
		t.Fatal(err)
	}
	adapters := newEphemeralCLIAdapters(registryStore, pluginData)
	runtimeManager, err := newCommandRuntimeManager(commandRuntimeDependencies{
		Path:             runtimePath,
		Diagnostics:      adapters.Diagnostics,
		Assets:           adapters.Assets,
		SurfaceTokens:    adapters.SurfaceTokens,
		PluginData:       pluginData,
		Connectivity:     adapters.Connectivity,
		NetworkExecutor:  adapters.NetworkExecutor,
		ShardCount:       1,
		HandshakeTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapters.RuntimeManager = runtimeManager
	h, err := host.Open(ctx, adapters)
	if err != nil {
		_ = pluginData.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	health, err := h.StartRuntime(ctx, host.StartRuntimeRequest{
		Target: host.RuntimeTarget{OS: goruntime.GOOS, Arch: goruntime.GOARCH},
	})
	if err != nil {
		t.Fatalf("StartRuntime() error = %v", err)
	}
	if !health.Ready || len(health.Shards) != 1 {
		t.Fatalf("runtime health mismatch: %#v", health)
	}
	for _, shard := range health.Shards {
		if !shard.Ready || shard.RuntimeGenerationID == "" {
			t.Fatalf("runtime shard health mismatch: %#v", shard)
		}
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := h.StopRuntime(stopCtx); err != nil {
			t.Errorf("StopRuntime() error = %v", err)
		}
	})

	installed, err := host.ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	now := time.Now().UTC()
	enabled, err := h.EnablePlugin(ctx, host.EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		Now:                        now,
	})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(ctx, host.OpenSurfaceRequest{
		PluginInstanceID:           enabled.PluginInstanceID,
		ExpectedManagementRevision: enabled.ManagementRevision,
		SurfaceID:                  "com.example.generated.runtime.view",
		SurfaceInstanceID:          "surface_generated_runtime",

		Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	prepared, err := h.PrepareSurface(ctx, host.ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,

		Now: now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("PrepareSurface() error = %v", err)
	}
	if prepared.Document.EntryPath != bootstrap.EntryPath || prepared.Document.EntrySHA256 != bootstrap.EntrySHA256 {
		t.Fatalf("PrepareSurface() document mismatch: %#v", prepared.Document)
	}
	handshake := bridge.Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		ManagementRevision: bootstrap.ManagementRevision,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v5",
	}
	gateway, err := h.MintBridgeToken(ctx, host.MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_generated_runtime",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_generated_runtime"),

		Now: now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}

	result, err := h.CallPluginMethod(ctx, host.CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,

		BridgeChannelID: "bridge_generated_runtime",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "hello from scaffold"},
		Now:             now.Add(4 * time.Second),
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

func TestCommandRuntimeManagerRequiresExplicitShardCount(t *testing.T) {
	ctx := cliContext(context.Background())
	registryStore := registry.NewMemoryStore()
	pluginData, err := plugindata.Open(ctx, t.TempDir(), registryStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pluginData.Close() })
	adapters := newEphemeralCLIAdapters(registryStore, pluginData)
	_, err = newCommandRuntimeManager(commandRuntimeDependencies{
		Path:            os.Args[0],
		Diagnostics:     adapters.Diagnostics,
		Assets:          adapters.Assets,
		SurfaceTokens:   adapters.SurfaceTokens,
		PluginData:      pluginData,
		Connectivity:    adapters.Connectivity,
		NetworkExecutor: adapters.NetworkExecutor,
		ShardCount:      0,
	})
	if !errors.Is(err, runtimeclient.ErrRuntimeShardCount) {
		t.Fatalf("newCommandRuntimeManager() error = %v, want %v", err, runtimeclient.ErrRuntimeShardCount)
	}
}

func TestCommandRuntimeManagerProvidesExplicitRuntimeTiming(t *testing.T) {
	ctx := cliContext(context.Background())
	registryStore := registry.NewMemoryStore()
	pluginData, err := plugindata.Open(ctx, t.TempDir(), registryStore)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pluginData.Close() })
	adapters := newEphemeralCLIAdapters(registryStore, pluginData)
	_, err = newCommandRuntimeManager(commandRuntimeDependencies{
		Path:             os.Args[0],
		Diagnostics:      adapters.Diagnostics,
		Assets:           adapters.Assets,
		SurfaceTokens:    adapters.SurfaceTokens,
		PluginData:       pluginData,
		Connectivity:     adapters.Connectivity,
		NetworkExecutor:  adapters.NetworkExecutor,
		ShardCount:       1,
		HandshakeTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("newCommandRuntimeManager() error = %v", err)
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
	addLifecycleStorageToManifest(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
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
	if installSummary.EnableState != registry.EnableDisabled || installSummary.StateRoot != stateRoot || installSummary.PluginDataRoot != filepath.Join(stateRoot, devPluginDataDir) {
		t.Fatalf("dev-install summary mismatch: %#v", installSummary)
	}
	for _, filename := range []string{devPackageFile, devRegistryFile, devSecretsFile} {
		if _, err := os.Stat(filepath.Join(stateRoot, filename)); err != nil {
			t.Fatalf("dev state artifact %s missing: %v", filename, err)
		}
	}
	rootEntries, err := os.ReadDir(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range rootEntries {
		if filepath.Ext(entry.Name()) == ".json" {
			t.Fatalf("dev state root contains a JSON authority mirror: %s", entry.Name())
		}
	}
	registryStore, err := registry.NewSQLiteStore(context.Background(), filepath.Join(stateRoot, devRegistryFile))
	if err != nil {
		t.Fatal(err)
	}
	record, err := registryStore.GetPlugin(context.Background(), installSummary.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableDisabled {
		t.Fatalf("registry record after install = %#v", record)
	}
	if err := registryStore.Close(); err != nil {
		t.Fatal(err)
	}

	harness, _, err := loadDevHarness(context.Background(), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	secondRegistry, err := registry.NewSQLiteStore(context.Background(), filepath.Join(stateRoot, devRegistryFile))
	if err != nil {
		t.Fatal(err)
	}
	if secondStore, err := plugindata.Open(context.Background(), filepath.Join(stateRoot, devPluginDataDir), secondRegistry); err == nil {
		_ = secondStore.Close()
		t.Fatal("second plugin data store acquired an already locked root")
	}
	if err := secondRegistry.Close(); err != nil {
		t.Fatal(err)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}

	enableOutput, err := captureCLIOutput(t, "dev-enable", stateRoot)
	if err != nil {
		t.Fatalf("dev-enable error = %v", err)
	}
	var enableSummary devLifecycleSummary
	if err := json.Unmarshal(enableOutput, &enableSummary); err != nil {
		t.Fatal(err)
	}
	if enableSummary.EnableState != registry.EnableEnabled || enableSummary.ManagementRevision <= installSummary.ManagementRevision {
		t.Fatalf("dev-enable summary mismatch: %#v", enableSummary)
	}

	openOutput, err := captureCLIOutput(t, "dev-open", stateRoot, "com.example.generated.lifecycle.view")
	if err != nil {
		t.Fatalf("dev-open error = %v", err)
	}
	var openSummary devOpenSurfaceSummary
	if err := json.Unmarshal(openOutput, &openSummary); err != nil {
		t.Fatalf("dev-open output decode error = %v: %s", err, openOutput)
	}
	if !openSummary.OK || openSummary.PluginInstanceID != installSummary.PluginInstanceID || openSummary.BridgeNonce == "" || openSummary.AssetTicketID == "" {
		t.Fatalf("dev-open summary mismatch: %#v", openSummary)
	}
	inspectOutput, err := captureCLIOutput(t, "inspect-data", stateRoot, installSummary.PluginInstanceID)
	if err != nil {
		t.Fatalf("inspect-data error = %v", err)
	}
	var inspectSummary dataInspectSummary
	if err := json.Unmarshal(inspectOutput, &inspectSummary); err != nil {
		t.Fatal(err)
	}
	if inspectSummary.BindingCount != 1 || inspectSummary.NamespaceCount != 1 || inspectSummary.Namespaces[0].Kind != storage.StoreFiles {
		t.Fatalf("inspect-data summary mismatch: %#v", inspectSummary)
	}

	if _, err := captureCLIOutput(t, "dev-disable", stateRoot); err != nil {
		t.Fatalf("dev-disable error = %v", err)
	}
	uninstallOutput, err := captureCLIOutput(t, "dev-uninstall", stateRoot)
	if err != nil {
		t.Fatalf("dev-uninstall error = %v", err)
	}
	var uninstallSummary devLifecycleSummary
	if err := json.Unmarshal(uninstallOutput, &uninstallSummary); err != nil {
		t.Fatalf("dev-uninstall output decode error = %v: %s", err, uninstallOutput)
	}
	if uninstallSummary.EnableState != registry.EnableDisabled {
		t.Fatalf("dev-uninstall summary mismatch: %#v", uninstallSummary)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, devPackageFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dev package copy still exists after uninstall: %v", err)
	}
	if _, err := captureCLIOutput(t, "dev-status", stateRoot); !errors.Is(err, errDevStateNotInstalled) {
		t.Fatalf("dev-status after uninstall error = %v, want %v", err, errDevStateNotInstalled)
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
	addLifecycleSettingsToManifest(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
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
	ctx := cliContext(context.Background())
	harness, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := harness.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ValuesRevision != 1 || snapshot.Values["accent_mode"] != "teal" || snapshot.Values["sync_enabled"] != true {
		t.Fatalf("settings defaults mismatch: %#v", snapshot)
	}
	patched, err := harness.host.PatchPluginSettings(ctx, host.PatchSettingsRequest{
		PluginInstanceID:       plugin.PluginInstanceID,
		ExpectedValuesRevision: snapshot.ValuesRevision,
		Set:                    map[string]any{"accent_mode": "amber", "sync_enabled": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.host.PatchPluginSettings(ctx, host.PatchSettingsRequest{
		PluginInstanceID:       plugin.PluginInstanceID,
		ExpectedValuesRevision: snapshot.ValuesRevision,
		Set:                    map[string]any{"accent_mode": "indigo"},
	}); !errors.Is(err, plugindata.ErrRevisionConflict) {
		t.Fatalf("stale settings CAS error = %v, want %v", err, plugindata.ErrRevisionConflict)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := reopened.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if restored.ValuesRevision != patched.ValuesRevision || restored.Values["accent_mode"] != "amber" || restored.Values["sync_enabled"] != false {
		t.Fatalf("settings did not persist across restart: %#v", restored)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	bindOutput, err := captureCLIOutput(t, "dev-secret-bind", stateRoot, " api_token ")
	if err != nil {
		t.Fatal(err)
	}
	var bindSummary devSecretSummary
	if err := json.Unmarshal(bindOutput, &bindSummary); err != nil {
		t.Fatal(err)
	}
	if !bindSummary.Bound || bindSummary.SecretRef != "api_token" {
		t.Fatalf("secret bind summary mismatch: %#v", bindSummary)
	}
	if _, err := captureCLIOutput(t, "dev-secret-test", stateRoot, "api_token"); err != nil {
		t.Fatal(err)
	}
	secretStore, err := secrets.NewSQLiteStore(context.Background(), filepath.Join(stateRoot, devSecretsFile))
	if err != nil {
		t.Fatal(err)
	}
	secretRecords, err := secretStore.List(context.Background(), secrets.ListRequest{PluginInstanceID: installSummary.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if err := secretStore.Close(); err != nil {
		t.Fatal(err)
	}
	if len(secretRecords) != 1 || !secretRecords[0].Bound || secretRecords[0].LastTestStatus != "passed" {
		t.Fatalf("SQLite secret record mismatch: %#v", secretRecords)
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
	addLifecycleStorageToManifest(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
	addLifecycleSettingsToManifest(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
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
	if _, err := captureCLIOutput(t, "dev-secret-bind", stateRoot, "api_token"); err != nil {
		t.Fatal(err)
	}
	ctx := cliContext(context.Background())
	harness, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.pluginData.WriteFile(context.Background(), storage.FileWriteRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		StoreID:          "workspace",
		Path:             "notes/exported.txt",
		Data:             []byte("original data"),
	}); err != nil {
		t.Fatalf("WriteFile(original) error = %v", err)
	}
	snapshot, err := harness.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	exportedSettings, err := harness.host.PatchPluginSettings(ctx, host.PatchSettingsRequest{
		PluginInstanceID:       plugin.PluginInstanceID,
		ExpectedValuesRevision: snapshot.ValuesRevision,
		Set:                    map[string]any{"accent_mode": "amber", "sync_enabled": false},
	})
	if err != nil {
		t.Fatalf("Patch(exported settings) error = %v", err)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}

	exportOutput, err := captureCLIOutput(t, "dev-export-data", stateRoot)
	if err != nil {
		t.Fatalf("dev-export-data error = %v", err)
	}
	var exportSummary devDataSummary
	if err := json.Unmarshal(exportOutput, &exportSummary); err != nil {
		t.Fatalf("dev-export-data output decode error = %v: %s", err, exportOutput)
	}
	if !exportSummary.OK || exportSummary.PluginInstanceID != installSummary.PluginInstanceID || exportSummary.BundleRef == "" || exportSummary.ContentHash == "" || exportSummary.SizeBytes <= 0 {
		t.Fatalf("dev-export-data summary mismatch: %#v", exportSummary)
	}
	assertFileTreeDoesNotContain(t, filepath.Join(stateRoot, devPluginDataDir, "objects", exportSummary.BundleRef), []byte("api_token"))

	harness, plugin, err = loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.pluginData.WriteFile(context.Background(), storage.FileWriteRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		StoreID:          "workspace",
		Path:             "notes/exported.txt",
		Data:             []byte("mutated data"),
	}); err != nil {
		t.Fatalf("WriteFile(mutated) error = %v", err)
	}
	mutatedSettings, err := harness.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.host.PatchPluginSettings(ctx, host.PatchSettingsRequest{
		PluginInstanceID:       plugin.PluginInstanceID,
		ExpectedValuesRevision: mutatedSettings.ValuesRevision,
		Set:                    map[string]any{"accent_mode": "indigo", "sync_enabled": true},
	}); err != nil {
		t.Fatalf("Patch(mutated settings) error = %v", err)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "dev-disable", stateRoot); err != nil {
		t.Fatal(err)
	}
	importOutput, err := captureCLIOutput(t, "dev-import-data", stateRoot, exportSummary.BundleRef)
	if err != nil {
		t.Fatalf("dev-import-data error = %v", err)
	}
	var importSummary devDataSummary
	if err := json.Unmarshal(importOutput, &importSummary); err != nil {
		t.Fatalf("dev-import-data output decode error = %v: %s", err, importOutput)
	}
	if !importSummary.Imported || importSummary.BundleRef != exportSummary.BundleRef {
		t.Fatalf("dev-import-data summary mismatch: %#v export=%#v", importSummary, exportSummary)
	}
	harness, plugin, err = loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	read, err := harness.pluginData.ReadFile(context.Background(), storage.FileReadRequest{
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
	importedSettings, err := harness.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID})
	if err != nil {
		t.Fatalf("Get(imported settings) error = %v", err)
	}
	if importedSettings.Values["accent_mode"] != exportedSettings.Values["accent_mode"] ||
		importedSettings.Values["sync_enabled"] != exportedSettings.Values["sync_enabled"] {
		t.Fatalf("import did not restore settings: %#v want %#v", importedSettings, exportedSettings)
	}
	secretRecords, err := harness.secretStore.List(context.Background(), secrets.ListRequest{PluginInstanceID: plugin.PluginInstanceID, BoundOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(secretRecords) != 1 || secretRecords[0].SecretRef != "api_token" {
		t.Fatalf("import changed external secret bindings: %#v", secretRecords)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "dev-delete-export", stateRoot, exportSummary.BundleRef); err != nil {
		t.Fatal(err)
	}
	registryStore, err := registry.NewSQLiteStore(context.Background(), filepath.Join(stateRoot, devRegistryFile))
	if err != nil {
		t.Fatal(err)
	}
	objects, next, err := registryStore.ListObjects(context.Background(), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if next != "" {
		t.Fatalf("unexpected object page cursor %q", next)
	}
	if err := registryStore.Close(); err != nil {
		t.Fatal(err)
	}
	if len(objects) != 0 {
		t.Fatalf("deleted export remains in catalog: %#v", objects)
	}
	if _, err := captureCLIOutput(t, "dev-import-data", stateRoot); err == nil {
		t.Fatal("dev-import-data accepted a missing bundle ref")
	}
	if _, err := captureCLIOutput(t, "dev-export-data", stateRoot, "unexpected"); err == nil {
		t.Fatal("dev-export-data accepted an unexpected argument")
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
	capabilityRoot, capabilityPin, capabilityPublicKey := buildCLITestCapabilityArtifact(t, dir, filepath.Join(scaffoldDir, "dist", "manifest.json"))
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
		t.Fatalf("package command error = %v", err)
	}

	installOutput, err := captureCLIOutput(t, "dev-install", stateRoot, packageFile, "--capability", capabilityRoot, capabilityPin, capabilityPublicKey)
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
	if _, err := captureCLIOutput(t, "dev-permission-grant", stateRoot, "demo.execute", "alice"); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("dev-permission-grant accepted caller-supplied actor: %v", err)
	}

	grantOutput, err := captureCLIOutput(t, "dev-permission-grant", stateRoot, "demo.execute")
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
		grantSummary.Permission.GrantedBy != "cli_owner_user" ||
		grantSummary.Permission.Effect != permissions.EffectGrant {
		t.Fatalf("dev-permission-grant summary mismatch: %#v", grantSummary)
	}
	registryStore, err := registry.NewSQLiteStore(context.Background(), filepath.Join(stateRoot, devRegistryFile))
	if err != nil {
		t.Fatal(err)
	}
	grantedState, err := registryStore.GetAuthorization(context.Background(), installSummary.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := registryStore.Close(); err != nil {
		t.Fatal(err)
	}
	if len(grantedState.Grants) != 1 || grantedState.Grants[0].PermissionID != "demo.execute" || grantedState.Plugin.PolicyRevision <= installSummary.PolicyRevision {
		t.Fatalf("authorization state not persisted after grant: %#v install=%#v", grantedState, installSummary)
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

	if _, err := captureCLIOutput(t, "dev-disable", stateRoot); err != nil {
		t.Fatalf("dev-disable error = %v", err)
	}
	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); err != nil {
		t.Fatalf("dev-enable after disable error = %v", err)
	}
	revokeOutput, err := captureCLIOutput(t, "dev-permission-revoke", stateRoot, "demo.execute", "reviewed")
	if err != nil {
		t.Fatalf("dev-permission-revoke error = %v", err)
	}
	var revokeSummary devPermissionSummary
	if err := json.Unmarshal(revokeOutput, &revokeSummary); err != nil {
		t.Fatalf("dev-permission-revoke output decode error = %v: %s", err, revokeOutput)
	}
	if revokeSummary.Permission.RevokedAt == nil ||
		revokeSummary.Permission.RevokedBy != "cli_owner_user" ||
		revokeSummary.Permission.RevokedReason != "reviewed" {
		t.Fatalf("dev-permission-revoke summary mismatch: %#v", revokeSummary)
	}
	registryStore, err = registry.NewSQLiteStore(context.Background(), filepath.Join(stateRoot, devRegistryFile))
	if err != nil {
		t.Fatal(err)
	}
	revokedState, err := registryStore.GetAuthorization(context.Background(), installSummary.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := registryStore.Close(); err != nil {
		t.Fatal(err)
	}
	if len(revokedState.Grants) != 1 || revokedState.Grants[0].RevokedAt == nil || revokedState.Plugin.RevokeEpoch <= grantedState.Plugin.RevokeEpoch {
		t.Fatalf("permission revoke state mismatch: %#v before=%#v", revokedState, grantedState.Plugin)
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
}

func TestCLIHostCapabilityGenerateClientRequiresVerifiedBundleAndDetectsStaleOutput(t *testing.T) {
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.client", "Generated Client Plugin", scaffoldDir); err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(scaffoldDir, "manifest.json")
	artifactRoot, pinFile, publicKeyFile := buildCLITestCapabilityArtifact(t, dir, manifestFile)
	outputFile := filepath.Join(dir, "generated", "client.ts")
	if _, err := captureCLIOutput(t, "host-capability", "generate-client", artifactRoot, pinFile, publicKeyFile, outputFile); err != nil {
		t.Fatalf("generate-client error = %v", err)
	}
	if _, err := captureCLIOutput(t, "host-capability", "generate-client", artifactRoot, pinFile, publicKeyFile, outputFile, "--check"); err != nil {
		t.Fatalf("generate-client --check error = %v", err)
	}
	if err := os.WriteFile(outputFile, []byte("stale client\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "host-capability", "generate-client", artifactRoot, pinFile, publicKeyFile, outputFile, "--check"); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("generate-client --check error = %v, want stale output", err)
	}
}

func TestCLIHostCapabilityVerifyRejectsLinkedArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name string
		link func(string, string) error
	}{
		{name: "symlink", link: os.Symlink},
		{name: "hardlink", link: os.Link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			scaffoldDir := filepath.Join(dir, "generated")
			if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.linked", "Generated Linked Plugin", scaffoldDir); err != nil {
				t.Fatal(err)
			}
			manifestFile := filepath.Join(scaffoldDir, "manifest.json")
			artifactRoot, pinFile, publicKeyFile := buildCLITestCapabilityArtifact(t, dir, manifestFile)
			var pin capabilitycontract.Pin
			if err := readStrictJSONFile(pinFile, &pin); err != nil {
				t.Fatal(err)
			}
			artifactFile := filepath.Join(artifactRoot, filepath.FromSlash(pin.ArtifactRef))
			outsideFile := filepath.Join(dir, "outside.schema.json")
			content, err := os.ReadFile(artifactFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(outsideFile, content, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(artifactFile); err != nil {
				t.Fatal(err)
			}
			if err := tc.link(outsideFile, artifactFile); err != nil {
				t.Fatal(err)
			}
			if _, err := captureCLIOutput(t, "host-capability", "verify", artifactRoot, pinFile, publicKeyFile); err == nil || !strings.Contains(err.Error(), "regular unlinked file") {
				t.Fatalf("verify linked artifact error = %v", err)
			}
		})
	}
}

func TestCLIDevInstallCapabilityFailureLeavesNoState(t *testing.T) {
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.atomic", "Generated Atomic Plugin", scaffoldDir); err != nil {
		t.Fatal(err)
	}
	artifactRoot, pinFile, publicKeyFile := buildCLITestCapabilityArtifact(t, dir, filepath.Join(scaffoldDir, "dist", "manifest.json"))
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
		t.Fatal(err)
	}
	var pin capabilitycontract.Pin
	if err := readStrictJSONFile(pinFile, &pin); err != nil {
		t.Fatal(err)
	}
	artifactFile := filepath.Join(artifactRoot, filepath.FromSlash(pin.ArtifactRef))
	if err := os.WriteFile(artifactFile, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "dev-install", stateRoot, packageFile, "--capability", artifactRoot, pinFile, publicKeyFile); err == nil {
		t.Fatal("dev-install accepted a tampered capability artifact")
	}
	if _, err := os.Lstat(stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed dev-install left state root behind: %v", err)
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
	if bridge.Path != "spec/plugin/bridge-v5.schema.json" || bridge.Version != version.BridgeSchemaVersion || bridge.SHA256 == "" {
		t.Fatalf("bridge contract mismatch: %#v", bridge)
	}
	openapi := contracts["plugin-platform-openapi"]
	if openapi.Version != version.PluginPlatformOpenAPIVersion || openapi.SHA256 == "" {
		t.Fatalf("openapi contract mismatch: %#v", openapi)
	}
	for _, contract := range []struct {
		id      string
		path    string
		version string
	}{
		{id: "release-metadata-schema", path: "spec/plugin/release-metadata-v5.schema.json", version: version.ReleaseMetadataSchemaVersion},
		{id: "source-policy-schema", path: "spec/plugin/source-policy-v1.schema.json", version: version.SourcePolicySchemaVersion},
		{id: "source-revocations-schema", path: "spec/plugin/source-revocations-v1.schema.json", version: version.SourceRevocationsSchemaVersion},
	} {
		got := contracts[contract.id]
		if got.Path != contract.path || got.Version != contract.version || got.SHA256 == "" {
			t.Fatalf("%s contract mismatch: %#v", contract.id, got)
		}
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
	manifest.Matrix.PluginHostProtocolVersion = "plugin-host-v999"
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

func TestCLIInspectDataReportsCatalogWithoutFileContents(t *testing.T) {
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.inspect", "Generated Inspect Plugin", scaffoldDir); err != nil {
		t.Fatal(err)
	}
	addLifecycleStorageToManifest(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
		t.Fatal(err)
	}
	installOutput, err := captureCLIOutput(t, "dev-install", stateRoot, packageFile)
	if err != nil {
		t.Fatal(err)
	}
	var installed devLifecycleSummary
	if err := json.Unmarshal(installOutput, &installed); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "dev-enable", stateRoot); err != nil {
		t.Fatal(err)
	}
	harness, _, err := loadDevHarness(context.Background(), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.pluginData.WriteFile(context.Background(), storage.FileWriteRequest{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "workspace",
		Path:             "notes/private.txt",
		Data:             []byte("secret contents"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}

	output, err := captureCLIOutput(t, "inspect-data", stateRoot, installed.PluginInstanceID)
	if err != nil {
		t.Fatalf("inspect-data command error = %v", err)
	}
	var summary dataInspectSummary
	if err := json.Unmarshal(output, &summary); err != nil {
		t.Fatalf("inspect-data output decode error = %v: %s", err, output)
	}
	if !summary.OK || summary.BindingCount != 1 || summary.NamespaceCount != 1 || summary.TotalUsageBytes != int64(len("secret contents")) {
		t.Fatalf("inspect-data summary mismatch: %#v", summary)
	}
	if summary.Namespaces[0].PluginInstanceID != installed.PluginInstanceID ||
		summary.Namespaces[0].StoreID != "workspace" ||
		summary.Namespaces[0].Kind != storage.StoreFiles ||
		summary.Namespaces[0].UsageBytes != int64(len("secret contents")) {
		t.Fatalf("inspect-data namespace mismatch: %#v", summary.Namespaces)
	}
	if bytes.Contains(output, []byte("secret contents")) {
		t.Fatalf("inspect-data leaked file contents: %s", output)
	}
	allOutput, err := captureCLIOutput(t, "inspect-data", stateRoot)
	if err != nil {
		t.Fatalf("inspect-data all command error = %v", err)
	}
	var allSummary dataInspectSummary
	if err := json.Unmarshal(allOutput, &allSummary); err != nil {
		t.Fatalf("inspect-data all output decode error = %v: %s", err, allOutput)
	}
	if allSummary.NamespaceCount != 1 || allSummary.PluginInstanceID != "" {
		t.Fatalf("inspect-data all summary mismatch: %#v", allSummary)
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

func buildCLITestCapabilityArtifact(t *testing.T, root, manifestFile string) (string, string, string) {
	t.Helper()
	raw, err := os.ReadFile(manifestFile)
	if err != nil {
		t.Fatal(err)
	}
	var plugin manifest.Manifest
	if err := json.Unmarshal(raw, &plugin); err != nil {
		t.Fatal(err)
	}
	if len(plugin.Methods) == 0 {
		t.Fatalf("capability fixture manifest mismatch: %#v", plugin)
	}
	method := plugin.Methods[0]
	responseSchema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           map[string]any{},
	}
	contract := capabilitycontract.Contract{
		SchemaVersion:     capabilitycontract.SchemaVersion,
		ContractID:        "example.capability.demo.v1",
		ContractVersion:   "1.0.0",
		PublisherID:       "example.contracts",
		CapabilityID:      "example.capability.demo",
		CapabilityVersion: "1.0.0",
		ClientName:        "ExampleDemoCapabilityClient",
		Methods: []capabilitycontract.Method{{
			Name:                "worker.echo",
			ClientMethod:        "echo",
			Effect:              string(method.Effect),
			Execution:           string(method.Execution),
			RequiredPermissions: []string{"demo.execute"},
			TargetFields:        []string{},
			TargetSchema:        method.RequestSchema,
			RequestTypeName:     "ExampleDemoEchoRequest",
			ResponseTypeName:    "ExampleDemoEchoResponse",
			RequestSchema:       method.RequestSchema,
			ResponseSchema:      responseSchema,
		}},
	}
	contractFile := filepath.Join(root, "host-capability.contract.json")
	privateKeyFile := filepath.Join(root, "host-capability.private.json")
	publicKeyFile := filepath.Join(root, "host-capability.public.json")
	configFile := filepath.Join(root, "host-capability.build.json")
	artifactRoot := filepath.Join(root, "host-capability-artifact")
	if err := writeJSONFile(contractFile, contract, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "keygen", "host-capability-test-key", privateKeyFile, publicKeyFile); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(configFile, hostCapabilityBuildConfig{
		ContractFile:             contractFile,
		PrivateKeyFile:           privateKeyFile,
		ArtifactBaseRef:          "capabilities/example/demo/v1.0.0",
		GeneratedAt:              "2026-07-13T00:00:00Z",
		SourceCommit:             strings.Repeat("a", 40),
		MinReDevPluginVersion:    version.CurrentMatrix().GoModuleVersion,
		SignaturePolicyEpoch:     "1",
		SignatureRevocationEpoch: "1",
	}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureCLIOutput(t, "host-capability", "build", configFile, artifactRoot); err != nil {
		t.Fatal(err)
	}
	pinFile := filepath.Join(artifactRoot, hostCapabilityPinFile)
	if _, err := captureCLIOutput(t, "host-capability", "verify", artifactRoot, pinFile, publicKeyFile); err != nil {
		t.Fatal(err)
	}
	var pin capabilitycontract.Pin
	if err := readStrictJSONFile(pinFile, &pin); err != nil {
		t.Fatal(err)
	}
	addLifecyclePermissionBindingToManifest(t, manifestFile, pin)
	clientFile := filepath.Join(root, "host-capability.client.ts")
	if _, err := captureCLIOutput(t, "host-capability", "generate-client", artifactRoot, pinFile, publicKeyFile, clientFile); err != nil {
		t.Fatal(err)
	}
	return artifactRoot, pinFile, publicKeyFile
}

func addLifecyclePermissionBindingToManifest(t *testing.T, filename string, pin capabilitycontract.Pin) {
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
		"binding_id": "demo",
		"contract":   pin,
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
	for _, field := range []string{
		"effect",
		"execution",
		"dangerous",
		"preflight_only",
		"confirmation",
		"cancel_policy",
		"request_schema",
		"response_schema",
	} {
		delete(method, field)
	}
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(updated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFileTreeDoesNotContain(t *testing.T, root string, forbidden []byte) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, forbidden) {
			t.Fatalf("%s contains forbidden bytes %q", path, forbidden)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func prefixLen(length int, maxLength int) int {
	if length < maxLength {
		return length
	}
	return maxLength
}
