package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/releasepublisher"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/secrets"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/settings"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"github.com/floegence/redevplugin/v3/pkg/trust"
	"github.com/floegence/redevplugin/v3/pkg/version"
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
		"message":   "hello",
	}); err != nil {
		t.Fatalf("scaffold echo response schema rejected valid data: %v", err)
	}
	if err := compiled.ValidateResponse(map[string]any{
		"method":          "worker.echo",
		"worker_id":       "backend",
		"backend":         "executed wasm worker scaffold",
		"transport":       "rust runtime ipc",
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
		"schema_version": "redevplugin.manifest.v9",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.cli",
			"display_name": "CLI",
			"version": "1.0.0"
		},
		"api": {"major": 1, "required_features": [], "optional_features": []},
		"permissions": [],
		"presentation": {"locales": {"default": "en-US"}},
		"surfaces": [
			{"surface_id": "cli.view", "kind": "view", "label": "CLI", "entry": "ui/index.html"}
		],
		"workers": [],
		"methods": []
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

	signedPkg, err := pluginpkg.ReadFile(context.Background(), signedPackage, pluginpkg.DefaultReadLimits())
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
	if installSummary.TrustState != registry.TrustVerified || installSummary.EnableState != registry.EnableEnabled {
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
	if summary.PluginID != "com.example.generated" || len(summary.Files) != 15 {
		t.Fatalf("scaffold summary mismatch: %#v", summary)
	}

	if _, err := captureCLIOutput(t, "validate", filepath.Join(scaffoldDir, "dist", "manifest.json")); err != nil {
		t.Fatalf("validate scaffold manifest error = %v", err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema_version": "redevplugin.manifest.v9"`, `"api": {`, `"presentation": {`} {
		if !bytes.Contains(manifestRaw, []byte(want)) {
			t.Fatalf("scaffold manifest missing current protocol %q: %s", want, manifestRaw)
		}
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
	if bytes.Contains(appRaw, []byte(`/^[A-Za-z0-9]`)) {
		t.Fatal("scaffold app.js contains a regex literal that the closed classic-worker parser cannot admit")
	}
	for _, sourcePath := range []string{"ui/src/app.tsx", "worker/src/lib.rs", "worker/Cargo.toml", "package.json", "tsconfig.json", "scripts/build.mjs", "README.md"} {
		if _, err := os.Stat(filepath.Join(scaffoldDir, filepath.FromSlash(sourcePath))); err != nil {
			t.Fatalf("editable scaffold source %s is missing: %v", sourcePath, err)
		}
	}
	packageJSONRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"check"`, `ui/src/app.tsx`, `--jsx=automatic`, `@floegence/redevplugin-ui`} {
		if !bytes.Contains(packageJSONRaw, []byte(want)) {
			t.Fatalf("scaffold package.json missing %q: %s", want, packageJSONRaw)
		}
	}
	wasmRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "dist", "workers", "backend.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(wasmRaw) < 8 || !bytes.Equal(wasmRaw[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		t.Fatalf("scaffold wasm artifact is invalid: %x", wasmRaw[:prefixLen(len(wasmRaw), 8)])
	}
	if !bytes.Contains(wasmRaw, []byte("redevplugin.io")) || !bytes.Contains(wasmRaw, []byte("rdp_call_v1")) {
		t.Fatal("scaffold wasm artifact does not exercise the Worker API 1 imports")
	}
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldDir, "dist"), packageFile); err != nil {
		t.Fatalf("package scaffold error = %v", err)
	}
	generatedPackage, err := pluginpkg.ReadFile(context.Background(), packageFile, pluginpkg.DefaultReadLimits())
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
	if _, err := captureCLIOutput(t, "install-local", packageFile); !errors.Is(err, host.ErrFeatureNotConfigured) {
		t.Fatalf("install-local scaffold package error = %v, want ErrFeatureNotConfigured", err)
	}
	for _, action := range []string{"enable", "disable", "uninstall"} {
		if _, err := captureCLIOutput(t, action, packageFile); !errors.Is(err, host.ErrFeatureNotConfigured) {
			t.Fatalf("%s scaffold package error = %v, want ErrFeatureNotConfigured", action, err)
		}
	}

	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated", "Generated Plugin", scaffoldDir); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("scaffold non-empty dir error = %v, want not empty", err)
	}
}

func TestCLIScaffoldRunsGeneratedWorkerThroughBuiltRustRuntime(t *testing.T) {
	repoRoot := cliRepoRoot(t)
	runtimePath := buildExamplesRuntime(t, repoRoot)

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
	adapters := newTestEphemeralCLIAdapters(t, ctx, dir)
	runtimeModule, err := newCommandRuntimeModule(
		ctx,
		runtimePath,
		dir,
		mustInspectCommandRuntimeArtifact(t, runtimePath),
		15*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	adapters.Runtime = runtimeModule
	h, err := host.Open(ctx, adapters)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	health, err := h.StartRuntime(ctx, host.StartRuntimeRequest{
		Target: mustCurrentCommandRuntimeTarget(t),
	})
	if err != nil {
		diagnostics, diagnosticsErr := h.ListDiagnosticEvents(ctx, host.ListDiagnosticEventsRequest{Limit: 50})
		t.Fatalf("StartRuntime() error = %v, diagnostics = %#v (error = %v)", err, diagnostics, diagnosticsErr)
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
		stopCtx, cancel := context.WithTimeout(cliContext(context.Background()), 3*time.Second)
		defer cancel()
		if err := h.StopRuntime(stopCtx); err != nil {
			t.Errorf("StopRuntime() error = %v", err)
		}
	})

	installed, err := host.ImportLocalPackageBytes(ctx, h, "plugini_cli_test", packageBytes)
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	if installed.EnableState != registry.EnableEnabled {
		t.Fatalf("installed enable state = %q, want %q", installed.EnableState, registry.EnableEnabled)
	}
	now := time.Now().UTC()
	bootstrap, err := h.OpenSurface(ctx, host.OpenSurfaceRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		SurfaceID:                  "com.example.generated.runtime.view",
		SurfaceInstanceID:          "surface_generated_runtime",

		Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	prepared, err := h.PrepareSurface(ctx, host.PrepareSurfaceRequest{
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

func TestInspectCommandRuntimeArtifactCapturesExactBytes(t *testing.T) {
	runtimePath := filepath.Join(t.TempDir(), "redevplugin-runtime")
	content := []byte("runtime artifact\n")
	if err := os.WriteFile(runtimePath, content, 0o700); err != nil {
		t.Fatal(err)
	}
	target := mustCurrentCommandRuntimeTarget(t)
	identity, err := inspectCommandRuntimeArtifact(runtimePath, target)
	if err != nil {
		t.Fatalf("inspectCommandRuntimeArtifact() error = %v", err)
	}
	if err := os.WriteFile(runtimePath, []byte("replaced runtime artifact\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if identity.PlatformVersion().String() != version.CurrentPlatformVersion() ||
		identity.Target().String() != target.String() ||
		identity.BinarySHA256().String() != fmt.Sprintf("%x", sum) {
		t.Fatalf("runtime artifact identity mismatch: %#v", identity)
	}
}

func TestCommandRuntimeModuleRejectsBinaryReplacedAfterInspection(t *testing.T) {
	if goruntime.GOOS != "linux" && goruntime.GOOS != "darwin" {
		t.Skip("verified runtime executable admission is unsupported on this platform")
	}
	runtimePath := filepath.Join(t.TempDir(), "redevplugin-runtime")
	original, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimePath, original, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := inspectCommandRuntimeArtifact(runtimePath, mustCurrentCommandRuntimeTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimePath, append(original, '\n'), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = newCommandRuntimeModule(context.Background(), runtimePath, t.TempDir(), identity, time.Second)
	if !errors.Is(err, host.ErrRuntimeArtifactIdentityMismatch) {
		t.Fatalf("newCommandRuntimeModule(replaced binary) error = %v, want %v", err, host.ErrRuntimeArtifactIdentityMismatch)
	}
}

func TestInspectCommandRuntimeArtifactRejectsUnsupportedTarget(t *testing.T) {
	runtimePath := filepath.Join(t.TempDir(), "redevplugin-runtime")
	if err := os.WriteFile(runtimePath, []byte("runtime artifact\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := inspectCommandRuntimeArtifact(runtimePath, runtimetarget.Target(255))
	if !errors.Is(err, host.ErrRuntimeArtifactIdentityInvalid) {
		t.Fatalf("inspectCommandRuntimeArtifact() error = %v, want %v", err, host.ErrRuntimeArtifactIdentityInvalid)
	}
}

func newTestEphemeralCLIAdapters(t *testing.T, ctx context.Context, stateRoot string) host.Config {
	t.Helper()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	config, err := newEphemeralCLIAdapters(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func mustInspectCommandRuntimeArtifact(t *testing.T, path string) host.RuntimeArtifactIdentity {
	t.Helper()
	identity, err := inspectCommandRuntimeArtifact(path, mustCurrentCommandRuntimeTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func mustCurrentCommandRuntimeTarget(t *testing.T) runtimetarget.Target {
	t.Helper()
	target, err := runtimetarget.Current()
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestCLIDevLifecyclePersistsGeneratedPluginState(t *testing.T) {
	ctx := cliContext(context.Background())
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.lifecycle", "Generated Lifecycle Plugin", scaffoldDir); err != nil {
		t.Fatalf("scaffold command error = %v", err)
	}
	makeScaffoldUIOnly(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
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
	if installSummary.EnableState != registry.EnableEnabled || installSummary.StateRoot != stateRoot || installSummary.PluginDataRoot != filepath.Join(stateRoot, devPluginDataDir) {
		t.Fatalf("dev-install summary mismatch: %#v", installSummary)
	}
	for _, filename := range []string{devPackageFile, "control.sqlite", devSecretsFile} {
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
	harness, record, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableEnabled {
		t.Fatalf("Host record after install = %#v", record)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
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
	if uninstallSummary.EnableState != registry.EnableDisabledByUser {
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
	makeScaffoldUIOnly(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
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
	snapshot, err := harness.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID, Scope: sessionctx.ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ValuesRevision != 1 || snapshot.Values["accent_mode"] != "teal" || snapshot.Values["sync_enabled"] != true {
		t.Fatalf("settings defaults mismatch: %#v", snapshot)
	}
	patched, err := harness.host.PatchPluginSettings(ctx, host.PatchSettingsRequest{
		PluginInstanceID:       plugin.PluginInstanceID,
		Scope:                  sessionctx.ScopeUser,
		ExpectedValuesRevision: snapshot.ValuesRevision,
		Set:                    map[string]any{"accent_mode": "amber", "sync_enabled": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.host.PatchPluginSettings(ctx, host.PatchSettingsRequest{
		PluginInstanceID:       plugin.PluginInstanceID,
		Scope:                  sessionctx.ScopeUser,
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
	restored, err := reopened.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID, Scope: sessionctx.ScopeUser})
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
	secretRecords, err := secretStore.List(ctx, secrets.ListRequest{PluginInstanceID: installSummary.PluginInstanceID})
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
	makeScaffoldUIOnly(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
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
	if _, err := harness.host.WritePluginDataFile(ctx, host.WritePluginDataFileRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		Scope:            sessionctx.ScopeUser,
		StoreID:          "workspace",
		Path:             "notes/exported.txt",
		Data:             []byte("original data"),
	}); err != nil {
		t.Fatalf("WriteFile(original) error = %v", err)
	}
	snapshot, err := harness.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID, Scope: sessionctx.ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	exportedSettings, err := harness.host.PatchPluginSettings(ctx, host.PatchSettingsRequest{
		PluginInstanceID:       plugin.PluginInstanceID,
		Scope:                  sessionctx.ScopeUser,
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
	session, err := sessionctx.Require(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertFileTreeDoesNotContain(t, filepath.Join(
		stateRoot,
		devPluginDataDir,
		"objects",
		"user",
		session.OwnerEnvHash,
		session.OwnerUserHash,
		exportSummary.PluginInstanceID,
		exportSummary.BundleRef,
	), []byte("api_token"))

	harness, plugin, err = loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.host.WritePluginDataFile(ctx, host.WritePluginDataFileRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		Scope:            sessionctx.ScopeUser,
		StoreID:          "workspace",
		Path:             "notes/exported.txt",
		Data:             []byte("mutated data"),
	}); err != nil {
		t.Fatalf("WriteFile(mutated) error = %v", err)
	}
	mutatedSettings, err := harness.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID, Scope: sessionctx.ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.host.PatchPluginSettings(ctx, host.PatchSettingsRequest{
		PluginInstanceID:       plugin.PluginInstanceID,
		Scope:                  sessionctx.ScopeUser,
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
	read, err := harness.host.ReadPluginDataFile(ctx, host.ReadPluginDataFileRequest{
		PluginInstanceID: installSummary.PluginInstanceID,
		Scope:            sessionctx.ScopeUser,
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
	importedSettings, err := harness.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: plugin.PluginInstanceID, Scope: sessionctx.ScopeUser})
	if err != nil {
		t.Fatalf("Get(imported settings) error = %v", err)
	}
	if importedSettings.Values["accent_mode"] != exportedSettings.Values["accent_mode"] ||
		importedSettings.Values["sync_enabled"] != exportedSettings.Values["sync_enabled"] {
		t.Fatalf("import did not restore settings: %#v want %#v", importedSettings, exportedSettings)
	}
	secretRecords, err := harness.secretStore.List(ctx, secrets.ListRequest{PluginInstanceID: plugin.PluginInstanceID, BoundOnly: true})
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
	harness, _, err = loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := harness.host.InspectPluginData(ctx, host.InspectPluginDataRequest{PluginInstanceID: plugin.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	if len(inspection.Objects) != 0 {
		t.Fatalf("deleted export remains in catalog: %#v", inspection.Objects)
	}
	if _, err := captureCLIOutput(t, "dev-import-data", stateRoot); err == nil {
		t.Fatal("dev-import-data accepted a missing bundle ref")
	}
	if _, err := captureCLIOutput(t, "dev-export-data", stateRoot, "unexpected"); err == nil {
		t.Fatal("dev-export-data accepted an unexpected argument")
	}
}

func TestCLIDevLifecyclePersistsPermissionGrants(t *testing.T) {
	ctx := cliContext(context.Background())
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.permissions", "Generated Permissions Plugin", scaffoldDir); err != nil {
		t.Fatalf("scaffold command error = %v", err)
	}
	makeScaffoldUIOnly(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
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
	harness, grantedPlugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	grantedRecords, err := harness.host.ListPermissionGrants(ctx, host.ListPermissionGrantsRequest{PluginInstanceID: installSummary.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	if len(grantedRecords) != 1 || grantedRecords[0].PermissionID != "demo.execute" || grantedPlugin.PolicyRevision <= installSummary.PolicyRevision {
		t.Fatalf("authorization state not persisted after grant: records=%#v plugin=%#v install=%#v", grantedRecords, grantedPlugin, installSummary)
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
	harness, revokedPlugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	revokedRecords, err := harness.host.ListPermissionGrants(ctx, host.ListPermissionGrantsRequest{PluginInstanceID: installSummary.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	if len(revokedRecords) != 1 || revokedRecords[0].RevokedAt == nil || revokedPlugin.RevokeEpoch <= grantedPlugin.RevokeEpoch {
		t.Fatalf("permission revoke state mismatch: records=%#v plugin=%#v before=%#v", revokedRecords, revokedPlugin, grantedPlugin)
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

func TestCLIVersionPrintsCurrentPlatformIdentity(t *testing.T) {
	output, err := captureCLIOutput(t, "version")
	if err != nil {
		t.Fatalf("version command error = %v", err)
	}
	var identity platformVersionSummary
	if err := json.Unmarshal(output, &identity); err != nil {
		t.Fatalf("version output decode error = %v: %s", err, output)
	}
	if identity.PlatformVersion != version.CurrentPlatformVersion() || identity.PluginAPI != 1 || identity.InternalWire != 1 {
		t.Fatalf("version identity mismatch: %#v", identity)
	}
}

func TestReleaseVerifyPresentationInspectionJSONContract(t *testing.T) {
	summary := presentationInspectionSummary{
		OK:           true,
		Phase:        "verified",
		Output:       "/tmp/release",
		Presentation: manifest.PresentationCatalog{DefaultLocale: "en-US", Locales: []manifest.PresentationLocale{}},
		PresentationIcon: &releasepublisher.PresentationIconEvidenceV1{
			SchemaVersion: releasepublisher.PresentationIconEvidenceSchemaVersion,
			Path:          "ui/assets/plugin.png", MediaType: "image/png", Width: 128, Height: 128,
			SHA256: "sha256:" + strings.Repeat("a", 64), Size: 1024,
		},
		ManifestSHA256:     "sha256:manifest",
		PresentationSHA256: "sha256:presentation",
		VerifierVersion:    "1.0.0",
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]json.RawMessage
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"ok", "phase", "output", "presentation", "presentation_icon", "manifest_sha256", "presentation_sha256", "verifier_version",
	} {
		value, exists := output[field]
		if !exists || len(value) == 0 || string(value) == `""` || string(value) == "null" {
			t.Fatalf("release verify JSON field %q = %s", field, value)
		}
	}
	if len(output) != 8 {
		t.Fatalf("release verify JSON fields = %#v", output)
	}
}

func TestReleaseIconExtractionJSONContract(t *testing.T) {
	summary := presentationIconExtractionSummary{
		OK: true, Phase: "presentation_icon_extracted", Output: "/tmp/release", IconOutput: "/tmp/icon.png",
		PresentationIcon: releasepublisher.PresentationIconEvidenceV1{
			SchemaVersion: releasepublisher.PresentationIconEvidenceSchemaVersion,
			Path:          "ui/assets/plugin.png", MediaType: "image/png", Width: 128, Height: 128,
			SHA256: "sha256:" + strings.Repeat("a", 64), Size: 1024,
		},
		VerifierVersion: "1.0.0",
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]json.RawMessage
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"ok", "phase", "output", "icon_output", "presentation_icon", "verifier_version",
	} {
		value, exists := output[field]
		if !exists || len(value) == 0 || string(value) == `""` || string(value) == "null" {
			t.Fatalf("release icon extraction JSON field %q = %s", field, value)
		}
	}
	if len(output) != 6 {
		t.Fatalf("release icon extraction JSON fields = %#v", output)
	}
}

func TestCLIInspectDataReportsCatalogWithoutFileContents(t *testing.T) {
	ctx := cliContext(context.Background())
	dir := t.TempDir()
	scaffoldDir := filepath.Join(dir, "generated")
	stateRoot := filepath.Join(dir, "state")
	packageFile := filepath.Join(dir, "generated.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.generated.inspect", "Generated Inspect Plugin", scaffoldDir); err != nil {
		t.Fatal(err)
	}
	makeScaffoldUIOnly(t, filepath.Join(scaffoldDir, "dist", "manifest.json"))
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
	harness, _, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.host.WritePluginDataFile(ctx, host.WritePluginDataFileRequest{
		PluginInstanceID: installed.PluginInstanceID,
		Scope:            sessionctx.ScopeUser,
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

func makeScaffoldUIOnly(t *testing.T, filename string) {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["workers"] = []any{}
	methods, _ := document["methods"].([]any)
	uiMethods := make([]any, 0, len(methods))
	for _, item := range methods {
		method, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("manifest method has unexpected shape: %#v", item)
		}
		route, _ := method["route"].(map[string]any)
		if route["kind"] == "worker" || strings.TrimSpace(fmt.Sprint(method["worker_id"])) != "" {
			continue
		}
		uiMethods = append(uiMethods, method)
	}
	if len(uiMethods) == 0 {
		document["methods"] = []any{}
	} else {
		document["methods"] = uiMethods
	}
	updated, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, updated, 0o644); err != nil {
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
			"options": []map[string]string{
				{"value": "teal", "label": "Teal"},
				{"value": "amber", "label": "Amber"},
				{"value": "indigo", "label": "Indigo"},
			},
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
