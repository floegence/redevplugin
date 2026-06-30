package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		"schema_version": "redeven.plugin.manifest.v1",
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

	unsignedPackage := filepath.Join(dir, "unsigned.redeven-plugin")
	signedPackage := filepath.Join(dir, "signed.redeven-plugin")
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
	if summary.PluginID != "com.example.generated" || len(summary.Files) != 7 {
		t.Fatalf("scaffold summary mismatch: %#v", summary)
	}

	if _, err := captureCLIOutput(t, "validate", filepath.Join(scaffoldDir, "manifest.json")); err != nil {
		t.Fatalf("validate scaffold manifest error = %v", err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifestRaw, []byte(`"workers"`)) || !bytes.Contains(manifestRaw, []byte(`"worker.echo"`)) {
		t.Fatalf("scaffold manifest missing worker contract: %s", manifestRaw)
	}
	wasmRaw, err := os.ReadFile(filepath.Join(scaffoldDir, "workers", "backend.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(wasmRaw) < 8 || !bytes.Equal(wasmRaw[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		t.Fatalf("scaffold wasm artifact is invalid: %x", wasmRaw[:prefixLen(len(wasmRaw), 8)])
	}
	packageFile := filepath.Join(dir, "generated.redeven-plugin")
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

func writeCLITestFile(t *testing.T, filename string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func prefixLen(length int, maxLength int) int {
	if length < maxLength {
		return length
	}
	return maxLength
}
