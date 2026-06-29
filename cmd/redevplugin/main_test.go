package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/trust"
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
	return buf.Bytes(), closeErr
}

func readCLITestPublicKey(t *testing.T, filename string) ed25519.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var doc signingPublicKeyFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(doc.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d", len(publicKey))
	}
	return ed25519.PublicKey(publicKey)
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
