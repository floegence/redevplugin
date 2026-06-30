package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
)

func TestEd25519VerifierAcceptsSignedVerifiedPackage(t *testing.T) {
	pkg, pub, _, verifier := signedFixture(t)

	result, err := verifier.VerifyPackageTrust(context.Background(), host.PackageTrustVerificationRequest{
		Package:             pkg,
		RequestedTrustState: registry.TrustVerified,
	})
	if err != nil {
		t.Fatalf("VerifyPackageTrust() error = %v", err)
	}
	if result.TrustState != registry.TrustVerified {
		t.Fatalf("TrustState = %s", result.TrustState)
	}
	if result.Metadata["trust.key_id"] != "test-key" || result.Metadata["trust.package_hash"] != pkg.PackageHash || result.Metadata["trust.verified_at"] == "" {
		t.Fatalf("metadata mismatch: %#v", result.Metadata)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d", len(pub))
	}
}

func TestEd25519VerifierAllowsReviewStateWithoutSignature(t *testing.T) {
	pkg := unsignedFixturePackage(t)
	verifier := Ed25519Verifier{}

	result, err := verifier.VerifyPackageTrust(context.Background(), host.PackageTrustVerificationRequest{
		Package:             pkg,
		RequestedTrustState: registry.TrustNeedsReview,
	})
	if err != nil {
		t.Fatalf("VerifyPackageTrust() error = %v", err)
	}
	if result.TrustState != registry.TrustNeedsReview {
		t.Fatalf("TrustState = %s", result.TrustState)
	}
}

func TestEd25519VerifierRejectsMissingSignatureForVerifiedPackage(t *testing.T) {
	pkg := unsignedFixturePackage(t)
	verifier := Ed25519Verifier{Keyring: StaticKeyring{}}

	_, err := verifier.VerifyPackageTrust(context.Background(), host.PackageTrustVerificationRequest{
		Package:             pkg,
		RequestedTrustState: registry.TrustVerified,
	})
	if !errors.Is(err, ErrSignatureRequired) {
		t.Fatalf("VerifyPackageTrust() error = %v, want ErrSignatureRequired", err)
	}
}

func TestEd25519VerifierRejectsTamperedSignature(t *testing.T) {
	pkg, _, _, verifier := signedFixture(t)
	pkg.PackageSignature.Signature = pkg.PackageSignature.Signature[:len(pkg.PackageSignature.Signature)-2] + "AA"

	_, err := verifier.VerifyPackageTrust(context.Background(), host.PackageTrustVerificationRequest{
		Package:             pkg,
		RequestedTrustState: registry.TrustVerified,
	})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("VerifyPackageTrust() error = %v, want ErrSignatureInvalid", err)
	}
}

func TestEd25519VerifierRejectsRevokedKey(t *testing.T) {
	pkg, pub, _, _ := signedFixture(t)
	verifier := Ed25519Verifier{
		Keyring: StaticKeyring{Keys: []SigningKey{{
			Algorithm: AlgorithmEd25519,
			KeyID:     "test-key",
			PublicKey: pub,
			Revoked:   true,
		}}},
	}

	_, err := verifier.VerifyPackageTrust(context.Background(), host.PackageTrustVerificationRequest{
		Package:             pkg,
		RequestedTrustState: registry.TrustVerified,
	})
	if !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("VerifyPackageTrust() error = %v, want ErrKeyRevoked", err)
	}
}

func TestSignatureForPackageProducesCanonicalPayload(t *testing.T) {
	pkg, _, priv, _ := signedFixture(t)
	signedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	sig, err := SignatureForPackage(pkg, "test-key", "", "", priv, signedAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := CanonicalPackageSignaturePayload(sig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["signature"]; ok {
		t.Fatal("canonical signature payload must not include signature bytes")
	}
	if decoded["package_hash"] != pkg.PackageHash || decoded["signed_at"] != signedAt.Format(time.RFC3339) {
		t.Fatalf("payload mismatch: %s", payload)
	}
}

func signedFixture(t *testing.T) (pluginpkg.Package, ed25519.PublicKey, ed25519.PrivateKey, Ed25519Verifier) {
	t.Helper()
	pkg := unsignedFixturePackage(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignatureForPackage(pkg, "test-key", "", "", priv, time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	pkg.PackageSignature = &sig
	verifier := Ed25519Verifier{
		Keyring: StaticKeyring{Keys: []SigningKey{{
			Algorithm: AlgorithmEd25519,
			KeyID:     "test-key",
			PublicKey: pub,
			Metadata:  map[string]string{"source": "unit-test"},
		}}},
		Now: func() time.Time {
			return time.Date(2026, 6, 30, 12, 30, 0, 0, time.UTC)
		},
	}
	return pkg, pub, priv, verifier
}

func unsignedFixturePackage(t *testing.T) pluginpkg.Package {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.trust",
			"display_name": "Trust",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "trust.activity", "kind": "activity", "label": "Trust", "entry": "ui/index.html"}
		]
	}`)
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Trust</title>")
	var buf bytes.Buffer
	pkg, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	return pkg
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
