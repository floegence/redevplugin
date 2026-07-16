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
		Package:              pkg,
		SourcePolicySnapshot: ptrSourcePolicy(sourcePolicyFixture(pkg, "test-key")),
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
		Package: pkg,
		SourcePolicySnapshot: &host.SourcePolicySnapshot{
			SchemaVersion:    "redevplugin.source_policy.v1",
			SourceID:         "community",
			SourceType:       host.PackageSourceRegistry,
			SourceClass:      host.PackageSourceClassCommunity,
			RequireSignature: false,
			UnsignedPolicy:   host.PackageUnsignedReviewRequired,
			InstallPolicy:    host.PackageInstallAllow,
			DowngradePolicy:  host.PackageDowngradeBlock,
			PolicyEpoch:      "1",
		},
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
		Package:              pkg,
		SourcePolicySnapshot: ptrSourcePolicy(sourcePolicyFixture(pkg, "test-key")),
	})
	if !errors.Is(err, ErrSignatureRequired) {
		t.Fatalf("VerifyPackageTrust() error = %v, want ErrSignatureRequired", err)
	}
}

func TestEd25519VerifierRejectsTamperedSignature(t *testing.T) {
	pkg, _, _, verifier := signedFixture(t)
	pkg.PackageSignature.Signature = pkg.PackageSignature.Signature[:len(pkg.PackageSignature.Signature)-2] + "AA"

	_, err := verifier.VerifyPackageTrust(context.Background(), host.PackageTrustVerificationRequest{
		Package:              pkg,
		SourcePolicySnapshot: ptrSourcePolicy(sourcePolicyFixture(pkg, "test-key")),
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
		Package:              pkg,
		SourcePolicySnapshot: ptrSourcePolicy(sourcePolicyFixture(pkg, "test-key")),
	})
	if !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("VerifyPackageTrust() error = %v, want ErrKeyRevoked", err)
	}
}

func TestEd25519VerifierAcceptsSignedReleaseMetadata(t *testing.T) {
	pkg, pub, priv, verifier := signedFixture(t)
	metadata := []byte(`{"schema_version":"redevplugin.release_metadata.v5","plugin_id":"com.example.trust","version":"1.0.0"}`)
	signature := ed25519.Sign(priv, metadata)
	release := releaseMetadataFixture(pkg, "test-key")

	result, err := verifier.VerifyReleaseMetadata(context.Background(), host.ReleaseMetadataVerificationRequest{
		ReleaseRef:               releaseRefFixture(pkg),
		Release:                  release,
		SourcePolicySnapshot:     sourcePolicyFixture(pkg, "test-key"),
		ReleaseMetadataBytes:     metadata,
		ReleaseMetadataSignature: signature,
	})
	if err != nil {
		t.Fatalf("VerifyReleaseMetadata() error = %v", err)
	}
	if result.Metadata["key_id"] != "test-key" || result.Metadata["verified_at"] == "" {
		t.Fatalf("metadata mismatch: %#v", result.Metadata)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d", len(pub))
	}
}

func TestEd25519VerifierRejectsTamperedReleaseMetadataSignature(t *testing.T) {
	pkg, _, priv, verifier := signedFixture(t)
	metadata := []byte(`{"schema_version":"redevplugin.release_metadata.v5","plugin_id":"com.example.trust","version":"1.0.0"}`)
	signature := ed25519.Sign(priv, metadata)
	metadata[0] = '['

	_, err := verifier.VerifyReleaseMetadata(context.Background(), host.ReleaseMetadataVerificationRequest{
		ReleaseRef:               releaseRefFixture(pkg),
		Release:                  releaseMetadataFixture(pkg, "test-key"),
		SourcePolicySnapshot:     sourcePolicyFixture(pkg, "test-key"),
		ReleaseMetadataBytes:     metadata,
		ReleaseMetadataSignature: signature,
	})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("VerifyReleaseMetadata() error = %v, want ErrSignatureInvalid", err)
	}
}

func TestEd25519VerifierRejectsRevokedReleaseMetadataKey(t *testing.T) {
	pkg, pub, priv, _ := signedFixture(t)
	metadata := []byte(`{"schema_version":"redevplugin.release_metadata.v5","plugin_id":"com.example.trust","version":"1.0.0"}`)
	signature := ed25519.Sign(priv, metadata)
	verifier := Ed25519Verifier{
		Keyring: StaticKeyring{Keys: []SigningKey{{
			Algorithm: AlgorithmEd25519,
			KeyID:     "test-key",
			PublicKey: pub,
			Revoked:   true,
		}}},
	}

	_, err := verifier.VerifyReleaseMetadata(context.Background(), host.ReleaseMetadataVerificationRequest{
		ReleaseRef:               releaseRefFixture(pkg),
		Release:                  releaseMetadataFixture(pkg, "test-key"),
		SourcePolicySnapshot:     sourcePolicyFixture(pkg, "test-key"),
		ReleaseMetadataBytes:     metadata,
		ReleaseMetadataSignature: signature,
	})
	if !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("VerifyReleaseMetadata() error = %v, want ErrKeyRevoked", err)
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

func releaseRefFixture(pkg pluginpkg.Package) host.PluginReleaseRef {
	return host.PluginReleaseRef{
		SourceID:              "official",
		ReleaseMetadataRef:    "plugins/example/com.example.trust/1.0.0/release.json",
		ReleaseMetadataSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PublisherID:           pkg.Manifest.Publisher.PublisherID,
		PluginID:              pkg.Manifest.PluginID(),
		Version:               pkg.Manifest.Version(),
		ExpectedHashes: host.PackageHashSet{
			PackageSHA256:  pkg.PackageHash,
			ManifestSHA256: pkg.ManifestHash,
			EntriesSHA256:  pkg.EntriesHash,
		},
	}
}

func releaseMetadataFixture(pkg pluginpkg.Package, keyID string) host.PluginPackageRelease {
	return host.PluginPackageRelease{
		SourceID:              "official",
		PublisherID:           pkg.Manifest.Publisher.PublisherID,
		PluginID:              pkg.Manifest.PluginID(),
		Version:               pkg.Manifest.Version(),
		ReleaseMetadataSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ReleaseMetadataSignature: &host.ReleaseMetadataSignature{
			Algorithm:         AlgorithmEd25519,
			KeyID:             keyID,
			SignatureRef:      "plugins/example/com.example.trust/1.0.0/release.json.sig",
			SourcePolicyEpoch: "1",
			RevocationEpoch:   "1",
		},
	}
}

func sourcePolicyFixture(pkg pluginpkg.Package, keyID string) host.SourcePolicySnapshot {
	return host.SourcePolicySnapshot{
		SchemaVersion:     "redevplugin.source_policy.v1",
		SourceID:          "official",
		SourceType:        host.PackageSourceRegistry,
		SourceClass:       host.PackageSourceClassOfficial,
		AllowedPublishers: []string{pkg.Manifest.Publisher.PublisherID},
		TrustedKeyIDs:     []string{keyID},
		RequireSignature:  true,
		InstallPolicy:     host.PackageInstallAllow,
		UnsignedPolicy:    host.PackageUnsignedBlock,
		DowngradePolicy:   host.PackageDowngradeBlock,
		PolicyEpoch:       "1",
		KeyRotationEpoch:  "1",
		RevocationEpoch:   "1",
		AssessedAt:        "2026-07-07T00:00:00Z",
	}
}

func ptrSourcePolicy(policy host.SourcePolicySnapshot) *host.SourcePolicySnapshot {
	return &policy
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.trust",
			"display_name": "Trust",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "trust.view", "kind": "view", "label": "Trust", "entry": "ui/index.html"}
		]
	}`)
	writeFile(t, filepath.Join(dir, "ui", "index.html"), `<!doctype html><title>Trust</title><body><main>Trust</main><script type="text/redevplugin-worker" src="assets/app.js"></script></body>`)
	writeFile(t, filepath.Join(dir, "ui", "assets", "app.js"), "void 0;")
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
