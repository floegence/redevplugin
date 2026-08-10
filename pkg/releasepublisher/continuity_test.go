package releasepublisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func TestPublisherExtendsVerifiedPreviousReleaseTrust(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	config, keys := continuityTestConfig(t)

	firstPackage := copyExamplePlugin(t, "weather")
	firstOutput := finalizeContinuityTestRelease(t, ctx, config, keys, firstPackage, "")

	secondPackage := copyExamplePlugin(t, "weather")
	setTestPluginVersion(t, secondPackage, "9.9.10")
	secondOutput := finalizeContinuityTestRelease(t, ctx, config, keys, secondPackage, firstOutput)

	first := readTestReleaseSnapshot(t, firstOutput)
	second := readTestReleaseSnapshot(t, secondOutput)
	for _, locator := range []string{
		"sources/example_official/root/current.json",
		"sources/example_official/stable/policy/current.json",
		"sources/example_official/stable/policy/1.json",
		"sources/example_official/stable/revocation/current.json",
		"sources/example_official/stable/revocation/1.json",
	} {
		if !bytes.Equal(first.files[locator], second.files[locator]) {
			t.Fatalf("same-epoch trust document %q changed across releases", locator)
		}
	}

	firstCheckpoint := decodeTestCheckpoint(t, first.files["sources/example_official/signing-ledger/checkpoints/current.json"])
	secondCheckpoint := decodeTestCheckpoint(t, second.files["sources/example_official/signing-ledger/checkpoints/current.json"])
	if firstCheckpoint.TreeSize != 7 || secondCheckpoint.TreeSize != 9 {
		t.Fatalf("checkpoint sizes = %d -> %d, want 7 -> 9", firstCheckpoint.TreeSize, secondCheckpoint.TreeSize)
	}
	consistencyLocator := "sources/example_official/signing-ledger/proofs/consistency/" +
		sha256Hex(first.files["sources/example_official/signing-ledger/checkpoints/current.json"]) + "/" +
		sha256Hex(second.files["sources/example_official/signing-ledger/checkpoints/current.json"]) + ".json"
	proof, err := releasecontract.DecodeSigningLedgerConsistencyProof(second.files[consistencyLocator])
	if err != nil {
		t.Fatalf("decode consistency proof: %v", err)
	}
	ledgerKey, err := decodePublicKey(config.SigningLedger.PublicKeyV1)
	if err != nil {
		t.Fatal(err)
	}
	if err := releasecontract.VerifySigningLedgerConsistency(
		firstCheckpoint,
		secondCheckpoint,
		proof,
		releasecontract.Ed25519PublicKeyVerifier{config.SigningLedger.KeyID: ledgerKey},
	); err != nil {
		t.Fatalf("verify ledger consistency: %v", err)
	}
	if err := VerifyOutput(ctx, secondOutput); err != nil {
		t.Fatalf("verify continued output: %v", err)
	}

	thirdPackage := copyExamplePlugin(t, "weather")
	setTestPluginVersion(t, thirdPackage, "9.9.11")
	thirdOutput := finalizeContinuityTestRelease(t, ctx, config, keys, thirdPackage, secondOutput)
	third := readTestReleaseSnapshot(t, thirdOutput)
	thirdCheckpoint := decodeTestCheckpoint(t, third.files["sources/example_official/signing-ledger/checkpoints/current.json"])
	if thirdCheckpoint.TreeSize != 11 {
		t.Fatalf("third checkpoint size = %d, want 11", thirdCheckpoint.TreeSize)
	}
	if err := VerifyOutput(ctx, thirdOutput); err != nil {
		t.Fatalf("verify second continued output: %v", err)
	}
}

func TestPublisherRejectsInvalidPreviousReleaseContinuity(t *testing.T) {
	ctx := context.Background()

	t.Run("version rollback", func(t *testing.T) {
		config, keys := continuityTestConfig(t)
		firstPackage := copyExamplePlugin(t, "weather")
		setTestPluginVersion(t, firstPackage, "9.9.10")
		firstOutput := finalizeContinuityTestRelease(t, ctx, config, keys, firstPackage, "")
		candidate := copyExamplePlugin(t, "weather")
		setTestPluginVersion(t, candidate, "9.9.9")
		expectPreviousReleaseRejected(t, ctx, config, candidate, firstOutput)
	})

	t.Run("same epoch document change", func(t *testing.T) {
		config, keys := continuityTestConfig(t)
		firstOutput := finalizeContinuityTestRelease(t, ctx, config, keys, copyExamplePlugin(t, "weather"), "")
		config.GeneratedAt = "2026-08-02T00:00:00Z"
		candidate := copyExamplePlugin(t, "weather")
		setTestPluginVersion(t, candidate, "9.9.10")
		expectPreviousReleaseRejected(t, ctx, config, candidate, firstOutput)
	})

	t.Run("invalid previous signature", func(t *testing.T) {
		config, keys := continuityTestConfig(t)
		firstOutput := finalizeContinuityTestRelease(t, ctx, config, keys, copyExamplePlugin(t, "weather"), "")
		snapshot := readTestReleaseSnapshot(t, firstOutput)
		rootLocator := "sources/example_official/root/current.json"
		rootAsset := assetNameForTestLocator(t, snapshot.reference, rootLocator)
		rootRaw := append([]byte(nil), snapshot.files[rootLocator]...)
		rootRaw[len(rootRaw)/2] ^= 1
		if err := os.WriteFile(filepath.Join(firstOutput, rootAsset), rootRaw, 0o644); err != nil {
			t.Fatal(err)
		}
		candidate := copyExamplePlugin(t, "weather")
		setTestPluginVersion(t, candidate, "9.9.10")
		expectPreviousReleaseRejected(t, ctx, config, candidate, firstOutput)
	})

	t.Run("incomplete previous ledger", func(t *testing.T) {
		config, keys := continuityTestConfig(t)
		firstOutput := finalizeContinuityTestRelease(t, ctx, config, keys, copyExamplePlugin(t, "weather"), "")
		referencePath := mustSingleMatch(t, filepath.Join(firstOutput, "*.release-ref.json"))
		var reference PublisherReleaseRefV1
		if err := readClosedJSONFile(referencePath, &reference, 1<<20); err != nil {
			t.Fatal(err)
		}
		for index, file := range reference.Files {
			if !strings.Contains(file.Locator, "/signing-ledger/log/") {
				continue
			}
			if err := os.Remove(filepath.Join(firstOutput, file.AssetName)); err != nil {
				t.Fatal(err)
			}
			reference.Files = append(reference.Files[:index], reference.Files[index+1:]...)
			break
		}
		raw, err := json.MarshalIndent(reference, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(referencePath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		candidate := copyExamplePlugin(t, "weather")
		setTestPluginVersion(t, candidate, "9.9.10")
		expectPreviousReleaseRejected(t, ctx, config, candidate, firstOutput)
	})
}

func expectPreviousReleaseRejected(t *testing.T, ctx context.Context, config ConfigV1, packageDir, previousOutput string) {
	t.Helper()
	packageFile := buildUnsignedTestPackage(t, ctx, packageDir)
	if _, err := PrepareWithPrevious(ctx, config, packageFile, filepath.Join(t.TempDir(), "workspace"), previousOutput); err == nil {
		t.Fatal("PrepareWithPrevious accepted invalid release continuity")
	}
}

func buildUnsignedTestPackage(t *testing.T, ctx context.Context, packageDir string) string {
	t.Helper()
	var packageBuffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, packageDir, &packageBuffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	packageFile := filepath.Join(t.TempDir(), "plugin.redevplugin")
	if err := os.WriteFile(packageFile, packageBuffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return packageFile
}

func assetNameForTestLocator(t *testing.T, reference PublisherReleaseRefV1, locator string) string {
	t.Helper()
	for _, file := range reference.Files {
		if file.Locator == locator {
			return file.AssetName
		}
	}
	t.Fatalf("missing locator %q", locator)
	return ""
}

type testReleaseSnapshot struct {
	reference PublisherReleaseRefV1
	files     map[string][]byte
}

func readTestReleaseSnapshot(t *testing.T, output string) testReleaseSnapshot {
	t.Helper()
	referencePath := mustSingleMatch(t, filepath.Join(output, "*.release-ref.json"))
	var reference PublisherReleaseRefV1
	if err := readClosedJSONFile(referencePath, &reference, 1<<20); err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(reference.Files))
	for _, file := range reference.Files {
		raw, err := os.ReadFile(filepath.Join(output, file.AssetName))
		if err != nil {
			t.Fatal(err)
		}
		files[file.Locator] = raw
	}
	return testReleaseSnapshot{reference: reference, files: files}
}

func decodeTestCheckpoint(t *testing.T, raw []byte) releasecontract.SigningLedgerCheckpointV1 {
	t.Helper()
	checkpoint, err := releasecontract.DecodeSigningLedgerCheckpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func continuityTestConfig(t *testing.T) (ConfigV1, map[string]ed25519.PrivateKey) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, ledgerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := ConfigV1{
		SchemaVersion: ConfigSchemaVersion, SourceID: "example_official", Channel: "stable",
		SourceType: "registry", SourceClass: "official", GeneratedAt: "2026-08-01T00:00:00Z", ExpiresAt: "2026-10-30T00:00:00Z",
		Root:                 PublicKeyV1{Algorithm: "ed25519", KeyID: "example_root", PublicKey: base64.StdEncoding.EncodeToString(rootPublic)},
		Signing:              PublicKeyV1{Algorithm: "ed25519", KeyID: "example_signing", PublicKey: base64.StdEncoding.EncodeToString(signingPublic)},
		SigningLedger:        SigningLedgerConfigV1{LogID: "example_signing_log", PublicKeyV1: PublicKeyV1{Algorithm: "ed25519", KeyID: "example_ledger", PublicKey: base64.StdEncoding.EncodeToString(ledgerPublic)}},
		AllowedArtifactHosts: []string{"github.com"}, MinReDevPluginVersion: "0.7.22", Distribution: "registry_ref", HostRequirements: []releasecontract.ReleaseHostRequirement{},
	}
	return config, map[string]ed25519.PrivateKey{
		config.Root.KeyID: rootPrivate, config.Signing.KeyID: signingPrivate, config.SigningLedger.KeyID: ledgerPrivate,
	}
}

func finalizeContinuityTestRelease(
	t *testing.T,
	ctx context.Context,
	config ConfigV1,
	keys map[string]ed25519.PrivateKey,
	packageDir string,
	previousOutput string,
) string {
	t.Helper()
	var packageBuffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, packageDir, &packageBuffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	packageFile := filepath.Join(t.TempDir(), "plugin.redevplugin")
	if err := os.WriteFile(packageFile, packageBuffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(t.TempDir(), "workspace")
	status, err := PrepareWithPrevious(ctx, config, packageFile, workspace, previousOutput)
	if err != nil {
		t.Fatalf("prepare release: %v", err)
	}
	for attempts := 0; status.PendingRequests > 0 && attempts < 32; attempts++ {
		entries, err := os.ReadDir(filepath.Join(workspace, "requests"))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			raw, err := os.ReadFile(filepath.Join(workspace, "requests", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			request, err := DecodeExternalSignerRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := hex.DecodeString(request.SigningPreimageSHA256)
			if err != nil {
				t.Fatal(err)
			}
			response := ExternalSignerResponseV1{
				SchemaVersion: ExternalSignerResponseSchemaVersion, RequestID: request.RequestID, Usage: request.Usage,
				KeyID: request.KeyID, SubjectIdentitySHA256: request.SubjectIdentitySHA256,
				SigningPreimageSHA256: request.SigningPreimageSHA256, Algorithm: releasecontract.SignatureAlgorithmEd25519,
				Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(keys[request.KeyID], digest)),
			}
			responseRaw, err := CanonicalExternalSignerResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			status, err = ApplySignature(ctx, workspace, responseRaw)
			if err != nil {
				t.Fatalf("apply %s signature: %v", request.Usage, err)
			}
		}
	}
	if status.PendingRequests != 0 || status.Phase != "complete" {
		t.Fatalf("publisher status = %#v", status)
	}
	output := filepath.Join(t.TempDir(), "release")
	if _, err := Finalize(ctx, workspace, output); err != nil {
		t.Fatalf("finalize release: %v", err)
	}
	return output
}

func setTestPluginVersion(t *testing.T, packageDir, version string) {
	t.Helper()
	manifestPath := filepath.Join(packageDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["plugin"].(map[string]any)["version"] = version
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
