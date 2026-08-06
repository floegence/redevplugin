package releasepublisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func TestPublisherWorkspaceCompletesExternalSigningFlow(t *testing.T) {
	ctx := context.Background()
	output := finalizeTestRelease(t, ctx, filepath.Join("..", "..", "examples", "plugins", "weather"))
	verified, err := VerifyAndInspectOutput(ctx, output)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Presentation.DefaultLocale != "en-US" || len(verified.Presentation.Locales) == 0 ||
		verified.Presentation.Locales[0].PluginName != "Weather" || verified.ManifestSHA256 == "" || verified.PresentationSHA256 == "" {
		t.Fatalf("verified presentation evidence = %#v", verified)
	}
	if matches, _ := filepath.Glob(filepath.Join(output, "weather-*.release-ref.json")); len(matches) != 1 {
		t.Fatalf("release ref assets = %#v", matches)
	}
}

func finalizeTestRelease(t *testing.T, ctx context.Context, packageDir string) string {
	t.Helper()
	var packageBuffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, packageDir, &packageBuffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	packageFile := filepath.Join(t.TempDir(), "plugin.redevplugin")
	if err := os.WriteFile(packageFile, packageBuffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
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
		AllowedArtifactHosts: []string{"github.com"}, MinReDevPluginVersion: "0.6.23", Distribution: "registry_ref", HostRequirements: []releasecontract.ReleaseHostRequirement{},
	}
	workspace := filepath.Join(t.TempDir(), "workspace")
	status, err := Prepare(ctx, config, packageFile, workspace)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PrivateKey{config.Root.KeyID: rootPrivate, config.Signing.KeyID: signingPrivate, config.SigningLedger.KeyID: ledgerPrivate}
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
				t.Fatal(err)
			}
		}
	}
	if status.PendingRequests != 0 || status.Phase != "complete" {
		t.Fatalf("publisher status = %#v", status)
	}
	output := filepath.Join(t.TempDir(), "release")
	if _, err := Finalize(ctx, workspace, output); err != nil {
		t.Fatal(err)
	}
	return output
}

func copyExamplePlugin(t *testing.T, name string) string {
	t.Helper()
	source := filepath.Join("..", "..", "examples", "plugins", name)
	destination := filepath.Join(t.TempDir(), name)
	if err := copyTestTree(source, destination); err != nil {
		t.Fatal(err)
	}
	return destination
}

func copyTestTree(source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		destinationPath := filepath.Join(destination, entry.Name())
		if entry.IsDir() {
			if err := copyTestTree(sourcePath, destinationPath); err != nil {
				return err
			}
			continue
		}
		content, err := os.ReadFile(sourcePath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(destinationPath, content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func mustDecodeHex(t *testing.T, encoded string) []byte {
	t.Helper()
	value, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustSingleMatch(t *testing.T, pattern string) string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches for %q = %#v", pattern, matches)
	}
	return matches[0]
}

func TestVerifiedOutputExtractsBoundPresentationIcon(t *testing.T) {
	ctx := context.Background()
	packageDir := copyExamplePlugin(t, "weather")
	icon := mustDecodeHex(t, "89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da6364f80f00010501012718e3660000000049454e44ae426082")
	manifestPath := filepath.Join(packageDir, "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(manifestRaw, &document); err != nil {
		t.Fatal(err)
	}
	document["presentation"].(map[string]any)["icon"] = map[string]any{"path": "ui/assets/plugin.png"}
	manifestRaw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "ui", "assets", "plugin.png"), icon, 0o644); err != nil {
		t.Fatal(err)
	}

	output := finalizeTestRelease(t, ctx, packageDir)
	verified, err := VerifyAndInspectOutput(ctx, output)
	if err != nil {
		t.Fatal(err)
	}
	if verified.PresentationIcon == nil {
		t.Fatal("verified release output did not include presentation icon evidence")
	}
	wantDigest := sha256.Sum256(icon)
	if got := verified.PresentationIcon; got.SchemaVersion != PresentationIconEvidenceSchemaVersion || got.Path != "ui/assets/plugin.png" || got.MediaType != "image/png" || got.Width != 1 || got.Height != 1 || got.Size != int64(len(icon)) || got.SHA256 != "sha256:"+hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("presentation icon evidence = %#v", got)
	}

	extracted := filepath.Join(t.TempDir(), "presentation-icon.png")
	evidence, err := ExtractPresentationIcon(ctx, output, extracted)
	if err != nil {
		t.Fatal(err)
	}
	if evidence != *verified.PresentationIcon {
		t.Fatalf("extracted evidence = %#v, want %#v", evidence, *verified.PresentationIcon)
	}
	extractedBytes, err := os.ReadFile(extracted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(extractedBytes, icon) {
		t.Fatal("extracted icon does not match verified package bytes")
	}
	if _, err := ExtractPresentationIcon(ctx, output, extracted); !errors.Is(err, ErrPresentationIconOutputExists) {
		t.Fatalf("ExtractPresentationIcon() overwrite error = %v", err)
	}

	packageAsset := mustSingleMatch(t, filepath.Join(output, "weather-*.redevplugin"))
	if err := os.WriteFile(packageAsset, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	tamperedOutput := filepath.Join(t.TempDir(), "tampered-icon.png")
	if _, err := ExtractPresentationIcon(ctx, output, tamperedOutput); !errors.Is(err, ErrInvalidWorkspace) {
		t.Fatalf("ExtractPresentationIcon() tampered output error = %v", err)
	}
	if _, err := os.Stat(tamperedOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered release wrote icon output: %v", err)
	}
}

func TestExtractPresentationIconRejectsReleaseWithoutIcon(t *testing.T) {
	ctx := context.Background()
	output := finalizeTestRelease(t, ctx, filepath.Join("..", "..", "examples", "plugins", "weather"))
	verified, err := VerifyAndInspectOutput(ctx, output)
	if err != nil {
		t.Fatal(err)
	}
	if verified.PresentationIcon != nil {
		t.Fatalf("release without a declared icon returned evidence: %#v", verified.PresentationIcon)
	}
	destination := filepath.Join(t.TempDir(), "icon.png")
	if _, err := ExtractPresentationIcon(ctx, output, destination); !errors.Is(err, ErrPresentationIconUnavailable) {
		t.Fatalf("ExtractPresentationIcon() no-icon error = %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("release without an icon wrote output: %v", err)
	}
}
