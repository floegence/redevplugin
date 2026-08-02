package releasepublisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func TestPublisherWorkspaceCompletesExternalSigningFlow(t *testing.T) {
	ctx := context.Background()
	var packageBuffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, filepath.Join("..", "..", "examples", "plugins", "weather"), &packageBuffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	packageFile := filepath.Join(t.TempDir(), "weather.redevplugin")
	if err := os.WriteFile(packageFile, packageBuffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	signingPublic, signingPrivate, _ := ed25519.GenerateKey(rand.Reader)
	ledgerPublic, ledgerPrivate, _ := ed25519.GenerateKey(rand.Reader)
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
			digest, _ := hex.DecodeString(request.SigningPreimageSHA256)
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
