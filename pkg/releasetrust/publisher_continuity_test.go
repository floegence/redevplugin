package releasetrust

import (
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
	"time"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasecontract"
	"github.com/floegence/redevplugin/pkg/releasepublisher"
)

func TestPublisherOutputSupportsFreshUpgradeAndRestartVerification(t *testing.T) {
	ctx := context.Background()
	config, signingKeys := publisherContinuityConfig(t)
	firstOutput := finalizePublisherContinuityRelease(t, ctx, config, signingKeys, "9.9.9", "")
	secondOutput := finalizePublisherContinuityRelease(t, ctx, config, signingKeys, "9.9.10", firstOutput)
	first := readPublisherContinuityOutput(t, firstOutput)
	second := readPublisherContinuityOutput(t, secondOutput)

	if first.checkpoint.TreeSize != 7 || second.checkpoint.TreeSize != 9 {
		t.Fatalf("publisher checkpoint sizes = %d -> %d, want 7 -> 9", first.checkpoint.TreeSize, second.checkpoint.TreeSize)
	}
	assertPublisherContinuityEvidenceContract(t, first, second)

	t.Run("fresh", func(t *testing.T) {
		harness := newPublisherContinuityHarness(t, config, second)
		verifyPublisherContinuityRelease(t, ctx, harness.service, second)
		if got := harness.state.committedState(t).SigningLedger.Checkpoint.TreeSize; got != 9 {
			t.Fatalf("fresh committed checkpoint tree size = %d, want 9", got)
		}
	})

	t.Run("upgrade and restart", func(t *testing.T) {
		harness := newPublisherContinuityHarness(t, config, first)
		verifyPublisherContinuityRelease(t, ctx, harness.service, first)
		if got := harness.state.committedState(t).SigningLedger.Checkpoint.TreeSize; got != 7 {
			t.Fatalf("baseline committed checkpoint tree size = %d, want 7", got)
		}

		harness.use(second)
		verifyPublisherContinuityRelease(t, ctx, harness.service, second)
		if got := harness.state.committedState(t).SigningLedger.Checkpoint.TreeSize; got != 9 {
			t.Fatalf("upgraded committed checkpoint tree size = %d, want 9", got)
		}

		restarted, err := NewReleaseTrustService(harness.options, harness.adapters)
		if err != nil {
			t.Fatal(err)
		}
		verifyPublisherContinuityRelease(t, ctx, restarted, second)
		if got := harness.state.committedState(t).SigningLedger.Checkpoint.TreeSize; got != 9 {
			t.Fatalf("restarted committed checkpoint tree size = %d, want 9", got)
		}
	})

	t.Run("upgrade rejects missing continuity evidence", func(t *testing.T) {
		harness := newPublisherContinuityHarness(t, config, first)
		verifyPublisherContinuityRelease(t, ctx, harness.service, first)
		incomplete := second
		incomplete.files = clonePublisherContinuityFiles(second.files)
		for locator := range incomplete.files {
			if strings.Contains(locator, "/evidence/continuity/") {
				delete(incomplete.files, locator)
			}
		}
		harness.use(incomplete)
		services, err := NewServiceSet(harness.service)
		if err != nil {
			t.Fatal(err)
		}
		reference := incomplete.reference.ReleaseRef
		if _, err := services.PrepareRelease(ctx, ReleaseIdentity{
			SourceID: reference.SourceID, Channel: reference.Channel,
			ReleaseMetadataRef: reference.ReleaseMetadataRef, ReleaseMetadataSHA256: reference.ReleaseMetadataSHA256,
			PublisherID: reference.PublisherID, PluginID: reference.PluginID, Version: reference.Version,
		}); err == nil {
			t.Fatal("PrepareRelease accepted an upgrade without continuity evidence")
		}
		if got := harness.state.committedState(t).SigningLedger.Checkpoint.TreeSize; got != 7 {
			t.Fatalf("failed upgrade committed checkpoint tree size = %d, want 7", got)
		}
	})

	t.Run("restart rejects consistency proof on canonical evidence", func(t *testing.T) {
		harness := newPublisherContinuityHarness(t, config, first)
		verifyPublisherContinuityRelease(t, ctx, harness.service, first)
		contaminated := first
		contaminated.files = clonePublisherContinuityFiles(first.files)
		checkpointSHA256 := digestHex(first.files["sources/"+first.reference.ReleaseRef.SourceID+"/signing-ledger/checkpoints/current.json"])
		metadata, err := releasecontract.DecodeReleaseMetadata(first.metadata)
		if err != nil {
			t.Fatal(err)
		}
		subjectDigest, err := releasecontract.SigningSubjectIdentitySHA256(releasecontract.SigningSubjectV1{
			SchemaVersion: releasecontract.SigningSubjectSchemaVersion,
			Usage:         releasecontract.SigningSubjectUsageSourcePolicy,
			SourceID:      first.reference.ReleaseRef.SourceID,
			Channel:       first.reference.ReleaseRef.Channel,
			Epoch:         metadata.ReleaseMetadataSignature.SourcePolicyEpoch,
		})
		if err != nil {
			t.Fatal(err)
		}
		locator := "sources/" + first.reference.ReleaseRef.SourceID + "/signing-ledger/evidence/" + subjectDigest + ".json"
		evidence, err := releasecontract.DecodeSigningLedgerEvidence(contaminated.files[locator])
		if err != nil {
			t.Fatal(err)
		}
		evidence.ConsistencyProofRef = "sources/" + first.reference.ReleaseRef.SourceID +
			"/signing-ledger/proofs/consistency/" + checkpointSHA256 + "/" + checkpointSHA256 + ".json"
		evidence.ConsistencyProofSHA256 = strings.Repeat("a", 64)
		contaminated.files[locator], err = releasecontract.CanonicalSigningLedgerEvidence(evidence)
		if err != nil {
			t.Fatal(err)
		}
		harness.use(contaminated)
		restarted, err := NewReleaseTrustService(harness.options, harness.adapters)
		if err != nil {
			t.Fatal(err)
		}
		services, err := NewServiceSet(restarted)
		if err != nil {
			t.Fatal(err)
		}
		reference := contaminated.reference.ReleaseRef
		if _, err := services.PrepareRelease(ctx, ReleaseIdentity{
			SourceID: reference.SourceID, Channel: reference.Channel,
			ReleaseMetadataRef: reference.ReleaseMetadataRef, ReleaseMetadataSHA256: reference.ReleaseMetadataSHA256,
			PublisherID: reference.PublisherID, PluginID: reference.PluginID, Version: reference.Version,
		}); err == nil {
			t.Fatal("PrepareRelease accepted consistency proof on same-checkpoint canonical evidence")
		}
		if got := harness.state.committedState(t).SigningLedger.Checkpoint.TreeSize; got != 7 {
			t.Fatalf("rejected restart committed checkpoint tree size = %d, want 7", got)
		}
	})
}

type publisherContinuityOutput struct {
	reference         releasepublisher.PublisherReleaseRefV1
	files             map[string][]byte
	checkpoint        releasecontract.SigningLedgerCheckpointV1
	metadata          []byte
	metadataSignature []byte
	packageSignature  releasecontract.PackageSignatureV1
}

type publisherContinuityHarness struct {
	options   ReleaseTrustOptions
	adapters  ReleaseTrustAdapters
	service   *ReleaseTrustService
	state     *memorySourceTrustStateStore
	documents *fixtureDocumentTransport
	ledger    *fixtureLedgerTransport
}

func assertPublisherContinuityEvidenceContract(
	t *testing.T,
	previous publisherContinuityOutput,
	current publisherContinuityOutput,
) {
	t.Helper()
	previousCheckpointSHA256 := digestHex(previous.files["sources/"+previous.reference.ReleaseRef.SourceID+"/signing-ledger/checkpoints/current.json"])
	currentCheckpointSHA256 := digestHex(current.files["sources/"+current.reference.ReleaseRef.SourceID+"/signing-ledger/checkpoints/current.json"])
	continuityPrefix := "sources/" + current.reference.ReleaseRef.SourceID + "/signing-ledger/evidence/continuity/" +
		previousCheckpointSHA256 + "/" + currentCheckpointSHA256 + "/"
	continuityCount := 0
	for locator, value := range current.files {
		if !strings.Contains(locator, "/signing-ledger/evidence/") {
			continue
		}
		evidence, err := releasecontract.DecodeSigningLedgerEvidence(value)
		if err != nil {
			t.Fatalf("decode evidence %q: %v", locator, err)
		}
		if !strings.HasPrefix(locator, continuityPrefix) {
			if evidence.ConsistencyProofRef != "" || evidence.ConsistencyProofSHA256 != "" {
				t.Fatalf("canonical evidence %q carries consistency proof", locator)
			}
			continue
		}
		continuityCount++
		if evidence.ConsistencyProofRef == "" || evidence.ConsistencyProofSHA256 == "" {
			t.Fatalf("continuity evidence %q is missing consistency proof", locator)
		}
		subjectDigest := strings.TrimSuffix(strings.TrimPrefix(locator, continuityPrefix), ".json")
		canonicalLocator := "sources/" + current.reference.ReleaseRef.SourceID + "/signing-ledger/evidence/" + subjectDigest + ".json"
		canonical, err := releasecontract.DecodeSigningLedgerEvidence(current.files[canonicalLocator])
		if err != nil {
			t.Fatalf("decode canonical evidence %q: %v", canonicalLocator, err)
		}
		evidence.ConsistencyProofRef = ""
		evidence.ConsistencyProofSHA256 = ""
		if evidence != canonical {
			t.Fatalf("continuity evidence %q differs from canonical evidence beyond the proof", locator)
		}
	}
	if continuityCount != 5 {
		t.Fatalf("source continuity evidence count = %d, want 5", continuityCount)
	}
}

func clonePublisherContinuityFiles(files map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(files))
	for locator, value := range files {
		cloned[locator] = append([]byte(nil), value...)
	}
	return cloned
}

func publisherContinuityConfig(t *testing.T) (releasepublisher.ConfigV1, map[string]ed25519.PrivateKey) {
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
	config := releasepublisher.ConfigV1{
		SchemaVersion: releasepublisher.ConfigSchemaVersion,
		SourceID:      "publisher_continuity", Channel: "stable", SourceType: "registry", SourceClass: "official",
		GeneratedAt: "2026-08-01T00:00:00Z", ExpiresAt: "2026-10-30T00:00:00Z",
		Root: releasepublisher.PublicKeyV1{
			Algorithm: string(releasecontract.SignatureAlgorithmEd25519), KeyID: "continuity_root",
			PublicKey: base64.StdEncoding.EncodeToString(rootPublic),
		},
		Signing: releasepublisher.PublicKeyV1{
			Algorithm: string(releasecontract.SignatureAlgorithmEd25519), KeyID: "continuity_signing",
			PublicKey: base64.StdEncoding.EncodeToString(signingPublic),
		},
		SigningLedger: releasepublisher.SigningLedgerConfigV1{
			LogID: "continuity_ledger",
			PublicKeyV1: releasepublisher.PublicKeyV1{
				Algorithm: string(releasecontract.SignatureAlgorithmEd25519), KeyID: "continuity_ledger_key",
				PublicKey: base64.StdEncoding.EncodeToString(ledgerPublic),
			},
		},
		AllowedArtifactHosts: []string{"github.com"}, MinReDevPluginVersion: "0.7.20",
		Distribution: "registry_ref", HostRequirements: []releasecontract.ReleaseHostRequirement{},
	}
	return config, map[string]ed25519.PrivateKey{
		config.Root.KeyID: rootPrivate, config.Signing.KeyID: signingPrivate,
		config.SigningLedger.KeyID: ledgerPrivate,
	}
}

func finalizePublisherContinuityRelease(
	t *testing.T,
	ctx context.Context,
	config releasepublisher.ConfigV1,
	keys map[string]ed25519.PrivateKey,
	version string,
	previousOutput string,
) string {
	t.Helper()
	packageDir := filepath.Join(t.TempDir(), "weather")
	if err := os.CopyFS(packageDir, os.DirFS(filepath.Join("..", "..", "examples", "plugins", "weather"))); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(packageDir, "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["plugin"].(map[string]any)["version"] = version
	manifestRaw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	packageFile := filepath.Join(t.TempDir(), "plugin.redevplugin")
	packageHandle, err := os.OpenFile(packageFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, buildErr := pluginpkg.BuildFromDir(ctx, packageDir, packageHandle, pluginpkg.DefaultReadLimits())
	closeErr := packageHandle.Close()
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	workspace := filepath.Join(t.TempDir(), "workspace")
	status, err := releasepublisher.PrepareWithPrevious(ctx, config, packageFile, workspace, previousOutput)
	if err != nil {
		t.Fatalf("prepare publisher output: %v", err)
	}
	for attempts := 0; status.PendingRequests > 0 && attempts < 32; attempts++ {
		entries, err := os.ReadDir(filepath.Join(workspace, "requests"))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			requestRaw, err := os.ReadFile(filepath.Join(workspace, "requests", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			request, err := releasepublisher.DecodeExternalSignerRequest(requestRaw)
			if err != nil {
				t.Fatal(err)
			}
			preimageDigest, err := hex.DecodeString(request.SigningPreimageSHA256)
			if err != nil {
				t.Fatal(err)
			}
			response := releasepublisher.ExternalSignerResponseV1{
				SchemaVersion: releasepublisher.ExternalSignerResponseSchemaVersion,
				RequestID:     request.RequestID, Usage: request.Usage, KeyID: request.KeyID,
				SubjectIdentitySHA256: request.SubjectIdentitySHA256,
				SigningPreimageSHA256: request.SigningPreimageSHA256,
				Algorithm:             releasecontract.SignatureAlgorithmEd25519,
				Signature:             base64.StdEncoding.EncodeToString(ed25519.Sign(keys[request.KeyID], preimageDigest)),
			}
			responseRaw, err := releasepublisher.CanonicalExternalSignerResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			status, err = releasepublisher.ApplySignature(ctx, workspace, responseRaw)
			if err != nil {
				t.Fatalf("apply %s signature: %v", request.Usage, err)
			}
		}
	}
	if status.PendingRequests != 0 || status.Phase != "complete" {
		t.Fatalf("publisher status = %#v", status)
	}
	output := filepath.Join(t.TempDir(), "release")
	if _, err := releasepublisher.Finalize(ctx, workspace, output); err != nil {
		t.Fatalf("finalize publisher output: %v", err)
	}
	return output
}

func readPublisherContinuityOutput(t *testing.T, output string) publisherContinuityOutput {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(output, "*.release-ref.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("release ref matches = %#v, error = %v", matches, err)
	}
	referenceRaw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var reference releasepublisher.PublisherReleaseRefV1
	if err := json.Unmarshal(referenceRaw, &reference); err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(reference.Files))
	for _, file := range reference.Files {
		value, err := os.ReadFile(filepath.Join(output, file.AssetName))
		if err != nil {
			t.Fatal(err)
		}
		files[file.Locator] = value
	}
	checkpoint, err := releasecontract.DecodeSigningLedgerCheckpoint(
		files["sources/"+reference.ReleaseRef.SourceID+"/signing-ledger/checkpoints/current.json"],
	)
	if err != nil {
		t.Fatal(err)
	}
	metadataRaw := files[reference.ReleaseRef.ReleaseMetadataRef]
	metadata, err := releasecontract.DecodeReleaseMetadata(metadataRaw)
	if err != nil {
		t.Fatal(err)
	}
	packageSignature, err := releasecontract.DecodePackageSignature(
		files[metadata.PackageSignature.SignatureBundleRef],
		releasecontract.PackageVerificationContext{
			SourceID: reference.ReleaseRef.SourceID, Channel: reference.ReleaseRef.Channel,
			Version: reference.ReleaseRef.Version,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return publisherContinuityOutput{
		reference: reference, files: files, checkpoint: checkpoint, metadata: metadataRaw,
		metadataSignature: files[metadata.ReleaseMetadataSignature.SignatureRef], packageSignature: packageSignature,
	}
}

func newPublisherContinuityHarness(
	t *testing.T,
	config releasepublisher.ConfigV1,
	output publisherContinuityOutput,
) *publisherContinuityHarness {
	t.Helper()
	configuration, err := NewSourceConfiguration(config.SourceID, []string{config.Channel})
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, err := base64.StdEncoding.Strict().DecodeString(config.Root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rootAnchor, err := NewEd25519TrustAnchor(config.Root.KeyID, ed25519.PublicKey(rootPublic))
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, err := base64.StdEncoding.Strict().DecodeString(config.SigningLedger.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ledgerAnchor, err := NewEd25519TrustAnchor(config.SigningLedger.KeyID, ed25519.PublicKey(ledgerPublic))
	if err != nil {
		t.Fatal(err)
	}
	ledgerRoot, err := NewPinnedSigningLedgerRoot(config.SigningLedger.LogID, ledgerAnchor)
	if err != nil {
		t.Fatal(err)
	}
	timePrivate := ed25519.NewKeyFromSeed([]byte(strings.Repeat("t", ed25519.SeedSize)))
	timeAnchor, err := NewEd25519TrustAnchor("time_key", timePrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	timeRoot, err := NewTransparencyRoot("continuity_time_log", timeAnchor)
	if err != nil {
		t.Fatal(err)
	}
	options, err := NewReleaseTrustOptions(configuration, rootAnchor, []TransparencyRoot{timeRoot}, ledgerRoot, SourceRelativeLocatorPolicyV1)
	if err != nil {
		t.Fatal(err)
	}
	state := &memorySourceTrustStateStore{}
	documents := &fixtureDocumentTransport{}
	ledger := &fixtureLedgerTransport{}
	adapters := ReleaseTrustAdapters{
		Documents: documents, Ledger: ledger, State: state,
		TrustedTime: &testTransparencyTimeAdapter{
			t: t, privateKey: timePrivate, start: time.Date(2026, 8, 1, 1, 0, 0, 0, time.UTC),
		},
		Fence: &fixtureFenceCoordinator{},
	}
	service, err := NewReleaseTrustService(options, adapters)
	if err != nil {
		t.Fatal(err)
	}
	harness := &publisherContinuityHarness{
		options: options, adapters: adapters, service: service, state: state, documents: documents, ledger: ledger,
	}
	harness.use(output)
	return harness
}

func (harness *publisherContinuityHarness) use(output publisherContinuityOutput) {
	harness.documents.values = map[string][]byte{}
	harness.documents.tokens = map[string]string{}
	harness.ledger.values = map[string][]byte{}
	for locator, value := range output.files {
		switch {
		case strings.Contains(locator, "/signing-ledger/"):
			harness.ledger.values[locator] = value
		case strings.HasSuffix(locator, "/root/current.json"),
			strings.Contains(locator, "/policy/"), strings.Contains(locator, "/revocation/"):
			harness.documents.values[locator] = value
			harness.documents.tokens[locator] = "etag-" + hex.EncodeToString([]byte(locator))
		}
	}
}

func verifyPublisherContinuityRelease(
	t *testing.T,
	ctx context.Context,
	service *ReleaseTrustService,
	output publisherContinuityOutput,
) {
	t.Helper()
	services, err := NewServiceSet(service)
	if err != nil {
		t.Fatal(err)
	}
	reference := output.reference.ReleaseRef
	prepared, err := services.PrepareRelease(ctx, ReleaseIdentity{
		SourceID: reference.SourceID, Channel: reference.Channel,
		ReleaseMetadataRef: reference.ReleaseMetadataRef, ReleaseMetadataSHA256: reference.ReleaseMetadataSHA256,
		PublisherID: reference.PublisherID, PluginID: reference.PluginID, Version: reference.Version,
	})
	if err != nil {
		t.Fatalf("PrepareRelease(%s): %v", reference.Version, err)
	}
	metadata, err := services.VerifyReleaseMetadata(ctx, prepared, output.metadata, output.metadataSignature)
	if err != nil {
		t.Fatalf("VerifyReleaseMetadata(%s): %v", reference.Version, err)
	}
	verified, err := services.VerifyPackage(ctx, metadata, output.packageSignature)
	if err != nil {
		t.Fatalf("VerifyPackage(%s): %v", reference.Version, err)
	}
	lease, err := verified.AuthorizeActivation()
	if err != nil {
		t.Fatalf("AuthorizeActivation(%s): %v", reference.Version, err)
	}
	if err := services.ValidateActivationLease(lease); err != nil {
		t.Fatalf("ValidateActivationLease(%s): %v", reference.Version, err)
	}
}
