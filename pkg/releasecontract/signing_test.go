package releasecontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type releaseSigningFixture struct {
	PublicKey              ed25519.PublicKey
	Verifier               Ed25519PublicKeyVerifier
	RootInput              RootDelegationInput
	Root                   RootDelegationV1
	PackageInput           PackageSigningInput
	PackageContext         PackageVerificationContext
	Package                PackageSignatureV1
	MetadataChannel        string
	Metadata               ReleaseMetadataV5
	MetadataSignature      []byte
	PolicyInput            SourcePolicyInput
	Policy                 SourcePolicyV2
	PolicyPointerInput     ReleasePointerInput
	PolicyPointer          SourcePolicyPointerV1
	RevocationInput        RevocationInput
	Revocation             RevocationV2
	RevocationPointerInput ReleasePointerInput
	RevocationPointer      RevocationPointerV1
	Preimages              map[SigningUsage][]byte
	Signatures             map[SigningUsage][]byte
}

func TestReleaseSigningDomainsAreCanonicalAndSeparated(t *testing.T) {
	fixture := newReleaseSigningFixture(t)

	if err := VerifyRootDelegation(fixture.Root, fixture.Verifier); err != nil {
		t.Fatalf("VerifyRootDelegation() error = %v", err)
	}
	if err := VerifyPackageSignature(fixture.PackageContext, fixture.Package, fixture.Verifier); err != nil {
		t.Fatalf("VerifyPackageSignature() error = %v", err)
	}
	if err := VerifyReleaseMetadata(fixture.MetadataChannel, fixture.Metadata, fixture.MetadataSignature, fixture.Verifier); err != nil {
		t.Fatalf("VerifyReleaseMetadata() error = %v", err)
	}
	if err := VerifySourcePolicy(fixture.Policy, fixture.Verifier); err != nil {
		t.Fatalf("VerifySourcePolicy() error = %v", err)
	}
	if err := VerifySourcePolicyPointer(fixture.PolicyPointer, fixture.Verifier); err != nil {
		t.Fatalf("VerifySourcePolicyPointer() error = %v", err)
	}
	if err := VerifyRevocation(fixture.Revocation, fixture.Verifier); err != nil {
		t.Fatalf("VerifyRevocation() error = %v", err)
	}
	if err := VerifyRevocationPointer(fixture.RevocationPointer, fixture.Verifier); err != nil {
		t.Fatalf("VerifyRevocationPointer() error = %v", err)
	}

	usages := []SigningUsage{
		SigningUsageRootDelegation,
		SigningUsagePackage,
		SigningUsageReleaseMetadata,
		SigningUsageSourcePolicy,
		SigningUsageSourcePolicyPointer,
		SigningUsageRevocation,
		SigningUsageRevocationPointer,
	}
	for _, signedUsage := range usages {
		for _, verifiedUsage := range usages {
			valid := ed25519.Verify(fixture.PublicKey, fixture.Preimages[verifiedUsage], fixture.Signatures[signedUsage])
			if signedUsage == verifiedUsage && !valid {
				t.Fatalf("signature for %s rejected by its own preimage", signedUsage)
			}
			if signedUsage != verifiedUsage && valid {
				t.Fatalf("signature for %s accepted as %s", signedUsage, verifiedUsage)
			}
		}
	}
}

func TestReleaseContractCanonicalRoundTripAndClosedDecoding(t *testing.T) {
	fixture := newReleaseSigningFixture(t)
	tests := []struct {
		name      string
		canonical func() ([]byte, error)
		decode    func([]byte) error
	}{
		{
			name:      "root delegation",
			canonical: func() ([]byte, error) { return CanonicalRootDelegation(fixture.Root) },
			decode:    func(raw []byte) error { _, err := DecodeRootDelegation(raw); return err },
		},
		{
			name:      "package signature",
			canonical: func() ([]byte, error) { return CanonicalPackageSignature(fixture.PackageContext, fixture.Package) },
			decode:    func(raw []byte) error { _, err := DecodePackageSignature(raw, fixture.PackageContext); return err },
		},
		{
			name:      "release metadata",
			canonical: func() ([]byte, error) { return CanonicalReleaseMetadata(fixture.Metadata) },
			decode:    func(raw []byte) error { _, err := DecodeReleaseMetadata(raw); return err },
		},
		{
			name:      "source policy",
			canonical: func() ([]byte, error) { return CanonicalSourcePolicy(fixture.Policy) },
			decode:    func(raw []byte) error { _, err := DecodeSourcePolicy(raw); return err },
		},
		{
			name:      "source policy pointer",
			canonical: func() ([]byte, error) { return CanonicalSourcePolicyPointer(fixture.PolicyPointer) },
			decode:    func(raw []byte) error { _, err := DecodeSourcePolicyPointer(raw); return err },
		},
		{
			name:      "revocation",
			canonical: func() ([]byte, error) { return CanonicalRevocation(fixture.Revocation) },
			decode:    func(raw []byte) error { _, err := DecodeRevocation(raw); return err },
		},
		{
			name:      "revocation pointer",
			canonical: func() ([]byte, error) { return CanonicalRevocationPointer(fixture.RevocationPointer) },
			decode:    func(raw []byte) error { _, err := DecodeRevocationPointer(raw); return err },
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			raw, err := testCase.canonical()
			if err != nil {
				t.Fatal(err)
			}
			if err := testCase.decode(raw); err != nil {
				t.Fatalf("canonical document rejected: %v", err)
			}
			for name, candidate := range map[string][]byte{
				"trailing":     append(append([]byte{}, raw...), []byte(` true`)...),
				"unknown":      insertBeforeObjectEnd(raw, `,"unknown":true`),
				"duplicate":    insertBeforeObjectEnd(raw, `,"schema_version":"duplicate"`),
				"noncanonical": append([]byte(" "), raw...),
			} {
				if err := testCase.decode(candidate); !errors.Is(err, ErrInvalidDocument) {
					t.Fatalf("%s input error = %v, want ErrInvalidDocument", name, err)
				}
			}
		})
	}
}

func TestExplicitTimestampsAndGenesisSentinelAreSigned(t *testing.T) {
	fixture := newReleaseSigningFixture(t)

	packageChanged := fixture.PackageInput
	packageChanged.SignedAt = "2026-07-20T00:00:01Z"
	assertPreimageChanges(t, fixture.Preimages[SigningUsagePackage], func() ([]byte, error) {
		return PackageSigningPreimage(packageChanged)
	})

	policyChanged := fixture.PolicyInput
	policyChanged.ExpiresAt = "2026-07-20T23:59:59Z"
	assertPreimageChanges(t, fixture.Preimages[SigningUsageSourcePolicy], func() ([]byte, error) {
		return SourcePolicySigningPreimage(policyChanged)
	})

	invalidGenesis := fixture.PolicyInput
	invalidGenesis.PreviousDocumentSHA256 = strings.Repeat("1", 64)
	if _, err := SourcePolicySigningPreimage(invalidGenesis); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("invalid genesis predecessor error = %v, want ErrInvalidDocument", err)
	}

	invalidSecondEpoch := fixture.PolicyInput
	invalidSecondEpoch.Epoch = "2"
	invalidSecondEpoch.PreviousEpoch = "1"
	invalidSecondEpoch.PreviousDocumentSHA256 = GenesisPreviousDocumentSHA256
	if _, err := SourcePolicySigningPreimage(invalidSecondEpoch); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("non-genesis sentinel error = %v, want ErrInvalidDocument", err)
	}

	invalidMetadata := fixture.Metadata
	invalidMetadata.SchemaVersion = ""
	if _, err := BuildReleaseMetadata(invalidMetadata); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("missing release metadata schema error = %v, want ErrInvalidDocument", err)
	}
	if err := VerifyReleaseMetadata(fixture.MetadataChannel, fixture.Metadata, nil, fixture.Verifier); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("short detached signature error = %v, want ErrInvalidSignature", err)
	}
}

func TestReleaseContractBuildersRejectSchemaLimitAndInvalidUTF8Drift(t *testing.T) {
	fixture := newReleaseSigningFixture(t)

	policy := fixture.PolicyInput
	policy.AllowedArtifactHosts = make([]string, 1025)
	for index := range policy.AllowedArtifactHosts {
		policy.AllowedArtifactHosts[index] = fmt.Sprintf("host-%04d.example", index)
	}
	if _, err := SourcePolicySigningPreimage(policy); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("oversized allowed_artifact_hosts error = %v, want ErrInvalidDocument", err)
	}

	metadata := fixture.Metadata
	metadata.Metadata = map[string]string{"valid": string([]byte{0xff})}
	if _, err := BuildReleaseMetadata(metadata); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("invalid UTF-8 metadata error = %v, want ErrInvalidDocument", err)
	}
}

func TestCanonicalAPIsDoNotReadSystemTime(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("time.Now(")) {
			t.Fatalf("%s reads the system clock", file)
		}
	}
}

func newReleaseSigningFixture(t testing.TB) releaseSigningFixture {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID := "test_signing_key"
	verifier := Ed25519PublicKeyVerifier{keyID: publicKey}

	rootInput := RootDelegationInput{
		SourceID:                 "example_source",
		RootEpoch:                "1",
		PreviousRootEpoch:        GenesisPreviousEpoch,
		PreviousDelegationSHA256: GenesisPreviousDocumentSHA256,
		GeneratedAt:              "2026-07-20T00:00:00Z",
		ExpiresAt:                "2027-07-20T00:00:00Z",
		DelegatedKeys: []RootDelegatedKey{{
			Algorithm: SignatureAlgorithmEd25519,
			KeyID:     keyID,
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
			Usages: []DelegatedKeyUsage{
				DelegatedKeyUsagePackage,
				DelegatedKeyUsageReleaseMetadata,
				DelegatedKeyUsageRevocation,
				DelegatedKeyUsageRevocationPointer,
				DelegatedKeyUsageSourcePolicy,
				DelegatedKeyUsageSourcePolicyPointer,
			},
			Channels:   []string{"stable"},
			ValidFrom:  "2026-07-20T00:00:00Z",
			ValidUntil: "2027-07-20T00:00:00Z",
		}},
		KeyID: keyID,
	}
	rootPreimage := mustPreimage(t, func() ([]byte, error) { return RootDelegationSigningPreimage(rootInput) })
	rootSignature := ed25519.Sign(privateKey, rootPreimage)
	root := mustBuild(t, func() (RootDelegationV1, error) { return BuildRootDelegation(rootInput, rootSignature) })

	packageInput := PackageSigningInput{
		SourceID:     "example_source",
		Channel:      "stable",
		Version:      "1.2.3",
		Algorithm:    SignatureAlgorithmEd25519,
		KeyID:        keyID,
		PublisherID:  "example.publisher",
		PluginID:     "example.plugin",
		PackageHash:  "sha256:" + strings.Repeat("1", 64),
		ManifestHash: "sha256:" + strings.Repeat("2", 64),
		EntriesHash:  "sha256:" + strings.Repeat("3", 64),
		SignedAt:     "2026-07-20T00:00:00Z",
	}
	packagePreimage := mustPreimage(t, func() ([]byte, error) { return PackageSigningPreimage(packageInput) })
	packageSignature := ed25519.Sign(privateKey, packagePreimage)
	packageDocument := mustBuild(t, func() (PackageSignatureV1, error) { return BuildPackageSignature(packageInput, packageSignature) })
	packageContext := PackageVerificationContext{SourceID: packageInput.SourceID, Channel: packageInput.Channel, Version: packageInput.Version}

	metadata := ReleaseMetadataV5{
		SchemaVersion:      ReleaseMetadataSchemaVersion,
		SourceID:           "example_source",
		ReleaseMetadataRef: "plugins/example.publisher/example.plugin/1.2.3/release.json",
		PublisherID:        "example.publisher",
		PluginID:           "example.plugin",
		Version:            "1.2.3",
		DistributionRef: ReleaseDistributionRef{
			Distribution: "registry_ref",
			ArtifactRef:  "plugins/example.publisher/example.plugin/1.2.3/package.zip",
		},
		Hashes: ReleasePackageHashSet{
			PackageSHA256:  strings.Repeat("1", 64),
			ManifestSHA256: strings.Repeat("2", 64),
			EntriesSHA256:  strings.Repeat("3", 64),
		},
		ReleaseMetadataSignature: ReleaseMetadataSignatureRef{
			Algorithm:         SignatureAlgorithmEd25519,
			KeyID:             keyID,
			SignatureRef:      "plugins/example.publisher/example.plugin/1.2.3/release.json.sig",
			SourcePolicyEpoch: "1",
			RevocationEpoch:   "1",
		},
		PackageSignature: PackageReleaseSignatureRef{
			Algorithm:          SignatureAlgorithmEd25519,
			KeyID:              keyID,
			SignatureBundleRef: "plugins/example.publisher/example.plugin/1.2.3/package.sig",
			SourcePolicyEpoch:  "1",
			RevocationEpoch:    "1",
		},
		Compatibility: ReleaseCompatibility{
			MinReDevPluginVersion: "0.6.0",
			MinRuntimeVersion:     "0.6.0",
			UIProtocolVersion:     "plugin-ui-v5",
			SupportedTargets:      []string{"linux/amd64", "linux/arm64"},
		},
		ReleaseEvidence: &ReleaseEvidence{
			NoticesSHA256:    strings.Repeat("4", 64),
			ProvenanceSHA256: strings.Repeat("5", 64),
			GeneratedAt:      "2026-07-20T00:00:00Z",
		},
		Metadata: map[string]string{
			"alpha": "first",
			"html":  "<>&",
			"line":  "first\nsecond",
			"zeta":  "last",
		},
	}
	metadata = mustBuild(t, func() (ReleaseMetadataV5, error) { return BuildReleaseMetadata(metadata) })
	metadataPreimage := mustPreimage(t, func() ([]byte, error) { return ReleaseMetadataSigningPreimage("stable", metadata) })
	metadataSignature := ed25519.Sign(privateKey, metadataPreimage)

	policyInput := SourcePolicyInput{
		SourceID:               "example_source",
		Channel:                "stable",
		Epoch:                  "1",
		PreviousEpoch:          GenesisPreviousEpoch,
		PreviousDocumentSHA256: GenesisPreviousDocumentSHA256,
		RootEpoch:              "1",
		SourceType:             "registry",
		SourceClass:            "official",
		AllowedPublishers:      []string{"example.publisher"},
		AllowedArtifactHosts:   []string{"plugins.example.test"},
		ActiveKeys: SourcePolicyActiveKeys{
			Package:             []string{keyID},
			ReleaseMetadata:     []string{keyID},
			SourcePolicyPointer: []string{keyID},
			Revocation:          []string{keyID},
			RevocationPointer:   []string{keyID},
		},
		RequireSignature:       true,
		InstallPolicy:          "allow",
		UnsignedPolicy:         "block",
		DowngradePolicy:        "block",
		MinimumRevocationEpoch: "1",
		Limits:                 DefaultSourcePolicyLimits(),
		GeneratedAt:            "2026-07-20T00:00:00Z",
		ExpiresAt:              "2026-07-21T00:00:00Z",
		KeyID:                  keyID,
	}
	policyPreimage := mustPreimage(t, func() ([]byte, error) { return SourcePolicySigningPreimage(policyInput) })
	policySignature := ed25519.Sign(privateKey, policyPreimage)
	policy := mustBuild(t, func() (SourcePolicyV2, error) { return BuildSourcePolicy(policyInput, policySignature) })
	policyBytes := mustPreimage(t, func() ([]byte, error) { return CanonicalSourcePolicy(policy) })
	policyDigest := sha256.Sum256(policyBytes)

	policyPointerInput := ReleasePointerInput{
		SourceID:               "example_source",
		Channel:                "stable",
		Epoch:                  "1",
		PreviousEpoch:          GenesisPreviousEpoch,
		PreviousDocumentSHA256: GenesisPreviousDocumentSHA256,
		Ref:                    "sources/example_source/stable/policy/1.json",
		DocumentSHA256:         fmtSHA256(policyDigest),
		GeneratedAt:            "2026-07-20T00:00:00Z",
		ExpiresAt:              "2026-07-21T00:00:00Z",
		KeyID:                  keyID,
	}
	policyPointerPreimage := mustPreimage(t, func() ([]byte, error) { return SourcePolicyPointerSigningPreimage(policyPointerInput) })
	policyPointerSignature := ed25519.Sign(privateKey, policyPointerPreimage)
	policyPointer := mustBuild(t, func() (SourcePolicyPointerV1, error) {
		return BuildSourcePolicyPointer(policyPointerInput, policyPointerSignature)
	})

	revocationInput := RevocationInput{
		SourceID:               "example_source",
		Channel:                "stable",
		Epoch:                  "1",
		PreviousEpoch:          GenesisPreviousEpoch,
		PreviousDocumentSHA256: GenesisPreviousDocumentSHA256,
		RootEpoch:              "1",
		GeneratedAt:            "2026-07-20T00:00:00Z",
		ExpiresAt:              "2026-07-21T00:00:00Z",
		RevokedKeyIDs:          []string{},
		RevokedReleases: []RevokedRelease{{
			PublisherID:           "example.publisher",
			PluginID:              "example.plugin",
			Version:               "1.0.0",
			ReleaseMetadataSHA256: strings.Repeat("6", 64),
			RevokedAt:             "2026-07-20T00:00:00Z",
		}},
		KeyID: keyID,
	}
	revocationPreimage := mustPreimage(t, func() ([]byte, error) { return RevocationSigningPreimage(revocationInput) })
	revocationSignature := ed25519.Sign(privateKey, revocationPreimage)
	revocation := mustBuild(t, func() (RevocationV2, error) { return BuildRevocation(revocationInput, revocationSignature) })
	revocationBytes := mustPreimage(t, func() ([]byte, error) { return CanonicalRevocation(revocation) })
	revocationDigest := sha256.Sum256(revocationBytes)

	revocationPointerInput := ReleasePointerInput{
		SourceID:               "example_source",
		Channel:                "stable",
		Epoch:                  "1",
		PreviousEpoch:          GenesisPreviousEpoch,
		PreviousDocumentSHA256: GenesisPreviousDocumentSHA256,
		Ref:                    "sources/example_source/stable/revocation/1.json",
		DocumentSHA256:         fmtSHA256(revocationDigest),
		GeneratedAt:            "2026-07-20T00:00:00Z",
		ExpiresAt:              "2026-07-21T00:00:00Z",
		KeyID:                  keyID,
	}
	revocationPointerPreimage := mustPreimage(t, func() ([]byte, error) { return RevocationPointerSigningPreimage(revocationPointerInput) })
	revocationPointerSignature := ed25519.Sign(privateKey, revocationPointerPreimage)
	revocationPointer := mustBuild(t, func() (RevocationPointerV1, error) {
		return BuildRevocationPointer(revocationPointerInput, revocationPointerSignature)
	})

	return releaseSigningFixture{
		PublicKey:              publicKey,
		Verifier:               verifier,
		RootInput:              rootInput,
		Root:                   root,
		PackageInput:           packageInput,
		PackageContext:         packageContext,
		Package:                packageDocument,
		MetadataChannel:        "stable",
		Metadata:               metadata,
		MetadataSignature:      metadataSignature,
		PolicyInput:            policyInput,
		Policy:                 policy,
		PolicyPointerInput:     policyPointerInput,
		PolicyPointer:          policyPointer,
		RevocationInput:        revocationInput,
		Revocation:             revocation,
		RevocationPointerInput: revocationPointerInput,
		RevocationPointer:      revocationPointer,
		Preimages: map[SigningUsage][]byte{
			SigningUsageRootDelegation:      rootPreimage,
			SigningUsagePackage:             packagePreimage,
			SigningUsageReleaseMetadata:     metadataPreimage,
			SigningUsageSourcePolicy:        policyPreimage,
			SigningUsageSourcePolicyPointer: policyPointerPreimage,
			SigningUsageRevocation:          revocationPreimage,
			SigningUsageRevocationPointer:   revocationPointerPreimage,
		},
		Signatures: map[SigningUsage][]byte{
			SigningUsageRootDelegation:      rootSignature,
			SigningUsagePackage:             packageSignature,
			SigningUsageReleaseMetadata:     metadataSignature,
			SigningUsageSourcePolicy:        policySignature,
			SigningUsageSourcePolicyPointer: policyPointerSignature,
			SigningUsageRevocation:          revocationSignature,
			SigningUsageRevocationPointer:   revocationPointerSignature,
		},
	}
}

func mustPreimage(t testing.TB, build func() ([]byte, error)) []byte {
	t.Helper()
	value, err := build()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustBuild[T any](t testing.TB, build func() (T, error)) T {
	t.Helper()
	value, err := build()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertPreimageChanges(t testing.TB, previous []byte, build func() ([]byte, error)) {
	t.Helper()
	changed, err := build()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(previous, changed) {
		t.Fatal("timestamp mutation did not change the signing preimage")
	}
}

func insertBeforeObjectEnd(raw []byte, suffix string) []byte {
	result := append([]byte{}, raw[:len(raw)-1]...)
	result = append(result, suffix...)
	return append(result, '}')
}

func fmtSHA256(value [sha256.Size]byte) string {
	return base64ToHex(value[:])
}

func base64ToHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&0x0f]
	}
	return string(result)
}

func TestReleaseSigningFixtureIsCurrent(t *testing.T) {
	fixture := newReleaseSigningFixture(t)
	value := map[string]any{
		"schema_version":           "redevplugin.release_signing_fixture.v1",
		"public_key_base64":        base64.StdEncoding.EncodeToString(fixture.PublicKey),
		"release_metadata_channel": fixture.MetadataChannel,
		"package_context": map[string]string{
			"source_id": fixture.PackageContext.SourceID,
			"channel":   fixture.PackageContext.Channel,
			"version":   fixture.PackageContext.Version,
		},
		"documents": map[string]any{
			"root_delegation":       fixture.Root,
			"package_signature":     fixture.Package,
			"release_metadata":      fixture.Metadata,
			"source_policy":         fixture.Policy,
			"source_policy_pointer": fixture.PolicyPointer,
			"revocation":            fixture.Revocation,
			"revocation_pointer":    fixture.RevocationPointer,
		},
		"detached_signatures": map[string]string{
			"release_metadata": base64.StdEncoding.EncodeToString(fixture.MetadataSignature),
		},
		"preimages":  map[string]string{},
		"signatures": map[string]string{},
	}
	for usage, preimage := range fixture.Preimages {
		value["preimages"].(map[string]string)[string(usage)] = base64.StdEncoding.EncodeToString(preimage)
	}
	for usage, signature := range fixture.Signatures {
		value["signatures"].(map[string]string)[string(usage)] = base64.StdEncoding.EncodeToString(signature)
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	root := filepath.Clean(filepath.Join("..", ".."))
	paths := []string{
		filepath.Join(root, "testdata", "contracts", "release-signing-v1.json"),
		filepath.Join(root, "crates", "redevplugin-contracts", "tests", "fixtures", "release-signing-v1.json"),
	}
	if os.Getenv("REDEVPLUGIN_UPDATE_RELEASE_SIGNING_FIXTURE") == "1" {
		for _, path := range paths {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, path := range paths {
		current, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("release signing fixture %s: %v", path, err)
		}
		if !bytes.Equal(current, raw) {
			t.Fatalf("release signing fixture %s is stale; rerun with REDEVPLUGIN_UPDATE_RELEASE_SIGNING_FIXTURE=1", path)
		}
	}
}
