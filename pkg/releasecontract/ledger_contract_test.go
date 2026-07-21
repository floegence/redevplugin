package releasecontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

func TestSigningSubjectIdentitySeparatesEverySemanticCoordinate(t *testing.T) {
	base := SigningSubjectV1{
		SchemaVersion:          SigningSubjectSchemaVersion,
		Usage:                  SigningSubjectUsagePackage,
		SourceID:               "example_source",
		Channel:                "stable",
		PublisherID:            "example.publisher",
		PluginID:               "example.plugin",
		Version:                "1.2.3",
		ArtifactIdentitySHA256: hex.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size)),
	}
	want, err := SigningSubjectIdentitySHA256(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 64 {
		t.Fatalf("subject identity = %q", want)
	}

	mutations := map[string]func(SigningSubjectV1) SigningSubjectV1{
		"source":    func(value SigningSubjectV1) SigningSubjectV1 { value.SourceID = "other_source"; return value },
		"channel":   func(value SigningSubjectV1) SigningSubjectV1 { value.Channel = "beta"; return value },
		"publisher": func(value SigningSubjectV1) SigningSubjectV1 { value.PublisherID = "other.publisher"; return value },
		"plugin":    func(value SigningSubjectV1) SigningSubjectV1 { value.PluginID = "other.plugin"; return value },
		"version":   func(value SigningSubjectV1) SigningSubjectV1 { value.Version = "1.2.4"; return value },
		"usage": func(value SigningSubjectV1) SigningSubjectV1 {
			value.Usage = SigningSubjectUsageReleaseMetadata
			return value
		},
		"artifact": func(value SigningSubjectV1) SigningSubjectV1 {
			value.ArtifactIdentitySHA256 = hex.EncodeToString(bytes.Repeat([]byte{2}, sha256.Size))
			return value
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			got, err := SigningSubjectIdentitySHA256(mutate(base))
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("semantic subject mutation retained the same identity")
			}
		})
	}

	invalid := base
	invalid.Epoch = "1"
	if _, err := CanonicalSigningSubject(invalid); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("release subject with epoch error = %v", err)
	}
}

func TestSignatureEnvelopeBindsSubjectAndPreimage(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	subject := SigningSubjectV1{
		SchemaVersion: SigningSubjectSchemaVersion, Usage: SigningSubjectUsageSourcePolicyPointer,
		SourceID: "example_source", Channel: "stable", Epoch: "1",
	}
	preimage := []byte("canonical pointer signing preimage")
	subjectDigest, err := SigningSubjectIdentitySHA256(subject)
	if err != nil {
		t.Fatal(err)
	}
	preimageDigest := sha256.Sum256(preimage)
	envelope := SignatureEnvelopeV1{
		SchemaVersion:         SigningEnvelopeSchemaVersion,
		SubjectIdentitySHA256: subjectDigest,
		SigningPreimageSHA256: hex.EncodeToString(preimageDigest[:]),
		Algorithm:             SignatureAlgorithmEd25519,
		KeyID:                 "policy_key",
		Signature:             base64.StdEncoding.EncodeToString(signReleasePreimage(privateKey, preimage)),
	}
	verifier := Ed25519PublicKeyVerifier{"policy_key": publicKey}
	if err := VerifySignatureEnvelope(subject, preimage, envelope, verifier); err != nil {
		t.Fatal(err)
	}

	tampered := envelope
	tampered.SigningPreimageSHA256 = hex.EncodeToString(bytes.Repeat([]byte{9}, sha256.Size))
	if err := VerifySignatureEnvelope(subject, preimage, tampered, verifier); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered envelope error = %v", err)
	}
}

func TestSigningLedgerEntryStateMachineIsClosed(t *testing.T) {
	subject := SigningSubjectV1{
		SchemaVersion: SigningSubjectSchemaVersion, Usage: SigningSubjectUsagePackage,
		SourceID: "example_source", Channel: "stable", PublisherID: "example.publisher",
		PluginID: "example.plugin", Version: "1.2.3",
		ArtifactIdentitySHA256: hex.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size)),
	}
	subjectDigest, err := SigningSubjectIdentitySHA256(subject)
	if err != nil {
		t.Fatal(err)
	}
	preimageDigest := hex.EncodeToString(bytes.Repeat([]byte{2}, sha256.Size))
	reserved := SigningLedgerEntryV1{
		SchemaVersion: SigningLedgerEntrySchemaVersion, State: SigningLedgerEntryReserved,
		Subject: subject, SubjectIdentitySHA256: subjectDigest, SigningPreimageSHA256: preimageDigest,
		Algorithm: SignatureAlgorithmEd25519, KeyID: "package_key", Revision: 1,
		ReservedAt: "2026-07-21T02:00:00Z",
	}
	if _, err := CanonicalSigningLedgerEntry(reserved); err != nil {
		t.Fatal(err)
	}

	envelope := SignatureEnvelopeV1{
		SchemaVersion: SigningEnvelopeSchemaVersion, SubjectIdentitySHA256: subjectDigest,
		SigningPreimageSHA256: preimageDigest, Algorithm: SignatureAlgorithmEd25519,
		KeyID: "package_key", Signature: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, ed25519.SignatureSize)),
	}
	envelopeBytes, err := CanonicalSignatureEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelopeDigest := sha256.Sum256(envelopeBytes)
	finalized := reserved
	finalized.State = SigningLedgerEntryFinalized
	finalized.SignatureEnvelope = &envelope
	finalized.SignatureEnvelopeSHA256 = hex.EncodeToString(envelopeDigest[:])
	finalized.FinalizedAt = "2026-07-21T02:00:01Z"
	if _, err := CanonicalSigningLedgerEntry(finalized); err != nil {
		t.Fatal(err)
	}

	failed := reserved
	failed.State = SigningLedgerEntryTerminalFailed
	failed.FailureCode = SigningLedgerFailureSignerRejected
	failed.FailedAt = "2026-07-21T02:00:01Z"
	if _, err := CanonicalSigningLedgerEntry(failed); err != nil {
		t.Fatal(err)
	}

	partial := finalized
	partial.SignatureEnvelopeSHA256 = ""
	if _, err := CanonicalSigningLedgerEntry(partial); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("partial finalization error = %v", err)
	}
	mixed := finalized
	mixed.FailureCode = SigningLedgerFailureSignerRejected
	mixed.FailedAt = "2026-07-21T02:00:01Z"
	if _, err := CanonicalSigningLedgerEntry(mixed); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("mixed terminal fields error = %v", err)
	}
}

func TestSigningLedgerReceiptAndProofsBindOneCheckpoint(t *testing.T) {
	fixture := newSigningLedgerFixture(t)
	if err := VerifySigningLedgerCheckpoint(fixture.checkpoint, fixture.verifier); err != nil {
		t.Fatal(err)
	}
	if err := VerifySigningLedgerReceipt(fixture.receipt, fixture.checkpoint, fixture.verifier); err != nil {
		t.Fatal(err)
	}
	if err := VerifySigningLedgerInclusion(fixture.receipt, fixture.inclusion, fixture.checkpoint, fixture.verifier); err != nil {
		t.Fatal(err)
	}
	if err := VerifySigningLedgerLatest(fixture.receipt, fixture.latest, fixture.checkpoint, fixture.verifier); err != nil {
		t.Fatal(err)
	}

	wrong := fixture.checkpoint
	wrong.LogRootHash = hex.EncodeToString(bytes.Repeat([]byte{8}, sha256.Size))
	if err := VerifySigningLedgerInclusion(fixture.receipt, fixture.inclusion, wrong, fixture.verifier); !errors.Is(err, ErrInvalidLedgerProof) && !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("checkpoint swap error = %v", err)
	}

	latest := fixture.latest
	latest.SignatureEnvelopeSHA256 = hex.EncodeToString(bytes.Repeat([]byte{6}, sha256.Size))
	if err := VerifySigningLedgerLatest(fixture.receipt, latest, fixture.checkpoint, fixture.verifier); !errors.Is(err, ErrInvalidLedgerProof) {
		t.Fatalf("latest-map swap error = %v", err)
	}
}

type signingLedgerFixture struct {
	checkpoint SigningLedgerCheckpointV1
	receipt    SigningLedgerReceiptV1
	inclusion  SigningLedgerInclusionProofV1
	latest     SigningLedgerLatestProofV1
	verifier   Ed25519PublicKeyVerifier
}

func newSigningLedgerFixture(t *testing.T) signingLedgerFixture {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	verifier := Ed25519PublicKeyVerifier{"ledger_key": privateKey.Public().(ed25519.PublicKey)}
	receipt := SigningLedgerReceiptV1{
		SchemaVersion: SigningLedgerReceiptSchemaVersion,
		LogID:         "signing_log", SourceID: "example_source", Channel: "stable",
		SubjectIdentitySHA256:   hex.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size)),
		SigningPreimageSHA256:   hex.EncodeToString(bytes.Repeat([]byte{2}, sha256.Size)),
		SignatureEnvelopeSHA256: hex.EncodeToString(bytes.Repeat([]byte{3}, sha256.Size)),
		Sequence:                1, LeafIndex: 0,
		TreeSize:       1,
		CheckpointTime: "2026-07-21T02:00:00Z",
		KeyID:          "ledger_key",
	}
	entryHash, err := signingLedgerLogLeafHash(receipt)
	if err != nil {
		t.Fatal(err)
	}
	latestSiblings := make([]string, SigningLedgerLatestProofDepth)
	for index := range latestSiblings {
		latestSiblings[index] = hex.EncodeToString(sparseEmptyHash())
	}
	latest := SigningLedgerLatestProofV1{
		SchemaVersion: SigningLedgerSchemaVersion, Kind: SigningLedgerArtifactLatestProof,
		LogID: receipt.LogID, SubjectIdentitySHA256: receipt.SubjectIdentitySHA256, Present: true,
		Sequence: receipt.Sequence, SigningPreimageSHA256: receipt.SigningPreimageSHA256,
		SignatureEnvelopeSHA256: receipt.SignatureEnvelopeSHA256, Siblings: latestSiblings,
	}
	latestRoot, err := signingLedgerLatestRoot(latest)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := SigningLedgerCheckpointV1{
		SchemaVersion: SigningLedgerSchemaVersion, Kind: SigningLedgerArtifactCheckpoint,
		LogID: receipt.LogID, TreeSize: 1, LogRootHash: hex.EncodeToString(entryHash), LatestMapRootHash: hex.EncodeToString(latestRoot),
		CheckpointTime: receipt.CheckpointTime, KeyID: "ledger_key",
	}
	checkpointPreimage, err := SigningLedgerCheckpointSigningPreimage(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Signature = base64.StdEncoding.EncodeToString(signReleasePreimage(privateKey, checkpointPreimage))
	checkpointBytes, err := CanonicalSigningLedgerCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest := sha256.Sum256(checkpointBytes)
	receipt.CheckpointSHA256 = hex.EncodeToString(checkpointDigest[:])
	receipt.LogRootHash = checkpoint.LogRootHash
	receipt.LatestMapRootHash = checkpoint.LatestMapRootHash
	receiptPreimage, err := SigningLedgerReceiptSigningPreimage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = base64.StdEncoding.EncodeToString(signReleasePreimage(privateKey, receiptPreimage))
	inclusion := SigningLedgerInclusionProofV1{
		SchemaVersion: SigningLedgerSchemaVersion, Kind: SigningLedgerArtifactInclusionProof,
		LogID: receipt.LogID, LeafIndex: 0, TreeSize: 1, Nodes: []string{},
	}
	return signingLedgerFixture{checkpoint: checkpoint, receipt: receipt, inclusion: inclusion, latest: latest, verifier: verifier}
}
