package releasecontract

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
)

const releaseContractMaxJSONSafeInteger uint64 = 1<<53 - 1

var ErrInvalidLedgerProof = errors.New("release signing ledger proof is invalid")

func CanonicalSigningSubject(subject SigningSubjectV1) ([]byte, error) {
	if err := validateSigningSubject(subject); err != nil {
		return nil, err
	}
	return canonicalJSON(subject)
}

func DecodeSigningSubject(raw []byte) (SigningSubjectV1, error) {
	var subject SigningSubjectV1
	if err := decodeCanonicalDocument(raw, &subject, func() error { return validateSigningSubject(subject) }); err != nil {
		return SigningSubjectV1{}, err
	}
	return subject, nil
}

func SigningSubjectIdentitySHA256(subject SigningSubjectV1) (string, error) {
	raw, err := CanonicalSigningSubject(subject)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validateSigningSubject(subject SigningSubjectV1) error {
	if subject.SchemaVersion != SigningSubjectSchemaVersion || !newContractIDPattern.MatchString(subject.SourceID) {
		return invalid("signing subject schema or source")
	}
	switch subject.Usage {
	case SigningSubjectUsageRootDelegation:
		if !positiveEpochPattern.MatchString(subject.RootEpoch) ||
			subject.Channel != "" || subject.PublisherID != "" || subject.PluginID != "" || subject.Version != "" ||
			subject.ArtifactIdentitySHA256 != "" || subject.Epoch != "" {
			return invalid("root signing subject")
		}
	case SigningSubjectUsagePackage, SigningSubjectUsageReleaseMetadata:
		if !newContractIDPattern.MatchString(subject.Channel) || !legacyIDPattern.MatchString(subject.PublisherID) ||
			!legacyIDPattern.MatchString(subject.PluginID) || !semverPattern.MatchString(subject.Version) ||
			!sha256Pattern.MatchString(subject.ArtifactIdentitySHA256) || subject.RootEpoch != "" || subject.Epoch != "" {
			return invalid("release signing subject")
		}
	case SigningSubjectUsageSourcePolicy, SigningSubjectUsageSourcePolicyPointer,
		SigningSubjectUsageRevocation, SigningSubjectUsageRevocationPointer:
		if !newContractIDPattern.MatchString(subject.Channel) ||
			!positiveEpochPattern.MatchString(subject.Epoch) || subject.RootEpoch != "" || subject.PublisherID != "" ||
			subject.PluginID != "" || subject.Version != "" || subject.ArtifactIdentitySHA256 != "" {
			return invalid("epoch signing subject")
		}
	default:
		return invalid("signing subject usage")
	}
	return nil
}

func signingUsageForSubject(usage SigningSubjectUsage) (SigningUsage, error) {
	switch usage {
	case SigningSubjectUsageRootDelegation:
		return SigningUsageRootDelegation, nil
	case SigningSubjectUsagePackage:
		return SigningUsagePackage, nil
	case SigningSubjectUsageReleaseMetadata:
		return SigningUsageReleaseMetadata, nil
	case SigningSubjectUsageSourcePolicy:
		return SigningUsageSourcePolicy, nil
	case SigningSubjectUsageSourcePolicyPointer:
		return SigningUsageSourcePolicyPointer, nil
	case SigningSubjectUsageRevocation:
		return SigningUsageRevocation, nil
	case SigningSubjectUsageRevocationPointer:
		return SigningUsageRevocationPointer, nil
	default:
		return "", ErrUnsupportedUsage
	}
}

func CanonicalSignatureEnvelope(envelope SignatureEnvelopeV1) ([]byte, error) {
	if err := validateSignatureEnvelope(envelope); err != nil {
		return nil, err
	}
	return canonicalJSON(envelope)
}

func DecodeSignatureEnvelope(raw []byte) (SignatureEnvelopeV1, error) {
	var envelope SignatureEnvelopeV1
	if err := decodeCanonicalDocument(raw, &envelope, func() error { return validateSignatureEnvelope(envelope) }); err != nil {
		return SignatureEnvelopeV1{}, err
	}
	return envelope, nil
}

func validateSignatureEnvelope(envelope SignatureEnvelopeV1) error {
	if envelope.SchemaVersion != SigningEnvelopeSchemaVersion || !sha256Pattern.MatchString(envelope.SubjectIdentitySHA256) ||
		!sha256Pattern.MatchString(envelope.SigningPreimageSHA256) || envelope.Algorithm != SignatureAlgorithmEd25519 ||
		!newContractIDPattern.MatchString(envelope.KeyID) {
		return invalid("signature envelope identity")
	}
	return validateSignatureString(envelope.Signature, true)
}

func CanonicalSigningLedgerEntry(entry SigningLedgerEntryV1) ([]byte, error) {
	if err := validateSigningLedgerEntry(entry); err != nil {
		return nil, err
	}
	return canonicalJSON(entry)
}

func DecodeSigningLedgerEntry(raw []byte) (SigningLedgerEntryV1, error) {
	var entry SigningLedgerEntryV1
	if err := decodeCanonicalDocument(raw, &entry, func() error { return validateSigningLedgerEntry(entry) }); err != nil {
		return SigningLedgerEntryV1{}, err
	}
	return entry, nil
}

func validateSigningLedgerEntry(entry SigningLedgerEntryV1) error {
	if entry.SchemaVersion != SigningLedgerEntrySchemaVersion ||
		!sha256Pattern.MatchString(entry.SubjectIdentitySHA256) ||
		!sha256Pattern.MatchString(entry.SigningPreimageSHA256) ||
		entry.Algorithm != SignatureAlgorithmEd25519 ||
		!newContractIDPattern.MatchString(entry.KeyID) || entry.Revision == 0 ||
		entry.Revision > releaseContractMaxJSONSafeInteger {
		return invalid("signing ledger entry shape")
	}
	if err := validateSigningSubject(entry.Subject); err != nil {
		return err
	}
	subjectDigest, err := SigningSubjectIdentitySHA256(entry.Subject)
	if err != nil || subjectDigest != entry.SubjectIdentitySHA256 {
		return invalid("signing ledger entry subject")
	}
	reservedAt, err := parseCanonicalTime(entry.ReservedAt)
	if err != nil {
		return invalid("signing ledger entry reserved_at")
	}

	switch entry.State {
	case SigningLedgerEntryReserved:
		if entry.SignatureEnvelope != nil || entry.SignatureEnvelopeSHA256 != "" || entry.FinalizedAt != "" ||
			entry.FailureCode != "" || entry.FailedAt != "" {
			return invalid("reserved signing ledger entry")
		}
	case SigningLedgerEntryFinalized:
		if entry.SignatureEnvelope == nil || !sha256Pattern.MatchString(entry.SignatureEnvelopeSHA256) ||
			entry.FinalizedAt == "" || entry.FailureCode != "" || entry.FailedAt != "" {
			return invalid("finalized signing ledger entry")
		}
		if err := validateSignatureEnvelope(*entry.SignatureEnvelope); err != nil {
			return err
		}
		envelope := *entry.SignatureEnvelope
		if envelope.SubjectIdentitySHA256 != entry.SubjectIdentitySHA256 ||
			envelope.SigningPreimageSHA256 != entry.SigningPreimageSHA256 ||
			envelope.Algorithm != entry.Algorithm || envelope.KeyID != entry.KeyID {
			return invalid("signing ledger entry envelope binding")
		}
		raw, err := CanonicalSignatureEnvelope(envelope)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		if entry.SignatureEnvelopeSHA256 != hex.EncodeToString(digest[:]) {
			return invalid("signing ledger entry envelope digest")
		}
		finalizedAt, err := parseCanonicalTime(entry.FinalizedAt)
		if err != nil || finalizedAt.Before(reservedAt) {
			return invalid("signing ledger entry finalized_at")
		}
	case SigningLedgerEntryTerminalFailed:
		if entry.SignatureEnvelope != nil || entry.SignatureEnvelopeSHA256 != "" || entry.FinalizedAt != "" ||
			!validSigningLedgerFailureCode(entry.FailureCode) || entry.FailedAt == "" {
			return invalid("terminal failed signing ledger entry")
		}
		failedAt, err := parseCanonicalTime(entry.FailedAt)
		if err != nil || failedAt.Before(reservedAt) {
			return invalid("signing ledger entry failed_at")
		}
	default:
		return invalid("signing ledger entry state")
	}
	return nil
}

func validSigningLedgerFailureCode(code SigningLedgerFailureCode) bool {
	switch code {
	case SigningLedgerFailureSignerRejected, SigningLedgerFailureSubjectConflict, SigningLedgerFailureLedgerRejected:
		return true
	default:
		return false
	}
}

func VerifySignatureEnvelope(subject SigningSubjectV1, signingPreimage []byte, envelope SignatureEnvelopeV1, verifier SignatureVerifier) error {
	if err := validateSigningSubject(subject); err != nil {
		return err
	}
	if err := validateSignatureEnvelope(envelope); err != nil {
		return err
	}
	subjectDigest, _ := SigningSubjectIdentitySHA256(subject)
	preimageDigest := sha256.Sum256(signingPreimage)
	if envelope.SubjectIdentitySHA256 != subjectDigest || envelope.SigningPreimageSHA256 != hex.EncodeToString(preimageDigest[:]) {
		return ErrInvalidSignature
	}
	usage, err := signingUsageForSubject(subject.Usage)
	if err != nil {
		return err
	}
	return verifyEncodedSignature(usage, envelope.KeyID, signingPreimage, envelope.Signature, verifier)
}

func CanonicalSigningLedgerCheckpoint(checkpoint SigningLedgerCheckpointV1) ([]byte, error) {
	if err := validateSigningLedgerCheckpoint(checkpoint, true); err != nil {
		return nil, err
	}
	return canonicalJSON(checkpoint)
}

func DecodeSigningLedgerCheckpoint(raw []byte) (SigningLedgerCheckpointV1, error) {
	var checkpoint SigningLedgerCheckpointV1
	if err := decodeCanonicalDocument(raw, &checkpoint, func() error { return validateSigningLedgerCheckpoint(checkpoint, true) }); err != nil {
		return SigningLedgerCheckpointV1{}, err
	}
	return checkpoint, nil
}

func SigningLedgerCheckpointSigningPreimage(checkpoint SigningLedgerCheckpointV1) ([]byte, error) {
	checkpoint.Signature = ""
	if err := validateSigningLedgerCheckpoint(checkpoint, false); err != nil {
		return nil, err
	}
	return signingPreimageWithoutTopLevelSignature(SigningUsageLedgerCheckpoint, checkpoint)
}

func VerifySigningLedgerCheckpoint(checkpoint SigningLedgerCheckpointV1, verifier SignatureVerifier) error {
	preimage, err := SigningLedgerCheckpointSigningPreimage(checkpoint)
	if err != nil {
		return err
	}
	return verifyEncodedSignature(SigningUsageLedgerCheckpoint, checkpoint.KeyID, preimage, checkpoint.Signature, verifier)
}

func validateSigningLedgerCheckpoint(checkpoint SigningLedgerCheckpointV1, requireSignature bool) error {
	if checkpoint.SchemaVersion != SigningLedgerSchemaVersion || checkpoint.Kind != SigningLedgerArtifactCheckpoint ||
		!newContractIDPattern.MatchString(checkpoint.LogID) || checkpoint.TreeSize == 0 || checkpoint.TreeSize > releaseContractMaxJSONSafeInteger ||
		!sha256Pattern.MatchString(checkpoint.LogRootHash) || !sha256Pattern.MatchString(checkpoint.LatestMapRootHash) ||
		!newContractIDPattern.MatchString(checkpoint.KeyID) {
		return invalid("signing ledger checkpoint shape")
	}
	if _, err := parseCanonicalTime(checkpoint.CheckpointTime); err != nil {
		return invalid("signing ledger checkpoint time")
	}
	return validateSignatureString(checkpoint.Signature, requireSignature)
}

func CanonicalSigningLedgerReceipt(receipt SigningLedgerReceiptV1) ([]byte, error) {
	if err := validateSigningLedgerReceipt(receipt, true); err != nil {
		return nil, err
	}
	return canonicalJSON(receipt)
}

func DecodeSigningLedgerReceipt(raw []byte) (SigningLedgerReceiptV1, error) {
	var receipt SigningLedgerReceiptV1
	if err := decodeCanonicalDocument(raw, &receipt, func() error { return validateSigningLedgerReceipt(receipt, true) }); err != nil {
		return SigningLedgerReceiptV1{}, err
	}
	return receipt, nil
}

func SigningLedgerReceiptSigningPreimage(receipt SigningLedgerReceiptV1) ([]byte, error) {
	receipt.Signature = ""
	if err := validateSigningLedgerReceipt(receipt, false); err != nil {
		return nil, err
	}
	return signingPreimageWithoutTopLevelSignature(SigningUsageLedgerReceipt, receipt)
}

func VerifySigningLedgerReceipt(receipt SigningLedgerReceiptV1, checkpoint SigningLedgerCheckpointV1, verifier SignatureVerifier) error {
	if err := VerifySigningLedgerCheckpoint(checkpoint, verifier); err != nil {
		return err
	}
	checkpointBytes, err := CanonicalSigningLedgerCheckpoint(checkpoint)
	if err != nil {
		return err
	}
	checkpointDigest := sha256.Sum256(checkpointBytes)
	if receipt.LogID != checkpoint.LogID || receipt.TreeSize != checkpoint.TreeSize || receipt.LogRootHash != checkpoint.LogRootHash ||
		receipt.LatestMapRootHash != checkpoint.LatestMapRootHash || receipt.CheckpointTime != checkpoint.CheckpointTime ||
		receipt.CheckpointSHA256 != hex.EncodeToString(checkpointDigest[:]) || receipt.KeyID != checkpoint.KeyID {
		return ErrInvalidLedgerProof
	}
	preimage, err := SigningLedgerReceiptSigningPreimage(receipt)
	if err != nil {
		return err
	}
	return verifyEncodedSignature(SigningUsageLedgerReceipt, receipt.KeyID, preimage, receipt.Signature, verifier)
}

func validateSigningLedgerReceipt(receipt SigningLedgerReceiptV1, requireSignature bool) error {
	if receipt.SchemaVersion != SigningLedgerReceiptSchemaVersion || !newContractIDPattern.MatchString(receipt.LogID) ||
		!newContractIDPattern.MatchString(receipt.SourceID) || (receipt.Channel != "" && !newContractIDPattern.MatchString(receipt.Channel)) ||
		!sha256Pattern.MatchString(receipt.SubjectIdentitySHA256) || !sha256Pattern.MatchString(receipt.SigningPreimageSHA256) ||
		!sha256Pattern.MatchString(receipt.SignatureEnvelopeSHA256) || receipt.Sequence == 0 || receipt.Sequence > releaseContractMaxJSONSafeInteger ||
		receipt.LeafIndex != receipt.Sequence-1 || receipt.TreeSize < receipt.Sequence || receipt.TreeSize > releaseContractMaxJSONSafeInteger ||
		!sha256Pattern.MatchString(receipt.LogRootHash) || !sha256Pattern.MatchString(receipt.LatestMapRootHash) ||
		!sha256Pattern.MatchString(receipt.CheckpointSHA256) || !newContractIDPattern.MatchString(receipt.KeyID) {
		return invalid("signing ledger receipt shape")
	}
	if _, err := parseCanonicalTime(receipt.CheckpointTime); err != nil {
		return invalid("signing ledger receipt time")
	}
	return validateSignatureString(receipt.Signature, requireSignature)
}

func SigningLedgerLogLeafFromReceipt(receipt SigningLedgerReceiptV1) (SigningLedgerLogLeafV1, error) {
	leaf := SigningLedgerLogLeafV1{
		SchemaVersion: SigningLedgerLogLeafSchemaVersion, SourceID: receipt.SourceID, Channel: receipt.Channel,
		SubjectIdentitySHA256: receipt.SubjectIdentitySHA256, SigningPreimageSHA256: receipt.SigningPreimageSHA256,
		SignatureEnvelopeSHA256: receipt.SignatureEnvelopeSHA256, Sequence: receipt.Sequence,
	}
	if _, err := CanonicalSigningLedgerLogLeaf(leaf); err != nil {
		return SigningLedgerLogLeafV1{}, err
	}
	return leaf, nil
}

func CanonicalSigningLedgerLogLeaf(leaf SigningLedgerLogLeafV1) ([]byte, error) {
	if leaf.SchemaVersion != SigningLedgerLogLeafSchemaVersion || !newContractIDPattern.MatchString(leaf.SourceID) ||
		(leaf.Channel != "" && !newContractIDPattern.MatchString(leaf.Channel)) ||
		!sha256Pattern.MatchString(leaf.SubjectIdentitySHA256) || !sha256Pattern.MatchString(leaf.SigningPreimageSHA256) ||
		!sha256Pattern.MatchString(leaf.SignatureEnvelopeSHA256) || leaf.Sequence == 0 || leaf.Sequence > releaseContractMaxJSONSafeInteger {
		return nil, invalid("signing ledger log leaf")
	}
	return canonicalJSON(leaf)
}

func signingLedgerLogLeafHash(receipt SigningLedgerReceiptV1) ([]byte, error) {
	leaf, err := SigningLedgerLogLeafFromReceipt(receipt)
	if err != nil {
		return nil, err
	}
	raw, err := CanonicalSigningLedgerLogLeaf(leaf)
	if err != nil {
		return nil, err
	}
	return ledgerLeafHash(raw), nil
}

func VerifySigningLedgerInclusion(receipt SigningLedgerReceiptV1, proof SigningLedgerInclusionProofV1, checkpoint SigningLedgerCheckpointV1, verifier SignatureVerifier) error {
	if err := VerifySigningLedgerReceipt(receipt, checkpoint, verifier); err != nil {
		return err
	}
	if err := validateSigningLedgerInclusionProof(proof); err != nil {
		return err
	}
	if proof.LogID != receipt.LogID || proof.LogID != checkpoint.LogID || proof.LeafIndex != receipt.LeafIndex ||
		proof.TreeSize != receipt.TreeSize || proof.TreeSize != checkpoint.TreeSize || receipt.LogRootHash != checkpoint.LogRootHash {
		return ErrInvalidLedgerProof
	}
	leaf, err := signingLedgerLogLeafHash(receipt)
	if err != nil {
		return err
	}
	nodes, err := decodeLedgerProofNodes(proof.Nodes, 64)
	if err != nil {
		return err
	}
	root, _ := hex.DecodeString(checkpoint.LogRootHash)
	if !verifyLedgerInclusion(leaf, proof.LeafIndex, proof.TreeSize, nodes, root) {
		return ErrInvalidLedgerProof
	}
	return nil
}

func CanonicalSigningLedgerInclusionProof(proof SigningLedgerInclusionProofV1) ([]byte, error) {
	if err := validateSigningLedgerInclusionProof(proof); err != nil {
		return nil, err
	}
	proof.Nodes = slices.Clone(proof.Nodes)
	return canonicalJSON(proof)
}

func DecodeSigningLedgerInclusionProof(raw []byte) (SigningLedgerInclusionProofV1, error) {
	var proof SigningLedgerInclusionProofV1
	if err := decodeCanonicalDocument(raw, &proof, func() error { return validateSigningLedgerInclusionProof(proof) }); err != nil {
		return SigningLedgerInclusionProofV1{}, err
	}
	proof.Nodes = slices.Clone(proof.Nodes)
	return proof, nil
}

func validateSigningLedgerInclusionProof(proof SigningLedgerInclusionProofV1) error {
	if proof.SchemaVersion != SigningLedgerSchemaVersion || proof.Kind != SigningLedgerArtifactInclusionProof ||
		!newContractIDPattern.MatchString(proof.LogID) || proof.TreeSize == 0 || proof.TreeSize > releaseContractMaxJSONSafeInteger ||
		proof.LeafIndex >= proof.TreeSize || len(proof.Nodes) > 64 {
		return invalid("signing ledger inclusion proof")
	}
	_, err := decodeLedgerProofNodes(proof.Nodes, 64)
	return err
}

func CanonicalSigningLedgerLatestProof(proof SigningLedgerLatestProofV1) ([]byte, error) {
	if err := validateSigningLedgerLatestProof(proof); err != nil {
		return nil, err
	}
	proof.Siblings = slices.Clone(proof.Siblings)
	return canonicalJSON(proof)
}

func DecodeSigningLedgerLatestProof(raw []byte) (SigningLedgerLatestProofV1, error) {
	var proof SigningLedgerLatestProofV1
	if err := decodeCanonicalDocument(raw, &proof, func() error { return validateSigningLedgerLatestProof(proof) }); err != nil {
		return SigningLedgerLatestProofV1{}, err
	}
	proof.Siblings = slices.Clone(proof.Siblings)
	return proof, nil
}

func VerifySigningLedgerLatest(receipt SigningLedgerReceiptV1, proof SigningLedgerLatestProofV1, checkpoint SigningLedgerCheckpointV1, verifier SignatureVerifier) error {
	if err := VerifySigningLedgerReceipt(receipt, checkpoint, verifier); err != nil {
		return err
	}
	if err := validateSigningLedgerLatestProof(proof); err != nil {
		return err
	}
	if !proof.Present || proof.LogID != receipt.LogID || proof.LogID != checkpoint.LogID ||
		proof.SubjectIdentitySHA256 != receipt.SubjectIdentitySHA256 || proof.Sequence != receipt.Sequence ||
		proof.SigningPreimageSHA256 != receipt.SigningPreimageSHA256 || proof.SignatureEnvelopeSHA256 != receipt.SignatureEnvelopeSHA256 ||
		receipt.LatestMapRootHash != checkpoint.LatestMapRootHash {
		return ErrInvalidLedgerProof
	}
	root, err := signingLedgerLatestRoot(proof)
	if err != nil {
		return err
	}
	if hex.EncodeToString(root) != checkpoint.LatestMapRootHash {
		return ErrInvalidLedgerProof
	}
	return nil
}

func validateSigningLedgerLatestProof(proof SigningLedgerLatestProofV1) error {
	if proof.SchemaVersion != SigningLedgerSchemaVersion || proof.Kind != SigningLedgerArtifactLatestProof ||
		!newContractIDPattern.MatchString(proof.LogID) || !sha256Pattern.MatchString(proof.SubjectIdentitySHA256) ||
		len(proof.Siblings) != SigningLedgerLatestProofDepth {
		return invalid("signing ledger latest proof")
	}
	if proof.Present {
		if proof.Sequence == 0 || proof.Sequence > releaseContractMaxJSONSafeInteger || !sha256Pattern.MatchString(proof.SigningPreimageSHA256) ||
			!sha256Pattern.MatchString(proof.SignatureEnvelopeSHA256) {
			return invalid("signing ledger latest membership")
		}
	} else if proof.Sequence != 0 || proof.SigningPreimageSHA256 != "" || proof.SignatureEnvelopeSHA256 != "" {
		return invalid("signing ledger latest non-membership")
	}
	_, err := decodeLedgerProofNodes(proof.Siblings, SigningLedgerLatestProofDepth)
	return err
}

func signingLedgerLatestRoot(proof SigningLedgerLatestProofV1) ([]byte, error) {
	if err := validateSigningLedgerLatestProof(proof); err != nil {
		return nil, err
	}
	key, _ := hex.DecodeString(proof.SubjectIdentitySHA256)
	var current []byte
	if proof.Present {
		preimage, _ := hex.DecodeString(proof.SigningPreimageSHA256)
		envelope, _ := hex.DecodeString(proof.SignatureEnvelopeSHA256)
		sequence := make([]byte, 8)
		binary.BigEndian.PutUint64(sequence, proof.Sequence)
		value := make([]byte, 1, 1+len(key)+len(sequence)+len(preimage)+len(envelope))
		value[0] = 3
		value = append(value, key...)
		value = append(value, sequence...)
		value = append(value, preimage...)
		value = append(value, envelope...)
		digest := sha256.Sum256(value)
		current = digest[:]
	} else {
		current = sparseEmptyHash()
	}
	siblings, _ := decodeLedgerProofNodes(proof.Siblings, SigningLedgerLatestProofDepth)
	for level, sibling := range siblings {
		bitIndex := SigningLedgerLatestProofDepth - 1 - level
		bit := (key[bitIndex/8] >> uint(7-bitIndex%8)) & 1
		if bit == 0 {
			current = ledgerMapNodeHash(current, sibling)
		} else {
			current = ledgerMapNodeHash(sibling, current)
		}
	}
	return current, nil
}

func sparseEmptyHash() []byte { return make([]byte, sha256.Size) }

func ledgerMapNodeHash(left, right []byte) []byte {
	value := make([]byte, 1, 1+len(left)+len(right))
	value[0] = 4
	value = append(value, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}

func CanonicalSigningLedgerConsistencyProof(proof SigningLedgerConsistencyProofV1) ([]byte, error) {
	if err := validateSigningLedgerConsistencyProof(proof); err != nil {
		return nil, err
	}
	proof.Nodes = slices.Clone(proof.Nodes)
	return canonicalJSON(proof)
}

func DecodeSigningLedgerConsistencyProof(raw []byte) (SigningLedgerConsistencyProofV1, error) {
	var proof SigningLedgerConsistencyProofV1
	if err := decodeCanonicalDocument(raw, &proof, func() error { return validateSigningLedgerConsistencyProof(proof) }); err != nil {
		return SigningLedgerConsistencyProofV1{}, err
	}
	proof.Nodes = slices.Clone(proof.Nodes)
	return proof, nil
}

func VerifySigningLedgerConsistency(previous, current SigningLedgerCheckpointV1, proof SigningLedgerConsistencyProofV1, verifier SignatureVerifier) error {
	if err := VerifySigningLedgerCheckpoint(previous, verifier); err != nil {
		return err
	}
	if err := VerifySigningLedgerCheckpoint(current, verifier); err != nil {
		return err
	}
	if err := validateSigningLedgerConsistencyProof(proof); err != nil {
		return err
	}
	if previous.LogID != current.LogID || proof.LogID != current.LogID || proof.OldTreeSize != previous.TreeSize || proof.NewTreeSize != current.TreeSize {
		return ErrInvalidLedgerProof
	}
	oldRoot, _ := hex.DecodeString(previous.LogRootHash)
	newRoot, _ := hex.DecodeString(current.LogRootHash)
	nodes, _ := decodeLedgerProofNodes(proof.Nodes, 64)
	if !verifyLedgerConsistency(previous.TreeSize, current.TreeSize, oldRoot, newRoot, nodes) {
		return ErrInvalidLedgerProof
	}
	return nil
}

func validateSigningLedgerConsistencyProof(proof SigningLedgerConsistencyProofV1) error {
	if proof.SchemaVersion != SigningLedgerSchemaVersion || proof.Kind != SigningLedgerArtifactConsistencyProof ||
		!newContractIDPattern.MatchString(proof.LogID) || proof.OldTreeSize == 0 || proof.OldTreeSize > proof.NewTreeSize ||
		proof.NewTreeSize > releaseContractMaxJSONSafeInteger || len(proof.Nodes) > 64 {
		return invalid("signing ledger consistency proof")
	}
	_, err := decodeLedgerProofNodes(proof.Nodes, 64)
	return err
}

func decodeLedgerProofNodes(values []string, maximum int) ([][]byte, error) {
	if len(values) > maximum {
		return nil, ErrInvalidLedgerProof
	}
	result := make([][]byte, len(values))
	for index, value := range values {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
			return nil, ErrInvalidLedgerProof
		}
		result[index] = decoded
	}
	return result, nil
}

func ledgerLeafHash(value []byte) []byte {
	digest := sha256.Sum256(append([]byte{0}, value...))
	return digest[:]
}

func ledgerNodeHash(left, right []byte) []byte {
	value := make([]byte, 1, 1+len(left)+len(right))
	value[0] = 1
	value = append(value, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}

func verifyLedgerInclusion(leaf []byte, leafIndex, treeSize uint64, proof [][]byte, root []byte) bool {
	if treeSize == 0 || leafIndex >= treeSize || len(leaf) != sha256.Size || len(root) != sha256.Size {
		return false
	}
	fn, sn := leafIndex, treeSize-1
	calculated := slices.Clone(leaf)
	for _, node := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			calculated = ledgerNodeHash(node, calculated)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			calculated = ledgerNodeHash(calculated, node)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && slices.Equal(calculated, root)
}

func verifyLedgerConsistency(oldSize, newSize uint64, oldRoot, newRoot []byte, proof [][]byte) bool {
	if oldSize == 0 || oldSize > newSize || len(oldRoot) != sha256.Size || len(newRoot) != sha256.Size {
		return false
	}
	if oldSize == newSize {
		return len(proof) == 0 && slices.Equal(oldRoot, newRoot)
	}
	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	var first, second []byte
	proofIndex := 0
	if fn == 0 {
		first = slices.Clone(oldRoot)
		second = slices.Clone(oldRoot)
	} else {
		if len(proof) == 0 {
			return false
		}
		first = slices.Clone(proof[0])
		second = slices.Clone(proof[0])
		proofIndex = 1
	}
	for ; proofIndex < len(proof); proofIndex++ {
		if sn == 0 {
			return false
		}
		node := proof[proofIndex]
		if fn&1 == 1 || fn == sn {
			first = ledgerNodeHash(node, first)
			second = ledgerNodeHash(node, second)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			second = ledgerNodeHash(second, node)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && slices.Equal(first, oldRoot) && slices.Equal(second, newRoot)
}

func SignatureEnvelopeSHA256(envelope SignatureEnvelopeV1) (string, error) {
	raw, err := CanonicalSignatureEnvelope(envelope)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func decodeLedgerSignature(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 64 {
		return nil, fmt.Errorf("%w: ledger signature", ErrInvalidDocument)
	}
	return decoded, nil
}
