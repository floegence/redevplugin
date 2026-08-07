package releasepublisher

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

type ledgerValue struct {
	subject       releasecontract.SigningSubjectV1
	subjectDigest string
	preimageHash  string
	envelopeHash  string
	sequence      uint64
}

type ledgerDraft struct {
	values                  []ledgerValue
	logLeafDocuments        []releasecontract.SigningLedgerLogLeafV1
	logLeaves               [][]byte
	latestProofs            map[string][]string
	receiptValueIndexes     []int
	checkpoint              releasecontract.SigningLedgerCheckpointV1
	checkpointPreimage      []byte
	previousCheckpoint      *releasecontract.SigningLedgerCheckpointV1
	previousCheckpointBytes []byte
	consistency             *releasecontract.SigningLedgerConsistencyProofV1
}

type receiptDraft struct {
	value     ledgerValue
	index     int
	receipt   releasecontract.SigningLedgerReceiptV1
	preimage  []byte
	inclusion releasecontract.SigningLedgerInclusionProofV1
	latest    releasecontract.SigningLedgerLatestProofV1
}

func prepareLedger(config ConfigV1, documents []signedDocument, previous *previousReleaseStateV1) (ledgerDraft, error) {
	previousCount := 0
	if previous != nil {
		previousCount = len(previous.LedgerLeaves)
	}
	values := make([]ledgerValue, previousCount)
	logLeafDocuments := make([]releasecontract.SigningLedgerLogLeafV1, previousCount)
	logLeaves := make([][]byte, previousCount)
	valueIndexBySubject := make(map[string]int, previousCount+len(documents))
	if previous != nil {
		for index, leaf := range previous.LedgerLeaves {
			raw, err := releasecontract.CanonicalSigningLedgerLogLeaf(leaf)
			if err != nil {
				return ledgerDraft{}, err
			}
			logLeafDocuments[index] = leaf
			logLeaves[index] = merkleLeafHash(raw)
			values[index] = ledgerValue{
				subjectDigest: leaf.SubjectIdentitySHA256, preimageHash: leaf.SigningPreimageSHA256,
				envelopeHash: leaf.SignatureEnvelopeSHA256, sequence: leaf.Sequence,
			}
			valueIndexBySubject[leaf.SubjectIdentitySHA256] = index
		}
	}
	receiptValueIndexes := make([]int, 0, len(documents))
	for _, document := range documents {
		subjectDigest, err := releasecontract.SigningSubjectIdentitySHA256(document.subject)
		if err != nil {
			return ledgerDraft{}, err
		}
		preimageDigest := sha256.Sum256(document.preimage)
		envelope := releasecontract.SignatureEnvelopeV1{
			SchemaVersion: releasecontract.SigningEnvelopeSchemaVersion, SubjectIdentitySHA256: subjectDigest,
			SigningPreimageSHA256: hex.EncodeToString(preimageDigest[:]), Algorithm: releasecontract.SignatureAlgorithmEd25519,
			KeyID: document.keyID, Signature: document.signature,
		}
		envelopeBytes, err := releasecontract.CanonicalSignatureEnvelope(envelope)
		if err != nil {
			return ledgerDraft{}, err
		}
		if existingIndex, exists := valueIndexBySubject[subjectDigest]; exists {
			existing := &values[existingIndex]
			if existing.preimageHash != envelope.SigningPreimageSHA256 || existing.envelopeHash != sha256Hex(envelopeBytes) {
				return ledgerDraft{}, ErrWorkspaceConflict
			}
			existing.subject = document.subject
			receiptValueIndexes = append(receiptValueIndexes, existingIndex)
			continue
		}
		valueIndex := len(values)
		leaf := releasecontract.SigningLedgerLogLeafV1{
			SchemaVersion: releasecontract.SigningLedgerLogLeafSchemaVersion, SourceID: document.subject.SourceID,
			Channel: document.subject.Channel, SubjectIdentitySHA256: subjectDigest, SigningPreimageSHA256: envelope.SigningPreimageSHA256,
			SignatureEnvelopeSHA256: sha256Hex(envelopeBytes), Sequence: uint64(valueIndex + 1),
		}
		leafBytes, err := releasecontract.CanonicalSigningLedgerLogLeaf(leaf)
		if err != nil {
			return ledgerDraft{}, err
		}
		logLeafDocuments = append(logLeafDocuments, leaf)
		logLeaves = append(logLeaves, merkleLeafHash(leafBytes))
		values = append(values, ledgerValue{subject: document.subject, subjectDigest: subjectDigest, preimageHash: envelope.SigningPreimageSHA256, envelopeHash: sha256Hex(envelopeBytes), sequence: uint64(valueIndex + 1)})
		valueIndexBySubject[subjectDigest] = valueIndex
		receiptValueIndexes = append(receiptValueIndexes, valueIndex)
	}
	latestRoot, latestProofs := latestMap(values)
	checkpointTime, err := parseCanonicalTime(config.GeneratedAt)
	if err != nil {
		return ledgerDraft{}, err
	}
	checkpoint := releasecontract.SigningLedgerCheckpointV1{
		SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactCheckpoint,
		LogID: config.SigningLedger.LogID, TreeSize: uint64(len(values)), LogRootHash: hex.EncodeToString(merkleRoot(logLeaves)),
		LatestMapRootHash: hex.EncodeToString(latestRoot), CheckpointTime: checkpointTime.Add(time.Hour).Format(time.RFC3339Nano),
		KeyID: config.SigningLedger.KeyID,
	}
	preimage, err := releasecontract.SigningLedgerCheckpointSigningPreimage(checkpoint)
	if err != nil {
		return ledgerDraft{}, err
	}
	draft := ledgerDraft{
		values: values, logLeafDocuments: logLeafDocuments, logLeaves: logLeaves, latestProofs: latestProofs,
		receiptValueIndexes: receiptValueIndexes, checkpoint: checkpoint, checkpointPreimage: preimage,
	}
	if previous != nil {
		proof := releasecontract.SigningLedgerConsistencyProofV1{
			SchemaVersion: releasecontract.SigningLedgerSchemaVersion,
			Kind:          releasecontract.SigningLedgerArtifactConsistencyProof,
			LogID:         config.SigningLedger.LogID,
			OldTreeSize:   previous.Checkpoint.TreeSize,
			NewTreeSize:   checkpoint.TreeSize,
			Nodes:         encodeProof(merkleConsistencyProof(logLeaves, previousCount)),
		}
		draft.previousCheckpoint = &previous.Checkpoint
		draft.previousCheckpointBytes = slices.Clone(previous.CheckpointBytes)
		draft.consistency = &proof
	}
	return draft, nil
}

func finalizeLedgerCheckpoint(config ConfigV1, draft ledgerDraft, signature []byte) (releasecontract.SigningLedgerCheckpointV1, []byte, error) {
	checkpoint := draft.checkpoint
	checkpoint.Signature = base64.StdEncoding.EncodeToString(signature)
	bytes, err := releasecontract.CanonicalSigningLedgerCheckpoint(checkpoint)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, nil, err
	}
	keys, _ := validateConfig(config)
	if err := releasecontract.VerifySigningLedgerCheckpoint(checkpoint, releasecontract.Ed25519PublicKeyVerifier(keys)); err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, nil, err
	}
	return checkpoint, bytes, nil
}

func prepareLedgerReceipts(config ConfigV1, draft ledgerDraft, checkpoint releasecontract.SigningLedgerCheckpointV1, checkpointBytes []byte) ([]receiptDraft, []ExternalSignerRequestV1, error) {
	checkpointSHA256 := sha256Hex(checkpointBytes)
	receipts := make([]receiptDraft, len(draft.receiptValueIndexes))
	requests := make([]ExternalSignerRequestV1, len(draft.receiptValueIndexes))
	for relativeIndex, index := range draft.receiptValueIndexes {
		value := draft.values[index]
		receipt := releasecontract.SigningLedgerReceiptV1{
			SchemaVersion: releasecontract.SigningLedgerReceiptSchemaVersion, LogID: config.SigningLedger.LogID,
			SourceID: value.subject.SourceID, Channel: value.subject.Channel, SubjectIdentitySHA256: value.subjectDigest,
			SigningPreimageSHA256: value.preimageHash, SignatureEnvelopeSHA256: value.envelopeHash,
			Sequence: value.sequence, LeafIndex: uint64(index), TreeSize: uint64(len(draft.values)),
			LogRootHash: checkpoint.LogRootHash, LatestMapRootHash: checkpoint.LatestMapRootHash,
			CheckpointSHA256: checkpointSHA256, CheckpointTime: checkpoint.CheckpointTime, KeyID: config.SigningLedger.KeyID,
		}
		preimage, err := releasecontract.SigningLedgerReceiptSigningPreimage(receipt)
		if err != nil {
			return nil, nil, err
		}
		request, err := NewExternalSignerRequest(releasecontract.SigningUsageLedgerReceipt, config.SigningLedger.KeyID, value.subject, preimage)
		if err != nil {
			return nil, nil, err
		}
		receipts[relativeIndex] = receiptDraft{
			value: value, index: index, receipt: receipt, preimage: preimage,
			inclusion: releasecontract.SigningLedgerInclusionProofV1{
				SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactInclusionProof,
				LogID: config.SigningLedger.LogID, LeafIndex: uint64(index), TreeSize: uint64(len(draft.values)), Nodes: encodeProof(merkleInclusionProof(draft.logLeaves, index)),
			},
			latest: releasecontract.SigningLedgerLatestProofV1{
				SchemaVersion: releasecontract.SigningLedgerSchemaVersion, Kind: releasecontract.SigningLedgerArtifactLatestProof,
				LogID: config.SigningLedger.LogID, SubjectIdentitySHA256: value.subjectDigest, Present: true, Sequence: value.sequence,
				SigningPreimageSHA256: value.preimageHash, SignatureEnvelopeSHA256: value.envelopeHash, Siblings: draft.latestProofs[value.subjectDigest],
			},
		}
		requests[relativeIndex] = request
	}
	return receipts, requests, nil
}

func buildCompleteAssembly(
	config ConfigV1,
	pointers signedPointers,
	checkpoint releasecontract.SigningLedgerCheckpointV1,
	checkpointBytes []byte,
	receipts []receiptDraft,
	requests []ExternalSignerRequestV1,
	responses map[string]string,
) (assemblyResult, error) {
	files := map[string][]byte{
		fmt.Sprintf("sources/%s/root/current.json", config.SourceID):                          pointers.primary.rootBytes,
		fmt.Sprintf("sources/%s/%s/policy/current.json", config.SourceID, config.Channel):     pointers.policyPointerBytes,
		pointers.primary.policyPointerInput.Ref:                                               pointers.primary.policyBytes,
		fmt.Sprintf("sources/%s/%s/revocation/current.json", config.SourceID, config.Channel): pointers.revocationPointerBytes,
		pointers.primary.revocationPointerInput.Ref:                                           pointers.primary.revocationBytes,
		pointers.primary.prepared.releaseMetadataRef:                                          pointers.primary.prepared.metadataBytes,
		pointers.primary.prepared.releaseMetadataSignatureRef:                                 slices.Clone(pointers.primary.metadataSignature),
		pointers.primary.prepared.packageArtifactRef:                                          slices.Clone(pointers.primary.signedPackage),
	}
	packageRequest, _ := requestForUsage(requestsForPrimaryMust(config, pointers.primary.prepared), releasecontract.SigningUsagePackage)
	packageSignatureBytes, err := signatureFor(packageRequest, responses)
	if err != nil {
		return assemblyResult{}, err
	}
	packageSignature, err := releasecontract.BuildPackageSignature(pointers.primary.prepared.packageInput, packageSignatureBytes)
	if err != nil {
		return assemblyResult{}, err
	}
	packageSignatureDocument, err := releasecontract.CanonicalPackageSignature(
		releasecontract.PackageVerificationContext{SourceID: config.SourceID, Channel: config.Channel, Version: pointers.primary.prepared.pkg.Manifest.Version()},
		packageSignature,
	)
	if err != nil {
		return assemblyResult{}, err
	}
	files[pointers.primary.prepared.packageSignatureRef] = packageSignatureDocument
	checkpointSHA256 := sha256Hex(checkpointBytes)
	ledgerBase := fmt.Sprintf("sources/%s/signing-ledger", config.SourceID)
	checkpointRef := fmt.Sprintf("%s/checkpoints/%s.json", ledgerBase, checkpointSHA256)
	files[checkpointRef] = checkpointBytes
	files[ledgerBase+"/checkpoints/current.json"] = checkpointBytes
	keys, _ := validateConfig(config)
	verifier := releasecontract.Ed25519PublicKeyVerifier(keys)
	consistencyRef := ""
	consistencySHA256 := ""
	previousCheckpointSHA256 := ""
	if previous := pointers.ledger.previousCheckpoint; previous != nil {
		previousSHA256 := sha256Hex(pointers.ledger.previousCheckpointBytes)
		previousCheckpointSHA256 = previousSHA256
		files[fmt.Sprintf("%s/checkpoints/%s.json", ledgerBase, previousSHA256)] = slices.Clone(pointers.ledger.previousCheckpointBytes)
		consistencyBytes, err := releasecontract.CanonicalSigningLedgerConsistencyProof(*pointers.ledger.consistency)
		if err != nil || releasecontract.VerifySigningLedgerConsistency(*previous, checkpoint, *pointers.ledger.consistency, verifier) != nil {
			return assemblyResult{}, ErrInvalidWorkspace
		}
		consistencyRef = fmt.Sprintf("%s/proofs/consistency/%s/%s.json", ledgerBase, previousSHA256, checkpointSHA256)
		consistencySHA256 = sha256Hex(consistencyBytes)
		files[consistencyRef] = consistencyBytes
	}
	for _, leaf := range pointers.ledger.logLeafDocuments {
		leafBytes, err := releasecontract.CanonicalSigningLedgerLogLeaf(leaf)
		if err != nil {
			return assemblyResult{}, err
		}
		files[fmt.Sprintf("%s/log/%020d.json", ledgerBase, leaf.Sequence)] = leafBytes
	}
	for index, draft := range receipts {
		signature, err := signatureFor(requests[index], responses)
		if err != nil {
			return assemblyResult{}, err
		}
		receipt := draft.receipt
		receipt.Signature = base64.StdEncoding.EncodeToString(signature)
		receiptBytes, err := releasecontract.CanonicalSigningLedgerReceipt(receipt)
		if err != nil {
			return assemblyResult{}, err
		}
		if err := releasecontract.VerifySigningLedgerReceipt(receipt, checkpoint, verifier); err != nil {
			return assemblyResult{}, err
		}
		inclusionBytes, err := releasecontract.CanonicalSigningLedgerInclusionProof(draft.inclusion)
		if err != nil {
			return assemblyResult{}, err
		}
		latestBytes, err := releasecontract.CanonicalSigningLedgerLatestProof(draft.latest)
		if err != nil {
			return assemblyResult{}, err
		}
		if err := releasecontract.VerifySigningLedgerInclusion(receipt, draft.inclusion, checkpoint, verifier); err != nil {
			return assemblyResult{}, err
		}
		if err := releasecontract.VerifySigningLedgerLatest(receipt, draft.latest, checkpoint, verifier); err != nil {
			return assemblyResult{}, err
		}
		receiptRef := fmt.Sprintf("%s/receipts/%s.json", ledgerBase, draft.value.subjectDigest)
		inclusionRef := fmt.Sprintf("%s/proofs/inclusion/%s.json", ledgerBase, draft.value.subjectDigest)
		latestRef := fmt.Sprintf("%s/proofs/latest/%s.json", ledgerBase, draft.value.subjectDigest)
		evidence := releasecontract.SigningLedgerEvidenceV1{
			SchemaVersion: releasecontract.SigningLedgerEvidenceSchemaVersion, SourceID: draft.value.subject.SourceID,
			Channel: draft.value.subject.Channel, SubjectIdentitySHA256: draft.value.subjectDigest,
			SigningPreimageSHA256: draft.value.preimageHash, SignatureEnvelopeSHA256: draft.value.envelopeHash,
			ReceiptRef: receiptRef, ReceiptSHA256: sha256Hex(receiptBytes), CheckpointRef: checkpointRef, CheckpointSHA256: checkpointSHA256,
			InclusionProofRef: inclusionRef, InclusionProofSHA256: sha256Hex(inclusionBytes), LatestProofRef: latestRef, LatestProofSHA256: sha256Hex(latestBytes),
		}
		evidenceBytes, err := releasecontract.CanonicalSigningLedgerEvidence(evidence)
		if err != nil {
			return assemblyResult{}, err
		}
		files[fmt.Sprintf("%s/evidence/%s.json", ledgerBase, draft.value.subjectDigest)] = evidenceBytes
		if consistencyRef != "" && sourceRefreshSubject(draft.value.subject.Usage) {
			continuityEvidence := evidence
			continuityEvidence.ConsistencyProofRef = consistencyRef
			continuityEvidence.ConsistencyProofSHA256 = consistencySHA256
			continuityBytes, err := releasecontract.CanonicalSigningLedgerEvidence(continuityEvidence)
			if err != nil {
				return assemblyResult{}, err
			}
			files[fmt.Sprintf(
				"%s/evidence/continuity/%s/%s/%s.json",
				ledgerBase, previousCheckpointSHA256, checkpointSHA256, draft.value.subjectDigest,
			)] = continuityBytes
		}
		files[receiptRef] = receiptBytes
		files[inclusionRef] = inclusionBytes
		files[latestRef] = latestBytes
	}
	reference := PublisherReleaseRefV1{
		SchemaVersion: ReleaseRefSchemaVersion,
		ReleaseRef: PluginReleaseRefV1{
			SourceID: config.SourceID, Channel: config.Channel, ReleaseMetadataRef: pointers.primary.prepared.releaseMetadataRef,
			ReleaseMetadataSHA256: sha256Hex(pointers.primary.prepared.metadataBytes),
			PublisherID:           pointers.primary.prepared.pkg.Manifest.Publisher.PublisherID,
			PluginID:              pointers.primary.prepared.pkg.Manifest.PluginID(), Version: pointers.primary.prepared.pkg.Manifest.Version(),
			ExpectedHashes: PackageHashSetV1{
				PackageSHA256: pointers.primary.prepared.pkg.PackageHash, ManifestSHA256: pointers.primary.prepared.pkg.ManifestHash,
				EntriesSHA256: pointers.primary.prepared.pkg.EntriesHash,
			},
		},
		Root: config.Root, SigningLedger: config.SigningLedger,
	}
	return assemblyResult{Phase: "complete", Complete: true, Files: files, ReleaseRef: reference}, nil
}

func sourceRefreshSubject(usage releasecontract.SigningSubjectUsage) bool {
	switch usage {
	case releasecontract.SigningSubjectUsageRootDelegation,
		releasecontract.SigningSubjectUsageSourcePolicyPointer,
		releasecontract.SigningSubjectUsageSourcePolicy,
		releasecontract.SigningSubjectUsageRevocationPointer,
		releasecontract.SigningSubjectUsageRevocation:
		return true
	default:
		return false
	}
}

func requestsForPrimaryMust(config ConfigV1, prepared preparedRelease) []ExternalSignerRequestV1 {
	requests, _ := requestsForPrimary(config, prepared)
	return requests
}

func requestForUsage(requests []ExternalSignerRequestV1, usage releasecontract.SigningUsage) (ExternalSignerRequestV1, bool) {
	for _, request := range requests {
		if request.Usage == usage {
			return request, true
		}
	}
	return ExternalSignerRequestV1{}, false
}

func merkleLeafHash(value []byte) []byte {
	digest := sha256.Sum256(append([]byte{0}, value...))
	return digest[:]
}

func merkleNodeHash(left, right []byte) []byte {
	value := append([]byte{1}, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return slices.Clone(leaves[0])
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	return merkleNodeHash(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
}

func merkleInclusionProof(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	if index < k {
		return append(merkleInclusionProof(leaves[:k], index), merkleRoot(leaves[k:]))
	}
	return append(merkleInclusionProof(leaves[k:], index-k), merkleRoot(leaves[:k]))
}

func largestPowerOfTwoLessThan(value int) int {
	result := 1
	for result<<1 < value {
		result <<= 1
	}
	return result
}

func encodeProof(values [][]byte) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = hex.EncodeToString(value)
	}
	return result
}

func merkleConsistencyProof(leaves [][]byte, oldSize int) [][]byte {
	if oldSize <= 0 || oldSize > len(leaves) {
		return nil
	}
	return merkleConsistencySubproof(leaves, oldSize, true)
}

func merkleConsistencySubproof(leaves [][]byte, oldSize int, complete bool) [][]byte {
	if oldSize == len(leaves) {
		if complete {
			return nil
		}
		return [][]byte{merkleRoot(leaves)}
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	if oldSize <= k {
		return append(merkleConsistencySubproof(leaves[:k], oldSize, complete), merkleRoot(leaves[k:]))
	}
	return append(merkleConsistencySubproof(leaves[k:], oldSize-k, false), merkleRoot(leaves[:k]))
}

type latestLeaf struct {
	key   [sha256.Size]byte
	value []byte
}

func latestMap(values []ledgerValue) ([]byte, map[string][]string) {
	leaves := make([]latestLeaf, len(values))
	for index, value := range values {
		keyBytes, _ := hex.DecodeString(value.subjectDigest)
		copy(leaves[index].key[:], keyBytes)
		sequence := make([]byte, 8)
		binary.BigEndian.PutUint64(sequence, value.sequence)
		preimage, _ := hex.DecodeString(value.preimageHash)
		envelope, _ := hex.DecodeString(value.envelopeHash)
		encoded := append([]byte{3}, keyBytes...)
		encoded = append(encoded, sequence...)
		encoded = append(encoded, preimage...)
		encoded = append(encoded, envelope...)
		digest := sha256.Sum256(encoded)
		leaves[index].value = digest[:]
	}
	root := latestSubtree(leaves, 0)
	proofs := make(map[string][]string, len(leaves))
	for _, leaf := range leaves {
		nodes := latestProof(leaves, leaf.key, 0)
		slices.Reverse(nodes)
		proofs[hex.EncodeToString(leaf.key[:])] = encodeProof(nodes)
	}
	return root, proofs
}

func latestSubtree(leaves []latestLeaf, depth int) []byte {
	if len(leaves) == 0 {
		return make([]byte, sha256.Size)
	}
	if depth == sha256.Size*8 {
		return slices.Clone(leaves[0].value)
	}
	left, right := splitLatestLeaves(leaves, depth)
	return latestNode(latestSubtree(left, depth+1), latestSubtree(right, depth+1))
}

func latestProof(leaves []latestLeaf, key [sha256.Size]byte, depth int) [][]byte {
	if depth == sha256.Size*8 {
		return nil
	}
	left, right := splitLatestLeaves(leaves, depth)
	if latestKeyBit(key, depth) == 0 {
		return append([][]byte{latestSubtree(right, depth+1)}, latestProof(left, key, depth+1)...)
	}
	return append([][]byte{latestSubtree(left, depth+1)}, latestProof(right, key, depth+1)...)
}

func splitLatestLeaves(leaves []latestLeaf, depth int) ([]latestLeaf, []latestLeaf) {
	left, right := []latestLeaf{}, []latestLeaf{}
	for _, leaf := range leaves {
		if latestKeyBit(leaf.key, depth) == 0 {
			left = append(left, leaf)
		} else {
			right = append(right, leaf)
		}
	}
	return left, right
}

func latestKeyBit(key [sha256.Size]byte, depth int) byte {
	return (key[depth/8] >> uint(7-depth%8)) & 1
}

func latestNode(left, right []byte) []byte {
	value := append([]byte{4}, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}
