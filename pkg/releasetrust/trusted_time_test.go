package releasetrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestTrustedTimeEvidenceBindsRequestAndUsesOnlyVerifiedLogTime(t *testing.T) {
	key, root, request, privateKey := trustedTimeFixture(t)
	now := time.Date(2026, 7, 21, 2, 0, 0, 0, time.UTC)
	evidenceBytes, leaf := buildTrustedTimeEvidence(t, request, privateKey, now, now.Add(24*time.Hour), 1, nil, nil)
	observation, err := NewTransparencyTimeObservation(request, evidenceBytes)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyTrustedTimeObservation(request, observation, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Floor().Equal(now) || verified.Checkpoint().TreeSize != 1 || verified.SourceTrustKey() != key {
		t.Fatalf("verified time = %#v leaf=%#v", verified, leaf)
	}
	if verified.Floor().Equal(now.Add(24 * time.Hour)) {
		t.Fatal("leaf claimed_time advanced the trusted floor")
	}
}

func TestTrustedTimeEvidenceRejectsTamperingAndDuplicateFields(t *testing.T) {
	_, root, request, privateKey := trustedTimeFixture(t)
	now := time.Date(2026, 7, 21, 2, 0, 0, 0, time.UTC)
	evidenceBytes, _ := buildTrustedTimeEvidence(t, request, privateKey, now, now, 1, nil, nil)
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown field": func(value []byte) []byte {
			return bytes.Replace(value, []byte(`"kind":"transparency"`), []byte(`"kind":"transparency","unknown":true`), 1)
		},
		"duplicate field": func(value []byte) []byte {
			return bytes.Replace(value, []byte(`"kind":"transparency"`), []byte(`"kind":"transparency","kind":"transparency"`), 1)
		},
		"set signature": func(value []byte) []byte {
			return bytes.Replace(value, []byte(`"signed_entry_timestamp":"`), []byte(`"signed_entry_timestamp":"A`), 1)
		},
		"request binding": func(value []byte) []byte {
			return bytes.Replace(value, []byte(request.requestSHA256), []byte("0"+request.requestSHA256[1:]), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			observation, err := NewTransparencyTimeObservation(request, mutate(evidenceBytes))
			if err != nil {
				if name == "set signature" {
					return
				}
				t.Fatal(err)
			}
			if _, err := verifyTrustedTimeObservation(request, observation, root, nil); err == nil {
				t.Fatal("tampered trusted time evidence accepted")
			}
		})
	}
}

func TestTrustedTimeEvidenceRequiresConsistencyProofForCheckpointAdvance(t *testing.T) {
	_, root, request, privateKey := trustedTimeFixture(t)
	firstTime := time.Date(2026, 7, 21, 2, 0, 0, 0, time.UTC)
	firstBytes, firstLeaf := buildTrustedTimeEvidence(t, request, privateKey, firstTime, firstTime, 1, nil, nil)
	firstObservation, err := NewTransparencyTimeObservation(request, firstBytes)
	if err != nil {
		t.Fatal(err)
	}
	first, err := verifyTrustedTimeObservation(request, firstObservation, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondTime := firstTime.Add(time.Minute)
	secondBytes, _ := buildTrustedTimeEvidence(t, request, privateKey, secondTime, secondTime, 2, [][]byte{merkleLeafHash(firstLeaf)}, [][]byte{merkleLeafHash(secondLeafPlaceholder(request, secondTime))})
	secondObservation, err := NewTransparencyTimeObservation(request, secondBytes)
	if err != nil {
		t.Fatal(err)
	}
	previousCheckpoint := first.Checkpoint()
	if _, err := verifyTrustedTimeObservation(request, secondObservation, root, &previousCheckpoint); err != nil {
		t.Fatal(err)
	}
	var withoutConsistency TrustedTimeEvidenceV1
	if err := json.Unmarshal(secondBytes, &withoutConsistency); err != nil {
		t.Fatal(err)
	}
	withoutConsistency.ConsistencyProof = []string{}
	withoutConsistencyBytes, _ := json.Marshal(withoutConsistency)
	withoutConsistencyObservation, err := NewTransparencyTimeObservation(request, withoutConsistencyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTrustedTimeObservation(request, withoutConsistencyObservation, root, &previousCheckpoint); !errors.Is(err, ErrTrustedTimeRollback) {
		t.Fatalf("missing consistency proof error = %v", err)
	}
}

func TestTrustedTimeRequestCarriesPreviousCheckpointTreeSize(t *testing.T) {
	configuration, err := NewSourceConfiguration("example_source", []string{"stable"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := configuration.TrustKey("stable")
	if err != nil {
		t.Fatal(err)
	}
	minimum := time.Date(2026, 7, 21, 1, 0, 0, 0, time.UTC)
	nonce := bytes.Repeat([]byte{8}, 32)
	initial, err := newTrustedTimeRequest(key, minimum, nil, "time_log", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if initial.PreviousCheckpointTreeSize() != 0 {
		t.Fatalf("initial previous tree size = %d", initial.PreviousCheckpointTreeSize())
	}
	previous := &TrustedTimeCheckpointV1{TreeSize: 7}
	advanced, err := newTrustedTimeRequest(key, minimum, previous, "time_log", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if advanced.PreviousCheckpointTreeSize() != 7 {
		t.Fatalf("advanced previous tree size = %d", advanced.PreviousCheckpointTreeSize())
	}
	if advanced.RequestSHA256() == initial.RequestSHA256() {
		t.Fatal("previous checkpoint tree size is not bound into the request digest")
	}
}

func trustedTimeFixture(t *testing.T) (SourceTrustKey, TransparencyRoot, TrustedTimeRequest, ed25519.PrivateKey) {
	t.Helper()
	configuration, err := NewSourceConfiguration("example_source", []string{"stable"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := configuration.TrustKey("stable")
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	anchor, err := NewEd25519TrustAnchor("time_key", privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewTransparencyRoot("time_log", anchor)
	if err != nil {
		t.Fatal(err)
	}
	request, err := newTrustedTimeRequest(key, time.Date(2026, 7, 21, 1, 0, 0, 0, time.UTC), nil, "time_log", bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key, root, request, privateKey
}

func buildTrustedTimeEvidence(t *testing.T, request TrustedTimeRequest, privateKey ed25519.PrivateKey, integrated, claimed time.Time, treeSize uint64, inclusion, consistency [][]byte) ([]byte, []byte) {
	t.Helper()
	leaf := TrustedTimeLeafV1{
		SchemaVersion: TrustedTimeLeafSchemaVersion, SourceID: request.key.sourceID, Channel: request.key.channel,
		Nonce: request.nonce, MinimumTime: request.minimumTime, ClaimedTime: claimed.UTC().Format(time.RFC3339Nano), RequestSHA256: request.requestSHA256, LogID: request.logID,
	}
	leafBytes, err := json.Marshal(leaf)
	if err != nil {
		t.Fatal(err)
	}
	leafSHA := digestHex(leafBytes)
	leafHash := merkleLeafHash(leafBytes)
	rootHash := leafHash
	for _, node := range inclusion {
		rootHash = merkleNodeHash(node, rootHash)
	}
	checkpoint := TrustedTimeCheckpointV1{
		SchemaVersion: TrustedTimeCheckpointSchemaVersion, LogID: request.logID, TreeSize: treeSize,
		RootHash: hex.EncodeToString(rootHash), CheckpointTime: integrated.UTC().Format(time.RFC3339Nano), KeyID: "time_key",
	}
	checkpointPreimage, _ := json.Marshal(checkpointPreimageFromEvidence(checkpoint))
	checkpoint.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, checkpointPreimage))
	setPreimage, _ := json.Marshal(trustedTimeSETPreimage{Domain: "redevplugin.trusted-time.set.v1", LeafSHA256: leafSHA, IntegratedTime: integrated.UTC().Format(time.RFC3339Nano), LogID: request.logID})
	evidence := TrustedTimeEvidenceV1{
		SchemaVersion: TrustedTimeEvidenceSchemaVersion, Kind: TrustedTimeEvidenceTransparency, Leaf: leaf, LeafSHA256: leafSHA,
		IntegratedTime: integrated.UTC().Format(time.RFC3339Nano), SignedEntryTimestamp: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, setPreimage)),
		Checkpoint: checkpoint, LeafIndex: treeSize - 1, InclusionProof: encodeProof(inclusion), ConsistencyProof: encodeProof(consistency),
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, leafBytes
}

func trustedTimeTestLeafBytes(t *testing.T, request TrustedTimeRequest, claimed time.Time) []byte {
	t.Helper()
	leaf := TrustedTimeLeafV1{
		SchemaVersion: TrustedTimeLeafSchemaVersion,
		SourceID:      request.key.sourceID,
		Channel:       request.key.channel,
		Nonce:         request.nonce,
		MinimumTime:   request.minimumTime,
		ClaimedTime:   claimed.UTC().Format(time.RFC3339Nano),
		RequestSHA256: request.requestSHA256,
		LogID:         request.logID,
	}
	encoded, err := json.Marshal(leaf)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func trustedTimeTestMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return slices.Clone(leaves[0])
	}
	k := trustedTimeTestLargestPowerOfTwoLessThan(len(leaves))
	return merkleNodeHash(trustedTimeTestMerkleRoot(leaves[:k]), trustedTimeTestMerkleRoot(leaves[k:]))
}

func trustedTimeTestInclusionProof(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := trustedTimeTestLargestPowerOfTwoLessThan(len(leaves))
	if index < k {
		return append(trustedTimeTestInclusionProof(leaves[:k], index), trustedTimeTestMerkleRoot(leaves[k:]))
	}
	return append(trustedTimeTestInclusionProof(leaves[k:], index-k), trustedTimeTestMerkleRoot(leaves[:k]))
}

func trustedTimeTestConsistencyProof(leaves [][]byte, oldSize int) [][]byte {
	if oldSize <= 0 || oldSize >= len(leaves) {
		return nil
	}
	return trustedTimeTestConsistencySubproof(leaves, oldSize, true)
}

func trustedTimeTestConsistencySubproof(leaves [][]byte, oldSize int, complete bool) [][]byte {
	if oldSize == len(leaves) {
		if complete {
			return nil
		}
		return [][]byte{trustedTimeTestMerkleRoot(leaves)}
	}
	k := trustedTimeTestLargestPowerOfTwoLessThan(len(leaves))
	if oldSize <= k {
		return append(
			trustedTimeTestConsistencySubproof(leaves[:k], oldSize, complete),
			trustedTimeTestMerkleRoot(leaves[k:]),
		)
	}
	return append(
		trustedTimeTestConsistencySubproof(leaves[k:], oldSize-k, false),
		trustedTimeTestMerkleRoot(leaves[:k]),
	)
}

func trustedTimeTestLargestPowerOfTwoLessThan(value int) int {
	result := 1
	for result<<1 < value {
		result <<= 1
	}
	return result
}

func secondLeafPlaceholder(request TrustedTimeRequest, timestamp time.Time) []byte {
	leaf := TrustedTimeLeafV1{SchemaVersion: TrustedTimeLeafSchemaVersion, SourceID: request.key.sourceID, Channel: request.key.channel, Nonce: request.nonce, MinimumTime: request.minimumTime, ClaimedTime: timestamp.UTC().Format(time.RFC3339Nano), RequestSHA256: request.requestSHA256, LogID: request.logID}
	encoded, _ := json.Marshal(leaf)
	return encoded
}

func encodeProof(values [][]byte) []string {
	encoded := make([]string, len(values))
	for index, value := range values {
		encoded[index] = hex.EncodeToString(value)
	}
	return encoded
}

func TestTrustedTimeHelperUsesCanonicalBytes(t *testing.T) {
	value := []byte("trusted-time")
	digest := sha256.Sum256(value)
	if digestHex(value) != hex.EncodeToString(digest[:]) || !slices.Equal(value, []byte("trusted-time")) {
		t.Fatal("digest helper changed canonical bytes")
	}
	if err := decodeClosedJSON([]byte(`{"kind":"transparency","kind":"transparency"}`), &map[string]any{}, 1024, ErrInvalidTrustedTimeEvidence); !errors.Is(err, ErrInvalidTrustedTimeEvidence) {
		t.Fatalf("duplicate JSON error = %v", err)
	}
}
