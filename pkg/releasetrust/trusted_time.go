package releasetrust

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	TrustedTimeLeafSchemaVersion       = "redevplugin.trusted_time_leaf.v1"
	TrustedTimeEvidenceSchemaVersion   = "redevplugin.trusted_time_evidence.v1"
	TrustedTimeCheckpointSchemaVersion = "redevplugin.trusted_time_checkpoint.v1"
	TrustedTimeEvidenceTransparency    = "transparency"
	MaxTrustedTimeEvidenceBytes        = 64 << 10
	MaxTrustedTimeCheckpointBytes      = 8 << 10
	MaxTrustedTimeProofNodes           = 64
)

var (
	ErrInvalidTrustedTimeRequest  = errors.New("trusted time request is invalid")
	ErrInvalidTrustedTimeEvidence = errors.New("trusted time evidence is invalid")
	ErrTrustedTimeRollback        = errors.New("trusted time evidence rolls back persisted state")
)

type TrustedTimeLeafV1 struct {
	SchemaVersion string `json:"schema_version"`
	SourceID      string `json:"source_id"`
	Channel       string `json:"channel"`
	Nonce         string `json:"nonce"`
	MinimumTime   string `json:"minimum_time"`
	ClaimedTime   string `json:"claimed_time"`
	RequestSHA256 string `json:"request_sha256"`
	LogID         string `json:"log_id"`
}

type TrustedTimeCheckpointV1 struct {
	SchemaVersion  string `json:"schema_version"`
	LogID          string `json:"log_id"`
	TreeSize       uint64 `json:"tree_size"`
	RootHash       string `json:"root_hash"`
	CheckpointTime string `json:"checkpoint_time"`
	KeyID          string `json:"key_id"`
	Signature      string `json:"signature"`
}

type TrustedTimeEvidenceV1 struct {
	SchemaVersion        string                  `json:"schema_version"`
	Kind                 string                  `json:"kind"`
	Leaf                 TrustedTimeLeafV1       `json:"leaf"`
	LeafSHA256           string                  `json:"leaf_sha256"`
	IntegratedTime       string                  `json:"integrated_time"`
	SignedEntryTimestamp string                  `json:"signed_entry_timestamp"`
	Checkpoint           TrustedTimeCheckpointV1 `json:"checkpoint"`
	LeafIndex            uint64                  `json:"leaf_index"`
	InclusionProof       []string                `json:"inclusion_proof"`
	ConsistencyProof     []string                `json:"consistency_proof"`
}

type trustedTimeRequestHashInput struct {
	SourceID    string `json:"source_id"`
	Channel     string `json:"channel"`
	Nonce       string `json:"nonce"`
	MinimumTime string `json:"minimum_time"`
	LogID       string `json:"log_id"`
}

type trustedTimeSETPreimage struct {
	Domain         string `json:"domain"`
	LeafSHA256     string `json:"leaf_sha256"`
	IntegratedTime string `json:"integrated_time"`
	LogID          string `json:"log_id"`
}

type trustedTimeCheckpointPreimage struct {
	Domain         string `json:"domain"`
	SchemaVersion  string `json:"schema_version"`
	LogID          string `json:"log_id"`
	TreeSize       uint64 `json:"tree_size"`
	RootHash       string `json:"root_hash"`
	CheckpointTime string `json:"checkpoint_time"`
	KeyID          string `json:"key_id"`
}

type TrustedTimeRequest struct {
	key           SourceTrustKey
	nonce         string
	minimumTime   string
	requestSHA256 string
	logID         string
}

func (request TrustedTimeRequest) SourceTrustKey() SourceTrustKey { return request.key }
func (request TrustedTimeRequest) Nonce() string                  { return request.nonce }
func (request TrustedTimeRequest) MinimumTime() string            { return request.minimumTime }
func (request TrustedTimeRequest) RequestSHA256() string          { return request.requestSHA256 }
func (request TrustedTimeRequest) LogID() string                  { return request.logID }

func newTrustedTimeRequest(key SourceTrustKey, minimum time.Time, logID string, nonce []byte) (TrustedTimeRequest, error) {
	if !key.valid() || !contractIDPattern.MatchString(logID) || len(nonce) != 32 || minimum.Location() != time.UTC {
		return TrustedTimeRequest{}, ErrInvalidTrustedTimeRequest
	}
	nonceValue := base64.RawURLEncoding.EncodeToString(nonce)
	minimumValue := minimum.Format(time.RFC3339Nano)
	input := trustedTimeRequestHashInput{SourceID: key.sourceID, Channel: key.channel, Nonce: nonceValue, MinimumTime: minimumValue, LogID: logID}
	raw, err := json.Marshal(input)
	if err != nil {
		return TrustedTimeRequest{}, ErrInvalidTrustedTimeRequest
	}
	return TrustedTimeRequest{
		key: key, nonce: nonceValue, minimumTime: minimumValue, requestSHA256: digestHex(raw), logID: logID,
	}, nil
}

func (request TrustedTimeRequest) valid() bool {
	return request.key.valid() && contractIDPattern.MatchString(request.logID) && len(request.nonce) == 43 && sha256Pattern.MatchString(request.requestSHA256) && validCanonicalTime(request.minimumTime)
}

type TrustedTimeObservation struct {
	request  TrustedTimeRequest
	kind     string
	evidence []byte
}

func NewTransparencyTimeObservation(request TrustedTimeRequest, evidence []byte) (TrustedTimeObservation, error) {
	if !request.valid() || len(evidence) == 0 || len(evidence) > MaxTrustedTimeEvidenceBytes {
		return TrustedTimeObservation{}, ErrInvalidTrustedTimeEvidence
	}
	return TrustedTimeObservation{request: request, kind: TrustedTimeEvidenceTransparency, evidence: slices.Clone(evidence)}, nil
}

type TrustedTimeAdapter interface {
	Observe(context.Context, TrustedTimeRequest) (TrustedTimeObservation, error)
}

type VerifiedTrustedTime struct {
	key              SourceTrustKey
	floor            time.Time
	checkpoint       TrustedTimeCheckpointV1
	checkpointSHA256 string
}

func (verified VerifiedTrustedTime) SourceTrustKey() SourceTrustKey { return verified.key }
func (verified VerifiedTrustedTime) Floor() time.Time               { return verified.floor }
func (verified VerifiedTrustedTime) Checkpoint() TrustedTimeCheckpointV1 {
	return verified.checkpoint
}
func (verified VerifiedTrustedTime) CheckpointSHA256() string { return verified.checkpointSHA256 }

func verifyTrustedTimeObservation(
	request TrustedTimeRequest,
	observation TrustedTimeObservation,
	root TransparencyRoot,
	previous *TrustedTimeCheckpointV1,
) (VerifiedTrustedTime, error) {
	if !request.valid() || observation.request != request || observation.kind != TrustedTimeEvidenceTransparency ||
		len(observation.evidence) == 0 || len(observation.evidence) > MaxTrustedTimeEvidenceBytes || root.logID != request.logID || !root.valid() {
		return VerifiedTrustedTime{}, ErrInvalidTrustedTimeEvidence
	}
	var evidence TrustedTimeEvidenceV1
	if err := decodeClosedJSON(observation.evidence, &evidence, MaxTrustedTimeEvidenceBytes, ErrInvalidTrustedTimeEvidence); err != nil {
		return VerifiedTrustedTime{}, err
	}
	if err := validateTrustedTimeEvidenceShape(evidence); err != nil {
		return VerifiedTrustedTime{}, err
	}
	if evidence.Leaf.SourceID != request.key.sourceID || evidence.Leaf.Channel != request.key.channel || evidence.Leaf.Nonce != request.nonce ||
		evidence.Leaf.MinimumTime != request.minimumTime || evidence.Leaf.RequestSHA256 != request.requestSHA256 || evidence.Leaf.LogID != request.logID ||
		evidence.Checkpoint.LogID != request.logID || evidence.Checkpoint.KeyID != root.pinnedAnchor.keyID {
		return VerifiedTrustedTime{}, ErrInvalidTrustedTimeEvidence
	}
	leafBytes, _ := json.Marshal(evidence.Leaf)
	if digestHex(leafBytes) != evidence.LeafSHA256 {
		return VerifiedTrustedTime{}, ErrInvalidTrustedTimeEvidence
	}
	integratedTime, _ := parseCanonicalTime(evidence.IntegratedTime)
	checkpointTime, _ := parseCanonicalTime(evidence.Checkpoint.CheckpointTime)
	minimumTime, _ := parseCanonicalTime(request.minimumTime)
	if integratedTime.Before(minimumTime) || checkpointTime.Before(integratedTime) {
		return VerifiedTrustedTime{}, ErrTrustedTimeRollback
	}
	setPreimage, _ := json.Marshal(trustedTimeSETPreimage{
		Domain: "redevplugin.trusted-time.set.v1", LeafSHA256: evidence.LeafSHA256, IntegratedTime: evidence.IntegratedTime, LogID: request.logID,
	})
	setSignature, err := decodeSignature(evidence.SignedEntryTimestamp)
	if err != nil || !ed25519.Verify(root.pinnedAnchor.publicKey, setPreimage, setSignature) {
		return VerifiedTrustedTime{}, ErrInvalidTrustedTimeEvidence
	}
	checkpointPreimage, _ := json.Marshal(checkpointPreimageFromEvidence(evidence.Checkpoint))
	if len(checkpointPreimage) > MaxTrustedTimeCheckpointBytes {
		return VerifiedTrustedTime{}, ErrInvalidTrustedTimeEvidence
	}
	checkpointSignature, err := decodeSignature(evidence.Checkpoint.Signature)
	if err != nil || !ed25519.Verify(root.pinnedAnchor.publicKey, checkpointPreimage, checkpointSignature) {
		return VerifiedTrustedTime{}, ErrInvalidTrustedTimeEvidence
	}
	rootHash, _ := hex.DecodeString(evidence.Checkpoint.RootHash)
	proof, err := decodeProof(evidence.InclusionProof)
	if err != nil || !verifyMerkleInclusion(merkleLeafHash(leafBytes), evidence.LeafIndex, evidence.Checkpoint.TreeSize, proof, rootHash) {
		return VerifiedTrustedTime{}, ErrInvalidTrustedTimeEvidence
	}
	if previous == nil {
		if len(evidence.ConsistencyProof) != 0 {
			return VerifiedTrustedTime{}, ErrInvalidTrustedTimeEvidence
		}
	} else if err := verifyCheckpointAdvance(*previous, evidence.Checkpoint, evidence.ConsistencyProof); err != nil {
		return VerifiedTrustedTime{}, err
	}
	checkpointBytes, _ := json.Marshal(evidence.Checkpoint)
	return VerifiedTrustedTime{
		key: request.key, floor: checkpointTime, checkpoint: cloneCheckpoint(evidence.Checkpoint), checkpointSHA256: digestHex(checkpointBytes),
	}, nil
}

func validateTrustedTimeEvidenceShape(evidence TrustedTimeEvidenceV1) error {
	if evidence.SchemaVersion != TrustedTimeEvidenceSchemaVersion || evidence.Kind != TrustedTimeEvidenceTransparency ||
		evidence.Leaf.SchemaVersion != TrustedTimeLeafSchemaVersion || evidence.Checkpoint.SchemaVersion != TrustedTimeCheckpointSchemaVersion ||
		!contractIDPattern.MatchString(evidence.Leaf.SourceID) || !contractIDPattern.MatchString(evidence.Leaf.Channel) || !contractIDPattern.MatchString(evidence.Leaf.LogID) ||
		!contractIDPattern.MatchString(evidence.Checkpoint.LogID) || !contractIDPattern.MatchString(evidence.Checkpoint.KeyID) ||
		len(evidence.Leaf.Nonce) != 43 || !sha256Pattern.MatchString(evidence.Leaf.RequestSHA256) || !sha256Pattern.MatchString(evidence.LeafSHA256) ||
		!sha256Pattern.MatchString(evidence.Checkpoint.RootHash) || evidence.Checkpoint.TreeSize == 0 || evidence.LeafIndex >= evidence.Checkpoint.TreeSize ||
		len(evidence.InclusionProof) > MaxTrustedTimeProofNodes || len(evidence.ConsistencyProof) > MaxTrustedTimeProofNodes ||
		!validCanonicalTime(evidence.Leaf.MinimumTime) || !validCanonicalTime(evidence.Leaf.ClaimedTime) ||
		!validCanonicalTime(evidence.IntegratedTime) || !validCanonicalTime(evidence.Checkpoint.CheckpointTime) {
		return ErrInvalidTrustedTimeEvidence
	}
	if _, err := decodeSignature(evidence.SignedEntryTimestamp); err != nil {
		return ErrInvalidTrustedTimeEvidence
	}
	if _, err := decodeSignature(evidence.Checkpoint.Signature); err != nil {
		return ErrInvalidTrustedTimeEvidence
	}
	if _, err := decodeProof(evidence.InclusionProof); err != nil {
		return ErrInvalidTrustedTimeEvidence
	}
	if _, err := decodeProof(evidence.ConsistencyProof); err != nil {
		return ErrInvalidTrustedTimeEvidence
	}
	return nil
}

func checkpointPreimageFromEvidence(checkpoint TrustedTimeCheckpointV1) trustedTimeCheckpointPreimage {
	return trustedTimeCheckpointPreimage{
		Domain: "redevplugin.trusted-time.checkpoint.v1", SchemaVersion: checkpoint.SchemaVersion, LogID: checkpoint.LogID,
		TreeSize: checkpoint.TreeSize, RootHash: checkpoint.RootHash, CheckpointTime: checkpoint.CheckpointTime, KeyID: checkpoint.KeyID,
	}
}

func verifyCheckpointAdvance(previous, current TrustedTimeCheckpointV1, encodedProof []string) error {
	previousTime, err := parseCanonicalTime(previous.CheckpointTime)
	if err != nil {
		return ErrInvalidTrustedTimeEvidence
	}
	currentTime, _ := parseCanonicalTime(current.CheckpointTime)
	if previous.LogID != current.LogID || previous.KeyID != current.KeyID || current.TreeSize < previous.TreeSize || currentTime.Before(previousTime) {
		return ErrTrustedTimeRollback
	}
	if current.TreeSize == previous.TreeSize {
		if current.RootHash != previous.RootHash || len(encodedProof) != 0 {
			return ErrTrustedTimeRollback
		}
		return nil
	}
	proof, err := decodeProof(encodedProof)
	if err != nil {
		return ErrInvalidTrustedTimeEvidence
	}
	oldRoot, _ := hex.DecodeString(previous.RootHash)
	newRoot, _ := hex.DecodeString(current.RootHash)
	if !verifyMerkleConsistency(previous.TreeSize, current.TreeSize, oldRoot, newRoot, proof) {
		return ErrTrustedTimeRollback
	}
	return nil
}

func merkleLeafHash(value []byte) []byte {
	digest := sha256.Sum256(append([]byte{0}, value...))
	return digest[:]
}

func merkleNodeHash(left, right []byte) []byte {
	value := make([]byte, 1, 1+len(left)+len(right))
	value[0] = 1
	value = append(value, left...)
	value = append(value, right...)
	digest := sha256.Sum256(value)
	return digest[:]
}

func verifyMerkleInclusion(leafHash []byte, leafIndex, treeSize uint64, proof [][]byte, root []byte) bool {
	if treeSize == 0 || leafIndex >= treeSize || len(leafHash) != sha256.Size || len(root) != sha256.Size {
		return false
	}
	fn, sn := leafIndex, treeSize-1
	calculated := slices.Clone(leafHash)
	for _, node := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			calculated = merkleNodeHash(node, calculated)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			calculated = merkleNodeHash(calculated, node)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && slices.Equal(calculated, root)
}

func verifyMerkleConsistency(oldSize, newSize uint64, oldRoot, newRoot []byte, proof [][]byte) bool {
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
			first = merkleNodeHash(node, first)
			second = merkleNodeHash(node, second)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			second = merkleNodeHash(second, node)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && slices.Equal(first, oldRoot) && slices.Equal(second, newRoot)
}

func decodeProof(values []string) ([][]byte, error) {
	if len(values) > MaxTrustedTimeProofNodes {
		return nil, ErrInvalidTrustedTimeEvidence
	}
	proof := make([][]byte, len(values))
	for index, value := range values {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			return nil, ErrInvalidTrustedTimeEvidence
		}
		proof[index] = decoded
	}
	return proof, nil
}

func decodeSignature(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidTrustedTimeEvidence
	}
	return decoded, nil
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("%w: noncanonical time", ErrInvalidTrustedTimeEvidence)
	}
	return parsed, nil
}

func validCanonicalTime(value string) bool {
	_, err := parseCanonicalTime(value)
	return err == nil
}

func cloneCheckpoint(value TrustedTimeCheckpointV1) TrustedTimeCheckpointV1 { return value }

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
