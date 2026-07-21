package releasetrust

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const (
	ReleaseTrustStateSchemaVersion          = "redevplugin.release_trust_state.v1"
	releaseTrustPendingSchemaVersion        = "redevplugin.release_trust_pending.v1"
	MaxReleaseTrustStateBytes               = 1 << 20
	MaxReleaseTrustPendingBytes             = 2 << 20
	maxJSONSafeInteger               uint64 = 1<<53 - 1
)

var (
	ErrInvalidReleaseTrustState  = errors.New("release trust state is invalid")
	ErrReleaseTrustStateConflict = errors.New("release trust state compare-and-swap conflict")
	ErrReleaseTrustStateUnknown  = errors.New("release trust state mutation outcome is unknown")
	ErrReleaseTrustSplitView     = errors.New("release trust local and monotonic state disagree")

	transportTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,512}$`)
)

type ReleaseTrustRootHeadV1 struct {
	Epoch          string `json:"epoch"`
	DocumentSHA256 string `json:"document_sha256"`
	GeneratedAt    string `json:"generated_at"`
	ExpiresAt      string `json:"expires_at"`
	KeyID          string `json:"key_id"`
}

type ReleaseTrustedTimeStateV1 struct {
	Floor            string                  `json:"floor"`
	CheckpointSHA256 string                  `json:"checkpoint_sha256"`
	Checkpoint       TrustedTimeCheckpointV1 `json:"checkpoint"`
}

type ReleaseTrustDocumentHeadV1 struct {
	PointerLocator         string `json:"pointer_locator"`
	PointerTransportToken  string `json:"pointer_transport_token"`
	PointerEpoch           string `json:"pointer_epoch"`
	PointerSHA256          string `json:"pointer_sha256"`
	DocumentLocator        string `json:"document_locator"`
	DocumentTransportToken string `json:"document_transport_token"`
	DocumentSHA256         string `json:"document_sha256"`
	GeneratedAt            string `json:"generated_at"`
	ExpiresAt              string `json:"expires_at"`
	KeyID                  string `json:"key_id"`
}

type ReleaseTrustChannelStateV1 struct {
	Channel    string                      `json:"channel"`
	Policy     *ReleaseTrustDocumentHeadV1 `json:"policy,omitempty"`
	Revocation *ReleaseTrustDocumentHeadV1 `json:"revocation,omitempty"`
}

type ReleaseTrustStateV1 struct {
	SchemaVersion   string                       `json:"schema_version"`
	SourceID        string                       `json:"source_id"`
	Revision        uint64                       `json:"revision"`
	ExternalCounter uint64                       `json:"external_counter"`
	Root            *ReleaseTrustRootHeadV1      `json:"root,omitempty"`
	TrustedTime     ReleaseTrustedTimeStateV1    `json:"trusted_time"`
	Channels        []ReleaseTrustChannelStateV1 `json:"channels"`
}

type sourceTrustPendingV1 struct {
	SchemaVersion           string              `json:"schema_version"`
	TransactionID           string              `json:"transaction_id"`
	SourceID                string              `json:"source_id"`
	PreviousStateSHA256     string              `json:"previous_state_sha256"`
	NextStateSHA256         string              `json:"next_state_sha256"`
	ExpectedExternalCounter uint64              `json:"expected_external_counter"`
	NextExternalCounter     uint64              `json:"next_external_counter"`
	EvidenceSHA256          string              `json:"evidence_sha256"`
	NextState               ReleaseTrustStateV1 `json:"next_state"`
}

func canonicalReleaseTrustState(state ReleaseTrustStateV1) ([]byte, error) {
	if err := validateReleaseTrustState(state); err != nil {
		return nil, err
	}
	return json.Marshal(state)
}

func decodeReleaseTrustState(raw []byte) (ReleaseTrustStateV1, error) {
	var state ReleaseTrustStateV1
	if err := decodeClosedJSON(raw, &state, MaxReleaseTrustStateBytes, ErrInvalidReleaseTrustState); err != nil {
		return ReleaseTrustStateV1{}, err
	}
	if err := validateReleaseTrustState(state); err != nil {
		return ReleaseTrustStateV1{}, err
	}
	canonical, _ := json.Marshal(state)
	if !slices.Equal(canonical, raw) {
		return ReleaseTrustStateV1{}, ErrInvalidReleaseTrustState
	}
	return cloneReleaseTrustState(state), nil
}

func validateReleaseTrustState(state ReleaseTrustStateV1) error {
	if state.SchemaVersion != ReleaseTrustStateSchemaVersion || !contractIDPattern.MatchString(state.SourceID) || state.Revision == 0 ||
		state.Revision > maxJSONSafeInteger || state.ExternalCounter > maxJSONSafeInteger || len(state.Channels) > 16 {
		return ErrInvalidReleaseTrustState
	}
	if err := validateTrustedTimeState(state.TrustedTime); err != nil {
		return err
	}
	if state.Root != nil && !validRootHead(*state.Root) {
		return ErrInvalidReleaseTrustState
	}
	for index, channel := range state.Channels {
		if !contractIDPattern.MatchString(channel.Channel) || (index > 0 && state.Channels[index-1].Channel >= channel.Channel) ||
			(channel.Policy != nil && !validDocumentHead(*channel.Policy)) || (channel.Revocation != nil && !validDocumentHead(*channel.Revocation)) {
			return ErrInvalidReleaseTrustState
		}
	}
	return nil
}

func validateTrustedTimeState(state ReleaseTrustedTimeStateV1) error {
	if !validCanonicalTime(state.Floor) || !validTrustedTimeCheckpoint(state.Checkpoint) || !sha256Pattern.MatchString(state.CheckpointSHA256) ||
		state.Floor != state.Checkpoint.CheckpointTime {
		return ErrInvalidReleaseTrustState
	}
	checkpointBytes, _ := json.Marshal(state.Checkpoint)
	if digestHex(checkpointBytes) != state.CheckpointSHA256 {
		return ErrInvalidReleaseTrustState
	}
	return nil
}

func validTrustedTimeCheckpoint(checkpoint TrustedTimeCheckpointV1) bool {
	if checkpoint.SchemaVersion != TrustedTimeCheckpointSchemaVersion || !contractIDPattern.MatchString(checkpoint.LogID) ||
		!contractIDPattern.MatchString(checkpoint.KeyID) || checkpoint.TreeSize == 0 || checkpoint.TreeSize > maxJSONSafeInteger ||
		!sha256Pattern.MatchString(checkpoint.RootHash) || !validCanonicalTime(checkpoint.CheckpointTime) {
		return false
	}
	_, err := decodeSignature(checkpoint.Signature)
	return err == nil
}

func validRootHead(head ReleaseTrustRootHeadV1) bool {
	generated, generatedErr := parseCanonicalTime(head.GeneratedAt)
	expires, expiresErr := parseCanonicalTime(head.ExpiresAt)
	return validEpoch(head.Epoch) && sha256Pattern.MatchString(head.DocumentSHA256) && contractIDPattern.MatchString(head.KeyID) &&
		generatedErr == nil && expiresErr == nil && expires.After(generated)
}

func validDocumentHead(head ReleaseTrustDocumentHeadV1) bool {
	generated, generatedErr := parseCanonicalTime(head.GeneratedAt)
	expires, expiresErr := parseCanonicalTime(head.ExpiresAt)
	_, pointerErr := newSourceRelativeLocator(head.PointerLocator)
	_, documentErr := newSourceRelativeLocator(head.DocumentLocator)
	return pointerErr == nil && documentErr == nil && transportTokenPattern.MatchString(head.PointerTransportToken) &&
		transportTokenPattern.MatchString(head.DocumentTransportToken) && validEpoch(head.PointerEpoch) &&
		sha256Pattern.MatchString(head.PointerSHA256) && sha256Pattern.MatchString(head.DocumentSHA256) && contractIDPattern.MatchString(head.KeyID) &&
		generatedErr == nil && expiresErr == nil && expires.After(generated)
}

func validEpoch(value string) bool {
	if value == "0" {
		return true
	}
	if len(value) == 0 || len(value) > 20 || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func cloneReleaseTrustState(state ReleaseTrustStateV1) ReleaseTrustStateV1 {
	if state.Root != nil {
		root := *state.Root
		state.Root = &root
	}
	channels := state.Channels
	state.Channels = make([]ReleaseTrustChannelStateV1, len(channels))
	for index, channel := range channels {
		state.Channels[index] = channel
		if channel.Policy != nil {
			policy := *channel.Policy
			state.Channels[index].Policy = &policy
		}
		if channel.Revocation != nil {
			revocation := *channel.Revocation
			state.Channels[index].Revocation = &revocation
		}
	}
	return state
}

type SourceTrustStateLoadRequest struct{ sourceID string }

func (request SourceTrustStateLoadRequest) SourceID() string { return request.sourceID }
func (request SourceTrustStateLoadRequest) valid() bool {
	return contractIDPattern.MatchString(request.sourceID)
}

type SourceTrustStateLoadResult struct {
	request   SourceTrustStateLoadRequest
	committed []byte
	pending   []byte
}

func NewSourceTrustStateLoadResult(request SourceTrustStateLoadRequest, committed, pending []byte) (SourceTrustStateLoadResult, error) {
	if !request.valid() || len(committed) > MaxReleaseTrustStateBytes || len(pending) > MaxReleaseTrustPendingBytes {
		return SourceTrustStateLoadResult{}, ErrInvalidReleaseTrustState
	}
	return SourceTrustStateLoadResult{request: request, committed: slices.Clone(committed), pending: slices.Clone(pending)}, nil
}

func (result SourceTrustStateLoadResult) bytesFor(request SourceTrustStateLoadRequest) ([]byte, []byte, error) {
	if !request.valid() || result.request != request || len(result.committed) > MaxReleaseTrustStateBytes || len(result.pending) > MaxReleaseTrustPendingBytes {
		return nil, nil, ErrInvalidReleaseTrustState
	}
	return slices.Clone(result.committed), slices.Clone(result.pending), nil
}

type SourceTrustStatePrepareRequest struct {
	sourceID                string
	expectedCommittedSHA256 string
	pendingSHA256           string
	pending                 []byte
}

func (request SourceTrustStatePrepareRequest) SourceID() string { return request.sourceID }
func (request SourceTrustStatePrepareRequest) ExpectedCommittedSHA256() string {
	return request.expectedCommittedSHA256
}
func (request SourceTrustStatePrepareRequest) PendingSHA256() string { return request.pendingSHA256 }
func (request SourceTrustStatePrepareRequest) PendingBytes() []byte {
	return slices.Clone(request.pending)
}

type SourceTrustStateCommitRequest struct {
	sourceID        string
	pendingSHA256   string
	nextStateSHA256 string
	nextState       []byte
}

func (request SourceTrustStateCommitRequest) SourceID() string        { return request.sourceID }
func (request SourceTrustStateCommitRequest) PendingSHA256() string   { return request.pendingSHA256 }
func (request SourceTrustStateCommitRequest) NextStateSHA256() string { return request.nextStateSHA256 }
func (request SourceTrustStateCommitRequest) NextStateBytes() []byte {
	return slices.Clone(request.nextState)
}

type StateMutationOutcome string

const (
	StateMutationApplied  StateMutationOutcome = "applied"
	StateMutationConflict StateMutationOutcome = "conflict"
	StateMutationUnknown  StateMutationOutcome = "unknown"
)

type SourceTrustStateStore interface {
	LoadSourceTrustState(context.Context, SourceTrustStateLoadRequest) (SourceTrustStateLoadResult, error)
	PrepareSourceTrustState(context.Context, SourceTrustStatePrepareRequest) (StateMutationOutcome, error)
	CommitSourceTrustState(context.Context, SourceTrustStateCommitRequest) (StateMutationOutcome, error)
}

type MonotonicStateReadRequest struct{ sourceID string }

func (request MonotonicStateReadRequest) SourceID() string { return request.sourceID }

type MonotonicStateReadResult struct {
	request     MonotonicStateReadRequest
	counter     uint64
	stateSHA256 string
}

func NewMonotonicStateReadResult(request MonotonicStateReadRequest, counter uint64, stateSHA256 string) (MonotonicStateReadResult, error) {
	if !contractIDPattern.MatchString(request.sourceID) || counter > maxJSONSafeInteger || !sha256Pattern.MatchString(stateSHA256) {
		return MonotonicStateReadResult{}, ErrInvalidReleaseTrustState
	}
	return MonotonicStateReadResult{request: request, counter: counter, stateSHA256: stateSHA256}, nil
}

func (result MonotonicStateReadResult) valuesFor(request MonotonicStateReadRequest) (uint64, string, error) {
	if result.request != request || result.counter > maxJSONSafeInteger || !sha256Pattern.MatchString(result.stateSHA256) {
		return 0, "", ErrInvalidReleaseTrustState
	}
	return result.counter, result.stateSHA256, nil
}

type MonotonicStateCASRequest struct {
	sourceID        string
	transactionID   string
	expectedCounter uint64
	nextCounter     uint64
	previousSHA256  string
	nextSHA256      string
}

func (request MonotonicStateCASRequest) SourceID() string        { return request.sourceID }
func (request MonotonicStateCASRequest) TransactionID() string   { return request.transactionID }
func (request MonotonicStateCASRequest) ExpectedCounter() uint64 { return request.expectedCounter }
func (request MonotonicStateCASRequest) NextCounter() uint64     { return request.nextCounter }
func (request MonotonicStateCASRequest) PreviousSHA256() string  { return request.previousSHA256 }
func (request MonotonicStateCASRequest) NextSHA256() string      { return request.nextSHA256 }

type MonotonicStateAdapter interface {
	ReadMonotonicState(context.Context, MonotonicStateReadRequest) (MonotonicStateReadResult, error)
	CompareAndSwapMonotonicState(context.Context, MonotonicStateCASRequest) (StateMutationOutcome, error)
}

func validateMutationOutcome(outcome StateMutationOutcome) error {
	switch outcome {
	case StateMutationApplied, StateMutationConflict, StateMutationUnknown:
		return nil
	default:
		return ErrInvalidReleaseTrustState
	}
}
