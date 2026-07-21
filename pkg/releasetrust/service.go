package releasetrust

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

const emptyReleaseTrustStateSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

type ReleaseTrustAdapters struct {
	Documents   ReleaseDocumentTransport
	Ledger      SigningLedgerTransport
	State       SourceTrustStateStore
	TrustedTime TrustedTimeAdapter
	Monotonic   MonotonicStateAdapter
}

type releaseTrustLiveAnchor struct {
	processInstanceID string
	stateSHA256       string
	floor             time.Time
	observedAt        time.Time
}

type ReleaseTrustService struct {
	mu                sync.Mutex
	options           ReleaseTrustOptions
	adapters          ReleaseTrustAdapters
	processInstanceID string
	now               func() time.Time
	live              map[SourceTrustKey]releaseTrustLiveAnchor
}

func NewReleaseTrustService(options ReleaseTrustOptions, adapters ReleaseTrustAdapters) (*ReleaseTrustService, error) {
	if !options.valid() || isNilInterface(adapters.Documents) || isNilInterface(adapters.Ledger) || isNilInterface(adapters.State) ||
		isNilInterface(adapters.TrustedTime) || (adapters.Monotonic != nil && isNilInterface(adapters.Monotonic)) {
		return nil, ErrInvalidReleaseTrustOptions
	}
	processID, err := newTrustTransactionID("process")
	if err != nil {
		return nil, err
	}
	return &ReleaseTrustService{
		options: options, adapters: adapters, processInstanceID: processID, now: time.Now,
		live: make(map[SourceTrustKey]releaseTrustLiveAnchor),
	}, nil
}

type TrustedTimeStatus struct {
	key               SourceTrustKey
	floor             time.Time
	checkpointSHA256  string
	stateSHA256       string
	processInstanceID string
}

func (status TrustedTimeStatus) SourceTrustKey() SourceTrustKey { return status.key }
func (status TrustedTimeStatus) Floor() time.Time               { return status.floor }
func (status TrustedTimeStatus) CheckpointSHA256() string       { return status.checkpointSHA256 }
func (status TrustedTimeStatus) StateSHA256() string            { return status.stateSHA256 }
func (status TrustedTimeStatus) ProcessInstanceID() string      { return status.processInstanceID }

func (service *ReleaseTrustService) RefreshTrustedTime(ctx context.Context, key SourceTrustKey) (TrustedTimeStatus, error) {
	if service == nil || ctx == nil || !sourceConfigurationContainsKey(service.options.sourceConfiguration, key) {
		return TrustedTimeStatus{}, ErrInvalidSourceConfiguration
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return TrustedTimeStatus{}, err
	}
	current, currentSHA256, err := service.loadAndRecover(ctx)
	if err != nil {
		return TrustedTimeStatus{}, err
	}
	root, previous, minimum, err := service.timeVerificationContext(current)
	if err != nil {
		return TrustedTimeStatus{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return TrustedTimeStatus{}, err
	}
	request, err := newTrustedTimeRequest(key, minimum, root.logID, nonce)
	if err != nil {
		return TrustedTimeStatus{}, err
	}
	observation, err := service.adapters.TrustedTime.Observe(ctx, request)
	if err != nil {
		return TrustedTimeStatus{}, err
	}
	verified, err := verifyTrustedTimeObservation(request, observation, root, previous)
	if err != nil {
		return TrustedTimeStatus{}, err
	}
	next := cloneReleaseTrustState(current)
	if next.SchemaVersion == "" {
		next = ReleaseTrustStateV1{
			SchemaVersion: ReleaseTrustStateSchemaVersion, SourceID: key.sourceID, Revision: 1, Channels: []ReleaseTrustChannelStateV1{},
		}
	} else {
		next.Revision++
	}
	next.TrustedTime = ReleaseTrustedTimeStateV1{
		Floor: verified.floor.Format(time.RFC3339Nano), CheckpointSHA256: verified.checkpointSHA256, Checkpoint: cloneCheckpoint(verified.checkpoint),
	}
	next, nextSHA256, err := service.commitState(ctx, current, currentSHA256, next, digestHex(observation.evidence))
	if err != nil {
		return TrustedTimeStatus{}, err
	}
	observedAt := service.now()
	service.live[key] = releaseTrustLiveAnchor{
		processInstanceID: service.processInstanceID, stateSHA256: nextSHA256, floor: verified.floor, observedAt: observedAt,
	}
	return TrustedTimeStatus{
		key: key, floor: verified.floor, checkpointSHA256: next.TrustedTime.CheckpointSHA256, stateSHA256: nextSHA256, processInstanceID: service.processInstanceID,
	}, nil
}

func (service *ReleaseTrustService) timeVerificationContext(state ReleaseTrustStateV1) (TransparencyRoot, *TrustedTimeCheckpointV1, time.Time, error) {
	minimum := time.Unix(0, 0).UTC()
	var previous *TrustedTimeCheckpointV1
	if state.SchemaVersion == ReleaseTrustStateSchemaVersion {
		parsed, err := parseCanonicalTime(state.TrustedTime.Floor)
		if err != nil {
			return TransparencyRoot{}, nil, time.Time{}, ErrInvalidReleaseTrustState
		}
		minimum = parsed
		checkpoint := cloneCheckpoint(state.TrustedTime.Checkpoint)
		previous = &checkpoint
	}
	logID := service.options.transparencyRoots[0].logID
	if previous != nil {
		logID = previous.LogID
	}
	for _, root := range service.options.transparencyRoots {
		if root.logID == logID {
			return root, previous, minimum, nil
		}
	}
	return TransparencyRoot{}, nil, time.Time{}, ErrInvalidReleaseTrustState
}

func (service *ReleaseTrustService) loadAndRecover(ctx context.Context) (ReleaseTrustStateV1, string, error) {
	committedBytes, pendingBytes, err := service.loadStateBytes(ctx)
	if err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	committed, committedSHA256, err := decodeOptionalCommittedState(committedBytes, service.options.sourceConfiguration.sourceID)
	if err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	if len(pendingBytes) != 0 {
		pending, pendingSHA256, err := decodePendingState(pendingBytes, service.options.sourceConfiguration.sourceID)
		if err != nil {
			return ReleaseTrustStateV1{}, "", err
		}
		return service.recoverPending(ctx, committed, committedSHA256, pending, pendingSHA256)
	}
	if err := service.validateExternalState(ctx, committed, committedSHA256); err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	return committed, committedSHA256, nil
}

func (service *ReleaseTrustService) loadStateBytes(ctx context.Context) ([]byte, []byte, error) {
	request := SourceTrustStateLoadRequest{sourceID: service.options.sourceConfiguration.sourceID}
	result, err := service.adapters.State.LoadSourceTrustState(ctx, request)
	if err != nil {
		return nil, nil, err
	}
	return result.bytesFor(request)
}

func decodeOptionalCommittedState(raw []byte, sourceID string) (ReleaseTrustStateV1, string, error) {
	if len(raw) == 0 {
		return ReleaseTrustStateV1{}, emptyReleaseTrustStateSHA256, nil
	}
	state, err := decodeReleaseTrustState(raw)
	if err != nil || state.SourceID != sourceID {
		return ReleaseTrustStateV1{}, "", ErrInvalidReleaseTrustState
	}
	return state, digestHex(raw), nil
}

func decodePendingState(raw []byte, sourceID string) (sourceTrustPendingV1, string, error) {
	var pending sourceTrustPendingV1
	if err := decodeClosedJSON(raw, &pending, MaxReleaseTrustPendingBytes, ErrInvalidReleaseTrustState); err != nil {
		return sourceTrustPendingV1{}, "", err
	}
	if pending.SchemaVersion != releaseTrustPendingSchemaVersion || !validTrustTransactionID(pending.TransactionID) || pending.SourceID != sourceID ||
		!sha256Pattern.MatchString(pending.PreviousStateSHA256) || !sha256Pattern.MatchString(pending.NextStateSHA256) || !sha256Pattern.MatchString(pending.EvidenceSHA256) ||
		pending.ExpectedExternalCounter > maxJSONSafeInteger || pending.NextExternalCounter > maxJSONSafeInteger || pending.NextExternalCounter < pending.ExpectedExternalCounter ||
		pending.NextExternalCounter > pending.ExpectedExternalCounter+1 || validateReleaseTrustState(pending.NextState) != nil ||
		pending.NextState.SourceID != sourceID || pending.NextState.ExternalCounter != pending.NextExternalCounter {
		return sourceTrustPendingV1{}, "", ErrInvalidReleaseTrustState
	}
	nextBytes, _ := canonicalReleaseTrustState(pending.NextState)
	if digestHex(nextBytes) != pending.NextStateSHA256 {
		return sourceTrustPendingV1{}, "", ErrInvalidReleaseTrustState
	}
	canonical, _ := json.Marshal(pending)
	if !slices.Equal(canonical, raw) {
		return sourceTrustPendingV1{}, "", ErrInvalidReleaseTrustState
	}
	return pending, digestHex(raw), nil
}

func (service *ReleaseTrustService) validateExternalState(ctx context.Context, state ReleaseTrustStateV1, stateSHA256 string) error {
	if service.adapters.Monotonic == nil {
		if state.SchemaVersion != "" && state.ExternalCounter != 0 {
			return ErrReleaseTrustSplitView
		}
		return nil
	}
	expectedCounter := uint64(0)
	if state.SchemaVersion != "" {
		expectedCounter = state.ExternalCounter
	}
	counter, digest, err := service.readMonotonicState(ctx)
	if err != nil {
		return err
	}
	if counter != expectedCounter || digest != stateSHA256 {
		return ErrReleaseTrustSplitView
	}
	return nil
}

func (service *ReleaseTrustService) recoverPending(
	ctx context.Context,
	committed ReleaseTrustStateV1,
	committedSHA256 string,
	pending sourceTrustPendingV1,
	pendingSHA256 string,
) (ReleaseTrustStateV1, string, error) {
	if pending.PreviousStateSHA256 != committedSHA256 {
		return ReleaseTrustStateV1{}, "", ErrReleaseTrustSplitView
	}
	expectedCounter := uint64(0)
	if committed.SchemaVersion != "" {
		expectedCounter = committed.ExternalCounter
	}
	if pending.ExpectedExternalCounter != expectedCounter {
		return ReleaseTrustStateV1{}, "", ErrReleaseTrustSplitView
	}
	if service.adapters.Monotonic == nil {
		if pending.NextExternalCounter != expectedCounter {
			return ReleaseTrustStateV1{}, "", ErrReleaseTrustSplitView
		}
	} else if err := service.ensureMonotonicApplied(ctx, pending); err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	nextBytes, _ := canonicalReleaseTrustState(pending.NextState)
	if err := service.commitPreparedState(ctx, pendingSHA256, pending.NextStateSHA256, nextBytes); err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	return cloneReleaseTrustState(pending.NextState), pending.NextStateSHA256, nil
}

func (service *ReleaseTrustService) commitState(
	ctx context.Context,
	current ReleaseTrustStateV1,
	currentSHA256 string,
	next ReleaseTrustStateV1,
	evidenceSHA256 string,
) (ReleaseTrustStateV1, string, error) {
	expectedCounter := uint64(0)
	if current.SchemaVersion != "" {
		expectedCounter = current.ExternalCounter
	}
	nextCounter := expectedCounter
	if service.adapters.Monotonic != nil {
		if expectedCounter == maxJSONSafeInteger {
			return ReleaseTrustStateV1{}, "", ErrInvalidReleaseTrustState
		}
		nextCounter++
	}
	next.ExternalCounter = nextCounter
	nextBytes, err := canonicalReleaseTrustState(next)
	if err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	nextSHA256 := digestHex(nextBytes)
	transactionID, err := newTrustTransactionID("transaction")
	if err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	pending := sourceTrustPendingV1{
		SchemaVersion: releaseTrustPendingSchemaVersion, TransactionID: transactionID, SourceID: next.SourceID,
		PreviousStateSHA256: currentSHA256, NextStateSHA256: nextSHA256, ExpectedExternalCounter: expectedCounter,
		NextExternalCounter: nextCounter, EvidenceSHA256: evidenceSHA256, NextState: cloneReleaseTrustState(next),
	}
	pendingBytes, _ := json.Marshal(pending)
	pendingSHA256 := digestHex(pendingBytes)
	prepare := SourceTrustStatePrepareRequest{
		sourceID: next.SourceID, expectedCommittedSHA256: currentSHA256, pendingSHA256: pendingSHA256, pending: pendingBytes,
	}
	outcome, err := service.adapters.State.PrepareSourceTrustState(ctx, prepare)
	if err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	if err := validateMutationOutcome(outcome); err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	switch outcome {
	case StateMutationConflict:
		return ReleaseTrustStateV1{}, "", ErrReleaseTrustStateConflict
	case StateMutationUnknown:
		committedBytes, observedPending, loadErr := service.loadStateBytes(ctx)
		if loadErr != nil {
			return ReleaseTrustStateV1{}, "", errors.Join(ErrReleaseTrustStateUnknown, loadErr)
		}
		if digestOrEmpty(committedBytes) == nextSHA256 && len(observedPending) == 0 {
			if err := service.validateExternalState(ctx, next, nextSHA256); err != nil {
				return ReleaseTrustStateV1{}, "", err
			}
			return cloneReleaseTrustState(next), nextSHA256, nil
		}
		if digestHex(observedPending) != pendingSHA256 {
			return ReleaseTrustStateV1{}, "", ErrReleaseTrustStateUnknown
		}
	}
	if service.adapters.Monotonic != nil {
		if err := service.ensureMonotonicApplied(ctx, pending); err != nil {
			return ReleaseTrustStateV1{}, "", err
		}
	}
	if err := service.commitPreparedState(ctx, pendingSHA256, nextSHA256, nextBytes); err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	return cloneReleaseTrustState(next), nextSHA256, nil
}

func (service *ReleaseTrustService) ensureMonotonicApplied(ctx context.Context, pending sourceTrustPendingV1) error {
	counter, digest, err := service.readMonotonicState(ctx)
	if err != nil {
		return err
	}
	if counter == pending.NextExternalCounter && digest == pending.NextStateSHA256 {
		return nil
	}
	if counter != pending.ExpectedExternalCounter || digest != pending.PreviousStateSHA256 {
		return ErrReleaseTrustSplitView
	}
	request := MonotonicStateCASRequest{
		sourceID: pending.SourceID, transactionID: pending.TransactionID, expectedCounter: pending.ExpectedExternalCounter,
		nextCounter: pending.NextExternalCounter, previousSHA256: pending.PreviousStateSHA256, nextSHA256: pending.NextStateSHA256,
	}
	outcome, err := service.adapters.Monotonic.CompareAndSwapMonotonicState(ctx, request)
	if err != nil {
		return err
	}
	if err := validateMutationOutcome(outcome); err != nil {
		return err
	}
	if outcome == StateMutationApplied {
		return nil
	}
	counter, digest, err = service.readMonotonicState(ctx)
	if err != nil {
		return errors.Join(ErrReleaseTrustStateUnknown, err)
	}
	if counter == pending.NextExternalCounter && digest == pending.NextStateSHA256 {
		return nil
	}
	if outcome == StateMutationConflict {
		return ErrReleaseTrustStateConflict
	}
	return ErrReleaseTrustStateUnknown
}

func (service *ReleaseTrustService) readMonotonicState(ctx context.Context) (uint64, string, error) {
	request := MonotonicStateReadRequest{sourceID: service.options.sourceConfiguration.sourceID}
	result, err := service.adapters.Monotonic.ReadMonotonicState(ctx, request)
	if err != nil {
		return 0, "", err
	}
	return result.valuesFor(request)
}

func (service *ReleaseTrustService) commitPreparedState(ctx context.Context, pendingSHA256, nextSHA256 string, nextBytes []byte) error {
	request := SourceTrustStateCommitRequest{
		sourceID: service.options.sourceConfiguration.sourceID, pendingSHA256: pendingSHA256, nextStateSHA256: nextSHA256, nextState: slices.Clone(nextBytes),
	}
	outcome, err := service.adapters.State.CommitSourceTrustState(ctx, request)
	if err != nil {
		return err
	}
	if err := validateMutationOutcome(outcome); err != nil {
		return err
	}
	if outcome == StateMutationApplied {
		return nil
	}
	committed, pending, loadErr := service.loadStateBytes(ctx)
	if loadErr != nil {
		return errors.Join(ErrReleaseTrustStateUnknown, loadErr)
	}
	if digestOrEmpty(committed) == nextSHA256 && len(pending) == 0 {
		return nil
	}
	if outcome == StateMutationConflict {
		return ErrReleaseTrustStateConflict
	}
	return ErrReleaseTrustStateUnknown
}

func digestOrEmpty(value []byte) string {
	if len(value) == 0 {
		return emptyReleaseTrustStateSHA256
	}
	return digestHex(value)
}

func newTrustTransactionID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(value), nil
}

func validTrustTransactionID(value string) bool {
	separator := strings.IndexByte(value, '_')
	if separator < 1 || len(value) != separator+1+32 || !contractIDPattern.MatchString(value[:separator]) {
		return false
	}
	_, err := hex.DecodeString(value[separator+1:])
	return err == nil && value == strings.ToLower(value)
}

func (service *ReleaseTrustService) String() string {
	if service == nil {
		return ""
	}
	return fmt.Sprintf("release-trust:%s", service.options.sourceConfiguration.sourceID)
}
