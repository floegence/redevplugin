package releasetrust

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	Fence       SourceFenceCoordinator
}

type releaseTrustLiveAnchor struct {
	processInstanceID string
	stateSHA256       string
	floor             time.Time
	observedAt        time.Time
}

type ReleaseTrustService struct {
	mu                sync.RWMutex
	refreshMu         sync.Mutex
	options           ReleaseTrustOptions
	adapters          ReleaseTrustAdapters
	processInstanceID string
	now               func() time.Time
	elapsedNow        func() time.Duration
	live              map[SourceTrustKey]releaseTrustLiveAnchor
	verified          map[SourceTrustKey]VerifiedSourceSnapshot
	leases            map[SourceTrustKey]activationLeaseState
}

func NewReleaseTrustService(options ReleaseTrustOptions, adapters ReleaseTrustAdapters) (*ReleaseTrustService, error) {
	if !options.valid() || isNilInterface(adapters.Documents) || isNilInterface(adapters.Ledger) || isNilInterface(adapters.State) ||
		isNilInterface(adapters.TrustedTime) || (adapters.Monotonic != nil && isNilInterface(adapters.Monotonic)) ||
		(adapters.Fence != nil && isNilInterface(adapters.Fence)) {
		return nil, ErrInvalidReleaseTrustOptions
	}
	processID, err := newTrustTransactionID("process")
	if err != nil {
		return nil, err
	}
	startedAt := time.Now()
	return &ReleaseTrustService{
		options: options, adapters: adapters, processInstanceID: processID, now: time.Now,
		elapsedNow: func() time.Duration { return time.Since(startedAt) },
		live:       make(map[SourceTrustKey]releaseTrustLiveAnchor),
		verified:   make(map[SourceTrustKey]VerifiedSourceSnapshot),
		leases:     make(map[SourceTrustKey]activationLeaseState),
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
	service.refreshMu.Lock()
	defer service.refreshMu.Unlock()
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
	service.mu.Lock()
	service.live[key] = releaseTrustLiveAnchor{
		processInstanceID: service.processInstanceID, stateSHA256: nextSHA256, floor: verified.floor, observedAt: observedAt,
	}
	service.mu.Unlock()
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
	return service.commitStateAttempt(ctx, current, currentSHA256, next, evidenceSHA256, 0)
}

func (service *ReleaseTrustService) commitStateAttempt(
	ctx context.Context,
	current ReleaseTrustStateV1,
	currentSHA256 string,
	next ReleaseTrustStateV1,
	evidenceSHA256 string,
	attempt int,
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
		if attempt >= 3 {
			return ReleaseTrustStateV1{}, "", ErrReleaseTrustStateConflict
		}
		latest, latestSHA256, loadErr := service.loadAndRecover(ctx)
		if loadErr != nil {
			return ReleaseTrustStateV1{}, "", loadErr
		}
		merged, mergeErr := mergeReleaseTrustStates(current, next, latest)
		if mergeErr != nil {
			return ReleaseTrustStateV1{}, "", mergeErr
		}
		return service.commitStateAttempt(ctx, latest, latestSHA256, merged, evidenceSHA256, attempt+1)
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

func mergeReleaseTrustStates(base, proposed, latest ReleaseTrustStateV1) (ReleaseTrustStateV1, error) {
	if base.SchemaVersion == "" || proposed.SchemaVersion != ReleaseTrustStateSchemaVersion || latest.SchemaVersion != ReleaseTrustStateSchemaVersion ||
		base.SourceID != proposed.SourceID || base.SourceID != latest.SourceID {
		return ReleaseTrustStateV1{}, ErrReleaseTrustStateConflict
	}
	merged := cloneReleaseTrustState(latest)
	if err := mergeTrustField(base.Root, proposed.Root, latest.Root, func() {
		if proposed.Root == nil {
			merged.Root = nil
		} else {
			value := *proposed.Root
			merged.Root = &value
		}
	}); err != nil {
		return ReleaseTrustStateV1{}, err
	}
	if err := mergeTrustField(base.TrustedTime, proposed.TrustedTime, latest.TrustedTime, func() {
		merged.TrustedTime = proposed.TrustedTime
	}); err != nil {
		return ReleaseTrustStateV1{}, err
	}
	if err := mergeTrustField(base.SigningLedger, proposed.SigningLedger, latest.SigningLedger, func() {
		if proposed.SigningLedger == nil {
			merged.SigningLedger = nil
		} else {
			value := *proposed.SigningLedger
			merged.SigningLedger = &value
		}
	}); err != nil {
		return ReleaseTrustStateV1{}, err
	}

	baseChannels := channelStateMap(base.Channels)
	proposedChannels := channelStateMap(proposed.Channels)
	latestChannels := channelStateMap(latest.Channels)
	for channel, proposedValue := range proposedChannels {
		baseValue, baseExists := baseChannels[channel]
		if baseExists && reflect.DeepEqual(baseValue, proposedValue) {
			continue
		}
		latestValue, latestExists := latestChannels[channel]
		if latestExists != baseExists || latestExists && !reflect.DeepEqual(latestValue, baseValue) {
			if !latestExists || !reflect.DeepEqual(latestValue, proposedValue) {
				return ReleaseTrustStateV1{}, ErrReleaseTrustStateConflict
			}
		}
		latestChannels[channel] = proposedValue
	}
	for channel := range baseChannels {
		if _, retained := proposedChannels[channel]; retained {
			continue
		}
		latestValue, latestExists := latestChannels[channel]
		if !latestExists || !reflect.DeepEqual(latestValue, baseChannels[channel]) {
			return ReleaseTrustStateV1{}, ErrReleaseTrustStateConflict
		}
		delete(latestChannels, channel)
	}
	merged.Channels = make([]ReleaseTrustChannelStateV1, 0, len(latestChannels))
	for _, value := range latestChannels {
		merged.Channels = append(merged.Channels, value)
	}
	slices.SortFunc(merged.Channels, func(left, right ReleaseTrustChannelStateV1) int {
		return strings.Compare(left.Channel, right.Channel)
	})
	if latest.Revision == maxJSONSafeInteger {
		return ReleaseTrustStateV1{}, ErrInvalidReleaseTrustState
	}
	merged.Revision = latest.Revision + 1
	return merged, nil
}

func mergeTrustField[T any](base, proposed, latest T, apply func()) error {
	if reflect.DeepEqual(base, proposed) {
		return nil
	}
	if !reflect.DeepEqual(latest, base) && !reflect.DeepEqual(latest, proposed) {
		return ErrReleaseTrustStateConflict
	}
	apply()
	return nil
}

func channelStateMap(values []ReleaseTrustChannelStateV1) map[string]ReleaseTrustChannelStateV1 {
	result := make(map[string]ReleaseTrustChannelStateV1, len(values))
	for _, value := range values {
		cloned := cloneReleaseTrustState(ReleaseTrustStateV1{Channels: []ReleaseTrustChannelStateV1{value}})
		result[value.Channel] = cloned.Channels[0]
	}
	return result
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
