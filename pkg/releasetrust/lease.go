package releasetrust

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrActivationLeaseInvalid = errors.New("release trust activation lease is invalid")
	ErrActivationLeaseExpired = errors.New("release trust activation lease expired")
	ErrSourceTrustFenced      = errors.New("release trust source is fenced")
)

type SourceFenceReason string

const (
	SourceFenceRefreshFailed   SourceFenceReason = "refresh_failed"
	SourceFenceExpired         SourceFenceReason = "expired"
	SourceFenceTrustAdvanced   SourceFenceReason = "trust_advanced"
	SourceFenceRestartRecovery SourceFenceReason = "restart_recovery"
)

type ActivationLease struct {
	leaseID           string
	key               SourceTrustKey
	stateSHA256       string
	processInstanceID string
	rootEpoch         string
	policyEpoch       string
	revocationEpoch   string
	issuedElapsed     time.Duration
	refreshElapsed    time.Duration
	expiresElapsed    time.Duration
}

func (lease ActivationLease) SourceTrustKey() SourceTrustKey { return lease.key }
func (lease ActivationLease) StateSHA256() string            { return lease.stateSHA256 }
func (lease ActivationLease) ProcessInstanceID() string      { return lease.processInstanceID }
func (lease ActivationLease) RefreshAfter() time.Duration {
	return lease.refreshElapsed - lease.issuedElapsed
}
func (lease ActivationLease) ValidFor() time.Duration {
	return lease.expiresElapsed - lease.issuedElapsed
}

type activationLeaseState = ActivationLease

type SourceFenceRequest struct {
	key               SourceTrustKey
	generation        uint64
	reason            SourceFenceReason
	stateSHA256       string
	processInstanceID string
	teardownDeadline  time.Duration
}

func (request SourceFenceRequest) SourceTrustKey() SourceTrustKey  { return request.key }
func (request SourceFenceRequest) Generation() uint64              { return request.generation }
func (request SourceFenceRequest) Reason() SourceFenceReason       { return request.reason }
func (request SourceFenceRequest) StateSHA256() string             { return request.stateSHA256 }
func (request SourceFenceRequest) ProcessInstanceID() string       { return request.processInstanceID }
func (request SourceFenceRequest) TeardownDeadline() time.Duration { return request.teardownDeadline }

type SourceFenceCoordinator interface {
	TeardownSourceTrust(context.Context, SourceFenceRequest) error
}

type SourceFenceStatus struct {
	key         SourceTrustKey
	generation  uint64
	reason      SourceFenceReason
	stateSHA256 string
}

func (status SourceFenceStatus) SourceTrustKey() SourceTrustKey { return status.key }
func (status SourceFenceStatus) Generation() uint64             { return status.generation }
func (status SourceFenceStatus) Reason() SourceFenceReason      { return status.reason }
func (status SourceFenceStatus) StateSHA256() string            { return status.stateSHA256 }

func (service *ReleaseTrustService) authorizeActivation(snapshot VerifiedSourceSnapshot) (ActivationLease, error) {
	if service == nil || !snapshot.key.valid() || snapshot.processInstanceID != service.processInstanceID || service.adapters.Fence == nil {
		return ActivationLease{}, ErrActivationLeaseInvalid
	}
	service.refreshMu.Lock()
	defer service.refreshMu.Unlock()
	service.mu.Lock()
	defer service.mu.Unlock()
	current, ok := service.verified[snapshot.key]
	if !ok || current.stateSHA256 != snapshot.stateSHA256 || current.processInstanceID != snapshot.processInstanceID {
		return ActivationLease{}, ErrActivationLeaseInvalid
	}
	elapsed := service.elapsedNow()
	if elapsed < current.refreshedElapsed {
		return ActivationLease{}, ErrActivationLeaseInvalid
	}
	trustedNow := current.trustedFloor.Add(elapsed - current.refreshedElapsed)
	maximum := time.Duration(current.policy.Limits.ActivationLeaseMaxSeconds) * time.Second
	for _, expiresAt := range []string{current.root.ExpiresAt, current.policy.ExpiresAt, current.revocation.ExpiresAt} {
		expires, err := parseCanonicalTime(expiresAt)
		if err != nil || !expires.After(trustedNow) {
			return ActivationLease{}, ErrActivationLeaseExpired
		}
		if remaining := expires.Sub(trustedNow); remaining < maximum {
			maximum = remaining
		}
	}
	if maximum <= 0 {
		return ActivationLease{}, ErrActivationLeaseExpired
	}
	refreshAfter := time.Duration(current.policy.Limits.RefreshIntervalMaxSeconds) * time.Second
	if refreshAfter > maximum {
		refreshAfter = maximum
	}
	leaseID, err := newTrustTransactionID("lease")
	if err != nil {
		return ActivationLease{}, err
	}
	lease := ActivationLease{
		leaseID: leaseID, key: snapshot.key, stateSHA256: snapshot.stateSHA256,
		processInstanceID: service.processInstanceID, rootEpoch: current.root.RootEpoch,
		policyEpoch: current.policy.Epoch, revocationEpoch: current.revocation.Epoch,
		issuedElapsed: elapsed, refreshElapsed: elapsed + refreshAfter, expiresElapsed: elapsed + maximum,
	}
	service.leases[snapshot.key] = lease
	return lease, nil
}

func (service *ReleaseTrustService) ValidateActivationLease(lease ActivationLease) error {
	if service == nil || !lease.key.valid() || lease.processInstanceID != service.processInstanceID || !validTrustTransactionID(lease.leaseID) {
		return ErrActivationLeaseInvalid
	}
	service.mu.RLock()
	current, ok := service.leases[lease.key]
	service.mu.RUnlock()
	if !ok || current != lease {
		return ErrActivationLeaseInvalid
	}
	if service.elapsedNow() >= lease.expiresElapsed {
		return ErrActivationLeaseExpired
	}
	return nil
}

func (service *ReleaseTrustService) RefreshActivationLease(ctx context.Context, lease ActivationLease) (ActivationLease, error) {
	if err := service.ValidateActivationLease(lease); err != nil {
		reason := SourceFenceRefreshFailed
		if errors.Is(err, ErrActivationLeaseExpired) {
			reason = SourceFenceExpired
		}
		_, fenceErr := service.FenceSource(ctx, lease.key, reason)
		return ActivationLease{}, errors.Join(err, fenceErr)
	}
	snapshot, err := service.RefreshSource(ctx, lease.key)
	if err != nil {
		_, fenceErr := service.FenceSource(ctx, lease.key, SourceFenceRefreshFailed)
		return ActivationLease{}, errors.Join(err, fenceErr)
	}
	return service.authorizeActivation(snapshot)
}

func (service *ReleaseTrustService) FenceSource(ctx context.Context, key SourceTrustKey, reason SourceFenceReason) (SourceFenceStatus, error) {
	if service == nil || ctx == nil || !sourceConfigurationContainsKey(service.options.sourceConfiguration, key) || !validFenceReason(reason) {
		return SourceFenceStatus{}, ErrInvalidSourceConfiguration
	}
	service.refreshMu.Lock()
	defer service.refreshMu.Unlock()
	current, currentSHA256, err := service.loadAndRecover(ctx)
	if err != nil {
		return SourceFenceStatus{}, err
	}
	deadline := service.teardownDeadline(key)
	status, _, _, err := service.fenceLoadedSourceLocked(ctx, key, reason, current, currentSHA256)
	if err != nil {
		service.invalidateLease(key)
		return SourceFenceStatus{}, err
	}
	service.invalidateLease(key)
	if err := service.teardownFencedSource(ctx, status, deadline); err != nil {
		return status, err
	}
	return status, nil
}

func (service *ReleaseTrustService) fenceLoadedSourceLocked(
	ctx context.Context,
	key SourceTrustKey,
	reason SourceFenceReason,
	current ReleaseTrustStateV1,
	currentSHA256 string,
) (SourceFenceStatus, ReleaseTrustStateV1, string, error) {
	channel := findChannelState(current, key.channel)
	if channel == nil {
		return SourceFenceStatus{}, ReleaseTrustStateV1{}, "", ErrSourceTrustFenced
	}
	if channel.Fence != nil {
		status := SourceFenceStatus{key: key, generation: channel.Fence.Generation, reason: channel.Fence.Reason, stateSHA256: currentSHA256}
		return status, current, currentSHA256, nil
	}
	if current.Revision == maxJSONSafeInteger || channel.FenceGeneration == maxJSONSafeInteger {
		return SourceFenceStatus{}, ReleaseTrustStateV1{}, "", ErrInvalidReleaseTrustState
	}
	next := cloneReleaseTrustState(current)
	next.Revision++
	index, found := slicesBinarySearchChannel(next.Channels, key.channel)
	if !found {
		return SourceFenceStatus{}, ReleaseTrustStateV1{}, "", ErrSourceTrustFenced
	}
	generation := next.Channels[index].FenceGeneration + 1
	next.Channels[index].FenceGeneration = generation
	next.Channels[index].Fence = &ReleaseTrustFenceV1{
		Generation: generation, Reason: reason, FencedAt: current.TrustedTime.Floor,
	}
	committed, committedSHA256, err := service.commitState(ctx, current, currentSHA256, next, digestHex([]byte(reason)))
	if err != nil {
		return SourceFenceStatus{}, ReleaseTrustStateV1{}, "", err
	}
	status := SourceFenceStatus{key: key, generation: generation, reason: reason, stateSHA256: committedSHA256}
	return status, committed, committedSHA256, nil
}

func (service *ReleaseTrustService) teardownFencedSource(ctx context.Context, status SourceFenceStatus, deadline time.Duration) error {
	if service.adapters.Fence == nil {
		return ErrSourceTrustFenced
	}
	request := SourceFenceRequest{
		key: status.key, generation: status.generation, reason: status.reason, stateSHA256: status.stateSHA256,
		processInstanceID: service.processInstanceID, teardownDeadline: deadline,
	}
	deadlineContext, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	if err := service.adapters.Fence.TeardownSourceTrust(deadlineContext, request); err != nil {
		return fmt.Errorf("%w: %v", ErrSourceTrustFenced, err)
	}
	return nil
}

const releasecontractDefaultTeardownSeconds = 30

func (service *ReleaseTrustService) teardownDeadline(key SourceTrustKey) time.Duration {
	deadline := time.Duration(releasecontractDefaultTeardownSeconds) * time.Second
	service.mu.RLock()
	snapshot, ok := service.verified[key]
	service.mu.RUnlock()
	if ok && snapshot.processInstanceID == service.processInstanceID {
		deadline = time.Duration(snapshot.policy.Limits.FailureTeardownDeadlineSeconds) * time.Second
	}
	return deadline
}

func (service *ReleaseTrustService) reconcileSourceFenceLocked(
	ctx context.Context,
	key SourceTrustKey,
	current ReleaseTrustStateV1,
	currentSHA256 string,
) (ReleaseTrustStateV1, string, error) {
	channel := findChannelState(current, key.channel)
	if channel == nil || channel.Fence == nil {
		return current, currentSHA256, nil
	}
	status := SourceFenceStatus{key: key, generation: channel.Fence.Generation, reason: channel.Fence.Reason, stateSHA256: currentSHA256}
	deadline := service.teardownDeadline(key)
	service.invalidateLease(key)
	if err := service.teardownFencedSource(ctx, status, deadline); err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	return service.acknowledgeSourceFenceLocked(ctx, key, status.generation, current, currentSHA256)
}

func (service *ReleaseTrustService) fenceTrustAdvanceLocked(
	ctx context.Context,
	key SourceTrustKey,
	current ReleaseTrustStateV1,
	currentSHA256 string,
	documents verifiedReleaseDocumentSet,
) (ReleaseTrustStateV1, string, error) {
	service.mu.RLock()
	lease, active := service.leases[key]
	service.mu.RUnlock()
	if !active || lease.rootEpoch == documents.root.RootEpoch && lease.policyEpoch == documents.policy.Epoch &&
		lease.revocationEpoch == documents.revocation.Epoch {
		return current, currentSHA256, nil
	}
	deadline := service.teardownDeadline(key)
	status, fenced, fencedSHA256, err := service.fenceLoadedSourceLocked(ctx, key, SourceFenceTrustAdvanced, current, currentSHA256)
	service.invalidateLease(key)
	if err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	if err := service.teardownFencedSource(ctx, status, deadline); err != nil {
		return ReleaseTrustStateV1{}, "", err
	}
	return service.acknowledgeSourceFenceLocked(ctx, key, status.generation, fenced, fencedSHA256)
}

func (service *ReleaseTrustService) acknowledgeSourceFenceLocked(
	ctx context.Context,
	key SourceTrustKey,
	generation uint64,
	current ReleaseTrustStateV1,
	currentSHA256 string,
) (ReleaseTrustStateV1, string, error) {
	next := cloneReleaseTrustState(current)
	index, found := slicesBinarySearchChannel(next.Channels, key.channel)
	if !found || next.Channels[index].Fence == nil || next.Channels[index].Fence.Generation != generation {
		return ReleaseTrustStateV1{}, "", ErrSourceTrustFenced
	}
	if next.Revision == maxJSONSafeInteger {
		return ReleaseTrustStateV1{}, "", ErrInvalidReleaseTrustState
	}
	next.Revision++
	next.Channels[index].Fence = nil
	return service.commitState(ctx, current, currentSHA256, next, digestHex([]byte("fence_acknowledged")))
}

func (service *ReleaseTrustService) invalidateLease(key SourceTrustKey) {
	service.mu.Lock()
	delete(service.leases, key)
	delete(service.verified, key)
	service.mu.Unlock()
}

func validFenceReason(reason SourceFenceReason) bool {
	switch reason {
	case SourceFenceRefreshFailed, SourceFenceExpired, SourceFenceTrustAdvanced, SourceFenceRestartRecovery:
		return true
	default:
		return false
	}
}

func slicesBinarySearchChannel(values []ReleaseTrustChannelStateV1, channel string) (int, bool) {
	left, right := 0, len(values)
	for left < right {
		middle := int(uint(left+right) >> 1)
		if values[middle].Channel < channel {
			left = middle + 1
		} else {
			right = middle
		}
	}
	return left, left < len(values) && values[left].Channel == channel
}
