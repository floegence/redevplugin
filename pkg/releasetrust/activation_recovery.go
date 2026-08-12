package releasetrust

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

const ActivationRecoveryEvidenceSchemaVersion = "redevplugin.activation_recovery_evidence.v1"

var ErrActivationRecoveryRejected = errors.New("release trust activation recovery evidence was rejected")

type ActivationRecoveryRejectionReason string

const (
	ActivationRecoveryReasonEvidenceInvalid          ActivationRecoveryRejectionReason = "evidence_invalid"
	ActivationRecoveryReasonStateAdvancementFailed   ActivationRecoveryRejectionReason = "state_advancement_revalidation_failed"
	ActivationRecoveryReasonTrustFenced              ActivationRecoveryRejectionReason = "trust_fenced"
	ActivationRecoveryReasonTrustEpochMismatch       ActivationRecoveryRejectionReason = "trust_epoch_mismatch"
	ActivationRecoveryReasonPolicyDenied             ActivationRecoveryRejectionReason = "policy_denied"
	ActivationRecoveryReasonReleaseRevoked           ActivationRecoveryRejectionReason = "release_revoked"
	ActivationRecoveryReasonStateChangedBeforeCommit ActivationRecoveryRejectionReason = "state_changed_before_commit"
)

type ActivationRecoveryRejection struct {
	reason  ActivationRecoveryRejectionReason
	message string
	cause   error
}

func (rejection *ActivationRecoveryRejection) Error() string {
	if rejection == nil {
		return ErrActivationRecoveryRejected.Error()
	}
	if rejection.cause != nil {
		return fmt.Sprintf("%s: %s: %v", ErrActivationRecoveryRejected, rejection.message, rejection.cause)
	}
	return fmt.Sprintf("%s: %s", ErrActivationRecoveryRejected, rejection.message)
}

func (rejection *ActivationRecoveryRejection) Is(target error) bool {
	return target == ErrActivationRecoveryRejected
}

func (rejection *ActivationRecoveryRejection) Unwrap() error { return rejection.cause }
func (rejection *ActivationRecoveryRejection) Reason() ActivationRecoveryRejectionReason {
	if rejection == nil {
		return ActivationRecoveryReasonEvidenceInvalid
	}
	return rejection.reason
}

func NewActivationRecoveryRejection(reason ActivationRecoveryRejectionReason, message string) error {
	return activationRecoveryRejected(reason, message, nil)
}

// ActivationRecoveryEvidence binds an installed package to the exact durable
// source-trust state that authorized it. It is reconstructed from the
// authoritative registry record rather than accepted from plugin input.
type ActivationRecoveryEvidence struct {
	schemaVersion     string
	pluginInstanceID  string
	identity          ReleaseIdentity
	packageSHA256     string
	manifestSHA256    string
	entriesSHA256     string
	activeFingerprint string
	stateSHA256       string
	rootEpoch         string
	policyEpoch       string
	revocationEpoch   string
}

// PreparedActivationRecovery is a verified, process-local recovery candidate.
// It is not an activation lease until CommitActivationRecovery succeeds.
type PreparedActivationRecovery struct {
	lease               ActivationLease
	previousStateSHA256 string
}

func (prepared PreparedActivationRecovery) StateSHA256() string { return prepared.lease.stateSHA256 }
func (prepared PreparedActivationRecovery) PreviousStateSHA256() string {
	return prepared.previousStateSHA256
}

func NewActivationRecoveryEvidence(
	pluginInstanceID string,
	identity ReleaseIdentity,
	packageSHA256 string,
	manifestSHA256 string,
	entriesSHA256 string,
	activeFingerprint string,
	stateSHA256 string,
	rootEpoch string,
	policyEpoch string,
	revocationEpoch string,
) (ActivationRecoveryEvidence, error) {
	evidence := ActivationRecoveryEvidence{
		schemaVersion: ActivationRecoveryEvidenceSchemaVersion, pluginInstanceID: strings.TrimSpace(pluginInstanceID),
		identity: identity, packageSHA256: packageSHA256, manifestSHA256: manifestSHA256,
		entriesSHA256: entriesSHA256, activeFingerprint: activeFingerprint, stateSHA256: stateSHA256,
		rootEpoch: rootEpoch, policyEpoch: policyEpoch, revocationEpoch: revocationEpoch,
	}
	if !evidence.valid() {
		return ActivationRecoveryEvidence{}, ErrActivationRecoveryRejected
	}
	return evidence, nil
}

func (evidence ActivationRecoveryEvidence) valid() bool {
	return evidence.schemaVersion == ActivationRecoveryEvidenceSchemaVersion && evidence.pluginInstanceID != "" &&
		validReleaseIdentity(evidence.identity) && sha256Pattern.MatchString(normalizeReleaseSHA256(evidence.packageSHA256)) &&
		sha256Pattern.MatchString(normalizeReleaseSHA256(evidence.manifestSHA256)) && sha256Pattern.MatchString(normalizeReleaseSHA256(evidence.entriesSHA256)) &&
		strings.HasPrefix(evidence.activeFingerprint, "sha256:") &&
		sha256Pattern.MatchString(strings.TrimPrefix(evidence.activeFingerprint, "sha256:")) &&
		sha256Pattern.MatchString(evidence.stateSHA256) && validEpoch(evidence.rootEpoch) &&
		validEpoch(evidence.policyEpoch) && validEpoch(evidence.revocationEpoch)
}

func (set *ServiceSet) RecoverActivationLease(ctx context.Context, evidence ActivationRecoveryEvidence) (ActivationLease, error) {
	prepared, err := set.PrepareActivationRecovery(ctx, evidence)
	if err != nil {
		return ActivationLease{}, err
	}
	return set.CommitActivationRecovery(ctx, prepared)
}

func (set *ServiceSet) PrepareActivationRecovery(ctx context.Context, evidence ActivationRecoveryEvidence) (PreparedActivationRecovery, error) {
	if set == nil || ctx == nil || !evidence.valid() {
		return PreparedActivationRecovery{}, ErrActivationRecoveryRejected
	}
	service := set.services[evidence.identity.SourceID]
	if service == nil {
		return PreparedActivationRecovery{}, ErrActivationRecoveryRejected
	}
	key, err := service.options.sourceConfiguration.TrustKey(evidence.identity.Channel)
	if err != nil {
		return PreparedActivationRecovery{}, ErrActivationRecoveryRejected
	}
	return service.prepareActivationRecovery(ctx, key, evidence)
}

func (set *ServiceSet) CommitActivationRecovery(ctx context.Context, prepared PreparedActivationRecovery) (ActivationLease, error) {
	service := set.serviceForKey(prepared.lease.key)
	if service == nil {
		return ActivationLease{}, ErrActivationRecoveryRejected
	}
	return service.commitActivationRecovery(ctx, prepared)
}

func (service *ReleaseTrustService) prepareActivationRecovery(
	ctx context.Context,
	key SourceTrustKey,
	evidence ActivationRecoveryEvidence,
) (PreparedActivationRecovery, error) {
	service.refreshMu.Lock()
	defer service.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return PreparedActivationRecovery{}, err
	}
	current, currentSHA256, err := service.loadAndRecover(ctx)
	if err != nil {
		return PreparedActivationRecovery{}, err
	}
	channel := findChannelState(current, key.channel)
	if current.Root == nil || current.SigningLedger == nil || channel == nil || channel.Policy == nil || channel.Revocation == nil {
		return PreparedActivationRecovery{}, activationRecoveryRejected(ActivationRecoveryReasonEvidenceInvalid, "durable trust evidence is incomplete", nil)
	}
	if channel.Fence != nil {
		return PreparedActivationRecovery{}, activationRecoveryRejected(ActivationRecoveryReasonTrustFenced, "source trust is fenced", nil)
	}
	if current.Root.Epoch != evidence.rootEpoch || channel.Policy.PointerEpoch != evidence.policyEpoch || channel.Revocation.PointerEpoch != evidence.revocationEpoch {
		return PreparedActivationRecovery{}, activationRecoveryRejected(ActivationRecoveryReasonTrustEpochMismatch, "trust epoch mismatch", nil)
	}
	if currentSHA256 != evidence.stateSHA256 {
		var snapshot VerifiedSourceSnapshot
		var refreshErr error
		if service.adapters.Monotonic == nil {
			snapshot, refreshErr = service.refreshSourceLocked(ctx, key)
		} else {
			snapshot, refreshErr = service.recoverVerifiedSnapshotFromDurableHeadsLocked(ctx, key, current, currentSHA256)
		}
		if refreshErr != nil {
			return PreparedActivationRecovery{}, activationRecoveryRejected(ActivationRecoveryReasonStateAdvancementFailed, "trust state advancement revalidation failed", refreshErr)
		}
		policy := snapshot.SourcePolicy()
		revocation := snapshot.Revocation()
		if policy.RootEpoch != evidence.rootEpoch || policy.Epoch != evidence.policyEpoch || revocation.Epoch != evidence.revocationEpoch {
			return PreparedActivationRecovery{}, activationRecoveryRejected(ActivationRecoveryReasonTrustEpochMismatch, "trust epoch mismatch", nil)
		}
		if !slices.Contains(policy.AllowedPublishers, evidence.identity.PublisherID) || policy.InstallPolicy == "block" {
			return PreparedActivationRecovery{}, activationRecoveryRejected(ActivationRecoveryReasonPolicyDenied, "source policy no longer authorizes release", nil)
		}
		if releaseRevoked(revocation, evidence.identity, "") {
			return PreparedActivationRecovery{}, activationRecoveryRejected(ActivationRecoveryReasonReleaseRevoked, "release is revoked", nil)
		}
		lease, leaseErr := service.activationLeaseForVerifiedSnapshot(snapshot)
		if leaseErr != nil {
			return PreparedActivationRecovery{}, leaseErr
		}
		return PreparedActivationRecovery{lease: lease, previousStateSHA256: evidence.stateSHA256}, nil
	}
	trustedFloor, err := parseCanonicalTime(current.TrustedTime.Floor)
	if err != nil {
		return PreparedActivationRecovery{}, ErrActivationRecoveryRejected
	}
	trustedNow := service.now().UTC()
	if trustedNow.Before(trustedFloor) {
		return PreparedActivationRecovery{}, ErrReleaseTrustRollback
	}
	maximum := time.Duration(releasecontract.DefaultSourcePolicyLimits().ActivationLeaseMaxSeconds) * time.Second
	for _, expiresAt := range []string{current.Root.ExpiresAt, channel.Policy.ExpiresAt, channel.Revocation.ExpiresAt} {
		expires, parseErr := parseCanonicalTime(expiresAt)
		if parseErr != nil || !expires.After(trustedNow) {
			return PreparedActivationRecovery{}, ErrActivationLeaseExpired
		}
		if remaining := expires.Sub(trustedNow); remaining < maximum {
			maximum = remaining
		}
	}
	if maximum <= 0 {
		return PreparedActivationRecovery{}, ErrActivationLeaseExpired
	}
	refreshAfter := time.Duration(releasecontract.DefaultSourcePolicyLimits().RefreshIntervalMaxSeconds) * time.Second
	if refreshAfter > maximum {
		refreshAfter = maximum
	}
	leaseID, err := newTrustTransactionID("lease")
	if err != nil {
		return PreparedActivationRecovery{}, err
	}
	elapsed := service.elapsedNow()
	lease := ActivationLease{
		leaseID: leaseID, key: key, stateSHA256: currentSHA256, processInstanceID: service.processInstanceID,
		rootEpoch: evidence.rootEpoch, policyEpoch: evidence.policyEpoch, revocationEpoch: evidence.revocationEpoch,
		issuedElapsed: elapsed, refreshElapsed: elapsed + refreshAfter, expiresElapsed: elapsed + maximum,
	}
	return PreparedActivationRecovery{lease: lease, previousStateSHA256: evidence.stateSHA256}, nil
}

func (service *ReleaseTrustService) recoverVerifiedSnapshotFromDurableHeadsLocked(
	ctx context.Context,
	key SourceTrustKey,
	current ReleaseTrustStateV1,
	currentSHA256 string,
) (VerifiedSourceSnapshot, error) {
	if current.Root == nil || current.SigningLedger == nil {
		return VerifiedSourceSnapshot{}, ErrReleaseTrustVerification
	}
	channel := findChannelState(current, key.channel)
	if channel == nil || channel.Policy == nil || channel.Revocation == nil || channel.Fence != nil {
		return VerifiedSourceSnapshot{}, ErrSourceTrustFenced
	}
	trustedFloor, err := parseCanonicalTime(current.TrustedTime.Floor)
	if err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	trustedNow := service.now().UTC()
	if trustedNow.Before(trustedFloor) {
		return VerifiedSourceSnapshot{}, ErrReleaseTrustRollback
	}

	rootRequest, err := fixedReleaseDocumentRequest(service.options.sourceConfiguration, key, ReleaseDocumentRootDelegation)
	if err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	rootBytes, _, err := service.fetchReleaseDocument(ctx, rootRequest)
	if err != nil || digestHex(rootBytes) != current.Root.DocumentSHA256 {
		return VerifiedSourceSnapshot{}, fmt.Errorf("recover durable root head: %w", ErrReleaseTrustVerification)
	}
	root, err := releasecontract.DecodeRootDelegation(rootBytes)
	if err != nil || root.SourceID != key.sourceID || root.RootEpoch != current.Root.Epoch ||
		root.GeneratedAt != current.Root.GeneratedAt || root.ExpiresAt != current.Root.ExpiresAt || root.KeyID != current.Root.KeyID {
		return VerifiedSourceSnapshot{}, fmt.Errorf("recover durable root identity: %w", ErrReleaseTrustVerification)
	}
	rootVerifier := releasecontract.Ed25519PublicKeyVerifier{
		service.options.rootAnchor.keyID: ed25519.PublicKey(service.options.rootAnchor.PublicKey()),
	}
	if err := releasecontract.VerifyRootDelegation(root, rootVerifier); err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	if err := validateDocumentWindow(root.GeneratedAt, root.ExpiresAt, trustedNow, releasecontract.DefaultSourcePolicyLimits().FutureSkewSeconds); err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	policyPointer, policyPointerBytes, policyPointerToken, err := service.fetchAndVerifyPolicyPointer(ctx, key, root, nil, trustedNow)
	if err != nil || digestHex(policyPointerBytes) != channel.Policy.PointerSHA256 || policyPointerToken != channel.Policy.PointerTransportToken ||
		policyPointer.Epoch != channel.Policy.PointerEpoch || policyPointer.DocumentSHA256 != channel.Policy.DocumentSHA256 {
		return VerifiedSourceSnapshot{}, fmt.Errorf("recover durable policy pointer: %w", ErrReleaseTrustVerification)
	}
	policy, policyBytes, policyToken, err := service.fetchAndVerifyPolicy(ctx, key, root, policyPointer, trustedNow)
	if err != nil || digestHex(policyBytes) != channel.Policy.DocumentSHA256 || policyToken != channel.Policy.DocumentTransportToken ||
		policy.GeneratedAt != channel.Policy.GeneratedAt || policy.ExpiresAt != channel.Policy.ExpiresAt || policy.KeyID != channel.Policy.KeyID {
		return VerifiedSourceSnapshot{}, fmt.Errorf("recover durable policy: %w", ErrReleaseTrustVerification)
	}
	revocationPointer, revocationPointerBytes, revocationPointerToken, err := service.fetchAndVerifyRevocationPointer(ctx, key, root, policy, nil, trustedNow)
	if err != nil || digestHex(revocationPointerBytes) != channel.Revocation.PointerSHA256 || revocationPointerToken != channel.Revocation.PointerTransportToken ||
		revocationPointer.Epoch != channel.Revocation.PointerEpoch || revocationPointer.DocumentSHA256 != channel.Revocation.DocumentSHA256 {
		return VerifiedSourceSnapshot{}, fmt.Errorf("recover durable revocation pointer: %w", ErrReleaseTrustVerification)
	}
	revocation, revocationBytes, revocationToken, err := service.fetchAndVerifyRevocation(ctx, key, root, policy, revocationPointer, trustedNow)
	if err != nil || digestHex(revocationBytes) != channel.Revocation.DocumentSHA256 || revocationToken != channel.Revocation.DocumentTransportToken ||
		revocation.GeneratedAt != channel.Revocation.GeneratedAt || revocation.ExpiresAt != channel.Revocation.ExpiresAt || revocation.KeyID != channel.Revocation.KeyID {
		return VerifiedSourceSnapshot{}, fmt.Errorf("recover durable revocation: %w", ErrReleaseTrustVerification)
	}

	snapshot := VerifiedSourceSnapshot{
		key: key, root: root, policy: policy, revocation: revocation,
		trustedFloor: trustedNow, stateSHA256: currentSHA256,
		processInstanceID: service.processInstanceID, refreshedElapsed: service.elapsedNow(),
	}
	service.mu.Lock()
	service.verified[key] = cloneVerifiedSourceSnapshot(snapshot)
	service.live[key] = releaseTrustLiveAnchor{
		processInstanceID: service.processInstanceID, stateSHA256: currentSHA256,
		floor: trustedNow, observedAt: service.now(),
	}
	service.mu.Unlock()
	return snapshot, nil
}

func (service *ReleaseTrustService) commitActivationRecovery(ctx context.Context, prepared PreparedActivationRecovery) (ActivationLease, error) {
	if service == nil || ctx == nil || prepared.lease.processInstanceID != service.processInstanceID || !prepared.lease.key.valid() {
		return ActivationLease{}, ErrActivationRecoveryRejected
	}
	service.refreshMu.Lock()
	defer service.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ActivationLease{}, err
	}
	_, currentSHA256, err := service.loadAndRecover(ctx)
	if err != nil {
		return ActivationLease{}, err
	}
	if currentSHA256 != prepared.lease.stateSHA256 {
		return ActivationLease{}, activationRecoveryRejected(ActivationRecoveryReasonStateChangedBeforeCommit, "trust state changed before activation commit", nil)
	}
	service.mu.Lock()
	service.leases[prepared.lease.key] = prepared.lease
	service.mu.Unlock()
	return prepared.lease, nil
}

func activationRecoveryRejected(reason ActivationRecoveryRejectionReason, message string, cause error) error {
	return &ActivationRecoveryRejection{reason: reason, message: message, cause: cause}
}
