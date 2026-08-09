package releasetrust

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

const ActivationRecoveryEvidenceSchemaVersion = "redevplugin.activation_recovery_evidence.v1"

var ErrActivationRecoveryRejected = errors.New("release trust activation recovery evidence was rejected")

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
	if set == nil || ctx == nil || !evidence.valid() {
		return ActivationLease{}, ErrActivationRecoveryRejected
	}
	service := set.services[evidence.identity.SourceID]
	if service == nil {
		return ActivationLease{}, ErrActivationRecoveryRejected
	}
	key, err := service.options.sourceConfiguration.TrustKey(evidence.identity.Channel)
	if err != nil {
		return ActivationLease{}, ErrActivationRecoveryRejected
	}
	return service.recoverActivationLease(ctx, key, evidence)
}

func (service *ReleaseTrustService) recoverActivationLease(
	ctx context.Context,
	key SourceTrustKey,
	evidence ActivationRecoveryEvidence,
) (ActivationLease, error) {
	service.refreshMu.Lock()
	defer service.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ActivationLease{}, err
	}
	current, currentSHA256, err := service.loadAndRecover(ctx)
	if err != nil {
		return ActivationLease{}, err
	}
	channel := findChannelState(current, key.channel)
	if currentSHA256 != evidence.stateSHA256 {
		return ActivationLease{}, activationRecoveryRejected("state digest mismatch")
	}
	if current.Root == nil || current.SigningLedger == nil || channel == nil || channel.Policy == nil || channel.Revocation == nil {
		return ActivationLease{}, activationRecoveryRejected("durable trust evidence is incomplete")
	}
	if channel.Fence != nil {
		return ActivationLease{}, activationRecoveryRejected("source trust is fenced")
	}
	if current.Root.Epoch != evidence.rootEpoch || channel.Policy.PointerEpoch != evidence.policyEpoch || channel.Revocation.PointerEpoch != evidence.revocationEpoch {
		return ActivationLease{}, activationRecoveryRejected("trust epoch mismatch")
	}
	trustedFloor, err := parseCanonicalTime(current.TrustedTime.Floor)
	if err != nil {
		return ActivationLease{}, ErrActivationRecoveryRejected
	}
	trustedNow := service.now().UTC()
	if trustedNow.Before(trustedFloor) {
		return ActivationLease{}, ErrReleaseTrustRollback
	}
	maximum := time.Duration(releasecontract.DefaultSourcePolicyLimits().ActivationLeaseMaxSeconds) * time.Second
	for _, expiresAt := range []string{current.Root.ExpiresAt, channel.Policy.ExpiresAt, channel.Revocation.ExpiresAt} {
		expires, parseErr := parseCanonicalTime(expiresAt)
		if parseErr != nil || !expires.After(trustedNow) {
			return ActivationLease{}, ErrActivationLeaseExpired
		}
		if remaining := expires.Sub(trustedNow); remaining < maximum {
			maximum = remaining
		}
	}
	if maximum <= 0 {
		return ActivationLease{}, ErrActivationLeaseExpired
	}
	refreshAfter := time.Duration(releasecontract.DefaultSourcePolicyLimits().RefreshIntervalMaxSeconds) * time.Second
	if refreshAfter > maximum {
		refreshAfter = maximum
	}
	leaseID, err := newTrustTransactionID("lease")
	if err != nil {
		return ActivationLease{}, err
	}
	elapsed := service.elapsedNow()
	lease := ActivationLease{
		leaseID: leaseID, key: key, stateSHA256: currentSHA256, processInstanceID: service.processInstanceID,
		rootEpoch: evidence.rootEpoch, policyEpoch: evidence.policyEpoch, revocationEpoch: evidence.revocationEpoch,
		issuedElapsed: elapsed, refreshElapsed: elapsed + refreshAfter, expiresElapsed: elapsed + maximum,
	}
	service.mu.Lock()
	service.leases[key] = lease
	service.live[key] = releaseTrustLiveAnchor{
		processInstanceID: service.processInstanceID, stateSHA256: currentSHA256, floor: trustedNow, observedAt: trustedNow,
	}
	service.mu.Unlock()
	return lease, nil
}

func activationRecoveryRejected(reason string) error {
	return fmt.Errorf("%w: %s", ErrActivationRecoveryRejected, reason)
}
