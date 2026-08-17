package releasetrust

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
)

func (service *ReleaseTrustService) RefreshSource(ctx context.Context, key SourceTrustKey) (VerifiedSourceSnapshot, error) {
	if service == nil || ctx == nil || !sourceConfigurationContainsKey(service.options.sourceConfiguration, key) {
		return VerifiedSourceSnapshot{}, ErrInvalidSourceConfiguration
	}
	if err := ctx.Err(); err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	now := service.now().UTC()
	root, err := service.fetchRoot(ctx, key, now)
	if err != nil {
		return VerifiedSourceSnapshot{}, fmt.Errorf("%w: %w", ErrReleaseTrustVerification, err)
	}
	policy, err := service.fetchPolicy(ctx, key, root, now)
	if err != nil {
		return VerifiedSourceSnapshot{}, fmt.Errorf("%w: %w", ErrReleaseTrustVerification, err)
	}
	revocation, err := service.fetchRevocation(ctx, key, root, policy, now)
	if err != nil {
		return VerifiedSourceSnapshot{}, fmt.Errorf("%w: %w", ErrReleaseTrustVerification, err)
	}
	return VerifiedSourceSnapshot{key: key, root: root, policy: policy, revocation: revocation, verifiedAt: now, service: service}, nil
}

func (service *ReleaseTrustService) fetchRoot(ctx context.Context, key SourceTrustKey, now time.Time) (releasecontract.RootDelegationV1, error) {
	request, err := fixedReleaseDocumentRequest(service.options.sourceConfiguration, key, ReleaseDocumentRootDelegation)
	if err != nil {
		return releasecontract.RootDelegationV1{}, err
	}
	raw, err := service.fetchReleaseDocument(ctx, request)
	if err != nil {
		return releasecontract.RootDelegationV1{}, err
	}
	document, err := releasecontract.DecodeRootDelegation(raw)
	if err != nil || document.SourceID != key.sourceID {
		return releasecontract.RootDelegationV1{}, ErrReleaseTrustVerification
	}
	verifier := releasecontract.Ed25519PublicKeyVerifier{
		service.options.rootAnchor.keyID: ed25519.PublicKey(service.options.rootAnchor.PublicKey()),
	}
	if err := releasecontract.VerifyRootDelegation(document, verifier); err != nil {
		return releasecontract.RootDelegationV1{}, err
	}
	if err := validateDocumentWindow(document.GeneratedAt, document.ExpiresAt, now, releasecontract.DefaultSourcePolicyLimits().FutureSkewSeconds); err != nil {
		return releasecontract.RootDelegationV1{}, err
	}
	return document, nil
}

func (service *ReleaseTrustService) fetchPolicy(ctx context.Context, key SourceTrustKey, root releasecontract.RootDelegationV1, now time.Time) (releasecontract.SourcePolicyV3, error) {
	pointerRequest, err := fixedReleaseDocumentRequest(service.options.sourceConfiguration, key, ReleaseDocumentSourcePolicyPointer)
	if err != nil {
		return releasecontract.SourcePolicyV3{}, err
	}
	pointerRaw, err := service.fetchReleaseDocument(ctx, pointerRequest)
	if err != nil {
		return releasecontract.SourcePolicyV3{}, err
	}
	pointer, err := releasecontract.DecodeSourcePolicyPointer(pointerRaw)
	if err != nil || pointer.SourceID != key.sourceID || pointer.Channel != key.channel {
		return releasecontract.SourcePolicyV3{}, ErrReleaseTrustVerification
	}
	verifier, err := delegatedVerifier(root, releasecontract.DelegatedKeyUsageSourcePolicyPointer, key.channel, now, []string{pointer.KeyID})
	if err != nil || releasecontract.VerifySourcePolicyPointer(pointer, verifier) != nil {
		return releasecontract.SourcePolicyV3{}, ErrReleaseTrustVerification
	}
	if err := validateDocumentWindow(pointer.GeneratedAt, pointer.ExpiresAt, now, releasecontract.DefaultSourcePolicyLimits().FutureSkewSeconds); err != nil {
		return releasecontract.SourcePolicyV3{}, err
	}
	request, err := releaseDocumentRequestForSignedRef(key, ReleaseDocumentSourcePolicy, pointer.Ref)
	if err != nil {
		return releasecontract.SourcePolicyV3{}, err
	}
	raw, err := service.fetchReleaseDocument(ctx, request)
	if err != nil || digestHex(raw) != pointer.DocumentSHA256 {
		return releasecontract.SourcePolicyV3{}, ErrReleaseTrustVerification
	}
	document, err := releasecontract.DecodeSourcePolicy(raw)
	if err != nil || document.SourceID != key.sourceID || document.Channel != key.channel || document.Epoch != pointer.Epoch || document.RootEpoch != root.RootEpoch {
		return releasecontract.SourcePolicyV3{}, ErrReleaseTrustVerification
	}
	verifier, err = delegatedVerifier(root, releasecontract.DelegatedKeyUsageSourcePolicy, key.channel, now, []string{document.KeyID})
	if err != nil || releasecontract.VerifySourcePolicy(document, verifier) != nil {
		return releasecontract.SourcePolicyV3{}, ErrReleaseTrustVerification
	}
	if err := validateDocumentWindow(document.GeneratedAt, document.ExpiresAt, now, document.Limits.FutureSkewSeconds); err != nil {
		return releasecontract.SourcePolicyV3{}, err
	}
	return document, nil
}

func (service *ReleaseTrustService) fetchRevocation(ctx context.Context, key SourceTrustKey, root releasecontract.RootDelegationV1, policy releasecontract.SourcePolicyV3, now time.Time) (releasecontract.RevocationV3, error) {
	pointerRequest, err := fixedReleaseDocumentRequest(service.options.sourceConfiguration, key, ReleaseDocumentRevocationPointer)
	if err != nil {
		return releasecontract.RevocationV3{}, err
	}
	pointerRaw, err := service.fetchReleaseDocument(ctx, pointerRequest)
	if err != nil {
		return releasecontract.RevocationV3{}, err
	}
	pointer, err := releasecontract.DecodeRevocationPointer(pointerRaw)
	if err != nil || pointer.SourceID != key.sourceID || pointer.Channel != key.channel || !slices.Contains(policy.ActiveKeys.RevocationPointer, pointer.KeyID) {
		return releasecontract.RevocationV3{}, ErrReleaseTrustVerification
	}
	verifier, err := delegatedVerifier(root, releasecontract.DelegatedKeyUsageRevocationPointer, key.channel, now, []string{pointer.KeyID})
	if err != nil || releasecontract.VerifyRevocationPointer(pointer, verifier) != nil {
		return releasecontract.RevocationV3{}, ErrReleaseTrustVerification
	}
	if err := validateDocumentWindow(pointer.GeneratedAt, pointer.ExpiresAt, now, policy.Limits.FutureSkewSeconds); err != nil {
		return releasecontract.RevocationV3{}, err
	}
	request, err := releaseDocumentRequestForSignedRef(key, ReleaseDocumentRevocation, pointer.Ref)
	if err != nil {
		return releasecontract.RevocationV3{}, err
	}
	raw, err := service.fetchReleaseDocument(ctx, request)
	if err != nil || digestHex(raw) != pointer.DocumentSHA256 {
		return releasecontract.RevocationV3{}, ErrReleaseTrustVerification
	}
	document, err := releasecontract.DecodeRevocation(raw)
	if err != nil || document.SourceID != key.sourceID || document.Channel != key.channel || document.Epoch != pointer.Epoch || document.RootEpoch != root.RootEpoch || !slices.Contains(policy.ActiveKeys.Revocation, document.KeyID) {
		return releasecontract.RevocationV3{}, ErrReleaseTrustVerification
	}
	verifier, err = delegatedVerifier(root, releasecontract.DelegatedKeyUsageRevocation, key.channel, now, []string{document.KeyID})
	if err != nil || releasecontract.VerifyRevocation(document, verifier) != nil {
		return releasecontract.RevocationV3{}, ErrReleaseTrustVerification
	}
	if err := validateDocumentWindow(document.GeneratedAt, document.ExpiresAt, now, policy.Limits.FutureSkewSeconds); err != nil {
		return releasecontract.RevocationV3{}, err
	}
	return document, nil
}

func (service *ReleaseTrustService) fetchReleaseDocument(ctx context.Context, request ReleaseDocumentRequest) ([]byte, error) {
	result, err := service.adapters.Documents.FetchReleaseDocument(ctx, request)
	if err != nil {
		return nil, err
	}
	return result.bytesFor(request)
}

func validateDocumentWindow(generatedAt, expiresAt string, now time.Time, futureSkewSeconds int) error {
	generated, err := parseCanonicalTime(generatedAt)
	if err != nil || generated.After(now.Add(time.Duration(futureSkewSeconds)*time.Second)) {
		return ErrReleaseTrustVerification
	}
	expires, err := parseCanonicalTime(expiresAt)
	if err != nil {
		return ErrReleaseTrustVerification
	}
	if !expires.After(now) {
		return ErrReleaseTrustExpired
	}
	return nil
}

func delegatedVerifier(root releasecontract.RootDelegationV1, usage releasecontract.DelegatedKeyUsage, channel string, now time.Time, keyIDs []string) (releasecontract.Ed25519PublicKeyVerifier, error) {
	verifier := make(releasecontract.Ed25519PublicKeyVerifier, len(keyIDs))
	for _, keyID := range keyIDs {
		key, err := delegatedKey(root, keyID, usage, channel, now)
		if err != nil {
			return nil, err
		}
		publicKey, err := decodeDelegatedPublicKey(key.PublicKey)
		if err != nil {
			return nil, err
		}
		verifier[keyID] = publicKey
	}
	return verifier, nil
}

func delegatedKey(root releasecontract.RootDelegationV1, keyID string, usage releasecontract.DelegatedKeyUsage, channel string, now time.Time) (releasecontract.RootDelegatedKey, error) {
	for _, key := range root.DelegatedKeys {
		if key.KeyID != keyID || !slices.Contains(key.Usages, usage) {
			continue
		}
		if channel == "" {
			if len(key.Channels) != 0 {
				continue
			}
		} else if !slices.Contains(key.Channels, channel) {
			continue
		}
		validFrom, fromErr := parseCanonicalTime(key.ValidFrom)
		validUntil, untilErr := parseCanonicalTime(key.ValidUntil)
		if fromErr != nil || untilErr != nil || now.Before(validFrom) || !now.Before(validUntil) {
			continue
		}
		return key, nil
	}
	return releasecontract.RootDelegatedKey{}, ErrReleaseTrustVerification
}

func decodeDelegatedPublicKey(encoded string) (ed25519.PublicKey, error) {
	value, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(value) != ed25519.PublicKeySize {
		return nil, ErrReleaseTrustVerification
	}
	return ed25519.PublicKey(value), nil
}
