package releasetrust

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

type verifiedReleaseDocumentSet struct {
	root                    releasecontract.RootDelegationV1
	rootBytes               []byte
	policyPointer           releasecontract.SourcePolicyPointerV1
	policyPointerBytes      []byte
	policyPointerToken      string
	policy                  releasecontract.SourcePolicyV2
	policyBytes             []byte
	policyToken             string
	revocationPointer       releasecontract.RevocationPointerV1
	revocationPointerBytes  []byte
	revocationPointerToken  string
	revocation              releasecontract.RevocationV2
	revocationBytes         []byte
	revocationToken         string
	trustedTime             VerifiedTrustedTime
	trustedTimeEvidence     []byte
	ledgerCheckpoint        releasecontract.SigningLedgerCheckpointV1
	ledgerCheckpointSHA256  string
	ledgerEvidenceSHA256Set []string
}

func (service *ReleaseTrustService) RefreshSource(ctx context.Context, key SourceTrustKey) (VerifiedSourceSnapshot, error) {
	if service == nil || ctx == nil || !sourceConfigurationContainsKey(service.options.sourceConfiguration, key) {
		return VerifiedSourceSnapshot{}, ErrInvalidSourceConfiguration
	}
	service.refreshMu.Lock()
	defer service.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	return service.refreshSourceLocked(ctx, key)
}

func (service *ReleaseTrustService) refreshSourceLocked(ctx context.Context, key SourceTrustKey) (VerifiedSourceSnapshot, error) {
	current, currentSHA256, err := service.loadAndRecover(ctx)
	if err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	current, currentSHA256, err = service.reconcileSourceFenceLocked(ctx, key, current, currentSHA256)
	if err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	documents, err := service.verifyReleaseDocumentSet(ctx, key, current)
	if err != nil {
		return VerifiedSourceSnapshot{}, fmt.Errorf("%w: %v", ErrReleaseTrustVerification, err)
	}
	return service.commitVerifiedDocumentSetLocked(ctx, key, current, currentSHA256, documents)
}

func (service *ReleaseTrustService) commitVerifiedDocumentSetLocked(
	ctx context.Context,
	key SourceTrustKey,
	current ReleaseTrustStateV1,
	currentSHA256 string,
	documents verifiedReleaseDocumentSet,
) (VerifiedSourceSnapshot, error) {
	var err error
	current, currentSHA256, err = service.fenceTrustAdvanceLocked(ctx, key, current, currentSHA256, documents)
	if err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	next := nextReleaseTrustState(current, key, documents)
	evidenceSHA256 := digestRefreshEvidence(documents)
	_, nextSHA256, err := service.commitState(ctx, current, currentSHA256, next, evidenceSHA256)
	if err != nil {
		return VerifiedSourceSnapshot{}, err
	}
	snapshot := VerifiedSourceSnapshot{
		key: key, root: documents.root, policy: documents.policy, revocation: documents.revocation,
		trustedFloor: documents.trustedTime.floor, stateSHA256: nextSHA256,
		processInstanceID: service.processInstanceID, refreshedElapsed: service.elapsedNow(),
	}
	service.mu.Lock()
	service.verified[key] = cloneVerifiedSourceSnapshot(snapshot)
	service.live[key] = releaseTrustLiveAnchor{
		processInstanceID: service.processInstanceID, stateSHA256: nextSHA256,
		floor: documents.trustedTime.floor, observedAt: service.now(),
	}
	service.mu.Unlock()
	return cloneVerifiedSourceSnapshot(snapshot), nil
}

func (service *ReleaseTrustService) CurrentVerifiedSource(key SourceTrustKey) (VerifiedSourceSnapshot, bool) {
	if service == nil || !key.valid() {
		return VerifiedSourceSnapshot{}, false
	}
	service.mu.RLock()
	snapshot, ok := service.verified[key]
	service.mu.RUnlock()
	if !ok || snapshot.processInstanceID != service.processInstanceID {
		return VerifiedSourceSnapshot{}, false
	}
	return cloneVerifiedSourceSnapshot(snapshot), true
}

func (service *ReleaseTrustService) verifyReleaseDocumentSet(
	ctx context.Context,
	key SourceTrustKey,
	current ReleaseTrustStateV1,
) (verifiedReleaseDocumentSet, error) {
	rootRequest, err := fixedReleaseDocumentRequest(service.options.sourceConfiguration, key, ReleaseDocumentRootDelegation)
	if err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	rootBytes, _, err := service.fetchReleaseDocument(ctx, rootRequest)
	if err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	root, err := releasecontract.DecodeRootDelegation(rootBytes)
	if err != nil || root.SourceID != key.sourceID {
		return verifiedReleaseDocumentSet{}, ErrReleaseTrustVerification
	}
	rootVerifier := releasecontract.Ed25519PublicKeyVerifier{
		service.options.rootAnchor.keyID: ed25519.PublicKey(service.options.rootAnchor.PublicKey()),
	}
	if err := releasecontract.VerifyRootDelegation(root, rootVerifier); err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	rootDigest := digestHex(rootBytes)
	if err := verifyRootAdvance(current.Root, root, rootDigest); err != nil {
		return verifiedReleaseDocumentSet{}, err
	}

	timeRoot, err := service.resolveTransparencyRoot(current, root)
	if err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	verifiedTime, timeEvidence, err := service.observeTrustedTime(ctx, key, current, timeRoot)
	if err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	if err := validateDocumentWindow(root.GeneratedAt, root.ExpiresAt, verifiedTime.floor, releasecontract.DefaultSourcePolicyLimits().FutureSkewSeconds); err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	if err := service.validateTransparencyDelegation(root, timeRoot.logID, verifiedTime.floor); err != nil {
		return verifiedReleaseDocumentSet{}, err
	}

	set := verifiedReleaseDocumentSet{root: root, rootBytes: rootBytes, trustedTime: verifiedTime, trustedTimeEvidence: timeEvidence}
	channelState := findChannelState(current, key.channel)
	policyPointer, policyPointerBytes, policyPointerToken, err := service.fetchAndVerifyPolicyPointer(ctx, key, root, channelState, verifiedTime.floor)
	if err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	set.policyPointer, set.policyPointerBytes, set.policyPointerToken = policyPointer, policyPointerBytes, policyPointerToken

	policy, policyBytes, policyToken, err := service.fetchAndVerifyPolicy(ctx, key, root, policyPointer, verifiedTime.floor)
	if err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	set.policy, set.policyBytes, set.policyToken = policy, policyBytes, policyToken

	revocationPointer, revocationPointerBytes, revocationPointerToken, err := service.fetchAndVerifyRevocationPointer(ctx, key, root, policy, channelState, verifiedTime.floor)
	if err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	set.revocationPointer, set.revocationPointerBytes, set.revocationPointerToken = revocationPointer, revocationPointerBytes, revocationPointerToken
	revocation, revocationBytes, revocationToken, err := service.fetchAndVerifyRevocation(ctx, key, root, policy, revocationPointer, verifiedTime.floor)
	if err != nil {
		return verifiedReleaseDocumentSet{}, err
	}
	set.revocation, set.revocationBytes, set.revocationToken = revocation, revocationBytes, revocationToken

	ledgerDocuments := []struct {
		subject   releasecontract.SigningSubjectV1
		preimage  []byte
		keyID     string
		signature string
	}{
		{rootSigningSubject(root), mustRootPreimage(root), root.KeyID, root.Signature},
		{epochSigningSubject(key, releasecontract.SigningSubjectUsageSourcePolicyPointer, policyPointer.Epoch), mustPolicyPointerPreimage(policyPointer), policyPointer.KeyID, policyPointer.Signature},
		{epochSigningSubject(key, releasecontract.SigningSubjectUsageSourcePolicy, policy.Epoch), mustPolicyPreimage(policy), policy.KeyID, policy.Signature},
		{epochSigningSubject(key, releasecontract.SigningSubjectUsageRevocationPointer, revocationPointer.Epoch), mustRevocationPointerPreimage(revocationPointer), revocationPointer.KeyID, revocationPointer.Signature},
		{epochSigningSubject(key, releasecontract.SigningSubjectUsageRevocation, revocation.Epoch), mustRevocationPreimage(revocation), revocation.KeyID, revocation.Signature},
	}
	for _, document := range ledgerDocuments {
		checkpoint, checkpointSHA256, evidenceSHA256, err := service.verifySigningLedgerEvidence(
			ctx, current, root, document.subject, document.preimage, document.keyID, document.signature, verifiedTime.floor,
		)
		if err != nil {
			return verifiedReleaseDocumentSet{}, err
		}
		if set.ledgerCheckpointSHA256 != "" && set.ledgerCheckpointSHA256 != checkpointSHA256 {
			return verifiedReleaseDocumentSet{}, ErrReleaseTrustRollback
		}
		set.ledgerCheckpoint = checkpoint
		set.ledgerCheckpointSHA256 = checkpointSHA256
		set.ledgerEvidenceSHA256Set = append(set.ledgerEvidenceSHA256Set, evidenceSHA256)
	}
	return set, nil
}

func (service *ReleaseTrustService) fetchReleaseDocument(ctx context.Context, request ReleaseDocumentRequest) ([]byte, string, error) {
	result, err := service.adapters.Documents.FetchReleaseDocument(ctx, request)
	if err != nil {
		return nil, "", err
	}
	raw, err := result.bytesFor(request)
	if err != nil {
		return nil, "", err
	}
	token, err := result.transportTokenFor(request)
	if err != nil {
		return nil, "", err
	}
	return raw, token, nil
}

func (service *ReleaseTrustService) observeTrustedTime(
	ctx context.Context,
	key SourceTrustKey,
	state ReleaseTrustStateV1,
	root TransparencyRoot,
) (VerifiedTrustedTime, []byte, error) {
	minimum := time.Unix(0, 0).UTC()
	var previous *TrustedTimeCheckpointV1
	if state.SchemaVersion != "" {
		parsed, err := parseCanonicalTime(state.TrustedTime.Floor)
		if err != nil {
			return VerifiedTrustedTime{}, nil, ErrInvalidReleaseTrustState
		}
		minimum = parsed
		checkpoint := cloneCheckpoint(state.TrustedTime.Checkpoint)
		previous = &checkpoint
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return VerifiedTrustedTime{}, nil, err
	}
	request, err := newTrustedTimeRequest(key, minimum, root.logID, nonce)
	if err != nil {
		return VerifiedTrustedTime{}, nil, err
	}
	observation, err := service.adapters.TrustedTime.Observe(ctx, request)
	if err != nil {
		return VerifiedTrustedTime{}, nil, err
	}
	verified, err := verifyTrustedTimeObservation(request, observation, root, previous)
	if err != nil {
		return VerifiedTrustedTime{}, nil, err
	}
	return verified, slices.Clone(observation.evidence), nil
}

func (service *ReleaseTrustService) resolveTransparencyRoot(state ReleaseTrustStateV1, root releasecontract.RootDelegationV1) (TransparencyRoot, error) {
	logID := service.options.transparencyRoots[0].logID
	if state.SchemaVersion != "" {
		logID = state.TrustedTime.Checkpoint.LogID
	}
	for _, configured := range service.options.transparencyRoots {
		if configured.logID != logID {
			continue
		}
		if configured.mode == TransparencyRootPinned {
			return cloneTransparencyRoot(configured), nil
		}
		key, err := delegatedKey(root, configured.delegatedKeyID, releasecontract.DelegatedKeyUsageTrustedTime, "", time.Time{})
		if err != nil {
			return TransparencyRoot{}, err
		}
		anchor, err := delegatedTrustAnchor(key)
		if err != nil {
			return TransparencyRoot{}, err
		}
		return NewTransparencyRoot(logID, anchor)
	}
	return TransparencyRoot{}, ErrInvalidTrustAnchor
}

func (service *ReleaseTrustService) validateTransparencyDelegation(root releasecontract.RootDelegationV1, logID string, floor time.Time) error {
	for _, configured := range service.options.transparencyRoots {
		if configured.logID != logID {
			continue
		}
		if configured.mode == TransparencyRootPinned {
			return nil
		}
		_, err := delegatedKey(root, configured.delegatedKeyID, releasecontract.DelegatedKeyUsageTrustedTime, "", floor)
		return err
	}
	return ErrInvalidTrustAnchor
}

func (service *ReleaseTrustService) fetchAndVerifyPolicyPointer(
	ctx context.Context,
	key SourceTrustKey,
	root releasecontract.RootDelegationV1,
	current *ReleaseTrustChannelStateV1,
	floor time.Time,
) (releasecontract.SourcePolicyPointerV1, []byte, string, error) {
	request, err := fixedReleaseDocumentRequest(service.options.sourceConfiguration, key, ReleaseDocumentSourcePolicyPointer)
	if err != nil {
		return releasecontract.SourcePolicyPointerV1{}, nil, "", err
	}
	raw, token, err := service.fetchReleaseDocument(ctx, request)
	if err != nil {
		return releasecontract.SourcePolicyPointerV1{}, nil, "", err
	}
	document, err := releasecontract.DecodeSourcePolicyPointer(raw)
	if err != nil || document.SourceID != key.sourceID || document.Channel != key.channel {
		return releasecontract.SourcePolicyPointerV1{}, nil, "", ErrReleaseTrustVerification
	}
	verifier, err := delegatedVerifier(root, releasecontract.DelegatedKeyUsageSourcePolicyPointer, key.channel, floor, []string{document.KeyID})
	if err != nil || releasecontract.VerifySourcePolicyPointer(document, verifier) != nil {
		return releasecontract.SourcePolicyPointerV1{}, nil, "", ErrReleaseTrustVerification
	}
	if err := validateDocumentWindow(document.GeneratedAt, document.ExpiresAt, floor, releasecontract.DefaultSourcePolicyLimits().FutureSkewSeconds); err != nil {
		return releasecontract.SourcePolicyPointerV1{}, nil, "", err
	}
	digest := digestHex(raw)
	var head *ReleaseTrustDocumentHeadV1
	if current != nil {
		head = current.Policy
	}
	if err := verifyPointerAdvance(head, document.Epoch, document.PreviousEpoch, document.PreviousDocumentSHA256, digest, document.DocumentSHA256); err != nil {
		return releasecontract.SourcePolicyPointerV1{}, nil, "", err
	}
	return document, raw, token, nil
}

func (service *ReleaseTrustService) fetchAndVerifyPolicy(
	ctx context.Context,
	key SourceTrustKey,
	root releasecontract.RootDelegationV1,
	pointer releasecontract.SourcePolicyPointerV1,
	floor time.Time,
) (releasecontract.SourcePolicyV2, []byte, string, error) {
	request, err := releaseDocumentRequestForSignedRef(key, ReleaseDocumentSourcePolicy, pointer.Ref)
	if err != nil {
		return releasecontract.SourcePolicyV2{}, nil, "", err
	}
	raw, token, err := service.fetchReleaseDocument(ctx, request)
	if err != nil {
		return releasecontract.SourcePolicyV2{}, nil, "", err
	}
	if digestHex(raw) != pointer.DocumentSHA256 {
		return releasecontract.SourcePolicyV2{}, nil, "", ErrReleaseTrustVerification
	}
	document, err := releasecontract.DecodeSourcePolicy(raw)
	if err != nil || document.SourceID != key.sourceID || document.Channel != key.channel || document.Epoch != pointer.Epoch ||
		document.PreviousEpoch != pointer.PreviousEpoch || document.PreviousDocumentSHA256 != pointer.PreviousDocumentSHA256 || document.RootEpoch != root.RootEpoch {
		return releasecontract.SourcePolicyV2{}, nil, "", ErrReleaseTrustVerification
	}
	verifier, err := delegatedVerifier(root, releasecontract.DelegatedKeyUsageSourcePolicy, key.channel, floor, []string{document.KeyID})
	if err != nil || releasecontract.VerifySourcePolicy(document, verifier) != nil {
		return releasecontract.SourcePolicyV2{}, nil, "", ErrReleaseTrustVerification
	}
	if err := validateDocumentWindow(document.GeneratedAt, document.ExpiresAt, floor, document.Limits.FutureSkewSeconds); err != nil {
		return releasecontract.SourcePolicyV2{}, nil, "", err
	}
	return document, raw, token, nil
}

func (service *ReleaseTrustService) fetchAndVerifyRevocationPointer(
	ctx context.Context,
	key SourceTrustKey,
	root releasecontract.RootDelegationV1,
	policy releasecontract.SourcePolicyV2,
	current *ReleaseTrustChannelStateV1,
	floor time.Time,
) (releasecontract.RevocationPointerV1, []byte, string, error) {
	request, err := fixedReleaseDocumentRequest(service.options.sourceConfiguration, key, ReleaseDocumentRevocationPointer)
	if err != nil {
		return releasecontract.RevocationPointerV1{}, nil, "", err
	}
	raw, token, err := service.fetchReleaseDocument(ctx, request)
	if err != nil {
		return releasecontract.RevocationPointerV1{}, nil, "", err
	}
	document, err := releasecontract.DecodeRevocationPointer(raw)
	if err != nil || document.SourceID != key.sourceID || document.Channel != key.channel || !slices.Contains(policy.ActiveKeys.RevocationPointer, document.KeyID) {
		return releasecontract.RevocationPointerV1{}, nil, "", ErrReleaseTrustVerification
	}
	verifier, err := delegatedVerifier(root, releasecontract.DelegatedKeyUsageRevocationPointer, key.channel, floor, []string{document.KeyID})
	if err != nil || releasecontract.VerifyRevocationPointer(document, verifier) != nil {
		return releasecontract.RevocationPointerV1{}, nil, "", ErrReleaseTrustVerification
	}
	if err := validateDocumentWindow(document.GeneratedAt, document.ExpiresAt, floor, policy.Limits.FutureSkewSeconds); err != nil {
		return releasecontract.RevocationPointerV1{}, nil, "", err
	}
	digest := digestHex(raw)
	var head *ReleaseTrustDocumentHeadV1
	if current != nil {
		head = current.Revocation
	}
	if err := verifyPointerAdvance(head, document.Epoch, document.PreviousEpoch, document.PreviousDocumentSHA256, digest, document.DocumentSHA256); err != nil {
		return releasecontract.RevocationPointerV1{}, nil, "", err
	}
	return document, raw, token, nil
}

func (service *ReleaseTrustService) fetchAndVerifyRevocation(
	ctx context.Context,
	key SourceTrustKey,
	root releasecontract.RootDelegationV1,
	policy releasecontract.SourcePolicyV2,
	pointer releasecontract.RevocationPointerV1,
	floor time.Time,
) (releasecontract.RevocationV2, []byte, string, error) {
	request, err := releaseDocumentRequestForSignedRef(key, ReleaseDocumentRevocation, pointer.Ref)
	if err != nil {
		return releasecontract.RevocationV2{}, nil, "", err
	}
	raw, token, err := service.fetchReleaseDocument(ctx, request)
	if err != nil {
		return releasecontract.RevocationV2{}, nil, "", err
	}
	if digestHex(raw) != pointer.DocumentSHA256 {
		return releasecontract.RevocationV2{}, nil, "", ErrReleaseTrustVerification
	}
	document, err := releasecontract.DecodeRevocation(raw)
	if err != nil || document.SourceID != key.sourceID || document.Channel != key.channel || document.Epoch != pointer.Epoch ||
		document.PreviousEpoch != pointer.PreviousEpoch || document.PreviousDocumentSHA256 != pointer.PreviousDocumentSHA256 ||
		document.RootEpoch != root.RootEpoch || !slices.Contains(policy.ActiveKeys.Revocation, document.KeyID) {
		return releasecontract.RevocationV2{}, nil, "", ErrReleaseTrustVerification
	}
	verifier, err := delegatedVerifier(root, releasecontract.DelegatedKeyUsageRevocation, key.channel, floor, []string{document.KeyID})
	if err != nil || releasecontract.VerifyRevocation(document, verifier) != nil {
		return releasecontract.RevocationV2{}, nil, "", ErrReleaseTrustVerification
	}
	if err := validateDocumentWindow(document.GeneratedAt, document.ExpiresAt, floor, policy.Limits.FutureSkewSeconds); err != nil {
		return releasecontract.RevocationV2{}, nil, "", err
	}
	if compareEpoch(document.Epoch, policy.MinimumRevocationEpoch) < 0 {
		return releasecontract.RevocationV2{}, nil, "", ErrReleaseTrustRollback
	}
	return document, raw, token, nil
}

func nextReleaseTrustState(current ReleaseTrustStateV1, key SourceTrustKey, documents verifiedReleaseDocumentSet) ReleaseTrustStateV1 {
	next := cloneReleaseTrustState(current)
	if next.SchemaVersion == "" {
		next = ReleaseTrustStateV1{SchemaVersion: ReleaseTrustStateSchemaVersion, SourceID: key.sourceID, Revision: 1, Channels: []ReleaseTrustChannelStateV1{}}
	} else {
		next.Revision++
	}
	next.Root = &ReleaseTrustRootHeadV1{
		Epoch: documents.root.RootEpoch, DocumentSHA256: digestHex(documents.rootBytes), GeneratedAt: documents.root.GeneratedAt,
		ExpiresAt: documents.root.ExpiresAt, KeyID: documents.root.KeyID,
	}
	next.TrustedTime = ReleaseTrustedTimeStateV1{
		Floor: documents.trustedTime.floor.Format(time.RFC3339Nano), CheckpointSHA256: documents.trustedTime.checkpointSHA256,
		Checkpoint: cloneCheckpoint(documents.trustedTime.checkpoint),
	}
	next.SigningLedger = &ReleaseSigningLedgerStateV1{
		CheckpointSHA256: documents.ledgerCheckpointSHA256, Checkpoint: documents.ledgerCheckpoint,
	}
	channel := ReleaseTrustChannelStateV1{
		Channel: key.channel,
		Policy: &ReleaseTrustDocumentHeadV1{
			PointerLocator: fixedLocatorValue(key, "policy/current.json"), PointerTransportToken: documents.policyPointerToken,
			PointerEpoch: documents.policyPointer.Epoch, PointerSHA256: digestHex(documents.policyPointerBytes),
			DocumentLocator: documents.policyPointer.Ref, DocumentTransportToken: documents.policyToken,
			DocumentSHA256: digestHex(documents.policyBytes), GeneratedAt: documents.policy.GeneratedAt,
			ExpiresAt: documents.policy.ExpiresAt, KeyID: documents.policy.KeyID,
		},
		Revocation: &ReleaseTrustDocumentHeadV1{
			PointerLocator: fixedLocatorValue(key, "revocation/current.json"), PointerTransportToken: documents.revocationPointerToken,
			PointerEpoch: documents.revocationPointer.Epoch, PointerSHA256: digestHex(documents.revocationPointerBytes),
			DocumentLocator: documents.revocationPointer.Ref, DocumentTransportToken: documents.revocationToken,
			DocumentSHA256: digestHex(documents.revocationBytes), GeneratedAt: documents.revocation.GeneratedAt,
			ExpiresAt: documents.revocation.ExpiresAt, KeyID: documents.revocation.KeyID,
		},
	}
	index, found := slices.BinarySearchFunc(next.Channels, key.channel, func(value ReleaseTrustChannelStateV1, channel string) int {
		if value.Channel < channel {
			return -1
		}
		if value.Channel > channel {
			return 1
		}
		return 0
	})
	if found {
		channel.FenceGeneration = next.Channels[index].FenceGeneration
		channel.Fence = next.Channels[index].Fence
		next.Channels[index] = channel
	} else {
		next.Channels = append(next.Channels, ReleaseTrustChannelStateV1{})
		copy(next.Channels[index+1:], next.Channels[index:])
		next.Channels[index] = channel
	}
	return next
}

func fixedLocatorValue(key SourceTrustKey, suffix string) string {
	return "sources/" + key.sourceID + "/" + key.channel + "/" + suffix
}

func digestRefreshEvidence(documents verifiedReleaseDocumentSet) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("redevplugin.release-trust-refresh-evidence.v1\x00"))
	for _, value := range [][]byte{
		documents.rootBytes, documents.trustedTimeEvidence, documents.policyPointerBytes, documents.policyBytes,
		documents.revocationPointerBytes, documents.revocationBytes,
	} {
		_ = binary.Write(hasher, binary.BigEndian, uint64(len(value)))
		_, _ = hasher.Write(value)
	}
	for _, digest := range documents.ledgerEvidenceSHA256Set {
		_ = binary.Write(hasher, binary.BigEndian, uint64(len(digest)))
		_, _ = hasher.Write([]byte(digest))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func findChannelState(state ReleaseTrustStateV1, channel string) *ReleaseTrustChannelStateV1 {
	index, found := slices.BinarySearchFunc(state.Channels, channel, func(value ReleaseTrustChannelStateV1, target string) int {
		if value.Channel < target {
			return -1
		}
		if value.Channel > target {
			return 1
		}
		return 0
	})
	if !found {
		return nil
	}
	value := state.Channels[index]
	return &value
}

func verifyRootAdvance(previous *ReleaseTrustRootHeadV1, current releasecontract.RootDelegationV1, digest string) error {
	if previous == nil {
		if current.RootEpoch != "1" || current.PreviousRootEpoch != releasecontract.GenesisPreviousEpoch ||
			current.PreviousDelegationSHA256 != releasecontract.GenesisPreviousDocumentSHA256 {
			return ErrReleaseTrustRollback
		}
		return nil
	}
	if current.RootEpoch == previous.Epoch && digest == previous.DocumentSHA256 {
		return nil
	}
	if !nextEpoch(previous.Epoch, current.RootEpoch) || current.PreviousRootEpoch != previous.Epoch || current.PreviousDelegationSHA256 != previous.DocumentSHA256 {
		return ErrReleaseTrustRollback
	}
	return nil
}

func verifyPointerAdvance(previous *ReleaseTrustDocumentHeadV1, epoch, previousEpoch, previousDocumentSHA256, pointerSHA256, documentSHA256 string) error {
	if previous == nil {
		if epoch != "1" || previousEpoch != releasecontract.GenesisPreviousEpoch || previousDocumentSHA256 != releasecontract.GenesisPreviousDocumentSHA256 {
			return ErrReleaseTrustRollback
		}
		return nil
	}
	if epoch == previous.PointerEpoch && pointerSHA256 == previous.PointerSHA256 && documentSHA256 == previous.DocumentSHA256 {
		return nil
	}
	if !nextEpoch(previous.PointerEpoch, epoch) || previousEpoch != previous.PointerEpoch || previousDocumentSHA256 != previous.DocumentSHA256 {
		return ErrReleaseTrustRollback
	}
	return nil
}

func nextEpoch(previous, current string) bool {
	left, leftOK := new(big.Int).SetString(previous, 10)
	right, rightOK := new(big.Int).SetString(current, 10)
	return leftOK && rightOK && right.Cmp(new(big.Int).Add(left, big.NewInt(1))) == 0
}

func compareEpoch(left, right string) int {
	leftValue, leftOK := new(big.Int).SetString(left, 10)
	rightValue, rightOK := new(big.Int).SetString(right, 10)
	if !leftOK || !rightOK {
		return -1
	}
	return leftValue.Cmp(rightValue)
}

func validateDocumentWindow(generatedAt, expiresAt string, floor time.Time, futureSkewSeconds int) error {
	generated, err := parseCanonicalTime(generatedAt)
	if err != nil {
		return ErrReleaseTrustVerification
	}
	expires, err := parseCanonicalTime(expiresAt)
	if err != nil {
		return ErrReleaseTrustVerification
	}
	if generated.After(floor.Add(time.Duration(futureSkewSeconds) * time.Second)) {
		return ErrReleaseTrustVerification
	}
	if !expires.After(floor) {
		return ErrReleaseTrustExpired
	}
	return nil
}

func delegatedVerifier(
	root releasecontract.RootDelegationV1,
	usage releasecontract.DelegatedKeyUsage,
	channel string,
	floor time.Time,
	keyIDs []string,
) (releasecontract.Ed25519PublicKeyVerifier, error) {
	verifier := make(releasecontract.Ed25519PublicKeyVerifier, len(keyIDs))
	for _, keyID := range keyIDs {
		key, err := delegatedKey(root, keyID, usage, channel, floor)
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

func delegatedKey(root releasecontract.RootDelegationV1, keyID string, usage releasecontract.DelegatedKeyUsage, channel string, floor time.Time) (releasecontract.RootDelegatedKey, error) {
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
		if !floor.IsZero() {
			validFrom, fromErr := parseCanonicalTime(key.ValidFrom)
			validUntil, untilErr := parseCanonicalTime(key.ValidUntil)
			if fromErr != nil || untilErr != nil || floor.Before(validFrom) || !floor.Before(validUntil) {
				continue
			}
		}
		return key, nil
	}
	return releasecontract.RootDelegatedKey{}, ErrReleaseTrustVerification
}

func delegatedTrustAnchor(key releasecontract.RootDelegatedKey) (TrustAnchor, error) {
	publicKey, err := decodeDelegatedPublicKey(key.PublicKey)
	if err != nil {
		return TrustAnchor{}, err
	}
	return NewEd25519TrustAnchor(key.KeyID, publicKey)
}

func decodeDelegatedPublicKey(encoded string) (ed25519.PublicKey, error) {
	value, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(value) != ed25519.PublicKeySize {
		return nil, ErrReleaseTrustVerification
	}
	return ed25519.PublicKey(value), nil
}

func rootSigningSubject(value releasecontract.RootDelegationV1) releasecontract.SigningSubjectV1 {
	return releasecontract.SigningSubjectV1{
		SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: releasecontract.SigningSubjectUsageRootDelegation,
		SourceID: value.SourceID, RootEpoch: value.RootEpoch,
	}
}

func epochSigningSubject(key SourceTrustKey, usage releasecontract.SigningSubjectUsage, epoch string) releasecontract.SigningSubjectV1 {
	return releasecontract.SigningSubjectV1{
		SchemaVersion: releasecontract.SigningSubjectSchemaVersion, Usage: usage,
		SourceID: key.sourceID, Channel: key.channel, Epoch: epoch,
	}
}

func mustRootPreimage(value releasecontract.RootDelegationV1) []byte {
	preimage, _ := releasecontract.RootDelegationSigningPreimage(releasecontract.RootDelegationInput{
		SourceID: value.SourceID, RootEpoch: value.RootEpoch, PreviousRootEpoch: value.PreviousRootEpoch,
		PreviousDelegationSHA256: value.PreviousDelegationSHA256, GeneratedAt: value.GeneratedAt, ExpiresAt: value.ExpiresAt,
		DelegatedKeys: cloneRootDelegatedKeys(value.DelegatedKeys), KeyID: value.KeyID,
	})
	return preimage
}

func mustPolicyPointerPreimage(value releasecontract.SourcePolicyPointerV1) []byte {
	preimage, _ := releasecontract.SourcePolicyPointerSigningPreimage(releasecontract.ReleasePointerInput{
		SourceID: value.SourceID, Channel: value.Channel, Epoch: value.Epoch, PreviousEpoch: value.PreviousEpoch,
		PreviousDocumentSHA256: value.PreviousDocumentSHA256, Ref: value.Ref, DocumentSHA256: value.DocumentSHA256,
		GeneratedAt: value.GeneratedAt, ExpiresAt: value.ExpiresAt, KeyID: value.KeyID,
	})
	return preimage
}

func mustPolicyPreimage(value releasecontract.SourcePolicyV2) []byte {
	preimage, _ := releasecontract.SourcePolicySigningPreimage(releasecontract.SourcePolicyInput{
		SourceID: value.SourceID, Channel: value.Channel, Epoch: value.Epoch, PreviousEpoch: value.PreviousEpoch,
		PreviousDocumentSHA256: value.PreviousDocumentSHA256, RootEpoch: value.RootEpoch, SourceType: value.SourceType,
		SourceClass: value.SourceClass, AllowedPublishers: slices.Clone(value.AllowedPublishers), AllowedArtifactHosts: slices.Clone(value.AllowedArtifactHosts),
		ActiveKeys: value.ActiveKeys, CapabilityPublisherScopes: slices.Clone(value.CapabilityPublisherScopes), RequireSignature: value.RequireSignature, InstallPolicy: value.InstallPolicy,
		UnsignedPolicy: value.UnsignedPolicy, DowngradePolicy: value.DowngradePolicy, MinimumRevocationEpoch: value.MinimumRevocationEpoch,
		Limits: value.Limits, GeneratedAt: value.GeneratedAt, ExpiresAt: value.ExpiresAt, KeyID: value.KeyID,
	})
	return preimage
}

func mustRevocationPointerPreimage(value releasecontract.RevocationPointerV1) []byte {
	preimage, _ := releasecontract.RevocationPointerSigningPreimage(releasecontract.ReleasePointerInput{
		SourceID: value.SourceID, Channel: value.Channel, Epoch: value.Epoch, PreviousEpoch: value.PreviousEpoch,
		PreviousDocumentSHA256: value.PreviousDocumentSHA256, Ref: value.Ref, DocumentSHA256: value.DocumentSHA256,
		GeneratedAt: value.GeneratedAt, ExpiresAt: value.ExpiresAt, KeyID: value.KeyID,
	})
	return preimage
}

func mustRevocationPreimage(value releasecontract.RevocationV2) []byte {
	preimage, _ := releasecontract.RevocationSigningPreimage(releasecontract.RevocationInput{
		SourceID: value.SourceID, Channel: value.Channel, Epoch: value.Epoch, PreviousEpoch: value.PreviousEpoch,
		PreviousDocumentSHA256: value.PreviousDocumentSHA256, RootEpoch: value.RootEpoch,
		GeneratedAt: value.GeneratedAt, ExpiresAt: value.ExpiresAt, RevokedKeyIDs: slices.Clone(value.RevokedKeyIDs),
		RevokedReleases: slices.Clone(value.RevokedReleases), KeyID: value.KeyID,
	})
	return preimage
}

func decodeEnvelopeSignature(encoded string) ([]byte, error) {
	value, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(value) != ed25519.SignatureSize {
		return nil, ErrReleaseTrustVerification
	}
	return value, nil
}

func (service *ReleaseTrustService) verifySigningLedgerEvidence(
	ctx context.Context,
	state ReleaseTrustStateV1,
	root releasecontract.RootDelegationV1,
	subject releasecontract.SigningSubjectV1,
	preimage []byte,
	keyID string,
	encodedSignature string,
	floor time.Time,
) (releasecontract.SigningLedgerCheckpointV1, string, string, error) {
	subjectDigest, err := releasecontract.SigningSubjectIdentitySHA256(subject)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	signature, err := decodeEnvelopeSignature(encodedSignature)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	preimageDigest := sha256.Sum256(preimage)
	envelope := releasecontract.SignatureEnvelopeV1{
		SchemaVersion: releasecontract.SigningEnvelopeSchemaVersion, SubjectIdentitySHA256: subjectDigest,
		SigningPreimageSHA256: hex.EncodeToString(preimageDigest[:]), Algorithm: releasecontract.SignatureAlgorithmEd25519,
		KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(signature),
	}
	envelopeBytes, err := releasecontract.CanonicalSignatureEnvelope(envelope)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	if err := verifySubjectSignature(root, subject, preimage, envelope, floor); err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	envelopeSHA256 := digestHex(envelopeBytes)
	scope, err := newSigningLedgerSubjectScope(service.options.sourceConfiguration, subject)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	evidenceRequest, err := fixedSigningLedgerRequest(service.options.sourceConfiguration, scope, SigningLedgerEvidence, subjectDigest, "", "")
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	evidenceBytes, err := service.fetchLedgerArtifact(ctx, evidenceRequest)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	evidence, err := releasecontract.DecodeSigningLedgerEvidence(evidenceBytes)
	if err != nil || evidence.SourceID != subject.SourceID || evidence.Channel != subject.Channel ||
		evidence.SubjectIdentitySHA256 != subjectDigest || evidence.SigningPreimageSHA256 != envelope.SigningPreimageSHA256 ||
		evidence.SignatureEnvelopeSHA256 != envelopeSHA256 {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
	}

	receiptRequest, _ := fixedSigningLedgerRequest(service.options.sourceConfiguration, scope, SigningLedgerReceipt, subjectDigest, "", "")
	checkpointRequest, _ := fixedSigningLedgerRequest(service.options.sourceConfiguration, scope, SigningLedgerCheckpoint, "", "", evidence.CheckpointSHA256)
	inclusionRequest, _ := fixedSigningLedgerRequest(service.options.sourceConfiguration, scope, SigningLedgerInclusionProof, subjectDigest, "", "")
	latestRequest, _ := fixedSigningLedgerRequest(service.options.sourceConfiguration, scope, SigningLedgerLatestProof, subjectDigest, "", "")
	if evidence.ReceiptRef != receiptRequest.locator.String() || evidence.CheckpointRef != checkpointRequest.locator.String() ||
		evidence.InclusionProofRef != inclusionRequest.locator.String() || evidence.LatestProofRef != latestRequest.locator.String() {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
	}
	receiptBytes, err := service.fetchLedgerArtifact(ctx, receiptRequest)
	if err != nil || digestHex(receiptBytes) != evidence.ReceiptSHA256 {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
	}
	checkpointBytes, err := service.fetchLedgerArtifact(ctx, checkpointRequest)
	if err != nil || digestHex(checkpointBytes) != evidence.CheckpointSHA256 {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
	}
	inclusionBytes, err := service.fetchLedgerArtifact(ctx, inclusionRequest)
	if err != nil || digestHex(inclusionBytes) != evidence.InclusionProofSHA256 {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
	}
	latestBytes, err := service.fetchLedgerArtifact(ctx, latestRequest)
	if err != nil || digestHex(latestBytes) != evidence.LatestProofSHA256 {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
	}
	receipt, err := releasecontract.DecodeSigningLedgerReceipt(receiptBytes)
	if err != nil || receipt.SourceID != subject.SourceID || receipt.Channel != subject.Channel ||
		receipt.SubjectIdentitySHA256 != subjectDigest || receipt.SigningPreimageSHA256 != envelope.SigningPreimageSHA256 ||
		receipt.SignatureEnvelopeSHA256 != envelopeSHA256 {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
	}
	checkpoint, err := releasecontract.DecodeSigningLedgerCheckpoint(checkpointBytes)
	if err != nil || checkpoint.LogID != service.options.signingLedgerRoot.logID {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
	}
	inclusion, err := releasecontract.DecodeSigningLedgerInclusionProof(inclusionBytes)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	latest, err := releasecontract.DecodeSigningLedgerLatestProof(latestBytes)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	ledgerVerifier, err := service.signingLedgerVerifier(root, floor, checkpoint.KeyID, receipt.KeyID)
	if err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	if err := releasecontract.VerifySigningLedgerInclusion(receipt, inclusion, checkpoint, ledgerVerifier); err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	if err := releasecontract.VerifySigningLedgerLatest(receipt, latest, checkpoint, ledgerVerifier); err != nil {
		return releasecontract.SigningLedgerCheckpointV1{}, "", "", err
	}
	if state.SigningLedger == nil {
		if evidence.ConsistencyProofRef != "" || evidence.ConsistencyProofSHA256 != "" {
			return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
		}
	} else if state.SigningLedger.CheckpointSHA256 == evidence.CheckpointSHA256 {
		if evidence.ConsistencyProofRef != "" || evidence.ConsistencyProofSHA256 != "" {
			return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
		}
	} else {
		if evidence.ConsistencyProofRef == "" {
			return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustRollback
		}
		consistencyRequest, err := fixedSigningLedgerRequest(
			service.options.sourceConfiguration, scope, SigningLedgerConsistencyProof, "",
			state.SigningLedger.CheckpointSHA256, evidence.CheckpointSHA256,
		)
		if err != nil || evidence.ConsistencyProofRef != consistencyRequest.locator.String() {
			return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
		}
		consistencyBytes, err := service.fetchLedgerArtifact(ctx, consistencyRequest)
		if err != nil || digestHex(consistencyBytes) != evidence.ConsistencyProofSHA256 {
			return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustVerification
		}
		consistency, err := releasecontract.DecodeSigningLedgerConsistencyProof(consistencyBytes)
		if err != nil || releasecontract.VerifySigningLedgerConsistency(state.SigningLedger.Checkpoint, checkpoint, consistency, ledgerVerifier) != nil {
			return releasecontract.SigningLedgerCheckpointV1{}, "", "", ErrReleaseTrustRollback
		}
	}
	return checkpoint, evidence.CheckpointSHA256, digestHex(evidenceBytes), nil
}

func (service *ReleaseTrustService) fetchLedgerArtifact(ctx context.Context, request SigningLedgerRequest) ([]byte, error) {
	result, err := service.adapters.Ledger.FetchSigningLedgerArtifact(ctx, request)
	if err != nil {
		return nil, err
	}
	return result.bytesFor(request)
}

func (service *ReleaseTrustService) signingLedgerVerifier(
	root releasecontract.RootDelegationV1,
	floor time.Time,
	keyIDs ...string,
) (releasecontract.Ed25519PublicKeyVerifier, error) {
	if service.options.signingLedgerRoot.mode == SigningLedgerRootPinned {
		anchor := service.options.signingLedgerRoot.pinnedAnchor
		verifier := releasecontract.Ed25519PublicKeyVerifier{}
		for _, keyID := range keyIDs {
			if keyID != anchor.keyID {
				return nil, ErrReleaseTrustVerification
			}
			verifier[keyID] = ed25519.PublicKey(anchor.PublicKey())
		}
		return verifier, nil
	}
	delegatedID := service.options.signingLedgerRoot.delegatedKeyID
	for _, keyID := range keyIDs {
		if keyID != delegatedID {
			return nil, ErrReleaseTrustVerification
		}
	}
	return delegatedVerifier(root, releasecontract.DelegatedKeyUsageSigningLedger, "", floor, []string{delegatedID})
}

func signingUsageForSubject(usage releasecontract.SigningSubjectUsage) releasecontract.DelegatedKeyUsage {
	switch usage {
	case releasecontract.SigningSubjectUsagePackage:
		return releasecontract.DelegatedKeyUsagePackage
	case releasecontract.SigningSubjectUsageReleaseMetadata:
		return releasecontract.DelegatedKeyUsageReleaseMetadata
	case releasecontract.SigningSubjectUsageSourcePolicy:
		return releasecontract.DelegatedKeyUsageSourcePolicy
	case releasecontract.SigningSubjectUsageSourcePolicyPointer:
		return releasecontract.DelegatedKeyUsageSourcePolicyPointer
	case releasecontract.SigningSubjectUsageRevocation:
		return releasecontract.DelegatedKeyUsageRevocation
	case releasecontract.SigningSubjectUsageRevocationPointer:
		return releasecontract.DelegatedKeyUsageRevocationPointer
	default:
		return ""
	}
}

func verifySubjectSignature(root releasecontract.RootDelegationV1, subject releasecontract.SigningSubjectV1, preimage []byte, envelope releasecontract.SignatureEnvelopeV1, floor time.Time) error {
	if subject.Usage == releasecontract.SigningSubjectUsageRootDelegation {
		return nil
	}
	usage := signingUsageForSubject(subject.Usage)
	if usage == "" {
		return ErrReleaseTrustVerification
	}
	verifier, err := delegatedVerifier(root, usage, subject.Channel, floor, []string{envelope.KeyID})
	if err != nil {
		return err
	}
	return releasecontract.VerifySignatureEnvelope(subject, preimage, envelope, verifier)
}
