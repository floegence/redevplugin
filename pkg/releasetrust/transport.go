package releasetrust

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

var (
	ErrInvalidLocator          = errors.New("release trust locator is invalid")
	ErrInvalidTransportPayload = errors.New("release trust transport payload is invalid")
)

const (
	MaxReleasePointerBytes          int64 = 64 << 10
	MaxReleaseDocumentBytes         int64 = 1 << 20
	MaxSigningLedgerCheckpointBytes int64 = 8 << 10
	MaxSigningLedgerEvidenceBytes   int64 = 64 << 10
)

var (
	locatorPattern = regexp.MustCompile(`^[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type SourceRelativeLocator struct {
	value string
}

func (locator SourceRelativeLocator) String() string { return locator.value }

func newSourceRelativeLocator(value string) (SourceRelativeLocator, error) {
	if len(value) == 0 || len(value) > 1024 || !locatorPattern.MatchString(value) || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsAny(value, "?#") {
		return SourceRelativeLocator{}, fmt.Errorf("%w: %q", ErrInvalidLocator, value)
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return SourceRelativeLocator{}, fmt.Errorf("%w: %q", ErrInvalidLocator, value)
		}
	}
	return SourceRelativeLocator{value: value}, nil
}

type ReleaseDocumentKind string

const (
	ReleaseDocumentRootDelegation      ReleaseDocumentKind = "root_delegation"
	ReleaseDocumentSourcePolicy        ReleaseDocumentKind = "source_policy"
	ReleaseDocumentSourcePolicyPointer ReleaseDocumentKind = "source_policy_pointer"
	ReleaseDocumentRevocation          ReleaseDocumentKind = "revocation"
	ReleaseDocumentRevocationPointer   ReleaseDocumentKind = "revocation_pointer"
)

type ReleaseDocumentRequest struct {
	sourceID string
	channel  string
	kind     ReleaseDocumentKind
	locator  SourceRelativeLocator
	maxBytes int64
}

func (request ReleaseDocumentRequest) SourceID() string               { return request.sourceID }
func (request ReleaseDocumentRequest) Channel() string                { return request.channel }
func (request ReleaseDocumentRequest) Kind() ReleaseDocumentKind      { return request.kind }
func (request ReleaseDocumentRequest) Locator() SourceRelativeLocator { return request.locator }
func (request ReleaseDocumentRequest) MaxBytes() int64                { return request.maxBytes }

type ReleaseDocumentTransport interface {
	FetchReleaseDocument(ctx context.Context, request ReleaseDocumentRequest) (ReleaseDocumentResult, error)
}

type ReleaseDocumentResult struct {
	request        ReleaseDocumentRequest
	transportToken string
	bytes          []byte
}

func NewReleaseDocumentResult(request ReleaseDocumentRequest, transportToken string, value []byte) (ReleaseDocumentResult, error) {
	if !request.valid() || !transportTokenPattern.MatchString(transportToken) || len(value) == 0 || int64(len(value)) > request.maxBytes {
		return ReleaseDocumentResult{}, ErrInvalidTransportPayload
	}
	return ReleaseDocumentResult{request: request, transportToken: transportToken, bytes: append([]byte(nil), value...)}, nil
}

func (result ReleaseDocumentResult) bytesFor(request ReleaseDocumentRequest) ([]byte, error) {
	if result.request != request || len(result.bytes) == 0 || int64(len(result.bytes)) > request.maxBytes {
		return nil, ErrInvalidTransportPayload
	}
	return append([]byte(nil), result.bytes...), nil
}

func (result ReleaseDocumentResult) transportTokenFor(request ReleaseDocumentRequest) (string, error) {
	if result.request != request || !transportTokenPattern.MatchString(result.transportToken) {
		return "", ErrInvalidTransportPayload
	}
	return result.transportToken, nil
}

func (request ReleaseDocumentRequest) valid() bool {
	if !contractIDPattern.MatchString(request.sourceID) || request.locator.value == "" {
		return false
	}
	switch request.kind {
	case ReleaseDocumentRootDelegation:
		return request.channel == "" && request.maxBytes == MaxReleaseDocumentBytes
	case ReleaseDocumentSourcePolicy, ReleaseDocumentRevocation:
		return contractIDPattern.MatchString(request.channel) && request.maxBytes == MaxReleaseDocumentBytes
	case ReleaseDocumentSourcePolicyPointer, ReleaseDocumentRevocationPointer:
		return contractIDPattern.MatchString(request.channel) && request.maxBytes == MaxReleasePointerBytes
	default:
		return false
	}
}

func fixedReleaseDocumentRequest(configuration SourceConfiguration, key SourceTrustKey, kind ReleaseDocumentKind) (ReleaseDocumentRequest, error) {
	if !sourceConfigurationContainsKey(configuration, key) {
		return ReleaseDocumentRequest{}, ErrInvalidSourceConfiguration
	}
	var value string
	var maxBytes int64
	switch kind {
	case ReleaseDocumentRootDelegation:
		value = fmt.Sprintf("sources/%s/root/current.json", key.sourceID)
		maxBytes = MaxReleaseDocumentBytes
	case ReleaseDocumentSourcePolicyPointer:
		value = fmt.Sprintf("sources/%s/%s/policy/current.json", key.sourceID, key.channel)
		maxBytes = MaxReleasePointerBytes
	case ReleaseDocumentRevocationPointer:
		value = fmt.Sprintf("sources/%s/%s/revocation/current.json", key.sourceID, key.channel)
		maxBytes = MaxReleasePointerBytes
	default:
		return ReleaseDocumentRequest{}, ErrInvalidLocator
	}
	locator, err := newSourceRelativeLocator(value)
	if err != nil {
		return ReleaseDocumentRequest{}, err
	}
	channel := key.channel
	if kind == ReleaseDocumentRootDelegation {
		channel = ""
	}
	return ReleaseDocumentRequest{sourceID: key.sourceID, channel: channel, kind: kind, locator: locator, maxBytes: maxBytes}, nil
}

func releaseDocumentRequestForSignedRef(key SourceTrustKey, kind ReleaseDocumentKind, ref string) (ReleaseDocumentRequest, error) {
	if !key.valid() {
		return ReleaseDocumentRequest{}, ErrInvalidSourceConfiguration
	}
	var prefix string
	switch kind {
	case ReleaseDocumentSourcePolicy:
		prefix = fmt.Sprintf("sources/%s/%s/policy/", key.sourceID, key.channel)
	case ReleaseDocumentRevocation:
		prefix = fmt.Sprintf("sources/%s/%s/revocation/", key.sourceID, key.channel)
	default:
		return ReleaseDocumentRequest{}, ErrInvalidLocator
	}
	locator, err := newSourceRelativeLocator(ref)
	if err != nil || !strings.HasPrefix(ref, prefix) || len(ref) == len(prefix) || ref == prefix+"current.json" {
		return ReleaseDocumentRequest{}, fmt.Errorf("%w: signed ref %q is outside %q", ErrInvalidLocator, ref, prefix)
	}
	return ReleaseDocumentRequest{sourceID: key.sourceID, channel: key.channel, kind: kind, locator: locator, maxBytes: MaxReleaseDocumentBytes}, nil
}

type SigningLedgerArtifactKind string

const (
	SigningLedgerCheckpoint       SigningLedgerArtifactKind = "checkpoint"
	SigningLedgerEvidence         SigningLedgerArtifactKind = "evidence"
	SigningLedgerReceipt          SigningLedgerArtifactKind = "receipt"
	SigningLedgerInclusionProof   SigningLedgerArtifactKind = "inclusion_proof"
	SigningLedgerLatestProof      SigningLedgerArtifactKind = "latest_proof"
	SigningLedgerConsistencyProof SigningLedgerArtifactKind = "consistency_proof"
)

type SigningLedgerRequest struct {
	sourceID string
	channel  string
	kind     SigningLedgerArtifactKind
	locator  SourceRelativeLocator
	maxBytes int64
}

type signingLedgerSubjectScope struct {
	sourceID string
	channel  string
}

func newSigningLedgerSubjectScope(configuration SourceConfiguration, subject releasecontract.SigningSubjectV1) (signingLedgerSubjectScope, error) {
	if _, err := releasecontract.CanonicalSigningSubject(subject); err != nil || !configuration.valid() ||
		subject.SourceID != configuration.sourceID {
		return signingLedgerSubjectScope{}, ErrInvalidSourceConfiguration
	}
	if subject.Channel == "" {
		if subject.Usage != releasecontract.SigningSubjectUsageRootDelegation {
			return signingLedgerSubjectScope{}, ErrInvalidSourceConfiguration
		}
		return signingLedgerSubjectScope{sourceID: subject.SourceID}, nil
	}
	if _, err := configuration.TrustKey(subject.Channel); err != nil {
		return signingLedgerSubjectScope{}, ErrInvalidSourceConfiguration
	}
	return signingLedgerSubjectScope{sourceID: subject.SourceID, channel: subject.Channel}, nil
}

func (request SigningLedgerRequest) SourceID() string                { return request.sourceID }
func (request SigningLedgerRequest) Channel() string                 { return request.channel }
func (request SigningLedgerRequest) Kind() SigningLedgerArtifactKind { return request.kind }
func (request SigningLedgerRequest) Locator() SourceRelativeLocator  { return request.locator }
func (request SigningLedgerRequest) MaxBytes() int64                 { return request.maxBytes }

type SigningLedgerTransport interface {
	FetchSigningLedgerArtifact(ctx context.Context, request SigningLedgerRequest) (SigningLedgerResult, error)
}

type SigningLedgerResult struct {
	request SigningLedgerRequest
	bytes   []byte
}

func NewSigningLedgerResult(request SigningLedgerRequest, value []byte) (SigningLedgerResult, error) {
	if !request.valid() || len(value) == 0 || int64(len(value)) > request.maxBytes {
		return SigningLedgerResult{}, ErrInvalidTransportPayload
	}
	return SigningLedgerResult{request: request, bytes: append([]byte(nil), value...)}, nil
}

func (result SigningLedgerResult) bytesFor(request SigningLedgerRequest) ([]byte, error) {
	if result.request != request || len(result.bytes) == 0 || int64(len(result.bytes)) > request.maxBytes {
		return nil, ErrInvalidTransportPayload
	}
	return append([]byte(nil), result.bytes...), nil
}

func (request SigningLedgerRequest) valid() bool {
	if !contractIDPattern.MatchString(request.sourceID) || request.locator.value == "" {
		return false
	}
	switch request.kind {
	case SigningLedgerCheckpoint:
		return request.channel == "" && request.maxBytes == MaxSigningLedgerCheckpointBytes
	case SigningLedgerConsistencyProof:
		return request.channel == "" && request.maxBytes == MaxSigningLedgerEvidenceBytes
	case SigningLedgerEvidence, SigningLedgerReceipt, SigningLedgerInclusionProof, SigningLedgerLatestProof:
		return (request.channel == "" || contractIDPattern.MatchString(request.channel)) && request.maxBytes == MaxSigningLedgerEvidenceBytes
	default:
		return false
	}
}

func fixedSigningLedgerRequest(
	configuration SourceConfiguration,
	scope signingLedgerSubjectScope,
	kind SigningLedgerArtifactKind,
	subjectIdentitySHA256 string,
	previousCheckpointSHA256 string,
	currentCheckpointSHA256 string,
) (SigningLedgerRequest, error) {
	if !configuration.valid() || scope.sourceID != configuration.sourceID ||
		(scope.channel != "" && !sourceConfigurationContainsKey(configuration, SourceTrustKey{sourceID: scope.sourceID, channel: scope.channel})) {
		return SigningLedgerRequest{}, ErrInvalidSourceConfiguration
	}
	base := fmt.Sprintf("sources/%s/signing-ledger", scope.sourceID)
	var value string
	var maxBytes int64
	switch kind {
	case SigningLedgerCheckpoint:
		value = base + "/checkpoints/current.json"
		if currentCheckpointSHA256 != "" {
			if !sha256Pattern.MatchString(currentCheckpointSHA256) {
				return SigningLedgerRequest{}, ErrInvalidLocator
			}
			value = base + "/checkpoints/" + currentCheckpointSHA256 + ".json"
		}
		maxBytes = MaxSigningLedgerCheckpointBytes
	case SigningLedgerEvidence:
		if !sha256Pattern.MatchString(subjectIdentitySHA256) {
			return SigningLedgerRequest{}, ErrInvalidLocator
		}
		value = base + "/evidence/" + subjectIdentitySHA256 + ".json"
		maxBytes = MaxSigningLedgerEvidenceBytes
	case SigningLedgerReceipt:
		if !sha256Pattern.MatchString(subjectIdentitySHA256) {
			return SigningLedgerRequest{}, ErrInvalidLocator
		}
		value = base + "/receipts/" + subjectIdentitySHA256 + ".json"
		maxBytes = MaxSigningLedgerEvidenceBytes
	case SigningLedgerInclusionProof:
		if !sha256Pattern.MatchString(subjectIdentitySHA256) {
			return SigningLedgerRequest{}, ErrInvalidLocator
		}
		value = base + "/proofs/inclusion/" + subjectIdentitySHA256 + ".json"
		maxBytes = MaxSigningLedgerEvidenceBytes
	case SigningLedgerLatestProof:
		if !sha256Pattern.MatchString(subjectIdentitySHA256) {
			return SigningLedgerRequest{}, ErrInvalidLocator
		}
		value = base + "/proofs/latest/" + subjectIdentitySHA256 + ".json"
		maxBytes = MaxSigningLedgerEvidenceBytes
	case SigningLedgerConsistencyProof:
		if !sha256Pattern.MatchString(previousCheckpointSHA256) || !sha256Pattern.MatchString(currentCheckpointSHA256) {
			return SigningLedgerRequest{}, ErrInvalidLocator
		}
		value = base + "/proofs/consistency/" + previousCheckpointSHA256 + "/" + currentCheckpointSHA256 + ".json"
		maxBytes = MaxSigningLedgerEvidenceBytes
	default:
		return SigningLedgerRequest{}, ErrInvalidLocator
	}
	locator, err := newSourceRelativeLocator(value)
	if err != nil {
		return SigningLedgerRequest{}, err
	}
	channel := scope.channel
	if kind == SigningLedgerCheckpoint || kind == SigningLedgerConsistencyProof {
		channel = ""
	}
	return SigningLedgerRequest{
		sourceID: scope.sourceID,
		channel:  channel,
		kind:     kind,
		locator:  locator,
		maxBytes: maxBytes,
	}, nil
}

func sourceConfigurationContainsKey(configuration SourceConfiguration, key SourceTrustKey) bool {
	if !configuration.valid() || !key.valid() || configuration.sourceID != key.sourceID {
		return false
	}
	_, err := configuration.TrustKey(key.channel)
	return err == nil
}
