package releasetrust

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrInvalidLocator          = errors.New("release trust locator is invalid")
	ErrInvalidTransportPayload = errors.New("release trust transport payload is invalid")
	locatorPattern             = regexp.MustCompile(`^[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*$`)
	sha256Pattern              = regexp.MustCompile(`^[0-9a-f]{64}$`)
	transportTokenPattern      = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,512}$`)
)

const (
	MaxReleasePointerBytes  int64 = 64 << 10
	MaxReleaseDocumentBytes int64 = 1 << 20
)

type SourceRelativeLocator struct{ value string }

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
	FetchReleaseDocument(context.Context, ReleaseDocumentRequest) (ReleaseDocumentResult, error)
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
	channel := key.channel
	var value string
	var maxBytes int64
	switch kind {
	case ReleaseDocumentRootDelegation:
		value, maxBytes, channel = fmt.Sprintf("sources/%s/root/current.json", key.sourceID), MaxReleaseDocumentBytes, ""
	case ReleaseDocumentSourcePolicyPointer:
		value, maxBytes = fmt.Sprintf("sources/%s/%s/policy/current.json", key.sourceID, key.channel), MaxReleasePointerBytes
	case ReleaseDocumentRevocationPointer:
		value, maxBytes = fmt.Sprintf("sources/%s/%s/revocation/current.json", key.sourceID, key.channel), MaxReleasePointerBytes
	default:
		return ReleaseDocumentRequest{}, ErrInvalidLocator
	}
	locator, err := newSourceRelativeLocator(value)
	if err != nil {
		return ReleaseDocumentRequest{}, err
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
