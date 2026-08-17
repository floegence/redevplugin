package releasepublisher

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
)

const (
	ExternalSignerRequestSchemaVersion  = "redevplugin.external_signer_request.v1"
	ExternalSignerResponseSchemaVersion = "redevplugin.external_signer_response.v1"
	maxExternalSignerExchangeBytes      = 64 << 10
)

var (
	ErrInvalidSignerRequest  = errors.New("external signer request is invalid")
	ErrInvalidSignerResponse = errors.New("external signer response is invalid")
)

// ExternalSignerRequestV1 contains only public signing inputs. It deliberately
// carries no signer invocation, credential, storage, account, or lookup data.
type ExternalSignerRequestV1 struct {
	SchemaVersion         string                       `json:"schema_version"`
	RequestID             string                       `json:"request_id"`
	Usage                 releasecontract.SigningUsage `json:"usage"`
	KeyID                 string                       `json:"key_id"`
	SigningPreimageSHA256 string                       `json:"signing_preimage_sha256"`
}

// ExternalSignerResponseV1 is the minimal public result accepted from an
// external Ed25519 signer.
type ExternalSignerResponseV1 struct {
	SchemaVersion         string                       `json:"schema_version"`
	RequestID             string                       `json:"request_id"`
	Usage                 releasecontract.SigningUsage `json:"usage"`
	KeyID                 string                       `json:"key_id"`
	SigningPreimageSHA256 string                       `json:"signing_preimage_sha256"`
	Algorithm             string                       `json:"algorithm"`
	Signature             string                       `json:"signature"`
}

type signerRequestIdentity struct {
	SchemaVersion         string                       `json:"schema_version"`
	Usage                 releasecontract.SigningUsage `json:"usage"`
	KeyID                 string                       `json:"key_id"`
	SigningPreimageSHA256 string                       `json:"signing_preimage_sha256"`
}

func NewExternalSignerRequest(
	usage releasecontract.SigningUsage,
	keyID string,
	signingPreimage []byte,
) (ExternalSignerRequestV1, error) {
	if !validSigningUsage(usage) || keyID == "" || len(signingPreimage) == 0 {
		return ExternalSignerRequestV1{}, ErrInvalidSignerRequest
	}
	preimageDigest := sha256.Sum256(signingPreimage)
	identity := signerRequestIdentity{
		SchemaVersion:         ExternalSignerRequestSchemaVersion,
		Usage:                 usage,
		KeyID:                 keyID,
		SigningPreimageSHA256: hex.EncodeToString(preimageDigest[:]),
	}
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return ExternalSignerRequestV1{}, ErrInvalidSignerRequest
	}
	requestDigest := sha256.Sum256(identityBytes)
	request := ExternalSignerRequestV1{
		SchemaVersion:         identity.SchemaVersion,
		RequestID:             hex.EncodeToString(requestDigest[:]),
		Usage:                 identity.Usage,
		KeyID:                 identity.KeyID,
		SigningPreimageSHA256: identity.SigningPreimageSHA256,
	}
	if err := validateExternalSignerRequest(request); err != nil {
		return ExternalSignerRequestV1{}, err
	}
	return request, nil
}

func CanonicalExternalSignerRequest(request ExternalSignerRequestV1) ([]byte, error) {
	if err := validateExternalSignerRequest(request); err != nil {
		return nil, err
	}
	return json.Marshal(request)
}

func DecodeExternalSignerRequest(raw []byte) (ExternalSignerRequestV1, error) {
	var request ExternalSignerRequestV1
	if err := decodeClosedJSON(raw, &request); err != nil {
		return ExternalSignerRequestV1{}, fmt.Errorf("%w: %v", ErrInvalidSignerRequest, err)
	}
	if err := validateExternalSignerRequest(request); err != nil {
		return ExternalSignerRequestV1{}, err
	}
	return request, nil
}

func CanonicalExternalSignerResponse(response ExternalSignerResponseV1) ([]byte, error) {
	if err := validateExternalSignerResponseShape(response); err != nil {
		return nil, err
	}
	return json.Marshal(response)
}

func DecodeExternalSignerResponse(raw []byte) (ExternalSignerResponseV1, error) {
	var response ExternalSignerResponseV1
	if err := decodeClosedJSON(raw, &response); err != nil {
		return ExternalSignerResponseV1{}, fmt.Errorf("%w: %v", ErrInvalidSignerResponse, err)
	}
	if err := validateExternalSignerResponseShape(response); err != nil {
		return ExternalSignerResponseV1{}, err
	}
	return response, nil
}

func VerifyExternalSignerResponse(
	request ExternalSignerRequestV1,
	response ExternalSignerResponseV1,
	publicKey ed25519.PublicKey,
) ([]byte, error) {
	if err := validateExternalSignerRequest(request); err != nil {
		return nil, err
	}
	if err := validateExternalSignerResponseShape(response); err != nil {
		return nil, err
	}
	if response.RequestID != request.RequestID || response.Usage != request.Usage || response.KeyID != request.KeyID ||
		response.SigningPreimageSHA256 != request.SigningPreimageSHA256 ||
		len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidSignerResponse
	}
	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != response.Signature {
		return nil, ErrInvalidSignerResponse
	}
	preimageDigest, err := hex.DecodeString(request.SigningPreimageSHA256)
	if err != nil || !ed25519.Verify(publicKey, preimageDigest, signature) {
		return nil, ErrInvalidSignerResponse
	}
	return append([]byte(nil), signature...), nil
}

func validateExternalSignerRequest(request ExternalSignerRequestV1) error {
	if request.SchemaVersion != ExternalSignerRequestSchemaVersion || !isSHA256(request.RequestID) ||
		!isSHA256(request.SigningPreimageSHA256) || request.KeyID == "" || !validSigningUsage(request.Usage) {
		return ErrInvalidSignerRequest
	}
	identityBytes, err := json.Marshal(signerRequestIdentity{
		SchemaVersion: request.SchemaVersion, Usage: request.Usage, KeyID: request.KeyID,
		SigningPreimageSHA256: request.SigningPreimageSHA256,
	})
	if err != nil {
		return ErrInvalidSignerRequest
	}
	digest := sha256.Sum256(identityBytes)
	if hex.EncodeToString(digest[:]) != request.RequestID {
		return ErrInvalidSignerRequest
	}
	return nil
}

func validateExternalSignerResponseShape(response ExternalSignerResponseV1) error {
	if response.SchemaVersion != ExternalSignerResponseSchemaVersion || !isSHA256(response.RequestID) ||
		!isSHA256(response.SigningPreimageSHA256) ||
		response.KeyID == "" || response.Algorithm != releasecontract.SignatureAlgorithmEd25519 || !validSigningUsage(response.Usage) {
		return ErrInvalidSignerResponse
	}
	return nil
}

func validSigningUsage(usage releasecontract.SigningUsage) bool {
	switch usage {
	case releasecontract.SigningUsageRootDelegation, releasecontract.SigningUsagePackage,
		releasecontract.SigningUsageReleaseMetadata, releasecontract.SigningUsageSourcePolicy,
		releasecontract.SigningUsageSourcePolicyPointer, releasecontract.SigningUsageRevocation,
		releasecontract.SigningUsageRevocationPointer:
		return true
	default:
		return false
	}
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func decodeClosedJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maxExternalSignerExchangeBytes {
		return io.ErrUnexpectedEOF
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
