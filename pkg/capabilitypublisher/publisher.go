// Package capabilitypublisher implements a resumable, external-signer
// publication flow for immutable host capability bundles.
package capabilitypublisher

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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/version"
)

const (
	ConfigSchemaVersion    = "redevplugin.host_capability_publisher_config.v1"
	RequestSchemaVersion   = "redevplugin.host_capability_signer_request.v1"
	ResponseSchemaVersion  = "redevplugin.host_capability_signer_response.v1"
	WorkspaceSchemaVersion = "redevplugin.host_capability_publisher_workspace.v1"
	SigningUsage           = "redevplugin.host-capability-signing.manifest.v1"
	workspaceStateFile     = "workspace.json"
	requestDirectory       = "requests"
	maxExchangeBytes       = 1 << 20
)

var (
	ErrInvalidConfig       = errors.New("host capability publisher config is invalid")
	ErrInvalidRequest      = errors.New("host capability signer request is invalid")
	ErrInvalidResponse     = errors.New("host capability signer response is invalid")
	ErrWorkspaceConflict   = errors.New("host capability publisher workspace conflicts with the requested input")
	ErrWorkspaceIncomplete = errors.New("host capability publisher workspace is incomplete")
	ErrInvalidWorkspace    = errors.New("host capability publisher workspace is invalid")
	sha256Pattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type PublicKeyV1 struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PublisherID   string `json:"publisher_id"`
	PublicKey     string `json:"public_key"`
	CreatedAt     string `json:"created_at,omitempty"`
}

type ConfigV1 struct {
	SchemaVersion            string                      `json:"schema_version"`
	Contract                 capabilitycontract.Contract `json:"contract"`
	ArtifactBaseRef          string                      `json:"artifact_base_ref"`
	GeneratedAt              string                      `json:"generated_at"`
	SourceCommit             string                      `json:"source_commit"`
	MinReDevPluginVersion    string                      `json:"min_redevplugin_version"`
	SignaturePolicyEpoch     string                      `json:"signature_policy_epoch"`
	SignatureRevocationEpoch string                      `json:"signature_revocation_epoch"`
	PublicKey                PublicKeyV1                 `json:"public_key"`
	Notices                  []capabilitycontract.Notice `json:"notices"`
}

type SignerRequestV1 struct {
	SchemaVersion         string `json:"schema_version"`
	RequestID             string `json:"request_id"`
	Usage                 string `json:"usage"`
	KeyID                 string `json:"key_id"`
	PublisherID           string `json:"publisher_id"`
	ContractID            string `json:"contract_id"`
	ContractVersion       string `json:"contract_version"`
	ManifestSHA256        string `json:"manifest_sha256"`
	SigningPreimageSHA256 string `json:"signing_preimage_sha256"`
	SigningPreimage       string `json:"signing_preimage"`
}

type SignerResponseV1 struct {
	SchemaVersion         string `json:"schema_version"`
	RequestID             string `json:"request_id"`
	Usage                 string `json:"usage"`
	KeyID                 string `json:"key_id"`
	PublisherID           string `json:"publisher_id"`
	ContractID            string `json:"contract_id"`
	ContractVersion       string `json:"contract_version"`
	ManifestSHA256        string `json:"manifest_sha256"`
	SigningPreimageSHA256 string `json:"signing_preimage_sha256"`
	Algorithm             string `json:"algorithm"`
	Signature             string `json:"signature"`
}

type StatusV1 struct {
	OK              bool   `json:"ok"`
	Phase           string `json:"phase"`
	PendingRequests int    `json:"pending_requests"`
	Workspace       string `json:"workspace"`
	Output          string `json:"output,omitempty"`
}

type workspaceStateV1 struct {
	SchemaVersion string   `json:"schema_version"`
	Config        ConfigV1 `json:"config"`
	RequestID     string   `json:"request_id"`
	Signature     string   `json:"signature,omitempty"`
}

type requestIdentity struct {
	SchemaVersion         string `json:"schema_version"`
	Usage                 string `json:"usage"`
	KeyID                 string `json:"key_id"`
	PublisherID           string `json:"publisher_id"`
	ContractID            string `json:"contract_id"`
	ContractVersion       string `json:"contract_version"`
	ManifestSHA256        string `json:"manifest_sha256"`
	SigningPreimageSHA256 string `json:"signing_preimage_sha256"`
	SigningPreimage       string `json:"signing_preimage"`
}

func Prepare(config ConfigV1, workspace string) (StatusV1, error) {
	prepared, _, err := prepareBundle(config)
	if err != nil {
		return StatusV1{}, err
	}
	request, err := newSignerRequest(config, prepared.Manifest)
	if err != nil {
		return StatusV1{}, err
	}
	statePath := filepath.Join(workspace, workspaceStateFile)
	if raw, readErr := os.ReadFile(statePath); readErr == nil {
		state, decodeErr := decodeWorkspace(raw)
		if decodeErr != nil {
			return StatusV1{}, decodeErr
		}
		if !equalConfig(state.Config, config) || state.RequestID != request.RequestID {
			return StatusV1{}, ErrWorkspaceConflict
		}
		return refreshWorkspace(workspace, state)
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return StatusV1{}, readErr
	}
	state := workspaceStateV1{SchemaVersion: WorkspaceSchemaVersion, Config: cloneConfig(config), RequestID: request.RequestID}
	if err := saveWorkspace(statePath, state); err != nil {
		return StatusV1{}, err
	}
	return refreshWorkspace(workspace, state)
}

func ApplySignature(workspace string, responseRaw []byte) (StatusV1, error) {
	response, err := DecodeSignerResponse(responseRaw)
	if err != nil {
		return StatusV1{}, err
	}
	state, prepared, publicKey, request, err := loadWorkspace(workspace)
	if err != nil {
		return StatusV1{}, err
	}
	if err := verifyResponse(request, response, prepared.Manifest, publicKey); err != nil {
		return StatusV1{}, err
	}
	if state.Signature != "" {
		if state.Signature != response.Signature {
			return StatusV1{}, ErrWorkspaceConflict
		}
		return refreshWorkspace(workspace, state)
	}
	state.Signature = response.Signature
	if err := saveWorkspace(filepath.Join(workspace, workspaceStateFile), state); err != nil {
		return StatusV1{}, err
	}
	return refreshWorkspace(workspace, state)
}

func Finalize(workspace, output string) (StatusV1, error) {
	state, prepared, publicKey, _, err := loadWorkspace(workspace)
	if err != nil {
		return StatusV1{}, err
	}
	if state.Signature == "" {
		return StatusV1{}, ErrWorkspaceIncomplete
	}
	signature, err := decodeCanonicalSignature(state.Signature)
	if err != nil {
		return StatusV1{}, ErrInvalidWorkspace
	}
	bundle, err := capabilitycontract.Finalize(prepared, signature, publicKey)
	if err != nil {
		return StatusV1{}, err
	}
	if err := writeBundleWithPublicKey(output, bundle, state.Config.PublicKey); err != nil {
		return StatusV1{}, err
	}
	if err := VerifyOutput(output); err != nil {
		return StatusV1{}, err
	}
	return StatusV1{OK: true, Phase: "complete", Workspace: filepath.Clean(workspace), Output: filepath.Clean(output)}, nil
}

func VerifyOutput(output string) error {
	var pin capabilitycontract.Pin
	if err := readClosedJSONFile(filepath.Join(output, "host-capability.pin.json"), &pin, maxExchangeBytes); err != nil {
		return err
	}
	var publicDoc PublicKeyV1
	if err := readClosedJSONFile(filepath.Join(output, "host-capability.public.json"), &publicDoc, maxExchangeBytes); err != nil {
		return err
	}
	publicKey, err := decodePublicKey(publicDoc)
	if err != nil || publicDoc.KeyID != pin.SignatureKeyID || publicDoc.PublisherID != pin.PublisherID {
		return ErrInvalidWorkspace
	}
	bundle, err := capabilitycontract.ReadBundle(output, pin)
	if err != nil {
		return err
	}
	_, err = capabilitycontract.Verify(capabilitycontract.VerifyRequest{
		Bundle: bundle, ExpectedPin: pin,
		TrustedKey: capabilitycontract.TrustedKey{PublisherID: pin.PublisherID, KeyID: pin.SignatureKeyID, PublicKey: publicKey,
			PolicyEpoch: pin.SignaturePolicyEpoch, RevocationEpoch: pin.SignatureRevocationEpoch},
		CurrentReDevPluginVersion: version.CurrentCompatibilityVersion(),
	})
	return err
}

func CanonicalSignerRequest(request SignerRequestV1) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	return json.Marshal(request)
}

func DecodeSignerRequest(raw []byte) (SignerRequestV1, error) {
	var request SignerRequestV1
	if len(raw) > maxExchangeBytes || decodeClosedJSON(raw, &request) != nil {
		return SignerRequestV1{}, ErrInvalidRequest
	}
	if err := validateRequest(request); err != nil {
		return SignerRequestV1{}, err
	}
	return request, nil
}

func CanonicalSignerResponse(response SignerResponseV1) ([]byte, error) {
	if err := validateResponseShape(response); err != nil {
		return nil, err
	}
	return json.Marshal(response)
}

func DecodeSignerResponse(raw []byte) (SignerResponseV1, error) {
	var response SignerResponseV1
	if len(raw) > maxExchangeBytes || decodeClosedJSON(raw, &response) != nil {
		return SignerResponseV1{}, ErrInvalidResponse
	}
	if err := validateResponseShape(response); err != nil {
		return SignerResponseV1{}, err
	}
	return response, nil
}

func prepareBundle(config ConfigV1) (capabilitycontract.PreparedBundle, ed25519.PublicKey, error) {
	publicKey, err := validateConfig(config)
	if err != nil {
		return capabilitycontract.PreparedBundle{}, nil, err
	}
	generatedAt, err := time.Parse(time.RFC3339, config.GeneratedAt)
	if err != nil {
		return capabilitycontract.PreparedBundle{}, nil, ErrInvalidConfig
	}
	prepared, err := capabilitycontract.Prepare(capabilitycontract.PrepareRequest{
		Contract: config.Contract, PublisherID: config.PublicKey.PublisherID, ArtifactBaseRef: config.ArtifactBaseRef,
		GeneratedAt: generatedAt, SourceCommit: config.SourceCommit, MinReDevPluginVersion: config.MinReDevPluginVersion,
		SignatureKeyID: config.PublicKey.KeyID, SignaturePolicyEpoch: config.SignaturePolicyEpoch,
		SignatureRevocationEpoch: config.SignatureRevocationEpoch, Notices: config.Notices,
	})
	if err != nil {
		return capabilitycontract.PreparedBundle{}, nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return prepared, publicKey, nil
}

func newSignerRequest(config ConfigV1, manifest []byte) (SignerRequestV1, error) {
	digest := sha256.Sum256(manifest)
	identity := requestIdentity{
		SchemaVersion: RequestSchemaVersion, Usage: SigningUsage, KeyID: config.PublicKey.KeyID,
		PublisherID: config.PublicKey.PublisherID, ContractID: config.Contract.ContractID,
		ContractVersion: config.Contract.ContractVersion, ManifestSHA256: hex.EncodeToString(digest[:]),
		SigningPreimageSHA256: hex.EncodeToString(digest[:]), SigningPreimage: base64.StdEncoding.EncodeToString(manifest),
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return SignerRequestV1{}, ErrInvalidRequest
	}
	requestDigest := sha256.Sum256(raw)
	request := SignerRequestV1{
		SchemaVersion: identity.SchemaVersion, RequestID: hex.EncodeToString(requestDigest[:]), Usage: identity.Usage,
		KeyID: identity.KeyID, PublisherID: identity.PublisherID, ContractID: identity.ContractID,
		ContractVersion: identity.ContractVersion, ManifestSHA256: identity.ManifestSHA256,
		SigningPreimageSHA256: identity.SigningPreimageSHA256, SigningPreimage: identity.SigningPreimage,
	}
	return request, validateRequest(request)
}

func verifyResponse(request SignerRequestV1, response SignerResponseV1, manifest []byte, publicKey ed25519.PublicKey) error {
	if response.RequestID != request.RequestID || response.Usage != request.Usage || response.KeyID != request.KeyID ||
		response.PublisherID != request.PublisherID || response.ContractID != request.ContractID ||
		response.ContractVersion != request.ContractVersion || response.ManifestSHA256 != request.ManifestSHA256 ||
		response.SigningPreimageSHA256 != request.SigningPreimageSHA256 {
		return ErrInvalidResponse
	}
	signature, err := decodeCanonicalSignature(response.Signature)
	if err != nil || !ed25519.Verify(publicKey, manifest, signature) {
		return ErrInvalidResponse
	}
	return nil
}

func validateConfig(config ConfigV1) (ed25519.PublicKey, error) {
	if config.SchemaVersion != ConfigSchemaVersion || config.PublicKey.PublisherID != config.Contract.PublisherID ||
		strings.TrimSpace(config.GeneratedAt) != config.GeneratedAt || config.Notices == nil {
		return nil, ErrInvalidConfig
	}
	key, err := decodePublicKey(config.PublicKey)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return key, nil
}

func decodePublicKey(value PublicKeyV1) (ed25519.PublicKey, error) {
	if value.SchemaVersion != "redevplugin.ed25519_signing_key.v1" || value.Algorithm != "ed25519" ||
		strings.TrimSpace(value.KeyID) == "" || strings.TrimSpace(value.PublisherID) == "" {
		return nil, ErrInvalidConfig
	}
	raw, err := base64.StdEncoding.DecodeString(value.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != value.PublicKey {
		return nil, ErrInvalidConfig
	}
	return ed25519.PublicKey(raw), nil
}

func validateRequest(request SignerRequestV1) error {
	if request.SchemaVersion != RequestSchemaVersion || request.Usage != SigningUsage || !sha256Pattern.MatchString(request.RequestID) ||
		!sha256Pattern.MatchString(request.ManifestSHA256) || request.SigningPreimageSHA256 != request.ManifestSHA256 ||
		request.KeyID == "" || request.PublisherID == "" || request.ContractID == "" || request.ContractVersion == "" {
		return ErrInvalidRequest
	}
	preimage, err := base64.StdEncoding.DecodeString(request.SigningPreimage)
	if err != nil || base64.StdEncoding.EncodeToString(preimage) != request.SigningPreimage || sha256Hex(preimage) != request.SigningPreimageSHA256 {
		return ErrInvalidRequest
	}
	identity := requestIdentity{request.SchemaVersion, request.Usage, request.KeyID, request.PublisherID, request.ContractID,
		request.ContractVersion, request.ManifestSHA256, request.SigningPreimageSHA256, request.SigningPreimage}
	raw, _ := json.Marshal(identity)
	if sha256Hex(raw) != request.RequestID {
		return ErrInvalidRequest
	}
	return nil
}

func validateResponseShape(response SignerResponseV1) error {
	if response.SchemaVersion != ResponseSchemaVersion || response.Usage != SigningUsage || response.Algorithm != "ed25519" ||
		!sha256Pattern.MatchString(response.RequestID) || !sha256Pattern.MatchString(response.ManifestSHA256) ||
		response.SigningPreimageSHA256 != response.ManifestSHA256 || response.KeyID == "" || response.PublisherID == "" ||
		response.ContractID == "" || response.ContractVersion == "" {
		return ErrInvalidResponse
	}
	_, err := decodeCanonicalSignature(response.Signature)
	if err != nil {
		return ErrInvalidResponse
	}
	return nil
}

func loadWorkspace(workspace string) (workspaceStateV1, capabilitycontract.PreparedBundle, ed25519.PublicKey, SignerRequestV1, error) {
	raw, err := os.ReadFile(filepath.Join(workspace, workspaceStateFile))
	if err != nil {
		return workspaceStateV1{}, capabilitycontract.PreparedBundle{}, nil, SignerRequestV1{}, err
	}
	state, err := decodeWorkspace(raw)
	if err != nil {
		return workspaceStateV1{}, capabilitycontract.PreparedBundle{}, nil, SignerRequestV1{}, err
	}
	prepared, publicKey, err := prepareBundle(state.Config)
	if err != nil {
		return workspaceStateV1{}, capabilitycontract.PreparedBundle{}, nil, SignerRequestV1{}, ErrInvalidWorkspace
	}
	request, err := newSignerRequest(state.Config, prepared.Manifest)
	if err != nil || request.RequestID != state.RequestID {
		return workspaceStateV1{}, capabilitycontract.PreparedBundle{}, nil, SignerRequestV1{}, ErrInvalidWorkspace
	}
	if state.Signature != "" {
		signature, decodeErr := decodeCanonicalSignature(state.Signature)
		if decodeErr != nil || !ed25519.Verify(publicKey, prepared.Manifest, signature) {
			return workspaceStateV1{}, capabilitycontract.PreparedBundle{}, nil, SignerRequestV1{}, ErrInvalidWorkspace
		}
	}
	return state, prepared, publicKey, request, nil
}

func refreshWorkspace(workspace string, state workspaceStateV1) (StatusV1, error) {
	_, _, _, request, err := loadWorkspace(workspace)
	if err != nil {
		return StatusV1{}, err
	}
	directory := filepath.Join(workspace, requestDirectory)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return StatusV1{}, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return StatusV1{}, err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
				return StatusV1{}, err
			}
		}
	}
	pending := 0
	phase := "ready"
	if state.Signature == "" {
		raw, _ := CanonicalSignerRequest(request)
		if err := writeFileAtomic(filepath.Join(directory, request.RequestID+".json"), append(raw, '\n'), 0o644); err != nil {
			return StatusV1{}, err
		}
		pending = 1
		phase = "awaiting_signature"
	}
	return StatusV1{OK: true, Phase: phase, PendingRequests: pending, Workspace: filepath.Clean(workspace)}, nil
}

func decodeWorkspace(raw []byte) (workspaceStateV1, error) {
	var state workspaceStateV1
	if decodeClosedJSON(raw, &state) != nil || state.SchemaVersion != WorkspaceSchemaVersion || !sha256Pattern.MatchString(state.RequestID) {
		return workspaceStateV1{}, ErrInvalidWorkspace
	}
	if _, err := validateConfig(state.Config); err != nil {
		return workspaceStateV1{}, ErrInvalidWorkspace
	}
	if state.Signature != "" {
		if _, err := decodeCanonicalSignature(state.Signature); err != nil {
			return workspaceStateV1{}, ErrInvalidWorkspace
		}
	}
	return state, nil
}

func saveWorkspace(path string, state workspaceStateV1) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(raw, '\n'), 0o600)
}

func writeBundleWithPublicKey(output string, bundle capabilitycontract.Bundle, publicDoc PublicKeyV1) error {
	for ref, content := range bundle.Files {
		if err := writeImmutableFile(filepath.Join(output, filepath.FromSlash(ref)), content, 0o644); err != nil {
			return err
		}
	}
	pinRaw, _ := json.MarshalIndent(bundle.Pin, "", "  ")
	if err := writeImmutableFile(filepath.Join(output, "host-capability.pin.json"), append(pinRaw, '\n'), 0o644); err != nil {
		return err
	}
	publicRaw, _ := json.MarshalIndent(publicDoc, "", "  ")
	return writeImmutableFile(filepath.Join(output, "host-capability.public.json"), append(publicRaw, '\n'), 0o644)
}

func writeImmutableFile(path string, value []byte, mode os.FileMode) error {
	if current, err := os.ReadFile(path); err == nil {
		if bytes.Equal(current, value) {
			return nil
		}
		return ErrWorkspaceConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFileAtomic(path, value, mode)
}

func writeFileAtomic(path string, value []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".capability-publisher-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func readClosedJSONFile(path string, target any, limit int64) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return ErrInvalidWorkspace
	}
	return decodeClosedJSON(raw, target)
}

func decodeClosedJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}

func decodeCanonicalSignature(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, ErrInvalidResponse
	}
	return raw, nil
}

func cloneConfig(config ConfigV1) ConfigV1 {
	raw, _ := json.Marshal(config)
	var clone ConfigV1
	_ = json.Unmarshal(raw, &clone)
	return clone
}

func equalConfig(left, right ConfigV1) bool {
	leftRaw, _ := json.Marshal(left)
	rightRaw, _ := json.Marshal(right)
	return bytes.Equal(leftRaw, rightRaw)
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
