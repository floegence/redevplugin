package releasepublisher

import (
	"bytes"
	"context"
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
	"slices"
	"strings"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

const (
	workspaceStateFile   = "workspace.json"
	workspacePackageFile = "package.unsigned.redevplugin"
)

var (
	ErrInvalidPublisherConfig       = errors.New("release publisher config is invalid")
	ErrWorkspaceConflict            = errors.New("release publisher workspace conflicts with the requested input")
	ErrWorkspaceIncomplete          = errors.New("release publisher workspace is incomplete")
	ErrInvalidWorkspace             = errors.New("release publisher workspace is invalid")
	ErrPresentationIconUnavailable  = errors.New("release publisher presentation icon is unavailable")
	ErrPresentationIconOutputExists = errors.New("release publisher presentation icon output already exists")
)

type workspaceStateV1 struct {
	SchemaVersion string            `json:"schema_version"`
	Config        ConfigV1          `json:"config"`
	PackageSHA256 string            `json:"package_sha256"`
	Responses     map[string]string `json:"responses"`
}

func DecodeConfig(raw []byte) (ConfigV1, error) {
	var config ConfigV1
	if err := decodeClosedJSON(raw, &config); err != nil {
		return ConfigV1{}, fmt.Errorf("%w: %v", ErrInvalidPublisherConfig, err)
	}
	if _, err := validateConfig(config); err != nil {
		return ConfigV1{}, err
	}
	return config, nil
}

func Prepare(ctx context.Context, config ConfigV1, packageFile, workspace string) (WorkspaceStatusV1, error) {
	if _, err := validateConfig(config); err != nil {
		return WorkspaceStatusV1{}, err
	}
	packageBytes, err := os.ReadFile(packageFile)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	if _, err := readUnsignedPackage(ctx, packageBytes); err != nil {
		return WorkspaceStatusV1{}, err
	}
	packageDigest := sha256Hex(packageBytes)
	statePath := filepath.Join(workspace, workspaceStateFile)
	if raw, readErr := os.ReadFile(statePath); readErr == nil {
		state, err := decodeWorkspace(raw)
		if err != nil {
			return WorkspaceStatusV1{}, err
		}
		if state.PackageSHA256 != packageDigest || !equalConfig(state.Config, config) {
			return WorkspaceStatusV1{}, ErrWorkspaceConflict
		}
		return refreshWorkspace(ctx, workspace, state)
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return WorkspaceStatusV1{}, readErr
	}
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return WorkspaceStatusV1{}, err
	}
	state := workspaceStateV1{
		SchemaVersion: WorkspaceSchemaVersion,
		Config:        cloneConfig(config),
		PackageSHA256: packageDigest,
		Responses:     map[string]string{},
	}
	if err := writeFileAtomic(filepath.Join(workspace, workspacePackageFile), packageBytes, 0o644); err != nil {
		return WorkspaceStatusV1{}, err
	}
	if err := saveWorkspace(statePath, state); err != nil {
		return WorkspaceStatusV1{}, err
	}
	return refreshWorkspace(ctx, workspace, state)
}

func ApplySignature(ctx context.Context, workspace string, responseRaw []byte) (WorkspaceStatusV1, error) {
	response, err := DecodeExternalSignerResponse(responseRaw)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	statePath := filepath.Join(workspace, workspaceStateFile)
	stateRaw, err := os.ReadFile(statePath)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	state, err := decodeWorkspace(stateRaw)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	packageBytes, err := os.ReadFile(filepath.Join(workspace, workspacePackageFile))
	if err != nil || sha256Hex(packageBytes) != state.PackageSHA256 {
		return WorkspaceStatusV1{}, ErrInvalidWorkspace
	}
	assembly, err := assemble(ctx, state.Config, packageBytes, state.Responses)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	request, ok := requestByID(assembly.Pending, response.RequestID)
	if !ok {
		if existing, exists := state.Responses[response.RequestID]; exists && existing == response.Signature {
			return refreshWorkspace(ctx, workspace, state)
		}
		return WorkspaceStatusV1{}, ErrInvalidSignerResponse
	}
	publicKey, err := publicKeyFor(state.Config, request.KeyID)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	signature, err := VerifyExternalSignerResponse(request, response, publicKey)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	if previous, exists := state.Responses[request.RequestID]; exists && previous != base64.StdEncoding.EncodeToString(signature) {
		return WorkspaceStatusV1{}, ErrWorkspaceConflict
	}
	state.Responses[request.RequestID] = base64.StdEncoding.EncodeToString(signature)
	if err := saveWorkspace(statePath, state); err != nil {
		return WorkspaceStatusV1{}, err
	}
	return refreshWorkspace(ctx, workspace, state)
}

func Finalize(ctx context.Context, workspace, output string) (WorkspaceStatusV1, error) {
	stateRaw, err := os.ReadFile(filepath.Join(workspace, workspaceStateFile))
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	state, err := decodeWorkspace(stateRaw)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	packageBytes, err := os.ReadFile(filepath.Join(workspace, workspacePackageFile))
	if err != nil || sha256Hex(packageBytes) != state.PackageSHA256 {
		return WorkspaceStatusV1{}, ErrInvalidWorkspace
	}
	assembly, err := assemble(ctx, state.Config, packageBytes, state.Responses)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	if len(assembly.Pending) != 0 || !assembly.Complete {
		return WorkspaceStatusV1{}, ErrWorkspaceIncomplete
	}
	if err := writeAssembly(output, assembly); err != nil {
		return WorkspaceStatusV1{}, err
	}
	if err := VerifyOutput(ctx, output); err != nil {
		return WorkspaceStatusV1{}, err
	}
	return WorkspaceStatusV1{OK: true, Phase: "complete", Workspace: workspace, Output: output}, nil
}

func refreshWorkspace(ctx context.Context, workspace string, state workspaceStateV1) (WorkspaceStatusV1, error) {
	packageBytes, err := os.ReadFile(filepath.Join(workspace, workspacePackageFile))
	if err != nil || sha256Hex(packageBytes) != state.PackageSHA256 {
		return WorkspaceStatusV1{}, ErrInvalidWorkspace
	}
	assembly, err := assemble(ctx, state.Config, packageBytes, state.Responses)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	requestDir := filepath.Join(workspace, "requests")
	if err := os.MkdirAll(requestDir, 0o755); err != nil {
		return WorkspaceStatusV1{}, err
	}
	entries, err := os.ReadDir(requestDir)
	if err != nil {
		return WorkspaceStatusV1{}, err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			if err := os.Remove(filepath.Join(requestDir, entry.Name())); err != nil {
				return WorkspaceStatusV1{}, err
			}
		}
	}
	for _, request := range assembly.Pending {
		raw, err := CanonicalExternalSignerRequest(request)
		if err != nil {
			return WorkspaceStatusV1{}, err
		}
		if err := writeFileAtomic(filepath.Join(requestDir, request.RequestID+".json"), append(raw, '\n'), 0o644); err != nil {
			return WorkspaceStatusV1{}, err
		}
	}
	return WorkspaceStatusV1{
		OK: true, Phase: assembly.Phase, PendingRequests: len(assembly.Pending), Workspace: workspace,
	}, nil
}

func validateConfig(config ConfigV1) (map[string]ed25519.PublicKey, error) {
	if config.SchemaVersion != ConfigSchemaVersion || config.SourceID == "" || config.Channel == "" || config.SourceType == "" ||
		config.SourceClass == "" || config.GeneratedAt == "" || config.ExpiresAt == "" || config.MinReDevPluginVersion == "" ||
		config.Distribution == "" || config.SigningLedger.LogID == "" {
		return nil, ErrInvalidPublisherConfig
	}
	keys := make(map[string]ed25519.PublicKey, 3)
	for _, value := range []PublicKeyV1{config.Root, config.Signing, config.SigningLedger.PublicKeyV1} {
		if value.Algorithm != "ed25519" || value.KeyID == "" {
			return nil, ErrInvalidPublisherConfig
		}
		decoded, err := base64.StdEncoding.DecodeString(value.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != value.PublicKey {
			return nil, ErrInvalidPublisherConfig
		}
		if _, exists := keys[value.KeyID]; exists {
			return nil, ErrInvalidPublisherConfig
		}
		keys[value.KeyID] = ed25519.PublicKey(slices.Clone(decoded))
	}
	return keys, nil
}

func publicKeyFor(config ConfigV1, keyID string) (ed25519.PublicKey, error) {
	keys, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	key := keys[keyID]
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublisherConfig
	}
	return key, nil
}

func decodeWorkspace(raw []byte) (workspaceStateV1, error) {
	var state workspaceStateV1
	if err := decodeClosedJSON(raw, &state); err != nil || state.SchemaVersion != WorkspaceSchemaVersion || !isSHA256(state.PackageSHA256) || state.Responses == nil {
		return workspaceStateV1{}, ErrInvalidWorkspace
	}
	if _, err := validateConfig(state.Config); err != nil {
		return workspaceStateV1{}, ErrInvalidWorkspace
	}
	for requestID, signature := range state.Responses {
		if !isSHA256(requestID) {
			return workspaceStateV1{}, ErrInvalidWorkspace
		}
		decoded, err := base64.StdEncoding.DecodeString(signature)
		if err != nil || len(decoded) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(decoded) != signature {
			return workspaceStateV1{}, ErrInvalidWorkspace
		}
	}
	return state, nil
}

func readUnsignedPackage(ctx context.Context, raw []byte) (pluginpkg.Package, error) {
	pkg, err := pluginpkg.Read(ctx, bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadLimits())
	if err != nil {
		return pluginpkg.Package{}, err
	}
	if pkg.PackageSignature != nil {
		return pluginpkg.Package{}, errors.New("release publisher requires an unsigned package input")
	}
	return pkg, nil
}

func saveWorkspace(path string, state workspaceStateV1) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(raw, '\n'), 0o600)
}

func writeFileAtomic(path string, value []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".publisher-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
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
	return os.Rename(temporaryName, path)
}

func equalConfig(left, right ConfigV1) bool {
	leftRaw, _ := json.Marshal(left)
	rightRaw, _ := json.Marshal(right)
	return bytes.Equal(leftRaw, rightRaw)
}

func cloneConfig(config ConfigV1) ConfigV1 {
	raw, _ := json.Marshal(config)
	var cloned ConfigV1
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func requestByID(requests []ExternalSignerRequestV1, requestID string) (ExternalSignerRequestV1, bool) {
	for _, request := range requests {
		if request.RequestID == requestID {
			return request, true
		}
	}
	return ExternalSignerRequestV1{}, false
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func readClosedJSONFile(path string, target any, maxBytes int64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
