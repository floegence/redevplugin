package version

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	GoModuleVersion               = "0.0.0-dev"
	UIPackageVersion              = "0.0.0-dev"
	RuntimeVersion                = "0.0.0-dev"
	PluginHostProtocolVersion     = "plugin-host-v1"
	RustIPCVersion                = "rust-ipc-v1"
	WASMABIVersion                = "redeven-wasm-worker-v1"
	ManifestSchemaVersion         = "manifest-v1"
	PackageSignatureSchemaVersion = "package-signature-v1"
	TokenTicketSchemaVersion      = "token-ticket-v1"
	BridgeSchemaVersion           = "bridge-v1"
	TargetClassifierVersion       = "target-classifier-v1"
	PluginPlatformOpenAPIVersion  = "plugin-platform-v1"
	CompatibilityManifestVersion  = "redevplugin.compatibility.v1"
	CompatibilitySchemaVersion    = "compatibility-manifest-v1"
)

type Matrix struct {
	GoModuleVersion               string `json:"redevplugin_go_version"`
	UIPackageVersion              string `json:"redevplugin_ui_version"`
	RuntimeVersion                string `json:"redevplugin_runtime_version"`
	PluginHostProtocolVersion     string `json:"plugin_host_protocol_version"`
	RustIPCVersion                string `json:"rust_ipc_version"`
	WASMABIVersion                string `json:"wasm_abi_version"`
	ManifestSchemaVersion         string `json:"manifest_schema_version"`
	PackageSignatureSchemaVersion string `json:"package_signature_schema_version"`
	TokenTicketSchemaVersion      string `json:"token_ticket_schema_version"`
	BridgeSchemaVersion           string `json:"bridge_schema_version"`
	TargetClassifierVersion       string `json:"target_classifier_version"`
	PluginPlatformOpenAPIVersion  string `json:"plugin_platform_openapi_version"`
	CompatibilitySchemaVersion    string `json:"compatibility_schema_version"`
}

type ContractArtifact struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type CompatibilityManifest struct {
	SchemaVersion string             `json:"schema_version"`
	Matrix        Matrix             `json:"matrix"`
	Contracts     []ContractArtifact `json:"contracts"`
}

var (
	ErrCompatibilitySchemaVersion = errors.New("compatibility manifest schema version mismatch")
	ErrCompatibilityMatrix        = errors.New("compatibility manifest version matrix mismatch")
	ErrCompatibilityContract      = errors.New("compatibility manifest contract mismatch")
	ErrCompatibilityPath          = errors.New("compatibility manifest contract path is invalid")
)

func CurrentMatrix() Matrix {
	return Matrix{
		GoModuleVersion:               GoModuleVersion,
		UIPackageVersion:              UIPackageVersion,
		RuntimeVersion:                RuntimeVersion,
		PluginHostProtocolVersion:     PluginHostProtocolVersion,
		RustIPCVersion:                RustIPCVersion,
		WASMABIVersion:                WASMABIVersion,
		ManifestSchemaVersion:         ManifestSchemaVersion,
		PackageSignatureSchemaVersion: PackageSignatureSchemaVersion,
		TokenTicketSchemaVersion:      TokenTicketSchemaVersion,
		BridgeSchemaVersion:           BridgeSchemaVersion,
		TargetClassifierVersion:       TargetClassifierVersion,
		PluginPlatformOpenAPIVersion:  PluginPlatformOpenAPIVersion,
		CompatibilitySchemaVersion:    CompatibilitySchemaVersion,
	}
}

func CurrentCompatibilityManifest() CompatibilityManifest {
	return CompatibilityManifest{
		SchemaVersion: CompatibilityManifestVersion,
		Matrix:        CurrentMatrix(),
		Contracts: []ContractArtifact{
			{
				ID:      "plugin-platform-openapi",
				Path:    "spec/openapi/plugin-platform-v1.yaml",
				Version: PluginPlatformOpenAPIVersion,
				SHA256:  "7af8c007332722a8d12c7da0a43bad90d3878719b27a93b6e605113a09bae5a0",
			},
			{
				ID:      "manifest-schema",
				Path:    "spec/plugin/manifest-v1.schema.json",
				Version: ManifestSchemaVersion,
				SHA256:  "8d76eb53ca63a4eaed623d12381a152da2da22634a5159845a46c8abc27a406a",
			},
			{
				ID:      "package-signature-schema",
				Path:    "spec/plugin/package-signature-v1.schema.json",
				Version: PackageSignatureSchemaVersion,
				SHA256:  "13951c0f6831ba28647774368c76a817868aeb7984628e2cf3dc4ad1b54f8284",
			},
			{
				ID:      "token-ticket-schema",
				Path:    "spec/plugin/token-ticket-v1.schema.json",
				Version: TokenTicketSchemaVersion,
				SHA256:  "0a96578cdedc73b1fa96ee94cbc23c03b97d1dcd1def52f412f02c978af32f14",
			},
			{
				ID:      "iframe-bridge-schema",
				Path:    "spec/plugin/bridge-v1.schema.json",
				Version: BridgeSchemaVersion,
				SHA256:  "d6c82f67bb86695b5a018d10ba64d3aef99863083094543659f3f39cf3d3ed50",
			},
			{
				ID:      "compatibility-manifest-schema",
				Path:    "spec/plugin/compatibility-manifest-v1.schema.json",
				Version: CompatibilitySchemaVersion,
				SHA256:  "6bc1f42cc42c5ad2e2844366a7cfa08759d05035e376351001271a2530ec501c",
			},
			{
				ID:      "rust-ipc-schema",
				Path:    "spec/plugin/ipc-v1.schema.json",
				Version: RustIPCVersion,
				SHA256:  "26ffdf7fff438fbf820d7d93b80861cc05fc1a7bb9e66ff6745c9f71c1ac8cf0",
			},
			{
				ID:      "wasm-worker-schema",
				Path:    "spec/plugin/wasm-worker-v1.schema.json",
				Version: WASMABIVersion,
				SHA256:  "6bff741d49a49e1e7685ccd9c1520c272412bdbe91d3654f601a7f083ba1fa38",
			},
			{
				ID:      "network-grant-schema",
				Path:    "spec/plugin/network-grant-v1.schema.json",
				Version: TargetClassifierVersion,
				SHA256:  "e3ba8e7aa42267596b5570c1de60994a0912b125ea78427776db8092c2b3ea7b",
			},
			{
				ID:      "target-classifier-fixture",
				Path:    "spec/plugin/target-classifier-v1.json",
				Version: TargetClassifierVersion,
				SHA256:  "cf5b02acaf59ccd578df7c8281c392b2721ee594d908d85f1aac39ccf9ebd079",
			},
		},
	}
}

func DecodeCompatibilityManifest(raw []byte) (CompatibilityManifest, error) {
	var manifest CompatibilityManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return CompatibilityManifest{}, err
	}
	return manifest, nil
}

func VerifyCompatibilityManifestFile(filename string, artifactRoot string) error {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	manifest, err := DecodeCompatibilityManifest(raw)
	if err != nil {
		return err
	}
	return VerifyCompatibilityManifest(manifest, artifactRoot)
}

func VerifyCompatibilityManifest(manifest CompatibilityManifest, artifactRoot string) error {
	expected := CurrentCompatibilityManifest()
	if manifest.SchemaVersion != expected.SchemaVersion {
		return fmt.Errorf("%w: got %q want %q", ErrCompatibilitySchemaVersion, manifest.SchemaVersion, expected.SchemaVersion)
	}
	if !matrixEqual(manifest.Matrix, expected.Matrix) {
		return fmt.Errorf("%w: got %#v want %#v", ErrCompatibilityMatrix, manifest.Matrix, expected.Matrix)
	}

	expectedContracts := map[string]ContractArtifact{}
	for _, contract := range expected.Contracts {
		expectedContracts[contract.ID] = contract
	}
	seen := map[string]bool{}
	for _, contract := range manifest.Contracts {
		if seen[contract.ID] {
			return fmt.Errorf("%w: duplicate contract id %q", ErrCompatibilityContract, contract.ID)
		}
		seen[contract.ID] = true
		expectedContract, ok := expectedContracts[contract.ID]
		if !ok {
			return fmt.Errorf("%w: unexpected contract id %q", ErrCompatibilityContract, contract.ID)
		}
		if contract.Path != expectedContract.Path || contract.Version != expectedContract.Version || contract.SHA256 != expectedContract.SHA256 {
			return fmt.Errorf("%w: contract %q metadata mismatch", ErrCompatibilityContract, contract.ID)
		}
		if err := verifyContractArtifactHash(artifactRoot, contract); err != nil {
			return err
		}
	}
	for id := range expectedContracts {
		if !seen[id] {
			return fmt.Errorf("%w: missing contract id %q", ErrCompatibilityContract, id)
		}
	}
	return nil
}

func verifyContractArtifactHash(root string, contract ContractArtifact) error {
	if err := validateContractPath(contract.Path); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(contract.Path)))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != contract.SHA256 {
		return fmt.Errorf("%w: %s sha256 got %s want %s", ErrCompatibilityContract, contract.Path, got, contract.SHA256)
	}
	return nil
}

func validateContractPath(path string) error {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return fmt.Errorf("%w: %q", ErrCompatibilityPath, path)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean != path || strings.HasPrefix(clean, "../") || clean == ".." {
		return fmt.Errorf("%w: %q", ErrCompatibilityPath, path)
	}
	if !strings.HasPrefix(path, "spec/openapi/") && !strings.HasPrefix(path, "spec/plugin/") {
		return fmt.Errorf("%w: %q", ErrCompatibilityPath, path)
	}
	return nil
}

func matrixEqual(a Matrix, b Matrix) bool {
	return a == b
}
