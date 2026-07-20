package version

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

const (
	modulePath                      = "github.com/floegence/redevplugin"
	devVersion                      = "0.0.0-dev"
	developmentCompatibilityVersion = "0.6.0"
)

var (
	GoModuleVersion  = devVersion
	UIPackageVersion = devVersion
	RuntimeVersion   = devVersion

	buildInfoModuleVersion = detectBuildInfoModuleVersion
)

type Matrix struct {
	GoModuleVersion                string `json:"redevplugin_go_version"`
	UIPackageVersion               string `json:"redevplugin_ui_version"`
	RuntimeVersion                 string `json:"redevplugin_runtime_version"`
	PluginUIProtocolVersion        string `json:"plugin_ui_protocol_version"`
	PluginHostProtocolVersion      string `json:"plugin_host_protocol_version"`
	RustIPCVersion                 string `json:"rust_ipc_version"`
	WASMABIVersion                 string `json:"wasm_abi_version"`
	ManifestSchemaVersion          string `json:"manifest_schema_version"`
	PackageSignatureSchemaVersion  string `json:"package_signature_schema_version"`
	ReleaseMetadataSchemaVersion   string `json:"release_metadata_schema_version"`
	SourcePolicySchemaVersion      string `json:"source_policy_schema_version"`
	SourceRevocationsSchemaVersion string `json:"source_revocations_schema_version"`
	TokenTicketSchemaVersion       string `json:"token_ticket_schema_version"`
	BridgeSchemaVersion            string `json:"bridge_schema_version"`
	OpaqueSurfaceDocumentVersion   string `json:"opaque_surface_document_schema_version"`
	OpaqueSurfaceTransportVersion  string `json:"opaque_surface_transport_schema_version"`
	TargetClassifierVersion        string `json:"target_classifier_version"`
	NetworkGrantSchemaVersion      string `json:"network_grant_schema_version"`
	ResourceScopeSchemaVersion     string `json:"resource_scope_schema_version"`
	SessionScopeSchemaVersion      string `json:"session_scope_schema_version"`
	PluginPlatformOpenAPIVersion   string `json:"plugin_platform_openapi_version"`
	CompatibilitySchemaVersion     string `json:"compatibility_schema_version"`
	ReleaseManifestSchemaVersion   string `json:"release_manifest_schema_version"`
	WorkerInvocationSchemaVersion  string `json:"worker_invocation_schema_version"`
	HostCapabilityContractVersion  string `json:"host_capability_contract_schema_version"`
	HostCapabilityPinVersion       string `json:"host_capability_pin_schema_version"`
	HostCapabilityManifestVersion  string `json:"host_capability_manifest_schema_version"`
	HostCapabilityCompatVersion    string `json:"host_capability_compatibility_schema_version"`
	HostCapabilitySignatureVersion string `json:"host_capability_signature_schema_version"`
	HostCapabilityNoticesVersion   string `json:"host_capability_notices_schema_version"`
	ErrorCodesSchemaVersion        string `json:"error_codes_schema_version"`
	PerformanceContractVersion     string `json:"performance_contract_version"`
	PerformanceEvidenceVersion     string `json:"performance_evidence_schema_version"`
	ContractRegistryVersion        string `json:"contract_registry_version"`
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
		GoModuleVersion:                resolvedReleaseVersion(GoModuleVersion),
		UIPackageVersion:               configuredArtifactVersion(UIPackageVersion),
		RuntimeVersion:                 configuredArtifactVersion(RuntimeVersion),
		PluginUIProtocolVersion:        PluginUIProtocolVersion,
		PluginHostProtocolVersion:      PluginHostProtocolVersion,
		RustIPCVersion:                 RustIPCVersion,
		WASMABIVersion:                 WASMABIVersion,
		ManifestSchemaVersion:          ManifestSchemaVersion,
		PackageSignatureSchemaVersion:  PackageSignatureSchemaVersion,
		ReleaseMetadataSchemaVersion:   ReleaseMetadataSchemaVersion,
		SourcePolicySchemaVersion:      SourcePolicySchemaVersion,
		SourceRevocationsSchemaVersion: SourceRevocationsSchemaVersion,
		TokenTicketSchemaVersion:       TokenTicketSchemaVersion,
		BridgeSchemaVersion:            BridgeSchemaVersion,
		OpaqueSurfaceDocumentVersion:   OpaqueSurfaceDocumentSchemaVersion,
		OpaqueSurfaceTransportVersion:  OpaqueSurfaceTransportSchemaVersion,
		TargetClassifierVersion:        TargetClassifierVersion,
		NetworkGrantSchemaVersion:      NetworkGrantSchemaVersion,
		ResourceScopeSchemaVersion:     ResourceScopeSchemaVersion,
		SessionScopeSchemaVersion:      SessionScopeSchemaVersion,
		PluginPlatformOpenAPIVersion:   PluginPlatformOpenAPIVersion,
		CompatibilitySchemaVersion:     CompatibilitySchemaVersion,
		ReleaseManifestSchemaVersion:   ReleaseManifestSchemaVersion,
		WorkerInvocationSchemaVersion:  WorkerInvocationSchemaVersion,
		HostCapabilityContractVersion:  HostCapabilityContractSchemaVersion,
		HostCapabilityPinVersion:       HostCapabilityPinSchemaVersion,
		HostCapabilityManifestVersion:  HostCapabilityManifestSchemaVersion,
		HostCapabilityCompatVersion:    HostCapabilityCompatibilitySchemaVersion,
		HostCapabilitySignatureVersion: HostCapabilitySignatureSchemaVersion,
		HostCapabilityNoticesVersion:   HostCapabilityNoticesSchemaVersion,
		ErrorCodesSchemaVersion:        ErrorCodesSchemaVersion,
		PerformanceContractVersion:     PerformanceContractVersion,
		PerformanceEvidenceVersion:     PerformanceEvidenceSchemaVersion,
		ContractRegistryVersion:        ContractRegistryVersion,
	}
}

func CurrentCompatibilityVersion() string {
	version := resolvedReleaseVersion(GoModuleVersion)
	if version == devVersion {
		return developmentCompatibilityVersion
	}
	return version
}

func configuredArtifactVersion(configured string) string {
	if configured == "" {
		return devVersion
	}
	return configured
}

func resolvedReleaseVersion(configured string) string {
	if configured != "" && configured != devVersion {
		return configured
	}
	if detected := buildInfoModuleVersion(); detected != "" {
		return detected
	}
	if configured == "" {
		return devVersion
	}
	return configured
}

func detectBuildInfoModuleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if info.Main.Path == modulePath {
		if version := normalizeModuleVersion(info.Main.Version); version != "" {
			return version
		}
	}
	for _, dep := range info.Deps {
		if dep.Path != modulePath {
			continue
		}
		if version := normalizeModuleVersion(dep.Version); version != "" {
			return version
		}
	}
	return ""
}

func normalizeModuleVersion(version string) string {
	if version == "" || version == "(devel)" {
		return ""
	}
	return strings.TrimPrefix(version, "v")
}

func CurrentCompatibilityManifest() CompatibilityManifest {
	contracts := make([]ContractArtifact, len(generatedContractArtifacts))
	copy(contracts, generatedContractArtifacts)
	return CompatibilityManifest{
		SchemaVersion: CompatibilityManifestVersion,
		Matrix:        CurrentMatrix(),
		Contracts:     contracts,
	}
}

func DecodeCompatibilityManifest(raw []byte) (CompatibilityManifest, error) {
	var manifest CompatibilityManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return CompatibilityManifest{}, err
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return CompatibilityManifest{}, errors.New("compatibility manifest must contain exactly one JSON document")
	} else if !errors.Is(err, io.EOF) {
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
