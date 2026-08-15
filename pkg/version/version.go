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
	"reflect"
	"runtime/debug"
	"strings"
)

const (
	modulePath                      = "github.com/floegence/redevplugin/v2"
	devVersion                      = "0.0.0-dev"
	developmentCompatibilityVersion = "2.0.2"
)

var (
	GoModuleVersion  = devVersion
	UIPackageVersion = devVersion
	RuntimeVersion   = devVersion

	buildInfoModuleVersion = detectBuildInfoModuleVersion
)

type Matrix struct {
	PluginUIProtocolVersion            string                     `json:"plugin_ui_protocol_version"`
	SupportedPluginUIProtocolVersions  []string                   `json:"supported_plugin_ui_protocol_versions"`
	PluginUITransportMappings          []PluginUITransportMapping `json:"plugin_ui_transport_mappings"`
	PluginHostProtocolVersion          string                     `json:"plugin_host_protocol_version"`
	RustIPCVersion                     string                     `json:"rust_ipc_version"`
	WASMABIVersion                     string                     `json:"wasm_abi_version"`
	ManifestSchemaVersion              string                     `json:"manifest_schema_version"`
	PackageSignatureSchemaVersion      string                     `json:"package_signature_schema_version"`
	ReleaseMetadataSchemaVersion       string                     `json:"release_metadata_schema_version"`
	ReleaseRootDelegationVersion       string                     `json:"release_root_delegation_schema_version"`
	ReleaseSourcePolicyVersion         string                     `json:"release_source_policy_schema_version"`
	ReleaseSourcePolicyPointerVersion  string                     `json:"release_source_policy_pointer_schema_version"`
	ReleaseRevocationVersion           string                     `json:"release_revocation_schema_version"`
	ReleaseRevocationPointerVersion    string                     `json:"release_revocation_pointer_schema_version"`
	TokenTicketSchemaVersion           string                     `json:"token_ticket_schema_version"`
	BridgeSchemaVersion                string                     `json:"bridge_schema_version"`
	OpaqueSurfaceDocumentVersion       string                     `json:"opaque_surface_document_schema_version"`
	OpaqueSurfaceTransportVersion      string                     `json:"opaque_surface_transport_schema_version"`
	TargetClassifierVersion            string                     `json:"target_classifier_version"`
	NetworkGrantSchemaVersion          string                     `json:"network_grant_schema_version"`
	ResourceScopeSchemaVersion         string                     `json:"resource_scope_schema_version"`
	SessionScopeSchemaVersion          string                     `json:"session_scope_schema_version"`
	PluginPlatformOpenAPIVersion       string                     `json:"plugin_platform_openapi_version"`
	PublicAPICatalogVersion            string                     `json:"public_api_catalog_version"`
	CompatibilitySchemaVersion         string                     `json:"compatibility_schema_version"`
	WorkerInvocationSchemaVersion      string                     `json:"worker_invocation_schema_version"`
	HostCapabilityContractVersion      string                     `json:"host_capability_contract_schema_version"`
	HostCapabilityPinVersion           string                     `json:"host_capability_pin_schema_version"`
	ErrorCodesSchemaVersion            string                     `json:"error_codes_schema_version"`
	PerformanceContractVersion         string                     `json:"performance_contract_version"`
	PerformanceEvidenceVersion         string                     `json:"performance_evidence_schema_version"`
	ContractRegistryVersion            string                     `json:"contract_registry_version"`
	PlatformPackageSetVersion          string                     `json:"platform_package_set_schema_version"`
	PlatformPackagePublicationVersion  string                     `json:"platform_package_publication_schema_version"`
	RuntimeAdmissionVersion            string                     `json:"runtime_admission_schema_version"`
	RuntimeDescriptorVersion           string                     `json:"runtime_descriptor_schema_version"`
	OwnerScopeInventoryRegistryVersion string                     `json:"owner_scope_inventory_registry_version"`
	OwnerScopeInventoryVersion         string                     `json:"owner_scope_inventory_schema_version"`
	OwnerScopeMigrationVersion         string                     `json:"owner_scope_migration_schema_version"`
	OwnerScopeRootRecoveryVersion      string                     `json:"owner_scope_root_recovery_schema_version"`
	ProcessContainmentVersion          string                     `json:"process_containment_schema_version"`
	RuntimeExecJournalVersion          string                     `json:"runtime_exec_journal_schema_version"`
	QuarantineCleanupVersion           string                     `json:"quarantine_cleanup_schema_version"`
}

type PluginUITransportMapping struct {
	PluginUIProtocolVersion             string `json:"plugin_ui_protocol_version"`
	OpaqueSurfaceTransportSchemaVersion string `json:"opaque_surface_transport_schema_version"`
	BridgeSchemaVersion                 string `json:"bridge_schema_version"`
}

type ContractArtifact struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type CompatibilityManifest struct {
	SchemaVersion     string             `json:"schema_version"`
	PackageSet        PlatformPackageSet `json:"package_set"`
	Matrix            Matrix             `json:"matrix"`
	ContractSetSHA256 string             `json:"contract_set_sha256"`
	Contracts         []ContractArtifact `json:"contracts"`
}

type PlatformPackageSet struct {
	SchemaVersion           string                 `json:"schema_version"`
	PlatformVersion         string                 `json:"platform_version"`
	GoModule                GoModuleCoordinate     `json:"go_module"`
	NPMPackages             []NPMPackageCoordinate `json:"npm_packages"`
	RustCrates              []RustCrateCoordinate  `json:"rust_crates"`
	ContractRegistryVersion string                 `json:"contract_registry_version"`
	ContractSetSHA256       string                 `json:"contract_set_sha256"`
}

type GoModuleCoordinate struct {
	Module  string `json:"module"`
	Version string `json:"version"`
}
type NPMPackageCoordinate struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type RustCrateCoordinate struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Role    string `json:"role"`
}

var (
	ErrCompatibilitySchemaVersion = errors.New("compatibility manifest schema version mismatch")
	ErrCompatibilityMatrix        = errors.New("compatibility manifest version matrix mismatch")
	ErrCompatibilityContract      = errors.New("compatibility manifest contract mismatch")
	ErrCompatibilityPath          = errors.New("compatibility manifest contract path is invalid")
)

func CurrentMatrix() Matrix {
	return Matrix{
		PluginUIProtocolVersion:           PluginUIProtocolVersion,
		SupportedPluginUIProtocolVersions: []string{"plugin-ui-v7"},
		PluginUITransportMappings: []PluginUITransportMapping{
			{PluginUIProtocolVersion: "plugin-ui-v7", OpaqueSurfaceTransportSchemaVersion: "opaque-surface-transport-v6", BridgeSchemaVersion: "bridge-v7"},
		},
		PluginHostProtocolVersion:          PluginHostProtocolVersion,
		RustIPCVersion:                     RustIPCVersion,
		WASMABIVersion:                     WASMABIVersion,
		ManifestSchemaVersion:              ManifestSchemaVersion,
		PackageSignatureSchemaVersion:      PackageSignatureSchemaVersion,
		ReleaseMetadataSchemaVersion:       ReleaseMetadataSchemaVersion,
		ReleaseRootDelegationVersion:       ReleaseRootDelegationSchemaVersion,
		ReleaseSourcePolicyVersion:         ReleaseSourcePolicySchemaVersion,
		ReleaseSourcePolicyPointerVersion:  ReleaseSourcePolicyPointerSchemaVersion,
		ReleaseRevocationVersion:           ReleaseRevocationSchemaVersion,
		ReleaseRevocationPointerVersion:    ReleaseRevocationPointerSchemaVersion,
		TokenTicketSchemaVersion:           TokenTicketSchemaVersion,
		BridgeSchemaVersion:                BridgeSchemaVersion,
		OpaqueSurfaceDocumentVersion:       OpaqueSurfaceDocumentSchemaVersion,
		OpaqueSurfaceTransportVersion:      OpaqueSurfaceTransportSchemaVersion,
		TargetClassifierVersion:            TargetClassifierVersion,
		NetworkGrantSchemaVersion:          NetworkGrantSchemaVersion,
		ResourceScopeSchemaVersion:         ResourceScopeSchemaVersion,
		SessionScopeSchemaVersion:          SessionScopeSchemaVersion,
		PluginPlatformOpenAPIVersion:       PluginPlatformOpenAPIVersion,
		PublicAPICatalogVersion:            PublicAPICatalogVersion,
		CompatibilitySchemaVersion:         CompatibilitySchemaVersion,
		WorkerInvocationSchemaVersion:      WorkerInvocationSchemaVersion,
		HostCapabilityContractVersion:      HostCapabilityContractSchemaVersion,
		HostCapabilityPinVersion:           HostCapabilityPinSchemaVersion,
		ErrorCodesSchemaVersion:            ErrorCodesSchemaVersion,
		PerformanceContractVersion:         PerformanceContractVersion,
		PerformanceEvidenceVersion:         PerformanceEvidenceSchemaVersion,
		ContractRegistryVersion:            ContractRegistryVersion,
		PlatformPackageSetVersion:          PlatformPackageSetSchemaVersion,
		PlatformPackagePublicationVersion:  PlatformPackagePublicationSchemaVersion,
		RuntimeAdmissionVersion:            RuntimeAdmissionSchemaVersion,
		RuntimeDescriptorVersion:           RuntimeDescriptorSchemaVersion,
		OwnerScopeInventoryRegistryVersion: OwnerScopeInventoryRegistryVersion,
		OwnerScopeInventoryVersion:         OwnerScopeInventorySchemaVersion,
		OwnerScopeMigrationVersion:         OwnerScopeMigrationSchemaVersion,
		OwnerScopeRootRecoveryVersion:      OwnerScopeRootRecoverySchemaVersion,
		ProcessContainmentVersion:          ProcessContainmentSchemaVersion,
		RuntimeExecJournalVersion:          RuntimeExecJournalSchemaVersion,
		QuarantineCleanupVersion:           QuarantineCleanupSchemaVersion,
	}
}

func SupportsPluginUIProtocol(protocolVersion string) bool {
	for _, supported := range CurrentMatrix().SupportedPluginUIProtocolVersions {
		if protocolVersion == supported {
			return true
		}
	}
	return false
}

func CurrentCompatibilityVersion() string {
	version := resolvedReleaseVersion(GoModuleVersion)
	if version == devVersion {
		return developmentCompatibilityVersion
	}
	return version
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
		SchemaVersion:     CompatibilityManifestVersion,
		PackageSet:        currentPlatformPackageSet(),
		Matrix:            CurrentMatrix(),
		ContractSetSHA256: ContractSetSHA256,
		Contracts:         contracts,
	}
}

func currentPlatformPackageSet() PlatformPackageSet {
	version := CurrentCompatibilityVersion()
	return PlatformPackageSet{
		SchemaVersion:   PlatformPackageSetSchemaVersion,
		PlatformVersion: version,
		GoModule:        GoModuleCoordinate{Module: modulePath, Version: "v" + version},
		NPMPackages: []NPMPackageCoordinate{
			{Name: "@floegence/redevplugin-contracts", Version: version},
			{Name: "@floegence/redevplugin-ui", Version: version},
		},
		RustCrates: []RustCrateCoordinate{
			{Name: "redevplugin-runtime", Version: version, Role: "runtime"},
			{Name: "redevplugin-worker-sdk", Version: version, Role: "worker_sdk"},
		},
		ContractRegistryVersion: ContractRegistryVersion,
		ContractSetSHA256:       ContractSetSHA256,
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
	if manifest.ContractSetSHA256 != expected.ContractSetSHA256 ||
		manifest.PackageSet.ContractSetSHA256 != expected.ContractSetSHA256 ||
		!reflect.DeepEqual(manifest.PackageSet, expected.PackageSet) {
		return fmt.Errorf("%w: package set or contract digest mismatch", ErrCompatibilityMatrix)
	}
	if len(manifest.Contracts) != len(expected.Contracts) {
		return fmt.Errorf("%w: contract count mismatch", ErrCompatibilityContract)
	}

	for index, contract := range manifest.Contracts {
		expectedContract := expected.Contracts[index]
		if contract.Path != expectedContract.Path || contract.Version != expectedContract.Version || contract.SHA256 != expectedContract.SHA256 {
			return fmt.Errorf("%w: contract %q metadata mismatch", ErrCompatibilityContract, contract.ID)
		}
		if contract.ID != expectedContract.ID {
			return fmt.Errorf("%w: contract order mismatch at %d", ErrCompatibilityContract, index)
		}
		if err := verifyContractArtifactHash(artifactRoot, contract); err != nil {
			return err
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
	return reflect.DeepEqual(a, b)
}
