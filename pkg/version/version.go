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
	modulePath                      = "github.com/floegence/redevplugin"
	devVersion                      = "0.0.0-dev"
	developmentCompatibilityVersion = "0.6.11"
)

var (
	GoModuleVersion  = devVersion
	UIPackageVersion = devVersion
	RuntimeVersion   = devVersion

	buildInfoModuleVersion = detectBuildInfoModuleVersion
)

type Matrix struct {
	PluginUIProtocolVersion             string `json:"plugin_ui_protocol_version"`
	PluginHostProtocolVersion           string `json:"plugin_host_protocol_version"`
	RustIPCVersion                      string `json:"rust_ipc_version"`
	WASMABIVersion                      string `json:"wasm_abi_version"`
	ManifestSchemaVersion               string `json:"manifest_schema_version"`
	PackageSignatureSchemaVersion       string `json:"package_signature_schema_version"`
	ReleaseMetadataSchemaVersion        string `json:"release_metadata_schema_version"`
	ReleaseRootDelegationVersion        string `json:"release_root_delegation_schema_version"`
	ReleaseSourcePolicyVersion          string `json:"release_source_policy_schema_version"`
	ReleaseSourcePolicyPointerVersion   string `json:"release_source_policy_pointer_schema_version"`
	ReleaseRevocationVersion            string `json:"release_revocation_schema_version"`
	ReleaseRevocationPointerVersion     string `json:"release_revocation_pointer_schema_version"`
	ReleaseTrustStateVersion            string `json:"release_trust_state_schema_version"`
	TrustedTimeEvidenceVersion          string `json:"trusted_time_evidence_schema_version"`
	TrustedTimeLeafVersion              string `json:"trusted_time_leaf_schema_version"`
	ReleaseSigningLedgerVersion         string `json:"release_signing_ledger_schema_version"`
	ReleaseSigningSubjectVersion        string `json:"release_signing_subject_schema_version"`
	ReleaseSignatureEnvelopeVersion     string `json:"release_signature_envelope_schema_version"`
	ReleaseSigningLedgerReceiptVersion  string `json:"release_signing_ledger_receipt_schema_version"`
	ReleaseSigningLedgerEvidenceVersion string `json:"release_signing_ledger_evidence_schema_version"`
	TokenTicketSchemaVersion            string `json:"token_ticket_schema_version"`
	BridgeSchemaVersion                 string `json:"bridge_schema_version"`
	OpaqueSurfaceDocumentVersion        string `json:"opaque_surface_document_schema_version"`
	OpaqueSurfaceTransportVersion       string `json:"opaque_surface_transport_schema_version"`
	TargetClassifierVersion             string `json:"target_classifier_version"`
	NetworkGrantSchemaVersion           string `json:"network_grant_schema_version"`
	ResourceScopeSchemaVersion          string `json:"resource_scope_schema_version"`
	SessionScopeSchemaVersion           string `json:"session_scope_schema_version"`
	PluginPlatformOpenAPIVersion        string `json:"plugin_platform_openapi_version"`
	CompatibilitySchemaVersion          string `json:"compatibility_schema_version"`
	WorkerInvocationSchemaVersion       string `json:"worker_invocation_schema_version"`
	HostCapabilityContractVersion       string `json:"host_capability_contract_schema_version"`
	HostCapabilityPinVersion            string `json:"host_capability_pin_schema_version"`
	HostCapabilityManifestVersion       string `json:"host_capability_manifest_schema_version"`
	HostCapabilityCompatVersion         string `json:"host_capability_compatibility_schema_version"`
	HostCapabilitySignatureVersion      string `json:"host_capability_signature_schema_version"`
	HostCapabilityNoticesVersion        string `json:"host_capability_notices_schema_version"`
	ErrorCodesSchemaVersion             string `json:"error_codes_schema_version"`
	PerformanceContractVersion          string `json:"performance_contract_version"`
	PerformanceEvidenceVersion          string `json:"performance_evidence_schema_version"`
	ContractRegistryVersion             string `json:"contract_registry_version"`
	PlatformPackageSetVersion           string `json:"platform_package_set_schema_version"`
	PlatformPackagePublicationVersion   string `json:"platform_package_publication_schema_version"`
	RuntimeAdmissionVersion             string `json:"runtime_admission_schema_version"`
	RuntimeDescriptorVersion            string `json:"runtime_descriptor_schema_version"`
	OwnerScopeInventoryRegistryVersion  string `json:"owner_scope_inventory_registry_version"`
	OwnerScopeInventoryVersion          string `json:"owner_scope_inventory_schema_version"`
	OwnerScopeMigrationVersion          string `json:"owner_scope_migration_schema_version"`
	ProcessContainmentVersion           string `json:"process_containment_schema_version"`
	RuntimeExecJournalVersion           string `json:"runtime_exec_journal_schema_version"`
	QuarantineCleanupVersion            string `json:"quarantine_cleanup_schema_version"`
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
		PluginUIProtocolVersion:             PluginUIProtocolVersion,
		PluginHostProtocolVersion:           PluginHostProtocolVersion,
		RustIPCVersion:                      RustIPCVersion,
		WASMABIVersion:                      WASMABIVersion,
		ManifestSchemaVersion:               ManifestSchemaVersion,
		PackageSignatureSchemaVersion:       PackageSignatureSchemaVersion,
		ReleaseMetadataSchemaVersion:        ReleaseMetadataSchemaVersion,
		ReleaseRootDelegationVersion:        ReleaseRootDelegationSchemaVersion,
		ReleaseSourcePolicyVersion:          ReleaseSourcePolicySchemaVersion,
		ReleaseSourcePolicyPointerVersion:   ReleaseSourcePolicyPointerSchemaVersion,
		ReleaseRevocationVersion:            ReleaseRevocationSchemaVersion,
		ReleaseRevocationPointerVersion:     ReleaseRevocationPointerSchemaVersion,
		ReleaseTrustStateVersion:            ReleaseTrustStateSchemaVersion,
		TrustedTimeEvidenceVersion:          TrustedTimeEvidenceSchemaVersion,
		TrustedTimeLeafVersion:              TrustedTimeLeafSchemaVersion,
		ReleaseSigningLedgerVersion:         ReleaseSigningLedgerSchemaVersion,
		ReleaseSigningSubjectVersion:        ReleaseSigningSubjectSchemaVersion,
		ReleaseSignatureEnvelopeVersion:     ReleaseSignatureEnvelopeSchemaVersion,
		ReleaseSigningLedgerReceiptVersion:  ReleaseSigningLedgerReceiptSchemaVersion,
		ReleaseSigningLedgerEvidenceVersion: ReleaseSigningLedgerEvidenceSchemaVersion,
		TokenTicketSchemaVersion:            TokenTicketSchemaVersion,
		BridgeSchemaVersion:                 BridgeSchemaVersion,
		OpaqueSurfaceDocumentVersion:        OpaqueSurfaceDocumentSchemaVersion,
		OpaqueSurfaceTransportVersion:       OpaqueSurfaceTransportSchemaVersion,
		TargetClassifierVersion:             TargetClassifierVersion,
		NetworkGrantSchemaVersion:           NetworkGrantSchemaVersion,
		ResourceScopeSchemaVersion:          ResourceScopeSchemaVersion,
		SessionScopeSchemaVersion:           SessionScopeSchemaVersion,
		PluginPlatformOpenAPIVersion:        PluginPlatformOpenAPIVersion,
		CompatibilitySchemaVersion:          CompatibilitySchemaVersion,
		WorkerInvocationSchemaVersion:       WorkerInvocationSchemaVersion,
		HostCapabilityContractVersion:       HostCapabilityContractSchemaVersion,
		HostCapabilityPinVersion:            HostCapabilityPinSchemaVersion,
		HostCapabilityManifestVersion:       HostCapabilityManifestSchemaVersion,
		HostCapabilityCompatVersion:         HostCapabilityCompatibilitySchemaVersion,
		HostCapabilitySignatureVersion:      HostCapabilitySignatureSchemaVersion,
		HostCapabilityNoticesVersion:        HostCapabilityNoticesSchemaVersion,
		ErrorCodesSchemaVersion:             ErrorCodesSchemaVersion,
		PerformanceContractVersion:          PerformanceContractVersion,
		PerformanceEvidenceVersion:          PerformanceEvidenceSchemaVersion,
		ContractRegistryVersion:             ContractRegistryVersion,
		PlatformPackageSetVersion:           PlatformPackageSetSchemaVersion,
		PlatformPackagePublicationVersion:   PlatformPackagePublicationSchemaVersion,
		RuntimeAdmissionVersion:             RuntimeAdmissionSchemaVersion,
		RuntimeDescriptorVersion:            RuntimeDescriptorSchemaVersion,
		OwnerScopeInventoryRegistryVersion:  OwnerScopeInventoryRegistryVersion,
		OwnerScopeInventoryVersion:          OwnerScopeInventorySchemaVersion,
		OwnerScopeMigrationVersion:          OwnerScopeMigrationSchemaVersion,
		ProcessContainmentVersion:           ProcessContainmentSchemaVersion,
		RuntimeExecJournalVersion:           RuntimeExecJournalSchemaVersion,
		QuarantineCleanupVersion:            QuarantineCleanupSchemaVersion,
	}
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
			{Name: "redevplugin-contracts", Version: version, Role: "contracts"},
			{Name: "redevplugin-ipc", Version: version, Role: "ipc"},
			{Name: "redevplugin-wasm-abi", Version: version, Role: "wasm_abi"},
			{Name: "redevplugin-target-classifier", Version: version, Role: "target_classifier"},
			{Name: "redevplugin-worker-sdk", Version: version, Role: "worker_sdk"},
			{Name: "redevplugin-runtime", Version: version, Role: "runtime"},
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
	return a == b
}
