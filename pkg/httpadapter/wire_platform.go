package httpadapter

import (
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/version"
)

func publicFeatures(features []host.Feature) []string {
	response := make([]string, len(features))
	for index, feature := range features {
		response[index] = string(feature)
	}
	return response
}

type compatibilityMatrixResponse struct {
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

type compatibilityContractResponse struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type compatibilityPackageSetResponse struct {
	SchemaVersion           string                         `json:"schema_version"`
	PlatformVersion         string                         `json:"platform_version"`
	GoModule                version.GoModuleCoordinate     `json:"go_module"`
	NPMPackages             []version.NPMPackageCoordinate `json:"npm_packages"`
	RustCrates              []version.RustCrateCoordinate  `json:"rust_crates"`
	ContractRegistryVersion string                         `json:"contract_registry_version"`
	ContractSetSHA256       string                         `json:"contract_set_sha256"`
}

type compatibilityResponse struct {
	SchemaVersion     string                          `json:"schema_version"`
	PackageSet        compatibilityPackageSetResponse `json:"package_set"`
	Matrix            compatibilityMatrixResponse     `json:"matrix"`
	ContractSetSHA256 string                          `json:"contract_set_sha256"`
	Contracts         []compatibilityContractResponse `json:"contracts"`
}

func publicCompatibility(source version.CompatibilityManifest) compatibilityResponse {
	contracts := make([]compatibilityContractResponse, len(source.Contracts))
	for index, contract := range source.Contracts {
		contracts[index] = compatibilityContractResponse{ID: contract.ID, Path: contract.Path, Version: contract.Version, SHA256: contract.SHA256}
	}
	packageSet := source.PackageSet
	responsePackageSet := compatibilityPackageSetResponse{
		SchemaVersion:           packageSet.SchemaVersion,
		PlatformVersion:         packageSet.PlatformVersion,
		GoModule:                packageSet.GoModule,
		NPMPackages:             append([]version.NPMPackageCoordinate(nil), packageSet.NPMPackages...),
		RustCrates:              append([]version.RustCrateCoordinate(nil), packageSet.RustCrates...),
		ContractRegistryVersion: packageSet.ContractRegistryVersion,
		ContractSetSHA256:       packageSet.ContractSetSHA256,
	}
	matrix := source.Matrix
	return compatibilityResponse{
		SchemaVersion: source.SchemaVersion,
		PackageSet:    responsePackageSet,
		Matrix: compatibilityMatrixResponse{
			PluginUIProtocolVersion: matrix.PluginUIProtocolVersion, PluginHostProtocolVersion: matrix.PluginHostProtocolVersion,
			RustIPCVersion: matrix.RustIPCVersion, WASMABIVersion: matrix.WASMABIVersion,
			ManifestSchemaVersion: matrix.ManifestSchemaVersion, PackageSignatureSchemaVersion: matrix.PackageSignatureSchemaVersion,
			ReleaseMetadataSchemaVersion: matrix.ReleaseMetadataSchemaVersion, ReleaseRootDelegationVersion: matrix.ReleaseRootDelegationVersion,
			ReleaseSourcePolicyVersion: matrix.ReleaseSourcePolicyVersion, ReleaseSourcePolicyPointerVersion: matrix.ReleaseSourcePolicyPointerVersion,
			ReleaseRevocationVersion: matrix.ReleaseRevocationVersion, ReleaseRevocationPointerVersion: matrix.ReleaseRevocationPointerVersion,
			ReleaseTrustStateVersion: matrix.ReleaseTrustStateVersion, TrustedTimeEvidenceVersion: matrix.TrustedTimeEvidenceVersion,
			TrustedTimeLeafVersion: matrix.TrustedTimeLeafVersion, ReleaseSigningLedgerVersion: matrix.ReleaseSigningLedgerVersion,
			ReleaseSigningSubjectVersion: matrix.ReleaseSigningSubjectVersion, ReleaseSignatureEnvelopeVersion: matrix.ReleaseSignatureEnvelopeVersion,
			ReleaseSigningLedgerReceiptVersion: matrix.ReleaseSigningLedgerReceiptVersion, ReleaseSigningLedgerEvidenceVersion: matrix.ReleaseSigningLedgerEvidenceVersion,
			TokenTicketSchemaVersion: matrix.TokenTicketSchemaVersion, BridgeSchemaVersion: matrix.BridgeSchemaVersion,
			OpaqueSurfaceDocumentVersion: matrix.OpaqueSurfaceDocumentVersion, OpaqueSurfaceTransportVersion: matrix.OpaqueSurfaceTransportVersion,
			TargetClassifierVersion: matrix.TargetClassifierVersion, NetworkGrantSchemaVersion: matrix.NetworkGrantSchemaVersion,
			ResourceScopeSchemaVersion: matrix.ResourceScopeSchemaVersion, SessionScopeSchemaVersion: matrix.SessionScopeSchemaVersion,
			PluginPlatformOpenAPIVersion: matrix.PluginPlatformOpenAPIVersion, CompatibilitySchemaVersion: matrix.CompatibilitySchemaVersion,
			WorkerInvocationSchemaVersion: matrix.WorkerInvocationSchemaVersion, HostCapabilityContractVersion: matrix.HostCapabilityContractVersion,
			HostCapabilityPinVersion: matrix.HostCapabilityPinVersion, HostCapabilityManifestVersion: matrix.HostCapabilityManifestVersion,
			HostCapabilityCompatVersion: matrix.HostCapabilityCompatVersion, HostCapabilitySignatureVersion: matrix.HostCapabilitySignatureVersion,
			HostCapabilityNoticesVersion: matrix.HostCapabilityNoticesVersion, ErrorCodesSchemaVersion: matrix.ErrorCodesSchemaVersion,
			PerformanceContractVersion: matrix.PerformanceContractVersion, PerformanceEvidenceVersion: matrix.PerformanceEvidenceVersion,
			ContractRegistryVersion: matrix.ContractRegistryVersion, PlatformPackageSetVersion: matrix.PlatformPackageSetVersion,
			PlatformPackagePublicationVersion: matrix.PlatformPackagePublicationVersion, RuntimeAdmissionVersion: matrix.RuntimeAdmissionVersion,
			RuntimeDescriptorVersion: matrix.RuntimeDescriptorVersion, OwnerScopeInventoryRegistryVersion: matrix.OwnerScopeInventoryRegistryVersion,
			OwnerScopeInventoryVersion: matrix.OwnerScopeInventoryVersion, OwnerScopeMigrationVersion: matrix.OwnerScopeMigrationVersion,
			ProcessContainmentVersion: matrix.ProcessContainmentVersion, RuntimeExecJournalVersion: matrix.RuntimeExecJournalVersion,
			QuarantineCleanupVersion: matrix.QuarantineCleanupVersion,
		},
		ContractSetSHA256: source.ContractSetSHA256,
		Contracts:         contracts,
	}
}
