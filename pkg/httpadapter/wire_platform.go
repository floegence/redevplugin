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

type compatibilityContractResponse struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type compatibilityResponse struct {
	SchemaVersion string                          `json:"schema_version"`
	Matrix        compatibilityMatrixResponse     `json:"matrix"`
	Contracts     []compatibilityContractResponse `json:"contracts"`
}

func publicCompatibility(source version.CompatibilityManifest) compatibilityResponse {
	matrix := source.Matrix
	contracts := make([]compatibilityContractResponse, len(source.Contracts))
	for index, contract := range source.Contracts {
		contracts[index] = compatibilityContractResponse{
			ID: contract.ID, Path: contract.Path, Version: contract.Version, SHA256: contract.SHA256,
		}
	}
	return compatibilityResponse{
		SchemaVersion: source.SchemaVersion,
		Matrix: compatibilityMatrixResponse{
			GoModuleVersion: matrix.GoModuleVersion, UIPackageVersion: matrix.UIPackageVersion,
			RuntimeVersion: matrix.RuntimeVersion, PluginUIProtocolVersion: matrix.PluginUIProtocolVersion,
			PluginHostProtocolVersion: matrix.PluginHostProtocolVersion, RustIPCVersion: matrix.RustIPCVersion,
			WASMABIVersion: matrix.WASMABIVersion, ManifestSchemaVersion: matrix.ManifestSchemaVersion,
			PackageSignatureSchemaVersion:  matrix.PackageSignatureSchemaVersion,
			ReleaseMetadataSchemaVersion:   matrix.ReleaseMetadataSchemaVersion,
			SourcePolicySchemaVersion:      matrix.SourcePolicySchemaVersion,
			SourceRevocationsSchemaVersion: matrix.SourceRevocationsSchemaVersion,
			TokenTicketSchemaVersion:       matrix.TokenTicketSchemaVersion, BridgeSchemaVersion: matrix.BridgeSchemaVersion,
			OpaqueSurfaceDocumentVersion:  matrix.OpaqueSurfaceDocumentVersion,
			OpaqueSurfaceTransportVersion: matrix.OpaqueSurfaceTransportVersion,
			TargetClassifierVersion:       matrix.TargetClassifierVersion, NetworkGrantSchemaVersion: matrix.NetworkGrantSchemaVersion,
			ResourceScopeSchemaVersion:     matrix.ResourceScopeSchemaVersion,
			SessionScopeSchemaVersion:      matrix.SessionScopeSchemaVersion,
			PluginPlatformOpenAPIVersion:   matrix.PluginPlatformOpenAPIVersion,
			CompatibilitySchemaVersion:     matrix.CompatibilitySchemaVersion,
			ReleaseManifestSchemaVersion:   matrix.ReleaseManifestSchemaVersion,
			WorkerInvocationSchemaVersion:  matrix.WorkerInvocationSchemaVersion,
			HostCapabilityContractVersion:  matrix.HostCapabilityContractVersion,
			HostCapabilityPinVersion:       matrix.HostCapabilityPinVersion,
			HostCapabilityManifestVersion:  matrix.HostCapabilityManifestVersion,
			HostCapabilityCompatVersion:    matrix.HostCapabilityCompatVersion,
			HostCapabilitySignatureVersion: matrix.HostCapabilitySignatureVersion,
			HostCapabilityNoticesVersion:   matrix.HostCapabilityNoticesVersion,
			ErrorCodesSchemaVersion:        matrix.ErrorCodesSchemaVersion,
			PerformanceContractVersion:     matrix.PerformanceContractVersion,
			PerformanceEvidenceVersion:     matrix.PerformanceEvidenceVersion,
			ContractRegistryVersion:        matrix.ContractRegistryVersion,
		},
		Contracts: contracts,
	}
}
