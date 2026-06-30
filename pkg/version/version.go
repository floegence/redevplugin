package version

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
				SHA256:  "ac07563a388fd2c8bd25ded126d30d59a3eb47f5e5e8bdd192df50a5443d15e7",
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
