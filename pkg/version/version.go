package version

const (
	GoModuleVersion              = "0.0.0-dev"
	UIPackageVersion             = "0.0.0-dev"
	RuntimeVersion               = "0.0.0-dev"
	PluginHostProtocolVersion    = "plugin-host-v1"
	RustIPCVersion               = "rust-ipc-v1"
	WASMABIVersion               = "redeven-wasm-worker-v1"
	ManifestSchemaVersion        = "manifest-v1"
	TokenTicketSchemaVersion     = "token-ticket-v1"
	TargetClassifierVersion      = "target-classifier-v1"
	PluginPlatformOpenAPIVersion = "plugin-platform-v1"
)

type Matrix struct {
	GoModuleVersion              string `json:"redevplugin_go_version"`
	UIPackageVersion             string `json:"redevplugin_ui_version"`
	RuntimeVersion               string `json:"redevplugin_runtime_version"`
	PluginHostProtocolVersion    string `json:"plugin_host_protocol_version"`
	RustIPCVersion               string `json:"rust_ipc_version"`
	WASMABIVersion               string `json:"wasm_abi_version"`
	ManifestSchemaVersion        string `json:"manifest_schema_version"`
	TokenTicketSchemaVersion     string `json:"token_ticket_schema_version"`
	TargetClassifierVersion      string `json:"target_classifier_version"`
	PluginPlatformOpenAPIVersion string `json:"plugin_platform_openapi_version"`
}

func CurrentMatrix() Matrix {
	return Matrix{
		GoModuleVersion:              GoModuleVersion,
		UIPackageVersion:             UIPackageVersion,
		RuntimeVersion:               RuntimeVersion,
		PluginHostProtocolVersion:    PluginHostProtocolVersion,
		RustIPCVersion:               RustIPCVersion,
		WASMABIVersion:               WASMABIVersion,
		ManifestSchemaVersion:        ManifestSchemaVersion,
		TokenTicketSchemaVersion:     TokenTicketSchemaVersion,
		TargetClassifierVersion:      TargetClassifierVersion,
		PluginPlatformOpenAPIVersion: PluginPlatformOpenAPIVersion,
	}
}
