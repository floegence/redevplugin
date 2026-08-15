package version

// PublicAPICatalog describes only plugin-observable compatibility. Internal
// IPC, OpenAPI, database, and contract-set versions intentionally do not
// appear here.
type PublicAPICatalog struct {
	SchemaVersion    string                 `json:"schema_version"`
	SurfaceAPIMajors []uint16               `json:"surface_api_majors"`
	WorkerAPIMajors  []uint16               `json:"worker_api_majors"`
	Features         []string               `json:"features"`
	Permissions      []string               `json:"permissions"`
	StableErrorCodes []string               `json:"stable_error_codes"`
	MinimumResources PublicMinimumResources `json:"minimum_resources"`
}

type PublicMinimumResources struct {
	ControlResponseBytes int64 `json:"control_response_bytes"`
	IOChunkBytes         int64 `json:"io_chunk_bytes"`
	OpenFiles            int64 `json:"open_files"`
	OpenConnections      int64 `json:"open_connections"`
	OpenWatches          int64 `json:"open_watches"`
}

func CurrentPublicAPICatalog() PublicAPICatalog {
	return PublicAPICatalog{
		SchemaVersion:    "redevplugin.public_api.v1",
		SurfaceAPIMajors: []uint16{1},
		WorkerAPIMajors:  []uint16{1},
		Features:         []string{"fs.environment.v1", "fs.home.v1", "fs.watch.v1", "fs.workspace.v1", "io.stream.v1", "net.http.v1", "net.tcp.v1", "net.udp.v1", "net.websocket.v1"},
		Permissions:      []string{"fs.environment.read", "fs.environment.write", "fs.home.read", "fs.home.write", "fs.workspace.read", "fs.workspace.write", "network.client", "network.listen"},
		StableErrorCodes: []string{"ALREADY_EXISTS", "CANCELED", "CROSS_DEVICE", "INTERNAL", "INVALID_ARGUMENT", "IO_ERROR", "MOUNT_UNAVAILABLE", "NETWORK_ERROR", "NOT_EMPTY", "NOT_FOUND", "PERMISSION_DENIED", "REDIRECT_REQUIRES_REPLAY", "RESOURCE_CLOSED", "RESOURCE_LIMIT", "RUNTIME_UNAVAILABLE", "SECURITY_INCOMPATIBLE", "TIMEOUT", "UNSUPPORTED_FEATURE", "WOULD_BLOCK"},
		MinimumResources: PublicMinimumResources{ControlResponseBytes: 65536, IOChunkBytes: 65536, OpenFiles: 64, OpenConnections: 32, OpenWatches: 8},
	}
}
