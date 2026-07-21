package host

import "github.com/floegence/redevplugin/internal/runtimeclient"

// RuntimeModuleCacheMetrics reports the bounded runtime module cache state.
type RuntimeModuleCacheMetrics struct {
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	Compiles    uint64 `json:"compiles"`
	Entries     int    `json:"entries"`
	SourceBytes int64  `json:"source_bytes"`
}

// RuntimeProcessHealth is the observable state of one admitted runtime process.
type RuntimeProcessHealth struct {
	RuntimeInstanceID   string                    `json:"runtime_instance_id"`
	RuntimeGenerationID string                    `json:"runtime_generation_id"`
	IPCChannelID        string                    `json:"ipc_channel_id,omitempty"`
	ConnectionNonce     string                    `json:"connection_nonce,omitempty"`
	Descriptor          RuntimeDescriptor         `json:"descriptor"`
	Ready               bool                      `json:"ready"`
	ActiveInvocations   int                       `json:"active_invocations"`
	QueuedInvocations   int                       `json:"queued_invocations"`
	Limits              RuntimeLimits             `json:"limits"`
	ModuleCache         RuntimeModuleCacheMetrics `json:"module_cache"`
}

// RuntimeShardHealth identifies one process within the Host-owned runtime module.
type RuntimeShardHealth struct {
	RuntimeShardID string `json:"runtime_shard_id"`
	RuntimeProcessHealth
}

// RuntimeHealth is the Host-owned public runtime health response.
type RuntimeHealth struct {
	Ready      bool                 `json:"ready"`
	Descriptor RuntimeDescriptor    `json:"descriptor"`
	Shards     []RuntimeShardHealth `json:"shards"`
}

type WorkerExecutionError = runtimeclient.WorkerExecutionError
type WorkerErrorOrigin = runtimeclient.WorkerErrorOrigin

const (
	WorkerErrorOriginRuntime  = runtimeclient.WorkerErrorOriginRuntime
	WorkerErrorOriginHostcall = runtimeclient.WorkerErrorOriginHostcall
	WorkerErrorOriginPlugin   = runtimeclient.WorkerErrorOriginPlugin
)

var (
	ErrRuntimeNotReady       = runtimeclient.ErrRuntimeNotReady
	ErrRuntimeIPCUnavailable = runtimeclient.ErrRuntimeIPCUnavailable
	ErrRuntimeRequestFailed  = runtimeclient.ErrRuntimeRequestFailed
	ErrRuntimeHandshake      = runtimeclient.ErrRuntimeHandshake
)

func publicRuntimeHealth(health runtimeclient.ManagerHealth) RuntimeHealth {
	result := RuntimeHealth{
		Ready:      health.Ready,
		Descriptor: publicRuntimeDescriptor(health.Descriptor),
		Shards:     make([]RuntimeShardHealth, 0, len(health.Shards)),
	}
	for _, shard := range health.Shards {
		result.Shards = append(result.Shards, RuntimeShardHealth{
			RuntimeShardID: shard.RuntimeShardID,
			RuntimeProcessHealth: RuntimeProcessHealth{
				RuntimeInstanceID:   shard.RuntimeInstanceID,
				RuntimeGenerationID: shard.RuntimeGenerationID,
				IPCChannelID:        shard.IPCChannelID,
				ConnectionNonce:     shard.ConnectionNonce,
				Descriptor:          publicRuntimeDescriptor(shard.Descriptor),
				Ready:               shard.Ready,
				ActiveInvocations:   shard.ActiveInvocations,
				QueuedInvocations:   shard.QueuedInvocations,
				Limits:              shard.Limits,
				ModuleCache: RuntimeModuleCacheMetrics{
					Hits:        shard.ModuleCache.Hits,
					Misses:      shard.ModuleCache.Misses,
					Compiles:    shard.ModuleCache.Compiles,
					Entries:     shard.ModuleCache.Entries,
					SourceBytes: shard.ModuleCache.SourceBytes,
				},
			},
		})
	}
	return result
}

func publicRuntimeDescriptor(descriptor runtimeclient.RuntimeDescriptor) RuntimeDescriptor {
	target, targetErr := ParseRuntimeAdmissionTarget(descriptor.Target().String())
	ipcVersion, ipcErr := ParseRustIPCVersion(descriptor.RustIPCVersion())
	wasmVersion, wasmErr := ParseWASMABIVersion(descriptor.WASMABIVersion())
	contractDigest, contractErr := ParseSHA256Digest(descriptor.ContractSetSHA256())
	binaryDigest, binaryErr := ParseSHA256Digest(descriptor.BinarySHA256())
	if targetErr != nil || ipcErr != nil || wasmErr != nil || contractErr != nil || binaryErr != nil {
		return RuntimeDescriptor{}
	}
	result, err := NewRuntimeDescriptor(RuntimeDescriptorOptions{
		PlatformVersion:   descriptor.PlatformVersion(),
		Target:            target,
		RustIPCVersion:    ipcVersion,
		WASMABIVersion:    wasmVersion,
		ContractSetSHA256: contractDigest,
		BinarySHA256:      binaryDigest,
	})
	if err != nil {
		return RuntimeDescriptor{}
	}
	return result
}
