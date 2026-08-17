package host

import "github.com/floegence/redevplugin/v3/internal/runtimeclient"

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
	ArtifactIdentity    RuntimeArtifactIdentity   `json:"artifact_identity"`
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
	Ready            bool                    `json:"ready"`
	ArtifactIdentity RuntimeArtifactIdentity `json:"artifact_identity"`
	Shards           []RuntimeShardHealth    `json:"shards"`
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
		Ready:            health.Ready,
		ArtifactIdentity: publicRuntimeArtifactIdentity(health.ArtifactIdentity),
		Shards:           make([]RuntimeShardHealth, 0, len(health.Shards)),
	}
	for _, shard := range health.Shards {
		result.Shards = append(result.Shards, RuntimeShardHealth{
			RuntimeShardID: shard.RuntimeShardID,
			RuntimeProcessHealth: RuntimeProcessHealth{
				RuntimeInstanceID:   shard.RuntimeInstanceID,
				RuntimeGenerationID: shard.RuntimeGenerationID,
				IPCChannelID:        shard.IPCChannelID,
				ConnectionNonce:     shard.ConnectionNonce,
				ArtifactIdentity:    publicRuntimeArtifactIdentity(shard.ArtifactIdentity),
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

func publicRuntimeArtifactIdentity(identity runtimeclient.RuntimeArtifactIdentity) RuntimeArtifactIdentity {
	binaryDigest, binaryErr := ParseSHA256Digest(identity.BinarySHA256())
	if binaryErr != nil {
		return RuntimeArtifactIdentity{}
	}
	result, err := NewRuntimeArtifactIdentity(RuntimeArtifactIdentityOptions{
		PlatformVersion: identity.PlatformVersion(),
		Target:          identity.Target(),
		BinarySHA256:    binaryDigest,
	})
	if err != nil {
		return RuntimeArtifactIdentity{}
	}
	return result
}
