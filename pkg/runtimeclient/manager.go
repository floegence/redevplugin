package runtimeclient

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	minProcessManagerShards       = 1
	maxProcessManagerShards       = 16
	processManagerRollbackTimeout = 5 * time.Second
)

var (
	ErrRuntimeShardCount              = errors.New("runtime shard count must be between 1 and 16")
	ErrRuntimeBindingInvalid          = errors.New("runtime binding is invalid")
	ErrManagerLifecycleOutcomeUnknown = errors.New("runtime manager lifecycle outcome is unknown")
)

type RuntimeBinding struct {
	RuntimeShardID      string `json:"runtime_shard_id"`
	RuntimeInstanceID   string `json:"runtime_instance_id"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	IPCChannelID        string `json:"ipc_channel_id"`
	ConnectionNonce     string `json:"connection_nonce"`
}

type ShardHealth struct {
	RuntimeShardID string `json:"runtime_shard_id"`
	Health
}

type ManagerHealth struct {
	Ready  bool          `json:"ready"`
	Shards []ShardHealth `json:"shards"`
}

type Manager interface {
	Start(ctx context.Context, target Target) (ManagerHealth, error)
	Stop(ctx context.Context) error
	Health(ctx context.Context) (ManagerHealth, error)
	BindPlugin(ctx context.Context, pluginInstanceID string) (RuntimeBinding, error)
	InvokeWorker(ctx context.Context, binding RuntimeBinding, lease Lease, method string, payload []byte) ([]byte, error)
	Revoke(ctx context.Context, pluginInstanceID string, revokeEpoch uint64) (RevokeResult, error)
}

type ProcessManagerOptions struct {
	ShardCount int
	Supervisor ProcessSupervisorOptions
}

type processShard interface {
	Start(context.Context, Target) error
	Stop(context.Context) error
	Health(context.Context) (Health, error)
	InvokeWorker(context.Context, Lease, string, []byte) ([]byte, error)
	Revoke(context.Context, string, uint64) (RevokeResult, error)
}

type processShardFactory func(ProcessSupervisorOptions) (processShard, error)

type processManagerShard struct {
	id      string
	process processShard
}

type ProcessManager struct {
	lifecycleMu sync.Mutex
	shards      []processManagerShard
}

func NewProcessManager(options ProcessManagerOptions) (*ProcessManager, error) {
	return newProcessManager(options, func(options ProcessSupervisorOptions) (processShard, error) {
		return NewProcessSupervisor(options)
	})
}

func newProcessManager(options ProcessManagerOptions, factory processShardFactory) (*ProcessManager, error) {
	shardCount := options.ShardCount
	if shardCount == 0 {
		shardCount = runtime.NumCPU()
		if shardCount > 4 {
			shardCount = 4
		}
	}
	if shardCount < minProcessManagerShards || shardCount > maxProcessManagerShards {
		return nil, ErrRuntimeShardCount
	}
	if factory == nil {
		return nil, errors.New("runtime shard factory is required")
	}
	manager := &ProcessManager{shards: make([]processManagerShard, 0, shardCount)}
	for index := 0; index < shardCount; index++ {
		process, err := factory(options.Supervisor)
		if err != nil {
			return nil, fmt.Errorf("create runtime shard %d: %w", index, err)
		}
		manager.shards = append(manager.shards, processManagerShard{
			id:      fmt.Sprintf("runtime_shard_%02d", index),
			process: process,
		})
	}
	return manager, nil
}

func (m *ProcessManager) Start(ctx context.Context, target Target) (ManagerHealth, error) {
	if m == nil {
		return ManagerHealth{}, ErrRuntimePathRequired
	}
	if err := ctx.Err(); err != nil {
		return ManagerHealth{}, err
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	started := make([]processManagerShard, 0, len(m.shards))
	for _, shard := range m.shards {
		health, err := shard.process.Health(ctx)
		if err != nil {
			rollbackErr := rollbackProcessShards(started)
			return ManagerHealth{}, managerStartError(
				fmt.Errorf("inspect runtime shard %s before start: %w", shard.id, err),
				rollbackErr,
			)
		}
		if health.Ready {
			continue
		}
		if err := shard.process.Start(ctx, target); err != nil {
			rollbackErr := rollbackProcessShards(started)
			return ManagerHealth{}, managerStartError(
				fmt.Errorf("start runtime shard %s: %w", shard.id, err),
				rollbackErr,
			)
		}
		started = append(started, shard)
	}
	health, err := m.health(ctx)
	if err != nil {
		rollbackErr := rollbackProcessShards(started)
		return ManagerHealth{}, managerStartError(err, rollbackErr)
	}
	if !health.Ready {
		rollbackErr := rollbackProcessShards(started)
		return ManagerHealth{}, managerStartError(ErrRuntimeNotReady, rollbackErr)
	}
	return health, nil
}

func (m *ProcessManager) Stop(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return stopProcessShards(ctx, m.shards)
}

func (m *ProcessManager) Health(ctx context.Context) (ManagerHealth, error) {
	if m == nil {
		return ManagerHealth{}, nil
	}
	return m.health(ctx)
}

func (m *ProcessManager) health(ctx context.Context) (ManagerHealth, error) {
	health := ManagerHealth{
		Ready:  len(m.shards) > 0,
		Shards: make([]ShardHealth, 0, len(m.shards)),
	}
	for _, shard := range m.shards {
		processHealth, err := shard.process.Health(ctx)
		if err != nil {
			return ManagerHealth{}, fmt.Errorf("inspect runtime shard %s: %w", shard.id, err)
		}
		health.Shards = append(health.Shards, ShardHealth{
			RuntimeShardID: shard.id,
			Health:         processHealth,
		})
		health.Ready = health.Ready && processHealth.Ready
	}
	return health, nil
}

func (m *ProcessManager) BindPlugin(ctx context.Context, pluginInstanceID string) (RuntimeBinding, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if m == nil || len(m.shards) == 0 || pluginInstanceID == "" {
		return RuntimeBinding{}, fmt.Errorf("%w: plugin_instance_id is required", ErrRuntimeBindingInvalid)
	}
	shard := m.shards[processShardIndex(pluginInstanceID, len(m.shards))]
	health, err := shard.process.Health(ctx)
	if err != nil {
		return RuntimeBinding{}, fmt.Errorf("inspect runtime shard %s: %w", shard.id, err)
	}
	if err := validateReadyHealth(health); err != nil {
		return RuntimeBinding{}, fmt.Errorf("bind plugin to runtime shard %s: %w", shard.id, err)
	}
	return runtimeBinding(shard.id, health), nil
}

func (m *ProcessManager) InvokeWorker(ctx context.Context, binding RuntimeBinding, lease Lease, method string, payload []byte) ([]byte, error) {
	pluginInstanceID := strings.TrimSpace(lease.PluginInstanceID)
	if m == nil || len(m.shards) == 0 || pluginInstanceID == "" {
		return nil, fmt.Errorf("%w: lease plugin_instance_id is required", ErrRuntimeBindingInvalid)
	}
	shard := m.shards[processShardIndex(pluginInstanceID, len(m.shards))]
	if strings.TrimSpace(binding.RuntimeShardID) != shard.id {
		return nil, fmt.Errorf("%w: plugin is bound to runtime shard %s", ErrRuntimeBindingInvalid, shard.id)
	}
	health, err := shard.process.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime shard %s: %w", shard.id, err)
	}
	if err := validateReadyHealth(health); err != nil {
		return nil, fmt.Errorf("invoke on runtime shard %s: %w", shard.id, err)
	}
	if binding != runtimeBinding(shard.id, health) {
		return nil, fmt.Errorf("%w: runtime shard generation changed", ErrRuntimeBindingInvalid)
	}
	if lease.RuntimeShardID != binding.RuntimeShardID ||
		lease.RuntimeInstanceID != binding.RuntimeInstanceID ||
		lease.RuntimeGenerationID != binding.RuntimeGenerationID ||
		lease.IPCChannelID != binding.IPCChannelID ||
		lease.ConnectionNonce != binding.ConnectionNonce {
		return nil, fmt.Errorf("%w: lease does not match runtime binding", ErrRuntimeBindingInvalid)
	}
	return shard.process.InvokeWorker(ctx, lease, method, payload)
}

func (m *ProcessManager) Revoke(ctx context.Context, pluginInstanceID string, revokeEpoch uint64) (RevokeResult, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if m == nil || len(m.shards) == 0 || pluginInstanceID == "" {
		return RevokeResult{}, fmt.Errorf("%w: plugin_instance_id is required", ErrRuntimeBindingInvalid)
	}
	shard := m.shards[processShardIndex(pluginInstanceID, len(m.shards))]
	health, err := shard.process.Health(ctx)
	if err == nil {
		err = validateReadyHealth(health)
	}
	if err == nil {
		var result RevokeResult
		result, err = shard.process.Revoke(ctx, pluginInstanceID, revokeEpoch)
		if err == nil {
			return result, nil
		}
	}
	revokeErr := err
	stopCtx, cancel := context.WithTimeout(context.Background(), processManagerRollbackTimeout)
	defer cancel()
	if stopErr := shard.process.Stop(stopCtx); stopErr != nil {
		return RevokeResult{}, errors.Join(
			fmt.Errorf("revoke runtime shard %s: %w", shard.id, revokeErr),
			fmt.Errorf("terminate runtime shard %s after revoke failure: %w", shard.id, stopErr),
		)
	}
	return RevokeResult{PluginInstanceID: pluginInstanceID, RevokeEpoch: revokeEpoch, RuntimeStopped: true}, nil
}

func managerStartError(cause error, rollbackErr error) error {
	if rollbackErr == nil {
		return cause
	}
	return errors.Join(ErrManagerLifecycleOutcomeUnknown, cause, rollbackErr)
}

func processShardIndex(pluginInstanceID string, shardCount int) int {
	digest := sha256.Sum256([]byte(pluginInstanceID))
	return int(binary.BigEndian.Uint64(digest[:8]) % uint64(shardCount))
}

func runtimeBinding(shardID string, health Health) RuntimeBinding {
	return RuntimeBinding{
		RuntimeShardID:      shardID,
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		IPCChannelID:        health.IPCChannelID,
		ConnectionNonce:     health.ConnectionNonce,
	}
}

func validateReadyHealth(health Health) error {
	if !health.Ready {
		return ErrRuntimeNotReady
	}
	if strings.TrimSpace(health.RuntimeInstanceID) == "" ||
		strings.TrimSpace(health.RuntimeGenerationID) == "" ||
		strings.TrimSpace(health.IPCChannelID) == "" ||
		strings.TrimSpace(health.ConnectionNonce) == "" {
		return fmt.Errorf("%w: ready shard health is incomplete", ErrRuntimeBindingInvalid)
	}
	return nil
}

func stopProcessShards(ctx context.Context, shards []processManagerShard) error {
	var wait sync.WaitGroup
	errorsByIndex := make([]error, len(shards))
	for index, shard := range shards {
		wait.Add(1)
		go func(index int, shard processManagerShard) {
			defer wait.Done()
			if err := shard.process.Stop(ctx); err != nil {
				errorsByIndex[index] = fmt.Errorf("stop runtime shard %s: %w", shard.id, err)
			}
		}(index, shard)
	}
	wait.Wait()
	return errors.Join(errorsByIndex...)
}

func rollbackProcessShards(shards []processManagerShard) error {
	ctx, cancel := context.WithTimeout(context.Background(), processManagerRollbackTimeout)
	defer cancel()
	return stopProcessShards(ctx, shards)
}
