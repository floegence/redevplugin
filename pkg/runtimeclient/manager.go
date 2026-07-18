package runtimeclient

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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
	// ErrRuntimeShardCount reports a ProcessManager shard count outside the
	// closed supported range.
	ErrRuntimeShardCount = errors.New("runtime shard count must be between 1 and 16")
	// ErrRuntimeBindingInvalid reports a plugin, lease, or generation binding
	// that does not identify the manager's current runtime shard.
	ErrRuntimeBindingInvalid = errors.New("runtime binding is invalid")
	// ErrManagerLifecycleOutcomeUnknown reports a failed manager transition
	// whose rollback also failed, so the caller must reconcile shard health.
	ErrManagerLifecycleOutcomeUnknown = errors.New("runtime manager lifecycle outcome is unknown")
	// ErrRuntimeHostServicesInvalid reports an incomplete or typed-nil set of
	// callbacks supplied at the Host/runtime ownership boundary.
	ErrRuntimeHostServicesInvalid = errors.New("runtime host services are invalid")
	// ErrRuntimeHostServicesRequired reports an operation attempted before the
	// manager completed its one-time Host-services binding.
	ErrRuntimeHostServicesRequired = errors.New("runtime host services are not bound")
	// ErrRuntimeHostServicesBound reports an attempt to replace Host services
	// after a successful binding. A successfully bound manager is never reusable
	// by another Host.
	ErrRuntimeHostServicesBound = errors.New("runtime host services are already bound")
)

// RuntimeHostServices is the complete callback set a Host transfers to a
// Manager before any runtime shard can be created or started. BindHostServices
// captures these interface values for the lifetime of the manager.
type RuntimeHostServices struct {
	StreamSink RuntimeStreamSink
}

type RuntimeBinding struct {
	RuntimeShardID      string            `json:"runtime_shard_id"`
	RuntimeInstanceID   string            `json:"runtime_instance_id"`
	RuntimeGenerationID string            `json:"runtime_generation_id"`
	IPCChannelID        string            `json:"ipc_channel_id"`
	ConnectionNonce     string            `json:"connection_nonce"`
	Descriptor          RuntimeDescriptor `json:"descriptor"`
}

type ShardHealth struct {
	RuntimeShardID string `json:"runtime_shard_id"`
	Health
}

type ManagerHealth struct {
	Ready      bool              `json:"ready"`
	Descriptor RuntimeDescriptor `json:"descriptor"`
	Shards     []ShardHealth     `json:"shards"`
}

// Manager owns the runtime shard lifecycle for exactly one Host. A new Manager
// starts unbound. BindHostServices must succeed before every other operation;
// failed binding may be retried, while successful binding is permanent. The
// concrete ProcessManager serializes binding and lifecycle transitions.
type Manager interface {
	// BindHostServices validates and atomically installs the Host callbacks used
	// by every shard. Concurrent calls are serialized. A failed call leaves the
	// manager unbound and retryable; a successful call makes every later call
	// return ErrRuntimeHostServicesBound.
	BindHostServices(services RuntimeHostServices) error
	Preflight(ctx context.Context, target Target) (RuntimeDescriptor, error)
	Start(ctx context.Context, target Target) (ManagerHealth, error)
	Stop(ctx context.Context) error
	Health(ctx context.Context) (ManagerHealth, error)
	BindPlugin(ctx context.Context, pluginInstanceID string) (RuntimeBinding, error)
	InvokeWorker(ctx context.Context, binding RuntimeBinding, lease Lease, method string, payload []byte) ([]byte, error)
	Revoke(ctx context.Context, req RevokeRequest) (RevokeResult, error)
}

// ProcessManagerOptions configures a ProcessManager. ShardCount and all
// supervisor runtime limits are explicit; Supervisor.StreamSink must remain
// unset because the owning Host supplies it through BindHostServices.
type ProcessManagerOptions struct {
	ShardCount int
	Supervisor ProcessSupervisorOptions
}

type processShard interface {
	Preflight(context.Context, Target) (RuntimeDescriptor, error)
	Start(context.Context, Target) error
	Stop(context.Context) error
	Health(context.Context) (Health, error)
	InvokeWorker(context.Context, Lease, string, []byte) ([]byte, error)
	Revoke(context.Context, RevokeRequest) (RevokeResult, error)
}

type processShardFactory func(ProcessSupervisorOptions) (processShard, error)

type processManagerShard struct {
	id      string
	process processShard
}

// ProcessManager implements Manager with a fixed set of runtime process shards.
// Its lifecycle mutex makes Host binding, start, stop, and health transitions a
// single ordered state machine.
type ProcessManager struct {
	lifecycleMu sync.Mutex
	shardCount  int
	supervisor  ProcessSupervisorOptions
	factory     processShardFactory
	bound       bool
	shards      []processManagerShard
}

// NewProcessManager creates an unbound manager without creating runtime shards.
func NewProcessManager(options ProcessManagerOptions) (*ProcessManager, error) {
	return newProcessManager(options, func(options ProcessSupervisorOptions) (processShard, error) {
		return NewProcessSupervisor(options)
	})
}

func newProcessManager(options ProcessManagerOptions, factory processShardFactory) (*ProcessManager, error) {
	shardCount := options.ShardCount
	if shardCount < minProcessManagerShards || shardCount > maxProcessManagerShards {
		return nil, ErrRuntimeShardCount
	}
	if factory == nil {
		return nil, errors.New("runtime shard factory is required")
	}
	if options.Supervisor.StreamSink != nil {
		return nil, fmt.Errorf("%w: stream sink must be supplied by BindHostServices", ErrRuntimeHostServicesInvalid)
	}
	if err := validateProcessSupervisorOptions(options.Supervisor, false); err != nil {
		return nil, err
	}
	options.Supervisor.Args = append([]string(nil), options.Supervisor.Args...)
	options.Supervisor.Env = append([]string(nil), options.Supervisor.Env...)
	return &ProcessManager{
		shardCount: shardCount,
		supervisor: options.Supervisor,
		factory:    factory,
	}, nil
}

// BindHostServices installs one Host's services and creates the fixed shard
// set. Validation or shard construction failure leaves the manager unbound so
// the caller can retry. Once this method succeeds, services are immutable and
// every later binding attempt returns ErrRuntimeHostServicesBound.
func (m *ProcessManager) BindHostServices(services RuntimeHostServices) error {
	if m == nil {
		return ErrRuntimeHostServicesRequired
	}
	if isNilInterfaceValue(services.StreamSink) {
		return fmt.Errorf("%w: stream sink is required", ErrRuntimeHostServicesInvalid)
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.bound {
		return ErrRuntimeHostServicesBound
	}
	options := m.supervisor
	options.StreamSink = services.StreamSink
	shards := make([]processManagerShard, 0, m.shardCount)
	for index := 0; index < m.shardCount; index++ {
		process, err := m.factory(options)
		if err != nil {
			return fmt.Errorf("create runtime shard %d: %w", index, err)
		}
		shards = append(shards, processManagerShard{
			id:      fmt.Sprintf("runtime_shard_%02d", index),
			process: process,
		})
	}
	m.shards = shards
	m.bound = true
	return nil
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
	if !m.bound {
		return ManagerHealth{}, ErrRuntimeHostServicesRequired
	}
	descriptor, err := m.preflight(ctx, target)
	if err != nil {
		return ManagerHealth{}, err
	}

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
			if health.Descriptor != descriptor {
				rollbackErr := rollbackProcessShards(started)
				return ManagerHealth{}, managerStartError(ErrRuntimeDescriptorMismatch, rollbackErr)
			}
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
	if health.Descriptor != descriptor {
		rollbackErr := rollbackProcessShards(started)
		return ManagerHealth{}, managerStartError(ErrRuntimeDescriptorMismatch, rollbackErr)
	}
	return health, nil
}

func (m *ProcessManager) Preflight(ctx context.Context, target Target) (RuntimeDescriptor, error) {
	if m == nil {
		return RuntimeDescriptor{}, ErrRuntimePathRequired
	}
	if err := ctx.Err(); err != nil {
		return RuntimeDescriptor{}, err
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if !m.bound {
		return RuntimeDescriptor{}, ErrRuntimeHostServicesRequired
	}
	return m.preflight(ctx, target)
}

func (m *ProcessManager) preflight(ctx context.Context, target Target) (RuntimeDescriptor, error) {
	if err := ValidateTarget(target); err != nil {
		return RuntimeDescriptor{}, err
	}
	var expected RuntimeDescriptor
	for _, shard := range m.shards {
		descriptor, err := shard.process.Preflight(ctx, target)
		if err != nil {
			return RuntimeDescriptor{}, fmt.Errorf("preflight runtime shard %s: %w", shard.id, err)
		}
		if descriptor.Target() != target {
			return RuntimeDescriptor{}, fmt.Errorf("%w: runtime shard %s target", ErrRuntimeDescriptorMismatch, shard.id)
		}
		if err := descriptor.CompatibleWithPlatform(); err != nil {
			return RuntimeDescriptor{}, fmt.Errorf("preflight runtime shard %s: %w", shard.id, err)
		}
		if expected.Version().String() == "" {
			expected = descriptor
			continue
		}
		if descriptor != expected {
			return RuntimeDescriptor{}, fmt.Errorf("%w: runtime shard %s", ErrRuntimeDescriptorMismatch, shard.id)
		}
	}
	if expected.Version().String() == "" {
		return RuntimeDescriptor{}, ErrRuntimeNotReady
	}
	return expected, nil
}

func (m *ProcessManager) Stop(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if !m.bound {
		return ErrRuntimeHostServicesRequired
	}
	return stopProcessShards(ctx, m.shards)
}

func (m *ProcessManager) Health(ctx context.Context) (ManagerHealth, error) {
	if m == nil {
		return ManagerHealth{}, nil
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if !m.bound {
		return ManagerHealth{}, ErrRuntimeHostServicesRequired
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
	if len(health.Shards) != 0 {
		health.Descriptor = health.Shards[0].Descriptor
		for _, shard := range health.Shards[1:] {
			if shard.Descriptor != health.Descriptor {
				return ManagerHealth{}, fmt.Errorf("%w: runtime shard %s health", ErrRuntimeDescriptorMismatch, shard.RuntimeShardID)
			}
		}
	}
	return health, nil
}

func (m *ProcessManager) BindPlugin(ctx context.Context, pluginInstanceID string) (RuntimeBinding, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	shards, err := m.boundShards()
	if err != nil {
		return RuntimeBinding{}, err
	}
	if pluginInstanceID == "" {
		return RuntimeBinding{}, fmt.Errorf("%w: plugin_instance_id is required", ErrRuntimeBindingInvalid)
	}
	shard := shards[processShardIndex(pluginInstanceID, len(shards))]
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
	shards, err := m.boundShards()
	if err != nil {
		return nil, err
	}
	if pluginInstanceID == "" {
		return nil, fmt.Errorf("%w: lease plugin_instance_id is required", ErrRuntimeBindingInvalid)
	}
	shard := shards[processShardIndex(pluginInstanceID, len(shards))]
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

func (m *ProcessManager) Revoke(ctx context.Context, req RevokeRequest) (RevokeResult, error) {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	shards, boundErr := m.boundShards()
	if boundErr != nil {
		return RevokeResult{}, boundErr
	}
	if err := validateRevokeRequest(req); err != nil {
		return RevokeResult{}, err
	}
	shard := shards[processShardIndex(req.PluginInstanceID, len(shards))]
	health, err := shard.process.Health(ctx)
	if err == nil {
		err = validateReadyHealth(health)
	}
	if err == nil {
		var result RevokeResult
		result, err = shard.process.Revoke(ctx, req)
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
	return RevokeResult{ResourceScope: req.ResourceScope, PluginInstanceID: req.PluginInstanceID, RevokeEpoch: req.RevokeEpoch, RuntimeStopped: true}, nil
}

func (m *ProcessManager) boundShards() ([]processManagerShard, error) {
	if m == nil {
		return nil, ErrRuntimeHostServicesRequired
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if !m.bound || len(m.shards) == 0 {
		return nil, ErrRuntimeHostServicesRequired
	}
	return m.shards, nil
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
		Descriptor:          health.Descriptor,
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
	if health.Descriptor.Version().String() == "" {
		return fmt.Errorf("%w: ready shard health descriptor is missing", ErrRuntimeBindingInvalid)
	}
	if err := health.Descriptor.CompatibleWithPlatform(); err != nil {
		return fmt.Errorf("%w: %v", ErrRuntimeBindingInvalid, err)
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
