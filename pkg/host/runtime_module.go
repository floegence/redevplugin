package host

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/runtimeclient"
)

const (
	DefaultRuntimeStartupTimeout  = 10 * time.Second
	DefaultRuntimeShutdownTimeout = 5 * time.Second
	MinimumRuntimeTimeout         = 100 * time.Millisecond
	MaximumRuntimeTimeout         = 2 * time.Minute
)

var (
	ErrVerifiedExecutableRequired  = errors.New("verified runtime executable is required")
	ErrRuntimeModuleOptionsInvalid = errors.New("runtime module options are invalid")
	ErrRuntimeModuleClosed         = errors.New("runtime module is closed")
	ErrRuntimeModuleConsumed       = errors.New("runtime module ownership was transferred to a host")
)

type RuntimeLimits = runtimeclient.RuntimeLimits

type RuntimeModuleOptions struct {
	Limits          RuntimeLimits
	StartupTimeout  time.Duration
	ShutdownTimeout time.Duration
}

type RuntimeModuleDisposition string

const (
	RuntimeModuleCallerOwned       RuntimeModuleDisposition = "caller_owned"
	RuntimeModuleAlreadyClosed     RuntimeModuleDisposition = "already_closed"
	RuntimeModuleConsumedAndClosed RuntimeModuleDisposition = "consumed_and_closed"
)

type RuntimeModuleCloseResult struct {
	Disposition RuntimeModuleDisposition
	Outcome     MutationOutcome
}

type runtimeModuleState uint8

const (
	runtimeModuleOwned runtimeModuleState = iota + 1
	runtimeModuleTransferred
	runtimeModuleClosed
)

type runtimeModuleCapability struct {
	mu              sync.Mutex
	state           runtimeModuleState
	descriptor      RuntimeDescriptor
	executable      *os.File
	executionRoot   *os.File
	executableOwner *VerifiedExecutable
	manager         runtimeclient.Manager
	limits          RuntimeLimits
	startupTimeout  time.Duration
	shutdownTimeout time.Duration
}

func NewRuntimeModule(executable *VerifiedExecutable, options RuntimeModuleOptions) (*RuntimeModule, error) {
	options, err := normalizeRuntimeModuleOptions(options)
	if err != nil {
		return nil, err
	}
	if executable == nil {
		return nil, ErrVerifiedExecutableRequired
	}
	executable.mu.Lock()
	defer executable.mu.Unlock()
	if executable.state != verifiedExecutableOwned || executable.executable == nil || executable.executionRoot == nil || !executable.descriptor.valid() {
		return nil, ErrVerifiedExecutableClosed
	}
	executable.state = verifiedExecutableModuleOwned
	return &RuntimeModule{capability: &runtimeModuleCapability{
		state:           runtimeModuleOwned,
		descriptor:      executable.descriptor,
		executable:      executable.executable,
		executionRoot:   executable.executionRoot,
		executableOwner: executable,
		limits:          options.Limits,
		startupTimeout:  options.StartupTimeout,
		shutdownTimeout: options.ShutdownTimeout,
	}}, nil
}

func normalizeRuntimeModuleOptions(options RuntimeModuleOptions) (RuntimeModuleOptions, error) {
	if options.Limits == (RuntimeLimits{}) {
		options.Limits = runtimeclient.DefaultRuntimeLimits()
	}
	if err := runtimeclient.ValidateRuntimeLimits(options.Limits); err != nil {
		return RuntimeModuleOptions{}, errors.Join(ErrRuntimeModuleOptionsInvalid, err)
	}
	if options.StartupTimeout == 0 {
		options.StartupTimeout = DefaultRuntimeStartupTimeout
	}
	if options.ShutdownTimeout == 0 {
		options.ShutdownTimeout = DefaultRuntimeShutdownTimeout
	}
	if options.StartupTimeout < MinimumRuntimeTimeout || options.StartupTimeout > MaximumRuntimeTimeout ||
		options.ShutdownTimeout < MinimumRuntimeTimeout || options.ShutdownTimeout > MaximumRuntimeTimeout {
		return RuntimeModuleOptions{}, ErrRuntimeModuleOptionsInvalid
	}
	return options, nil
}

func (module *RuntimeModule) Descriptor() RuntimeDescriptor {
	if module == nil || module.capability == nil {
		return RuntimeDescriptor{}
	}
	module.capability.mu.Lock()
	defer module.capability.mu.Unlock()
	if module.capability.state == runtimeModuleClosed {
		return RuntimeDescriptor{}
	}
	return module.capability.descriptor
}

func (module *RuntimeModule) claimForHost() (*runtimeModuleCapability, error) {
	if module == nil || module.capability == nil {
		return nil, ErrRuntimeModuleRequired
	}
	capability := module.capability
	capability.mu.Lock()
	defer capability.mu.Unlock()
	switch capability.state {
	case runtimeModuleOwned:
		capability.state = runtimeModuleTransferred
		return capability, nil
	case runtimeModuleTransferred:
		return nil, ErrRuntimeModuleConsumed
	default:
		return nil, ErrRuntimeModuleClosed
	}
}

func (module *RuntimeModule) Close(ctx context.Context) (RuntimeModuleCloseResult, error) {
	if module == nil {
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeNotCommitted}, nil
	}
	if module.capability == nil {
		if module.Manager == nil {
			return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeNotCommitted}, nil
		}
		if ctx == nil {
			ctx = context.Background()
		}
		err := module.Manager.Stop(ctx)
		module.Manager = nil
		if err != nil {
			return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeUnknown}, err
		}
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeCommitted}, nil
	}
	capability := module.capability
	capability.mu.Lock()
	defer capability.mu.Unlock()
	switch capability.state {
	case runtimeModuleTransferred:
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleConsumedAndClosed, Outcome: MutationOutcomeNotCommitted}, ErrRuntimeModuleConsumed
	case runtimeModuleClosed:
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeNotCommitted}, nil
	case runtimeModuleOwned:
		capability.state = runtimeModuleClosed
		err := closeRuntimeModuleFiles(capability)
		if err != nil {
			return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeUnknown}, err
		}
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeCommitted}, nil
	default:
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeUnknown}, ErrRuntimeModuleClosed
	}
}

func (module *RuntimeModule) closeFromHost(ctx context.Context) (RuntimeModuleCloseResult, error) {
	if module == nil || module.capability == nil {
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeNotCommitted}, nil
	}
	capability := module.capability
	capability.mu.Lock()
	defer capability.mu.Unlock()
	if capability.state == runtimeModuleClosed {
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleAlreadyClosed, Outcome: MutationOutcomeNotCommitted}, nil
	}
	if capability.state != runtimeModuleTransferred {
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleCallerOwned, Outcome: MutationOutcomeNotCommitted}, ErrRuntimeModuleClosed
	}
	capability.state = runtimeModuleClosed
	if ctx == nil {
		ctx = context.Background()
	}
	var stopErr error
	if capability.manager != nil {
		stopErr = capability.manager.Stop(ctx)
		capability.manager = nil
	}
	closeErr := closeRuntimeModuleFiles(capability)
	if err := errors.Join(stopErr, closeErr); err != nil {
		return RuntimeModuleCloseResult{Disposition: RuntimeModuleConsumedAndClosed, Outcome: MutationOutcomeUnknown}, err
	}
	return RuntimeModuleCloseResult{Disposition: RuntimeModuleConsumedAndClosed, Outcome: MutationOutcomeCommitted}, nil
}

func closeRuntimeModuleFiles(capability *runtimeModuleCapability) error {
	if capability == nil {
		return nil
	}
	err := errors.Join(closeRuntimeFile(capability.executable), closeRuntimeFile(capability.executionRoot))
	capability.executable = nil
	capability.executionRoot = nil
	if capability.executableOwner != nil {
		capability.executableOwner.mu.Lock()
		capability.executableOwner.state = verifiedExecutableClosed
		capability.executableOwner.executable = nil
		capability.executableOwner.executionRoot = nil
		capability.executableOwner.mu.Unlock()
		capability.executableOwner = nil
	}
	return err
}

func newRuntimeManagerFromCapability(capability *runtimeModuleCapability, adapters normalizedAdapters) (runtimeclient.Manager, error) {
	if capability == nil {
		return nil, ErrRuntimeModuleRequired
	}
	capability.mu.Lock()
	if capability.state != runtimeModuleTransferred || capability.executable == nil || !capability.descriptor.valid() {
		capability.mu.Unlock()
		return nil, ErrRuntimeModuleClosed
	}
	descriptor := capability.descriptor
	executable := capability.executable
	limits := capability.limits
	startupTimeout := capability.startupTimeout
	capability.mu.Unlock()

	internalDescriptor, err := runtimeclient.NewRuntimeDescriptor(
		descriptor.PlatformVersion(),
		descriptor.Target().classifierTarget(),
		descriptor.RustIPCVersion().String(),
		descriptor.WASMABIVersion().String(),
		descriptor.BinarySHA256().String(),
	)
	if err != nil {
		return nil, err
	}
	return runtimeclient.NewProcessManager(runtimeclient.ProcessManagerOptions{
		ShardCount: 1,
		Supervisor: runtimeclient.ProcessSupervisorOptions{
			RuntimeExecutable:     executable,
			Descriptor:            internalDescriptor,
			Diagnostics:           adapters.Diagnostics,
			Artifacts:             runtimeArtifactProvider{assets: adapters.Assets},
			HandleGrants:          runtimeHandleGrantValidator{tokens: adapters.SurfaceTokens},
			StorageFiles:          adapters.PluginData,
			StorageKV:             adapters.PluginData,
			StorageSQLite:         adapters.PluginData,
			Connectivity:          adapters.Connectivity,
			NetworkExecutor:       adapters.NetworkExecutor,
			HandshakeTimeout:      startupTimeout,
			HeartbeatInterval:     2 * time.Second,
			MaxHeartbeatStaleness: 5 * time.Second,
			Limits:                limits,
		},
	})
}
