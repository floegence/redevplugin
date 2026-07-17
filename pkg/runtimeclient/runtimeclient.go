package runtimeclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Lease struct {
	LeaseID                string      `json:"lease_id"`
	TokenID                string      `json:"token_id"`
	LeaseNonce             string      `json:"lease_nonce"`
	PluginID               string      `json:"plugin_id"`
	PluginVersion          string      `json:"plugin_version"`
	ActiveFingerprint      string      `json:"active_fingerprint"`
	SurfaceInstanceID      string      `json:"surface_instance_id,omitempty"`
	OwnerSessionHash       string      `json:"owner_session_hash,omitempty"`
	OwnerUserHash          string      `json:"owner_user_hash,omitempty"`
	OwnerEnvHash           string      `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash   string      `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID        string      `json:"bridge_channel_id,omitempty"`
	RuntimeGenerationID    string      `json:"runtime_generation_id"`
	PluginInstanceID       string      `json:"plugin_instance_id"`
	Method                 string      `json:"method"`
	Effect                 string      `json:"effect"`
	Execution              string      `json:"execution"`
	OperationID            string      `json:"operation_id,omitempty"`
	StreamID               string      `json:"stream_id,omitempty"`
	AuditCorrelationID     string      `json:"audit_correlation_id"`
	TargetDescriptorHashes []string    `json:"target_descriptor_hashes"`
	Limits                 LeaseLimits `json:"limits"`
	PolicyRevision         uint64      `json:"policy_revision"`
	ManagementRevision     uint64      `json:"management_revision"`
	RevokeEpoch            uint64      `json:"revoke_epoch"`
	RuntimeShardID         string      `json:"runtime_shard_id"`
	RuntimeInstanceID      string      `json:"runtime_instance_id"`
	IPCChannelID           string      `json:"ipc_channel_id"`
	ConnectionNonce        string      `json:"connection_nonce"`
	KeyID                  string      `json:"key_id"`
	Signature              string      `json:"signature"`
	IssuedAtUnixMillis     int64       `json:"issued_at_unix_ms"`
	ExpiresAtUnixMillis    int64       `json:"expires_at_unix_ms"`
}

type LeaseLimits struct {
	TimeoutMillis           int64 `json:"timeout_ms"`
	MemoryBytes             int64 `json:"memory_bytes"`
	MaxPayloadBytes         int64 `json:"max_payload_bytes"`
	MaxStreamBytesPerSecond int64 `json:"max_stream_bytes_per_sec"`
}

type Health struct {
	RuntimeInstanceID   string             `json:"runtime_instance_id"`
	RuntimeGenerationID string             `json:"runtime_generation_id"`
	IPCChannelID        string             `json:"ipc_channel_id,omitempty"`
	ConnectionNonce     string             `json:"connection_nonce,omitempty"`
	Descriptor          RuntimeDescriptor  `json:"descriptor"`
	Ready               bool               `json:"ready"`
	ActiveInvocations   int                `json:"active_invocations"`
	QueuedInvocations   int                `json:"queued_invocations"`
	Limits              RuntimeLimits      `json:"limits"`
	ModuleCache         ModuleCacheMetrics `json:"module_cache"`
}

type RuntimeLimits struct {
	WorkerCount            int   `json:"worker_count"`
	QueueCapacity          int   `json:"queue_capacity"`
	PerPluginConcurrency   int   `json:"per_plugin_concurrency"`
	ModuleCacheEntries     int   `json:"module_cache_entries"`
	ModuleCacheSourceBytes int64 `json:"module_cache_source_bytes"`
}

type ModuleCacheMetrics struct {
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	Compiles    uint64 `json:"compiles"`
	Entries     int    `json:"entries"`
	SourceBytes int64  `json:"source_bytes"`
}

type RevokeResult struct {
	PluginInstanceID         string `json:"plugin_instance_id"`
	RevokeEpoch              uint64 `json:"revoke_epoch"`
	ClosedSocketCount        int    `json:"closed_socket_count"`
	ClosedStreamCount        int    `json:"closed_stream_count"`
	ClosedStorageHandleCount int    `json:"closed_storage_handle_count"`
	RuntimeStopped           bool   `json:"runtime_stopped,omitempty"`
}

type HeartbeatResult struct {
	RuntimeGenerationID  string             `json:"runtime_generation_id"`
	RuntimeUnixNano      int64              `json:"runtime_unix_nano"`
	MaxStalenessMillis   int64              `json:"max_staleness_ms"`
	HostSentUnixNanoEcho int64              `json:"host_sent_unix_nano"`
	ActiveInvocations    int                `json:"active_invocations"`
	QueuedInvocations    int                `json:"queued_invocations"`
	Limits               RuntimeLimits      `json:"limits"`
	ModuleCache          ModuleCacheMetrics `json:"module_cache"`
}

type ArtifactProvider interface {
	ReadArtifact(ctx context.Context, req ArtifactRequest) (ArtifactResult, error)
}

type HandleGrantValidator interface {
	ValidateHandleGrant(ctx context.Context, req HandleGrantValidationRequest) (HandleGrantValidationResult, error)
}

type ArtifactRequest struct {
	PackageHash    string `json:"package_hash"`
	Artifact       string `json:"artifact"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type ArtifactResult struct {
	Content []byte `json:"-"`
	SHA256  string `json:"sha256"`
}

type workerInvocationContext struct {
	Artifact     ArtifactRequest
	BrokerAccess workerBrokerAccess
	identity     workerInvocationIdentity
}

type workerInvocationIdentity struct {
	PluginID             string
	PluginInstanceID     string
	ActiveFingerprint    string
	PolicyRevision       uint64
	ManagementRevision   uint64
	RevokeEpoch          uint64
	RuntimeShardID       string
	RuntimeInstanceID    string
	RuntimeGenerationID  string
	OwnerSessionHash     string
	OwnerUserHash        string
	OwnerEnvHash         string
	SessionChannelIDHash string
}

type workerBrokerAccess struct {
	Storage []workerStorageBrokerAccess `json:"storage,omitempty"`
	Network []workerNetworkBrokerAccess `json:"network,omitempty"`
}

type workerStorageBrokerAccess struct {
	StoreID    string   `json:"store_id"`
	Operations []string `json:"operations"`
}

type workerNetworkBrokerAccess struct {
	ConnectorID string   `json:"connector_id"`
	Transport   string   `json:"transport"`
	Operations  []string `json:"operations"`
	HTTPMethods []string `json:"http_methods,omitempty"`
}

type HandleGrantValidationRequest struct {
	HandleGrantToken    string `json:"handle_grant_token"`
	PluginInstanceID    string `json:"plugin_instance_id"`
	ActiveFingerprint   string `json:"active_fingerprint"`
	RuntimeInstanceID   string `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	RuntimeShardID      string `json:"runtime_shard_id,omitempty"`
	HandleID            string `json:"handle_id"`
	Method              string `json:"method"`
	PolicyRevision      uint64 `json:"policy_revision"`
	ManagementRevision  uint64 `json:"management_revision"`
	RevokeEpoch         uint64 `json:"revoke_epoch"`
}

type HandleGrantValidationResult struct {
	HandleGrantID       string `json:"handle_grant_id"`
	HandleID            string `json:"handle_id"`
	Method              string `json:"method"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	MaxBytesPerSecond   int64  `json:"max_bytes_per_second,omitempty"`
	MaxTotalBytes       int64  `json:"max_total_bytes,omitempty"`
}

var (
	ErrRuntimePathRequired   = errors.New("runtime path is required")
	ErrRuntimeNotReady       = errors.New("runtime is not ready")
	ErrRuntimeIPCUnavailable = errors.New("runtime ipc transport is unavailable")
	ErrRuntimeHandshake      = errors.New("runtime ipc handshake failed")
	ErrRuntimeRequestFailed  = errors.New("runtime ipc request failed")
	ErrRuntimeArtifactDigest = errors.New("runtime artifact digest mismatch")
	// ErrRuntimeTimingInvalid reports a non-positive or internally inconsistent
	// process handshake and heartbeat timing configuration.
	ErrRuntimeTimingInvalid = errors.New("runtime timing is invalid")
)

type WorkerExecutionError struct {
	Code    string
	Message string
	Origin  WorkerErrorOrigin
}

type WorkerErrorOrigin string

const (
	WorkerErrorOriginRuntime  WorkerErrorOrigin = "runtime"
	WorkerErrorOriginHostcall WorkerErrorOrigin = "hostcall"
	WorkerErrorOriginPlugin   WorkerErrorOrigin = "plugin"
)

func (origin WorkerErrorOrigin) valid() bool {
	return origin == WorkerErrorOriginRuntime || origin == WorkerErrorOriginHostcall || origin == WorkerErrorOriginPlugin
}

func (e *WorkerExecutionError) Error() string {
	if e == nil {
		return ErrRuntimeRequestFailed.Error()
	}
	if e.Code == "" {
		return fmt.Sprintf("%s: %s", ErrRuntimeRequestFailed, e.Message)
	}
	return fmt.Sprintf("%s: %s: %s", ErrRuntimeRequestFailed, e.Code, e.Message)
}

func (e *WorkerExecutionError) Unwrap() error {
	return ErrRuntimeRequestFailed
}

// ProcessSupervisorOptions defines the immutable process, broker, Host-service,
// timing, and resource-limit inputs for one runtime supervisor. All three timing
// values must be positive, and MaxHeartbeatStaleness must not be less than
// HeartbeatInterval.
type ProcessSupervisorOptions struct {
	RuntimePath           string
	Descriptor            RuntimeDescriptor
	Args                  []string
	Env                   []string
	Dir                   string
	Diagnostics           observability.DiagnosticsSink
	Artifacts             ArtifactProvider
	HandleGrants          HandleGrantValidator
	RuntimeLeaseReplays   RuntimeLeaseReplayStore
	StorageFiles          storage.FilesBroker
	StorageKV             storage.KVBroker
	StorageSQLite         storage.SQLiteBroker
	Connectivity          connectivity.Broker
	NetworkExecutor       connectivity.NetworkExecutor
	StreamSink            RuntimeStreamSink
	Now                   func() time.Time
	HandshakeTimeout      time.Duration
	HeartbeatInterval     time.Duration
	MaxHeartbeatStaleness time.Duration
	Limits                RuntimeLimits
}

// RuntimeStreamSink is the required Host-owned destination for stream events
// emitted by runtime hostcalls. A nil or typed-nil implementation is invalid.
type RuntimeStreamSink interface {
	AppendRuntimeStream(ctx context.Context, streamID, kind string, data []byte) error
	CloseRuntimeStream(ctx context.Context, streamID string) error
	FailRuntimeStream(ctx context.Context, streamID string, code capability.ExecutionFailureCode, cause error) error
}

type ProcessSupervisor struct {
	startMu                sync.Mutex
	controlMu              sync.Mutex
	mu                     sync.Mutex
	pendingMu              sync.Mutex
	path                   string
	descriptor             RuntimeDescriptor
	args                   []string
	env                    []string
	dir                    string
	diagnostics            observability.DiagnosticsSink
	artifacts              ArtifactProvider
	handleGrants           HandleGrantValidator
	runtimeLeaseReplays    RuntimeLeaseReplayStore
	runtimeLeaseVerifier   RuntimeLeaseVerifier
	runtimeLeaseSigningKey string
	runtimeLeasePrivateKey ed25519.PrivateKey
	runtimeLeasePublicKeys []RuntimeLeasePublicKey
	storageFiles           storage.FilesBroker
	storageKV              storage.KVBroker
	storageSQLite          storage.SQLiteBroker
	connectivity           connectivity.Broker
	networkExecutor        connectivity.NetworkExecutor
	streamSink             RuntimeStreamSink
	now                    func() time.Time
	handshakeTimeout       time.Duration
	heartbeatInterval      time.Duration
	maxHeartbeatStaleness  time.Duration
	seq                    uint64
	requestSeq             uint64
	limits                 RuntimeLimits
	admission              *runtimeAdmissionController
	pending                map[string]*pendingIPCRequest
	compileFlights         map[string]*pendingCompileFlight

	cmd              *exec.Cmd
	cancel           context.CancelFunc
	exit             *processExit
	ipcIn            io.WriteCloser
	ipcOut           *bufio.Reader
	controlIn        io.WriteCloser
	controlOut       *bufio.Reader
	controlOutCloser io.Closer
	generation       *runtimeGeneration
	health           Health
	exitError        error
}

type processExit struct {
	done              chan struct{}
	ipcReaderDone     chan struct{}
	ipcReaderDoneOnce sync.Once
	err               error
	stopEvent         sync.Once
}

type pendingIPCRequest struct {
	ctx               context.Context
	generation        *runtimeGeneration
	responseFrameType string
	invocation        *workerInvocationContext
	result            chan ipcCallResult
}

type pendingCompileFlight struct {
	generation        *runtimeGeneration
	parentRequestID   string
	artifactRequestID string
	artifact          ArtifactRequest
	wasmABIVersion    string
	registered        bool
	artifactRequested bool
}

type runtimeGeneration struct {
	id    string
	ctx   context.Context
	stdin io.Writer
}

func (e *processExit) finishIPCReader() {
	if e == nil || e.ipcReaderDone == nil {
		return
	}
	e.ipcReaderDoneOnce.Do(func() { close(e.ipcReaderDone) })
}

type ipcCallResult struct {
	frame ipcFrame
	err   error
}

type serializedWriteCloser struct {
	mu sync.Mutex
	io.WriteCloser
}

func (w *serializedWriteCloser) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.WriteCloser.Write(payload)
}

// NewProcessSupervisor validates all required runtime and Host-service inputs
// and creates a stopped supervisor. Timing and limits are never defaulted or
// widened. StreamSink must be a concrete non-nil implementation; typed-nil
// interface values are rejected.
func NewProcessSupervisor(options ProcessSupervisorOptions) (*ProcessSupervisor, error) {
	if err := validateProcessSupervisorOptions(options, true); err != nil {
		return nil, err
	}
	path := strings.TrimSpace(options.RuntimePath)
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256(publicKey)
	keyID := "host_ephemeral_" + hex.EncodeToString(keyHash[:8])
	runtimeLeasePublicKey, err := RuntimeLeasePublicKeyFromEd25519(keyID, publicKey)
	if err != nil {
		return nil, err
	}
	keyring := StaticRuntimeLeaseSigningKeyring{Keys: []RuntimeLeaseSigningKey{{KeyID: keyID, PublicKey: publicKey}}}
	return &ProcessSupervisor{
		path:                   path,
		descriptor:             options.Descriptor,
		args:                   append([]string(nil), options.Args...),
		env:                    append([]string(nil), options.Env...),
		dir:                    strings.TrimSpace(options.Dir),
		diagnostics:            options.Diagnostics,
		artifacts:              options.Artifacts,
		handleGrants:           options.HandleGrants,
		runtimeLeaseReplays:    options.RuntimeLeaseReplays,
		runtimeLeaseVerifier:   Ed25519RuntimeLeaseVerifier{Keyring: keyring, Now: now},
		runtimeLeaseSigningKey: keyID,
		runtimeLeasePrivateKey: append(ed25519.PrivateKey(nil), privateKey...),
		runtimeLeasePublicKeys: []RuntimeLeasePublicKey{runtimeLeasePublicKey},
		storageFiles:           options.StorageFiles,
		storageKV:              options.StorageKV,
		storageSQLite:          options.StorageSQLite,
		connectivity:           options.Connectivity,
		networkExecutor:        options.NetworkExecutor,
		streamSink:             options.StreamSink,
		now:                    now,
		handshakeTimeout:       options.HandshakeTimeout,
		heartbeatInterval:      options.HeartbeatInterval,
		maxHeartbeatStaleness:  options.MaxHeartbeatStaleness,
		limits:                 options.Limits,
		admission:              newRuntimeAdmissionController(options.Limits),
		pending:                map[string]*pendingIPCRequest{},
		compileFlights:         map[string]*pendingCompileFlight{},
		health: Health{
			Descriptor: options.Descriptor,
			Limits:     options.Limits,
		},
	}, nil
}

func validateProcessSupervisorOptions(options ProcessSupervisorOptions, requireHostServices bool) error {
	if strings.TrimSpace(options.RuntimePath) == "" {
		return ErrRuntimePathRequired
	}
	if options.Descriptor.Version().String() == "" {
		return fmt.Errorf("%w: descriptor is required", ErrRuntimeDescriptorInvalid)
	}
	if err := options.Descriptor.CompatibleWithPlatform(); err != nil {
		return err
	}
	if err := ValidateRuntimeLimits(options.Limits); err != nil {
		return err
	}
	if options.HandshakeTimeout <= 0 {
		return fmt.Errorf("%w: handshake timeout must be positive", ErrRuntimeTimingInvalid)
	}
	if options.HeartbeatInterval <= 0 {
		return fmt.Errorf("%w: heartbeat interval must be positive", ErrRuntimeTimingInvalid)
	}
	if options.MaxHeartbeatStaleness <= 0 {
		return fmt.Errorf("%w: maximum heartbeat staleness must be positive", ErrRuntimeTimingInvalid)
	}
	if options.MaxHeartbeatStaleness < options.HeartbeatInterval {
		return fmt.Errorf("%w: maximum heartbeat staleness must not be less than the heartbeat interval", ErrRuntimeTimingInvalid)
	}
	if requireHostServices && isNilInterfaceValue(options.StreamSink) {
		return fmt.Errorf("%w: stream sink is required", ErrRuntimeHostServicesInvalid)
	}
	return nil
}

func DefaultRuntimeLimits() RuntimeLimits {
	workerCount := min(max(runtime.GOMAXPROCS(0), 4), 16)
	return RuntimeLimits{
		WorkerCount:            workerCount,
		QueueCapacity:          min(workerCount*4, 64),
		PerPluginConcurrency:   min(max(workerCount/2, 2), 8),
		ModuleCacheEntries:     64,
		ModuleCacheSourceBytes: 128 << 20,
	}
}

func ValidateRuntimeLimits(limits RuntimeLimits) error {
	if limits.WorkerCount < 1 || limits.WorkerCount > 64 {
		return errors.New("runtime worker_count must be between 1 and 64")
	}
	if limits.QueueCapacity < 1 || limits.QueueCapacity > 64 {
		return errors.New("runtime queue_capacity must be between 1 and 64")
	}
	if limits.PerPluginConcurrency < 1 || limits.PerPluginConcurrency > limits.WorkerCount {
		return errors.New("runtime per_plugin_concurrency must be between 1 and worker_count")
	}
	if limits.ModuleCacheEntries < 1 || limits.ModuleCacheEntries > 1024 {
		return errors.New("runtime module_cache_entries must be between 1 and 1024")
	}
	if limits.ModuleCacheSourceBytes < 1 {
		return errors.New("runtime module_cache_source_bytes must be positive")
	}
	return nil
}

func (s *ProcessSupervisor) Start(ctx context.Context, target Target) error {
	if s == nil {
		return ErrRuntimePathRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateTarget(target); err != nil {
		return err
	}
	if target != s.descriptor.Target() {
		return fmt.Errorf("%w: requested target os=%q arch=%q", ErrRuntimeDescriptorMismatch, target.OS, target.Arch)
	}
	s.startMu.Lock()
	defer s.startMu.Unlock()
	s.mu.Lock()
	if s.readyLocked() {
		s.mu.Unlock()
		return nil
	}
	if s.cmd != nil {
		s.mu.Unlock()
		return ErrRuntimeNotReady
	}
	s.mu.Unlock()
	verifiedPath, cleanupVerifiedPath, err := s.prepareRuntimeExecutable(ctx)
	if err != nil {
		return err
	}
	defer cleanupVerifiedPath()
	s.mu.Lock()
	if s.readyLocked() || s.cmd != nil {
		s.mu.Unlock()
		return ErrRuntimeNotReady
	}
	s.seq++
	generationID := fmt.Sprintf("runtime_gen_%d_%d", s.now().UnixNano(), s.seq)
	runtimeCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(runtimeCtx, verifiedPath, s.args...)
	controlRuntimeRead, controlHostWrite, err := os.Pipe()
	if err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	controlHostRead, controlRuntimeWrite, err := os.Pipe()
	if err != nil {
		_ = controlRuntimeRead.Close()
		_ = controlHostWrite.Close()
		cancel()
		s.mu.Unlock()
		return err
	}
	closeControlPipes := func() {
		_ = controlRuntimeRead.Close()
		_ = controlHostWrite.Close()
		_ = controlHostRead.Close()
		_ = controlRuntimeWrite.Close()
	}
	commandEnv := append([]string(nil), s.env...)
	if len(commandEnv) == 0 {
		commandEnv = os.Environ()
	}
	cmd.Env = append(commandEnv,
		"REDEVPLUGIN_CONTROL_READ_FD=3",
		"REDEVPLUGIN_CONTROL_WRITE_FD=4",
	)
	cmd.ExtraFiles = []*os.File{controlRuntimeRead, controlRuntimeWrite}
	if s.dir != "" {
		cmd.Dir = s.dir
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		closeControlPipes()
		cancel()
		s.mu.Unlock()
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		closeControlPipes()
		cancel()
		s.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		closeControlPipes()
		cancel()
		s.mu.Unlock()
		return err
	}
	if err := cmd.Start(); err != nil {
		closeControlPipes()
		cancel()
		s.mu.Unlock()
		return err
	}
	_ = controlRuntimeRead.Close()
	_ = controlRuntimeWrite.Close()
	stdoutReader := bufio.NewReader(stdout)
	controlReader := bufio.NewReader(controlHostRead)
	health := Health{
		RuntimeInstanceID:   fmt.Sprintf("runtime_%d", cmd.Process.Pid),
		RuntimeGenerationID: generationID,
		IPCChannelID:        fmt.Sprintf("ipc_%d_%d", cmd.Process.Pid, s.seq),
		Descriptor:          s.descriptor,
		Limits:              s.limits,
	}
	exit := &processExit{done: make(chan struct{}), ipcReaderDone: make(chan struct{})}
	s.cmd = cmd
	s.cancel = cancel
	s.exit = exit
	serializedStdin := &serializedWriteCloser{WriteCloser: stdin}
	generation := &runtimeGeneration{id: generationID, ctx: runtimeCtx, stdin: serializedStdin}
	s.ipcIn = serializedStdin
	s.ipcOut = stdoutReader
	s.controlIn = controlHostWrite
	s.controlOut = controlReader
	s.controlOutCloser = controlHostRead
	s.generation = generation
	s.health = health
	s.exitError = nil
	s.mu.Unlock()

	s.emit("plugin.runtime.process.started", "info", "runtime process started", map[string]any{
		"runtime_instance_id":   health.RuntimeInstanceID,
		"runtime_generation_id": health.RuntimeGenerationID,
		"os":                    target.OS,
		"arch":                  target.Arch,
	})
	go s.scanPipe(stderr, "stderr")
	go s.wait(cmd, exit, cancel, generation, health)

	ack, err := s.performHandshake(ctx, serializedStdin, stdoutReader, health, target)
	if err != nil {
		exit.finishIPCReader()
		cancel()
		s.mu.Lock()
		if s.cmd == cmd {
			s.health.Ready = false
		}
		s.mu.Unlock()
		select {
		case <-exit.done:
		case <-time.After(3 * time.Second):
			s.emit("plugin.runtime.process.cleanup_timeout", "warning", "runtime process did not exit after failed handshake", map[string]any{
				"runtime_instance_id":   health.RuntimeInstanceID,
				"runtime_generation_id": health.RuntimeGenerationID,
			})
		}
		return err
	}
	s.mu.Lock()
	if s.cmd == cmd && runtimeCtx.Err() == nil {
		health.ConnectionNonce = ack.ChannelNonce
		health.Limits = ack.Limits
		health.Ready = true
		s.health = health
	} else {
		s.mu.Unlock()
		return ErrRuntimeNotReady
	}
	s.mu.Unlock()
	go func() {
		defer exit.finishIPCReader()
		s.readIPCLoop(stdoutReader, generation, health)
	}()
	s.emit("plugin.runtime.ipc.handshake", "info", "runtime ipc handshake completed", map[string]any{
		"runtime_instance_id":     health.RuntimeInstanceID,
		"runtime_generation_id":   health.RuntimeGenerationID,
		"runtime_version":         health.Descriptor.Version().String(),
		"rust_ipc_version":        health.Descriptor.IPCVersion(),
		"wasm_abi_version":        health.Descriptor.WASMABIVersion(),
		"runtime_target_os":       health.Descriptor.Target().OS,
		"runtime_target_arch":     health.Descriptor.Target().Arch,
		"runtime_artifact_sha256": health.Descriptor.ArtifactSHA256(),
	})
	go s.heartbeatLoop(runtimeCtx, health)
	return nil
}

func (s *ProcessSupervisor) Preflight(ctx context.Context, target Target) (RuntimeDescriptor, error) {
	if s == nil {
		return RuntimeDescriptor{}, ErrRuntimePathRequired
	}
	if err := ctx.Err(); err != nil {
		return RuntimeDescriptor{}, err
	}
	if err := ValidateTarget(target); err != nil {
		return RuntimeDescriptor{}, err
	}
	if target != s.descriptor.Target() {
		return RuntimeDescriptor{}, fmt.Errorf("%w: requested target os=%q arch=%q", ErrRuntimeDescriptorMismatch, target.OS, target.Arch)
	}
	if err := s.descriptor.CompatibleWithPlatform(); err != nil {
		return RuntimeDescriptor{}, err
	}
	if err := verifyRuntimeExecutable(ctx, s.path, s.descriptor.ArtifactSHA256()); err != nil {
		return RuntimeDescriptor{}, err
	}
	return s.descriptor, nil
}

const maxRuntimeExecutableBytes int64 = 256 << 20

func verifyRuntimeExecutable(ctx context.Context, path string, expectedSHA256 string) error {
	file, err := openRuntimeExecutable(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	if err := copyBoundedRuntimeExecutable(ctx, file, hasher); err != nil {
		return err
	}
	if actual := hex.EncodeToString(hasher.Sum(nil)); actual != expectedSHA256 {
		return fmt.Errorf("%w: got %s want %s", ErrRuntimeArtifactDigest, actual, expectedSHA256)
	}
	return nil
}

func (s *ProcessSupervisor) prepareRuntimeExecutable(ctx context.Context) (string, func(), error) {
	source, err := openRuntimeExecutable(s.path)
	if err != nil {
		return "", nil, err
	}
	defer source.Close()
	directory, err := os.MkdirTemp("", "redevplugin-runtime-verified-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	verifiedPath := filepath.Join(directory, "redevplugin-runtime")
	destination, err := os.OpenFile(verifiedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	hasher := sha256.New()
	if err := copyBoundedRuntimeExecutable(ctx, source, io.MultiWriter(destination, hasher)); err != nil {
		_ = destination.Close()
		cleanup()
		return "", nil, err
	}
	if err := destination.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	if actual := hex.EncodeToString(hasher.Sum(nil)); actual != s.descriptor.ArtifactSHA256() {
		cleanup()
		return "", nil, fmt.Errorf("%w: got %s want %s", ErrRuntimeArtifactDigest, actual, s.descriptor.ArtifactSHA256())
	}
	if err := os.Chmod(verifiedPath, 0o500); err != nil {
		cleanup()
		return "", nil, err
	}
	return verifiedPath, cleanup, nil
}

func copyBoundedRuntimeExecutable(ctx context.Context, source *os.File, destination io.Writer) error {
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRuntimeExecutableBytes {
		return fmt.Errorf("%w: runtime artifact must be a non-empty regular file no larger than %d bytes", ErrRuntimeArtifactDigest, maxRuntimeExecutableBytes)
	}
	remaining := info.Size()
	buffer := make([]byte, 128*1024)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		readSize := int64(len(buffer))
		if remaining < readSize {
			readSize = remaining
		}
		read, readErr := source.Read(buffer[:readSize])
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			if writeErr != nil {
				return writeErr
			}
			if written != read {
				return io.ErrShortWrite
			}
			remaining -= int64(read)
		}
		if readErr != nil && !(errors.Is(readErr, io.EOF) && remaining == 0) {
			return readErr
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
	var extra [1]byte
	if read, err := source.Read(extra[:]); read != 0 || !errors.Is(err, io.EOF) {
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return fmt.Errorf("%w: runtime artifact size changed while reading", ErrRuntimeArtifactDigest)
	}
	return nil
}

func (s *ProcessSupervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cancel := s.cancel
	exit := s.exit
	health := s.health
	if cancel == nil || exit == nil {
		s.mu.Unlock()
		return nil
	}
	s.health.Ready = false
	cancel()
	s.mu.Unlock()

	select {
	case <-exit.done:
		exit.stopEvent.Do(func() {
			details := map[string]any{
				"runtime_instance_id":   health.RuntimeInstanceID,
				"runtime_generation_id": health.RuntimeGenerationID,
			}
			var internalDetails map[string]any
			if exit.err != nil && ctx.Err() == nil {
				internalDetails = map[string]any{"error": exit.err.Error()}
			}
			s.emitInternal("plugin.runtime.process.stopped", observability.DiagnosticSeverityInfo, "runtime process stopped", details, internalDetails)
		})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *ProcessSupervisor) Health(context.Context) (Health, error) {
	if s == nil {
		return Health{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health, nil
}

func (s *ProcessSupervisor) Heartbeat(ctx context.Context) (HeartbeatResult, error) {
	rawPayload, err := s.heartbeatRequest(ctx)
	if err != nil {
		return HeartbeatResult{}, err
	}
	frame, err := s.callControlIPC(ctx, ipcFrameTypeHeartbeat, ipcFrameTypeHeartbeat, rawPayload)
	if err != nil {
		return HeartbeatResult{}, err
	}
	return decodeHeartbeatResponse(frame)
}

func (s *ProcessSupervisor) heartbeatRequest(ctx context.Context) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || !s.isReady() {
		return nil, ErrRuntimeNotReady
	}
	rawPayload, err := json.Marshal(heartbeatRequestPayload{
		SentUnixNano:       s.now().UnixNano(),
		MaxStalenessMillis: int64(s.maxHeartbeatStaleness / time.Millisecond),
	})
	if err != nil {
		return nil, err
	}
	return rawPayload, nil
}

func decodeHeartbeatResponse(frame ipcFrame) (HeartbeatResult, error) {
	response, err := decodeRuntimeResponse(frame)
	if err != nil {
		return HeartbeatResult{}, err
	}
	if !response.OK {
		return HeartbeatResult{}, response.err()
	}
	if len(response.Result) == 0 {
		return HeartbeatResult{}, fmt.Errorf("%w: heartbeat missing result", ErrRuntimeRequestFailed)
	}
	return decodeHeartbeatResult(response.Result, frame.RuntimeGenerationID)
}

func decodeHeartbeatResult(raw json.RawMessage, runtimeGenerationID string) (HeartbeatResult, error) {
	var payload heartbeatResultPayload
	if err := decodeStrictJSON(raw, &payload); err != nil {
		return HeartbeatResult{}, err
	}
	if payload.RuntimeGenerationID == "" ||
		payload.RuntimeUnixNano == nil ||
		payload.MaxStalenessMillis == nil ||
		payload.HostSentUnixNanoEcho == nil {
		return HeartbeatResult{}, fmt.Errorf("%w: heartbeat result missing required field", ErrRuntimeRequestFailed)
	}
	if payload.RuntimeGenerationID != runtimeGenerationID {
		return HeartbeatResult{}, fmt.Errorf("%w: heartbeat runtime_generation_id mismatch", ErrRuntimeRequestFailed)
	}
	if *payload.RuntimeUnixNano <= 0 || *payload.MaxStalenessMillis <= 0 || *payload.HostSentUnixNanoEcho <= 0 {
		return HeartbeatResult{}, fmt.Errorf("%w: heartbeat result contains non-positive timing field", ErrRuntimeRequestFailed)
	}
	return HeartbeatResult{
		RuntimeGenerationID:  payload.RuntimeGenerationID,
		RuntimeUnixNano:      *payload.RuntimeUnixNano,
		MaxStalenessMillis:   *payload.MaxStalenessMillis,
		HostSentUnixNanoEcho: *payload.HostSentUnixNanoEcho,
		ActiveInvocations:    payload.ActiveInvocations,
		QueuedInvocations:    payload.QueuedInvocations,
		Limits:               payload.Limits,
		ModuleCache:          payload.ModuleCache,
	}, nil
}

func (s *ProcessSupervisor) InvokeWorker(ctx context.Context, lease Lease, method string, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || !s.isReady() {
		return nil, ErrRuntimeNotReady
	}
	releaseAdmission, err := s.admission.acquire(ctx, lease.PluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer releaseAdmission()
	health := s.healthSnapshot()
	if err := validateRuntimeLeaseAudience(lease, health); err != nil {
		return nil, err
	}
	lease.KeyID = ""
	lease.Signature = ""
	lease, err = SignRuntimeLease(lease, method, s.runtimeLeaseSigningKey, s.runtimeLeasePrivateKey)
	if err != nil {
		s.emit("plugin.runtime.lease.signature_rejected", observability.DiagnosticSeverityWarning, "runtime execution lease could not be signed", map[string]any{
			"lease_id":              lease.LeaseID,
			"plugin_instance_id":    lease.PluginInstanceID,
			"runtime_generation_id": lease.RuntimeGenerationID,
			"runtime_instance_id":   lease.RuntimeInstanceID,
			"ipc_channel_id":        lease.IPCChannelID,
			"method":                method,
			"revoke_epoch":          lease.RevokeEpoch,
		})
		return nil, err
	}
	if err := s.verifyRuntimeLease(ctx, lease, method); err != nil {
		return nil, err
	}
	invocation := json.RawMessage(payload)
	if len(invocation) == 0 {
		invocation = json.RawMessage("null")
	}
	allowedInvocation, err := workerInvocationContextFromInvocation(lease, invocation)
	if err != nil {
		return nil, err
	}
	rawPayload, err := json.Marshal(invokeWorkerRequestPayload{
		Lease:      lease,
		Method:     method,
		Invocation: invocation,
	})
	if err != nil {
		return nil, err
	}
	if err := s.consumeRuntimeLease(ctx, lease, method); err != nil {
		return nil, err
	}
	frame, err := s.callIPC(ctx, ipcFrameTypeInvokeWorker, ipcFrameTypeInvokeWorkerResult, rawPayload, &allowedInvocation)
	if err != nil {
		return nil, err
	}
	response, err := decodeRuntimeResponse(frame)
	if err != nil {
		return nil, err
	}
	if !response.OK {
		return nil, response.workerExecutionError()
	}
	return append([]byte(nil), response.Result...), nil
}

func (s *ProcessSupervisor) Revoke(ctx context.Context, pluginInstanceID string, revokeEpoch uint64) (RevokeResult, error) {
	if err := ctx.Err(); err != nil {
		return RevokeResult{}, err
	}
	if s == nil || !s.isReady() {
		return RevokeResult{}, ErrRuntimeNotReady
	}
	rawPayload, err := json.Marshal(revokeEpochRequestPayload{
		PluginInstanceID: pluginInstanceID,
		RevokeEpoch:      revokeEpoch,
	})
	if err != nil {
		return RevokeResult{}, err
	}
	frame, err := s.callControlIPC(ctx, ipcFrameTypeRevokeEpoch, ipcFrameTypeRevokeEpochAck, rawPayload)
	if err != nil {
		return RevokeResult{}, err
	}
	response, err := decodeRuntimeResponse(frame)
	if err != nil {
		return RevokeResult{}, err
	}
	if !response.OK {
		return RevokeResult{}, response.err()
	}
	if len(response.Result) == 0 {
		return RevokeResult{}, fmt.Errorf("%w: revoke ack missing result", ErrRuntimeRequestFailed)
	}
	return decodeRevokeResult(response.Result, pluginInstanceID, revokeEpoch)
}

func (s *ProcessSupervisor) consumeRuntimeLease(ctx context.Context, lease Lease, method string) error {
	if s == nil || s.runtimeLeaseReplays == nil {
		return nil
	}
	_, err := s.runtimeLeaseReplays.ConsumeRuntimeLease(ctx, RuntimeLeaseReplayConsumeRequest{
		Lease:  lease,
		Method: method,
		Now:    s.now(),
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRuntimeLeaseReplay) {
		s.emit("plugin.runtime.lease.replayed", observability.DiagnosticSeverityWarning, "runtime execution lease was already consumed", map[string]any{
			"lease_id":              lease.LeaseID,
			"plugin_instance_id":    lease.PluginInstanceID,
			"runtime_generation_id": lease.RuntimeGenerationID,
			"method":                method,
			"revoke_epoch":          lease.RevokeEpoch,
		})
	}
	return err
}

func (s *ProcessSupervisor) verifyRuntimeLease(ctx context.Context, lease Lease, method string) error {
	if s == nil || s.runtimeLeaseVerifier == nil {
		return ErrRuntimeLeaseSignatureKeyringRequired
	}
	err := s.runtimeLeaseVerifier.VerifyRuntimeLease(ctx, RuntimeLeaseVerificationRequest{
		Lease:  lease,
		Method: method,
		Now:    s.now(),
	})
	if err == nil {
		return nil
	}
	s.emit("plugin.runtime.lease.signature_rejected", observability.DiagnosticSeverityWarning, "runtime execution lease signature was rejected", map[string]any{
		"lease_id":              lease.LeaseID,
		"plugin_instance_id":    lease.PluginInstanceID,
		"runtime_generation_id": lease.RuntimeGenerationID,
		"runtime_instance_id":   lease.RuntimeInstanceID,
		"ipc_channel_id":        lease.IPCChannelID,
		"key_id":                lease.KeyID,
		"method":                method,
		"revoke_epoch":          lease.RevokeEpoch,
	})
	return err
}

func (s *ProcessSupervisor) healthSnapshot() Health {
	if s == nil {
		return Health{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health
}

func validateRuntimeLeaseAudience(lease Lease, health Health) error {
	if !health.Ready {
		return ErrRuntimeNotReady
	}
	if strings.TrimSpace(lease.RuntimeGenerationID) != health.RuntimeGenerationID {
		return ErrRuntimeLeaseInvalid
	}
	if strings.TrimSpace(lease.RuntimeInstanceID) != health.RuntimeInstanceID {
		return ErrRuntimeLeaseInvalid
	}
	if strings.TrimSpace(lease.IPCChannelID) != health.IPCChannelID {
		return ErrRuntimeLeaseInvalid
	}
	if strings.TrimSpace(lease.ConnectionNonce) != health.ConnectionNonce {
		return ErrRuntimeLeaseInvalid
	}
	return nil
}

type revokeResultPayload struct {
	PluginInstanceID         string  `json:"plugin_instance_id"`
	RevokeEpoch              *uint64 `json:"revoke_epoch"`
	ClosedSocketCount        *int    `json:"closed_socket_count"`
	ClosedStreamCount        *int    `json:"closed_stream_count"`
	ClosedStorageHandleCount *int    `json:"closed_storage_handle_count"`
}

func decodeRevokeResult(raw json.RawMessage, pluginInstanceID string, revokeEpoch uint64) (RevokeResult, error) {
	var payload revokeResultPayload
	if err := decodeStrictJSON(raw, &payload); err != nil {
		return RevokeResult{}, err
	}
	if payload.PluginInstanceID == "" ||
		payload.RevokeEpoch == nil ||
		payload.ClosedSocketCount == nil ||
		payload.ClosedStreamCount == nil ||
		payload.ClosedStorageHandleCount == nil {
		return RevokeResult{}, fmt.Errorf("%w: revoke ack result missing required field", ErrRuntimeRequestFailed)
	}
	result := RevokeResult{
		PluginInstanceID:         payload.PluginInstanceID,
		RevokeEpoch:              *payload.RevokeEpoch,
		ClosedSocketCount:        *payload.ClosedSocketCount,
		ClosedStreamCount:        *payload.ClosedStreamCount,
		ClosedStorageHandleCount: *payload.ClosedStorageHandleCount,
	}
	if err := validateRevokeResult(result, pluginInstanceID, revokeEpoch); err != nil {
		return RevokeResult{}, err
	}
	return result, nil
}

func validateRevokeResult(result RevokeResult, pluginInstanceID string, revokeEpoch uint64) error {
	if result.PluginInstanceID != pluginInstanceID {
		return fmt.Errorf("%w: revoke ack plugin_instance_id mismatch", ErrRuntimeRequestFailed)
	}
	if result.RevokeEpoch != revokeEpoch {
		return fmt.Errorf("%w: revoke ack revoke_epoch mismatch", ErrRuntimeRequestFailed)
	}
	if result.ClosedSocketCount < 0 || result.ClosedStreamCount < 0 || result.ClosedStorageHandleCount < 0 {
		return fmt.Errorf("%w: revoke ack close counters must be non-negative", ErrRuntimeRequestFailed)
	}
	return nil
}

func (s *ProcessSupervisor) isReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readyLocked()
}

func (s *ProcessSupervisor) readyLocked() bool {
	return s.cmd != nil && s.health.Ready
}

func (s *ProcessSupervisor) wait(cmd *exec.Cmd, exit *processExit, cancel context.CancelFunc, generation *runtimeGeneration, health Health) {
	err := cmd.Wait()
	cancel()
	<-exit.ipcReaderDone
	s.failPendingGeneration(generation, fmt.Errorf("%w: runtime generation exited", ErrRuntimeIPCUnavailable))
	var controlIn io.WriteCloser
	var controlOut io.Closer
	s.mu.Lock()
	if s.cmd == cmd {
		s.health.Ready = false
		s.exitError = err
		s.cancel = nil
		s.exit = nil
		s.cmd = nil
		s.ipcIn = nil
		s.ipcOut = nil
		controlIn = s.controlIn
		controlOut = s.controlOutCloser
		s.controlIn = nil
		s.controlOut = nil
		s.controlOutCloser = nil
		if s.generation == generation {
			s.generation = nil
		}
	}
	s.mu.Unlock()
	if controlIn != nil {
		_ = controlIn.Close()
	}
	if controlOut != nil {
		_ = controlOut.Close()
	}
	severity := observability.DiagnosticSeverityInfo
	message := "runtime process exited"
	details := map[string]any{
		"runtime_instance_id":   health.RuntimeInstanceID,
		"runtime_generation_id": health.RuntimeGenerationID,
	}
	var internalDetails map[string]any
	if err != nil {
		severity = observability.DiagnosticSeverityWarning
		message = "runtime process exited with error"
		internalDetails = map[string]any{"error": err.Error()}
	}
	s.emitInternal("plugin.runtime.process.exited", severity, message, details, internalDetails)
	exit.err = err
	close(exit.done)
}

func (s *ProcessSupervisor) heartbeatLoop(ctx context.Context, health Health) {
	ticker := time.NewTicker(s.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !s.runtimeGenerationReady(health) {
			return
		}
		heartbeatCtx, cancel := context.WithTimeout(ctx, s.maxHeartbeatStaleness)
		_, err := s.Heartbeat(heartbeatCtx)
		cancel()
		if err == nil {
			continue
		}
		if ctx.Err() != nil || !s.runtimeGenerationReady(health) {
			return
		}
		s.invalidateRuntimeAfterIPCFailure(health, "runtime heartbeat failed", err)
		return
	}
}

func (s *ProcessSupervisor) runtimeGenerationReady(health Health) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readyLocked() && s.health.RuntimeGenerationID == health.RuntimeGenerationID
}

func (s *ProcessSupervisor) scanPipe(reader io.Reader, streamName string) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		severity := observability.DiagnosticSeverityInfo
		if streamName == "stderr" {
			severity = observability.DiagnosticSeverityWarning
		}
		s.emitInternal(
			"plugin.runtime.process."+streamName,
			severity,
			"runtime process wrote to "+streamName,
			map[string]any{"stream": streamName},
			map[string]any{"line": line},
		)
	}
	if err := scanner.Err(); err != nil {
		s.emitInternal(
			"plugin.runtime.process."+streamName+".error",
			observability.DiagnosticSeverityWarning,
			"runtime process output could not be read",
			map[string]any{"stream": streamName},
			map[string]any{"error": err.Error()},
		)
	}
}

func (s *ProcessSupervisor) emit(eventType string, severity observability.DiagnosticSeverity, message string, details map[string]any) {
	s.emitInternal(eventType, severity, message, details, nil)
}

func (s *ProcessSupervisor) emitInternal(eventType string, severity observability.DiagnosticSeverity, message string, details, internalDetails map[string]any) {
	if s == nil || s.diagnostics == nil {
		return
	}
	_ = s.diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type:            eventType,
		Severity:        severity,
		Message:         message,
		OccurredAt:      s.now(),
		Details:         details,
		InternalDetails: internalDetails,
	})
}

func (s *ProcessSupervisor) emitHostcallFailure(runtimeGenerationID, hostcall, code string, err error, details map[string]any) {
	if err == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	details["runtime_generation_id"] = runtimeGenerationID
	details["hostcall"] = hostcall
	details["code"] = code
	if s == nil || s.diagnostics == nil {
		return
	}
	_ = s.diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type:            "plugin.runtime.hostcall.failed",
		Severity:        "warning",
		Message:         "runtime hostcall failed",
		OccurredAt:      s.now(),
		Details:         details,
		InternalDetails: map[string]any{"error": err.Error()},
	})
}

const (
	ipcFrameTypeHello                 = "hello"
	ipcFrameTypeHelloAck              = "hello_ack"
	ipcFrameTypeHeartbeat             = "heartbeat"
	ipcFrameTypeInvokeWorker          = "invoke_worker"
	ipcFrameTypeInvokeWorkerResult    = "invoke_worker_result"
	ipcFrameTypeCancelInvoke          = "cancel_invoke"
	ipcFrameTypeCancelInvokeAck       = "cancel_invoke_ack"
	ipcFrameTypeCompileFlightRegister = "compile_flight_register"
	ipcFrameTypeCompileFlightComplete = "compile_flight_complete"
	ipcFrameTypeOpenHandle            = "open_handle"
	ipcFrameTypeValidateHandleGrant   = "validate_handle_grant"
	ipcFrameTypeStorageFile           = "storage_file"
	ipcFrameTypeStorageKV             = "storage_kv"
	ipcFrameTypeStorageSQLite         = "storage_sqlite"
	ipcFrameTypeNetworkGrant          = "network_grant"
	ipcFrameTypeNetworkExecute        = "network_execute"
	ipcFrameTypeRevokeEpoch           = "revoke_epoch"
	ipcFrameTypeRevokeEpochAck        = "revoke_epoch_ack"
)

const (
	defaultRuntimeHostcallTimeout    = 30 * time.Second
	maxRuntimeHostcallTimeout        = 30 * time.Second
	defaultRuntimeCancelAckTimeout   = 5 * time.Second
	maxIPCFrameBytes                 = 64 << 20
	maxWASMHostcallResponseBytes     = 512 << 10
	maxSynchronousBrokerPayloadBytes = 384 << 10
)

type ipcFrame struct {
	IPCVersion          string          `json:"ipc_version"`
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	ParentRequestID     string          `json:"parent_request_id,omitempty"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type helloRequestPayload struct {
	Target                 Target                  `json:"target"`
	HostProcessID          int                     `json:"host_process_id"`
	HostIPCVersion         string                  `json:"host_ipc_version"`
	HostWASMABI            string                  `json:"host_wasm_abi"`
	StartedUnixNano        int64                   `json:"started_unix_nano"`
	ChannelNonce           string                  `json:"channel_nonce"`
	RuntimeLeasePublicKeys []RuntimeLeasePublicKey `json:"runtime_lease_public_keys"`
	Limits                 RuntimeLimits           `json:"limits"`
}

type helloAckPayload struct {
	RuntimeVersion string        `json:"runtime_version"`
	ActualTarget   Target        `json:"actual_target"`
	RustIPCVersion string        `json:"rust_ipc_version"`
	WASMABIVersion string        `json:"wasm_abi_version"`
	ChannelNonce   string        `json:"channel_nonce"`
	Limits         RuntimeLimits `json:"limits"`
}

type heartbeatRequestPayload struct {
	SentUnixNano       int64 `json:"sent_unix_nano"`
	MaxStalenessMillis int64 `json:"max_staleness_ms"`
}

type heartbeatResultPayload struct {
	RuntimeGenerationID  string             `json:"runtime_generation_id"`
	RuntimeUnixNano      *int64             `json:"runtime_unix_nano"`
	MaxStalenessMillis   *int64             `json:"max_staleness_ms"`
	HostSentUnixNanoEcho *int64             `json:"host_sent_unix_nano"`
	ActiveInvocations    int                `json:"active_invocations"`
	QueuedInvocations    int                `json:"queued_invocations"`
	Limits               RuntimeLimits      `json:"limits"`
	ModuleCache          ModuleCacheMetrics `json:"module_cache"`
}

type invokeWorkerRequestPayload struct {
	Lease      Lease           `json:"lease"`
	Method     string          `json:"method"`
	Invocation json.RawMessage `json:"invocation"`
}

type cancelInvokeRequestPayload struct {
	InvocationRequestID string `json:"invocation_request_id"`
}

type cancelInvokeAckResultPayload struct {
	InvocationRequestID string `json:"invocation_request_id"`
	Disposition         string `json:"disposition"`
}

type revokeEpochRequestPayload struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	RevokeEpoch      uint64 `json:"revoke_epoch"`
}

type runtimeResponsePayload struct {
	OK          bool              `json:"ok"`
	Result      json.RawMessage   `json:"result,omitempty"`
	Code        string            `json:"code,omitempty"`
	Message     string            `json:"message,omitempty"`
	ErrorOrigin WorkerErrorOrigin `json:"error_origin,omitempty"`
}

type hostcallFailurePayload struct {
	OK          bool              `json:"ok"`
	Code        string            `json:"code"`
	Message     string            `json:"message"`
	ErrorOrigin WorkerErrorOrigin `json:"error_origin"`
}

type artifactHandleRequestPayload struct {
	PackageHash    string `json:"package_hash"`
	Artifact       string `json:"artifact"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type compileFlightLifecyclePayload struct {
	ArtifactRequestID string `json:"artifact_request_id"`
	PackageHash       string `json:"package_hash"`
	Artifact          string `json:"artifact"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	WASMABIVersion    string `json:"wasm_abi_version"`
}

type artifactHandleResultPayload struct {
	OK            bool              `json:"ok"`
	PackageHash   string            `json:"package_hash"`
	Artifact      string            `json:"artifact"`
	SHA256        string            `json:"sha256"`
	ContentBase64 string            `json:"content_base64"`
	Code          string            `json:"code,omitempty"`
	Message       string            `json:"message,omitempty"`
	ErrorOrigin   WorkerErrorOrigin `json:"error_origin,omitempty"`
}

type handleGrantValidationResultPayload struct {
	OK                  bool              `json:"ok"`
	HandleGrantID       string            `json:"handle_grant_id"`
	HandleID            string            `json:"handle_id"`
	Method              string            `json:"method"`
	RuntimeGenerationID string            `json:"runtime_generation_id"`
	MaxBytesPerSecond   int64             `json:"max_bytes_per_second,omitempty"`
	MaxTotalBytes       int64             `json:"max_total_bytes,omitempty"`
	Code                string            `json:"code,omitempty"`
	Message             string            `json:"message,omitempty"`
	ErrorOrigin         WorkerErrorOrigin `json:"error_origin,omitempty"`
}

type storageFileRequestPayload struct {
	HandleGrantToken    string `json:"handle_grant_token"`
	PluginInstanceID    string `json:"plugin_instance_id"`
	ActiveFingerprint   string `json:"active_fingerprint"`
	RuntimeInstanceID   string `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	RuntimeShardID      string `json:"runtime_shard_id,omitempty"`
	HandleID            string `json:"handle_id"`
	Method              string `json:"method"`
	PolicyRevision      uint64 `json:"policy_revision"`
	ManagementRevision  uint64 `json:"management_revision"`
	RevokeEpoch         uint64 `json:"revoke_epoch"`
	Operation           string `json:"operation"`
	StoreID             string `json:"store_id"`
	Path                string `json:"path,omitempty"`
	DataBase64          string `json:"data_base64,omitempty"`
	MaxBytes            int64  `json:"max_bytes,omitempty"`
	MaxEntries          int    `json:"max_entries,omitempty"`
	Recursive           bool   `json:"recursive,omitempty"`
}

type storageFileResponsePayload struct {
	Operation     string              `json:"-"`
	OK            bool                `json:"ok"`
	Path          string              `json:"path"`
	DataBase64    string              `json:"data_base64,omitempty"`
	SizeBytes     int64               `json:"size_bytes,omitempty"`
	Entries       []storage.FileEntry `json:"entries,omitempty"`
	Usage         *storage.Usage      `json:"usage,omitempty"`
	Code          string              `json:"code,omitempty"`
	Message       string              `json:"message,omitempty"`
	ErrorOrigin   WorkerErrorOrigin   `json:"error_origin,omitempty"`
	InternalError error               `json:"-"`
}

type storageFileReadSuccessPayload struct {
	OK         bool          `json:"ok"`
	Path       string        `json:"path"`
	DataBase64 string        `json:"data_base64"`
	SizeBytes  int64         `json:"size_bytes"`
	Usage      storage.Usage `json:"usage"`
}

type storageFileWriteSuccessPayload struct {
	OK        bool          `json:"ok"`
	Path      string        `json:"path"`
	SizeBytes int64         `json:"size_bytes"`
	Usage     storage.Usage `json:"usage"`
}

type storageFileDeleteSuccessPayload struct {
	OK   bool   `json:"ok"`
	Path string `json:"path"`
}

type storageFileListSuccessPayload struct {
	OK      bool                `json:"ok"`
	Path    string              `json:"path"`
	Entries []storage.FileEntry `json:"entries"`
	Usage   storage.Usage       `json:"usage"`
}

type storageKVRequestPayload struct {
	HandleGrantToken    string `json:"handle_grant_token"`
	PluginInstanceID    string `json:"plugin_instance_id"`
	ActiveFingerprint   string `json:"active_fingerprint"`
	RuntimeInstanceID   string `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	RuntimeShardID      string `json:"runtime_shard_id,omitempty"`
	HandleID            string `json:"handle_id"`
	Method              string `json:"method"`
	PolicyRevision      uint64 `json:"policy_revision"`
	ManagementRevision  uint64 `json:"management_revision"`
	RevokeEpoch         uint64 `json:"revoke_epoch"`
	Operation           string `json:"operation"`
	StoreID             string `json:"store_id"`
	Key                 string `json:"key,omitempty"`
	ValueBase64         string `json:"value_base64,omitempty"`
	Prefix              string `json:"prefix,omitempty"`
	MaxBytes            int64  `json:"max_bytes,omitempty"`
	MaxEntries          int    `json:"max_entries,omitempty"`
}

type storageKVResponsePayload struct {
	Operation     string            `json:"-"`
	OK            bool              `json:"ok"`
	Key           string            `json:"key,omitempty"`
	ValueBase64   string            `json:"value_base64,omitempty"`
	SizeBytes     int64             `json:"size_bytes,omitempty"`
	Prefix        string            `json:"prefix,omitempty"`
	Entries       []storage.KVEntry `json:"entries,omitempty"`
	Usage         *storage.Usage    `json:"usage,omitempty"`
	Code          string            `json:"code,omitempty"`
	Message       string            `json:"message,omitempty"`
	ErrorOrigin   WorkerErrorOrigin `json:"error_origin,omitempty"`
	InternalError error             `json:"-"`
}

type storageKVGetSuccessPayload struct {
	OK          bool          `json:"ok"`
	Key         string        `json:"key"`
	ValueBase64 string        `json:"value_base64"`
	SizeBytes   int64         `json:"size_bytes"`
	Usage       storage.Usage `json:"usage"`
}

type storageKVPutSuccessPayload struct {
	OK        bool          `json:"ok"`
	Key       string        `json:"key"`
	SizeBytes int64         `json:"size_bytes"`
	Usage     storage.Usage `json:"usage"`
}

type storageKVDeleteSuccessPayload struct {
	OK  bool   `json:"ok"`
	Key string `json:"key"`
}

type storageKVListSuccessPayload struct {
	OK      bool              `json:"ok"`
	Prefix  string            `json:"prefix,omitempty"`
	Entries []storage.KVEntry `json:"entries"`
	Usage   storage.Usage     `json:"usage"`
}

type storageSQLiteRequestPayload struct {
	HandleGrantToken    string                  `json:"handle_grant_token"`
	PluginInstanceID    string                  `json:"plugin_instance_id"`
	ActiveFingerprint   string                  `json:"active_fingerprint"`
	RuntimeInstanceID   string                  `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string                  `json:"runtime_generation_id"`
	RuntimeShardID      string                  `json:"runtime_shard_id,omitempty"`
	HandleID            string                  `json:"handle_id"`
	Method              string                  `json:"method"`
	PolicyRevision      uint64                  `json:"policy_revision"`
	ManagementRevision  uint64                  `json:"management_revision"`
	RevokeEpoch         uint64                  `json:"revoke_epoch"`
	Operation           string                  `json:"operation"`
	StoreID             string                  `json:"store_id"`
	Database            string                  `json:"database,omitempty"`
	SQL                 string                  `json:"sql"`
	Args                []storageSQLiteValueIPC `json:"args,omitempty"`
	MaxRows             int                     `json:"max_rows,omitempty"`
	MaxResponseBytes    int64                   `json:"max_response_bytes,omitempty"`
	TimeoutMillis       int64                   `json:"timeout_ms,omitempty"`
}

type storageSQLiteResponsePayload struct {
	Operation     string                     `json:"-"`
	OK            bool                       `json:"ok"`
	Database      string                     `json:"database"`
	RowsAffected  *int64                     `json:"rows_affected,omitempty"`
	LastInsertID  int64                      `json:"last_insert_id,omitempty"`
	Columns       *[]string                  `json:"columns,omitempty"`
	Rows          *[][]storageSQLiteValueIPC `json:"rows,omitempty"`
	Usage         *storage.Usage             `json:"usage,omitempty"`
	Code          string                     `json:"code,omitempty"`
	Message       string                     `json:"message,omitempty"`
	ErrorOrigin   WorkerErrorOrigin          `json:"error_origin,omitempty"`
	InternalError error                      `json:"-"`
}

type storageSQLiteExecSuccessPayload struct {
	OK           bool          `json:"ok"`
	Database     string        `json:"database"`
	RowsAffected int64         `json:"rows_affected"`
	LastInsertID int64         `json:"last_insert_id,omitempty"`
	Usage        storage.Usage `json:"usage"`
}

type storageSQLiteQuerySuccessPayload struct {
	OK       bool                      `json:"ok"`
	Database string                    `json:"database"`
	Columns  []string                  `json:"columns"`
	Rows     [][]storageSQLiteValueIPC `json:"rows"`
	Usage    storage.Usage             `json:"usage"`
}

type storageSQLiteValueIPC struct {
	Null       *bool    `json:"null,omitempty"`
	Int        *int64   `json:"int,omitempty"`
	Float      *float64 `json:"float,omitempty"`
	Text       *string  `json:"text,omitempty"`
	BlobBase64 *string  `json:"blob_base64,omitempty"`
}

type networkGrantRequestPayload struct {
	PluginInstanceID    string                 `json:"plugin_instance_id"`
	ActiveFingerprint   string                 `json:"active_fingerprint"`
	RuntimeInstanceID   string                 `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string                 `json:"runtime_generation_id"`
	RuntimeShardID      string                 `json:"runtime_shard_id,omitempty"`
	PolicyRevision      uint64                 `json:"policy_revision"`
	ManagementRevision  uint64                 `json:"management_revision"`
	RevokeEpoch         uint64                 `json:"revoke_epoch"`
	ConnectorID         string                 `json:"connector_id"`
	Transport           connectivity.Transport `json:"transport"`
	Destination         string                 `json:"destination"`
	TTLMillis           int64                  `json:"ttl_ms,omitempty"`
}

type networkGrantResponsePayload struct {
	OK                      bool                     `json:"ok"`
	GrantID                 string                   `json:"grant_id"`
	PluginInstanceID        string                   `json:"plugin_instance_id"`
	ActiveFingerprint       string                   `json:"active_fingerprint"`
	PolicyRevision          uint64                   `json:"policy_revision"`
	ManagementRevision      uint64                   `json:"management_revision"`
	RevokeEpoch             uint64                   `json:"revoke_epoch"`
	ConnectorID             string                   `json:"connector_id"`
	Transport               connectivity.Transport   `json:"transport"`
	Destination             connectivity.Destination `json:"destination"`
	RuntimeGenerationID     string                   `json:"runtime_generation_id"`
	TargetClassifierVersion string                   `json:"target_classifier_version"`
	ExpiresAt               time.Time                `json:"expires_at"`
	Code                    string                   `json:"code,omitempty"`
	Message                 string                   `json:"message,omitempty"`
	ErrorOrigin             WorkerErrorOrigin        `json:"error_origin,omitempty"`
	InternalError           error                    `json:"-"`
}

type networkExecuteRequestPayload struct {
	PluginID             string                 `json:"plugin_id,omitempty"`
	PluginInstanceID     string                 `json:"plugin_instance_id"`
	ActiveFingerprint    string                 `json:"active_fingerprint"`
	RuntimeInstanceID    string                 `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID  string                 `json:"runtime_generation_id"`
	RuntimeShardID       string                 `json:"runtime_shard_id,omitempty"`
	PolicyRevision       uint64                 `json:"policy_revision"`
	ManagementRevision   uint64                 `json:"management_revision"`
	RevokeEpoch          uint64                 `json:"revoke_epoch"`
	ConnectorID          string                 `json:"connector_id"`
	Transport            connectivity.Transport `json:"transport"`
	Destination          string                 `json:"destination"`
	TTLMillis            int64                  `json:"ttl_ms,omitempty"`
	Operation            string                 `json:"operation,omitempty"`
	Method               string                 `json:"method,omitempty"`
	Path                 string                 `json:"path,omitempty"`
	Query                url.Values             `json:"query,omitempty"`
	Headers              http.Header            `json:"headers,omitempty"`
	MessageType          string                 `json:"message_type,omitempty"`
	BodyBase64           string                 `json:"body_base64,omitempty"`
	PayloadBase64        string                 `json:"payload_base64,omitempty"`
	MaxRequestBytes      int64                  `json:"max_request_bytes,omitempty"`
	MaxResponseBytes     int64                  `json:"max_response_bytes,omitempty"`
	MaxChunkBytes        int64                  `json:"max_chunk_bytes,omitempty"`
	MaxBufferedBytes     int64                  `json:"max_buffered_bytes,omitempty"`
	TimeoutMillis        int64                  `json:"timeout_ms,omitempty"`
	StreamID             string                 `json:"stream_id,omitempty"`
	StreamMethod         string                 `json:"stream_method,omitempty"`
	StreamEffect         string                 `json:"stream_effect,omitempty"`
	StreamExecution      string                 `json:"stream_execution,omitempty"`
	SurfaceInstanceID    string                 `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string                 `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string                 `json:"owner_user_hash,omitempty"`
	OwnerEnvHash         string                 `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash string                 `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string                 `json:"bridge_channel_id,omitempty"`
	ContentType          string                 `json:"content_type,omitempty"`
}

type networkExecuteResponsePayload struct {
	OK                bool                     `json:"ok"`
	Transport         connectivity.Transport   `json:"transport"`
	Destination       connectivity.Destination `json:"destination"`
	StatusCode        int                      `json:"status_code,omitempty"`
	Headers           http.Header              `json:"headers,omitempty"`
	MessageType       string                   `json:"message_type,omitempty"`
	BodyBase64        string                   `json:"body_base64,omitempty"`
	PayloadBase64     string                   `json:"payload_base64,omitempty"`
	StreamID          string                   `json:"stream_id,omitempty"`
	BytesRead         int64                    `json:"bytes_read,omitempty"`
	ChunkCount        int                      `json:"chunk_count,omitempty"`
	GrantID           string                   `json:"grant_id"`
	ConnectorID       string                   `json:"connector_id"`
	RuntimeGeneration string                   `json:"runtime_generation_id"`
	Code              string                   `json:"code,omitempty"`
	Message           string                   `json:"message,omitempty"`
	ErrorOrigin       WorkerErrorOrigin        `json:"error_origin,omitempty"`
	InternalError     error                    `json:"-"`
}

func (p runtimeResponsePayload) err() error {
	message := strings.TrimSpace(p.Message)
	code := strings.TrimSpace(p.Code)
	if p.OK || code == "" || message == "" || !p.ErrorOrigin.valid() {
		return fmt.Errorf("%w: invalid runtime error response", ErrRuntimeIPCUnavailable)
	}
	return fmt.Errorf("%w: %s: %s", ErrRuntimeRequestFailed, code, message)
}

func (p runtimeResponsePayload) workerExecutionError() error {
	message := strings.TrimSpace(p.Message)
	code := strings.TrimSpace(p.Code)
	if p.OK || code == "" || message == "" || !p.ErrorOrigin.valid() {
		return fmt.Errorf("%w: worker response error_origin is missing or invalid", ErrRuntimeIPCUnavailable)
	}
	return &WorkerExecutionError{Code: code, Message: message, Origin: p.ErrorOrigin}
}

func (s *ProcessSupervisor) performHandshake(ctx context.Context, stdin io.Writer, stdout *bufio.Reader, health Health, target Target) (helloAckPayload, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, s.handshakeTimeout)
	defer cancel()
	requestID := health.RuntimeGenerationID + ":hello"
	channelNonce, err := randomIPCChannelNonce()
	if err != nil {
		return helloAckPayload{}, err
	}
	payload, err := json.Marshal(helloRequestPayload{
		Target:                 target,
		HostProcessID:          os.Getpid(),
		HostIPCVersion:         version.RustIPCVersion,
		HostWASMABI:            version.WASMABIVersion,
		StartedUnixNano:        s.now().UnixNano(),
		ChannelNonce:           channelNonce,
		RuntimeLeasePublicKeys: append([]RuntimeLeasePublicKey(nil), s.runtimeLeasePublicKeys...),
		Limits:                 s.limits,
	})
	if err != nil {
		return helloAckPayload{}, err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeHello,
		RequestID:           requestID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		Payload:             payload,
	}); err != nil {
		return helloAckPayload{}, fmt.Errorf("%w: write hello: %v", ErrRuntimeHandshake, err)
	}

	result := make(chan struct {
		frame ipcFrame
		err   error
	}, 1)
	go func() {
		frame, err := readIPCFrame(stdout)
		result <- struct {
			frame ipcFrame
			err   error
		}{frame: frame, err: err}
	}()

	select {
	case <-handshakeCtx.Done():
		return helloAckPayload{}, fmt.Errorf("%w: %v", ErrRuntimeHandshake, handshakeCtx.Err())
	case got := <-result:
		if got.err != nil {
			return helloAckPayload{}, fmt.Errorf("%w: read hello ack: %v", ErrRuntimeHandshake, got.err)
		}
		return validateHelloAck(requestID, health.RuntimeGenerationID, channelNonce, s.descriptor, s.limits, got.frame)
	}
}

func randomIPCChannelNonce() (string, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate ipc channel nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}

func (s *ProcessSupervisor) callIPC(ctx context.Context, frameType string, responseFrameType string, payload json.RawMessage, allowedInvocation *workerInvocationContext) (ipcFrame, error) {
	return s.callIPCRequest(ctx, frameType, responseFrameType, payload, allowedInvocation, frameType == ipcFrameTypeInvokeWorker)
}

func (s *ProcessSupervisor) callControlIPC(ctx context.Context, frameType string, responseFrameType string, payload json.RawMessage) (ipcFrame, error) {
	if err := ctx.Err(); err != nil {
		return ipcFrame{}, err
	}
	s.controlMu.Lock()
	defer s.controlMu.Unlock()

	s.mu.Lock()
	if !s.readyLocked() || s.controlIn == nil || s.controlOut == nil {
		s.mu.Unlock()
		return ipcFrame{}, ErrRuntimeNotReady
	}
	s.requestSeq++
	health := s.health
	requestID := fmt.Sprintf("%s:%s:%d", health.RuntimeGenerationID, frameType, s.requestSeq)
	stdin := s.controlIn
	stdout := s.controlOut
	s.mu.Unlock()

	if len(payload) == 0 {
		payload = json.RawMessage("null")
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           frameType,
		RequestID:           requestID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		Payload:             payload,
	}); err != nil {
		return ipcFrame{}, fmt.Errorf("%w: write control %s: %v", ErrRuntimeIPCUnavailable, frameType, err)
	}

	type readResult struct {
		frame ipcFrame
		err   error
	}
	result := make(chan readResult, 1)
	go func() {
		frame, err := readIPCFrame(stdout)
		result <- readResult{frame: frame, err: err}
	}()
	select {
	case <-ctx.Done():
		s.invalidateRuntimeAfterIPCFailure(health, "runtime control request context canceled", ctx.Err())
		return ipcFrame{}, ctx.Err()
	case got := <-result:
		if got.err != nil {
			return ipcFrame{}, fmt.Errorf("%w: read control %s: %v", ErrRuntimeIPCUnavailable, responseFrameType, got.err)
		}
		if err := validateIPCResponse(requestID, health.RuntimeGenerationID, responseFrameType, got.frame); err != nil {
			return ipcFrame{}, fmt.Errorf("%w: invalid control response: %v", ErrRuntimeRequestFailed, err)
		}
		return got.frame, nil
	}
}

func (s *ProcessSupervisor) callIPCRequest(ctx context.Context, frameType string, responseFrameType string, payload json.RawMessage, allowedInvocation *workerInvocationContext, cancelInvocation bool) (ipcFrame, error) {
	if err := ctx.Err(); err != nil {
		return ipcFrame{}, err
	}
	s.mu.Lock()
	if !s.readyLocked() || s.generation == nil || s.ipcOut == nil {
		s.mu.Unlock()
		return ipcFrame{}, ErrRuntimeNotReady
	}
	s.requestSeq++
	health := s.health
	requestID := fmt.Sprintf("%s:%s:%d", health.RuntimeGenerationID, frameType, s.requestSeq)
	generation := s.generation
	stdin := generation.stdin
	s.mu.Unlock()
	if generation.id != health.RuntimeGenerationID || generation.ctx.Err() != nil || stdin == nil {
		return ipcFrame{}, ErrRuntimeNotReady
	}
	if len(payload) == 0 {
		payload = json.RawMessage("null")
	}
	pending := &pendingIPCRequest{
		ctx:               ctx,
		generation:        generation,
		responseFrameType: responseFrameType,
		invocation:        allowedInvocation,
		result:            make(chan ipcCallResult, 1),
	}
	s.pendingMu.Lock()
	if _, exists := s.pending[requestID]; exists {
		s.pendingMu.Unlock()
		return ipcFrame{}, fmt.Errorf("%w: duplicate request_id", ErrRuntimeIPCUnavailable)
	}
	var compileFlight *pendingCompileFlight
	if allowedInvocation != nil {
		artifactRequestID := requestID + ":artifact"
		if s.compileFlights == nil {
			s.compileFlights = map[string]*pendingCompileFlight{}
		}
		if _, exists := s.compileFlights[artifactRequestID]; exists {
			s.pendingMu.Unlock()
			return ipcFrame{}, fmt.Errorf("%w: duplicate compile flight artifact request_id", ErrRuntimeIPCUnavailable)
		}
		maxCompileFlightIntents := s.limits.WorkerCount + s.limits.QueueCapacity
		if len(s.compileFlights) >= maxCompileFlightIntents {
			s.pendingMu.Unlock()
			return ipcFrame{}, fmt.Errorf("%w: compile flight intent capacity is exhausted", ErrRuntimeIPCUnavailable)
		}
		compileFlight = &pendingCompileFlight{
			generation:        generation,
			parentRequestID:   requestID,
			artifactRequestID: artifactRequestID,
			artifact:          allowedInvocation.Artifact,
			wasmABIVersion:    version.WASMABIVersion,
		}
		s.compileFlights[artifactRequestID] = compileFlight
	}
	s.pending[requestID] = pending
	s.pendingMu.Unlock()
	unregister := func() {
		s.pendingMu.Lock()
		if s.pending[requestID] == pending {
			delete(s.pending, requestID)
		}
		s.pendingMu.Unlock()
	}
	if err := ctx.Err(); err != nil {
		unregister()
		s.removeCompileFlightIntent(compileFlight)
		return ipcFrame{}, err
	}
	if !s.runtimeGenerationCurrent(generation) {
		unregister()
		s.removeCompileFlightIntent(compileFlight)
		return ipcFrame{}, ErrRuntimeNotReady
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           frameType,
		RequestID:           requestID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		Payload:             payload,
	}); err != nil {
		unregister()
		s.removeCompileFlightIntent(compileFlight)
		return ipcFrame{}, fmt.Errorf("%w: write %s: %v", ErrRuntimeIPCUnavailable, frameType, err)
	}
	select {
	case got := <-pending.result:
		unregister()
		return got.frame, got.err
	case <-ctx.Done():
		if !cancelInvocation {
			unregister()
			return ipcFrame{}, ctx.Err()
		}
		cancelPayload, err := json.Marshal(cancelInvokeRequestPayload{InvocationRequestID: requestID})
		if err != nil {
			unregister()
			return ipcFrame{}, ctx.Err()
		}
		cancelCtx, cancel := context.WithTimeout(context.Background(), defaultRuntimeCancelAckTimeout)
		cancelFrame, cancelErr := s.callIPCRequest(cancelCtx, ipcFrameTypeCancelInvoke, ipcFrameTypeCancelInvokeAck, cancelPayload, nil, false)
		cancel()
		if cancelErr == nil {
			disposition, decodeErr := decodeCancelInvokeAck(cancelFrame, requestID)
			if decodeErr != nil {
				cancelErr = decodeErr
			} else {
				s.reconcileCompileFlightAfterCancelAck(generation, requestID, disposition)
			}
		}
		unregister()
		if cancelErr != nil {
			s.invalidateRuntimeAfterIPCFailure(health, "runtime invocation cancellation acknowledgement failed", cancelErr)
		}
		return ipcFrame{}, ctx.Err()
	}
}

func decodeCancelInvokeAck(frame ipcFrame, invocationRequestID string) (string, error) {
	response, err := decodeRuntimeResponse(frame)
	if err != nil {
		return "", err
	}
	if !response.OK || len(response.Result) == 0 {
		return "", fmt.Errorf("%w: cancel acknowledgement is not successful", ErrRuntimeIPCUnavailable)
	}
	var result cancelInvokeAckResultPayload
	if err := decodeStrictJSON(response.Result, &result); err != nil {
		return "", fmt.Errorf("%w: invalid cancel acknowledgement: %v", ErrRuntimeIPCUnavailable, err)
	}
	if result.InvocationRequestID != invocationRequestID ||
		(result.Disposition != "queued" && result.Disposition != "running" && result.Disposition != "complete") {
		return "", fmt.Errorf("%w: cancel acknowledgement identity is invalid", ErrRuntimeIPCUnavailable)
	}
	return result.Disposition, nil
}

func (s *ProcessSupervisor) runtimeGenerationCurrent(generation *runtimeGeneration) bool {
	if s == nil || generation == nil || generation.ctx.Err() != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readyLocked() && s.generation == generation && s.health.RuntimeGenerationID == generation.id
}

func (s *ProcessSupervisor) readIPCLoop(stdout *bufio.Reader, generation *runtimeGeneration, health Health) {
	for {
		frame, err := readIPCFrame(stdout)
		if err != nil {
			wrapped := fmt.Errorf("%w: read ipc frame: %v", ErrRuntimeIPCUnavailable, err)
			s.failPendingGeneration(generation, wrapped)
			if s.runtimeGenerationReady(health) {
				s.invalidateRuntimeAfterIPCFailure(health, "runtime ipc reader failed", wrapped)
			}
			return
		}
		if frame.IPCVersion != version.RustIPCVersion || frame.RuntimeGenerationID != health.RuntimeGenerationID {
			err := fmt.Errorf("%w: invalid runtime frame identity", ErrRuntimeIPCUnavailable)
			s.failPendingGeneration(generation, err)
			s.invalidateRuntimeAfterIPCFailure(health, "runtime ipc frame identity failed", err)
			return
		}
		switch frame.FrameType {
		case ipcFrameTypeCompileFlightRegister:
			if err := s.registerCompileFlight(generation, frame); err != nil {
				s.failPendingGeneration(generation, err)
				s.invalidateRuntimeAfterIPCFailure(health, "runtime compile flight registration failed", err)
				return
			}
			continue
		case ipcFrameTypeCompileFlightComplete:
			if err := s.completeCompileFlight(generation, frame); err != nil {
				s.failPendingGeneration(generation, err)
				s.invalidateRuntimeAfterIPCFailure(health, "runtime compile flight completion failed", err)
				return
			}
			continue
		case ipcFrameTypeOpenHandle:
			flight, ok := s.claimCompileFlightArtifact(generation, frame)
			if !ok {
				err := fmt.Errorf("%w: runtime artifact request is not bound to a registered compile flight", ErrRuntimeIPCUnavailable)
				s.failPendingGeneration(generation, err)
				s.invalidateRuntimeAfterIPCFailure(health, "runtime compile flight artifact binding failed", err)
				return
			}
			s.dispatchCompileFlightArtifact(generation, health, frame, flight)
			continue
		case ipcFrameTypeInvokeWorkerResult:
			s.removeUnregisteredCompileFlightIntent(generation, frame.RequestID)
		}
		if runtimeOriginFrame(frame.FrameType) {
			parent, ok := s.activeInvocationParent(generation, frame.ParentRequestID)
			if !ok {
				err := fmt.Errorf("%w: runtime hostcall parent_request_id is not an active invocation", ErrRuntimeIPCUnavailable)
				s.failPendingGeneration(generation, err)
				s.invalidateRuntimeAfterIPCFailure(health, "runtime hostcall parent binding failed", err)
				return
			}
			s.dispatchRuntimeHostcall(generation, health, frame, parent)
			continue
		}
		s.pendingMu.Lock()
		pending := s.pending[frame.RequestID]
		s.pendingMu.Unlock()
		if pending == nil || pending.generation != generation {
			continue
		}
		result := ipcCallResult{frame: frame}
		if err := validateIPCResponse(frame.RequestID, health.RuntimeGenerationID, pending.responseFrameType, frame); err != nil {
			result = ipcCallResult{err: err}
		}
		select {
		case pending.result <- result:
		default:
		}
	}
}

func runtimeOriginFrame(frameType string) bool {
	switch frameType {
	case ipcFrameTypeValidateHandleGrant, ipcFrameTypeStorageFile, ipcFrameTypeStorageKV, ipcFrameTypeStorageSQLite, ipcFrameTypeNetworkGrant, ipcFrameTypeNetworkExecute:
		return true
	default:
		return false
	}
}

func (s *ProcessSupervisor) removeCompileFlightIntent(flight *pendingCompileFlight) {
	if s == nil || flight == nil {
		return
	}
	s.pendingMu.Lock()
	if s.compileFlights[flight.artifactRequestID] == flight {
		delete(s.compileFlights, flight.artifactRequestID)
	}
	s.pendingMu.Unlock()
}

func (s *ProcessSupervisor) removeUnregisteredCompileFlightIntent(generation *runtimeGeneration, parentRequestID string) {
	s.pendingMu.Lock()
	for artifactRequestID, flight := range s.compileFlights {
		if flight.generation == generation && flight.parentRequestID == parentRequestID && !flight.registered {
			delete(s.compileFlights, artifactRequestID)
		}
	}
	s.pendingMu.Unlock()
}

func (s *ProcessSupervisor) reconcileCompileFlightAfterCancelAck(generation *runtimeGeneration, parentRequestID, disposition string) {
	if disposition == "queued" || disposition == "complete" {
		s.removeUnregisteredCompileFlightIntent(generation, parentRequestID)
	}
}

func (s *ProcessSupervisor) registerCompileFlight(generation *runtimeGeneration, frame ipcFrame) error {
	var payload compileFlightLifecyclePayload
	if err := decodeStrictJSON(frame.Payload, &payload); err != nil {
		return fmt.Errorf("%w: invalid compile flight registration payload: %v", ErrRuntimeIPCUnavailable, err)
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	flight := s.compileFlights[payload.ArtifactRequestID]
	if flight == nil || flight.generation != generation || flight.registered ||
		frame.ParentRequestID != flight.parentRequestID || frame.RequestID != flight.artifactRequestID+":register" ||
		payload.ArtifactRequestID != flight.artifactRequestID || payload.WASMABIVersion != flight.wasmABIVersion ||
		payload.PackageHash != flight.artifact.PackageHash || payload.Artifact != flight.artifact.Artifact ||
		payload.ArtifactSHA256 != flight.artifact.ArtifactSHA256 {
		return fmt.Errorf("%w: compile flight registration identity mismatch", ErrRuntimeIPCUnavailable)
	}
	flight.registered = true
	return nil
}

func (s *ProcessSupervisor) completeCompileFlight(generation *runtimeGeneration, frame ipcFrame) error {
	var payload compileFlightLifecyclePayload
	if err := decodeStrictJSON(frame.Payload, &payload); err != nil {
		return fmt.Errorf("%w: invalid compile flight completion payload: %v", ErrRuntimeIPCUnavailable, err)
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	flight := s.compileFlights[payload.ArtifactRequestID]
	if flight == nil || flight.generation != generation || !flight.registered ||
		frame.ParentRequestID != flight.parentRequestID || frame.RequestID != flight.artifactRequestID+":complete" ||
		payload.ArtifactRequestID != flight.artifactRequestID || payload.WASMABIVersion != flight.wasmABIVersion || payload.PackageHash != flight.artifact.PackageHash ||
		payload.Artifact != flight.artifact.Artifact || payload.ArtifactSHA256 != flight.artifact.ArtifactSHA256 {
		return fmt.Errorf("%w: compile flight completion identity mismatch", ErrRuntimeIPCUnavailable)
	}
	delete(s.compileFlights, payload.ArtifactRequestID)
	return nil
}

func (s *ProcessSupervisor) claimCompileFlightArtifact(generation *runtimeGeneration, frame ipcFrame) (*pendingCompileFlight, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	flight := s.compileFlights[frame.RequestID]
	if flight == nil || flight.generation != generation || !flight.registered || flight.artifactRequested ||
		frame.ParentRequestID != flight.parentRequestID {
		return nil, false
	}
	flight.artifactRequested = true
	copy := *flight
	return &copy, true
}

func (s *ProcessSupervisor) dispatchCompileFlightArtifact(generation *runtimeGeneration, health Health, frame ipcFrame, flight *pendingCompileFlight) {
	stdin := generation.stdin
	if stdin == nil || flight == nil {
		return
	}
	go func() {
		artifactCtx, cancelArtifact := runtimeArtifactHostcallContext(context.Background(), generation.ctx)
		err := s.respondToOpenHandle(artifactCtx, stdin, health.RuntimeGenerationID, frame, &flight.artifact)
		cancelArtifact()
		if err != nil {
			s.invalidateRuntimeAfterIPCFailure(health, "runtime compile flight artifact response failed", err)
		}
	}()
}

func (s *ProcessSupervisor) activeInvocationParent(generation *runtimeGeneration, parentRequestID string) (*pendingIPCRequest, bool) {
	if strings.TrimSpace(parentRequestID) == "" {
		return nil, false
	}
	s.pendingMu.Lock()
	parent := s.pending[parentRequestID]
	s.pendingMu.Unlock()
	return parent, parent != nil && parent.generation == generation && parent.invocation != nil && parent.responseFrameType == ipcFrameTypeInvokeWorkerResult
}

func (s *ProcessSupervisor) dispatchRuntimeHostcall(generation *runtimeGeneration, health Health, frame ipcFrame, parent *pendingIPCRequest) {
	invocation := parent.invocation
	ctx := parent.ctx
	stdin := generation.stdin
	if stdin == nil {
		return
	}
	go func() {
		var err error
		switch frame.FrameType {
		case ipcFrameTypeValidateHandleGrant:
			err = s.respondToValidateHandleGrant(ctx, stdin, health.RuntimeGenerationID, frame, allowedArtifactRequest(invocation))
		case ipcFrameTypeStorageFile:
			err = s.respondToStorageFile(ctx, stdin, health, frame, invocation)
		case ipcFrameTypeStorageKV:
			err = s.respondToStorageKV(ctx, stdin, health, frame, invocation)
		case ipcFrameTypeStorageSQLite:
			err = s.respondToStorageSQLite(ctx, stdin, health, frame, invocation)
		case ipcFrameTypeNetworkGrant:
			err = s.respondToNetworkGrant(ctx, stdin, health, frame, invocation)
		case ipcFrameTypeNetworkExecute:
			err = s.respondToNetworkExecute(ctx, stdin, health, frame, invocation)
		}
		if err != nil {
			s.invalidateRuntimeAfterIPCFailure(health, "runtime hostcall response failed", err)
		}
	}()
}

func runtimeArtifactHostcallContext(invocationCtx context.Context, generationCtx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(invocationCtx), defaultRuntimeHostcallTimeout)
	stopGenerationCancel := context.AfterFunc(generationCtx, cancel)
	return ctx, func() {
		stopGenerationCancel()
		cancel()
	}
}

func (s *ProcessSupervisor) failPendingGeneration(generation *runtimeGeneration, err error) {
	s.pendingMu.Lock()
	pending := make([]*pendingIPCRequest, 0, len(s.pending))
	for requestID, request := range s.pending {
		if request.generation != generation {
			continue
		}
		delete(s.pending, requestID)
		pending = append(pending, request)
	}
	for artifactRequestID, flight := range s.compileFlights {
		if flight.generation == generation {
			delete(s.compileFlights, artifactRequestID)
		}
	}
	s.pendingMu.Unlock()
	for _, request := range pending {
		select {
		case request.result <- ipcCallResult{err: err}:
		default:
		}
	}
}

func (s *ProcessSupervisor) invalidateRuntimeAfterIPCFailure(health Health, message string, err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.health.RuntimeGenerationID != health.RuntimeGenerationID || s.cmd == nil {
		s.mu.Unlock()
		return
	}
	cancel := s.cancel
	cmd := s.cmd
	s.health.Ready = false
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	details := map[string]any{
		"runtime_instance_id":   health.RuntimeInstanceID,
		"runtime_generation_id": health.RuntimeGenerationID,
	}
	var internalDetails map[string]any
	if err != nil {
		internalDetails = map[string]any{"error": err.Error()}
	}
	s.emitInternal("plugin.runtime.ipc.invalidated", observability.DiagnosticSeverityWarning, message, details, internalDetails)
}

func (s *ProcessSupervisor) respondToOpenHandle(ctx context.Context, stdin io.Writer, runtimeGenerationID string, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	var req artifactHandleRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_REQUEST_INVALID",
			Message: "missing artifact request payload",
		})
	}
	if err := decodeStrictJSON(frame.Payload, &req); err != nil {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_REQUEST_INVALID",
			Message: "artifact request is invalid",
		})
	}
	if allowedArtifact == nil || !artifactRequestMatches(ArtifactRequest(req), *allowedArtifact) {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_REQUEST_DENIED",
			Message: "artifact request is not bound to the active worker invocation",
		})
	}
	if s.artifacts == nil {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_PROVIDER_UNAVAILABLE",
			Message: "runtime artifact provider is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, 0)
	defer cancel()
	artifact, err := s.artifacts.ReadArtifact(hostcallCtx, ArtifactRequest(req))
	if err != nil {
		s.emitHostcallFailure(runtimeGenerationID, "artifact", "ARTIFACT_READ_FAILED", err, map[string]any{
			"package_hash": req.PackageHash,
			"artifact":     req.Artifact,
		})
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_READ_FAILED",
			Message: "artifact could not be read",
		})
	}
	sum := sha256.Sum256(artifact.Content)
	actual := "sha256:" + fmt.Sprintf("%x", sum[:])
	if artifact.SHA256 != "" && artifact.SHA256 != actual {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_HASH_MISMATCH",
			Message: "artifact provider returned content that does not match sha256",
		})
	}
	if req.ArtifactSHA256 != "" && req.ArtifactSHA256 != actual {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_HASH_MISMATCH",
			Message: "artifact content does not match requested sha256",
		})
	}
	return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame, artifactHandleResultPayload{
		OK:            true,
		PackageHash:   req.PackageHash,
		Artifact:      req.Artifact,
		SHA256:        actual,
		ContentBase64: base64.StdEncoding.EncodeToString(artifact.Content),
	})
}

func (s *ProcessSupervisor) writeOpenHandleResponse(stdin io.Writer, runtimeGenerationID string, request ipcFrame, payload artifactHandleResultPayload) error {
	raw, err := marshalHostcallPayload(payload.OK, payload, payload.Code, payload.Message)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeOpenHandle,
		RequestID:           request.RequestID,
		ParentRequestID:     request.ParentRequestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
		return fmt.Errorf("%w: write open_handle response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func (s *ProcessSupervisor) respondToValidateHandleGrant(ctx context.Context, stdin io.Writer, runtimeGenerationID string, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	if allowedArtifact == nil {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_DENIED",
			Message: "handle grant validation is only available during worker invocation",
		})
	}
	var req HandleGrantValidationRequest
	if len(frame.Payload) == 0 {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_INVALID",
			Message: "missing handle grant validation payload",
		})
	}
	if err := decodeStrictJSON(frame.Payload, &req); err != nil {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_INVALID",
			Message: "handle grant validation request is invalid",
		})
	}
	if strings.TrimSpace(req.RuntimeGenerationID) != runtimeGenerationID {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_DENIED",
			Message: "runtime_generation_id is not bound to this runtime generation",
		})
	}
	if strings.TrimSpace(req.HandleGrantToken) == "" ||
		strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.HandleID) == "" ||
		strings.TrimSpace(req.Method) == "" {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_INVALID",
			Message: "handle grant token, plugin identity, handle id, and method are required",
		})
	}
	if s.handleGrants == nil {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATOR_UNAVAILABLE",
			Message: "runtime handle grant validator is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, 0)
	defer cancel()
	result, err := s.handleGrants.ValidateHandleGrant(hostcallCtx, req)
	if err != nil {
		s.emitHostcallFailure(runtimeGenerationID, "handle_grant", "HANDLE_GRANT_VALIDATION_FAILED", err, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"handle_id":          req.HandleID,
			"method":             req.Method,
		})
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation failed",
		})
	}
	return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame, handleGrantValidationResultPayload{
		OK:                  true,
		HandleGrantID:       result.HandleGrantID,
		HandleID:            result.HandleID,
		Method:              result.Method,
		RuntimeGenerationID: result.RuntimeGenerationID,
		MaxBytesPerSecond:   result.MaxBytesPerSecond,
		MaxTotalBytes:       result.MaxTotalBytes,
	})
}

func (s *ProcessSupervisor) writeHandleGrantValidationResponse(stdin io.Writer, runtimeGenerationID string, request ipcFrame, payload handleGrantValidationResultPayload) error {
	raw, err := marshalHostcallPayload(payload.OK, payload, payload.Code, payload.Message)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeValidateHandleGrant,
		RequestID:           request.RequestID,
		ParentRequestID:     request.ParentRequestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
		return fmt.Errorf("%w: write validate_handle_grant response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func (s *ProcessSupervisor) respondToStorageFile(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedInvocation *workerInvocationContext) error {
	if allowedInvocation == nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_DENIED",
			Message: "storage file access is only available during worker invocation",
		})
	}
	var req storageFileRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_INVALID",
			Message: "missing storage file payload",
		})
	}
	if err := decodeStrictJSON(frame.Payload, &req); err != nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_INVALID",
			Message: "storage file request is invalid",
		})
	}
	if err := validateStorageFileRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_INVALID",
			Message: "storage file request is invalid",
		})
	}
	if !allowedInvocation.identity.matchesRuntimeHostcall(
		req.PluginInstanceID,
		req.ActiveFingerprint,
		req.RuntimeInstanceID,
		req.RuntimeGenerationID,
		req.RuntimeShardID,
		req.PolicyRevision,
		req.ManagementRevision,
		req.RevokeEpoch,
	) {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_DENIED",
			Message: "storage file request identity is not bound to the active worker invocation",
		})
	}
	if !allowedInvocation.BrokerAccess.allowsStorage(req.StoreID, req.Operation) {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK: false, Code: "STORAGE_FILE_REQUEST_DENIED", Message: "worker method is not allowed to perform this storage operation",
		})
	}
	if s.storageFiles == nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_BROKER_UNAVAILABLE",
			Message: "runtime storage files broker is unavailable",
		})
	}
	if s.handleGrants == nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATOR_UNAVAILABLE",
			Message: "runtime handle grant validator is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, 0)
	defer cancel()
	grant, err := s.handleGrants.ValidateHandleGrant(hostcallCtx, HandleGrantValidationRequest{
		HandleGrantToken:    req.HandleGrantToken,
		PluginInstanceID:    req.PluginInstanceID,
		ActiveFingerprint:   req.ActiveFingerprint,
		RuntimeInstanceID:   req.RuntimeInstanceID,
		RuntimeGenerationID: req.RuntimeGenerationID,
		RuntimeShardID:      req.RuntimeShardID,
		HandleID:            req.HandleID,
		Method:              req.Method,
		PolicyRevision:      req.PolicyRevision,
		ManagementRevision:  req.ManagementRevision,
		RevokeEpoch:         req.RevokeEpoch,
	})
	if err != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "storage_file", "HANDLE_GRANT_VALIDATION_FAILED", err, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"store_id":           req.StoreID,
			"operation":          req.Operation,
		})
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation failed",
		})
	}
	if grant.HandleID != req.HandleID || grant.Method != req.Method || grant.RuntimeGenerationID != health.RuntimeGenerationID {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, storageFileResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation result did not match storage file request",
		})
	}
	payload := dispatchStorageFileRequest(hostcallCtx, s.storageFiles, req)
	payload.Operation = req.Operation
	if payload.InternalError != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "storage_file", payload.Code, payload.InternalError, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"store_id":           req.StoreID,
			"operation":          req.Operation,
		})
	}
	return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame, payload)
}

func (s *ProcessSupervisor) writeStorageFileResponse(stdin io.Writer, runtimeGenerationID string, request ipcFrame, payload storageFileResponsePayload) error {
	raw, err := marshalStorageFileHostcallPayload(payload)
	if err == nil {
		raw, err = boundHostcallPayload(raw, "STORAGE_FILE_TOO_LARGE", "storage file response exceeds the WASM hostcall limit")
	}
	if err != nil {
		return err
	}
	if err := writeIPCResponseFrame(stdin, ipcFrameTypeStorageFile, runtimeGenerationID, request, raw); err != nil {
		return fmt.Errorf("%w: write storage_file response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func validateStorageFileRequest(req storageFileRequestPayload, runtimeGenerationID string) error {
	if strings.TrimSpace(req.RuntimeGenerationID) != runtimeGenerationID {
		return errors.New("runtime_generation_id is not bound to this runtime generation")
	}
	if strings.TrimSpace(req.HandleGrantToken) == "" ||
		strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.StoreID) == "" ||
		strings.TrimSpace(req.HandleID) == "" ||
		strings.TrimSpace(req.Method) == "" ||
		strings.TrimSpace(req.Operation) == "" {
		return errors.New("handle grant token, plugin identity, store id, handle id, method, and operation are required")
	}
	if req.Method != "storage.files" {
		return errors.New("storage file access requires method storage.files")
	}
	if req.HandleID != "storage:"+req.StoreID {
		return errors.New("storage handle id must match store id")
	}
	switch req.Operation {
	case "read":
		_, err := boundedSynchronousBrokerPayloadBytes(req.MaxBytes)
		return err
	case "write", "delete", "list":
		return nil
	default:
		return errors.New("storage file operation is not supported")
	}
}

func dispatchStorageFileRequest(ctx context.Context, broker storage.FilesBroker, req storageFileRequestPayload) storageFileResponsePayload {
	switch req.Operation {
	case "read":
		maxBytes, err := boundedSynchronousBrokerPayloadBytes(req.MaxBytes)
		if err != nil {
			return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_REQUEST_INVALID", Message: "storage file request is invalid"}
		}
		result, err := broker.ReadFile(ctx, storage.FileReadRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Path:             req.Path,
			MaxBytes:         maxBytes,
		})
		if err != nil {
			return storageFileErrorResponse(err)
		}
		usage := result.Usage
		return storageFileResponsePayload{
			OK:         true,
			Path:       result.Path,
			DataBase64: base64.StdEncoding.EncodeToString(result.Data),
			SizeBytes:  result.SizeBytes,
			Usage:      &usage,
		}
	case "write":
		data, err := base64.StdEncoding.DecodeString(req.DataBase64)
		if err != nil {
			return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_REQUEST_INVALID", Message: "storage file request is invalid"}
		}
		result, err := broker.WriteFile(ctx, storage.FileWriteRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Path:             req.Path,
			Data:             data,
		})
		if err != nil {
			return storageFileErrorResponse(err)
		}
		usage := result.Usage
		return storageFileResponsePayload{OK: true, Path: result.Path, SizeBytes: result.SizeBytes, Usage: &usage}
	case "delete":
		if err := broker.DeleteFile(ctx, storage.FileDeleteRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Path:             req.Path,
			Recursive:        req.Recursive,
		}); err != nil {
			return storageFileErrorResponse(err)
		}
		return storageFileResponsePayload{OK: true, Path: req.Path}
	case "list":
		result, err := broker.ListFiles(ctx, storage.FileListRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Path:             req.Path,
			MaxEntries:       req.MaxEntries,
		})
		if err != nil {
			return storageFileErrorResponse(err)
		}
		usage := result.Usage
		return storageFileResponsePayload{OK: true, Path: result.Path, Entries: result.Entries, Usage: &usage}
	default:
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_REQUEST_INVALID", Message: "storage file operation is not supported"}
	}
}

func storageFileErrorResponse(err error) storageFileResponsePayload {
	switch {
	case errors.Is(err, storage.ErrFileNotFound), errors.Is(err, storage.ErrNamespaceNotFound):
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_NOT_FOUND", Message: "storage file was not found", InternalError: err}
	case errors.Is(err, storage.ErrInvalidFilePath), errors.Is(err, storage.ErrInvalidNamespace):
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_INVALID_PATH", Message: "storage file path is invalid", InternalError: err}
	case errors.Is(err, storage.ErrQuotaExceeded):
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_QUOTA_EXCEEDED", Message: "storage file quota was exceeded", InternalError: err}
	case errors.Is(err, storage.ErrFileTooLarge):
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_TOO_LARGE", Message: "storage file is too large", InternalError: err}
	default:
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_FAILED", Message: "storage file operation failed", InternalError: err}
	}
}

func (s *ProcessSupervisor) respondToStorageKV(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedInvocation *workerInvocationContext) error {
	if allowedInvocation == nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_DENIED",
			Message: "storage kv access is only available during worker invocation",
		})
	}
	var req storageKVRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_INVALID",
			Message: "missing storage kv payload",
		})
	}
	if err := decodeStrictJSON(frame.Payload, &req); err != nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_INVALID",
			Message: "storage kv request is invalid",
		})
	}
	if err := validateStorageKVRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_INVALID",
			Message: "storage kv request is invalid",
		})
	}
	if !allowedInvocation.identity.matchesRuntimeHostcall(
		req.PluginInstanceID,
		req.ActiveFingerprint,
		req.RuntimeInstanceID,
		req.RuntimeGenerationID,
		req.RuntimeShardID,
		req.PolicyRevision,
		req.ManagementRevision,
		req.RevokeEpoch,
	) {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_DENIED",
			Message: "storage kv request identity is not bound to the active worker invocation",
		})
	}
	if !allowedInvocation.BrokerAccess.allowsStorage(req.StoreID, req.Operation) {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK: false, Code: "STORAGE_KV_REQUEST_DENIED", Message: "worker method is not allowed to perform this storage operation",
		})
	}
	if s.storageKV == nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_BROKER_UNAVAILABLE",
			Message: "runtime storage kv broker is unavailable",
		})
	}
	if s.handleGrants == nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATOR_UNAVAILABLE",
			Message: "runtime handle grant validator is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, 0)
	defer cancel()
	grant, err := s.handleGrants.ValidateHandleGrant(hostcallCtx, HandleGrantValidationRequest{
		HandleGrantToken:    req.HandleGrantToken,
		PluginInstanceID:    req.PluginInstanceID,
		ActiveFingerprint:   req.ActiveFingerprint,
		RuntimeInstanceID:   req.RuntimeInstanceID,
		RuntimeGenerationID: req.RuntimeGenerationID,
		RuntimeShardID:      req.RuntimeShardID,
		HandleID:            req.HandleID,
		Method:              req.Method,
		PolicyRevision:      req.PolicyRevision,
		ManagementRevision:  req.ManagementRevision,
		RevokeEpoch:         req.RevokeEpoch,
	})
	if err != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "storage_kv", "HANDLE_GRANT_VALIDATION_FAILED", err, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"store_id":           req.StoreID,
			"operation":          req.Operation,
		})
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation failed",
		})
	}
	if grant.HandleID != req.HandleID || grant.Method != req.Method || grant.RuntimeGenerationID != health.RuntimeGenerationID {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, storageKVResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation result did not match storage kv request",
		})
	}
	payload := dispatchStorageKVRequest(hostcallCtx, s.storageKV, req)
	payload.Operation = req.Operation
	if payload.InternalError != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "storage_kv", payload.Code, payload.InternalError, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"store_id":           req.StoreID,
			"operation":          req.Operation,
		})
	}
	return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame, payload)
}

func (s *ProcessSupervisor) writeStorageKVResponse(stdin io.Writer, runtimeGenerationID string, request ipcFrame, payload storageKVResponsePayload) error {
	raw, err := marshalStorageKVHostcallPayload(payload)
	if err == nil {
		raw, err = boundHostcallPayload(raw, "STORAGE_KV_VALUE_TOO_LARGE", "storage KV response exceeds the WASM hostcall limit")
	}
	if err != nil {
		return err
	}
	if err := writeIPCResponseFrame(stdin, ipcFrameTypeStorageKV, runtimeGenerationID, request, raw); err != nil {
		return fmt.Errorf("%w: write storage_kv response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func validateStorageKVRequest(req storageKVRequestPayload, runtimeGenerationID string) error {
	if strings.TrimSpace(req.RuntimeGenerationID) != runtimeGenerationID {
		return errors.New("runtime_generation_id is not bound to this runtime generation")
	}
	if strings.TrimSpace(req.HandleGrantToken) == "" ||
		strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.StoreID) == "" ||
		strings.TrimSpace(req.HandleID) == "" ||
		strings.TrimSpace(req.Method) == "" ||
		strings.TrimSpace(req.Operation) == "" {
		return errors.New("handle grant token, plugin identity, store id, handle id, method, and operation are required")
	}
	if req.Method != "storage.kv" {
		return errors.New("storage kv access requires method storage.kv")
	}
	if req.HandleID != "storage:"+req.StoreID {
		return errors.New("storage handle id must match store id")
	}
	switch req.Operation {
	case "get":
		if strings.TrimSpace(req.Key) == "" {
			return errors.New("storage kv key is required")
		}
		_, err := boundedSynchronousBrokerPayloadBytes(req.MaxBytes)
		return err
	case "put", "delete":
		if strings.TrimSpace(req.Key) == "" {
			return errors.New("storage kv key is required")
		}
		return nil
	case "list":
		return nil
	default:
		return errors.New("storage kv operation is not supported")
	}
}

func dispatchStorageKVRequest(ctx context.Context, broker storage.KVBroker, req storageKVRequestPayload) storageKVResponsePayload {
	switch req.Operation {
	case "get":
		maxBytes, err := boundedSynchronousBrokerPayloadBytes(req.MaxBytes)
		if err != nil {
			return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_REQUEST_INVALID", Message: "storage kv request is invalid"}
		}
		result, err := broker.GetKV(ctx, storage.KVGetRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Key:              req.Key,
			MaxBytes:         maxBytes,
		})
		if err != nil {
			return storageKVErrorResponse(err)
		}
		usage := result.Usage
		return storageKVResponsePayload{
			OK:          true,
			Key:         result.Key,
			ValueBase64: base64.StdEncoding.EncodeToString(result.Value),
			SizeBytes:   result.SizeBytes,
			Usage:       &usage,
		}
	case "put":
		value, err := base64.StdEncoding.DecodeString(req.ValueBase64)
		if err != nil {
			return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_REQUEST_INVALID", Message: "storage kv request is invalid"}
		}
		result, err := broker.PutKV(ctx, storage.KVPutRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Key:              req.Key,
			Value:            value,
		})
		if err != nil {
			return storageKVErrorResponse(err)
		}
		usage := result.Usage
		return storageKVResponsePayload{OK: true, Key: result.Key, SizeBytes: result.SizeBytes, Usage: &usage}
	case "delete":
		if err := broker.DeleteKV(ctx, storage.KVDeleteRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Key:              req.Key,
		}); err != nil {
			return storageKVErrorResponse(err)
		}
		return storageKVResponsePayload{OK: true, Key: req.Key}
	case "list":
		result, err := broker.ListKV(ctx, storage.KVListRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Prefix:           req.Prefix,
			MaxEntries:       req.MaxEntries,
		})
		if err != nil {
			return storageKVErrorResponse(err)
		}
		usage := result.Usage
		return storageKVResponsePayload{OK: true, Prefix: result.Prefix, Entries: result.Entries, Usage: &usage}
	default:
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_REQUEST_INVALID", Message: "storage kv operation is not supported"}
	}
}

func storageKVErrorResponse(err error) storageKVResponsePayload {
	switch {
	case errors.Is(err, storage.ErrKVKeyNotFound), errors.Is(err, storage.ErrNamespaceNotFound):
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_NOT_FOUND", Message: "storage kv key was not found", InternalError: err}
	case errors.Is(err, storage.ErrInvalidKVKey), errors.Is(err, storage.ErrInvalidNamespace):
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_INVALID_KEY", Message: "storage kv key is invalid", InternalError: err}
	case errors.Is(err, storage.ErrQuotaExceeded):
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_QUOTA_EXCEEDED", Message: "storage kv quota was exceeded", InternalError: err}
	case errors.Is(err, storage.ErrKVValueTooLarge):
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_VALUE_TOO_LARGE", Message: "storage kv value is too large", InternalError: err}
	default:
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_FAILED", Message: "storage kv operation failed", InternalError: err}
	}
}

func (s *ProcessSupervisor) respondToStorageSQLite(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedInvocation *workerInvocationContext) error {
	if allowedInvocation == nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_DENIED",
			Message: "storage sqlite access is only available during worker invocation",
		})
	}
	var req storageSQLiteRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_INVALID",
			Message: "missing storage sqlite payload",
		})
	}
	if err := decodeStrictJSON(frame.Payload, &req); err != nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_INVALID",
			Message: "storage sqlite request is invalid",
		})
	}
	if err := validateStorageSQLiteRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_INVALID",
			Message: "storage sqlite request is invalid",
		})
	}
	if !allowedInvocation.identity.matchesRuntimeHostcall(
		req.PluginInstanceID,
		req.ActiveFingerprint,
		req.RuntimeInstanceID,
		req.RuntimeGenerationID,
		req.RuntimeShardID,
		req.PolicyRevision,
		req.ManagementRevision,
		req.RevokeEpoch,
	) {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_DENIED",
			Message: "storage sqlite request identity is not bound to the active worker invocation",
		})
	}
	if !allowedInvocation.BrokerAccess.allowsStorage(req.StoreID, req.Operation) {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK: false, Code: "STORAGE_SQLITE_REQUEST_DENIED", Message: "worker method is not allowed to perform this storage operation",
		})
	}
	if s.storageSQLite == nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_BROKER_UNAVAILABLE",
			Message: "runtime storage sqlite broker is unavailable",
		})
	}
	if s.handleGrants == nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATOR_UNAVAILABLE",
			Message: "runtime handle grant validator is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, time.Duration(req.TimeoutMillis)*time.Millisecond)
	defer cancel()
	grant, err := s.handleGrants.ValidateHandleGrant(hostcallCtx, HandleGrantValidationRequest{
		HandleGrantToken:    req.HandleGrantToken,
		PluginInstanceID:    req.PluginInstanceID,
		ActiveFingerprint:   req.ActiveFingerprint,
		RuntimeInstanceID:   req.RuntimeInstanceID,
		RuntimeGenerationID: req.RuntimeGenerationID,
		RuntimeShardID:      req.RuntimeShardID,
		HandleID:            req.HandleID,
		Method:              req.Method,
		PolicyRevision:      req.PolicyRevision,
		ManagementRevision:  req.ManagementRevision,
		RevokeEpoch:         req.RevokeEpoch,
	})
	if err != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "storage_sqlite", "HANDLE_GRANT_VALIDATION_FAILED", err, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"store_id":           req.StoreID,
			"operation":          req.Operation,
		})
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation failed",
		})
	}
	if grant.HandleID != req.HandleID || grant.Method != req.Method || grant.RuntimeGenerationID != health.RuntimeGenerationID {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation result did not match storage sqlite request",
		})
	}
	payload := dispatchStorageSQLiteRequest(hostcallCtx, s.storageSQLite, req)
	payload.Operation = req.Operation
	if payload.InternalError != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "storage_sqlite", payload.Code, payload.InternalError, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"store_id":           req.StoreID,
			"operation":          req.Operation,
		})
	}
	return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame, payload)
}

func (s *ProcessSupervisor) writeStorageSQLiteResponse(stdin io.Writer, runtimeGenerationID string, request ipcFrame, payload storageSQLiteResponsePayload) error {
	raw, err := marshalStorageSQLiteHostcallPayload(payload)
	if err == nil {
		raw, err = boundHostcallPayload(raw, "STORAGE_SQLITE_RESULT_TOO_LARGE", "storage SQLite response exceeds the WASM hostcall limit")
	}
	if err != nil {
		return err
	}
	if err := writeIPCResponseFrame(stdin, ipcFrameTypeStorageSQLite, runtimeGenerationID, request, raw); err != nil {
		return fmt.Errorf("%w: write storage_sqlite response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func validateStorageSQLiteRequest(req storageSQLiteRequestPayload, runtimeGenerationID string) error {
	if strings.TrimSpace(req.RuntimeGenerationID) != runtimeGenerationID {
		return errors.New("runtime_generation_id is not bound to this runtime generation")
	}
	if strings.TrimSpace(req.HandleGrantToken) == "" ||
		strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.StoreID) == "" ||
		strings.TrimSpace(req.HandleID) == "" ||
		strings.TrimSpace(req.Method) == "" ||
		strings.TrimSpace(req.Operation) == "" ||
		strings.TrimSpace(req.SQL) == "" {
		return errors.New("handle grant token, plugin identity, store id, handle id, method, operation, and sql are required")
	}
	if req.Method != "storage.sqlite" {
		return errors.New("storage sqlite access requires method storage.sqlite")
	}
	if req.HandleID != "storage:"+req.StoreID {
		return errors.New("storage handle id must match store id")
	}
	if req.TimeoutMillis < 0 {
		return errors.New("timeout_ms must not be negative")
	}
	switch req.Operation {
	case "exec":
		return nil
	case "query":
		_, err := boundedSynchronousBrokerPayloadBytes(req.MaxResponseBytes)
		return err
	default:
		return errors.New("storage sqlite operation is not supported")
	}
}

func dispatchStorageSQLiteRequest(ctx context.Context, broker storage.SQLiteBroker, req storageSQLiteRequestPayload) storageSQLiteResponsePayload {
	args, err := storageSQLiteArgsFromIPC(req.Args)
	if err != nil {
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_REQUEST_INVALID", Message: "storage sqlite request is invalid"}
	}
	timeout := time.Duration(req.TimeoutMillis) * time.Millisecond
	switch req.Operation {
	case "exec":
		result, err := broker.ExecSQLite(ctx, storage.SQLiteExecRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Database:         req.Database,
			SQL:              req.SQL,
			Args:             args,
			Timeout:          timeout,
		})
		if err != nil {
			return storageSQLiteErrorResponse(err)
		}
		usage := result.Usage
		rowsAffected := result.RowsAffected
		return storageSQLiteResponsePayload{
			OK:           true,
			Database:     result.Database,
			RowsAffected: &rowsAffected,
			LastInsertID: result.LastInsertID,
			Usage:        &usage,
		}
	case "query":
		maxResponseBytes, err := boundedSynchronousBrokerPayloadBytes(req.MaxResponseBytes)
		if err != nil {
			return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_REQUEST_INVALID", Message: "storage sqlite request is invalid"}
		}
		result, err := broker.QuerySQLite(ctx, storage.SQLiteQueryRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Database:         req.Database,
			SQL:              req.SQL,
			Args:             args,
			MaxRows:          req.MaxRows,
			MaxResponseBytes: maxResponseBytes,
			Timeout:          timeout,
		})
		if err != nil {
			return storageSQLiteErrorResponse(err)
		}
		usage := result.Usage
		columns := append([]string{}, result.Columns...)
		rows := storageSQLiteRowsToIPC(result.Rows)
		if rows == nil {
			rows = [][]storageSQLiteValueIPC{}
		}
		return storageSQLiteResponsePayload{
			OK:       true,
			Database: result.Database,
			Columns:  &columns,
			Rows:     &rows,
			Usage:    &usage,
		}
	default:
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_REQUEST_INVALID", Message: "storage sqlite operation is not supported"}
	}
}

func storageSQLiteArgsFromIPC(values []storageSQLiteValueIPC) ([]storage.SQLiteValue, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]storage.SQLiteValue, 0, len(values))
	for _, value := range values {
		converted, err := storageSQLiteValueFromIPC(value)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return out, nil
}

func storageSQLiteRowsToIPC(rows [][]storage.SQLiteValue) [][]storageSQLiteValueIPC {
	if len(rows) == 0 {
		return nil
	}
	out := make([][]storageSQLiteValueIPC, 0, len(rows))
	for _, row := range rows {
		converted := make([]storageSQLiteValueIPC, 0, len(row))
		for _, value := range row {
			converted = append(converted, storageSQLiteValueToIPC(value))
		}
		out = append(out, converted)
	}
	return out
}

func storageSQLiteValueFromIPC(value storageSQLiteValueIPC) (storage.SQLiteValue, error) {
	if !validStorageSQLiteValueIPC(value) {
		return storage.SQLiteValue{}, errors.New("storage sqlite value must contain exactly one typed field")
	}
	if value.BlobBase64 != nil {
		data, err := base64.StdEncoding.DecodeString(*value.BlobBase64)
		if err != nil {
			return storage.SQLiteValue{}, fmt.Errorf("decode sqlite blob_base64: %v", err)
		}
		if data == nil {
			data = []byte{}
		}
		return storage.SQLiteValue{Blob: data}, nil
	}
	return storage.SQLiteValue{
		Null:  value.Null != nil && *value.Null,
		Int:   value.Int,
		Float: value.Float,
		Text:  value.Text,
	}, nil
}

func storageSQLiteValueToIPC(value storage.SQLiteValue) storageSQLiteValueIPC {
	if value.Blob != nil {
		encoded := base64.StdEncoding.EncodeToString(value.Blob)
		return storageSQLiteValueIPC{BlobBase64: &encoded}
	}
	if value.Null {
		null := true
		return storageSQLiteValueIPC{Null: &null}
	}
	return storageSQLiteValueIPC{
		Int:   value.Int,
		Float: value.Float,
		Text:  value.Text,
	}
}

func validStorageSQLiteValueIPC(value storageSQLiteValueIPC) bool {
	variants := 0
	if value.Null != nil {
		if !*value.Null {
			return false
		}
		variants++
	}
	if value.Int != nil {
		variants++
	}
	if value.Float != nil {
		variants++
	}
	if value.Text != nil {
		variants++
	}
	if value.BlobBase64 != nil {
		variants++
	}
	return variants == 1
}

func storageSQLiteErrorResponse(err error) storageSQLiteResponsePayload {
	switch {
	case errors.Is(err, storage.ErrNamespaceNotFound):
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_NOT_FOUND", Message: "storage sqlite database was not found", InternalError: err}
	case errors.Is(err, storage.ErrInvalidSQLite), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrInvalidFilePath):
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_INVALID_REQUEST", Message: "storage sqlite request is invalid", InternalError: err}
	case errors.Is(err, storage.ErrQuotaExceeded):
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_QUOTA_EXCEEDED", Message: "storage sqlite quota was exceeded", InternalError: err}
	case errors.Is(err, storage.ErrSQLiteResultTooLarge):
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_RESULT_TOO_LARGE", Message: "storage sqlite result is too large", InternalError: err}
	default:
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_FAILED", Message: "storage sqlite operation failed", InternalError: err}
	}
}

func (s *ProcessSupervisor) respondToNetworkGrant(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedInvocation *workerInvocationContext) error {
	if allowedInvocation == nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_DENIED",
			Message: "network grants are only available during worker invocation",
		})
	}
	var req networkGrantRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_INVALID",
			Message: "missing network grant payload",
		})
	}
	if err := decodeStrictJSON(frame.Payload, &req); err != nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_INVALID",
			Message: "network grant request is invalid",
		})
	}
	if err := validateNetworkGrantRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_INVALID",
			Message: "network grant request is invalid",
		})
	}
	if !allowedInvocation.identity.matchesRuntimeHostcall(
		req.PluginInstanceID,
		req.ActiveFingerprint,
		req.RuntimeInstanceID,
		req.RuntimeGenerationID,
		req.RuntimeShardID,
		req.PolicyRevision,
		req.ManagementRevision,
		req.RevokeEpoch,
	) {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_DENIED",
			Message: "network grant request identity is not bound to the active worker invocation",
		})
	}
	if !allowedInvocation.BrokerAccess.allowsNetworkConnector(req.ConnectorID, string(req.Transport)) {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
			OK: false, Code: "NETWORK_GRANT_REQUEST_DENIED", Message: "worker method is not allowed to use this network connector",
		})
	}
	if s.connectivity == nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_BROKER_UNAVAILABLE",
			Message: "runtime connectivity broker is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, 0)
	defer cancel()
	ttl := time.Duration(req.TTLMillis) * time.Millisecond
	grant, err := s.connectivity.MintConnectionGrant(hostcallCtx, connectivity.GrantRequest{
		PluginInstanceID:    req.PluginInstanceID,
		ActiveFingerprint:   req.ActiveFingerprint,
		PolicyRevision:      req.PolicyRevision,
		ManagementRevision:  req.ManagementRevision,
		RevokeEpoch:         req.RevokeEpoch,
		ConnectorID:         req.ConnectorID,
		Transport:           req.Transport,
		Destination:         req.Destination,
		RuntimeGenerationID: req.RuntimeGenerationID,
		Now:                 s.now(),
		TTL:                 ttl,
	})
	if err != nil {
		payload := networkGrantErrorResponse(err)
		s.emitHostcallFailure(health.RuntimeGenerationID, "network_grant", payload.Code, err, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"connector_id":       req.ConnectorID,
			"transport":          req.Transport,
		})
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, payload)
	}
	if err := validateNetworkGrantResult(req, grant, health.RuntimeGenerationID); err != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "network_grant", "NETWORK_GRANT_VALIDATION_FAILED", err, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"connector_id":       req.ConnectorID,
			"transport":          req.Transport,
		})
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_VALIDATION_FAILED",
			Message: "network grant validation failed",
		})
	}
	return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame, networkGrantResponsePayload{
		OK:                      true,
		GrantID:                 grant.GrantID,
		PluginInstanceID:        grant.PluginInstanceID,
		ActiveFingerprint:       grant.ActiveFingerprint,
		PolicyRevision:          grant.PolicyRevision,
		ManagementRevision:      grant.ManagementRevision,
		RevokeEpoch:             grant.RevokeEpoch,
		ConnectorID:             grant.ConnectorID,
		Transport:               grant.Transport,
		Destination:             grant.Destination,
		RuntimeGenerationID:     grant.RuntimeGenerationID,
		TargetClassifierVersion: grant.TargetClassifierVersion,
		ExpiresAt:               grant.ExpiresAt,
	})
}

func (s *ProcessSupervisor) writeNetworkGrantResponse(stdin io.Writer, runtimeGenerationID string, request ipcFrame, payload networkGrantResponsePayload) error {
	raw, err := marshalHostcallPayload(payload.OK, payload, payload.Code, payload.Message)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeNetworkGrant,
		RequestID:           request.RequestID,
		ParentRequestID:     request.ParentRequestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
		return fmt.Errorf("%w: write network_grant response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func (s *ProcessSupervisor) respondToNetworkExecute(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedInvocation *workerInvocationContext) error {
	if allowedInvocation == nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_DENIED",
			Message: "network execution is only available during worker invocation",
		})
	}
	var req networkExecuteRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_INVALID",
			Message: "missing network execute payload",
		})
	}
	if err := decodeStrictJSON(frame.Payload, &req); err != nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_INVALID",
			Message: "network execute request is invalid",
		})
	}
	if err := validateNetworkExecuteRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_INVALID",
			Message: "network execute request is invalid",
		})
	}
	if !allowedInvocation.identity.matchesNetworkExecute(req) {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_DENIED",
			Message: "network execute request identity is not bound to the active worker invocation",
		})
	}
	if !allowedInvocation.BrokerAccess.allowsNetwork(req.ConnectorID, string(req.Transport), req.Operation, req.Method) {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK: false, Code: "NETWORK_EXECUTE_REQUEST_DENIED", Message: "worker method is not allowed to perform this network operation",
		})
	}
	if s.connectivity == nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_BROKER_UNAVAILABLE",
			Message: "runtime connectivity broker is unavailable",
		})
	}
	if s.networkExecutor == nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTOR_UNAVAILABLE",
			Message: "runtime network executor is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, time.Duration(req.TimeoutMillis)*time.Millisecond)
	defer cancel()
	grant, err := s.mintGrantForNetworkExecute(hostcallCtx, req)
	if err != nil {
		payload := networkExecuteErrorResponse(err)
		s.emitHostcallFailure(health.RuntimeGenerationID, "network_execute", payload.Code, err, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"connector_id":       req.ConnectorID,
			"transport":          req.Transport,
			"operation":          req.Operation,
		})
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, payload)
	}
	if err := validateNetworkGrantResult(networkGrantRequestPayload{
		PluginInstanceID:    req.PluginInstanceID,
		ActiveFingerprint:   req.ActiveFingerprint,
		RuntimeGenerationID: req.RuntimeGenerationID,
		PolicyRevision:      req.PolicyRevision,
		ManagementRevision:  req.ManagementRevision,
		RevokeEpoch:         req.RevokeEpoch,
		ConnectorID:         req.ConnectorID,
		Transport:           req.Transport,
		Destination:         req.Destination,
		TTLMillis:           req.TTLMillis,
	}, grant, health.RuntimeGenerationID); err != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "network_execute", "NETWORK_GRANT_VALIDATION_FAILED", err, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"connector_id":       req.ConnectorID,
			"transport":          req.Transport,
			"operation":          req.Operation,
		})
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_VALIDATION_FAILED",
			Message: "network grant validation failed",
		})
	}
	payload := dispatchNetworkExecute(hostcallCtx, s.networkExecutor, s.streamSink, grant, req, s.now())
	if payload.InternalError != nil {
		s.emitHostcallFailure(health.RuntimeGenerationID, "network_execute", payload.Code, payload.InternalError, map[string]any{
			"plugin_instance_id": req.PluginInstanceID,
			"connector_id":       req.ConnectorID,
			"transport":          req.Transport,
			"operation":          req.Operation,
		})
	}
	if payload.OK {
		payload.GrantID = grant.GrantID
		payload.ConnectorID = grant.ConnectorID
		payload.RuntimeGeneration = grant.RuntimeGenerationID
		payload.Transport = grant.Transport
		payload.Destination = grant.Destination
	}
	return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame, payload)
}

func (s *ProcessSupervisor) mintGrantForNetworkExecute(ctx context.Context, req networkExecuteRequestPayload) (connectivity.ConnectionGrant, error) {
	ttl := time.Duration(req.TTLMillis) * time.Millisecond
	return s.connectivity.MintConnectionGrant(ctx, connectivity.GrantRequest{
		PluginInstanceID:    req.PluginInstanceID,
		ActiveFingerprint:   req.ActiveFingerprint,
		PolicyRevision:      req.PolicyRevision,
		ManagementRevision:  req.ManagementRevision,
		RevokeEpoch:         req.RevokeEpoch,
		ConnectorID:         req.ConnectorID,
		Transport:           req.Transport,
		Destination:         req.Destination,
		RuntimeGenerationID: req.RuntimeGenerationID,
		Now:                 s.now(),
		TTL:                 ttl,
	})
}

func (s *ProcessSupervisor) writeNetworkExecuteResponse(stdin io.Writer, runtimeGenerationID string, request ipcFrame, payload networkExecuteResponsePayload) error {
	raw, err := marshalBoundedHostcallPayload(payload.OK, payload, payload.Code, payload.Message, "NETWORK_RESPONSE_TOO_LARGE", "network response exceeds the WASM hostcall limit")
	if err != nil {
		return err
	}
	if err := writeIPCResponseFrame(stdin, ipcFrameTypeNetworkExecute, runtimeGenerationID, request, raw); err != nil {
		return fmt.Errorf("%w: write network_execute response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func validateNetworkGrantResult(req networkGrantRequestPayload, grant connectivity.ConnectionGrant, runtimeGenerationID string) error {
	if strings.TrimSpace(grant.GrantID) == "" ||
		strings.TrimSpace(grant.PluginInstanceID) != strings.TrimSpace(req.PluginInstanceID) ||
		strings.TrimSpace(grant.ActiveFingerprint) != strings.TrimSpace(req.ActiveFingerprint) ||
		grant.PolicyRevision != req.PolicyRevision ||
		grant.ManagementRevision != req.ManagementRevision ||
		grant.RevokeEpoch != req.RevokeEpoch ||
		strings.TrimSpace(grant.ConnectorID) != strings.TrimSpace(req.ConnectorID) ||
		grant.Transport != req.Transport ||
		strings.TrimSpace(grant.RuntimeGenerationID) != runtimeGenerationID ||
		strings.TrimSpace(grant.TargetClassifierVersion) != version.TargetClassifierVersion {
		return errors.New("network grant result did not match request audience")
	}
	requested, err := connectivity.ParseDestination(req.Transport, req.Destination)
	if err != nil {
		return err
	}
	if grant.Destination != requested {
		return errors.New("network grant destination did not match request")
	}
	if grant.ExpiresAt.IsZero() {
		return errors.New("network grant expires_at is required")
	}
	return nil
}

func validateNetworkGrantRequest(req networkGrantRequestPayload, runtimeGenerationID string) error {
	if strings.TrimSpace(req.RuntimeGenerationID) != runtimeGenerationID {
		return errors.New("runtime_generation_id is not bound to this runtime generation")
	}
	if strings.TrimSpace(req.PluginInstanceID) == "" ||
		strings.TrimSpace(req.ActiveFingerprint) == "" ||
		strings.TrimSpace(req.ConnectorID) == "" ||
		strings.TrimSpace(req.Destination) == "" {
		return errors.New("plugin identity, connector id, and destination are required")
	}
	if !connectivity.ValidTransport(req.Transport) {
		return errors.New("network transport is not supported")
	}
	if req.TTLMillis < 0 {
		return errors.New("ttl_ms must not be negative")
	}
	return nil
}

func validateNetworkExecuteRequest(req networkExecuteRequestPayload, runtimeGenerationID string) error {
	grantReq := networkGrantRequestPayload{
		PluginInstanceID:    req.PluginInstanceID,
		ActiveFingerprint:   req.ActiveFingerprint,
		RuntimeInstanceID:   req.RuntimeInstanceID,
		RuntimeGenerationID: req.RuntimeGenerationID,
		RuntimeShardID:      req.RuntimeShardID,
		PolicyRevision:      req.PolicyRevision,
		ManagementRevision:  req.ManagementRevision,
		RevokeEpoch:         req.RevokeEpoch,
		ConnectorID:         req.ConnectorID,
		Transport:           req.Transport,
		Destination:         req.Destination,
		TTLMillis:           req.TTLMillis,
	}
	if err := validateNetworkGrantRequest(grantReq, runtimeGenerationID); err != nil {
		return err
	}
	if req.TimeoutMillis < 0 {
		return errors.New("timeout_ms must not be negative")
	}
	if req.MaxRequestBytes < 0 || req.MaxResponseBytes < 0 || req.MaxChunkBytes < 0 || req.MaxBufferedBytes < 0 {
		return errors.New("max request, response, chunk, and buffered bytes must not be negative")
	}
	operation := strings.TrimSpace(req.Operation)
	switch req.Transport {
	case connectivity.TransportHTTP:
		if operation != "" && operation != "http" && operation != "http_stream" {
			return errors.New("http network execution operation must be http or http_stream")
		}
		if operation == "http_stream" {
			if strings.TrimSpace(req.PluginID) == "" ||
				strings.TrimSpace(req.StreamMethod) == "" ||
				strings.TrimSpace(req.StreamExecution) == "" ||
				strings.TrimSpace(req.SurfaceInstanceID) == "" ||
				strings.TrimSpace(req.OwnerSessionHash) == "" ||
				strings.TrimSpace(req.OwnerUserHash) == "" ||
				strings.TrimSpace(req.OwnerEnvHash) == "" ||
				strings.TrimSpace(req.SessionChannelIDHash) == "" ||
				strings.TrimSpace(req.BridgeChannelID) == "" {
				return errors.New("http_stream network execution requires plugin and stream audience fields")
			}
		}
	case connectivity.TransportWebSocket:
		if operation != "" && operation != "websocket_round_trip" {
			return errors.New("websocket network execution operation must be websocket_round_trip")
		}
	case connectivity.TransportTCP:
		if operation != "" && operation != "tcp_round_trip" {
			return errors.New("tcp network execution operation must be tcp_round_trip")
		}
	case connectivity.TransportUDP:
		if operation != "" && operation != "udp_round_trip" {
			return errors.New("udp network execution operation must be udp_round_trip")
		}
	}
	if operation != "http_stream" {
		if _, err := boundedSynchronousBrokerPayloadBytes(req.MaxResponseBytes); err != nil {
			return err
		}
	}
	return nil
}

func dispatchNetworkExecute(ctx context.Context, executor connectivity.NetworkExecutor, streamSink RuntimeStreamSink, grant connectivity.ConnectionGrant, req networkExecuteRequestPayload, now time.Time) networkExecuteResponsePayload {
	timeout := time.Duration(req.TimeoutMillis) * time.Millisecond
	switch req.Transport {
	case connectivity.TransportHTTP:
		body, err := decodeOptionalBase64(req.BodyBase64)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid"}
		}
		if strings.TrimSpace(req.Operation) == "http_stream" {
			if streamSink == nil {
				return networkExecuteResponsePayload{OK: false, Code: "NETWORK_STREAM_SINK_UNAVAILABLE", Message: "runtime stream sink is unavailable"}
			}
			return dispatchHTTPStreamExecute(ctx, executor, streamSink, grant, req, body, timeout, now)
		}
		maxResponseBytes, err := boundedSynchronousBrokerPayloadBytes(req.MaxResponseBytes)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid"}
		}
		result, err := executor.DoHTTP(ctx, connectivity.HTTPRequest{
			Grant:            grant,
			Method:           req.Method,
			Path:             req.Path,
			Query:            req.Query,
			Headers:          req.Headers,
			Body:             body,
			MaxRequestBytes:  req.MaxRequestBytes,
			MaxResponseBytes: maxResponseBytes,
			Timeout:          timeout,
			Now:              now,
		})
		if err != nil {
			return networkExecuteErrorResponse(err)
		}
		return networkExecuteResponsePayload{OK: true, StatusCode: result.StatusCode, Headers: result.Headers, BodyBase64: base64.StdEncoding.EncodeToString(result.Body)}
	case connectivity.TransportWebSocket:
		payload, err := decodeOptionalBase64(req.PayloadBase64)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid"}
		}
		maxResponseBytes, err := boundedSynchronousBrokerPayloadBytes(req.MaxResponseBytes)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid"}
		}
		result, err := executor.WebSocketRoundTrip(ctx, connectivity.WebSocketRoundTripRequest{
			Grant:            grant,
			Path:             req.Path,
			Headers:          req.Headers,
			MessageType:      connectivity.WebSocketMessageType(strings.TrimSpace(req.MessageType)),
			Payload:          payload,
			MaxRequestBytes:  req.MaxRequestBytes,
			MaxResponseBytes: maxResponseBytes,
			Timeout:          timeout,
			Now:              now,
		})
		if err != nil {
			return networkExecuteErrorResponse(err)
		}
		return networkExecuteResponsePayload{OK: true, MessageType: string(result.MessageType), PayloadBase64: base64.StdEncoding.EncodeToString(result.Payload)}
	case connectivity.TransportTCP:
		payload, err := decodeOptionalBase64(req.PayloadBase64)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid"}
		}
		maxResponseBytes, err := boundedSynchronousBrokerPayloadBytes(req.MaxResponseBytes)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid"}
		}
		result, err := executor.TCPRoundTrip(ctx, connectivity.TCPRoundTripRequest{
			Grant:           grant,
			Payload:         payload,
			MaxRequestBytes: req.MaxRequestBytes,
			MaxReadBytes:    maxResponseBytes,
			Timeout:         timeout,
			Now:             now,
		})
		if err != nil {
			return networkExecuteErrorResponse(err)
		}
		return networkExecuteResponsePayload{OK: true, PayloadBase64: base64.StdEncoding.EncodeToString(result.Payload)}
	case connectivity.TransportUDP:
		payload, err := decodeOptionalBase64(req.PayloadBase64)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid"}
		}
		maxResponseBytes, err := boundedSynchronousBrokerPayloadBytes(req.MaxResponseBytes)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid"}
		}
		result, err := executor.UDPRoundTrip(ctx, connectivity.UDPRoundTripRequest{
			Grant:        grant,
			Payload:      payload,
			MaxReadBytes: maxResponseBytes,
			Timeout:      timeout,
			Now:          now,
		})
		if err != nil {
			return networkExecuteErrorResponse(err)
		}
		return networkExecuteResponsePayload{OK: true, PayloadBase64: base64.StdEncoding.EncodeToString(result.Payload)}
	default:
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network transport is not supported"}
	}
}

func dispatchHTTPStreamExecute(ctx context.Context, executor connectivity.NetworkExecutor, streamSink RuntimeStreamSink, grant connectivity.ConnectionGrant, req networkExecuteRequestPayload, body []byte, timeout time.Duration, now time.Time) networkExecuteResponsePayload {
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_STREAM_FAILED", Message: "host-owned stream_id is required"}
	}
	result, err := executor.StreamHTTP(ctx, connectivity.HTTPRequest{
		Grant:            grant,
		Method:           req.Method,
		Path:             req.Path,
		Query:            req.Query,
		Headers:          req.Headers,
		Body:             body,
		MaxRequestBytes:  req.MaxRequestBytes,
		MaxResponseBytes: req.MaxResponseBytes,
		MaxChunkBytes:    req.MaxChunkBytes,
		Timeout:          timeout,
		Now:              now,
	}, func(chunk connectivity.HTTPResponseChunk) error {
		return streamSink.AppendRuntimeStream(ctx, streamID, "data", chunk.Data)
	})
	if err != nil {
		response := networkExecuteErrorResponse(err)
		_ = streamSink.FailRuntimeStream(ctx, streamID, capability.ExecutionFailurePlatformFailed, err)
		return response
	}
	if err := streamSink.CloseRuntimeStream(ctx, streamID); err != nil {
		return networkExecuteErrorResponse(err)
	}
	return networkExecuteResponsePayload{
		OK:         true,
		StatusCode: result.StatusCode,
		Headers:    result.Headers,
		StreamID:   streamID,
		BytesRead:  result.BytesRead,
		ChunkCount: result.ChunkCount,
	}
}

func runtimeHostcallContext(parent context.Context, requested time.Duration) (context.Context, context.CancelFunc) {
	timeout := requested
	if timeout <= 0 {
		timeout = defaultRuntimeHostcallTimeout
	}
	if timeout > maxRuntimeHostcallTimeout {
		timeout = maxRuntimeHostcallTimeout
	}
	return context.WithTimeout(parent, timeout)
}

func boundedSynchronousBrokerPayloadBytes(requested int64) (int64, error) {
	if requested < 0 {
		return 0, errors.New("response byte limit must not be negative")
	}
	if requested == 0 {
		return maxSynchronousBrokerPayloadBytes, nil
	}
	if requested > maxSynchronousBrokerPayloadBytes {
		return 0, fmt.Errorf("response byte limit must not exceed %d", maxSynchronousBrokerPayloadBytes)
	}
	return requested, nil
}

func decodeOptionalBase64(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode base64 payload: %v", err)
	}
	return data, nil
}

func networkGrantErrorResponse(err error) networkGrantResponsePayload {
	switch {
	case errors.Is(err, connectivity.ErrInvalidConnector):
		return networkGrantResponsePayload{OK: false, Code: "NETWORK_GRANT_REQUEST_INVALID", Message: "network grant request is invalid", InternalError: err}
	case errors.Is(err, connectivity.ErrTargetDenied):
		return networkGrantResponsePayload{OK: false, Code: "NETWORK_TARGET_DENIED", Message: "network target was denied", InternalError: err}
	case errors.Is(err, connectivity.ErrConnectorDenied):
		return networkGrantResponsePayload{OK: false, Code: "NETWORK_CONNECTOR_DENIED", Message: "network connector was denied", InternalError: err}
	default:
		return networkGrantResponsePayload{OK: false, Code: "NETWORK_GRANT_FAILED", Message: "network grant operation failed", InternalError: err}
	}
}

func networkExecuteErrorResponse(err error) networkExecuteResponsePayload {
	switch {
	case errors.Is(err, connectivity.ErrInvalidConnector):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: "network execute request is invalid", InternalError: err}
	case errors.Is(err, connectivity.ErrTargetDenied):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_TARGET_DENIED", Message: "network target was denied", InternalError: err}
	case errors.Is(err, connectivity.ErrConnectorDenied):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_CONNECTOR_DENIED", Message: "network connector was denied", InternalError: err}
	case errors.Is(err, connectivity.ErrGrantExpired):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_GRANT_EXPIRED", Message: "network grant has expired", InternalError: err}
	case errors.Is(err, connectivity.ErrRequestTooLarge):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_REQUEST_TOO_LARGE", Message: "network request is too large", InternalError: err}
	case errors.Is(err, connectivity.ErrResponseTooLarge):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_RESPONSE_TOO_LARGE", Message: "network response is too large", InternalError: err}
	case errors.Is(err, connectivity.ErrRateLimited):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_RATE_LIMITED", Message: "network request was rate limited", InternalError: err}
	case errors.Is(err, connectivity.ErrConnectionClosed):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_CONNECTION_CLOSED", Message: "network connection was closed", InternalError: err}
	case errors.Is(err, connectivity.ErrWebSocketFailed):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_WEBSOCKET_FAILED", Message: "network websocket operation failed", InternalError: err}
	case errors.Is(err, stream.ErrBackpressure):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_STREAM_BACKPRESSURE", Message: "network stream is backpressured", InternalError: err}
	case errors.Is(err, stream.ErrInvalidStream):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_STREAM_INVALID", Message: "network stream is invalid", InternalError: err}
	case errors.Is(err, stream.ErrNotFound):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_STREAM_NOT_FOUND", Message: "network stream was not found", InternalError: err}
	case errors.Is(err, stream.ErrStreamClosed):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_STREAM_CLOSED", Message: "network stream is closed", InternalError: err}
	default:
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_FAILED", Message: "network execute operation failed", InternalError: err}
	}
}

func allowedArtifactRequest(invocation *workerInvocationContext) *ArtifactRequest {
	if invocation == nil {
		return nil
	}
	return &invocation.Artifact
}

func (identity workerInvocationIdentity) matchesRuntimeHostcall(
	pluginInstanceID string,
	activeFingerprint string,
	runtimeInstanceID string,
	runtimeGenerationID string,
	runtimeShardID string,
	policyRevision uint64,
	managementRevision uint64,
	revokeEpoch uint64,
) bool {
	return pluginInstanceID == identity.PluginInstanceID &&
		activeFingerprint == identity.ActiveFingerprint &&
		runtimeInstanceID == identity.RuntimeInstanceID &&
		runtimeGenerationID == identity.RuntimeGenerationID &&
		runtimeShardID == identity.RuntimeShardID &&
		policyRevision == identity.PolicyRevision &&
		managementRevision == identity.ManagementRevision &&
		revokeEpoch == identity.RevokeEpoch
}

func (identity workerInvocationIdentity) matchesNetworkExecute(req networkExecuteRequestPayload) bool {
	return identity.matchesRuntimeHostcall(
		req.PluginInstanceID,
		req.ActiveFingerprint,
		req.RuntimeInstanceID,
		req.RuntimeGenerationID,
		req.RuntimeShardID,
		req.PolicyRevision,
		req.ManagementRevision,
		req.RevokeEpoch,
	) &&
		req.PluginID == identity.PluginID &&
		req.OwnerSessionHash == identity.OwnerSessionHash &&
		req.OwnerUserHash == identity.OwnerUserHash &&
		req.OwnerEnvHash == identity.OwnerEnvHash &&
		req.SessionChannelIDHash == identity.SessionChannelIDHash
}

func workerInvocationContextFromInvocation(lease Lease, invocation json.RawMessage) (workerInvocationContext, error) {
	var envelope struct {
		PluginID             string          `json:"plugin_id"`
		PluginInstanceID     string          `json:"plugin_instance_id"`
		ActiveFingerprint    string          `json:"active_fingerprint"`
		RuntimeInstanceID    string          `json:"runtime_instance_id"`
		RuntimeGenerationID  string          `json:"runtime_generation_id"`
		PackageHash          string          `json:"package_hash"`
		Artifact             string          `json:"artifact"`
		ArtifactSHA256       string          `json:"artifact_sha256"`
		Method               string          `json:"method"`
		Effect               string          `json:"effect"`
		Execution            string          `json:"execution"`
		SurfaceInstanceID    string          `json:"surface_instance_id"`
		OwnerSessionHash     string          `json:"owner_session_hash"`
		OwnerUserHash        string          `json:"owner_user_hash"`
		OwnerEnvHash         string          `json:"owner_env_hash"`
		SessionChannelIDHash string          `json:"session_channel_id_hash"`
		BridgeChannelID      string          `json:"bridge_channel_id"`
		OperationID          string          `json:"operation_id"`
		StreamID             string          `json:"stream_id"`
		AuditCorrelationID   string          `json:"audit_correlation_id"`
		BrokerAccess         json.RawMessage `json:"broker_access"`
		BrokerAccessSHA256   string          `json:"broker_access_sha256"`
	}
	if err := json.Unmarshal(invocation, &envelope); err != nil {
		return workerInvocationContext{}, fmt.Errorf("%w: decode worker invocation context: %v", ErrRuntimeRequestFailed, err)
	}
	bindings := []struct {
		name       string
		lease      string
		invocation string
	}{
		{name: "plugin_id", lease: lease.PluginID, invocation: envelope.PluginID},
		{name: "plugin_instance_id", lease: lease.PluginInstanceID, invocation: envelope.PluginInstanceID},
		{name: "active_fingerprint", lease: lease.ActiveFingerprint, invocation: envelope.ActiveFingerprint},
		{name: "runtime_instance_id", lease: lease.RuntimeInstanceID, invocation: envelope.RuntimeInstanceID},
		{name: "runtime_generation_id", lease: lease.RuntimeGenerationID, invocation: envelope.RuntimeGenerationID},
		{name: "method", lease: lease.Method, invocation: envelope.Method},
		{name: "effect", lease: lease.Effect, invocation: envelope.Effect},
		{name: "execution", lease: lease.Execution, invocation: envelope.Execution},
		{name: "surface_instance_id", lease: lease.SurfaceInstanceID, invocation: envelope.SurfaceInstanceID},
		{name: "owner_session_hash", lease: lease.OwnerSessionHash, invocation: envelope.OwnerSessionHash},
		{name: "owner_user_hash", lease: lease.OwnerUserHash, invocation: envelope.OwnerUserHash},
		{name: "owner_env_hash", lease: lease.OwnerEnvHash, invocation: envelope.OwnerEnvHash},
		{name: "session_channel_id_hash", lease: lease.SessionChannelIDHash, invocation: envelope.SessionChannelIDHash},
		{name: "bridge_channel_id", lease: lease.BridgeChannelID, invocation: envelope.BridgeChannelID},
		{name: "operation_id", lease: lease.OperationID, invocation: envelope.OperationID},
		{name: "stream_id", lease: lease.StreamID, invocation: envelope.StreamID},
		{name: "audit_correlation_id", lease: lease.AuditCorrelationID, invocation: envelope.AuditCorrelationID},
	}
	for _, binding := range bindings {
		expected := strings.TrimSpace(binding.lease)
		if binding.invocation != expected || binding.invocation != strings.TrimSpace(binding.invocation) {
			return workerInvocationContext{}, fmt.Errorf("%w: worker invocation %s does not match signed lease", ErrRuntimeRequestFailed, binding.name)
		}
	}
	artifact := ArtifactRequest{
		PackageHash:    strings.TrimSpace(envelope.PackageHash),
		Artifact:       strings.TrimSpace(envelope.Artifact),
		ArtifactSHA256: strings.TrimSpace(envelope.ArtifactSHA256),
	}
	if artifact.PackageHash == "" || artifact.Artifact == "" || artifact.ArtifactSHA256 == "" {
		return workerInvocationContext{}, fmt.Errorf("%w: worker invocation must include package_hash, artifact, and artifact_sha256", ErrRuntimeRequestFailed)
	}
	if !isSHA256Ref(artifact.PackageHash) || !isSHA256Ref(artifact.ArtifactSHA256) {
		return workerInvocationContext{}, fmt.Errorf("%w: worker invocation artifact hashes must use sha256:<hex>", ErrRuntimeRequestFailed)
	}
	if !isWorkerArtifactPath(artifact.Artifact) {
		return workerInvocationContext{}, fmt.Errorf("%w: worker invocation artifact path is invalid", ErrRuntimeRequestFailed)
	}
	if len(envelope.BrokerAccess) == 0 || !isSHA256Ref(envelope.BrokerAccessSHA256) {
		return workerInvocationContext{}, fmt.Errorf("%w: worker invocation must include broker_access and broker_access_sha256", ErrRuntimeRequestFailed)
	}
	var access workerBrokerAccess
	if err := decodeStrictJSON(envelope.BrokerAccess, &access); err != nil {
		return workerInvocationContext{}, fmt.Errorf("%w: decode worker broker access contract: %v", ErrRuntimeRequestFailed, err)
	}
	canonical, err := json.Marshal(access)
	if err != nil {
		return workerInvocationContext{}, fmt.Errorf("%w: encode worker broker access contract: %v", ErrRuntimeRequestFailed, err)
	}
	sum := sha256.Sum256(canonical)
	wantHash := "sha256:" + hex.EncodeToString(sum[:])
	if envelope.BrokerAccessSHA256 != wantHash {
		return workerInvocationContext{}, fmt.Errorf("%w: worker broker access hash mismatch", ErrRuntimeRequestFailed)
	}
	return workerInvocationContext{
		Artifact:     artifact,
		BrokerAccess: access,
		identity: workerInvocationIdentity{
			PluginID:             strings.TrimSpace(lease.PluginID),
			PluginInstanceID:     strings.TrimSpace(lease.PluginInstanceID),
			ActiveFingerprint:    strings.TrimSpace(lease.ActiveFingerprint),
			PolicyRevision:       lease.PolicyRevision,
			ManagementRevision:   lease.ManagementRevision,
			RevokeEpoch:          lease.RevokeEpoch,
			RuntimeShardID:       strings.TrimSpace(lease.RuntimeShardID),
			RuntimeInstanceID:    strings.TrimSpace(lease.RuntimeInstanceID),
			RuntimeGenerationID:  strings.TrimSpace(lease.RuntimeGenerationID),
			OwnerSessionHash:     strings.TrimSpace(lease.OwnerSessionHash),
			OwnerUserHash:        strings.TrimSpace(lease.OwnerUserHash),
			OwnerEnvHash:         strings.TrimSpace(lease.OwnerEnvHash),
			SessionChannelIDHash: strings.TrimSpace(lease.SessionChannelIDHash),
		},
	}, nil
}

func (access workerBrokerAccess) allowsStorage(storeID string, operation string) bool {
	for _, item := range access.Storage {
		if item.StoreID == storeID && stringSliceContains(item.Operations, operation) {
			return true
		}
	}
	return false
}

func (access workerBrokerAccess) allowsNetworkConnector(connectorID string, transport string) bool {
	for _, item := range access.Network {
		if item.ConnectorID == connectorID && item.Transport == transport {
			return true
		}
	}
	return false
}

func (access workerBrokerAccess) allowsNetwork(connectorID string, transport string, operation string, httpMethod string) bool {
	for _, item := range access.Network {
		if item.ConnectorID != connectorID || item.Transport != transport || !stringSliceContains(item.Operations, operation) {
			continue
		}
		if transport == string(connectivity.TransportHTTP) && !stringSliceContains(item.HTTPMethods, httpMethod) {
			continue
		}
		return true
	}
	return false
}

func stringSliceContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func artifactRequestMatches(got ArtifactRequest, want ArtifactRequest) bool {
	return strings.TrimSpace(got.PackageHash) == strings.TrimSpace(want.PackageHash) &&
		strings.TrimSpace(got.Artifact) == strings.TrimSpace(want.Artifact) &&
		strings.TrimSpace(got.ArtifactSHA256) == strings.TrimSpace(want.ArtifactSHA256)
}

func isSHA256Ref(value string) bool {
	hexValue, ok := strings.CutPrefix(value, "sha256:")
	if !ok || len(hexValue) != 64 {
		return false
	}
	for _, ch := range hexValue {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func isWorkerArtifactPath(value string) bool {
	if !strings.HasPrefix(value, "workers/") || !strings.HasSuffix(value, ".wasm") {
		return false
	}
	if strings.Contains(value, "\\") || strings.Contains(value, "//") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

func readIPCFrame(reader *bufio.Reader) (ipcFrame, error) {
	line, err := readBoundedIPCLine(reader, maxIPCFrameBytes)
	if err != nil {
		return ipcFrame{}, err
	}
	var frame ipcFrame
	if err := decodeStrictJSON(line, &frame); err != nil {
		return ipcFrame{}, err
	}
	return frame, nil
}

func readBoundedIPCLine(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	if reader == nil || maxBytes <= 0 {
		return nil, errors.New("IPC frame reader and positive size limit are required")
	}
	line := make([]byte, 0, min(maxBytes, 4096))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > maxBytes-len(line) {
			return nil, fmt.Errorf("IPC frame exceeds %d bytes", maxBytes)
		}
		line = append(line, fragment...)
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

func marshalHostcallPayload(ok bool, successPayload any, code string, message string) ([]byte, error) {
	if ok {
		return json.Marshal(successPayload)
	}
	return json.Marshal(hostcallFailurePayload{
		OK:          false,
		Code:        code,
		Message:     message,
		ErrorOrigin: WorkerErrorOriginHostcall,
	})
}

func marshalStorageFileHostcallPayload(payload storageFileResponsePayload) ([]byte, error) {
	if !payload.OK {
		return marshalHostcallPayload(false, nil, payload.Code, payload.Message)
	}
	if payload.Usage != nil && !validStorageUsage(*payload.Usage) {
		return nil, errors.New("storage file success response has invalid usage")
	}
	switch payload.Operation {
	case "read":
		if payload.Usage == nil || payload.SizeBytes < 0 || payload.Entries != nil {
			return nil, errors.New("storage file read success response violates its closed contract")
		}
		return json.Marshal(storageFileReadSuccessPayload{
			OK: true, Path: payload.Path, DataBase64: payload.DataBase64,
			SizeBytes: payload.SizeBytes, Usage: *payload.Usage,
		})
	case "write":
		if payload.Usage == nil || payload.SizeBytes < 0 || payload.DataBase64 != "" || payload.Entries != nil {
			return nil, errors.New("storage file write success response violates its closed contract")
		}
		return json.Marshal(storageFileWriteSuccessPayload{
			OK: true, Path: payload.Path, SizeBytes: payload.SizeBytes, Usage: *payload.Usage,
		})
	case "delete":
		if payload.DataBase64 != "" || payload.SizeBytes != 0 || payload.Entries != nil || payload.Usage != nil {
			return nil, errors.New("storage file delete success response violates its closed contract")
		}
		return json.Marshal(storageFileDeleteSuccessPayload{OK: true, Path: payload.Path})
	case "list":
		if payload.Usage == nil || payload.DataBase64 != "" || payload.SizeBytes != 0 {
			return nil, errors.New("storage file list success response violates its closed contract")
		}
		entries := payload.Entries
		if entries == nil {
			entries = []storage.FileEntry{}
		}
		return json.Marshal(storageFileListSuccessPayload{
			OK: true, Path: payload.Path, Entries: entries, Usage: *payload.Usage,
		})
	default:
		return nil, errors.New("storage file success response operation is invalid")
	}
}

func marshalStorageKVHostcallPayload(payload storageKVResponsePayload) ([]byte, error) {
	if !payload.OK {
		return marshalHostcallPayload(false, nil, payload.Code, payload.Message)
	}
	if payload.Usage != nil && !validStorageUsage(*payload.Usage) {
		return nil, errors.New("storage KV success response has invalid usage")
	}
	switch payload.Operation {
	case "get":
		if payload.Usage == nil || payload.SizeBytes < 0 || payload.Prefix != "" || payload.Entries != nil {
			return nil, errors.New("storage KV get success response violates its closed contract")
		}
		return json.Marshal(storageKVGetSuccessPayload{
			OK: true, Key: payload.Key, ValueBase64: payload.ValueBase64,
			SizeBytes: payload.SizeBytes, Usage: *payload.Usage,
		})
	case "put":
		if payload.Usage == nil || payload.SizeBytes < 0 || payload.ValueBase64 != "" || payload.Prefix != "" || payload.Entries != nil {
			return nil, errors.New("storage KV put success response violates its closed contract")
		}
		return json.Marshal(storageKVPutSuccessPayload{
			OK: true, Key: payload.Key, SizeBytes: payload.SizeBytes, Usage: *payload.Usage,
		})
	case "delete":
		if payload.ValueBase64 != "" || payload.SizeBytes != 0 || payload.Prefix != "" || payload.Entries != nil || payload.Usage != nil {
			return nil, errors.New("storage KV delete success response violates its closed contract")
		}
		return json.Marshal(storageKVDeleteSuccessPayload{OK: true, Key: payload.Key})
	case "list":
		if payload.Usage == nil || payload.Key != "" || payload.ValueBase64 != "" || payload.SizeBytes != 0 {
			return nil, errors.New("storage KV list success response violates its closed contract")
		}
		entries := payload.Entries
		if entries == nil {
			entries = []storage.KVEntry{}
		}
		return json.Marshal(storageKVListSuccessPayload{
			OK: true, Prefix: payload.Prefix, Entries: entries, Usage: *payload.Usage,
		})
	default:
		return nil, errors.New("storage KV success response operation is invalid")
	}
}

func marshalStorageSQLiteHostcallPayload(payload storageSQLiteResponsePayload) ([]byte, error) {
	if !payload.OK {
		return marshalHostcallPayload(false, nil, payload.Code, payload.Message)
	}
	if payload.Usage == nil || !validStorageUsage(*payload.Usage) {
		return nil, errors.New("storage SQLite success response has invalid usage")
	}
	switch payload.Operation {
	case "exec":
		if payload.RowsAffected == nil || *payload.RowsAffected < 0 || payload.LastInsertID < 0 || payload.Columns != nil || payload.Rows != nil {
			return nil, errors.New("storage SQLite exec success response violates its closed contract")
		}
		return json.Marshal(storageSQLiteExecSuccessPayload{
			OK: true, Database: payload.Database, RowsAffected: *payload.RowsAffected,
			LastInsertID: payload.LastInsertID, Usage: *payload.Usage,
		})
	case "query":
		if payload.RowsAffected != nil || payload.LastInsertID != 0 || payload.Columns == nil || payload.Rows == nil {
			return nil, errors.New("storage SQLite query success response violates its closed contract")
		}
		columns := *payload.Columns
		if columns == nil {
			columns = []string{}
		}
		rows := *payload.Rows
		if rows == nil {
			rows = [][]storageSQLiteValueIPC{}
		}
		for _, row := range rows {
			for _, value := range row {
				if !validStorageSQLiteValueIPC(value) {
					return nil, errors.New("storage SQLite query success response contains an invalid typed value")
				}
			}
		}
		return json.Marshal(storageSQLiteQuerySuccessPayload{
			OK: true, Database: payload.Database, Columns: columns, Rows: rows, Usage: *payload.Usage,
		})
	default:
		return nil, errors.New("storage SQLite success response operation is invalid")
	}
}

func validStorageUsage(usage storage.Usage) bool {
	return strings.TrimSpace(usage.PluginInstanceID) != "" &&
		strings.TrimSpace(usage.StoreID) != "" &&
		usage.UsageBytes >= 0 && usage.QuotaBytes >= 0 && usage.UsageFiles >= 0 && usage.QuotaFiles >= 0
}

func marshalBoundedHostcallPayload(ok bool, successPayload any, code string, message string, oversizedCode string, oversizedMessage string) ([]byte, error) {
	raw, err := marshalHostcallPayload(ok, successPayload, code, message)
	if err != nil {
		return nil, err
	}
	return boundHostcallPayload(raw, oversizedCode, oversizedMessage)
}

func boundHostcallPayload(raw []byte, oversizedCode string, oversizedMessage string) ([]byte, error) {
	if len(raw) <= maxWASMHostcallResponseBytes {
		return raw, nil
	}
	raw, err := marshalHostcallPayload(false, nil, oversizedCode, oversizedMessage)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxWASMHostcallResponseBytes {
		return nil, errors.New("bounded broker error payload exceeds the WASM hostcall limit")
	}
	return raw, nil
}

func writeIPCResponseFrame(stdin io.Writer, frameType string, runtimeGenerationID string, request ipcFrame, payload []byte) error {
	return json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           frameType,
		RequestID:           request.RequestID,
		ParentRequestID:     request.ParentRequestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             payload,
	})
}

func validateIPCResponse(requestID string, runtimeGenerationID string, responseFrameType string, frame ipcFrame) error {
	if frame.IPCVersion != version.RustIPCVersion {
		return fmt.Errorf("%w: ipc_version %q", ErrRuntimeIPCUnavailable, frame.IPCVersion)
	}
	if frame.FrameType != responseFrameType {
		return fmt.Errorf("%w: frame_type %q", ErrRuntimeIPCUnavailable, frame.FrameType)
	}
	if frame.RequestID != requestID {
		return fmt.Errorf("%w: request_id %q", ErrRuntimeIPCUnavailable, frame.RequestID)
	}
	if frame.RuntimeGenerationID != runtimeGenerationID {
		return fmt.Errorf("%w: runtime_generation_id %q", ErrRuntimeIPCUnavailable, frame.RuntimeGenerationID)
	}
	return nil
}

func decodeRuntimeResponse(frame ipcFrame) (runtimeResponsePayload, error) {
	if len(frame.Payload) == 0 {
		return runtimeResponsePayload{}, fmt.Errorf("%w: missing response payload", ErrRuntimeIPCUnavailable)
	}
	var wire struct {
		OK          *bool              `json:"ok"`
		Result      json.RawMessage    `json:"result"`
		Code        *string            `json:"code"`
		Message     *string            `json:"message"`
		ErrorOrigin *WorkerErrorOrigin `json:"error_origin"`
	}
	if err := decodeStrictJSON(frame.Payload, &wire); err != nil {
		return runtimeResponsePayload{}, fmt.Errorf("%w: decode response payload: %v", ErrRuntimeIPCUnavailable, err)
	}
	if wire.OK == nil {
		return runtimeResponsePayload{}, fmt.Errorf("%w: response payload is missing ok", ErrRuntimeIPCUnavailable)
	}
	if *wire.OK {
		if len(wire.Result) == 0 || wire.Code != nil || wire.Message != nil || wire.ErrorOrigin != nil {
			return runtimeResponsePayload{}, fmt.Errorf("%w: success response payload must contain only ok and result", ErrRuntimeIPCUnavailable)
		}
		return runtimeResponsePayload{OK: true, Result: append(json.RawMessage(nil), wire.Result...)}, nil
	}
	if len(wire.Result) != 0 || wire.Code == nil || wire.Message == nil || wire.ErrorOrigin == nil ||
		strings.TrimSpace(*wire.Code) == "" || strings.TrimSpace(*wire.Message) == "" || !wire.ErrorOrigin.valid() {
		return runtimeResponsePayload{}, fmt.Errorf("%w: failure response payload must contain only ok, code, message, and valid error_origin", ErrRuntimeIPCUnavailable)
	}
	return runtimeResponsePayload{
		Code:        strings.TrimSpace(*wire.Code),
		Message:     strings.TrimSpace(*wire.Message),
		ErrorOrigin: *wire.ErrorOrigin,
	}, nil
}

func decodeStrictJSON(raw []byte, target any) error {
	if target == nil {
		return errors.New("strict JSON target is required")
	}
	if err := validateJSONKeys(raw); err != nil {
		return err
	}
	if err := validateStructKeyBindings(raw, reflect.TypeOf(target)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains a trailing value")
		}
		return err
	}
	return nil
}

func validateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walkValue func() error
	walkValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err := walkValue(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
		case '[':
			for decoder.More() {
				if err := walkValue(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil {
				return err
			}
			if closing != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := walkValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains a trailing value")
		}
		return err
	}
	return nil
}

type strictJSONField struct {
	name  string
	type_ reflect.Type
}

func validateStructKeyBindings(raw []byte, targetType reflect.Type) error {
	targetType = dereferenceJSONType(targetType)
	if targetType == nil || targetType == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	switch targetType.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil
		}
		fields := strictJSONStructFields(targetType)
		seen := make(map[string]string)
		for key, value := range object {
			field, ok := strictJSONFieldForKey(fields, key)
			if !ok {
				continue
			}
			if field.name != key {
				return fmt.Errorf("JSON object key %q must exactly match field %q", key, field.name)
			}
			if previous, exists := seen[field.name]; exists && previous != key {
				return fmt.Errorf("JSON keys %q and %q both bind to struct field %q", previous, key, field.name)
			}
			seen[field.name] = key
			if err := validateStructKeyBindings(value, field.type_); err != nil {
				return err
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil
		}
		for _, value := range object {
			if err := validateStructKeyBindings(value, targetType.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if targetType.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil
		}
		for _, value := range values {
			if err := validateStructKeyBindings(value, targetType.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func strictJSONStructFields(targetType reflect.Type) []strictJSONField {
	fields := make([]strictJSONField, 0, targetType.NumField())
	for index := 0; index < targetType.NumField(); index++ {
		field := targetType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			fields = append(fields, strictJSONStructFields(dereferenceJSONType(field.Type))...)
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields = append(fields, strictJSONField{name: name, type_: field.Type})
	}
	return fields
}

func strictJSONFieldForKey(fields []strictJSONField, key string) (strictJSONField, bool) {
	for _, field := range fields {
		if field.name == key {
			return field, true
		}
	}
	for _, field := range fields {
		if strings.EqualFold(field.name, key) {
			return field, true
		}
	}
	return strictJSONField{}, false
}

func dereferenceJSONType(targetType reflect.Type) reflect.Type {
	for targetType != nil && targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}
	return targetType
}

func validateHelloAck(requestID string, runtimeGenerationID string, channelNonce string, expectedDescriptor RuntimeDescriptor, expectedLimits RuntimeLimits, frame ipcFrame) (helloAckPayload, error) {
	if frame.IPCVersion != version.RustIPCVersion {
		return helloAckPayload{}, fmt.Errorf("%w: ipc_version %q", ErrRuntimeHandshake, frame.IPCVersion)
	}
	if frame.FrameType != ipcFrameTypeHelloAck {
		return helloAckPayload{}, fmt.Errorf("%w: frame_type %q", ErrRuntimeHandshake, frame.FrameType)
	}
	if frame.RequestID != requestID {
		return helloAckPayload{}, fmt.Errorf("%w: request_id %q", ErrRuntimeHandshake, frame.RequestID)
	}
	if frame.RuntimeGenerationID != runtimeGenerationID {
		return helloAckPayload{}, fmt.Errorf("%w: runtime_generation_id %q", ErrRuntimeHandshake, frame.RuntimeGenerationID)
	}
	var ack helloAckPayload
	if err := decodeStrictJSON(frame.Payload, &ack); err != nil {
		return helloAckPayload{}, fmt.Errorf("%w: decode payload: %v", ErrRuntimeHandshake, err)
	}
	runtimeVersion, err := version.ParseSemVer(ack.RuntimeVersion)
	if err != nil {
		return helloAckPayload{}, fmt.Errorf("%w: runtime version: %v", ErrRuntimeHandshake, err)
	}
	actualDescriptor, err := NewRuntimeDescriptor(
		runtimeVersion,
		ack.ActualTarget,
		ack.RustIPCVersion,
		ack.WASMABIVersion,
		expectedDescriptor.ArtifactSHA256(),
	)
	if err != nil || actualDescriptor != expectedDescriptor {
		return helloAckPayload{}, fmt.Errorf(
			"%w: %w: runtime=%q target=%s/%s ipc=%q wasm=%q",
			ErrRuntimeHandshake,
			ErrRuntimeDescriptorMismatch,
			ack.RuntimeVersion,
			ack.ActualTarget.OS,
			ack.ActualTarget.Arch,
			ack.RustIPCVersion,
			ack.WASMABIVersion,
		)
	}
	if ack.ChannelNonce != channelNonce {
		return helloAckPayload{}, fmt.Errorf("%w: channel_nonce mismatch", ErrRuntimeHandshake)
	}
	if ack.Limits != expectedLimits {
		return helloAckPayload{}, fmt.Errorf("%w: runtime limits mismatch", ErrRuntimeHandshake)
	}
	return ack, nil
}
