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
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/jsonvalue"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

type Lease struct {
	LeaseID                string               `json:"lease_id"`
	TokenID                string               `json:"token_id"`
	LeaseNonce             string               `json:"lease_nonce"`
	PluginID               string               `json:"plugin_id"`
	PluginVersion          string               `json:"plugin_version"`
	ActiveFingerprint      string               `json:"active_fingerprint"`
	InvocationID           string               `json:"invocation_id"`
	ScopeKind              sessionctx.ScopeKind `json:"scope_kind"`
	SurfaceInstanceID      string               `json:"surface_instance_id,omitempty"`
	OwnerSessionHash       string               `json:"owner_session_hash,omitempty"`
	OwnerUserHash          string               `json:"owner_user_hash,omitempty"`
	OwnerEnvHash           string               `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash   string               `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID        string               `json:"bridge_channel_id,omitempty"`
	RuntimeGenerationID    string               `json:"runtime_generation_id"`
	PluginInstanceID       string               `json:"plugin_instance_id"`
	Method                 string               `json:"method"`
	Effect                 string               `json:"effect"`
	Execution              string               `json:"execution"`
	ExecutionID            string               `json:"execution_id,omitempty"`
	AuditCorrelationID     string               `json:"audit_correlation_id"`
	TargetDescriptorHashes []string             `json:"target_descriptor_hashes"`
	Limits                 LeaseLimits          `json:"limits"`
	PolicyRevision         uint64               `json:"policy_revision"`
	ManagementRevision     uint64               `json:"management_revision"`
	RevokeEpoch            uint64               `json:"revoke_epoch"`
	RuntimeShardID         string               `json:"runtime_shard_id"`
	RuntimeInstanceID      string               `json:"runtime_instance_id"`
	IPCChannelID           string               `json:"ipc_channel_id"`
	ConnectionNonce        string               `json:"connection_nonce"`
	KeyID                  string               `json:"key_id"`
	Signature              string               `json:"signature"`
	IssuedAtUnixMillis     int64                `json:"issued_at_unix_ms"`
	ExpiresAtUnixMillis    int64                `json:"expires_at_unix_ms"`
}

type LeaseLimits struct {
	TimeoutMillis           int64 `json:"timeout_ms"`
	MemoryBytes             int64 `json:"memory_bytes"`
	MaxPayloadBytes         int64 `json:"max_payload_bytes"`
	MaxStreamBytesPerSecond int64 `json:"max_stream_bytes_per_sec"`
}

type Health struct {
	RuntimeInstanceID   string                  `json:"runtime_instance_id"`
	RuntimeGenerationID string                  `json:"runtime_generation_id"`
	IPCChannelID        string                  `json:"ipc_channel_id,omitempty"`
	ConnectionNonce     string                  `json:"connection_nonce,omitempty"`
	ContainmentIdentity string                  `json:"-"`
	ArtifactIdentity    RuntimeArtifactIdentity `json:"artifact_identity"`
	Ready               bool                    `json:"ready"`
	ActiveInvocations   int                     `json:"active_invocations"`
	QueuedInvocations   int                     `json:"queued_invocations"`
	Limits              RuntimeLimits           `json:"limits"`
	ModuleCache         ModuleCacheMetrics      `json:"module_cache"`
}

type RuntimeLimits struct {
	WorkerCount            int   `json:"worker_count"`
	QueueCapacity          int   `json:"queue_capacity"`
	PerPluginConcurrency   int   `json:"per_plugin_concurrency"`
	ModuleCacheEntries     int   `json:"module_cache_entries"`
	ModuleCacheSourceBytes int64 `json:"module_cache_source_bytes"`
}

// RuntimeProcessExitFailure binds one released runtime process exit status to
// the stable diagnostic code reported by ProcessSupervisor.
type RuntimeProcessExitFailure struct {
	ExitCode int
	Code     observability.RuntimeProcessFailureCode
}

const (
	runtimeProcessExitGeneral                     = 1
	runtimeProcessExitWriterCapacityOverflow      = 80
	runtimeProcessExitWriterCapacityLimitExceeded = 81
	runtimeProcessExitWriterStartFailed           = 82
	runtimeProcessExitWriterClosed                = 83
	runtimeProcessExitWriterBatchSizeOverflow     = 84
	runtimeProcessExitWriterWriteFailed           = 85
	runtimeProcessExitWriterFlushFailed           = 86
	runtimeProcessExitWriterPanicked              = 87
)

var runtimeProcessExitFailureContract = [...]RuntimeProcessExitFailure{
	{ExitCode: runtimeProcessExitGeneral, Code: observability.RuntimeProcessFailed},
	{ExitCode: runtimeProcessExitWriterCapacityOverflow, Code: observability.RuntimeProcessWriterCapacityOverflow},
	{ExitCode: runtimeProcessExitWriterCapacityLimitExceeded, Code: observability.RuntimeProcessWriterCapacityLimitExceeded},
	{ExitCode: runtimeProcessExitWriterStartFailed, Code: observability.RuntimeProcessWriterStartFailed},
	{ExitCode: runtimeProcessExitWriterClosed, Code: observability.RuntimeProcessWriterClosed},
	{ExitCode: runtimeProcessExitWriterBatchSizeOverflow, Code: observability.RuntimeProcessWriterBatchSizeOverflow},
	{ExitCode: runtimeProcessExitWriterWriteFailed, Code: observability.RuntimeProcessWriterWriteFailed},
	{ExitCode: runtimeProcessExitWriterFlushFailed, Code: observability.RuntimeProcessWriterFlushFailed},
	{ExitCode: runtimeProcessExitWriterPanicked, Code: observability.RuntimeProcessWriterPanicked},
}

// RuntimeProcessExitFailures returns an owned copy of the fixed exit mapping.
func RuntimeProcessExitFailures() []RuntimeProcessExitFailure {
	return append([]RuntimeProcessExitFailure(nil), runtimeProcessExitFailureContract[:]...)
}

const (
	RuntimeWorkerCountMin            = 1
	RuntimeWorkerCountMax            = 64
	RuntimeQueueCapacityMin          = 1
	RuntimeQueueCapacityMax          = 64
	RuntimePerPluginConcurrencyMin   = 1
	RuntimePerPluginConcurrencyMax   = 64
	RuntimeModuleCacheEntriesMin     = 1
	RuntimeModuleCacheEntriesMax     = 1024
	RuntimeModuleCacheSourceBytesMin = 1
	RuntimeModuleCacheSourceBytesMax = 128 << 20
)

type ModuleCacheMetrics struct {
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	Compiles    uint64 `json:"compiles"`
	Entries     int    `json:"entries"`
	SourceBytes int64  `json:"source_bytes"`
}

type RevokeResult struct {
	ResourceScope            sessionctx.ResourceScope `json:"resource_scope"`
	PluginInstanceID         string                   `json:"plugin_instance_id"`
	RevokeEpoch              uint64                   `json:"revoke_epoch"`
	ClosedSocketCount        int                      `json:"closed_socket_count"`
	ClosedStreamCount        int                      `json:"closed_stream_count"`
	ClosedStorageHandleCount int                      `json:"closed_storage_handle_count"`
	RuntimeStopped           bool                     `json:"runtime_stopped,omitempty"`
}

type RevokeRequest struct {
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	PluginInstanceID string                   `json:"plugin_instance_id"`
	RevokeEpoch      uint64                   `json:"revoke_epoch"`
}

type SessionRevokeState string

const SessionRevokeStateComplete SessionRevokeState = "complete"

type SessionRevokeRequest struct {
	SessionScope          sessionctx.SessionScope `json:"-"`
	SessionRevokeSequence uint64                  `json:"session_revoke_sequence"`
}

type SessionRevokeCounts struct {
	QueuedInvocations     uint64 `json:"queued_invocations"`
	RunningInvocations    uint64 `json:"running_invocations"`
	StorageHostcalls      uint64 `json:"storage_hostcalls"`
	ActiveNetworkRequests uint64 `json:"active_network_requests"`
	Sockets               uint64 `json:"sockets"`
	NetworkStreams        uint64 `json:"network_streams"`
}

type SessionRevokeShardResult struct {
	RuntimeShardID      string              `json:"runtime_shard_id"`
	RuntimeGenerationID string              `json:"runtime_generation_id"`
	State               SessionRevokeState  `json:"state"`
	Counts              SessionRevokeCounts `json:"counts"`
}

type SessionRevokeResult struct {
	SessionScope          sessionctx.SessionScope    `json:"-"`
	SessionRevokeSequence uint64                     `json:"session_revoke_sequence"`
	Shards                []SessionRevokeShardResult `json:"shards"`
	Counts                SessionRevokeCounts        `json:"counts"`
	RuntimeStopped        bool                       `json:"runtime_stopped,omitempty"`
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

type ArtifactRequest struct {
	PackageHash    string `json:"package_hash"`
	Artifact       string `json:"artifact"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type PrewarmWorkerRequest struct {
	PluginInstanceID string
	WorkerID         string
	Artifact         ArtifactRequest
}

type ArtifactResult struct {
	Content []byte `json:"-"`
	SHA256  string `json:"sha256"`
}

type workerInvocationContext struct {
	InvocationID string
	Artifact     ArtifactRequest
	Prewarm      bool
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
	Scope      string   `json:"scope"`
	Operations []string `json:"operations"`
}

type workerNetworkBrokerAccess struct {
	ConnectorID string   `json:"connector_id"`
	Transport   string   `json:"transport"`
	Scope       string   `json:"scope"`
	Operations  []string `json:"operations"`
	HTTPMethods []string `json:"http_methods,omitempty"`
}

var (
	ErrRuntimePathRequired           = errors.New("runtime path is required")
	ErrRuntimeNotReady               = errors.New("runtime is not ready")
	ErrRuntimeIPCUnavailable         = errors.New("runtime ipc transport is unavailable")
	ErrRuntimeHandshake              = errors.New("runtime ipc handshake failed")
	ErrRuntimeRequestFailed          = errors.New("runtime ipc request failed")
	ErrRuntimeArtifactDigest         = errors.New("runtime artifact digest mismatch")
	ErrRuntimeContainmentUnsupported = errors.New("runtime process containment is unsupported")
	// ErrRuntimeLimitsInvalid reports runtime capacity limits outside the
	// negotiated platform contract.
	ErrRuntimeLimitsInvalid = errors.New("runtime limits are invalid")
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
	RuntimePath          string
	RuntimeExecutable    *os.File
	RuntimeExecutionRoot *os.File
	ArtifactIdentity     RuntimeArtifactIdentity
	Args                 []string
	Env                  []string
	Dir                  string
	Diagnostics          observability.DiagnosticsSink
	Artifacts            ArtifactProvider

	RuntimeLeaseReplays RuntimeLeaseReplayStore

	StreamSink            RuntimeStreamSink
	IOBroker              RuntimeIOBroker
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

// RuntimeIOBroker is the Host-owned authority for Worker API resource I/O.
// Runtime frames provide only a signed invocation ID and opaque handle; owner
// hashes, permissions, revisions, epochs, paths, and policy remain in Host.
type RuntimeIOBroker interface {
	Control(context.Context, string, []byte) ([]byte, error)
	Read(context.Context, string, uint64, []byte) (int, uint32, error)
	Write(context.Context, string, uint64, []byte, uint32) (int, error)
	Seek(context.Context, string, uint64, int64, int) (int64, error)
	Close(context.Context, string, uint64) error
}

type ProcessSupervisor struct {
	startMu       sync.Mutex
	controlMu     sync.Mutex
	mu            sync.Mutex
	pendingMu     sync.Mutex
	path          string
	executable    *os.File
	executionRoot *os.File
	descriptor    RuntimeArtifactIdentity
	args          []string
	env           []string
	dir           string
	diagnostics   observability.DiagnosticsSink
	artifacts     ArtifactProvider

	runtimeLeaseReplays    RuntimeLeaseReplayStore
	runtimeLeaseVerifier   RuntimeLeaseVerifier
	runtimeLeaseSigningKey string
	runtimeLeasePrivateKey ed25519.PrivateKey
	runtimeLeasePublicKeys []RuntimeLeasePublicKey

	streamSink            RuntimeStreamSink
	ioBroker              RuntimeIOBroker
	now                   func() time.Time
	handshakeTimeout      time.Duration
	heartbeatInterval     time.Duration
	maxHeartbeatStaleness time.Duration
	seq                   uint64
	requestSeq            uint64
	limits                RuntimeLimits
	admission             *runtimeAdmissionController
	pending               map[string]*pendingIPCRequest
	pendingInvocations    map[string]*pendingIPCRequest
	compileFlights        map[string]*pendingCompileFlight
	ioRouteSlots          chan struct{}

	process          *runtimeProcess
	cancel           context.CancelFunc
	exit             *processExit
	ipcIn            io.WriteCloser
	ipcOut           *bufio.Reader
	controlIn        io.WriteCloser
	controlOut       *bufio.Reader
	controlOutCloser io.Closer
	generation       *runtimeGeneration
	health           Health
}

type processExit struct {
	done              chan struct{}
	ipcReaderDone     chan struct{}
	ipcReaderDoneOnce sync.Once
	diagnosticReaders sync.WaitGroup
	diagnosticMu      sync.Mutex
	diagnosticBytes   int64
	stopEvent         sync.Once
	intentMu          sync.Mutex
	intent            runtimeProcessTerminationIntent
}

type runtimeProcessTerminationIntent uint8

const (
	runtimeProcessTerminationNone runtimeProcessTerminationIntent = iota
	runtimeProcessTerminationStop
	runtimeProcessTerminationHandshakeCleanup
	runtimeProcessTerminationIPCInvalidation
)

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
	registered        bool
	artifactRequested bool
}

type runtimeGeneration struct {
	id          string
	ctx         context.Context
	stdin       io.Writer
	framedStdin *semanticIPCWriteCloser
}

func (e *processExit) finishIPCReader() {
	if e == nil || e.ipcReaderDone == nil {
		return
	}
	e.ipcReaderDoneOnce.Do(func() { close(e.ipcReaderDone) })
}

func (e *processExit) markTerminationIntent(intent runtimeProcessTerminationIntent) {
	if e == nil || intent == runtimeProcessTerminationNone {
		return
	}
	e.intentMu.Lock()
	defer e.intentMu.Unlock()
	if e.intent == runtimeProcessTerminationNone {
		e.intent = intent
	}
}

func (e *processExit) terminationIntent() runtimeProcessTerminationIntent {
	if e == nil {
		return runtimeProcessTerminationNone
	}
	e.intentMu.Lock()
	defer e.intentMu.Unlock()
	return e.intent
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
		path:          path,
		executable:    options.RuntimeExecutable,
		executionRoot: options.RuntimeExecutionRoot,
		descriptor:    options.ArtifactIdentity,
		args:          append([]string(nil), options.Args...),
		env:           append([]string(nil), options.Env...),
		dir:           strings.TrimSpace(options.Dir),
		diagnostics:   options.Diagnostics,
		artifacts:     options.Artifacts,

		runtimeLeaseReplays:    options.RuntimeLeaseReplays,
		runtimeLeaseVerifier:   Ed25519RuntimeLeaseVerifier{Keyring: keyring, Now: now},
		runtimeLeaseSigningKey: keyID,
		runtimeLeasePrivateKey: append(ed25519.PrivateKey(nil), privateKey...),
		runtimeLeasePublicKeys: []RuntimeLeasePublicKey{runtimeLeasePublicKey},

		streamSink:            options.StreamSink,
		ioBroker:              options.IOBroker,
		now:                   now,
		handshakeTimeout:      options.HandshakeTimeout,
		heartbeatInterval:     options.HeartbeatInterval,
		maxHeartbeatStaleness: options.MaxHeartbeatStaleness,
		limits:                options.Limits,
		admission:             newRuntimeAdmissionController(options.Limits),
		pending:               map[string]*pendingIPCRequest{},
		pendingInvocations:    map[string]*pendingIPCRequest{},
		compileFlights:        map[string]*pendingCompileFlight{},
		ioRouteSlots:          make(chan struct{}, options.Limits.WorkerCount),
		health: Health{
			ArtifactIdentity: options.ArtifactIdentity,
			Limits:           options.Limits,
		},
	}, nil
}

func validateProcessSupervisorOptions(options ProcessSupervisorOptions, requireHostServices bool) error {
	if (strings.TrimSpace(options.RuntimePath) == "") == (options.RuntimeExecutable == nil) {
		return ErrRuntimePathRequired
	}
	if (options.RuntimeExecutable == nil) != (options.RuntimeExecutionRoot == nil) {
		return ErrRuntimePathRequired
	}
	if options.ArtifactIdentity.PlatformVersion().String() == "" {
		return fmt.Errorf("%w: descriptor is required", ErrRuntimeArtifactIdentityInvalid)
	}
	if err := options.ArtifactIdentity.CompatibleWithPlatform(); err != nil {
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
	if requireHostServices && isNilInterfaceValue(options.IOBroker) {
		return fmt.Errorf("%w: I/O broker is required", ErrRuntimeHostServicesInvalid)
	}
	return nil
}

func DefaultRuntimeLimits() RuntimeLimits {
	workerCount := min(max(runtime.GOMAXPROCS(0), 4), 16)
	return RuntimeLimits{
		WorkerCount:            workerCount,
		QueueCapacity:          min(workerCount*4, RuntimeQueueCapacityMax),
		PerPluginConcurrency:   min(max(workerCount/2, 2), 8),
		ModuleCacheEntries:     64,
		ModuleCacheSourceBytes: RuntimeModuleCacheSourceBytesMax,
	}
}

func ValidateRuntimeLimits(limits RuntimeLimits) error {
	if limits.WorkerCount < RuntimeWorkerCountMin || limits.WorkerCount > RuntimeWorkerCountMax {
		return fmt.Errorf("%w: worker_count must be between %d and %d", ErrRuntimeLimitsInvalid, RuntimeWorkerCountMin, RuntimeWorkerCountMax)
	}
	if limits.QueueCapacity < RuntimeQueueCapacityMin || limits.QueueCapacity > RuntimeQueueCapacityMax {
		return fmt.Errorf("%w: queue_capacity must be between %d and %d", ErrRuntimeLimitsInvalid, RuntimeQueueCapacityMin, RuntimeQueueCapacityMax)
	}
	if limits.PerPluginConcurrency < RuntimePerPluginConcurrencyMin || limits.PerPluginConcurrency > RuntimePerPluginConcurrencyMax {
		return fmt.Errorf("%w: per_plugin_concurrency must be between %d and %d", ErrRuntimeLimitsInvalid, RuntimePerPluginConcurrencyMin, RuntimePerPluginConcurrencyMax)
	}
	if limits.PerPluginConcurrency > limits.WorkerCount {
		return fmt.Errorf("%w: per_plugin_concurrency must not exceed worker_count", ErrRuntimeLimitsInvalid)
	}
	if limits.ModuleCacheEntries < RuntimeModuleCacheEntriesMin || limits.ModuleCacheEntries > RuntimeModuleCacheEntriesMax {
		return fmt.Errorf("%w: module_cache_entries must be between %d and %d", ErrRuntimeLimitsInvalid, RuntimeModuleCacheEntriesMin, RuntimeModuleCacheEntriesMax)
	}
	if limits.ModuleCacheSourceBytes < RuntimeModuleCacheSourceBytesMin || limits.ModuleCacheSourceBytes > RuntimeModuleCacheSourceBytesMax {
		return fmt.Errorf("%w: module_cache_source_bytes must be between %d and %d", ErrRuntimeLimitsInvalid, RuntimeModuleCacheSourceBytesMin, RuntimeModuleCacheSourceBytesMax)
	}
	return nil
}

func (s *ProcessSupervisor) Start(ctx context.Context, target runtimetarget.Target) error {
	if s == nil {
		return ErrRuntimePathRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := runtimetarget.Validate(target); err != nil {
		return err
	}
	if target != s.descriptor.Target() {
		return fmt.Errorf("%w: requested target=%q", ErrRuntimeArtifactIdentityMismatch, target.String())
	}
	s.startMu.Lock()
	defer s.startMu.Unlock()
	s.mu.Lock()
	if s.readyLocked() {
		s.mu.Unlock()
		return nil
	}
	if s.process != nil {
		s.mu.Unlock()
		return ErrRuntimeNotReady
	}
	s.mu.Unlock()
	verifiedPath := s.path
	cleanupVerifiedPath := func() {}
	if s.executable == nil {
		var err error
		verifiedPath, _, cleanupVerifiedPath, err = s.prepareRuntimeExecutable(ctx)
		if err != nil {
			return err
		}
	}
	defer cleanupVerifiedPath()
	s.mu.Lock()
	if s.readyLocked() || s.process != nil {
		s.mu.Unlock()
		return ErrRuntimeNotReady
	}
	s.seq++
	generationID := fmt.Sprintf("runtime_gen_%d_%d", s.now().UnixNano(), s.seq)
	runtimeCtx, cancel := context.WithCancel(context.Background())
	process, err := launchRuntimeProcess(runtimeProcessLaunchOptions{
		context:        runtimeCtx,
		path:           verifiedPath,
		executable:     s.executable,
		executionRoot:  s.executionRoot,
		expectedDigest: s.descriptor.BinarySHA256(),
		args:           s.args,
		env:            s.env,
		dir:            s.dir,
	})
	if err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	stdoutReader := bufio.NewReader(process.ipcOut)
	controlReader := bufio.NewReader(process.controlOut)
	health := Health{
		RuntimeInstanceID:   fmt.Sprintf("runtime_%d", process.pid),
		RuntimeGenerationID: generationID,
		IPCChannelID:        fmt.Sprintf("ipc_%d_%d", process.pid, s.seq),
		ContainmentIdentity: process.containmentIdentity,
		ArtifactIdentity:    s.descriptor,
		Limits:              s.limits,
	}
	exit := &processExit{done: make(chan struct{}), ipcReaderDone: make(chan struct{})}
	s.process = process
	s.cancel = cancel
	s.exit = exit
	semanticStdin := newSemanticIPCWriteCloser(process.ipcIn)
	semanticControlStdin := newSemanticIPCWriteCloser(process.controlIn)
	generation := &runtimeGeneration{id: generationID, ctx: runtimeCtx, stdin: semanticStdin, framedStdin: semanticStdin}
	s.ipcIn = semanticStdin
	s.ipcOut = stdoutReader
	s.controlIn = semanticControlStdin
	s.controlOut = controlReader
	s.controlOutCloser = process.controlOut
	s.generation = generation
	s.health = health
	s.mu.Unlock()

	s.emit("plugin.runtime.process.started", "info", "runtime process started", observability.DiagnosticDetails{
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		OS:                  target.OS(),
		Arch:                target.Arch(),
	})
	if process.diagnosticOut != nil {
		exit.diagnosticReaders.Add(1)
		go s.scanPipe(process.diagnosticOut, "stdout", process, exit, health)
	}
	if process.diagnosticErr != nil {
		exit.diagnosticReaders.Add(1)
		go s.scanPipe(process.diagnosticErr, "stderr", process, exit, health)
	}
	go s.wait(process, exit, cancel, generation, health)

	ack, err := s.performHandshake(ctx, semanticStdin, stdoutReader, health, target, process.containmentRequired)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			exit.markTerminationIntent(runtimeProcessTerminationHandshakeCleanup)
		}
		exit.finishIPCReader()
		cancel()
		_ = process.Kill()
		s.mu.Lock()
		if s.process == process {
			s.health.Ready = false
		}
		s.mu.Unlock()
		select {
		case <-exit.done:
		case <-time.After(3 * time.Second):
			s.emit("plugin.runtime.process.cleanup_timeout", "warning", "runtime process did not exit after failed handshake", observability.DiagnosticDetails{
				RuntimeInstanceID:   health.RuntimeInstanceID,
				RuntimeGenerationID: health.RuntimeGenerationID,
			})
		}
		return err
	}
	s.mu.Lock()
	if s.process == process && runtimeCtx.Err() == nil {
		health.ConnectionNonce = ack.ConnectionNonce
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
	s.emit("plugin.runtime.ipc.handshake", "info", "runtime IPC handshake completed", observability.DiagnosticDetails{
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		RuntimeVersion:      health.ArtifactIdentity.PlatformVersion().String(),
		RuntimeTargetOS:     health.ArtifactIdentity.Target().OS(),
		RuntimeTargetArch:   health.ArtifactIdentity.Target().Arch(),
		RuntimeBinarySHA256: health.ArtifactIdentity.BinarySHA256(),
	})
	go s.heartbeatLoop(runtimeCtx, health)
	return nil
}

func (s *ProcessSupervisor) Preflight(ctx context.Context, target runtimetarget.Target) (RuntimeArtifactIdentity, error) {
	if s == nil {
		return RuntimeArtifactIdentity{}, ErrRuntimePathRequired
	}
	if err := ctx.Err(); err != nil {
		return RuntimeArtifactIdentity{}, err
	}
	if err := runtimetarget.Validate(target); err != nil {
		return RuntimeArtifactIdentity{}, err
	}
	if target != s.descriptor.Target() {
		return RuntimeArtifactIdentity{}, fmt.Errorf("%w: requested target=%q", ErrRuntimeArtifactIdentityMismatch, target.String())
	}
	if err := s.descriptor.CompatibleWithPlatform(); err != nil {
		return RuntimeArtifactIdentity{}, err
	}
	if s.executable != nil {
		if err := verifyRuntimeExecutableFile(ctx, s.executable, s.descriptor.BinarySHA256()); err != nil {
			return RuntimeArtifactIdentity{}, err
		}
	} else if err := verifyRuntimeExecutable(ctx, s.path, s.descriptor.BinarySHA256()); err != nil {
		return RuntimeArtifactIdentity{}, err
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

func (s *ProcessSupervisor) prepareRuntimeExecutable(ctx context.Context) (string, *os.File, func(), error) {
	if s.executable != nil {
		if err := verifyRuntimeExecutableFile(ctx, s.executable, s.descriptor.BinarySHA256()); err != nil {
			return "", nil, nil, err
		}
		inherited, err := duplicateRuntimeExecutableForChild(s.executable)
		if err != nil {
			return "", nil, nil, err
		}
		return "/proc/self/fd/3", inherited, func() { _ = inherited.Close() }, nil
	}
	source, err := openRuntimeExecutable(s.path)
	if err != nil {
		return "", nil, nil, err
	}
	defer source.Close()
	directory, err := os.MkdirTemp("", "redevplugin-runtime-verified-")
	if err != nil {
		return "", nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	verifiedPath := filepath.Join(directory, "redevplugin-runtime")
	destination, err := os.OpenFile(verifiedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return "", nil, nil, err
	}
	hasher := sha256.New()
	if err := copyBoundedRuntimeExecutable(ctx, source, io.MultiWriter(destination, hasher)); err != nil {
		_ = destination.Close()
		cleanup()
		return "", nil, nil, err
	}
	if err := destination.Close(); err != nil {
		cleanup()
		return "", nil, nil, err
	}
	if actual := hex.EncodeToString(hasher.Sum(nil)); actual != s.descriptor.BinarySHA256() {
		cleanup()
		return "", nil, nil, fmt.Errorf("%w: got %s want %s", ErrRuntimeArtifactDigest, actual, s.descriptor.BinarySHA256())
	}
	if err := os.Chmod(verifiedPath, 0o500); err != nil {
		cleanup()
		return "", nil, nil, err
	}
	return verifiedPath, nil, cleanup, nil
}

func verifyRuntimeExecutableFile(ctx context.Context, file *os.File, expectedSHA256 string) error {
	if file == nil {
		return ErrRuntimePathRequired
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxRuntimeExecutableBytes {
		return fmt.Errorf("%w: runtime artifact must be a non-empty regular file no larger than %d bytes", ErrRuntimeArtifactDigest, maxRuntimeExecutableBytes)
	}
	hasher := sha256.New()
	buffer := make([]byte, 128*1024)
	for offset := int64(0); offset < info.Size(); {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := int64(len(buffer))
		if remaining := info.Size() - offset; remaining < chunk {
			chunk = remaining
		}
		read, err := file.ReadAt(buffer[:chunk], offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if read == 0 {
			return io.ErrUnexpectedEOF
		}
		_, _ = hasher.Write(buffer[:read])
		offset += int64(read)
	}
	if actual := hex.EncodeToString(hasher.Sum(nil)); actual != expectedSHA256 {
		return fmt.Errorf("%w: got %s want %s", ErrRuntimeArtifactDigest, actual, expectedSHA256)
	}
	return nil
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
	process := s.process
	health := s.health
	if cancel == nil || exit == nil {
		s.mu.Unlock()
		return nil
	}
	s.health.Ready = false
	exit.markTerminationIntent(runtimeProcessTerminationStop)
	cancel()
	s.mu.Unlock()
	if process != nil {
		_ = process.Kill()
	}

	select {
	case <-exit.done:
		exit.stopEvent.Do(func() {
			details := observability.DiagnosticDetails{
				RuntimeInstanceID:   health.RuntimeInstanceID,
				RuntimeGenerationID: health.RuntimeGenerationID,
			}
			s.emitInternal("plugin.runtime.process.stopped", observability.DiagnosticSeverityInfo, "runtime process stopped", details, observability.Failure{})
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
	result, err := decodeHeartbeatResponse(frame)
	if err != nil {
		return HeartbeatResult{}, err
	}
	s.mu.Lock()
	if s.health.Ready && s.health.RuntimeGenerationID == result.RuntimeGenerationID {
		s.health.ActiveInvocations = result.ActiveInvocations
		s.health.QueuedInvocations = result.QueuedInvocations
		s.health.ModuleCache = result.ModuleCache
	}
	s.mu.Unlock()
	return result, nil
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
		s.emit("plugin.runtime.lease.signature_rejected", observability.DiagnosticSeverityWarning, "runtime execution lease signature was rejected", observability.DiagnosticDetails{
			PluginInstanceID:    lease.PluginInstanceID,
			RuntimeGenerationID: lease.RuntimeGenerationID,
			RuntimeInstanceID:   lease.RuntimeInstanceID,
			Method:              method,
			RevokeEpoch:         lease.RevokeEpoch,
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

func (s *ProcessSupervisor) PrewarmWorker(ctx context.Context, req PrewarmWorkerRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.isReady() {
		return ErrRuntimeNotReady
	}
	if err := validatePrewarmWorkerRequest(req); err != nil {
		return err
	}
	health := s.healthSnapshot()
	invocation, err := json.Marshal(map[string]any{
		"plugin_instance_id":    req.PluginInstanceID,
		"runtime_generation_id": health.RuntimeGenerationID,
		"package_hash":          req.Artifact.PackageHash,
		"worker_id":             req.WorkerID,
		"worker_mode":           "job",
		"worker_scope":          "environment",
		"artifact":              req.Artifact.Artifact,
		"artifact_sha256":       req.Artifact.ArtifactSHA256,
		"method":                "platform.prewarm",
	})
	if err != nil {
		return err
	}
	rawPayload, err := json.Marshal(invokeWorkerRequestPayload{
		Prewarm:    true,
		Method:     "platform.prewarm",
		Invocation: invocation,
	})
	if err != nil {
		return err
	}
	frame, err := s.callIPC(ctx, ipcFrameTypeInvokeWorker, ipcFrameTypeInvokeWorkerResult, rawPayload, &workerInvocationContext{
		Artifact: req.Artifact,
		Prewarm:  true,
	})
	if err != nil {
		return err
	}
	response, err := decodeRuntimeResponse(frame)
	if err != nil {
		return err
	}
	if !response.OK {
		return response.workerExecutionError()
	}
	return nil
}

func validatePrewarmWorkerRequest(req PrewarmWorkerRequest) error {
	if strings.TrimSpace(req.PluginInstanceID) == "" || strings.TrimSpace(req.WorkerID) == "" {
		return fmt.Errorf("%w: prewarm worker identity is required", ErrRuntimeRequestFailed)
	}
	if !isSHA256Ref(req.Artifact.PackageHash) || !isSHA256Ref(req.Artifact.ArtifactSHA256) || !isWorkerArtifactPath(req.Artifact.Artifact) {
		return fmt.Errorf("%w: prewarm artifact identity is invalid", ErrRuntimeRequestFailed)
	}
	return nil
}

func (s *ProcessSupervisor) Revoke(ctx context.Context, req RevokeRequest) (RevokeResult, error) {
	if err := ctx.Err(); err != nil {
		return RevokeResult{}, err
	}
	if s == nil || !s.isReady() {
		return RevokeResult{}, ErrRuntimeNotReady
	}
	if err := validateRevokeRequest(req); err != nil {
		return RevokeResult{}, err
	}
	rawPayload, err := json.Marshal(revokeEpochRequestPayload(req))
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
	return decodeRevokeResult(response.Result, req)
}

func (s *ProcessSupervisor) RevokeSession(ctx context.Context, req SessionRevokeRequest) (SessionRevokeShardResult, error) {
	if err := ctx.Err(); err != nil {
		return SessionRevokeShardResult{}, err
	}
	if s == nil || !s.isReady() {
		return SessionRevokeShardResult{}, ErrRuntimeNotReady
	}
	if err := validateSessionRevokeRequest(req); err != nil {
		return SessionRevokeShardResult{}, err
	}
	rawPayload, err := json.Marshal(sessionRevokeRequestPayload{
		SessionRevokeSequence: req.SessionRevokeSequence,
		OwnerSessionHash:      req.SessionScope.OwnerSessionHash, OwnerUserHash: req.SessionScope.OwnerUserHash,
		OwnerEnvHash: req.SessionScope.OwnerEnvHash, SessionChannelIDHash: req.SessionScope.SessionChannelIDHash,
	})
	if err != nil {
		return SessionRevokeShardResult{}, err
	}
	frame, err := s.callControlIPC(ctx, ipcFrameTypeSessionRevoke, ipcFrameTypeSessionRevokeAck, rawPayload)
	if err != nil {
		return SessionRevokeShardResult{}, err
	}
	response, err := decodeRuntimeResponse(frame)
	if err != nil {
		return SessionRevokeShardResult{}, err
	}
	if !response.OK {
		return SessionRevokeShardResult{}, response.err()
	}
	if len(response.Result) == 0 {
		return SessionRevokeShardResult{}, fmt.Errorf("%w: session revoke ack missing result", ErrRuntimeRequestFailed)
	}
	return decodeSessionRevokeResult(response.Result, frame.RuntimeGenerationID, req)
}

func validateSessionRevokeRequest(req SessionRevokeRequest) error {
	if err := req.SessionScope.Validate(); err != nil || req.SessionRevokeSequence == 0 || req.SessionRevokeSequence > jsonvalue.MaxSafeInteger {
		return fmt.Errorf("%w: session revoke scope and sequence are invalid", ErrRuntimeRequestFailed)
	}
	return nil
}

func validateRevokeRequest(req RevokeRequest) error {
	if req.ResourceScope.Kind != sessionctx.ScopeEnvironment || req.ResourceScope.Validate() != nil {
		return fmt.Errorf("%w: revoke resource scope must be an environment scope", ErrRuntimeRequestFailed)
	}
	if strings.TrimSpace(req.PluginInstanceID) == "" || req.RevokeEpoch == 0 {
		return fmt.Errorf("%w: revoke plugin_instance_id and revoke_epoch are required", ErrRuntimeRequestFailed)
	}
	return nil
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
		s.emit("plugin.runtime.lease.replayed", observability.DiagnosticSeverityWarning, "runtime execution lease was already consumed", observability.DiagnosticDetails{
			PluginInstanceID:    lease.PluginInstanceID,
			RuntimeGenerationID: lease.RuntimeGenerationID,
			Method:              method,
			RevokeEpoch:         lease.RevokeEpoch,
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
	s.emit("plugin.runtime.lease.signature_rejected", observability.DiagnosticSeverityWarning, "runtime execution lease signature was rejected", observability.DiagnosticDetails{
		PluginInstanceID:    lease.PluginInstanceID,
		RuntimeGenerationID: lease.RuntimeGenerationID,
		RuntimeInstanceID:   lease.RuntimeInstanceID,
		Method:              method,
		RevokeEpoch:         lease.RevokeEpoch,
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
	ResourceScope            sessionctx.ResourceScope `json:"resource_scope"`
	PluginInstanceID         string                   `json:"plugin_instance_id"`
	RevokeEpoch              *uint64                  `json:"revoke_epoch"`
	ClosedSocketCount        *int                     `json:"closed_socket_count"`
	ClosedStreamCount        *int                     `json:"closed_stream_count"`
	ClosedStorageHandleCount *int                     `json:"closed_storage_handle_count"`
}

func decodeRevokeResult(raw json.RawMessage, request RevokeRequest) (RevokeResult, error) {
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
		ResourceScope:            payload.ResourceScope,
		PluginInstanceID:         payload.PluginInstanceID,
		RevokeEpoch:              *payload.RevokeEpoch,
		ClosedSocketCount:        *payload.ClosedSocketCount,
		ClosedStreamCount:        *payload.ClosedStreamCount,
		ClosedStorageHandleCount: *payload.ClosedStorageHandleCount,
	}
	if err := validateRevokeResult(result, request); err != nil {
		return RevokeResult{}, err
	}
	return result, nil
}

func validateRevokeResult(result RevokeResult, request RevokeRequest) error {
	if !result.ResourceScope.Matches(request.ResourceScope) {
		return fmt.Errorf("%w: revoke ack resource_scope mismatch", ErrRuntimeRequestFailed)
	}
	if result.PluginInstanceID != request.PluginInstanceID {
		return fmt.Errorf("%w: revoke ack plugin_instance_id mismatch", ErrRuntimeRequestFailed)
	}
	if result.RevokeEpoch != request.RevokeEpoch {
		return fmt.Errorf("%w: revoke ack revoke_epoch mismatch", ErrRuntimeRequestFailed)
	}
	if result.ClosedSocketCount < 0 || result.ClosedStreamCount < 0 || result.ClosedStorageHandleCount < 0 {
		return fmt.Errorf("%w: revoke ack close counters must be non-negative", ErrRuntimeRequestFailed)
	}
	return nil
}

type sessionRevokeResultPayload struct {
	SessionRevokeSequence *uint64              `json:"session_revoke_sequence"`
	State                 SessionRevokeState   `json:"state"`
	Counts                *SessionRevokeCounts `json:"counts"`
}

func decodeSessionRevokeResult(raw json.RawMessage, runtimeGenerationID string, request SessionRevokeRequest) (SessionRevokeShardResult, error) {
	var payload sessionRevokeResultPayload
	if err := decodeStrictJSON(raw, &payload); err != nil {
		return SessionRevokeShardResult{}, fmt.Errorf("%w: decode session revoke ack: %v", ErrRuntimeRequestFailed, err)
	}
	if payload.SessionRevokeSequence == nil || payload.Counts == nil || payload.State == "" {
		return SessionRevokeShardResult{}, fmt.Errorf("%w: session revoke ack result missing required field", ErrRuntimeRequestFailed)
	}
	if *payload.SessionRevokeSequence != request.SessionRevokeSequence {
		return SessionRevokeShardResult{}, fmt.Errorf("%w: session revoke ack sequence mismatch", ErrRuntimeRequestFailed)
	}
	if payload.State != SessionRevokeStateComplete {
		return SessionRevokeShardResult{}, fmt.Errorf("%w: session revoke ack state is invalid", ErrRuntimeRequestFailed)
	}
	if strings.TrimSpace(runtimeGenerationID) == "" {
		return SessionRevokeShardResult{}, fmt.Errorf("%w: session revoke ack runtime generation is missing", ErrRuntimeRequestFailed)
	}
	if !validSessionRevokeCounts(*payload.Counts) {
		return SessionRevokeShardResult{}, fmt.Errorf("%w: session revoke ack count exceeds JSON safe integer", ErrRuntimeRequestFailed)
	}
	return SessionRevokeShardResult{
		RuntimeGenerationID: runtimeGenerationID,
		State:               payload.State,
		Counts:              *payload.Counts,
	}, nil
}

func validSessionRevokeCounts(counts SessionRevokeCounts) bool {
	return counts.QueuedInvocations <= jsonvalue.MaxSafeInteger &&
		counts.RunningInvocations <= jsonvalue.MaxSafeInteger &&
		counts.StorageHostcalls <= jsonvalue.MaxSafeInteger &&
		counts.ActiveNetworkRequests <= jsonvalue.MaxSafeInteger &&
		counts.Sockets <= jsonvalue.MaxSafeInteger &&
		counts.NetworkStreams <= jsonvalue.MaxSafeInteger
}

func (s *ProcessSupervisor) isReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readyLocked()
}

func (s *ProcessSupervisor) readyLocked() bool {
	return s.process != nil && s.health.Ready
}

func (s *ProcessSupervisor) wait(process *runtimeProcess, exit *processExit, cancel context.CancelFunc, generation *runtimeGeneration, health Health) {
	err := process.Wait()
	cancel()
	<-exit.ipcReaderDone
	exit.diagnosticReaders.Wait()
	var controlIn io.WriteCloser
	var controlOut io.Closer
	s.mu.Lock()
	if s.process == process {
		s.health.Ready = false
		s.cancel = nil
		s.exit = nil
		s.process = nil
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
	s.failPendingGeneration(generation, fmt.Errorf("%w: runtime generation exited", ErrRuntimeIPCUnavailable))
	if controlIn != nil {
		_ = controlIn.Close()
	}
	if controlOut != nil {
		_ = controlOut.Close()
	}
	failureCode := classifyRuntimeProcessExit(err, exit.terminationIntent())
	severity := observability.DiagnosticSeverityInfo
	message := "runtime process exited"
	details := observability.DiagnosticDetails{
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
	}
	var failure observability.Failure
	if failureCode != "" {
		severity = observability.DiagnosticSeverityWarning
		message = "runtime process exited with error"
		details.RuntimeProcessFailureCode = failureCode
		failure = observability.Failure{
			Code:      observability.FailureAction,
			Component: observability.FailureComponentRuntime,
			Operation: observability.FailureOperationRuntimeProcessExit,
		}
	}
	s.emitInternal("plugin.runtime.process.exited", severity, message, details, failure)
	close(exit.done)
}

func classifyRuntimeProcessExit(err error, intent runtimeProcessTerminationIntent) observability.RuntimeProcessFailureCode {
	code := runtimeProcessFailureCodeFromWaitError(err)
	if intent != runtimeProcessTerminationNone &&
		(code == observability.RuntimeProcessExitUnexpected || code == observability.RuntimeProcessSignalled) {
		return ""
	}
	return code
}

func runtimeProcessFailureCodeFromWaitError(err error) observability.RuntimeProcessFailureCode {
	if err == nil {
		return observability.RuntimeProcessExitUnexpected
	}
	var exitErr interface{ ExitCode() int }
	if !errors.As(err, &exitErr) {
		return observability.RuntimeProcessExitUnrecognized
	}
	exitCode := exitErr.ExitCode()
	if exitCode == -1 {
		return observability.RuntimeProcessSignalled
	}
	for _, failure := range runtimeProcessExitFailureContract {
		if failure.ExitCode == exitCode {
			return failure.Code
		}
	}
	return observability.RuntimeProcessExitUnrecognized
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
		s.invalidateRuntimeAfterIPCFailure(health, err)
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

func (s *ProcessSupervisor) scanPipe(reader io.ReadCloser, streamName string, process *runtimeProcess, exit *processExit, health Health) {
	defer exit.diagnosticReaders.Done()
	defer reader.Close()
	const (
		bufferBytes     = 16 << 10
		bytesPerSecond  = 1 << 20
		burstBytes      = 4 << 20
		generationBytes = 64 << 20
	)
	buffer := make([]byte, bufferBytes)
	available := int64(burstBytes)
	lastRefill := time.Now()
	for {
		read, err := reader.Read(buffer)
		if read > 0 {
			now := time.Now()
			refill := now.Sub(lastRefill).Nanoseconds() * bytesPerSecond / int64(time.Second)
			if refill > 0 {
				available = min(int64(burstBytes), available+refill)
				lastRefill = now
			}
			allowed := int64(read) <= available
			if allowed {
				available -= int64(read)
				exit.diagnosticMu.Lock()
				if exit.diagnosticBytes > generationBytes-int64(read) {
					allowed = false
				} else {
					exit.diagnosticBytes += int64(read)
				}
				exit.diagnosticMu.Unlock()
			}
			if !allowed {
				exit.markTerminationIntent(runtimeProcessTerminationIPCInvalidation)
				_ = process.Kill()
				s.emitInternal(
					"plugin.runtime.process."+streamName+".limit",
					observability.DiagnosticSeverityWarning,
					"runtime process diagnostic output exceeded the closed limit",
					observability.DiagnosticDetails{RuntimeInstanceID: health.RuntimeInstanceID, RuntimeGenerationID: health.RuntimeGenerationID, Stream: streamName},
					observability.Failure{Code: observability.FailureAction, Component: observability.FailureComponentRuntime, Operation: observability.FailureOperationRuntimeProcessOutput},
				)
				return
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			if exit.terminationIntent() == runtimeProcessTerminationNone && process.Alive() {
				exit.markTerminationIntent(runtimeProcessTerminationIPCInvalidation)
				_ = process.Kill()
				s.emitInternal(
					"plugin.runtime.process."+streamName+".premature_eof",
					observability.DiagnosticSeverityWarning,
					"runtime process diagnostic output closed while the process was running",
					observability.DiagnosticDetails{RuntimeInstanceID: health.RuntimeInstanceID, RuntimeGenerationID: health.RuntimeGenerationID, Stream: streamName},
					observability.Failure{Code: observability.FailureAction, Component: observability.FailureComponentRuntime, Operation: observability.FailureOperationRuntimeProcessOutput},
				)
			}
			return
		}
		exit.markTerminationIntent(runtimeProcessTerminationIPCInvalidation)
		_ = process.Kill()
		s.emitInternal(
			"plugin.runtime.process."+streamName+".error",
			observability.DiagnosticSeverityWarning,
			"runtime process diagnostic output could not be drained",
			observability.DiagnosticDetails{RuntimeInstanceID: health.RuntimeInstanceID, RuntimeGenerationID: health.RuntimeGenerationID, Stream: streamName},
			observability.Failure{Code: observability.FailureAction, Component: observability.FailureComponentRuntime, Operation: observability.FailureOperationRuntimeProcessOutput},
		)
		return
	}
}

func (s *ProcessSupervisor) emit(eventType string, severity observability.DiagnosticSeverity, message string, details observability.DiagnosticDetails) {
	s.emitInternal(eventType, severity, message, details, observability.Failure{})
}

func (s *ProcessSupervisor) emitInternal(eventType string, severity observability.DiagnosticSeverity, message string, details observability.DiagnosticDetails, failure observability.Failure) {
	if s == nil || s.diagnostics == nil {
		return
	}
	_ = s.diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type:       eventType,
		Severity:   severity,
		Message:    message,
		OccurredAt: s.now(),
		Details:    details,
		Failure:    failure,
	})
}

func (s *ProcessSupervisor) emitHostcallFailure(requestID, correlationID, runtimeGenerationID, hostcall, code string, err error, details observability.DiagnosticDetails) {
	if err == nil {
		return
	}
	details.RuntimeGenerationID = runtimeGenerationID
	details.Hostcall = hostcall
	details.Code = code
	if s == nil || s.diagnostics == nil {
		return
	}
	_ = s.diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type:          "plugin.runtime.hostcall.failed",
		Severity:      "warning",
		Message:       "runtime hostcall failed",
		OccurredAt:    s.now(),
		RequestID:     requestID,
		CorrelationID: correlationID,
		Details:       details,
		Failure: observability.FailureFromError(
			observability.FailureAction,
			observability.FailureComponentRuntime,
			observability.FailureOperationRuntimeHostcall,
			err,
		),
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

	ipcFrameTypeRevokeEpoch      = "revoke_epoch"
	ipcFrameTypeRevokeEpochAck   = "revoke_epoch_ack"
	ipcFrameTypeSessionRevoke    = "session_revoke"
	ipcFrameTypeSessionRevokeAck = "session_revoke_ack"
)

const (
	defaultRuntimeHostcallTimeout  = 30 * time.Second
	maxRuntimeHostcallTimeout      = 30 * time.Second
	defaultRuntimeCancelAckTimeout = 5 * time.Second
	maxIPCFrameBytes               = 64 << 20
)

type ipcFrame struct {
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	ParentRequestID     string          `json:"parent_request_id,omitempty"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type helloRequestPayload struct {
	InternalWire           uint16                  `json:"internal_wire"`
	PlatformVersion        string                  `json:"platform_version"`
	RuntimeArtifactSHA256  string                  `json:"runtime_artifact_sha256"`
	ConnectionNonce        string                  `json:"connection_nonce"`
	Target                 string                  `json:"target"`
	HostProcessID          int                     `json:"host_process_id"`
	StartedUnixNano        int64                   `json:"started_unix_nano"`
	RuntimeLeasePublicKeys []RuntimeLeasePublicKey `json:"runtime_lease_public_keys"`
	Limits                 RuntimeLimits           `json:"limits"`
}

type helloAckPayload struct {
	InternalWire          uint16                      `json:"internal_wire"`
	PlatformVersion       string                      `json:"platform_version"`
	RuntimeArtifactSHA256 string                      `json:"runtime_artifact_sha256"`
	ConnectionNonce       string                      `json:"connection_nonce"`
	ActualTarget          string                      `json:"actual_target"`
	Limits                RuntimeLimits               `json:"limits"`
	ProcessContainment    *processContainmentEvidence `json:"process_containment,omitempty"`
}

type processContainmentEvidence struct {
	SchemaVersion         string `json:"schema_version"`
	Profile               string `json:"profile"`
	SeccompPolicySHA256   string `json:"seccomp_policy_sha256"`
	NoNewPrivileges       bool   `json:"no_new_privs"`
	SeccompTSync          bool   `json:"seccomp_tsync"`
	ProcessCreationDenied bool   `json:"process_creation_denied"`
	ReexecDenied          bool   `json:"reexec_denied"`
	Active                bool   `json:"active"`
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
	Prewarm    bool            `json:"prewarm,omitempty"`
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
	ResourceScope    sessionctx.ResourceScope `json:"resource_scope"`
	PluginInstanceID string                   `json:"plugin_instance_id"`
	RevokeEpoch      uint64                   `json:"revoke_epoch"`
}

type sessionRevokeRequestPayload struct {
	SessionRevokeSequence uint64 `json:"session_revoke_sequence"`
	OwnerSessionHash      string `json:"owner_session_hash"`
	OwnerUserHash         string `json:"owner_user_hash"`
	OwnerEnvHash          string `json:"owner_env_hash"`
	SessionChannelIDHash  string `json:"session_channel_id_hash"`
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

func (s *ProcessSupervisor) performHandshake(ctx context.Context, stdin io.Writer, stdout *bufio.Reader, health Health, target runtimetarget.Target, containmentRequired bool) (helloAckPayload, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, s.handshakeTimeout)
	defer cancel()
	requestID := health.RuntimeGenerationID + ":hello"
	channelNonce, err := randomIPCChannelNonce()
	if err != nil {
		return helloAckPayload{}, err
	}
	targetPayload, err := runtimeAdmissionTargetString(target)
	if err != nil {
		return helloAckPayload{}, err
	}
	payload, err := json.Marshal(helloRequestPayload{
		InternalWire:           InternalWire,
		PlatformVersion:        health.ArtifactIdentity.PlatformVersion().String(),
		RuntimeArtifactSHA256:  health.ArtifactIdentity.BinarySHA256(),
		ConnectionNonce:        channelNonce,
		Target:                 targetPayload,
		HostProcessID:          os.Getpid(),
		StartedUnixNano:        s.now().UnixNano(),
		RuntimeLeasePublicKeys: append([]RuntimeLeasePublicKey(nil), s.runtimeLeasePublicKeys...),
		Limits:                 s.limits,
	})
	if err != nil {
		return helloAckPayload{}, err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
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
			return helloAckPayload{}, fmt.Errorf("%w: read hello ack: %w", ErrRuntimeHandshake, got.err)
		}
		return validateHelloAck(requestID, health.RuntimeGenerationID, channelNonce, s.descriptor, s.limits, got.frame, containmentRequired)
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
		s.invalidateRuntimeAfterIPCFailure(health, ctx.Err())
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
		invocationID := strings.TrimSpace(allowedInvocation.InvocationID)
		if !allowedInvocation.Prewarm && (invocationID == "" || s.pendingInvocations[invocationID] != nil) {
			s.pendingMu.Unlock()
			return ipcFrame{}, fmt.Errorf("%w: duplicate or empty invocation_id", ErrRuntimeIPCUnavailable)
		}
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
		}
		s.compileFlights[artifactRequestID] = compileFlight
		if !allowedInvocation.Prewarm {
			s.pendingInvocations[invocationID] = pending
		}
	}
	s.pending[requestID] = pending
	s.pendingMu.Unlock()
	unregister := func() {
		s.pendingMu.Lock()
		if s.pending[requestID] == pending {
			delete(s.pending, requestID)
		}
		if allowedInvocation != nil && !allowedInvocation.Prewarm && s.pendingInvocations[allowedInvocation.InvocationID] == pending {
			delete(s.pendingInvocations, allowedInvocation.InvocationID)
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
			s.invalidateRuntimeAfterIPCFailure(health, cancelErr)
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
		framed, err := ReadIPCFrame(stdout)
		if err != nil {
			wrapped := fmt.Errorf("%w: read ipc frame: %v", ErrRuntimeIPCUnavailable, err)
			if errors.Is(err, io.EOF) {
				s.invalidateRuntimeAfterProcessExit(health, wrapped)
				s.failPendingGeneration(generation, wrapped)
			} else {
				s.invalidateAndFailPending(generation, health, wrapped)
			}
			return
		}
		if isRuntimeIORequestFrame(framed.Type) || isRuntimeIOControlRequestFrame(framed) {
			if err := s.dispatchRuntimeIOFrame(generation, framed); err != nil {
				s.invalidateAndFailPending(generation, health, err)
				return
			}
			continue
		}
		frame, err := readRuntimeSemanticIPCFrame(stdout, framed)
		if err != nil {
			s.invalidateAndFailPending(generation, health, fmt.Errorf("%w: read semantic ipc frame: %v", ErrRuntimeIPCUnavailable, err))
			return
		}
		if frame.RuntimeGenerationID != health.RuntimeGenerationID {
			err := fmt.Errorf("%w: invalid runtime frame identity", ErrRuntimeIPCUnavailable)
			s.invalidateAndFailPending(generation, health, err)
			return
		}
		switch frame.FrameType {
		case ipcFrameTypeCompileFlightRegister:
			if err := s.registerCompileFlight(generation, frame); err != nil {
				s.invalidateAndFailPending(generation, health, err)
				return
			}
			continue
		case ipcFrameTypeCompileFlightComplete:
			if err := s.completeCompileFlight(generation, frame); err != nil {
				s.invalidateAndFailPending(generation, health, err)
				return
			}
			continue
		case ipcFrameTypeOpenHandle:
			flight, ok := s.claimCompileFlightArtifact(generation, frame)
			if !ok {
				err := fmt.Errorf("%w: runtime artifact request is not bound to a registered compile flight", ErrRuntimeIPCUnavailable)
				s.invalidateAndFailPending(generation, health, err)
				return
			}
			s.dispatchCompileFlightArtifact(generation, health, frame, flight)
			continue
		case ipcFrameTypeInvokeWorkerResult:
			s.removeUnregisteredCompileFlightIntent(generation, frame.RequestID)
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

func (s *ProcessSupervisor) invalidateAndFailPending(generation *runtimeGeneration, health Health, err error) {
	s.invalidateRuntimeAfterIPCFailure(health, err)
	s.failPendingGeneration(generation, err)
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
		payload.ArtifactRequestID != flight.artifactRequestID ||
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
		payload.ArtifactRequestID != flight.artifactRequestID || payload.PackageHash != flight.artifact.PackageHash ||
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
			s.invalidateRuntimeAfterIPCFailure(health, err)
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
		if request.invocation != nil && s.pendingInvocations[request.invocation.InvocationID] == request {
			delete(s.pendingInvocations, request.invocation.InvocationID)
		}
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

func (s *ProcessSupervisor) invalidateRuntimeAfterIPCFailure(health Health, err error) {
	s.invalidateRuntime(health, err, true)
}

func (s *ProcessSupervisor) invalidateRuntimeAfterProcessExit(health Health, err error) {
	s.invalidateRuntime(health, err, false)
}

func (s *ProcessSupervisor) invalidateRuntime(health Health, err error, markTerminationIntent bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.health.RuntimeGenerationID != health.RuntimeGenerationID || s.process == nil {
		s.mu.Unlock()
		return
	}
	cancel := s.cancel
	process := s.process
	exit := s.exit
	s.health.Ready = false
	if markTerminationIntent {
		exit.markTerminationIntent(runtimeProcessTerminationIPCInvalidation)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if process != nil {
		_ = process.Kill()
	}
	details := observability.DiagnosticDetails{
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
	}
	var failure observability.Failure
	if err != nil {
		failure = observability.FailureFromError(
			observability.FailureAction,
			observability.FailureComponentRuntime,
			observability.FailureOperationRuntimeIPCInvalidate,
			err,
		)
	}
	s.emitInternal("plugin.runtime.ipc.invalidated", observability.DiagnosticSeverityWarning, "runtime IPC channel was invalidated", details, failure)
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
		s.emitHostcallFailure(frame.RequestID, frame.ParentRequestID, runtimeGenerationID, "artifact", "ARTIFACT_READ_FAILED", err, observability.DiagnosticDetails{
			PackageHash: req.PackageHash,
			Artifact:    req.Artifact,
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
		ExecutionID          string          `json:"execution_id"`
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
		{name: "execution_id", lease: lease.ExecutionID, invocation: envelope.ExecutionID},
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
		InvocationID: strings.TrimSpace(lease.InvocationID),
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
	return readSemanticIPCFrame(reader)
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

func writeIPCResponseFrame(stdin io.Writer, frameType string, runtimeGenerationID string, request ipcFrame, payload []byte) error {
	return json.NewEncoder(stdin).Encode(ipcFrame{
		FrameType:           frameType,
		RequestID:           request.RequestID,
		ParentRequestID:     request.ParentRequestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             payload,
	})
}

func validateIPCResponse(requestID string, runtimeGenerationID string, responseFrameType string, frame ipcFrame) error {
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

func validateHelloAck(requestID string, runtimeGenerationID string, channelNonce string, expectedDescriptor RuntimeArtifactIdentity, expectedLimits RuntimeLimits, frame ipcFrame, containmentRequired ...bool) (helloAckPayload, error) {
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
	if ack.InternalWire != InternalWire {
		return helloAckPayload{}, fmt.Errorf("%w: internal_wire %d", ErrRuntimeHandshake, ack.InternalWire)
	}
	runtimeVersion, err := version.ParseSemVer(ack.PlatformVersion)
	if err != nil {
		return helloAckPayload{}, fmt.Errorf("%w: platform version: %v", ErrRuntimeHandshake, err)
	}
	actualTarget, err := parseRuntimeAdmissionTarget(ack.ActualTarget)
	if err != nil {
		return helloAckPayload{}, fmt.Errorf("%w: actual_target: %v", ErrRuntimeHandshake, err)
	}
	if runtimeVersion != expectedDescriptor.PlatformVersion() || actualTarget != expectedDescriptor.Target() || ack.RuntimeArtifactSHA256 != expectedDescriptor.BinarySHA256() {
		return helloAckPayload{}, fmt.Errorf(
			"%w: %w: platform=%q target=%s artifact=%q",
			ErrRuntimeHandshake,
			ErrRuntimeArtifactIdentityMismatch,
			ack.PlatformVersion,
			ack.ActualTarget,
			ack.RuntimeArtifactSHA256,
		)
	}
	if ack.ConnectionNonce != channelNonce {
		return helloAckPayload{}, fmt.Errorf("%w: connection_nonce mismatch", ErrRuntimeHandshake)
	}
	if ack.Limits != expectedLimits {
		return helloAckPayload{}, fmt.Errorf("%w: runtime limits mismatch", ErrRuntimeHandshake)
	}
	requireContainment := len(containmentRequired) != 0 && containmentRequired[0]
	if requireContainment && ack.ProcessContainment == nil {
		return helloAckPayload{}, fmt.Errorf("%w: process containment evidence is missing", ErrRuntimeHandshake)
	}
	if ack.ProcessContainment != nil {
		containment := ack.ProcessContainment
		if containment.SchemaVersion != "redevplugin.process_containment.v1" ||
			containment.Profile != runtimeContainmentProfile ||
			containment.SeccompPolicySHA256 != runtimeContainmentPolicySHA ||
			!containment.NoNewPrivileges ||
			!containment.SeccompTSync ||
			!containment.ProcessCreationDenied ||
			!containment.ReexecDenied ||
			!containment.Active {
			return helloAckPayload{}, fmt.Errorf("%w: process containment evidence is invalid", ErrRuntimeHandshake)
		}
	}
	return ack, nil
}
