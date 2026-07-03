package runtimeclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/version"
)

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Lease struct {
	LeaseID             string    `json:"lease_id"`
	LeaseToken          string    `json:"lease_token"`
	LeaseNonce          string    `json:"lease_nonce"`
	RuntimeGenerationID string    `json:"runtime_generation_id"`
	PluginInstanceID    string    `json:"plugin_instance_id"`
	PolicyRevision      uint64    `json:"policy_revision"`
	ManagementRevision  uint64    `json:"management_revision"`
	RevokeEpoch         uint64    `json:"revoke_epoch"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type Health struct {
	RuntimeInstanceID   string `json:"runtime_instance_id"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	RuntimeVersion      string `json:"runtime_version,omitempty"`
	RustIPCVersion      string `json:"rust_ipc_version,omitempty"`
	WASMABIVersion      string `json:"wasm_abi_version,omitempty"`
	Ready               bool   `json:"ready"`
}

type RevokeResult struct {
	PluginInstanceID         string `json:"plugin_instance_id"`
	RevokeEpoch              uint64 `json:"revoke_epoch"`
	ClosedActorCount         int    `json:"closed_actor_count"`
	ClosedSocketCount        int    `json:"closed_socket_count"`
	ClosedStreamCount        int    `json:"closed_stream_count"`
	ClosedStorageHandleCount int    `json:"closed_storage_handle_count"`
}

type HeartbeatResult struct {
	RuntimeGenerationID  string `json:"runtime_generation_id"`
	RuntimeUnixNano      int64  `json:"runtime_unix_nano"`
	MaxStalenessMillis   int64  `json:"max_staleness_ms"`
	HostSentUnixNanoEcho int64  `json:"host_sent_unix_nano"`
}

type Supervisor interface {
	Start(ctx context.Context, target Target) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) (Health, error)
	Heartbeat(ctx context.Context) (HeartbeatResult, error)
	InvokeWorker(ctx context.Context, lease Lease, method string, payload []byte) ([]byte, error)
	Revoke(ctx context.Context, pluginInstanceID string, revokeEpoch uint64) (RevokeResult, error)
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
)

type ProcessSupervisorOptions struct {
	RuntimePath           string
	Args                  []string
	Env                   []string
	Dir                   string
	Diagnostics           observability.DiagnosticsSink
	Artifacts             ArtifactProvider
	HandleGrants          HandleGrantValidator
	StorageFiles          storage.FilesBroker
	StorageKV             storage.KVBroker
	StorageSQLite         storage.SQLiteBroker
	Connectivity          connectivity.Broker
	NetworkExecutor       connectivity.NetworkExecutor
	Now                   func() time.Time
	HandshakeTimeout      time.Duration
	HeartbeatInterval     time.Duration
	MaxHeartbeatStaleness time.Duration
}

type ProcessSupervisor struct {
	startMu               sync.Mutex
	ipcMu                 sync.Mutex
	mu                    sync.Mutex
	path                  string
	args                  []string
	env                   []string
	dir                   string
	diagnostics           observability.DiagnosticsSink
	artifacts             ArtifactProvider
	handleGrants          HandleGrantValidator
	storageFiles          storage.FilesBroker
	storageKV             storage.KVBroker
	storageSQLite         storage.SQLiteBroker
	connectivity          connectivity.Broker
	networkExecutor       connectivity.NetworkExecutor
	now                   func() time.Time
	handshakeTimeout      time.Duration
	heartbeatInterval     time.Duration
	maxHeartbeatStaleness time.Duration
	seq                   uint64
	requestSeq            uint64

	cmd       *exec.Cmd
	cancel    context.CancelFunc
	done      chan error
	ipcIn     io.WriteCloser
	ipcOut    *bufio.Reader
	health    Health
	exitError error
}

func NewProcessSupervisor(options ProcessSupervisorOptions) (*ProcessSupervisor, error) {
	path := strings.TrimSpace(options.RuntimePath)
	if path == "" {
		return nil, ErrRuntimePathRequired
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	handshakeTimeout := options.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 5 * time.Second
	}
	heartbeatInterval := options.HeartbeatInterval
	if heartbeatInterval <= 0 {
		heartbeatInterval = defaultRuntimeHeartbeatInterval
	}
	maxHeartbeatStaleness := options.MaxHeartbeatStaleness
	if maxHeartbeatStaleness <= 0 {
		maxHeartbeatStaleness = defaultRuntimeHeartbeatMaxStaleness
	}
	if maxHeartbeatStaleness < heartbeatInterval {
		maxHeartbeatStaleness = heartbeatInterval
	}
	return &ProcessSupervisor{
		path:                  path,
		args:                  append([]string(nil), options.Args...),
		env:                   append([]string(nil), options.Env...),
		dir:                   strings.TrimSpace(options.Dir),
		diagnostics:           options.Diagnostics,
		artifacts:             options.Artifacts,
		handleGrants:          options.HandleGrants,
		storageFiles:          options.StorageFiles,
		storageKV:             options.StorageKV,
		storageSQLite:         options.StorageSQLite,
		connectivity:          options.Connectivity,
		networkExecutor:       options.NetworkExecutor,
		now:                   now,
		handshakeTimeout:      handshakeTimeout,
		heartbeatInterval:     heartbeatInterval,
		maxHeartbeatStaleness: maxHeartbeatStaleness,
	}, nil
}

func (s *ProcessSupervisor) Start(ctx context.Context, target Target) error {
	if s == nil {
		return ErrRuntimePathRequired
	}
	if err := ctx.Err(); err != nil {
		return err
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
	s.seq++
	generationID := fmt.Sprintf("runtime_gen_%d_%d", s.now().UnixNano(), s.seq)
	runtimeCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(runtimeCtx, s.path, s.args...)
	if len(s.env) > 0 {
		cmd.Env = append([]string(nil), s.env...)
	}
	if s.dir != "" {
		cmd.Dir = s.dir
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		s.mu.Unlock()
		return err
	}
	stdoutReader := bufio.NewReader(stdout)
	health := Health{
		RuntimeInstanceID:   fmt.Sprintf("runtime_%d", cmd.Process.Pid),
		RuntimeGenerationID: generationID,
	}
	done := make(chan error, 1)
	s.cmd = cmd
	s.cancel = cancel
	s.done = done
	s.ipcIn = stdin
	s.ipcOut = stdoutReader
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
	go s.wait(cmd, done, cancel, health)

	ack, err := s.performHandshake(ctx, stdin, stdoutReader, health, target)
	if err != nil {
		cancel()
		s.mu.Lock()
		if s.cmd == cmd {
			s.health.Ready = false
		}
		s.mu.Unlock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			s.emit("plugin.runtime.process.cleanup_timeout", "warning", "runtime process did not exit after failed handshake", map[string]any{
				"runtime_instance_id":   health.RuntimeInstanceID,
				"runtime_generation_id": health.RuntimeGenerationID,
			})
		}
		return err
	}
	s.mu.Lock()
	if s.cmd == cmd {
		health.RuntimeVersion = ack.RuntimeVersion
		health.RustIPCVersion = ack.RustIPCVersion
		health.WASMABIVersion = ack.WASMABIVersion
		health.Ready = true
		s.health = health
	} else {
		s.mu.Unlock()
		return ErrRuntimeNotReady
	}
	s.mu.Unlock()
	s.emit("plugin.runtime.ipc.handshake", "info", "runtime ipc handshake completed", map[string]any{
		"runtime_instance_id":   health.RuntimeInstanceID,
		"runtime_generation_id": health.RuntimeGenerationID,
		"runtime_version":       health.RuntimeVersion,
		"rust_ipc_version":      health.RustIPCVersion,
		"wasm_abi_version":      health.WASMABIVersion,
	})
	go s.heartbeatLoop(runtimeCtx, health)
	return nil
}

func (s *ProcessSupervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	health := s.health
	if cancel == nil || done == nil || !s.health.Ready {
		s.mu.Unlock()
		return nil
	}
	cancel()
	s.mu.Unlock()

	select {
	case err := <-done:
		if err != nil && ctx.Err() == nil {
			s.emit("plugin.runtime.process.stopped", "info", "runtime process stopped", map[string]any{
				"runtime_instance_id":   health.RuntimeInstanceID,
				"runtime_generation_id": health.RuntimeGenerationID,
				"exit_error":            err.Error(),
			})
		} else {
			s.emit("plugin.runtime.process.stopped", "info", "runtime process stopped", map[string]any{
				"runtime_instance_id":   health.RuntimeInstanceID,
				"runtime_generation_id": health.RuntimeGenerationID,
			})
		}
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
	if err := ctx.Err(); err != nil {
		return HeartbeatResult{}, err
	}
	if s == nil || !s.isReady() {
		return HeartbeatResult{}, ErrRuntimeNotReady
	}
	rawPayload, err := json.Marshal(heartbeatRequestPayload{
		SentUnixNano:       s.now().UnixNano(),
		MaxStalenessMillis: int64(s.maxHeartbeatStaleness / time.Millisecond),
	})
	if err != nil {
		return HeartbeatResult{}, err
	}
	frame, err := s.callIPC(ctx, ipcFrameTypeHeartbeat, ipcFrameTypeHeartbeat, rawPayload, nil)
	if err != nil {
		return HeartbeatResult{}, err
	}
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
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
	}, nil
}

func (s *ProcessSupervisor) InvokeWorker(ctx context.Context, lease Lease, method string, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || !s.isReady() {
		return nil, ErrRuntimeNotReady
	}
	invocation := json.RawMessage(payload)
	if len(invocation) == 0 {
		invocation = json.RawMessage("null")
	}
	allowedArtifact, err := artifactRequestFromInvocation(invocation)
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
	frame, err := s.callIPC(ctx, ipcFrameTypeInvokeWorker, ipcFrameTypeInvokeWorkerResult, rawPayload, &allowedArtifact)
	if err != nil {
		return nil, err
	}
	response, err := decodeRuntimeResponse(frame)
	if err != nil {
		return nil, err
	}
	if !response.OK {
		return nil, response.err()
	}
	if len(response.Result) == 0 {
		return []byte("{}"), nil
	}
	return append([]byte(nil), response.Result...), nil
}

func (s *ProcessSupervisor) Revoke(ctx context.Context, pluginInstanceID string, revokeEpoch uint64) (RevokeResult, error) {
	fallback := RevokeResult{
		PluginInstanceID: pluginInstanceID,
		RevokeEpoch:      revokeEpoch,
	}
	if err := ctx.Err(); err != nil {
		return RevokeResult{}, err
	}
	if s == nil || !s.isReady() {
		return fallback, nil
	}
	rawPayload, err := json.Marshal(revokeEpochRequestPayload{
		PluginInstanceID: pluginInstanceID,
		RevokeEpoch:      revokeEpoch,
	})
	if err != nil {
		return RevokeResult{}, err
	}
	frame, err := s.callIPC(ctx, ipcFrameTypeRevokeEpoch, ipcFrameTypeRevokeEpochAck, rawPayload, nil)
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

type revokeResultPayload struct {
	PluginInstanceID         string  `json:"plugin_instance_id"`
	RevokeEpoch              *uint64 `json:"revoke_epoch"`
	ClosedActorCount         *int    `json:"closed_actor_count"`
	ClosedSocketCount        *int    `json:"closed_socket_count"`
	ClosedStreamCount        *int    `json:"closed_stream_count"`
	ClosedStorageHandleCount *int    `json:"closed_storage_handle_count"`
}

func decodeRevokeResult(raw json.RawMessage, pluginInstanceID string, revokeEpoch uint64) (RevokeResult, error) {
	var payload revokeResultPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return RevokeResult{}, err
	}
	if payload.PluginInstanceID == "" ||
		payload.RevokeEpoch == nil ||
		payload.ClosedActorCount == nil ||
		payload.ClosedSocketCount == nil ||
		payload.ClosedStreamCount == nil ||
		payload.ClosedStorageHandleCount == nil {
		return RevokeResult{}, fmt.Errorf("%w: revoke ack result missing required field", ErrRuntimeRequestFailed)
	}
	result := RevokeResult{
		PluginInstanceID:         payload.PluginInstanceID,
		RevokeEpoch:              *payload.RevokeEpoch,
		ClosedActorCount:         *payload.ClosedActorCount,
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
	if result.ClosedActorCount < 0 || result.ClosedSocketCount < 0 || result.ClosedStreamCount < 0 || result.ClosedStorageHandleCount < 0 {
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

func (s *ProcessSupervisor) wait(cmd *exec.Cmd, done chan<- error, cancel context.CancelFunc, health Health) {
	err := cmd.Wait()
	cancel()
	s.mu.Lock()
	if s.cmd == cmd {
		s.health.Ready = false
		s.exitError = err
		s.cancel = nil
		s.done = nil
		s.cmd = nil
		s.ipcIn = nil
		s.ipcOut = nil
	}
	s.mu.Unlock()
	severity := "info"
	message := "runtime process exited"
	details := map[string]any{
		"runtime_instance_id":   health.RuntimeInstanceID,
		"runtime_generation_id": health.RuntimeGenerationID,
	}
	if err != nil {
		severity = "warning"
		message = "runtime process exited with error"
		details["exit_error"] = err.Error()
	}
	s.emit("plugin.runtime.process.exited", severity, message, details)
	done <- err
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
		severity := "info"
		if streamName == "stderr" {
			severity = "warning"
		}
		s.emit("plugin.runtime.process."+streamName, severity, line, map[string]any{"stream": streamName})
	}
	if err := scanner.Err(); err != nil {
		s.emit("plugin.runtime.process."+streamName+".error", "warning", err.Error(), map[string]any{"stream": streamName})
	}
}

func (s *ProcessSupervisor) emit(eventType string, severity string, message string, details map[string]any) {
	if s == nil || s.diagnostics == nil {
		return
	}
	_ = s.diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type:       eventType,
		Severity:   severity,
		Message:    message,
		OccurredAt: s.now(),
		Details:    details,
	})
}

const (
	ipcFrameTypeHello               = "hello"
	ipcFrameTypeHelloAck            = "hello_ack"
	ipcFrameTypeHeartbeat           = "heartbeat"
	ipcFrameTypeInvokeWorker        = "invoke_worker"
	ipcFrameTypeInvokeWorkerResult  = "invoke_worker_result"
	ipcFrameTypeOpenHandle          = "open_handle"
	ipcFrameTypeValidateHandleGrant = "validate_handle_grant"
	ipcFrameTypeStorageFile         = "storage_file"
	ipcFrameTypeStorageKV           = "storage_kv"
	ipcFrameTypeStorageSQLite       = "storage_sqlite"
	ipcFrameTypeNetworkGrant        = "network_grant"
	ipcFrameTypeNetworkExecute      = "network_execute"
	ipcFrameTypeRevokeEpoch         = "revoke_epoch"
	ipcFrameTypeRevokeEpochAck      = "revoke_epoch_ack"
)

const (
	defaultRuntimeHostcallTimeout       = 30 * time.Second
	maxRuntimeHostcallTimeout           = 30 * time.Second
	defaultRuntimeHeartbeatInterval     = 2 * time.Second
	defaultRuntimeHeartbeatMaxStaleness = 5 * time.Second
)

type ipcFrame struct {
	IPCVersion          string          `json:"ipc_version"`
	FrameType           string          `json:"frame_type"`
	RequestID           string          `json:"request_id"`
	RuntimeGenerationID string          `json:"runtime_generation_id,omitempty"`
	Payload             json.RawMessage `json:"payload,omitempty"`
}

type helloRequestPayload struct {
	Target          Target `json:"target"`
	HostProcessID   int    `json:"host_process_id"`
	HostIPCVersion  string `json:"host_ipc_version"`
	HostWASMABI     string `json:"host_wasm_abi"`
	StartedUnixNano int64  `json:"started_unix_nano"`
	ChannelNonce    string `json:"channel_nonce"`
}

type helloAckPayload struct {
	RuntimeVersion string `json:"runtime_version"`
	RustIPCVersion string `json:"rust_ipc_version"`
	WASMABIVersion string `json:"wasm_abi_version"`
	ChannelNonce   string `json:"channel_nonce"`
}

type heartbeatRequestPayload struct {
	SentUnixNano       int64 `json:"sent_unix_nano"`
	MaxStalenessMillis int64 `json:"max_staleness_ms"`
}

type heartbeatResultPayload struct {
	RuntimeGenerationID  string `json:"runtime_generation_id"`
	RuntimeUnixNano      *int64 `json:"runtime_unix_nano"`
	MaxStalenessMillis   *int64 `json:"max_staleness_ms"`
	HostSentUnixNanoEcho *int64 `json:"host_sent_unix_nano"`
}

type invokeWorkerRequestPayload struct {
	Lease      Lease           `json:"lease"`
	Method     string          `json:"method"`
	Invocation json.RawMessage `json:"invocation"`
}

type revokeEpochRequestPayload struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	RevokeEpoch      uint64 `json:"revoke_epoch"`
}

type runtimeResponsePayload struct {
	OK      bool            `json:"ok"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
	Code    string          `json:"code,omitempty"`
	Message string          `json:"message,omitempty"`
}

type artifactHandleRequestPayload struct {
	PackageHash    string `json:"package_hash"`
	Artifact       string `json:"artifact"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type artifactHandleResultPayload struct {
	OK            bool   `json:"ok"`
	PackageHash   string `json:"package_hash,omitempty"`
	Artifact      string `json:"artifact,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	ContentBase64 string `json:"content_base64,omitempty"`
	Code          string `json:"code,omitempty"`
	Message       string `json:"message,omitempty"`
}

type handleGrantValidationResultPayload struct {
	OK                  bool   `json:"ok"`
	HandleGrantID       string `json:"handle_grant_id,omitempty"`
	HandleID            string `json:"handle_id,omitempty"`
	Method              string `json:"method,omitempty"`
	RuntimeGenerationID string `json:"runtime_generation_id,omitempty"`
	MaxBytesPerSecond   int64  `json:"max_bytes_per_second,omitempty"`
	MaxTotalBytes       int64  `json:"max_total_bytes,omitempty"`
	Code                string `json:"code,omitempty"`
	Message             string `json:"message,omitempty"`
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
	OK         bool                `json:"ok"`
	Path       string              `json:"path,omitempty"`
	DataBase64 string              `json:"data_base64,omitempty"`
	SizeBytes  int64               `json:"size_bytes,omitempty"`
	Entries    []storage.FileEntry `json:"entries,omitempty"`
	Usage      *storage.Usage      `json:"usage,omitempty"`
	Code       string              `json:"code,omitempty"`
	Message    string              `json:"message,omitempty"`
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
	OK          bool              `json:"ok"`
	Key         string            `json:"key,omitempty"`
	ValueBase64 string            `json:"value_base64,omitempty"`
	SizeBytes   int64             `json:"size_bytes,omitempty"`
	Prefix      string            `json:"prefix,omitempty"`
	Entries     []storage.KVEntry `json:"entries,omitempty"`
	Usage       *storage.Usage    `json:"usage,omitempty"`
	Code        string            `json:"code,omitempty"`
	Message     string            `json:"message,omitempty"`
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
	OK           bool                      `json:"ok"`
	Database     string                    `json:"database,omitempty"`
	RowsAffected int64                     `json:"rows_affected,omitempty"`
	LastInsertID int64                     `json:"last_insert_id,omitempty"`
	Columns      []string                  `json:"columns,omitempty"`
	Rows         [][]storageSQLiteValueIPC `json:"rows,omitempty"`
	Usage        *storage.Usage            `json:"usage,omitempty"`
	Code         string                    `json:"code,omitempty"`
	Message      string                    `json:"message,omitempty"`
}

type storageSQLiteValueIPC struct {
	Null       bool     `json:"null,omitempty"`
	Int        *int64   `json:"int,omitempty"`
	Float      *float64 `json:"float,omitempty"`
	Text       *string  `json:"text,omitempty"`
	BlobBase64 string   `json:"blob_base64,omitempty"`
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
	GrantID                 string                   `json:"grant_id,omitempty"`
	PluginInstanceID        string                   `json:"plugin_instance_id,omitempty"`
	ActiveFingerprint       string                   `json:"active_fingerprint,omitempty"`
	PolicyRevision          uint64                   `json:"policy_revision,omitempty"`
	ManagementRevision      uint64                   `json:"management_revision,omitempty"`
	RevokeEpoch             uint64                   `json:"revoke_epoch,omitempty"`
	ConnectorID             string                   `json:"connector_id,omitempty"`
	Transport               connectivity.Transport   `json:"transport,omitempty"`
	Destination             connectivity.Destination `json:"destination,omitempty"`
	RuntimeGenerationID     string                   `json:"runtime_generation_id,omitempty"`
	TargetClassifierVersion string                   `json:"target_classifier_version,omitempty"`
	ExpiresAt               time.Time                `json:"expires_at,omitempty"`
	Code                    string                   `json:"code,omitempty"`
	Message                 string                   `json:"message,omitempty"`
}

type networkExecuteRequestPayload struct {
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
	Operation           string                 `json:"operation,omitempty"`
	Method              string                 `json:"method,omitempty"`
	Path                string                 `json:"path,omitempty"`
	Headers             http.Header            `json:"headers,omitempty"`
	MessageType         string                 `json:"message_type,omitempty"`
	BodyBase64          string                 `json:"body_base64,omitempty"`
	PayloadBase64       string                 `json:"payload_base64,omitempty"`
	MaxRequestBytes     int64                  `json:"max_request_bytes,omitempty"`
	MaxResponseBytes    int64                  `json:"max_response_bytes,omitempty"`
	TimeoutMillis       int64                  `json:"timeout_ms,omitempty"`
}

type networkExecuteResponsePayload struct {
	OK                bool                     `json:"ok"`
	Transport         connectivity.Transport   `json:"transport,omitempty"`
	Destination       connectivity.Destination `json:"destination,omitempty"`
	StatusCode        int                      `json:"status_code,omitempty"`
	Headers           http.Header              `json:"headers,omitempty"`
	MessageType       string                   `json:"message_type,omitempty"`
	BodyBase64        string                   `json:"body_base64,omitempty"`
	PayloadBase64     string                   `json:"payload_base64,omitempty"`
	GrantID           string                   `json:"grant_id,omitempty"`
	ConnectorID       string                   `json:"connector_id,omitempty"`
	RuntimeGeneration string                   `json:"runtime_generation_id,omitempty"`
	Code              string                   `json:"code,omitempty"`
	Message           string                   `json:"message,omitempty"`
}

func (p runtimeResponsePayload) err() error {
	message := strings.TrimSpace(p.Message)
	if message == "" {
		message = strings.TrimSpace(p.Error)
	}
	if message == "" {
		message = "runtime request failed"
	}
	code := strings.TrimSpace(p.Code)
	if code == "" {
		return fmt.Errorf("%w: %s", ErrRuntimeRequestFailed, message)
	}
	return fmt.Errorf("%w: %s: %s", ErrRuntimeRequestFailed, code, message)
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
		Target:          target,
		HostProcessID:   os.Getpid(),
		HostIPCVersion:  version.RustIPCVersion,
		HostWASMABI:     version.WASMABIVersion,
		StartedUnixNano: s.now().UnixNano(),
		ChannelNonce:    channelNonce,
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
		return validateHelloAck(requestID, health.RuntimeGenerationID, channelNonce, got.frame)
	}
}

func randomIPCChannelNonce() (string, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generate ipc channel nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}

func (s *ProcessSupervisor) callIPC(ctx context.Context, frameType string, responseFrameType string, payload json.RawMessage, allowedArtifact *ArtifactRequest) (ipcFrame, error) {
	if err := ctx.Err(); err != nil {
		return ipcFrame{}, err
	}
	s.mu.Lock()
	if !s.readyLocked() || s.ipcIn == nil || s.ipcOut == nil {
		s.mu.Unlock()
		return ipcFrame{}, ErrRuntimeNotReady
	}
	preLockHealth := s.health
	s.mu.Unlock()
	if err := s.lockIPC(ctx); err != nil {
		s.invalidateRuntimeAfterIPCFailure(preLockHealth, "runtime ipc lock context canceled", err)
		return ipcFrame{}, err
	}
	defer s.ipcMu.Unlock()
	s.mu.Lock()
	if !s.readyLocked() || s.ipcIn == nil || s.ipcOut == nil {
		s.mu.Unlock()
		return ipcFrame{}, ErrRuntimeNotReady
	}
	s.requestSeq++
	health := s.health
	requestID := fmt.Sprintf("%s:%s:%d", health.RuntimeGenerationID, frameType, s.requestSeq)
	stdin := s.ipcIn
	stdout := s.ipcOut
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
		return ipcFrame{}, fmt.Errorf("%w: write %s: %v", ErrRuntimeIPCUnavailable, frameType, err)
	}

	for {
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
		case <-ctx.Done():
			s.invalidateRuntimeAfterIPCFailure(health, "runtime ipc request context canceled", ctx.Err())
			return ipcFrame{}, ctx.Err()
		case got := <-result:
			if got.err != nil {
				return ipcFrame{}, fmt.Errorf("%w: read %s: %v", ErrRuntimeIPCUnavailable, responseFrameType, got.err)
			}
			if got.frame.FrameType == ipcFrameTypeOpenHandle {
				if err := s.respondToOpenHandle(ctx, stdin, health.RuntimeGenerationID, got.frame, allowedArtifact); err != nil {
					return ipcFrame{}, err
				}
				continue
			}
			if got.frame.FrameType == ipcFrameTypeValidateHandleGrant {
				if err := s.respondToValidateHandleGrant(ctx, stdin, health.RuntimeGenerationID, got.frame, allowedArtifact); err != nil {
					return ipcFrame{}, err
				}
				continue
			}
			if got.frame.FrameType == ipcFrameTypeStorageFile {
				if err := s.respondToStorageFile(ctx, stdin, health, got.frame, allowedArtifact); err != nil {
					return ipcFrame{}, err
				}
				continue
			}
			if got.frame.FrameType == ipcFrameTypeStorageKV {
				if err := s.respondToStorageKV(ctx, stdin, health, got.frame, allowedArtifact); err != nil {
					return ipcFrame{}, err
				}
				continue
			}
			if got.frame.FrameType == ipcFrameTypeStorageSQLite {
				if err := s.respondToStorageSQLite(ctx, stdin, health, got.frame, allowedArtifact); err != nil {
					return ipcFrame{}, err
				}
				continue
			}
			if got.frame.FrameType == ipcFrameTypeNetworkGrant {
				if err := s.respondToNetworkGrant(ctx, stdin, health, got.frame, allowedArtifact); err != nil {
					return ipcFrame{}, err
				}
				continue
			}
			if got.frame.FrameType == ipcFrameTypeNetworkExecute {
				if err := s.respondToNetworkExecute(ctx, stdin, health, got.frame, allowedArtifact); err != nil {
					return ipcFrame{}, err
				}
				continue
			}
			if err := validateIPCResponse(requestID, health.RuntimeGenerationID, responseFrameType, got.frame); err != nil {
				return ipcFrame{}, err
			}
			return got.frame, nil
		}
	}
}

func (s *ProcessSupervisor) lockIPC(ctx context.Context) error {
	for {
		if s.ipcMu.TryLock() {
			return nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
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
	if err != nil {
		details["error"] = err.Error()
	}
	s.emit("plugin.runtime.ipc.invalidated", "warning", message, details)
}

func (s *ProcessSupervisor) respondToOpenHandle(ctx context.Context, stdin io.Writer, runtimeGenerationID string, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	var req artifactHandleRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame.RequestID, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_REQUEST_INVALID",
			Message: "missing artifact request payload",
		})
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame.RequestID, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_REQUEST_INVALID",
			Message: "decode artifact request payload: " + err.Error(),
		})
	}
	if allowedArtifact == nil || !artifactRequestMatches(ArtifactRequest(req), *allowedArtifact) {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame.RequestID, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_REQUEST_DENIED",
			Message: "artifact request is not bound to the active worker invocation",
		})
	}
	if s.artifacts == nil {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame.RequestID, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_PROVIDER_UNAVAILABLE",
			Message: "runtime artifact provider is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, 0)
	defer cancel()
	artifact, err := s.artifacts.ReadArtifact(hostcallCtx, ArtifactRequest(req))
	if err != nil {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame.RequestID, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_READ_FAILED",
			Message: err.Error(),
		})
	}
	sum := sha256.Sum256(artifact.Content)
	actual := "sha256:" + fmt.Sprintf("%x", sum[:])
	if artifact.SHA256 != "" && artifact.SHA256 != actual {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame.RequestID, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_HASH_MISMATCH",
			Message: "artifact provider returned content that does not match sha256",
		})
	}
	if req.ArtifactSHA256 != "" && req.ArtifactSHA256 != actual {
		return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame.RequestID, artifactHandleResultPayload{
			OK:      false,
			Code:    "ARTIFACT_HASH_MISMATCH",
			Message: "artifact content does not match requested sha256",
		})
	}
	return s.writeOpenHandleResponse(stdin, runtimeGenerationID, frame.RequestID, artifactHandleResultPayload{
		OK:            true,
		PackageHash:   req.PackageHash,
		Artifact:      req.Artifact,
		SHA256:        actual,
		ContentBase64: base64.StdEncoding.EncodeToString(artifact.Content),
	})
}

func (s *ProcessSupervisor) writeOpenHandleResponse(stdin io.Writer, runtimeGenerationID string, requestID string, payload artifactHandleResultPayload) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeOpenHandle,
		RequestID:           requestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
		return fmt.Errorf("%w: write open_handle response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func (s *ProcessSupervisor) respondToValidateHandleGrant(ctx context.Context, stdin io.Writer, runtimeGenerationID string, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	if allowedArtifact == nil {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame.RequestID, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_DENIED",
			Message: "handle grant validation is only available during worker invocation",
		})
	}
	var req HandleGrantValidationRequest
	if len(frame.Payload) == 0 {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame.RequestID, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_INVALID",
			Message: "missing handle grant validation payload",
		})
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame.RequestID, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_INVALID",
			Message: "decode handle grant validation payload: " + err.Error(),
		})
	}
	if strings.TrimSpace(req.RuntimeGenerationID) != runtimeGenerationID {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame.RequestID, handleGrantValidationResultPayload{
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
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame.RequestID, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_REQUEST_INVALID",
			Message: "handle grant token, plugin identity, handle id, and method are required",
		})
	}
	if s.handleGrants == nil {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame.RequestID, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATOR_UNAVAILABLE",
			Message: "runtime handle grant validator is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, 0)
	defer cancel()
	result, err := s.handleGrants.ValidateHandleGrant(hostcallCtx, req)
	if err != nil {
		return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame.RequestID, handleGrantValidationResultPayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: err.Error(),
		})
	}
	return s.writeHandleGrantValidationResponse(stdin, runtimeGenerationID, frame.RequestID, handleGrantValidationResultPayload{
		OK:                  true,
		HandleGrantID:       result.HandleGrantID,
		HandleID:            result.HandleID,
		Method:              result.Method,
		RuntimeGenerationID: result.RuntimeGenerationID,
		MaxBytesPerSecond:   result.MaxBytesPerSecond,
		MaxTotalBytes:       result.MaxTotalBytes,
	})
}

func (s *ProcessSupervisor) writeHandleGrantValidationResponse(stdin io.Writer, runtimeGenerationID string, requestID string, payload handleGrantValidationResultPayload) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeValidateHandleGrant,
		RequestID:           requestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
		return fmt.Errorf("%w: write validate_handle_grant response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func (s *ProcessSupervisor) respondToStorageFile(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	if allowedArtifact == nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_DENIED",
			Message: "storage file access is only available during worker invocation",
		})
	}
	var req storageFileRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_INVALID",
			Message: "missing storage file payload",
		})
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_INVALID",
			Message: "decode storage file payload: " + err.Error(),
		})
	}
	if err := validateStorageFileRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_REQUEST_INVALID",
			Message: err.Error(),
		})
	}
	if s.storageFiles == nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageFileResponsePayload{
			OK:      false,
			Code:    "STORAGE_FILE_BROKER_UNAVAILABLE",
			Message: "runtime storage files broker is unavailable",
		})
	}
	if s.handleGrants == nil {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageFileResponsePayload{
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
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageFileResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: err.Error(),
		})
	}
	if grant.HandleID != req.HandleID || grant.Method != req.Method || grant.RuntimeGenerationID != health.RuntimeGenerationID {
		return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageFileResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation result did not match storage file request",
		})
	}
	payload := dispatchStorageFileRequest(hostcallCtx, s.storageFiles, req)
	return s.writeStorageFileResponse(stdin, health.RuntimeGenerationID, frame.RequestID, payload)
}

func (s *ProcessSupervisor) writeStorageFileResponse(stdin io.Writer, runtimeGenerationID string, requestID string, payload storageFileResponsePayload) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeStorageFile,
		RequestID:           requestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
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
	case "read", "write", "delete", "list":
		return nil
	default:
		return errors.New("storage file operation is not supported")
	}
}

func dispatchStorageFileRequest(ctx context.Context, broker storage.FilesBroker, req storageFileRequestPayload) storageFileResponsePayload {
	switch req.Operation {
	case "read":
		result, err := broker.ReadFile(ctx, storage.FileReadRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Path:             req.Path,
			MaxBytes:         req.MaxBytes,
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
			return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_REQUEST_INVALID", Message: "decode data_base64: " + err.Error()}
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
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_NOT_FOUND", Message: err.Error()}
	case errors.Is(err, storage.ErrInvalidFilePath), errors.Is(err, storage.ErrInvalidNamespace):
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_INVALID_PATH", Message: err.Error()}
	case errors.Is(err, storage.ErrQuotaExceeded):
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_QUOTA_EXCEEDED", Message: err.Error()}
	case errors.Is(err, storage.ErrFileTooLarge):
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_TOO_LARGE", Message: err.Error()}
	default:
		return storageFileResponsePayload{OK: false, Code: "STORAGE_FILE_FAILED", Message: err.Error()}
	}
}

func (s *ProcessSupervisor) respondToStorageKV(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	if allowedArtifact == nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_DENIED",
			Message: "storage kv access is only available during worker invocation",
		})
	}
	var req storageKVRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_INVALID",
			Message: "missing storage kv payload",
		})
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_INVALID",
			Message: "decode storage kv payload: " + err.Error(),
		})
	}
	if err := validateStorageKVRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_REQUEST_INVALID",
			Message: err.Error(),
		})
	}
	if s.storageKV == nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageKVResponsePayload{
			OK:      false,
			Code:    "STORAGE_KV_BROKER_UNAVAILABLE",
			Message: "runtime storage kv broker is unavailable",
		})
	}
	if s.handleGrants == nil {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageKVResponsePayload{
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
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageKVResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: err.Error(),
		})
	}
	if grant.HandleID != req.HandleID || grant.Method != req.Method || grant.RuntimeGenerationID != health.RuntimeGenerationID {
		return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageKVResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation result did not match storage kv request",
		})
	}
	payload := dispatchStorageKVRequest(hostcallCtx, s.storageKV, req)
	return s.writeStorageKVResponse(stdin, health.RuntimeGenerationID, frame.RequestID, payload)
}

func (s *ProcessSupervisor) writeStorageKVResponse(stdin io.Writer, runtimeGenerationID string, requestID string, payload storageKVResponsePayload) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeStorageKV,
		RequestID:           requestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
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
	case "get", "put", "delete":
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
		result, err := broker.GetKV(ctx, storage.KVGetRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Key:              req.Key,
			MaxBytes:         req.MaxBytes,
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
			return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_REQUEST_INVALID", Message: "decode value_base64: " + err.Error()}
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
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_NOT_FOUND", Message: err.Error()}
	case errors.Is(err, storage.ErrInvalidKVKey), errors.Is(err, storage.ErrInvalidNamespace):
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_INVALID_KEY", Message: err.Error()}
	case errors.Is(err, storage.ErrQuotaExceeded):
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_QUOTA_EXCEEDED", Message: err.Error()}
	case errors.Is(err, storage.ErrKVValueTooLarge):
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_VALUE_TOO_LARGE", Message: err.Error()}
	default:
		return storageKVResponsePayload{OK: false, Code: "STORAGE_KV_FAILED", Message: err.Error()}
	}
}

func (s *ProcessSupervisor) respondToStorageSQLite(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	if allowedArtifact == nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_DENIED",
			Message: "storage sqlite access is only available during worker invocation",
		})
	}
	var req storageSQLiteRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_INVALID",
			Message: "missing storage sqlite payload",
		})
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_INVALID",
			Message: "decode storage sqlite payload: " + err.Error(),
		})
	}
	if err := validateStorageSQLiteRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_REQUEST_INVALID",
			Message: err.Error(),
		})
	}
	if s.storageSQLite == nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "STORAGE_SQLITE_BROKER_UNAVAILABLE",
			Message: "runtime storage sqlite broker is unavailable",
		})
	}
	if s.handleGrants == nil {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageSQLiteResponsePayload{
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
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: err.Error(),
		})
	}
	if grant.HandleID != req.HandleID || grant.Method != req.Method || grant.RuntimeGenerationID != health.RuntimeGenerationID {
		return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, storageSQLiteResponsePayload{
			OK:      false,
			Code:    "HANDLE_GRANT_VALIDATION_FAILED",
			Message: "handle grant validation result did not match storage sqlite request",
		})
	}
	payload := dispatchStorageSQLiteRequest(hostcallCtx, s.storageSQLite, req)
	return s.writeStorageSQLiteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, payload)
}

func (s *ProcessSupervisor) writeStorageSQLiteResponse(stdin io.Writer, runtimeGenerationID string, requestID string, payload storageSQLiteResponsePayload) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeStorageSQLite,
		RequestID:           requestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
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
	case "exec", "query":
		return nil
	default:
		return errors.New("storage sqlite operation is not supported")
	}
}

func dispatchStorageSQLiteRequest(ctx context.Context, broker storage.SQLiteBroker, req storageSQLiteRequestPayload) storageSQLiteResponsePayload {
	args, err := storageSQLiteArgsFromIPC(req.Args)
	if err != nil {
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_REQUEST_INVALID", Message: err.Error()}
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
		return storageSQLiteResponsePayload{
			OK:           true,
			Database:     result.Database,
			RowsAffected: result.RowsAffected,
			LastInsertID: result.LastInsertID,
			Usage:        &usage,
		}
	case "query":
		result, err := broker.QuerySQLite(ctx, storage.SQLiteQueryRequest{
			PluginInstanceID: req.PluginInstanceID,
			StoreID:          req.StoreID,
			Database:         req.Database,
			SQL:              req.SQL,
			Args:             args,
			MaxRows:          req.MaxRows,
			MaxResponseBytes: req.MaxResponseBytes,
			Timeout:          timeout,
		})
		if err != nil {
			return storageSQLiteErrorResponse(err)
		}
		usage := result.Usage
		return storageSQLiteResponsePayload{
			OK:       true,
			Database: result.Database,
			Columns:  append([]string(nil), result.Columns...),
			Rows:     storageSQLiteRowsToIPC(result.Rows),
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
	if value.BlobBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(value.BlobBase64)
		if err != nil {
			return storage.SQLiteValue{}, fmt.Errorf("decode sqlite blob_base64: %v", err)
		}
		return storage.SQLiteValue{Blob: data}, nil
	}
	return storage.SQLiteValue{
		Null:  value.Null,
		Int:   value.Int,
		Float: value.Float,
		Text:  value.Text,
	}, nil
}

func storageSQLiteValueToIPC(value storage.SQLiteValue) storageSQLiteValueIPC {
	if len(value.Blob) > 0 {
		return storageSQLiteValueIPC{BlobBase64: base64.StdEncoding.EncodeToString(value.Blob)}
	}
	return storageSQLiteValueIPC{
		Null:  value.Null,
		Int:   value.Int,
		Float: value.Float,
		Text:  value.Text,
	}
}

func storageSQLiteErrorResponse(err error) storageSQLiteResponsePayload {
	switch {
	case errors.Is(err, storage.ErrNamespaceNotFound):
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_NOT_FOUND", Message: err.Error()}
	case errors.Is(err, storage.ErrInvalidSQLite), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrInvalidFilePath):
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_INVALID_REQUEST", Message: err.Error()}
	case errors.Is(err, storage.ErrQuotaExceeded):
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_QUOTA_EXCEEDED", Message: err.Error()}
	case errors.Is(err, storage.ErrSQLiteResultTooLarge):
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_RESULT_TOO_LARGE", Message: err.Error()}
	default:
		return storageSQLiteResponsePayload{OK: false, Code: "STORAGE_SQLITE_FAILED", Message: err.Error()}
	}
}

func (s *ProcessSupervisor) respondToNetworkGrant(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	if allowedArtifact == nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_DENIED",
			Message: "network grants are only available during worker invocation",
		})
	}
	var req networkGrantRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_INVALID",
			Message: "missing network grant payload",
		})
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_INVALID",
			Message: "decode network grant payload: " + err.Error(),
		})
	}
	if err := validateNetworkGrantRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_REQUEST_INVALID",
			Message: err.Error(),
		})
	}
	if s.connectivity == nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkGrantResponsePayload{
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
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkGrantErrorResponse(err))
	}
	if err := validateNetworkGrantResult(req, grant, health.RuntimeGenerationID); err != nil {
		return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkGrantResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_VALIDATION_FAILED",
			Message: err.Error(),
		})
	}
	return s.writeNetworkGrantResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkGrantResponsePayload{
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

func (s *ProcessSupervisor) writeNetworkGrantResponse(stdin io.Writer, runtimeGenerationID string, requestID string, payload networkGrantResponsePayload) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeNetworkGrant,
		RequestID:           requestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
		return fmt.Errorf("%w: write network_grant response: %v", ErrRuntimeIPCUnavailable, err)
	}
	return nil
}

func (s *ProcessSupervisor) respondToNetworkExecute(ctx context.Context, stdin io.Writer, health Health, frame ipcFrame, allowedArtifact *ArtifactRequest) error {
	if allowedArtifact == nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_DENIED",
			Message: "network execution is only available during worker invocation",
		})
	}
	var req networkExecuteRequestPayload
	if len(frame.Payload) == 0 {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_INVALID",
			Message: "missing network execute payload",
		})
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_INVALID",
			Message: "decode network execute payload: " + err.Error(),
		})
	}
	if err := validateNetworkExecuteRequest(req, health.RuntimeGenerationID); err != nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTE_REQUEST_INVALID",
			Message: err.Error(),
		})
	}
	if s.connectivity == nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_BROKER_UNAVAILABLE",
			Message: "runtime connectivity broker is unavailable",
		})
	}
	if s.networkExecutor == nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_EXECUTOR_UNAVAILABLE",
			Message: "runtime network executor is unavailable",
		})
	}
	hostcallCtx, cancel := runtimeHostcallContext(ctx, time.Duration(req.TimeoutMillis)*time.Millisecond)
	defer cancel()
	grant, err := s.mintGrantForNetworkExecute(hostcallCtx, req)
	if err != nil {
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkExecuteErrorResponse(err))
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
		return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, networkExecuteResponsePayload{
			OK:      false,
			Code:    "NETWORK_GRANT_VALIDATION_FAILED",
			Message: err.Error(),
		})
	}
	payload := dispatchNetworkExecute(hostcallCtx, s.networkExecutor, grant, req, s.now())
	if payload.OK {
		payload.GrantID = grant.GrantID
		payload.ConnectorID = grant.ConnectorID
		payload.RuntimeGeneration = grant.RuntimeGenerationID
		payload.Transport = grant.Transport
		payload.Destination = grant.Destination
	}
	return s.writeNetworkExecuteResponse(stdin, health.RuntimeGenerationID, frame.RequestID, payload)
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

func (s *ProcessSupervisor) writeNetworkExecuteResponse(stdin io.Writer, runtimeGenerationID string, requestID string, payload networkExecuteResponsePayload) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(ipcFrame{
		IPCVersion:          version.RustIPCVersion,
		FrameType:           ipcFrameTypeNetworkExecute,
		RequestID:           requestID,
		RuntimeGenerationID: runtimeGenerationID,
		Payload:             raw,
	}); err != nil {
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
	if req.MaxRequestBytes < 0 || req.MaxResponseBytes < 0 {
		return errors.New("max request and response bytes must not be negative")
	}
	switch req.Transport {
	case connectivity.TransportHTTP:
		if strings.TrimSpace(req.Operation) != "" && strings.TrimSpace(req.Operation) != "http" {
			return errors.New("http network execution operation must be http")
		}
	case connectivity.TransportWebSocket:
		if strings.TrimSpace(req.Operation) != "" && strings.TrimSpace(req.Operation) != "websocket_round_trip" {
			return errors.New("websocket network execution operation must be websocket_round_trip")
		}
	case connectivity.TransportTCP:
		if strings.TrimSpace(req.Operation) != "" && strings.TrimSpace(req.Operation) != "tcp_round_trip" {
			return errors.New("tcp network execution operation must be tcp_round_trip")
		}
	case connectivity.TransportUDP:
		if strings.TrimSpace(req.Operation) != "" && strings.TrimSpace(req.Operation) != "udp_round_trip" {
			return errors.New("udp network execution operation must be udp_round_trip")
		}
	}
	return nil
}

func dispatchNetworkExecute(ctx context.Context, executor connectivity.NetworkExecutor, grant connectivity.ConnectionGrant, req networkExecuteRequestPayload, now time.Time) networkExecuteResponsePayload {
	timeout := time.Duration(req.TimeoutMillis) * time.Millisecond
	switch req.Transport {
	case connectivity.TransportHTTP:
		body, err := decodeOptionalBase64(req.BodyBase64)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: err.Error()}
		}
		result, err := executor.DoHTTP(ctx, connectivity.HTTPRequest{
			Grant:            grant,
			Method:           req.Method,
			Path:             req.Path,
			Headers:          req.Headers,
			Body:             body,
			MaxRequestBytes:  req.MaxRequestBytes,
			MaxResponseBytes: req.MaxResponseBytes,
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
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: err.Error()}
		}
		result, err := executor.WebSocketRoundTrip(ctx, connectivity.WebSocketRoundTripRequest{
			Grant:            grant,
			Path:             req.Path,
			Headers:          req.Headers,
			MessageType:      connectivity.WebSocketMessageType(strings.TrimSpace(req.MessageType)),
			Payload:          payload,
			MaxRequestBytes:  req.MaxRequestBytes,
			MaxResponseBytes: req.MaxResponseBytes,
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
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: err.Error()}
		}
		result, err := executor.TCPRoundTrip(ctx, connectivity.TCPRoundTripRequest{
			Grant:        grant,
			Payload:      payload,
			MaxReadBytes: req.MaxResponseBytes,
			Timeout:      timeout,
			Now:          now,
		})
		if err != nil {
			return networkExecuteErrorResponse(err)
		}
		return networkExecuteResponsePayload{OK: true, PayloadBase64: base64.StdEncoding.EncodeToString(result.Payload)}
	case connectivity.TransportUDP:
		payload, err := decodeOptionalBase64(req.PayloadBase64)
		if err != nil {
			return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: err.Error()}
		}
		result, err := executor.UDPRoundTrip(ctx, connectivity.UDPRoundTripRequest{
			Grant:        grant,
			Payload:      payload,
			MaxReadBytes: req.MaxResponseBytes,
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
		return networkGrantResponsePayload{OK: false, Code: "NETWORK_GRANT_REQUEST_INVALID", Message: err.Error()}
	case errors.Is(err, connectivity.ErrTargetDenied):
		return networkGrantResponsePayload{OK: false, Code: "NETWORK_TARGET_DENIED", Message: err.Error()}
	case errors.Is(err, connectivity.ErrConnectorDenied):
		return networkGrantResponsePayload{OK: false, Code: "NETWORK_CONNECTOR_DENIED", Message: err.Error()}
	default:
		return networkGrantResponsePayload{OK: false, Code: "NETWORK_GRANT_FAILED", Message: err.Error()}
	}
}

func networkExecuteErrorResponse(err error) networkExecuteResponsePayload {
	switch {
	case errors.Is(err, connectivity.ErrInvalidConnector):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_REQUEST_INVALID", Message: err.Error()}
	case errors.Is(err, connectivity.ErrTargetDenied):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_TARGET_DENIED", Message: err.Error()}
	case errors.Is(err, connectivity.ErrConnectorDenied):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_CONNECTOR_DENIED", Message: err.Error()}
	case errors.Is(err, connectivity.ErrGrantExpired):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_GRANT_EXPIRED", Message: err.Error()}
	case errors.Is(err, connectivity.ErrRequestTooLarge):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_REQUEST_TOO_LARGE", Message: err.Error()}
	case errors.Is(err, connectivity.ErrResponseTooLarge):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_RESPONSE_TOO_LARGE", Message: err.Error()}
	case errors.Is(err, connectivity.ErrRateLimited):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_RATE_LIMITED", Message: err.Error()}
	case errors.Is(err, connectivity.ErrConnectionClosed):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_CONNECTION_CLOSED", Message: err.Error()}
	case errors.Is(err, connectivity.ErrWebSocketFailed):
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_WEBSOCKET_FAILED", Message: err.Error()}
	default:
		return networkExecuteResponsePayload{OK: false, Code: "NETWORK_EXECUTE_FAILED", Message: err.Error()}
	}
}

func artifactRequestFromInvocation(invocation json.RawMessage) (ArtifactRequest, error) {
	var payload struct {
		PackageHash    string `json:"package_hash"`
		Artifact       string `json:"artifact"`
		ArtifactSHA256 string `json:"artifact_sha256"`
	}
	if len(invocation) == 0 {
		return ArtifactRequest{}, fmt.Errorf("%w: worker invocation payload is required", ErrRuntimeRequestFailed)
	}
	if err := json.Unmarshal(invocation, &payload); err != nil {
		return ArtifactRequest{}, fmt.Errorf("%w: decode worker invocation identity: %v", ErrRuntimeRequestFailed, err)
	}
	req := ArtifactRequest{
		PackageHash:    strings.TrimSpace(payload.PackageHash),
		Artifact:       strings.TrimSpace(payload.Artifact),
		ArtifactSHA256: strings.TrimSpace(payload.ArtifactSHA256),
	}
	if req.PackageHash == "" || req.Artifact == "" || req.ArtifactSHA256 == "" {
		return ArtifactRequest{}, fmt.Errorf("%w: worker invocation must include package_hash, artifact, and artifact_sha256", ErrRuntimeRequestFailed)
	}
	if !isSHA256Ref(req.PackageHash) || !isSHA256Ref(req.ArtifactSHA256) {
		return ArtifactRequest{}, fmt.Errorf("%w: worker invocation artifact hashes must use sha256:<hex>", ErrRuntimeRequestFailed)
	}
	if !isWorkerArtifactPath(req.Artifact) {
		return ArtifactRequest{}, fmt.Errorf("%w: worker invocation artifact path is invalid", ErrRuntimeRequestFailed)
	}
	return req, nil
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
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return ipcFrame{}, err
	}
	var frame ipcFrame
	if err := json.Unmarshal(line, &frame); err != nil {
		return ipcFrame{}, err
	}
	return frame, nil
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
	var payload runtimeResponsePayload
	if len(frame.Payload) == 0 {
		return runtimeResponsePayload{}, fmt.Errorf("%w: missing response payload", ErrRuntimeIPCUnavailable)
	}
	if err := json.Unmarshal(frame.Payload, &payload); err != nil {
		return runtimeResponsePayload{}, fmt.Errorf("%w: decode response payload: %v", ErrRuntimeIPCUnavailable, err)
	}
	return payload, nil
}

func validateHelloAck(requestID string, runtimeGenerationID string, channelNonce string, frame ipcFrame) (helloAckPayload, error) {
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
	if err := json.Unmarshal(frame.Payload, &ack); err != nil {
		return helloAckPayload{}, fmt.Errorf("%w: decode payload: %v", ErrRuntimeHandshake, err)
	}
	if ack.RuntimeVersion == "" || ack.RustIPCVersion != version.RustIPCVersion || ack.WASMABIVersion != version.WASMABIVersion {
		return helloAckPayload{}, fmt.Errorf("%w: incompatible versions runtime=%q ipc=%q wasm=%q", ErrRuntimeHandshake, ack.RuntimeVersion, ack.RustIPCVersion, ack.WASMABIVersion)
	}
	if ack.ChannelNonce != channelNonce {
		return helloAckPayload{}, fmt.Errorf("%w: channel_nonce mismatch", ErrRuntimeHandshake)
	}
	return ack, nil
}
