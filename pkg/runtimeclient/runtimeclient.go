package runtimeclient

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

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

type Supervisor interface {
	Start(ctx context.Context, target Target) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) (Health, error)
	InvokeWorker(ctx context.Context, lease Lease, method string, payload []byte) ([]byte, error)
	Revoke(ctx context.Context, pluginInstanceID string, revokeEpoch uint64) error
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
	RuntimePath      string
	Args             []string
	Env              []string
	Dir              string
	Diagnostics      observability.DiagnosticsSink
	Artifacts        ArtifactProvider
	HandleGrants     HandleGrantValidator
	StorageFiles     storage.FilesBroker
	Now              func() time.Time
	HandshakeTimeout time.Duration
}

type ProcessSupervisor struct {
	startMu          sync.Mutex
	ipcMu            sync.Mutex
	mu               sync.Mutex
	path             string
	args             []string
	env              []string
	dir              string
	diagnostics      observability.DiagnosticsSink
	artifacts        ArtifactProvider
	handleGrants     HandleGrantValidator
	storageFiles     storage.FilesBroker
	now              func() time.Time
	handshakeTimeout time.Duration
	seq              uint64
	requestSeq       uint64

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
	return &ProcessSupervisor{
		path:             path,
		args:             append([]string(nil), options.Args...),
		env:              append([]string(nil), options.Env...),
		dir:              strings.TrimSpace(options.Dir),
		diagnostics:      options.Diagnostics,
		artifacts:        options.Artifacts,
		handleGrants:     options.HandleGrants,
		storageFiles:     options.StorageFiles,
		now:              now,
		handshakeTimeout: handshakeTimeout,
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

func (s *ProcessSupervisor) Revoke(ctx context.Context, pluginInstanceID string, revokeEpoch uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.isReady() {
		return ErrRuntimeNotReady
	}
	rawPayload, err := json.Marshal(revokeEpochRequestPayload{
		PluginInstanceID: pluginInstanceID,
		RevokeEpoch:      revokeEpoch,
	})
	if err != nil {
		return err
	}
	frame, err := s.callIPC(ctx, ipcFrameTypeRevokeEpoch, ipcFrameTypeRevokeEpochAck, rawPayload, nil)
	if err != nil {
		return err
	}
	response, err := decodeRuntimeResponse(frame)
	if err != nil {
		return err
	}
	if !response.OK {
		return response.err()
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
	ipcFrameTypeInvokeWorker        = "invoke_worker"
	ipcFrameTypeInvokeWorkerResult  = "invoke_worker_result"
	ipcFrameTypeOpenHandle          = "open_handle"
	ipcFrameTypeValidateHandleGrant = "validate_handle_grant"
	ipcFrameTypeStorageFile         = "storage_file"
	ipcFrameTypeRevokeEpoch         = "revoke_epoch"
	ipcFrameTypeRevokeEpochAck      = "revoke_epoch_ack"
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
}

type helloAckPayload struct {
	RuntimeVersion string `json:"runtime_version"`
	RustIPCVersion string `json:"rust_ipc_version"`
	WASMABIVersion string `json:"wasm_abi_version"`
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
	payload, err := json.Marshal(helloRequestPayload{
		Target:          target,
		HostProcessID:   os.Getpid(),
		HostIPCVersion:  version.RustIPCVersion,
		HostWASMABI:     version.WASMABIVersion,
		StartedUnixNano: s.now().UnixNano(),
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
		return validateHelloAck(requestID, health.RuntimeGenerationID, got.frame)
	}
}

func (s *ProcessSupervisor) callIPC(ctx context.Context, frameType string, responseFrameType string, payload json.RawMessage, allowedArtifact *ArtifactRequest) (ipcFrame, error) {
	if err := ctx.Err(); err != nil {
		return ipcFrame{}, err
	}
	s.ipcMu.Lock()
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
			if err := validateIPCResponse(requestID, health.RuntimeGenerationID, responseFrameType, got.frame); err != nil {
				return ipcFrame{}, err
			}
			return got.frame, nil
		}
	}
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
	artifact, err := s.artifacts.ReadArtifact(ctx, ArtifactRequest(req))
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
	result, err := s.handleGrants.ValidateHandleGrant(ctx, req)
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
	grant, err := s.handleGrants.ValidateHandleGrant(ctx, HandleGrantValidationRequest{
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
	payload := dispatchStorageFileRequest(ctx, s.storageFiles, req)
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

func validateHelloAck(requestID string, runtimeGenerationID string, frame ipcFrame) (helloAckPayload, error) {
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
	return ack, nil
}
