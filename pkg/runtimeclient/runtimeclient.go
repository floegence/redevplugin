package runtimeclient

import (
	"bufio"
	"context"
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

var (
	ErrRuntimePathRequired   = errors.New("runtime path is required")
	ErrRuntimeNotReady       = errors.New("runtime is not ready")
	ErrRuntimeIPCUnavailable = errors.New("runtime ipc transport is unavailable")
	ErrRuntimeHandshake      = errors.New("runtime ipc handshake failed")
)

type ProcessSupervisorOptions struct {
	RuntimePath      string
	Args             []string
	Env              []string
	Dir              string
	Diagnostics      observability.DiagnosticsSink
	Now              func() time.Time
	HandshakeTimeout time.Duration
}

type ProcessSupervisor struct {
	startMu          sync.Mutex
	mu               sync.Mutex
	path             string
	args             []string
	env              []string
	dir              string
	diagnostics      observability.DiagnosticsSink
	now              func() time.Time
	handshakeTimeout time.Duration
	seq              uint64

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

func (s *ProcessSupervisor) InvokeWorker(ctx context.Context, _ Lease, _ string, _ []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || !s.isReady() {
		return nil, ErrRuntimeNotReady
	}
	return nil, ErrRuntimeIPCUnavailable
}

func (s *ProcessSupervisor) Revoke(ctx context.Context, _ string, _ uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.isReady() {
		return ErrRuntimeNotReady
	}
	return ErrRuntimeIPCUnavailable
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
	ipcFrameTypeHello    = "hello"
	ipcFrameTypeHelloAck = "hello_ack"
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
