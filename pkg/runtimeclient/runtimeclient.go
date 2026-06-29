package runtimeclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/observability"
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
)

type ProcessSupervisorOptions struct {
	RuntimePath string
	Args        []string
	Env         []string
	Dir         string
	Diagnostics observability.DiagnosticsSink
	Now         func() time.Time
}

type ProcessSupervisor struct {
	mu          sync.Mutex
	path        string
	args        []string
	env         []string
	dir         string
	diagnostics observability.DiagnosticsSink
	now         func() time.Time
	seq         uint64

	cmd       *exec.Cmd
	cancel    context.CancelFunc
	done      chan error
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
	return &ProcessSupervisor{
		path:        path,
		args:        append([]string(nil), options.Args...),
		env:         append([]string(nil), options.Env...),
		dir:         strings.TrimSpace(options.Dir),
		diagnostics: options.Diagnostics,
		now:         now,
	}, nil
}

func (s *ProcessSupervisor) Start(ctx context.Context, target Target) error {
	if s == nil {
		return ErrRuntimePathRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.readyLocked() {
		s.mu.Unlock()
		return nil
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
	health := Health{
		RuntimeInstanceID:   fmt.Sprintf("runtime_%d", cmd.Process.Pid),
		RuntimeGenerationID: generationID,
		Ready:               true,
	}
	done := make(chan error, 1)
	s.cmd = cmd
	s.cancel = cancel
	s.done = done
	s.health = health
	s.exitError = nil
	s.mu.Unlock()

	s.emit("plugin.runtime.process.started", "info", "runtime process started", map[string]any{
		"runtime_instance_id":   health.RuntimeInstanceID,
		"runtime_generation_id": health.RuntimeGenerationID,
		"os":                    target.OS,
		"arch":                  target.Arch,
	})
	go s.scanPipe(stdout, "stdout")
	go s.scanPipe(stderr, "stderr")
	go s.wait(cmd, done, cancel, health)
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
