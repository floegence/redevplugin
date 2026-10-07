package process

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	MaxArguments            = 256
	MaxArgumentBytes        = 64 << 10
	MaxEnvironmentEntries   = 128
	MaxEnvironmentBytes     = 64 << 10
	MaxOutputBufferBytes    = 16 << 20
	MaxRuntimeMilliseconds  = 24 * 60 * 60 * 1000
	MaxClientKeyBytes       = 256
	MaxOwnerFieldBytes      = 256
	MaxStdinBytes           = 16 << 20
	defaultOutputBufferSize = 64 << 10
)

var (
	ErrInvalidRequest    = errors.New("PROCESS_INVALID_REQUEST")
	ErrPermissionDenied  = errors.New("PROCESS_PERMISSION_DENIED")
	ErrNotFound          = errors.New("PROCESS_NOT_FOUND")
	ErrLaunchConflict    = errors.New("PROCESS_LAUNCH_CONFLICT")
	ErrSecretUnavailable = errors.New("PROCESS_SECRET_UNAVAILABLE")
	ErrRevoked           = errors.New("PROCESS_OWNER_REVOKED")
	ErrClosed            = errors.New("PROCESS_SUPERVISOR_CLOSED")
)

type Owner struct {
	PluginInstanceID string
	UserScope        string
	EnvironmentScope string
}

func (o Owner) valid() bool {
	for _, value := range []string{o.PluginInstanceID, o.UserScope, o.EnvironmentScope} {
		if value == "" || len(value) > MaxOwnerFieldBytes || strings.IndexByte(value, 0) >= 0 {
			return false
		}
	}
	return true
}

func (o Owner) ValidForHost() bool {
	return o.valid()
}

func (o Owner) key() string {
	return o.PluginInstanceID + "\x00" + o.UserScope + "\x00" + o.EnvironmentScope
}

type SecretResolver func(context.Context, Owner, string) (string, error)

type Options struct {
	GracePeriod     time.Duration
	Secrets         SecretResolver
	BaseEnvironment []string
	Permission      func(context.Context, Owner) error
}

type Stream string

const (
	Stdout Stream = "stdout"
	Stderr Stream = "stderr"
)

type ResourceLimits struct {
	OutputBufferBytes int `json:"output_buffer_bytes,omitempty"`
	MaxRuntimeMS      int `json:"max_runtime_ms,omitempty"`
}

type StartRequest struct {
	Program             string            `json:"program"`
	Argv                []string          `json:"argv,omitempty"`
	Cwd                 string            `json:"cwd,omitempty"`
	Environment         map[string]string `json:"environment,omitempty"`
	EnvironmentRemovals []string          `json:"environment_removals,omitempty"`
	SecretReferences    map[string]string `json:"secret_references,omitempty"`
	ClientKey           string            `json:"client_key"`
	Limits              ResourceLimits    `json:"resource_limits,omitempty"`
}

type Status struct {
	Handle            string `json:"handle"`
	ClientKey         string `json:"client_key"`
	State             string `json:"state"`
	ExitCode          *int   `json:"exit_code,omitempty"`
	TerminationReason string `json:"termination_reason,omitempty"`
}

type ReadRequest struct {
	Cursor   uint64 `json:"cursor,omitempty"`
	MaxBytes int    `json:"max_bytes"`
}

type ReadResult struct {
	Data         []byte `json:"data"`
	Cursor       uint64 `json:"cursor"`
	EOF          bool   `json:"eof"`
	ProcessExit  bool   `json:"process_exit"`
	StreamGap    bool   `json:"stream_gap"`
	DroppedBytes uint64 `json:"dropped_bytes,omitempty"`
}

type ExitResult struct {
	ExitCode          *int   `json:"exit_code,omitempty"`
	TerminationReason string `json:"termination_reason,omitempty"`
}

type streamBuffer struct {
	mu     sync.Mutex
	data   []byte
	start  uint64
	cursor uint64
	closed bool
	limit  int
}

type streamWriter struct {
	buffer *streamBuffer
}

func (w streamWriter) Write(data []byte) (int, error) {
	w.buffer.append(data)
	return len(data), nil
}

func (b *streamBuffer) append(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, data...)
	b.cursor += uint64(len(data))
	if len(b.data) > b.limit {
		dropped := len(b.data) - b.limit
		b.data = b.data[dropped:]
		b.start += uint64(dropped)
	}
}

func (b *streamBuffer) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
}

func (b *streamBuffer) read(request ReadRequest, processExit bool) (ReadResult, error) {
	if request.MaxBytes <= 0 || request.MaxBytes > MaxOutputBufferBytes {
		return ReadResult{}, ErrInvalidRequest
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if request.Cursor > b.cursor {
		return ReadResult{}, ErrInvalidRequest
	}
	result := ReadResult{Cursor: request.Cursor, ProcessExit: processExit}
	if request.Cursor < b.start {
		result.StreamGap = true
		result.DroppedBytes = b.start - request.Cursor
		end := request.MaxBytes
		if end > len(b.data) {
			end = len(b.data)
		}
		result.Data = append([]byte(nil), b.data[:end]...)
		result.Cursor = b.start + uint64(len(result.Data))
		result.EOF = b.closed && processExit
		return result, nil
	}
	offset := int(request.Cursor - b.start)
	if offset < len(b.data) {
		end := offset + request.MaxBytes
		if end > len(b.data) {
			end = len(b.data)
		}
		result.Data = append([]byte(nil), b.data[offset:end]...)
		result.Cursor += uint64(len(result.Data))
	}
	result.EOF = b.closed && processExit && result.Cursor >= b.cursor
	return result, nil
}

type session struct {
	owner   Owner
	request StartRequest
	command *exec.Cmd
	tree    processTree
	stdin   io.WriteCloser
	stdout  *streamBuffer
	stderr  *streamBuffer
	done    chan struct{}

	mu                sync.Mutex
	stdinMu           sync.Mutex
	status            Status
	exit              ExitResult
	terminationReason string
	cleanupOnce       sync.Once
}

type startReservation struct {
	done        chan struct{}
	fingerprint string
	status      Status
	err         error
}

type Supervisor struct {
	mu             sync.Mutex
	options        Options
	sessions       map[string]*session
	clients        map[string]string
	starting       map[string]*startReservation
	revoked        map[string]bool
	revokedPlugins map[string]bool
	closed         bool
}

func NewSupervisor(options Options) (*Supervisor, error) {
	if options.GracePeriod <= 0 {
		options.GracePeriod = 2 * time.Second
	}
	return &Supervisor{
		options:        options,
		sessions:       map[string]*session{},
		clients:        map[string]string{},
		starting:       map[string]*startReservation{},
		revoked:        map[string]bool{},
		revokedPlugins: map[string]bool{},
	}, nil
}

func pluginEnvironmentKey(pluginInstanceID, environmentScope string) string {
	return pluginInstanceID + "\x00" + environmentScope
}

func validateStart(request StartRequest) error {
	if request.Program == "" || strings.IndexByte(request.Program, 0) >= 0 ||
		len(request.Program) > MaxArgumentBytes || len(request.Argv) > MaxArguments ||
		request.ClientKey == "" || len(request.ClientKey) > MaxClientKeyBytes || strings.IndexByte(request.ClientKey, 0) >= 0 {
		return ErrInvalidRequest
	}
	if strings.IndexByte(request.Cwd, 0) >= 0 || len(request.Cwd) > MaxArgumentBytes ||
		(request.Cwd != "" && !filepath.IsAbs(request.Cwd)) {
		return ErrInvalidRequest
	}
	total := len(request.Program) + len(request.Cwd) + len(request.ClientKey)
	for _, argument := range request.Argv {
		if strings.IndexByte(argument, 0) >= 0 || len(argument) > MaxArgumentBytes {
			return ErrInvalidRequest
		}
		total += len(argument)
	}
	if total > MaxEnvironmentBytes || len(request.Environment) > MaxEnvironmentEntries {
		return ErrInvalidRequest
	}
	environmentBytes := 0
	environmentKeys := make(map[string]struct{}, len(request.Environment))
	for key, value := range request.Environment {
		if !validEnvironmentKey(key) || strings.IndexByte(value, 0) >= 0 {
			return ErrInvalidRequest
		}
		normalized := normalizeEnvironmentKey(key)
		if _, exists := environmentKeys[normalized]; exists {
			return ErrInvalidRequest
		}
		environmentKeys[normalized] = struct{}{}
		environmentBytes += len(key) + len(value)
		if environmentBytes > MaxEnvironmentBytes {
			return ErrInvalidRequest
		}
	}
	if len(request.EnvironmentRemovals) > MaxEnvironmentEntries {
		return ErrInvalidRequest
	}
	removalBytes := 0
	removalKeys := make(map[string]struct{}, len(request.EnvironmentRemovals))
	for _, key := range request.EnvironmentRemovals {
		if !validEnvironmentKey(key) {
			return ErrInvalidRequest
		}
		normalized := normalizeEnvironmentKey(key)
		if _, exists := removalKeys[normalized]; exists {
			return ErrInvalidRequest
		}
		removalKeys[normalized] = struct{}{}
		removalBytes += len(key)
		if removalBytes > MaxEnvironmentBytes {
			return ErrInvalidRequest
		}
	}
	if len(request.SecretReferences) > MaxEnvironmentEntries {
		return ErrInvalidRequest
	}
	secretReferenceBytes := 0
	secretKeys := make(map[string]struct{}, len(request.SecretReferences))
	for key, reference := range request.SecretReferences {
		if !validEnvironmentKey(key) || reference == "" || len(reference) > MaxArgumentBytes || strings.IndexByte(reference, 0) >= 0 {
			return ErrInvalidRequest
		}
		normalized := normalizeEnvironmentKey(key)
		if _, exists := secretKeys[normalized]; exists {
			return ErrInvalidRequest
		}
		if _, exists := environmentKeys[normalized]; exists {
			return ErrInvalidRequest
		}
		if _, exists := removalKeys[normalized]; exists {
			return ErrInvalidRequest
		}
		secretKeys[normalized] = struct{}{}
		secretReferenceBytes += len(key) + len(reference)
		if secretReferenceBytes > MaxEnvironmentBytes {
			return ErrInvalidRequest
		}
	}
	if request.Limits.OutputBufferBytes < 0 || request.Limits.OutputBufferBytes > MaxOutputBufferBytes || request.Limits.MaxRuntimeMS < 0 ||
		request.Limits.MaxRuntimeMS > MaxRuntimeMilliseconds {
		return ErrInvalidRequest
	}
	return nil
}

func launchFingerprint(request StartRequest) string {
	hash := sha256.New()
	fmt.Fprintf(hash, "%s\x00%s\x00%s\x00", request.Program, request.Cwd, request.ClientKey)
	for _, argument := range request.Argv {
		fmt.Fprintf(hash, "%s\x00", argument)
	}
	keys := make([]string, 0, len(request.Environment))
	for key := range request.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(hash, "%s=%s\x00", key, request.Environment[key])
	}
	for _, key := range request.EnvironmentRemovals {
		fmt.Fprintf(hash, "-%s\x00", key)
	}
	secretKeys := make([]string, 0, len(request.SecretReferences))
	for key := range request.SecretReferences {
		secretKeys = append(secretKeys, key)
	}
	sort.Strings(secretKeys)
	for _, key := range secretKeys {
		fmt.Fprintf(hash, "secret:%s=%s\x00", key, request.SecretReferences[key])
	}
	fmt.Fprintf(hash, "limits:%d:%d\x00", request.Limits.OutputBufferBytes, request.Limits.MaxRuntimeMS)
	return hex.EncodeToString(hash.Sum(nil))
}

func validEnvironmentKey(key string) bool {
	return key != "" && len(key) <= MaxArgumentBytes && !strings.ContainsAny(key, "=\x00")
}

func (s *Supervisor) isRevokedLocked(owner Owner) bool {
	return s.revoked[owner.key()] || s.revokedPlugins[pluginEnvironmentKey(owner.PluginInstanceID, owner.EnvironmentScope)]
}

func (s *Supervisor) Start(ctx context.Context, owner Owner, request StartRequest) (Status, error) {
	if !owner.valid() {
		return Status{}, ErrInvalidRequest
	}
	if err := validateStart(request); err != nil {
		return Status{}, err
	}
	if s.options.Permission != nil {
		if err := s.options.Permission(ctx, owner); err != nil {
			return Status{}, ErrPermissionDenied
		}
	}

	clientID := owner.key() + "\x00" + request.ClientKey
	fingerprint := launchFingerprint(request)
	var reservation *startReservation
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return Status{}, ErrClosed
		}
		if s.isRevokedLocked(owner) {
			s.mu.Unlock()
			return Status{}, ErrRevoked
		}
		if handle := s.clients[clientID]; handle != "" {
			if existing := s.sessions[handle]; existing != nil {
				existing.mu.Lock()
				state := existing.status.State
				status := existing.status
				existing.mu.Unlock()
				if state != "exited" {
					s.mu.Unlock()
					if launchFingerprint(existing.request) != fingerprint {
						return Status{}, ErrLaunchConflict
					}
					return status, nil
				}
				delete(s.sessions, handle)
				if s.clients[clientID] == handle {
					delete(s.clients, clientID)
				}
				s.mu.Unlock()
				existing.finalizeTree()
				continue
			}
			delete(s.clients, clientID)
		}
		if existing := s.starting[clientID]; existing != nil {
			if existing.fingerprint != fingerprint {
				s.mu.Unlock()
				return Status{}, ErrLaunchConflict
			}
			wait := existing.done
			s.mu.Unlock()
			select {
			case <-wait:
				return existing.status, existing.err
			case <-ctx.Done():
				return Status{}, ctx.Err()
			}
		}
		reservation = &startReservation{done: make(chan struct{}), fingerprint: fingerprint}
		s.starting[clientID] = reservation
		s.mu.Unlock()
		break
	}

	finish := func(status Status, err error) {
		s.mu.Lock()
		reservation.status = status
		reservation.err = err
		delete(s.starting, clientID)
		close(reservation.done)
		s.mu.Unlock()
	}

	environment, err := s.childEnvironment(ctx, owner, request)
	if err != nil {
		finish(Status{}, err)
		return Status{}, err
	}
	command := exec.Command(request.Program, request.Argv...)
	command.Env = environment
	if request.Cwd != "" {
		command.Dir = request.Cwd
	}
	configureCommand(command)
	stdin, err := command.StdinPipe()
	if err != nil {
		finish(Status{}, ErrInvalidRequest)
		return Status{}, ErrInvalidRequest
	}
	bufferSize := request.Limits.OutputBufferBytes
	if bufferSize == 0 {
		bufferSize = defaultOutputBufferSize
	}
	stdoutBuffer := &streamBuffer{limit: bufferSize}
	stderrBuffer := &streamBuffer{limit: bufferSize}
	command.Stdout = streamWriter{buffer: stdoutBuffer}
	command.Stderr = streamWriter{buffer: stderrBuffer}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		finish(Status{}, err)
		return Status{}, err
	}
	tree, err := attachProcessTree(command)
	if err != nil {
		cleanupStartedProcess(tree, command)
		finish(Status{}, err)
		return Status{}, err
	}
	handle := opaqueHandle(owner, request.ClientKey)
	process := &session{
		owner: owner, request: request, command: command, tree: tree, stdin: stdin,
		stdout: stdoutBuffer, stderr: stderrBuffer,
		done: make(chan struct{}), status: Status{Handle: handle, ClientKey: request.ClientKey, State: "running"},
	}

	s.mu.Lock()
	closed := s.closed
	revoked := s.isRevokedLocked(owner)
	invalidated := closed || revoked
	if !invalidated {
		s.sessions[handle] = process
		s.clients[clientID] = handle
	}
	s.mu.Unlock()
	if invalidated {
		cleanupStartedProcess(tree, command)
		if closed {
			finish(Status{}, ErrClosed)
			return Status{}, ErrClosed
		}
		finish(Status{}, ErrRevoked)
		return Status{}, ErrRevoked
	}
	initialStatus := process.status
	finish(initialStatus, nil)
	go s.wait(process, request.Limits.MaxRuntimeMS)
	return initialStatus, nil
}

func cleanupStartedProcess(tree processTree, command *exec.Cmd) {
	_ = terminateProcessTree(tree, command, true)
	_ = command.Wait()
	closeProcessTree(tree)
}

func opaqueHandle(owner Owner, clientKey string) string {
	hash := sha256.Sum256([]byte(owner.key() + "\x00" + clientKey + "\x00" + time.Now().UTC().String()))
	return hex.EncodeToString(hash[:])
}

func (s *Supervisor) childEnvironment(ctx context.Context, owner Owner, request StartRequest) ([]string, error) {
	values := make(map[string]string, len(s.options.BaseEnvironment)+len(request.Environment)+len(request.SecretReferences))
	if len(s.options.BaseEnvironment) == 0 {
		values[normalizeEnvironmentKey("PATH")] = os.Getenv("PATH")
	}
	for _, entry := range s.options.BaseEnvironment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !validEnvironmentKey(key) || strings.IndexByte(value, 0) >= 0 {
			return nil, ErrInvalidRequest
		}
		normalized := normalizeEnvironmentKey(key)
		if _, exists := values[normalized]; exists {
			return nil, ErrInvalidRequest
		}
		values[normalized] = value
	}
	removed := make(map[string]struct{}, len(request.EnvironmentRemovals))
	for _, key := range request.EnvironmentRemovals {
		removed[normalizeEnvironmentKey(key)] = struct{}{}
	}
	for key := range removed {
		delete(values, key)
	}
	keys := make([]string, 0, len(request.Environment))
	for key := range request.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !validEnvironmentKey(key) || strings.IndexByte(request.Environment[key], 0) >= 0 {
			return nil, ErrInvalidRequest
		}
		normalized := normalizeEnvironmentKey(key)
		if _, exists := values[normalized]; exists {
			return nil, ErrInvalidRequest
		}
		if _, wasRemoved := removed[normalized]; wasRemoved {
			return nil, ErrInvalidRequest
		}
		values[normalized] = request.Environment[key]
	}
	keys = keys[:0]
	for key := range request.SecretReferences {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if s.options.Secrets == nil {
			return nil, ErrSecretUnavailable
		}
		value, err := s.options.Secrets(ctx, owner, request.SecretReferences[key])
		if err != nil {
			return nil, ErrSecretUnavailable
		}
		if !validEnvironmentKey(key) || strings.IndexByte(value, 0) >= 0 {
			return nil, ErrInvalidRequest
		}
		normalized := normalizeEnvironmentKey(key)
		if _, exists := values[normalized]; exists {
			return nil, ErrInvalidRequest
		}
		if _, wasRemoved := removed[normalized]; wasRemoved {
			return nil, ErrInvalidRequest
		}
		values[normalized] = value
	}
	if len(values) > MaxEnvironmentEntries {
		return nil, ErrInvalidRequest
	}
	keys = keys[:0]
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(values))
	totalBytes := 0
	for _, key := range keys {
		entry := key + "=" + values[key]
		totalBytes += len(entry)
		if totalBytes > MaxEnvironmentBytes {
			return nil, ErrInvalidRequest
		}
		environment = append(environment, entry)
	}
	return environment, nil
}

func (s *Supervisor) wait(process *session, maxRuntimeMS int) {
	result := make(chan error, 1)
	go func() { result <- process.command.Wait() }()
	var timer *time.Timer
	var timeout <-chan time.Time
	if maxRuntimeMS > 0 {
		timer = time.NewTimer(time.Duration(maxRuntimeMS) * time.Millisecond)
		timeout = timer.C
	}
	select {
	case err := <-result:
		process.setExit(err, "")
	case <-timeout:
		process.setExit(nil, "timeout")
		_ = terminateProcessTree(process.tree, process.command, true)
		<-result
	}
	if timer != nil {
		timer.Stop()
	}
	process.stdout.close()
	process.stderr.close()
	_ = process.stdin.Close()
	process.mu.Lock()
	process.status.State = "exited"
	process.status.ExitCode = process.exit.ExitCode
	process.status.TerminationReason = process.exit.TerminationReason
	close(process.done)
	process.mu.Unlock()
	process.finalizeTree()
}

func (process *session) finalizeTree() {
	process.cleanupOnce.Do(func() { closeProcessTree(process.tree) })
}

func (s *Supervisor) removeSession(process *session) {
	if process == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.sessions[process.status.Handle]; current == process {
		delete(s.sessions, process.status.Handle)
		clientID := process.owner.key() + "\x00" + process.request.ClientKey
		if s.clients[clientID] == process.status.Handle {
			delete(s.clients, clientID)
		}
	}
}

func (process *session) setExit(waitErr error, reason string) {
	process.mu.Lock()
	defer process.mu.Unlock()
	if reason == "" {
		reason = process.terminationReason
		if reason == "" {
			reason = "exited"
		}
	}
	process.exit.TerminationReason = reason
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		code := exitErr.ExitCode()
		process.exit.ExitCode = &code
	} else if waitErr == nil {
		code := 0
		process.exit.ExitCode = &code
	}
}

func (s *Supervisor) session(owner Owner, handle string) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	process := s.sessions[handle]
	if process == nil || process.owner != owner || s.revoked[owner.key()] || s.revokedPlugins[pluginEnvironmentKey(owner.PluginInstanceID, owner.EnvironmentScope)] {
		return nil, ErrNotFound
	}
	return process, nil
}

func (s *Supervisor) Attach(owner Owner, clientKey string) (Status, error) {
	if !owner.valid() || clientKey == "" || len(clientKey) > MaxClientKeyBytes || strings.IndexByte(clientKey, 0) >= 0 {
		return Status{}, ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked[owner.key()] || s.revokedPlugins[pluginEnvironmentKey(owner.PluginInstanceID, owner.EnvironmentScope)] {
		return Status{}, ErrRevoked
	}
	process := s.sessions[s.clients[owner.key()+"\x00"+clientKey]]
	if process == nil {
		return Status{}, ErrNotFound
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.status, nil
}

func (s *Supervisor) GetStatus(owner Owner, handle string) (Status, error) {
	process, err := s.session(owner, handle)
	if err != nil {
		return Status{}, err
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.status, nil
}

func (s *Supervisor) WriteStdin(ctx context.Context, owner Owner, handle string, data []byte) (int, error) {
	if len(data) > MaxStdinBytes {
		return 0, ErrInvalidRequest
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	process, err := s.session(owner, handle)
	if err != nil {
		return 0, err
	}
	process.stdinMu.Lock()
	defer process.stdinMu.Unlock()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	return process.stdin.Write(data)
}

func (s *Supervisor) CloseStdin(owner Owner, handle string) error {
	process, err := s.session(owner, handle)
	if err != nil {
		return err
	}
	return process.stdin.Close()
}

func (s *Supervisor) Read(ctx context.Context, owner Owner, handle string, stream Stream, request ReadRequest) (ReadResult, error) {
	process, err := s.session(owner, handle)
	if err != nil {
		return ReadResult{}, err
	}
	process.mu.Lock()
	exited := process.status.State == "exited"
	process.mu.Unlock()
	switch stream {
	case Stdout:
		return process.stdout.read(request, exited)
	case Stderr:
		return process.stderr.read(request, exited)
	default:
		return ReadResult{}, ErrInvalidRequest
	}
}

func (s *Supervisor) Wait(ctx context.Context, owner Owner, handle string) (ExitResult, error) {
	process, err := s.session(owner, handle)
	if err != nil {
		return ExitResult{}, err
	}
	select {
	case <-process.done:
		process.mu.Lock()
		defer process.mu.Unlock()
		return process.exit, nil
	case <-ctx.Done():
		return ExitResult{}, ctx.Err()
	}
}

func (s *Supervisor) Terminate(ctx context.Context, owner Owner, handle string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	process, err := s.session(owner, handle)
	if err != nil {
		return err
	}
	process.mu.Lock()
	process.terminationReason = "terminated"
	process.mu.Unlock()
	return terminateProcessTree(process.tree, process.command, false)
}

func (s *Supervisor) Kill(owner Owner, handle string) error {
	process, err := s.session(owner, handle)
	if err != nil {
		return err
	}
	process.mu.Lock()
	process.terminationReason = "killed"
	process.mu.Unlock()
	return terminateProcessTree(process.tree, process.command, true)
}

func (s *Supervisor) closeSession(ctx context.Context, process *session) error {
	process.mu.Lock()
	if process.status.State != "exited" {
		process.terminationReason = "closed"
	}
	process.mu.Unlock()
	_ = terminateProcessTree(process.tree, process.command, false)
	timer := time.NewTimer(s.options.GracePeriod)
	defer timer.Stop()
	select {
	case <-process.done:
	case <-timer.C:
		_ = terminateProcessTree(process.tree, process.command, true)
		select {
		case <-process.done:
		case <-ctx.Done():
			_ = terminateProcessTree(process.tree, process.command, true)
			<-process.done
			process.finalizeTree()
			return ctx.Err()
		}
	case <-ctx.Done():
		_ = terminateProcessTree(process.tree, process.command, true)
		<-process.done
		process.finalizeTree()
		return ctx.Err()
	}
	process.finalizeTree()
	return nil
}

func (s *Supervisor) Close(ctx context.Context, owner Owner, handle string) error {
	process, err := s.session(owner, handle)
	if err != nil {
		return err
	}
	if err := s.closeSession(ctx, process); err != nil {
		return err
	}
	s.removeSession(process)
	return nil
}

func (s *Supervisor) Revoke(ctx context.Context, owner Owner) error {
	if !owner.valid() {
		return ErrInvalidRequest
	}
	s.mu.Lock()
	s.revoked[owner.key()] = true
	owned := make([]*session, 0)
	for _, process := range s.sessions {
		if process.owner == owner {
			owned = append(owned, process)
		}
	}
	s.mu.Unlock()
	var joined error
	for _, process := range owned {
		if err := s.closeSession(ctx, process); err != nil {
			joined = errors.Join(joined, err)
		}
		s.removeSession(process)
	}
	return joined
}

func (s *Supervisor) RevokePlugin(ctx context.Context, pluginInstanceID, environmentScope string) error {
	if pluginInstanceID == "" || environmentScope == "" {
		return ErrInvalidRequest
	}
	pluginKey := pluginEnvironmentKey(pluginInstanceID, environmentScope)
	s.mu.Lock()
	s.revokedPlugins[pluginKey] = true
	owned := make([]*session, 0)
	for _, process := range s.sessions {
		if process.owner.PluginInstanceID == pluginInstanceID && process.owner.EnvironmentScope == environmentScope {
			owned = append(owned, process)
		}
	}
	s.mu.Unlock()
	var joined error
	for _, process := range owned {
		if err := s.closeSession(ctx, process); err != nil {
			joined = errors.Join(joined, err)
		}
		s.removeSession(process)
	}
	return joined
}

func (s *Supervisor) RestorePlugin(pluginInstanceID, environmentScope string) error {
	if pluginInstanceID == "" || environmentScope == "" {
		return ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	delete(s.revokedPlugins, pluginEnvironmentKey(pluginInstanceID, environmentScope))
	return nil
}

func (s *Supervisor) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	owned := make([]*session, 0, len(s.sessions))
	for _, process := range s.sessions {
		owned = append(owned, process)
	}
	s.mu.Unlock()
	var joined error
	for _, process := range owned {
		if err := s.closeSession(ctx, process); err != nil {
			joined = errors.Join(joined, err)
		}
		s.removeSession(process)
	}
	return joined
}
