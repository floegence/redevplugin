package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	processruntime "github.com/floegence/redevplugin/v3/pkg/process"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// CapabilityProcess provides bounded byte streams for a trusted capability
// adapter, under the original execution plus an explicit process.local grant.
// It never exposes a process handle to the plugin or extends the original lease.
// This is an external tool process, not a native plugin backend.
type CapabilityProcess struct {
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	Stderr io.ReadCloser
	close  func() error
}

func (p *CapabilityProcess) Close() error { return p.close() }

// OpenCapabilityProcess retains a platform-issued binding. The host adapter
// owns protocol framing and component selection; Host owns process admission,
// current grants, quotas, revocation, audit and teardown. Do not pass a binding
// supplied by a plugin. Launch errors never imply that retrying is safe.
func (h *Host) OpenCapabilityProcess(ctx context.Context, source capability.ExecutionBinding, request processruntime.StartRequest) (*CapabilityProcess, error) {
	if h == nil || h.processSupervisor == nil || request.ClientKey == "" || len(request.ClientKey) > processruntime.MaxClientKeyBytes || strings.ContainsRune(request.ClientKey, 0) {
		return nil, ErrActionDenied
	}
	source, err := capability.CloneExecutionBinding(source)
	if err != nil {
		return nil, err
	}
	scope, err := requireUserSession(ctx)
	if err != nil || !scope.CanWrite || !sameSurfaceOwner(scope, sessionctx.Context{OwnerSessionHash: source.OwnerSessionHash, OwnerUserHash: source.OwnerUserHash, OwnerEnvHash: source.OwnerEnvHash, SessionChannelIDHash: source.SessionChannelIDHash}) {
		return nil, ErrActionDenied
	}
	validate := func(ctx context.Context) error { return h.validateCapabilityProcess(ctx, source) }
	if err := validate(ctx); err != nil {
		return nil, err
	}
	record, err := h.getPluginRecord(ctx, source.PluginInstanceID)
	if err != nil || record.Manifest.Process == nil {
		return nil, ErrActionDenied
	}
	declared := record.Manifest.Process.ResourceLimits
	if err := applyProcessLimits(&request, &processruntime.ResourceLimits{OutputBufferBytes: declared.OutputBufferBytes, MaxRuntimeMS: declared.MaxRuntimeMS}); err != nil {
		return nil, err
	}
	if !source.Quota.ExpiresAt.IsZero() {
		remaining := int(time.Until(source.Quota.ExpiresAt).Milliseconds())
		if remaining <= 0 {
			return nil, capability.ErrExecutionRevoked
		}
		if request.Limits.MaxRuntimeMS == 0 || request.Limits.MaxRuntimeMS > remaining {
			request.Limits.MaxRuntimeMS = remaining
		}
	}
	key := sha256.Sum256([]byte(source.InvocationID + "\x00" + request.ClientKey))
	request.ClientKey = "capability:" + hex.EncodeToString(key[:])
	h.capabilityProcessesMu.Lock()
	if h.capabilityProcesses == nil {
		h.capabilityProcesses = map[string]string{}
	}
	count := 0
	for _, installation := range h.capabilityProcesses {
		if installation == source.PluginInstanceID {
			count++
		}
	}
	if _, exists := h.capabilityProcesses[request.ClientKey]; exists || count >= 4 || len(h.capabilityProcesses) >= 32 {
		h.capabilityProcessesMu.Unlock()
		return nil, processruntime.ErrLaunchConflict
	}
	h.capabilityProcesses[request.ClientKey] = source.PluginInstanceID
	h.capabilityProcessesMu.Unlock()
	release := func() {
		h.capabilityProcessesMu.Lock()
		delete(h.capabilityProcesses, request.ClientKey)
		h.capabilityProcessesMu.Unlock()
	}
	owner := processruntime.Owner{PluginInstanceID: source.PluginInstanceID, UserScope: source.OwnerUserHash, EnvironmentScope: source.OwnerEnvHash, SessionScope: source.OwnerSessionHash, ChannelScope: source.SessionChannelIDHash}
	h.lifecycleMu.RLock()
	if h.closed {
		h.lifecycleMu.RUnlock()
		release()
		return nil, ErrHostClosed
	}
	h.lifecycleWG.Add(1)
	h.lifecycleMu.RUnlock()
	lifetime, cancel := context.WithCancel(ctx)
	stopHost := context.AfterFunc(h.lifecycleCtx, cancel)
	status, err := h.processSupervisor.Start(lifetime, owner, request)
	if err != nil {
		stopHost()
		cancel()
		release()
		h.lifecycleWG.Done()
		return nil, mutation.Unknown(err)
	}
	var once sync.Once
	var closeErr error
	close := func() error {
		once.Do(func() {
			stopHost()
			cancel()
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer done()
			closeErr = h.processSupervisor.Close(cleanup, owner, status.Handle)
			if errors.Is(closeErr, processruntime.ErrNotFound) {
				closeErr = nil
			}
			closeErr = errors.Join(closeErr, h.recordSecurityEvent(cleanup, AuditEvent{Type: "plugin.capability.process.closed", PluginID: source.PluginID, PluginInstanceID: source.PluginInstanceID, Details: map[string]any{"invocation_id": source.InvocationID}}))
			release()
			h.lifecycleWG.Done()
		})
		return closeErr
	}
	if err := validate(ctx); err != nil {
		_ = close()
		return nil, mutation.Unknown(err)
	}
	if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.capability.process.started", PluginID: source.PluginID, PluginInstanceID: source.PluginInstanceID, Details: map[string]any{"invocation_id": source.InvocationID}}); err != nil {
		_ = close()
		return nil, mutation.Unknown(err)
	}
	reader := func(stream processruntime.Stream) *capabilityProcessReader {
		return &capabilityProcessReader{ctx: lifetime, supervisor: h.processSupervisor, owner: owner, handle: status.Handle, stream: stream, validate: validate, close: close}
	}
	out := &CapabilityProcess{Stdout: reader(processruntime.Stdout), Stderr: reader(processruntime.Stderr), Stdin: &capabilityProcessWriter{ctx: lifetime, supervisor: h.processSupervisor, owner: owner, handle: status.Handle, validate: validate}, close: close}
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		defer func() { _ = close() }()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
				if validate(lifetime) != nil {
					return
				}
			}
		}
	}()
	return out, nil
}

func (h *Host) validateCapabilityProcess(ctx context.Context, source capability.ExecutionBinding) error {
	if err := h.validateCapabilityResourceSource(ctx, source); err != nil {
		return err
	}
	record, err := h.getPluginRecord(ctx, source.PluginInstanceID)
	if err != nil || record.Manifest.Process == nil {
		return ErrActionDenied
	}
	decision, err := h.authorizePlugin(ctx, registry.AuthorizeRequest{PluginInstanceID: source.PluginInstanceID, Method: source.Method, PermissionIDs: []string{string(manifest.PermissionProcessLocal)}, Expected: registry.AuthorizationRevisions{PolicyRevision: source.Revision.PolicyRevision, ManagementRevision: source.Revision.ManagementRevision, RevokeEpoch: source.Revision.RevokeEpoch}})
	if err != nil {
		return err
	}
	if err := authorizationDecisionError(decision, source.Method); err != nil {
		return err
	}
	return ctx.Err()
}

func (h *Host) validateCapabilitySurface(source capability.ExecutionBinding) error {
	if source.SurfaceInstanceID != "" {
		bound, err := h.surfaceTokens.InspectBoundSurface(bridge.InspectBoundSurfaceRequest{SurfaceInstanceID: source.SurfaceInstanceID, BridgeChannelID: source.BridgeChannelID, OwnerSessionHash: source.OwnerSessionHash, OwnerUserHash: source.OwnerUserHash, OwnerEnvHash: source.OwnerEnvHash, SessionChannelIDHash: source.SessionChannelIDHash})
		if err != nil {
			return err
		}
		if bound.PluginInstanceID != source.PluginInstanceID || bound.ActiveFingerprint != source.ActiveFingerprint {
			return capability.ErrExecutionRevoked
		}
		if err := h.requireSurfaceGeneration(bound.Audience.SurfaceInstanceID, bound.Audience.RuntimeGenerationID, time.Time{}); err != nil {
			return err
		}
	}
	return nil
}

type capabilityProcessReader struct {
	ctx        context.Context
	supervisor *processruntime.Supervisor
	owner      processruntime.Owner
	handle     string
	stream     processruntime.Stream
	cursor     uint64
	mu         sync.Mutex
	validate   func(context.Context) error
	close      func() error
}

func (r *capabilityProcessReader) Read(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(data) == 0 {
		return 0, nil
	}
	for {
		if err := r.validate(r.ctx); err != nil {
			return 0, err
		}
		result, err := r.supervisor.Read(r.ctx, r.owner, r.handle, r.stream, processruntime.ReadRequest{Cursor: r.cursor, MaxBytes: min(len(data), 256<<10)})
		if err != nil {
			return 0, err
		}
		if result.StreamGap {
			return 0, errors.New("process byte stream exceeded its buffer; continuation is unavailable")
		}
		if err := r.validate(r.ctx); err != nil {
			return 0, err
		}
		r.cursor = result.Cursor
		if len(result.Data) > 0 {
			return copy(data, result.Data), nil
		}
		if result.EOF {
			return 0, io.EOF
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return 0, r.ctx.Err()
		case <-timer.C:
		}
	}
}
func (r *capabilityProcessReader) Close() error { return r.close() }

type capabilityProcessWriter struct {
	ctx        context.Context
	supervisor *processruntime.Supervisor
	owner      processruntime.Owner
	handle     string
	validate   func(context.Context) error
}

func (w *capabilityProcessWriter) Write(data []byte) (int, error) {
	if err := w.validate(w.ctx); err != nil {
		return 0, err
	}
	return w.supervisor.WriteStdin(w.ctx, w.owner, w.handle, data)
}
func (w *capabilityProcessWriter) Close() error { return w.supervisor.CloseStdin(w.owner, w.handle) }
