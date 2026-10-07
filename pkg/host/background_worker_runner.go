package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/background"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// NewBackgroundWorkerRunner creates the platform-owned runner used by a Host
// when a host supplies BackgroundModule.RunnerFactory. The runner keeps the
// worker invocation in the WASM runtime and only exposes an opaque lifecycle
// handle to the background manager.
func NewBackgroundWorkerRunner(h *Host) (background.Runner, error) {
	if h == nil {
		return nil, errors.New("host is required")
	}
	return &backgroundWorkerRunner{host: h, sessions: make(map[string]*backgroundWorkerSession)}, nil
}

type backgroundWorkerRunner struct {
	host     *Host
	mu       sync.Mutex
	sessions map[string]*backgroundWorkerSession
}

type backgroundWorkerSession struct {
	session background.Session
	cancel  context.CancelFunc
	done    chan struct{}
}

func (r *backgroundWorkerRunner) Start(ctx context.Context, owner background.Owner, workerID string) (background.Session, error) {
	if r == nil || r.host == nil {
		return background.Session{}, errors.New("background runner is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return background.Session{}, err
	}
	authorizationContext := sessionctx.WithContext(ctx, backgroundSessionContext(owner))
	record, err := r.host.getPluginRecord(authorizationContext, owner.PluginInstanceID)
	if err != nil {
		return background.Session{}, err
	}
	if record.OwnerEnvHash != owner.EnvironmentScope {
		return background.Session{}, ErrOwnerScopeMismatch
	}
	if record.EnableState != registry.EnableEnabled {
		return background.Session{}, errors.New("plugin is not enabled")
	}
	if record.Manifest.Background == nil || record.Manifest.Background.WorkerID != workerID {
		return background.Session{}, fmt.Errorf("background worker %q is not declared as the plugin background entry", workerID)
	}
	if err := r.host.canRun(authorizationContext, record); err != nil {
		return background.Session{}, err
	}
	if err := r.host.pluginAuthorizationError(authorizationContext, record); err != nil {
		return background.Session{}, err
	}
	worker, ok := manifestWorker(record.Manifest, workerID)
	if !ok {
		return background.Session{}, fmt.Errorf("worker %q is not declared", workerID)
	}
	method, ok := backgroundWorkerMethod(record.Manifest, workerID)
	if !ok {
		return background.Session{}, fmt.Errorf("background worker %q has no declared worker method", workerID)
	}
	permissions, err := r.host.requiredPermissionsForMethod(record, method)
	if err != nil {
		return background.Session{}, err
	}
	if err := r.host.requireCurrentPermissionGrants(authorizationContext, record.PluginInstanceID, permissions); err != nil {
		return background.Session{}, err
	}
	if worker.Scope != "environment" {
		return background.Session{}, fmt.Errorf("background worker %q must use environment scope", workerID)
	}

	method.Execution = manifest.MethodExecutionOperation
	method.Confirmation = nil
	method.PreflightOnly = false
	method.CancelPolicy = &manifest.CancelPolicySpec{Cancelable: true, DisableBehavior: "cancel", UninstallBehavior: "cancel", AckTimeoutMS: 2000}
	backgroundContext, cancel := context.WithCancel(context.WithoutCancel(authorizationContext))
	backgroundContext = sessionctx.WithContext(backgroundContext, backgroundSessionContext(owner))
	handle := backgroundHandle(owner, workerID)
	session := background.Session{Handle: handle, Owner: owner, WorkerID: workerID}
	entry := &backgroundWorkerSession{session: session, cancel: cancel, done: make(chan struct{})}
	r.mu.Lock()
	if existing := r.sessions[handle]; existing != nil {
		r.mu.Unlock()
		cancel()
		return existing.session, nil
	}
	r.sessions[handle] = entry
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			if current := r.sessions[handle]; current == entry {
				delete(r.sessions, handle)
			}
			r.mu.Unlock()
			close(entry.done)
		}()
		request := CallMethodRequest{
			PluginInstanceID: owner.PluginInstanceID,
			Method:           method.Method,
			Params:           map[string]any{},
			session:          backgroundSessionContext(owner),
			Now:              time.Now().UTC(),
		}
		dispatch, invokeErr := r.host.invokeWorker(backgroundContext, record, method, request)
		if dispatch.finish != nil {
			if invokeErr != nil {
				invokeErr = errors.Join(invokeErr, dispatch.finish(false, invokeErr))
			} else {
				invokeErr = dispatch.finish(true, nil)
			}
		}
		if invokeErr != nil && !errors.Is(invokeErr, context.Canceled) {
			r.host.reportLifecycleDiagnostic(
				context.WithoutCancel(backgroundContext),
				record,
				"plugin.background.failed",
				"plugin background worker stopped unexpectedly",
				invokeErr,
				observability.DiagnosticDetails{Method: method.Method, Operation: "background_worker"},
			)
		}
	}()
	return session, nil
}

func (r *backgroundWorkerRunner) Done(session background.Session) <-chan struct{} {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry := r.sessions[session.Handle]; entry != nil {
		return entry.done
	}
	done := make(chan struct{})
	close(done)
	return done
}

func (r *backgroundWorkerRunner) Stop(ctx context.Context, session background.Session) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	entry := r.sessions[session.Handle]
	if entry != nil {
		delete(r.sessions, session.Handle)
	}
	r.mu.Unlock()
	if entry == nil {
		return nil
	}
	entry.cancel()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-entry.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func backgroundWorkerMethod(pluginManifest manifest.Manifest, workerID string) (manifest.MethodSpec, bool) {
	for _, method := range pluginManifest.Methods {
		if method.Route.Kind == manifest.MethodRouteWorker && method.Route.WorkerID == workerID {
			return method, true
		}
	}
	return manifest.MethodSpec{}, false
}

func backgroundSessionContext(owner background.Owner) sessionctx.Context {
	seed := owner.PluginInstanceID + "\x00" + owner.EnvironmentScope
	return sessionctx.Context{
		OwnerSessionHash:     "background-session-" + shortBackgroundHash(seed),
		OwnerUserHash:        "background",
		OwnerEnvHash:         owner.EnvironmentScope,
		SessionChannelIDHash: "background-channel-" + shortBackgroundHash(seed),
		CanRead:              true,
		CanWrite:             true,
	}
}

func backgroundHandle(owner background.Owner, workerID string) string {
	return "background-" + shortBackgroundHash(owner.PluginInstanceID+"\x00"+owner.EnvironmentScope+"\x00"+workerID)
}

func shortBackgroundHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:12])
}
