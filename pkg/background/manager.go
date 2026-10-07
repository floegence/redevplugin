package background

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrInvalidOwner = errors.New("BACKGROUND_INVALID_OWNER")
	ErrInvalidEntry = errors.New("BACKGROUND_INVALID_ENTRY")
	ErrNotFound     = errors.New("BACKGROUND_NOT_FOUND")
	ErrClosed       = errors.New("BACKGROUND_MANAGER_CLOSED")
)

type Owner struct {
	PluginInstanceID string
	UserScope        string
	EnvironmentScope string
}

func (owner Owner) valid() bool {
	return owner.PluginInstanceID != "" && owner.UserScope != "" && owner.EnvironmentScope != ""
}

func (owner Owner) key() string {
	return owner.PluginInstanceID + "\x00" + owner.UserScope + "\x00" + owner.EnvironmentScope
}

type Strategy string

const (
	RuntimeStart Strategy = "runtime_start"
	OnDemand     Strategy = "on_demand"
)

type Entry struct {
	WorkerID string
	Strategy Strategy
}

type Session struct {
	Handle   string
	Owner    Owner
	WorkerID string
}

type Runner interface {
	Start(context.Context, Owner, string) (Session, error)
	Stop(context.Context, Session) error
}

type CompletionWatcher interface {
	Done(Session) <-chan struct{}
}

type Manager struct {
	mu       sync.Mutex
	runner   Runner
	sessions map[string]Session
	starting map[string]*startAttempt
	closed   bool
}

type startAttempt struct {
	done    chan struct{}
	session Session
	err     error
}

func NewManager(runner Runner) (*Manager, error) {
	if runner == nil {
		return nil, ErrInvalidEntry
	}
	return &Manager{runner: runner, sessions: make(map[string]Session), starting: make(map[string]*startAttempt)}, nil
}

func validateEntry(entry Entry) error {
	if entry.WorkerID == "" || (entry.Strategy != RuntimeStart && entry.Strategy != OnDemand) {
		return ErrInvalidEntry
	}
	return nil
}

func sessionKey(owner Owner, workerID string) string {
	return owner.key() + "\x00" + workerID
}

func (manager *Manager) Start(ctx context.Context, owner Owner, entry Entry) (Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !owner.valid() {
		return Session{}, ErrInvalidOwner
	}
	if err := validateEntry(entry); err != nil {
		return Session{}, err
	}
	key := sessionKey(owner, entry.WorkerID)
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return Session{}, ErrClosed
	}
	if existing, ok := manager.sessions[key]; ok {
		manager.mu.Unlock()
		return existing, nil
	}
	if attempt := manager.starting[key]; attempt != nil {
		manager.mu.Unlock()
		select {
		case <-attempt.done:
			return attempt.session, attempt.err
		case <-ctx.Done():
			return Session{}, ctx.Err()
		}
	}
	attempt := &startAttempt{done: make(chan struct{})}
	manager.starting[key] = attempt
	manager.mu.Unlock()

	session, err := manager.runner.Start(ctx, owner, entry.WorkerID)
	valid := err == nil && session.Handle != "" && session.Owner == owner && session.WorkerID == entry.WorkerID
	if err == nil && !valid {
		err = fmt.Errorf("%w: runner returned an invalid session", ErrInvalidEntry)
	}
	var stopSession *Session
	manager.mu.Lock()
	delete(manager.starting, key)
	if err == nil {
		switch {
		case manager.closed:
			err = ErrClosed
			stopSession = &session
		case manager.sessions[key].Handle != "":
			existing := manager.sessions[key]
			session = existing
		default:
			manager.sessions[key] = session
		}
	}
	if err != nil && session.Handle != "" {
		stopSession = &session
		session = Session{}
	}
	attempt.session = session
	attempt.err = err
	close(attempt.done)
	manager.mu.Unlock()
	if stopSession != nil {
		_ = manager.runner.Stop(ctx, *stopSession)
	}
	if err == nil {
		if watcher, ok := manager.runner.(CompletionWatcher); ok {
			go manager.watchCompletion(key, session, watcher.Done(session))
		}
	}
	return session, err
}

func (manager *Manager) watchCompletion(key string, session Session, done <-chan struct{}) {
	if done == nil {
		return
	}
	<-done
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if current, ok := manager.sessions[key]; ok && current == session {
		delete(manager.sessions, key)
	}
}

func (manager *Manager) Recover(ctx context.Context, owner Owner, entries []Entry) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for _, entry := range entries {
		if entry.Strategy != RuntimeStart {
			continue
		}
		if _, err := manager.Start(ctx, owner, entry); err != nil {
			return err
		}
	}
	return nil
}

func (manager *Manager) Get(owner Owner, workerID string) (Session, error) {
	if !owner.valid() || workerID == "" {
		return Session{}, ErrInvalidOwner
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	session, ok := manager.sessions[sessionKey(owner, workerID)]
	if !ok {
		return Session{}, ErrNotFound
	}
	return session, nil
}

func (manager *Manager) Stop(ctx context.Context, owner Owner, workerID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	session, err := manager.Get(owner, workerID)
	if err != nil {
		return err
	}
	if err := manager.runner.Stop(ctx, session); err != nil {
		return err
	}
	manager.mu.Lock()
	delete(manager.sessions, sessionKey(owner, workerID))
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) StopOwner(ctx context.Context, owner Owner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !owner.valid() {
		return ErrInvalidOwner
	}
	manager.mu.Lock()
	sessions := make([]Session, 0)
	for key, session := range manager.sessions {
		if key == sessionKey(owner, session.WorkerID) {
			sessions = append(sessions, session)
		}
	}
	manager.mu.Unlock()
	for _, session := range sessions {
		if err := manager.runner.Stop(ctx, session); err != nil {
			return err
		}
		manager.mu.Lock()
		delete(manager.sessions, sessionKey(owner, session.WorkerID))
		manager.mu.Unlock()
	}
	return nil
}

func (manager *Manager) StopPluginEnvironment(ctx context.Context, pluginInstanceID, environmentScope string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if pluginInstanceID == "" || environmentScope == "" {
		return ErrInvalidOwner
	}
	manager.mu.Lock()
	sessions := make([]Session, 0)
	for _, session := range manager.sessions {
		if session.Owner.PluginInstanceID == pluginInstanceID && session.Owner.EnvironmentScope == environmentScope {
			sessions = append(sessions, session)
		}
	}
	manager.mu.Unlock()
	var firstErr error
	for _, session := range sessions {
		if err := manager.runner.Stop(ctx, session); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		manager.mu.Lock()
		delete(manager.sessions, sessionKey(session.Owner, session.WorkerID))
		manager.mu.Unlock()
	}
	return firstErr
}

func (manager *Manager) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return nil
	}
	manager.closed = true
	sessions := make([]Session, 0, len(manager.sessions))
	for _, session := range manager.sessions {
		sessions = append(sessions, session)
	}
	starting := make([]*startAttempt, 0, len(manager.starting))
	for _, attempt := range manager.starting {
		starting = append(starting, attempt)
	}
	manager.mu.Unlock()
	var firstErr error
	for _, attempt := range starting {
		select {
		case <-attempt.done:
		case <-ctx.Done():
			if firstErr == nil {
				firstErr = ctx.Err()
			}
		}
	}
	for _, session := range sessions {
		if err := manager.runner.Stop(ctx, session); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	manager.mu.Lock()
	clear(manager.sessions)
	manager.mu.Unlock()
	return firstErr
}
