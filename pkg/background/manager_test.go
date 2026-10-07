package background

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testRunner struct {
	mu     sync.Mutex
	starts int
	stops  int
	gate   chan struct{}
	done   chan struct{}
}

func (runner *testRunner) Start(ctx context.Context, owner Owner, workerID string) (Session, error) {
	if runner.gate != nil {
		select {
		case <-runner.gate:
		case <-ctx.Done():
			return Session{}, ctx.Err()
		}
	}
	runner.mu.Lock()
	runner.starts++
	if runner.done == nil {
		runner.done = make(chan struct{})
	}
	runner.mu.Unlock()
	return Session{Handle: "opaque", Owner: owner, WorkerID: workerID}, nil
}

func (runner *testRunner) Stop(_ context.Context, _ Session) error {
	runner.mu.Lock()
	runner.stops++
	runner.mu.Unlock()
	return nil
}

func (runner *testRunner) Done(Session) <-chan struct{} {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.done
}

func (runner *testRunner) counts() (starts, stops int) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.starts, runner.stops
}

func nilBackgroundContext() context.Context {
	return nil
}

func TestManagerIsIdempotentAndRecoversOnlyRuntimeStart(t *testing.T) {
	runner := &testRunner{}
	manager, err := NewManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	owner := Owner{PluginInstanceID: "plugin", UserScope: "user", EnvironmentScope: "environment"}
	entry := Entry{WorkerID: "background", Strategy: RuntimeStart}
	first, err := manager.Start(context.Background(), owner, entry)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Start(context.Background(), owner, entry)
	starts, _ := runner.counts()
	if err != nil || first != second || starts != 1 {
		t.Fatalf("idempotency: %#v %#v starts=%d err=%v", first, second, starts, err)
	}
	if err := manager.StopOwner(context.Background(), owner); err != nil {
		t.Fatalf("stop owner: err=%v", err)
	}
	_, stops := runner.counts()
	if stops != 1 {
		t.Fatalf("stop owner: stops=%d", stops)
	}
	if err := manager.Recover(context.Background(), owner, []Entry{{WorkerID: "on-demand", Strategy: OnDemand}, entry}); err != nil {
		t.Fatalf("recovery: err=%v", err)
	}
	starts, _ = runner.counts()
	if starts != 2 {
		t.Fatalf("recovery: starts=%d", starts)
	}
}

func TestManagerRejectsInvalidRunnerSessionAndStopsOnShutdown(t *testing.T) {
	manager, err := NewManager(&invalidRunner{})
	if err != nil {
		t.Fatal(err)
	}
	owner := Owner{PluginInstanceID: "plugin", UserScope: "user", EnvironmentScope: "environment"}
	if _, err := manager.Start(context.Background(), owner, Entry{WorkerID: "worker", Strategy: OnDemand}); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("invalid session error = %v", err)
	}
	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), owner, Entry{WorkerID: "worker", Strategy: OnDemand}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed manager error = %v", err)
	}
}

func TestManagerSerializesConcurrentStarts(t *testing.T) {
	runner := &testRunner{gate: make(chan struct{})}
	manager, err := NewManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	owner := Owner{PluginInstanceID: "plugin", UserScope: "user", EnvironmentScope: "environment"}
	entry := Entry{WorkerID: "background", Strategy: OnDemand}
	results := make(chan Session, 2)
	errorsOut := make(chan error, 2)
	for range 2 {
		go func() {
			session, startErr := manager.Start(context.Background(), owner, entry)
			results <- session
			errorsOut <- startErr
		}()
	}
	time.Sleep(10 * time.Millisecond)
	starts, _ := runner.counts()
	if starts != 0 {
		t.Fatal("runner started before the gate opened")
	}
	close(runner.gate)
	for range 2 {
		if err := <-errorsOut; err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-results, <-results
	starts, _ = runner.counts()
	if first != second || starts != 1 {
		t.Fatalf("concurrent starts = %#v, %#v, runner starts = %d", first, second, starts)
	}
}

func TestManagerReleasesCompletedSessionForRecovery(t *testing.T) {
	runner := &testRunner{}
	manager, err := NewManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	owner := Owner{PluginInstanceID: "plugin", UserScope: "user", EnvironmentScope: "environment"}
	entry := Entry{WorkerID: "background", Strategy: OnDemand}
	if _, err := manager.Start(context.Background(), owner, entry); err != nil {
		t.Fatal(err)
	}
	close(runner.done)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := manager.Get(owner, entry.WorkerID); errors.Is(err, ErrNotFound) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("completed background session was not released")
}

func TestManagerShutdownWaitsForInFlightStart(t *testing.T) {
	runner := &testRunner{gate: make(chan struct{})}
	manager, err := NewManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	owner := Owner{PluginInstanceID: "plugin", UserScope: "user", EnvironmentScope: "environment"}
	entry := Entry{WorkerID: "background", Strategy: RuntimeStart}
	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = manager.Start(context.Background(), owner, entry)
	}()
	<-started
	time.Sleep(10 * time.Millisecond)
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- manager.Shutdown(context.Background()) }()
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned while start was in flight")
	case <-time.After(10 * time.Millisecond):
	}
	close(runner.gate)
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
	_, stops := runner.counts()
	if stops != 1 {
		t.Fatalf("stops = %d, want 1", stops)
	}
}

func TestManagerAcceptsNilContexts(t *testing.T) {
	runner := &testRunner{}
	manager, err := NewManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	owner := Owner{PluginInstanceID: "plugin", UserScope: "user", EnvironmentScope: "environment"}
	entry := Entry{WorkerID: "background", Strategy: OnDemand}
	if _, err := manager.Start(nilBackgroundContext(), owner, entry); err != nil {
		t.Fatalf("Start(nil) error = %v", err)
	}
	if err := manager.Stop(nilBackgroundContext(), owner, entry.WorkerID); err != nil {
		t.Fatalf("Stop(nil) error = %v", err)
	}
	if err := manager.Shutdown(nilBackgroundContext()); err != nil {
		t.Fatalf("Shutdown(nil) error = %v", err)
	}
}

type invalidRunner struct{}

func (*invalidRunner) Start(context.Context, Owner, string) (Session, error) { return Session{}, nil }
func (*invalidRunner) Stop(context.Context, Session) error                   { return nil }
