package background

import (
	"context"
	"errors"
	"testing"
)

type testRunner struct {
	starts int
	stops  int
}

func (runner *testRunner) Start(_ context.Context, owner Owner, workerID string) (Session, error) {
	runner.starts++
	return Session{Handle: "opaque", Owner: owner, WorkerID: workerID}, nil
}

func (runner *testRunner) Stop(_ context.Context, _ Session) error {
	runner.stops++
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
	if err != nil || first != second || runner.starts != 1 {
		t.Fatalf("idempotency: %#v %#v starts=%d err=%v", first, second, runner.starts, err)
	}
	if err := manager.StopOwner(context.Background(), owner); err != nil || runner.stops != 1 {
		t.Fatalf("stop owner: stops=%d err=%v", runner.stops, err)
	}
	if err := manager.Recover(context.Background(), owner, []Entry{{WorkerID: "on-demand", Strategy: OnDemand}, entry}); err != nil || runner.starts != 2 {
		t.Fatalf("recovery: starts=%d err=%v", runner.starts, err)
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

type invalidRunner struct{}

func (*invalidRunner) Start(context.Context, Owner, string) (Session, error) { return Session{}, nil }
func (*invalidRunner) Stop(context.Context, Session) error                   { return nil }
