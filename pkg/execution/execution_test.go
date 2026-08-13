package execution

import (
	"errors"
	"testing"
	"time"
)

func TestExecutionAndEventHaveOnePublicIdentity(t *testing.T) {
	exec := Execution{ID: "exec-1", PluginInstanceID: "plugin-1", Kind: KindSubscription, Status: StatusRunning}
	event, err := NewEvent(exec, 1, EventData, map[string]any{"value": "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if event.ExecutionID != exec.ID {
		t.Fatalf("event identity = %q, want %q", event.ExecutionID, exec.ID)
	}
	if err := exec.Append(event); err != nil {
		t.Fatal(err)
	}
	if exec.Cursor != 1 {
		t.Fatalf("cursor = %d, want 1", exec.Cursor)
	}
	if err := exec.Append(event); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("duplicate sequence error = %v, want ErrSequenceConflict", err)
	}
}

func TestExecutionCancelAndTerminalStateMachine(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	exec, err := New(Execution{ID: "exec-1", PluginInstanceID: "plugin-1", Kind: KindOperation, Cancelable: true, Status: StatusRunning})
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.RequestCancel(now); err != nil {
		t.Fatal(err)
	}
	if exec.Status != StatusCancelRequested || exec.CancelRequestedAt == nil || !exec.CancelRequestedAt.Equal(now) {
		t.Fatalf("cancel state = %#v", exec)
	}
	if err := exec.RequestCancel(now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("duplicate cancel error = %v", err)
	}
	terminal, err := NewEvent(exec, 1, EventTerminal, map[string]any{"status": StatusCanceled})
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Finish(StatusCanceled, "", terminal, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if exec.Status != StatusCanceled || exec.Cursor != 1 || exec.TerminalAt == nil {
		t.Fatalf("terminal state = %#v", exec)
	}
	if err := exec.Append(Event{ExecutionID: exec.ID, Sequence: 2, Kind: EventData}); !errors.Is(err, ErrTerminal) {
		t.Fatalf("append after terminal error = %v", err)
	}
}

func TestExecutionRejectsInvalidTransitionAndTerminalEnvelope(t *testing.T) {
	exec, err := New(Execution{ID: "exec-1", PluginInstanceID: "plugin-1", Kind: KindSubscription, Status: StatusRunning})
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.RequestCancel(time.Now()); !errors.Is(err, ErrNotCancelable) {
		t.Fatalf("RequestCancel() error = %v, want ErrNotCancelable", err)
	}
	data, _ := NewEvent(exec, 1, EventData, nil)
	if err := exec.Finish(StatusCompleted, "", data, time.Now()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Finish(data event) error = %v", err)
	}
	terminal, _ := NewEvent(exec, 1, EventTerminal, nil)
	if err := exec.Append(terminal); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Append(terminal) error = %v", err)
	}
	if err := exec.Finish(StatusRunning, "", terminal, time.Now()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Finish(running) error = %v", err)
	}
}
