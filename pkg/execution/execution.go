package execution

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	KindSync              = "sync"
	KindOperation         = "operation"
	KindSubscription      = "subscription"
	StatusRunning         = "running"
	StatusCancelRequested = "cancel_requested"
	StatusCompleted       = "completed"
	StatusCanceled        = "canceled"
	StatusFailed          = "failed"
	StatusOrphaned        = "orphaned"
	EventProgress         = "progress"
	EventData             = "data"
	EventDiagnostic       = "diagnostic"
	EventTerminal         = "terminal"
)

var (
	ErrSequenceConflict  = errors.New("execution event sequence conflict")
	ErrInvalidTransition = errors.New("execution state transition is invalid")
	ErrNotCancelable     = errors.New("execution is not cancelable")
	ErrTerminal          = errors.New("execution is terminal")
)

type Execution struct {
	ID                string     `json:"execution_id"`
	PluginInstanceID  string     `json:"plugin_instance_id"`
	Kind              string     `json:"kind"`
	Status            string     `json:"status"`
	Cursor            uint64     `json:"cursor"`
	FailureCode       string     `json:"failure_code,omitempty"`
	Cancelable        bool       `json:"cancelable"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	CancelRequestedAt *time.Time `json:"cancel_requested_at,omitempty"`
	TerminalAt        *time.Time `json:"terminal_at,omitempty"`
	events            map[uint64]Event
}

type Event struct {
	ExecutionID string         `json:"execution_id"`
	Sequence    uint64         `json:"sequence"`
	Kind        string         `json:"kind"`
	Payload     map[string]any `json:"payload,omitempty"`
	Error       *PublicError   `json:"error,omitempty"`
}

type PublicError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewEvent(exec Execution, sequence uint64, kind string, payload map[string]any) (Event, error) {
	if exec.ID == "" || sequence == 0 || !validEventKind(kind) {
		return Event{}, ErrSequenceConflict
	}
	return Event{ExecutionID: exec.ID, Sequence: sequence, Kind: kind, Payload: payload}, nil
}
func (e *Execution) Append(event Event) error {
	if event.Kind == EventTerminal {
		return ErrInvalidTransition
	}
	return e.append(event)
}

func (e *Execution) append(event Event) error {
	if e != nil && terminalStatus(e.Status) {
		return ErrTerminal
	}
	if e == nil || event.ExecutionID != e.ID || event.Sequence == 0 || event.Sequence != e.Cursor+1 {
		return ErrSequenceConflict
	}
	if e.events == nil {
		e.events = map[uint64]Event{}
	}
	if _, ok := e.events[event.Sequence]; ok {
		return ErrSequenceConflict
	}
	e.events[event.Sequence] = event
	e.Cursor = event.Sequence
	return nil
}

func New(value Execution) (Execution, error) {
	if value.Status == "" {
		value.Status = StatusRunning
	}
	if value.CreatedAt.IsZero() {
		value.CreatedAt = time.Now().UTC()
	}
	value.CreatedAt = value.CreatedAt.UTC()
	if value.UpdatedAt.IsZero() {
		value.UpdatedAt = value.CreatedAt
	}
	value.UpdatedAt = value.UpdatedAt.UTC()
	value.events = map[uint64]Event{}
	if err := value.Validate(); err != nil {
		return Execution{}, err
	}
	return value, nil
}

func (e *Execution) RequestCancel(now time.Time) error {
	if e == nil || e.Status != StatusRunning {
		return ErrInvalidTransition
	}
	if !e.Cancelable {
		return ErrNotCancelable
	}
	now = normalizedTime(now)
	e.Status = StatusCancelRequested
	e.CancelRequestedAt = &now
	e.UpdatedAt = now
	return nil
}

func (e *Execution) Finish(status, failureCode string, event Event, now time.Time) error {
	if e == nil || terminalStatus(e.Status) || !terminalStatus(status) || event.Kind != EventTerminal || event.ExecutionID != e.ID || event.Sequence != e.Cursor+1 {
		return ErrInvalidTransition
	}
	if status == StatusCanceled && e.Status != StatusCancelRequested {
		return ErrInvalidTransition
	}
	if status != StatusCanceled && e.Status != StatusRunning && e.Status != StatusCancelRequested {
		return ErrInvalidTransition
	}
	if err := e.append(event); err != nil {
		return err
	}
	now = normalizedTime(now)
	e.Status = status
	e.FailureCode = failureCode
	e.TerminalAt = &now
	e.UpdatedAt = now
	return nil
}

func (e Execution) EventsAfter(cursor uint64) []Event {
	result := make([]Event, 0)
	for sequence := cursor + 1; sequence <= e.Cursor; sequence++ {
		if event, ok := e.events[sequence]; ok {
			result = append(result, event)
		}
	}
	return result
}

func (e Event) MarshalJSON() ([]byte, error) { type alias Event; return json.Marshal(alias(e)) }
func (e Execution) Validate() error {
	if e.ID == "" || e.PluginInstanceID == "" {
		return fmt.Errorf("execution identity is required")
	}
	switch e.Kind {
	case KindSync, KindOperation, KindSubscription:
	default:
		return fmt.Errorf("unknown execution kind %q", e.Kind)
	}
	switch e.Status {
	case StatusRunning, StatusCancelRequested, StatusCompleted, StatusCanceled, StatusFailed, StatusOrphaned:
	default:
		return fmt.Errorf("unknown execution status %q", e.Status)
	}
	if e.Kind == KindSync && e.Cancelable {
		return fmt.Errorf("sync execution cannot be cancelable")
	}
	if e.Status == StatusCancelRequested && (!e.Cancelable || e.CancelRequestedAt == nil) {
		return ErrInvalidTransition
	}
	if terminalStatus(e.Status) && e.TerminalAt == nil {
		return ErrInvalidTransition
	}
	return nil
}

func validEventKind(kind string) bool {
	switch kind {
	case EventProgress, EventData, EventDiagnostic, EventTerminal:
		return true
	default:
		return false
	}
}

func terminalStatus(status string) bool {
	switch status {
	case StatusCompleted, StatusCanceled, StatusFailed, StatusOrphaned:
		return true
	default:
		return false
	}
}

func normalizedTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}
