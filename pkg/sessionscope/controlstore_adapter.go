package sessionscope

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
)

// ControlRecord is the complete durable session fence representation shared
// with Host's single control database.
type ControlRecord struct {
	Scope               sessionctx.SessionScope `json:"scope"`
	State               State                   `json:"state"`
	Counts              Counts                  `json:"counts"`
	TeardownOperationID string                  `json:"teardown_operation_id"`
	ProofSHA256         []byte                  `json:"proof_sha256"`
	CreatedAt           time.Time               `json:"created_at"`
	UpdatedAt           time.Time               `json:"updated_at"`
	Phases              map[Phase]Counts        `json:"phases,omitempty"`
}

// ControlStore is the atomic persistence boundary supplied by Host's single
// control database. The adapter retains sessionscope's state-machine policy.
type ControlStore interface {
	GetSessionControlRecord(context.Context, sessionctx.SessionScope) (ControlRecord, error)
	ListSessionControlRecords(context.Context) ([]ControlRecord, error)
	BeginSessionControlTeardown(context.Context, ControlRecord, int) (ControlRecord, error)
	AccumulateSessionControl(context.Context, sessionctx.SessionScope, Counts, time.Time) (ControlRecord, error)
	AccumulateSessionControlPhase(context.Context, sessionctx.SessionScope, Phase, Counts, time.Time) (ControlRecord, error)
	TransitionSessionControl(context.Context, sessionctx.SessionScope, State, State, time.Time) (ControlRecord, error)
	FinalizeSessionControl(context.Context, sessionctx.SessionScope, string, []byte) error
}

type controlStoreAdapter struct {
	backend ControlStore
	options StoreOptions
}

func NewControlStore(backend ControlStore, options StoreOptions) (Store, error) {
	if backend == nil {
		return nil, ErrStoreRequired
	}
	normalized, err := normalizeStoreOptions(options)
	if err != nil {
		return nil, err
	}
	return &controlStoreAdapter{backend: backend, options: normalized}, nil
}

func (*controlStoreAdapter) Durable() bool { return true }

func (s *controlStoreAdapter) Get(ctx context.Context, scope sessionctx.SessionScope) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	value, err := s.backend.GetSessionControlRecord(ctx, scope)
	if err != nil {
		return record{}, err
	}
	return recordFromControl(value)
}

func (s *controlStoreAdapter) ListRetained(ctx context.Context) ([]record, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	values, err := s.backend.ListSessionControlRecords(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]record, 0, len(values))
	for _, value := range values {
		current, err := recordFromControl(value)
		if err != nil {
			return nil, err
		}
		result = append(result, current)
	}
	return result, nil
}

func (s *controlStoreAdapter) BeginTeardown(ctx context.Context, scope sessionctx.SessionScope, operationID string, proof [sha256.Size]byte, now time.Time) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	if !validTeardownOperationID(operationID) {
		return record{}, ErrTeardownIdentityInvalid
	}
	now = normalizedStoreTime(now)
	value, err := s.backend.BeginSessionControlTeardown(ctx, ControlRecord{Scope: scope, State: StateDraining, TeardownOperationID: operationID, ProofSHA256: append([]byte(nil), proof[:]...), CreatedAt: now, UpdatedAt: now}, s.options.MaxScopes)
	if err != nil {
		return record{}, err
	}
	return recordFromControl(value)
}

func (s *controlStoreAdapter) Accumulate(ctx context.Context, scope sessionctx.SessionScope, delta Counts, now time.Time) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	if !delta.Valid() {
		return record{}, ErrInvalidCounts
	}
	value, err := s.backend.AccumulateSessionControl(ctx, scope, delta, normalizedStoreTime(now))
	if err != nil {
		return record{}, err
	}
	return recordFromControl(value)
}

func (s *controlStoreAdapter) AccumulatePhase(ctx context.Context, scope sessionctx.SessionScope, phase Phase, delta Counts, now time.Time) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	if !phase.Valid() || !delta.Valid() {
		return record{}, ErrInvalidCounts
	}
	value, err := s.backend.AccumulateSessionControlPhase(ctx, scope, phase, delta, normalizedStoreTime(now))
	if err != nil {
		return record{}, err
	}
	return recordFromControl(value)
}

func (s *controlStoreAdapter) MarkIncomplete(ctx context.Context, scope sessionctx.SessionScope, now time.Time) (record, error) {
	return s.transition(ctx, scope, StateDraining, StateIncomplete, now, true)
}

func (s *controlStoreAdapter) MarkComplete(ctx context.Context, scope sessionctx.SessionScope, now time.Time) (record, error) {
	return s.transition(ctx, scope, StateDraining, StateComplete, now, false)
}

func (s *controlStoreAdapter) transition(ctx context.Context, scope sessionctx.SessionScope, expected, next State, now time.Time, allowReplay bool) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	value, err := s.backend.TransitionSessionControl(ctx, scope, expected, next, normalizedStoreTime(now))
	if allowReplay && errors.Is(err, ErrInvalidState) {
		current, getErr := s.Get(ctx, scope)
		if getErr == nil && current.State == next {
			return current, nil
		}
	}
	if !allowReplay && errors.Is(err, ErrInvalidState) {
		current, getErr := s.Get(ctx, scope)
		if getErr == nil && current.State == StateComplete {
			return current, nil
		}
	}
	if err != nil {
		return record{}, err
	}
	return recordFromControl(value)
}

func (s *controlStoreAdapter) Finalize(ctx context.Context, scope sessionctx.SessionScope, operationID string, proof [sha256.Size]byte) error {
	if err := validateStoreCall(ctx, scope); err != nil {
		return err
	}
	return s.backend.FinalizeSessionControl(ctx, scope, operationID, proof[:])
}

func recordFromControl(value ControlRecord) (record, error) {
	if value.Scope.Validate() != nil || !value.State.Valid() || !value.Counts.Valid() || !validTeardownOperationID(value.TeardownOperationID) || len(value.ProofSHA256) != sha256.Size || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() {
		return record{}, ErrInvalidState
	}
	var proof [sha256.Size]byte
	copy(proof[:], value.ProofSHA256)
	result := record{Scope: value.Scope, State: value.State, Counts: value.Counts, TeardownOperationID: value.TeardownOperationID, ProofSHA256: proof, HasProof: true, CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(), Phases: make(map[Phase]Counts, len(value.Phases))}
	for phase, counts := range value.Phases {
		if !phase.Valid() || !counts.Valid() {
			return record{}, ErrInvalidCounts
		}
		result.Phases[phase] = counts
	}
	return result, nil
}

var _ Store = (*controlStoreAdapter)(nil)
