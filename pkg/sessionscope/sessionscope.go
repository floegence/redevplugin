package sessionscope

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

const (
	DefaultMaxScopes = 4_096
	HardMaxScopes    = 65_536
	MinProofBytes    = 32
	MaxProofBytes    = MinProofBytes
)

var (
	ErrInvalidState              = errors.New("session scope state is invalid")
	ErrInvalidCounts             = errors.New("session scope counts are invalid")
	ErrSessionRevoked            = errors.New("session scope is revoked")
	ErrFenceCapacity             = errors.New("session fence capacity is exhausted")
	ErrScopeNotFound             = errors.New("session scope is not found")
	ErrClosedSessionProofInvalid = errors.New("closed session proof is invalid")
	ErrTeardownIdentityInvalid   = errors.New("session teardown identity is invalid")
	ErrTeardownIdentityMismatch  = errors.New("session teardown identity does not match")
	ErrStoreRequired             = errors.New("session scope store is required")
	ErrSchemaVersion             = errors.New("session scope schema version is unsupported")
)

var teardownOperationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

type State string

const (
	StateActive     State = "active"
	StateDraining   State = "draining"
	StateIncomplete State = "incomplete"
	StateComplete   State = "complete"
)

func (state State) Valid() bool {
	switch state {
	case StateActive, StateDraining, StateIncomplete, StateComplete:
		return true
	default:
		return false
	}
}

type Counts struct {
	Surfaces              uint64 `json:"surfaces"`
	AssetTickets          uint64 `json:"asset_tickets"`
	AssetSessions         uint64 `json:"asset_sessions"`
	PluginGatewayTokens   uint64 `json:"plugin_gateway_tokens"`
	ConfirmationTokens    uint64 `json:"confirmation_tokens"`
	StreamTickets         uint64 `json:"stream_tickets"`
	HandleGrants          uint64 `json:"handle_grants"`
	Confirmations         uint64 `json:"confirmations"`
	Operations            uint64 `json:"operations"`
	Streams               uint64 `json:"streams"`
	RuntimeExecutions     uint64 `json:"runtime_executions"`
	ActiveNetworkRequests uint64 `json:"active_network_requests"`
	Sockets               uint64 `json:"sockets"`
	NetworkStreams        uint64 `json:"network_streams"`
	StorageHostcalls      uint64 `json:"storage_hostcalls"`
}

type Phase string

const (
	PhaseBridge       Phase = "bridge"
	PhaseConfirmation Phase = "confirmation"
	PhaseExecution    Phase = "execution"
	PhaseOperation    Phase = "operation"
	PhaseStream       Phase = "stream"
	PhaseRuntime      Phase = "runtime"
)

func (phase Phase) Valid() bool {
	switch phase {
	case PhaseBridge, PhaseConfirmation, PhaseExecution, PhaseOperation, PhaseStream, PhaseRuntime:
		return true
	default:
		return false
	}
}

func (counts Counts) Add(delta Counts) (Counts, error) {
	left := reflect.ValueOf(&counts).Elem()
	right := reflect.ValueOf(delta)
	for index := 0; index < left.NumField(); index++ {
		current := left.Field(index).Uint()
		increase := right.Field(index).Uint()
		if increase > jsonvalue.MaxSafeInteger || current > jsonvalue.MaxSafeInteger-increase {
			return Counts{}, ErrInvalidCounts
		}
		left.Field(index).SetUint(current + increase)
	}
	return counts, nil
}

func (counts Counts) Valid() bool {
	value := reflect.ValueOf(counts)
	for index := 0; index < value.NumField(); index++ {
		if value.Field(index).Uint() > jsonvalue.MaxSafeInteger {
			return false
		}
	}
	return true
}

type Snapshot struct {
	State    State  `json:"state"`
	Fenced   bool   `json:"fenced"`
	Complete bool   `json:"complete"`
	Counts   Counts `json:"counts"`
}

// RetainedScope is the durable, owner-private startup reconciliation view for
// fenced session scopes. It never contains the teardown operation ID or proof.
type RetainedScope struct {
	SessionScope sessionctx.SessionScope `json:"-"`
	Snapshot     Snapshot                `json:"snapshot"`
	identityHash [sha256.Size]byte
	hasIdentity  bool
}

// MatchesIdentity verifies that a trusted host-side teardown identity is bound
// to this exact durable fence without exposing the operation ID or proof hash.
func (retained RetainedScope) MatchesIdentity(identity TeardownIdentity) bool {
	digest, err := identity.digest()
	if err != nil || !retained.hasIdentity {
		return false
	}
	binding := retainedIdentityHash(identity.OperationID, digest)
	return subtle.ConstantTimeCompare(retained.identityHash[:], binding[:]) == 1
}

func retainedIdentityHash(operationID string, proofSHA256 [sha256.Size]byte) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte("redevplugin-session-scope-retained-identity-v1\x00"))
	_, _ = digest.Write([]byte(operationID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(proofSHA256[:])
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

type record struct {
	Scope               sessionctx.SessionScope
	State               State
	Counts              Counts
	TeardownOperationID string
	ProofSHA256         [sha256.Size]byte
	HasProof            bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
	Phases              map[Phase]Counts
}

func (r record) snapshot() Snapshot {
	return Snapshot{
		State:    r.State,
		Fenced:   r.State != StateActive,
		Complete: r.State == StateComplete,
		Counts:   r.Counts,
	}
}

type StoreOptions struct {
	MaxScopes int
}

func normalizeStoreOptions(options StoreOptions) (StoreOptions, error) {
	if options.MaxScopes == 0 {
		options.MaxScopes = DefaultMaxScopes
	}
	if options.MaxScopes < 1 || options.MaxScopes > HardMaxScopes {
		return StoreOptions{}, fmt.Errorf("%w: max scopes must be between 1 and %d", ErrFenceCapacity, HardMaxScopes)
	}
	return options, nil
}

type Store interface {
	Durable() bool
	Get(context.Context, sessionctx.SessionScope) (record, error)
	ListRetained(context.Context) ([]record, error)
	BeginTeardown(context.Context, sessionctx.SessionScope, string, [sha256.Size]byte, time.Time) (record, error)
	Accumulate(context.Context, sessionctx.SessionScope, Counts, time.Time) (record, error)
	AccumulatePhase(context.Context, sessionctx.SessionScope, Phase, Counts, time.Time) (record, error)
	MarkIncomplete(context.Context, sessionctx.SessionScope, time.Time) (record, error)
	MarkComplete(context.Context, sessionctx.SessionScope, time.Time) (record, error)
	Finalize(context.Context, sessionctx.SessionScope, string, [sha256.Size]byte) error
}

type MemoryStore struct {
	mu      sync.Mutex
	options StoreOptions
	records map[sessionctx.SessionScope]record
}

func NewMemoryStore(options StoreOptions) (*MemoryStore, error) {
	normalized, err := normalizeStoreOptions(options)
	if err != nil {
		return nil, err
	}
	return &MemoryStore{options: normalized, records: make(map[sessionctx.SessionScope]record)}, nil
}

func (s *MemoryStore) Durable() bool { return false }

func (s *MemoryStore) Get(ctx context.Context, scope sessionctx.SessionScope) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[scope]
	if !ok {
		return record{}, ErrScopeNotFound
	}
	return current, nil
}

func (s *MemoryStore) ListRetained(ctx context.Context) ([]record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]record, 0, len(s.records))
	for _, current := range s.records {
		result = append(result, current)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].Scope, result[j].Scope
		if left.OwnerSessionHash != right.OwnerSessionHash {
			return left.OwnerSessionHash < right.OwnerSessionHash
		}
		if left.OwnerUserHash != right.OwnerUserHash {
			return left.OwnerUserHash < right.OwnerUserHash
		}
		if left.OwnerEnvHash != right.OwnerEnvHash {
			return left.OwnerEnvHash < right.OwnerEnvHash
		}
		return left.SessionChannelIDHash < right.SessionChannelIDHash
	})
	return result, nil
}

func (s *MemoryStore) BeginTeardown(
	ctx context.Context,
	scope sessionctx.SessionScope,
	operationID string,
	proof [sha256.Size]byte,
	now time.Time,
) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	if !validTeardownOperationID(operationID) {
		return record{}, ErrTeardownIdentityInvalid
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.records[scope]
	if !exists {
		if len(s.records) >= s.options.MaxScopes {
			return record{}, ErrFenceCapacity
		}
		current = record{
			Scope:               scope,
			State:               StateDraining,
			TeardownOperationID: operationID,
			ProofSHA256:         proof,
			HasProof:            true,
			CreatedAt:           now.UTC(),
			UpdatedAt:           now.UTC(),
		}
	} else {
		if !recordMatchesTeardownIdentity(current, operationID, proof) {
			return record{}, ErrTeardownIdentityMismatch
		}
		switch current.State {
		case StateIncomplete, StateDraining:
			current.State = StateDraining
			current.UpdatedAt = now.UTC()
		case StateComplete:
		default:
			return record{}, ErrInvalidState
		}
	}
	s.records[scope] = current
	return current, nil
}

func (s *MemoryStore) Accumulate(ctx context.Context, scope sessionctx.SessionScope, delta Counts, now time.Time) (record, error) {
	if !delta.Valid() {
		return record{}, ErrInvalidCounts
	}
	return s.transition(ctx, scope, now, func(current *record) error {
		if current.State != StateDraining {
			return ErrInvalidState
		}
		counts, err := current.Counts.Add(delta)
		if err != nil {
			return err
		}
		current.Counts = counts
		return nil
	})
}

func (s *MemoryStore) AccumulatePhase(ctx context.Context, scope sessionctx.SessionScope, phase Phase, delta Counts, now time.Time) (record, error) {
	if !phase.Valid() || !delta.Valid() {
		return record{}, ErrInvalidCounts
	}
	return s.transition(ctx, scope, now, func(current *record) error {
		if current.State != StateDraining {
			return ErrInvalidState
		}
		if _, ok := current.Phases[phase]; ok {
			return nil
		}
		counts, err := current.Counts.Add(delta)
		if err != nil {
			return err
		}
		if current.Phases == nil {
			current.Phases = make(map[Phase]Counts)
		}
		current.Phases[phase] = delta
		current.Counts = counts
		return nil
	})
}

func (s *MemoryStore) MarkIncomplete(ctx context.Context, scope sessionctx.SessionScope, now time.Time) (record, error) {
	return s.transition(ctx, scope, now, func(current *record) error {
		if current.State != StateDraining && current.State != StateIncomplete {
			return ErrInvalidState
		}
		current.State = StateIncomplete
		return nil
	})
}

func (s *MemoryStore) MarkComplete(ctx context.Context, scope sessionctx.SessionScope, now time.Time) (record, error) {
	return s.transition(ctx, scope, now, func(current *record) error {
		if current.State == StateComplete {
			return nil
		}
		if current.State != StateDraining {
			return ErrInvalidState
		}
		current.State = StateComplete
		return nil
	})
}

func (s *MemoryStore) Finalize(ctx context.Context, scope sessionctx.SessionScope, operationID string, proof [sha256.Size]byte) error {
	if err := validateStoreCall(ctx, scope); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[scope]
	if !ok || current.State != StateComplete || !recordMatchesTeardownIdentity(current, operationID, proof) {
		return ErrClosedSessionProofInvalid
	}
	delete(s.records, scope)
	return nil
}

func (s *MemoryStore) transition(ctx context.Context, scope sessionctx.SessionScope, now time.Time, apply func(*record) error) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[scope]
	if !ok {
		return record{}, ErrScopeNotFound
	}
	if err := apply(&current); err != nil {
		return record{}, err
	}
	current.UpdatedAt = now.UTC()
	s.records[scope] = current
	return current, nil
}

func validateStoreCall(ctx context.Context, scope sessionctx.SessionScope) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return scope.Validate()
}

type ClosedSessionProof struct {
	value []byte
}

type TeardownIdentity struct {
	OperationID string `json:"-"`
	proof       ClosedSessionProof
}

func NewTeardownIdentity(operationID string, proof ClosedSessionProof) (TeardownIdentity, error) {
	operationID = strings.TrimSpace(operationID)
	if !validTeardownOperationID(operationID) || !proof.Valid() {
		return TeardownIdentity{}, ErrTeardownIdentityInvalid
	}
	return TeardownIdentity{OperationID: operationID, proof: proof}, nil
}

func (identity TeardownIdentity) Valid() bool {
	return validTeardownOperationID(identity.OperationID) && identity.proof.Valid()
}

func (identity TeardownIdentity) Matches(other TeardownIdentity) bool {
	if !identity.Valid() || !other.Valid() || identity.OperationID != other.OperationID {
		return false
	}
	left, leftErr := identity.digest()
	right, rightErr := other.digest()
	return leftErr == nil && rightErr == nil && subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func (identity TeardownIdentity) digest() ([sha256.Size]byte, error) {
	if !identity.Valid() {
		return [sha256.Size]byte{}, ErrTeardownIdentityInvalid
	}
	return identity.proof.digest()
}

func validTeardownOperationID(operationID string) bool {
	return operationID == strings.TrimSpace(operationID) && teardownOperationIDPattern.MatchString(operationID)
}

func recordMatchesTeardownIdentity(current record, operationID string, proof [sha256.Size]byte) bool {
	return current.HasProof && current.TeardownOperationID == operationID &&
		subtle.ConstantTimeCompare(current.ProofSHA256[:], proof[:]) == 1
}

// GenerateClosedSessionProof creates a proof with 256 bits of operating-system
// CSPRNG entropy. Session lifecycle adapters use this function when creating a
// new closed-session tombstone.
func GenerateClosedSessionProof() (ClosedSessionProof, error) {
	value := make([]byte, MinProofBytes)
	if _, err := rand.Read(value); err != nil {
		return ClosedSessionProof{}, err
	}
	return ClosedSessionProof{value: value}, nil
}

// NewClosedSessionProof reconstructs a proof previously generated by
// GenerateClosedSessionProof from trusted durable host storage. Entropy cannot
// be inferred from bytes after generation, so untrusted payloads must never call
// this constructor.
func NewClosedSessionProof(value []byte) (ClosedSessionProof, error) {
	if len(value) < MinProofBytes || len(value) > MaxProofBytes {
		return ClosedSessionProof{}, ErrClosedSessionProofInvalid
	}
	return ClosedSessionProof{value: append([]byte(nil), value...)}, nil
}

func (proof ClosedSessionProof) Valid() bool {
	return len(proof.value) >= MinProofBytes && len(proof.value) <= MaxProofBytes
}

// BytesForDurableStorage returns an owned copy for the trusted host session
// adapter's private durable tombstone. It must never enter HTTP or plugin IPC.
func (proof ClosedSessionProof) BytesForDurableStorage() ([]byte, error) {
	if !proof.Valid() {
		return nil, ErrClosedSessionProofInvalid
	}
	return append([]byte(nil), proof.value...), nil
}

func (proof ClosedSessionProof) digest() ([sha256.Size]byte, error) {
	if !proof.Valid() {
		return [sha256.Size]byte{}, ErrClosedSessionProofInvalid
	}
	return sha256.Sum256(proof.value), nil
}

type Coordinator struct {
	store Store
	mu    sync.Mutex
	gates map[sessionctx.SessionScope]*scopeGate
}

type scopeGate struct {
	active   uint64
	teardown bool
	fenced   bool
	waiters  uint64
	changed  chan struct{}
}

func NewCoordinator(store Store) (*Coordinator, error) {
	if isNilInterface(store) {
		return nil, ErrStoreRequired
	}
	return &Coordinator{store: store, gates: make(map[sessionctx.SessionScope]*scopeGate)}, nil
}

func (c *Coordinator) Durable() bool { return c != nil && c.store.Durable() }

func (c *Coordinator) ListRetained(ctx context.Context) ([]RetainedScope, error) {
	if c == nil {
		return nil, ErrStoreRequired
	}
	records, err := c.store.ListRetained(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RetainedScope, 0, len(records))
	for _, current := range records {
		if err := current.Scope.Validate(); err != nil || !current.State.Valid() || current.State == StateActive || !current.Counts.Valid() {
			return nil, ErrInvalidState
		}
		result = append(result, RetainedScope{
			SessionScope: current.Scope,
			Snapshot:     current.snapshot(),
			identityHash: retainedIdentityHash(current.TeardownOperationID, current.ProofSHA256),
			hasIdentity:  current.HasProof,
		})
	}
	return result, nil
}

type Reservation struct {
	coordinator *Coordinator
	scope       sessionctx.SessionScope
	gate        *scopeGate
	once        sync.Once
}

func (reservation *Reservation) Release() {
	if reservation == nil || reservation.gate == nil {
		return
	}
	reservation.once.Do(func() {
		reservation.coordinator.releaseReservation(reservation.scope, reservation.gate)
	})
}

func (c *Coordinator) Reserve(ctx context.Context, scope sessionctx.SessionScope) (*Reservation, error) {
	if c == nil {
		return nil, ErrStoreRequired
	}
	if err := validateStoreCall(ctx, scope); err != nil {
		return nil, err
	}
	for {
		c.mu.Lock()
		gate := c.gateLocked(scope)
		if gate.teardown {
			if gate.fenced {
				c.mu.Unlock()
				return nil, ErrSessionRevoked
			}
			changed := gate.changed
			gate.waiters++
			c.mu.Unlock()
			waitErr := waitForGateChange(ctx, changed)
			c.mu.Lock()
			gate.waiters--
			c.cleanupGateLocked(scope, gate)
			c.mu.Unlock()
			if waitErr != nil {
				return nil, waitErr
			}
			continue
		}
		gate.active++
		c.mu.Unlock()

		current, err := c.store.Get(ctx, scope)
		if errors.Is(err, ErrScopeNotFound) {
			return &Reservation{coordinator: c, scope: scope, gate: gate}, nil
		}
		reservation := &Reservation{coordinator: c, scope: scope, gate: gate}
		if err != nil {
			reservation.Release()
			return nil, err
		}
		if current.State != StateActive {
			reservation.Release()
			return nil, ErrSessionRevoked
		}
		return reservation, nil
	}
}

type Teardown struct {
	coordinator *Coordinator
	scope       sessionctx.SessionScope
	gate        *scopeGate
	once        sync.Once
	mu          sync.Mutex
	released    bool
}

func (teardown *Teardown) Release() {
	if teardown == nil || teardown.gate == nil {
		return
	}
	teardown.once.Do(func() {
		teardown.mu.Lock()
		teardown.released = true
		teardown.mu.Unlock()
		teardown.coordinator.releaseTeardown(teardown.scope, teardown.gate)
	})
}

func (teardown *Teardown) Accumulate(ctx context.Context, delta Counts) (Snapshot, error) {
	teardown.mu.Lock()
	defer teardown.mu.Unlock()
	if teardown.released {
		return Snapshot{}, ErrInvalidState
	}
	current, err := teardown.coordinator.store.Accumulate(ctx, teardown.scope, delta, time.Now().UTC())
	return current.snapshot(), err
}

func (teardown *Teardown) AccumulatePhase(ctx context.Context, phase Phase, delta Counts) (Snapshot, error) {
	teardown.mu.Lock()
	defer teardown.mu.Unlock()
	if teardown.released {
		return Snapshot{}, ErrInvalidState
	}
	current, err := teardown.coordinator.store.AccumulatePhase(ctx, teardown.scope, phase, delta, time.Now().UTC())
	return current.snapshot(), err
}

func (teardown *Teardown) MarkIncomplete(ctx context.Context, now time.Time) (Snapshot, error) {
	teardown.mu.Lock()
	defer teardown.mu.Unlock()
	if teardown.released {
		return Snapshot{}, ErrInvalidState
	}
	current, err := teardown.coordinator.store.MarkIncomplete(ctx, teardown.scope, now)
	return current.snapshot(), err
}

func (teardown *Teardown) MarkComplete(ctx context.Context, now time.Time) (Snapshot, error) {
	teardown.mu.Lock()
	defer teardown.mu.Unlock()
	if teardown.released {
		return Snapshot{}, ErrInvalidState
	}
	current, err := teardown.coordinator.store.MarkComplete(ctx, teardown.scope, now)
	return current.snapshot(), err
}

func (c *Coordinator) BeginTeardown(ctx context.Context, scope sessionctx.SessionScope, identity TeardownIdentity, now time.Time) (*Teardown, Snapshot, error) {
	if c == nil {
		return nil, Snapshot{}, ErrStoreRequired
	}
	if err := validateStoreCall(ctx, scope); err != nil {
		return nil, Snapshot{}, err
	}
	digest, err := identity.digest()
	if err != nil {
		return nil, Snapshot{}, err
	}
	gate, err := c.acquireTeardown(ctx, scope)
	if err != nil {
		return nil, Snapshot{}, err
	}
	releaseOnError := true
	defer func() {
		if releaseOnError {
			c.releaseTeardown(scope, gate)
		}
	}()
	current, err := c.store.BeginTeardown(ctx, scope, identity.OperationID, digest, now)
	if err != nil {
		return nil, Snapshot{}, err
	}
	c.markGateFenced(scope, gate)
	releaseOnError = false
	return &Teardown{coordinator: c, scope: scope, gate: gate}, current.snapshot(), nil
}

func (c *Coordinator) Snapshot(ctx context.Context, scope sessionctx.SessionScope) (Snapshot, error) {
	current, err := c.store.Get(ctx, scope)
	return current.snapshot(), err
}

func (c *Coordinator) Finalize(ctx context.Context, scope sessionctx.SessionScope, identity TeardownIdentity) error {
	if c == nil {
		return ErrStoreRequired
	}
	if err := validateStoreCall(ctx, scope); err != nil {
		return err
	}
	digest, err := identity.digest()
	if err != nil {
		return err
	}
	gate, err := c.acquireTeardown(ctx, scope)
	if err != nil {
		return err
	}
	defer c.releaseTeardown(scope, gate)
	if err := c.store.Finalize(ctx, scope, identity.OperationID, digest); err != nil {
		return err
	}
	return nil
}

func (c *Coordinator) gateLocked(scope sessionctx.SessionScope) *scopeGate {
	gate := c.gates[scope]
	if gate == nil {
		gate = &scopeGate{changed: make(chan struct{})}
		c.gates[scope] = gate
	}
	return gate
}

func (c *Coordinator) acquireTeardown(ctx context.Context, scope sessionctx.SessionScope) (*scopeGate, error) {
	owned := false
	var gate *scopeGate
	for {
		c.mu.Lock()
		if gate == nil {
			gate = c.gateLocked(scope)
		}
		if !owned {
			if gate.teardown {
				changed := gate.changed
				gate.waiters++
				c.mu.Unlock()
				waitErr := waitForGateChange(ctx, changed)
				c.mu.Lock()
				gate.waiters--
				c.cleanupGateLocked(scope, gate)
				c.mu.Unlock()
				if waitErr != nil {
					return nil, waitErr
				}
				gate = nil
				continue
			}
			gate.teardown = true
			owned = true
		}
		if gate.active == 0 {
			c.mu.Unlock()
			return gate, nil
		}
		changed := gate.changed
		gate.waiters++
		c.mu.Unlock()
		waitErr := waitForGateChange(ctx, changed)
		c.mu.Lock()
		gate.waiters--
		if waitErr != nil {
			gate.teardown = false
			c.signalGateLocked(gate)
			c.cleanupGateLocked(scope, gate)
			c.mu.Unlock()
			return nil, waitErr
		}
		c.mu.Unlock()
	}
}

func waitForGateChange(ctx context.Context, changed <-chan struct{}) error {
	select {
	case <-changed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Coordinator) releaseReservation(scope sessionctx.SessionScope, gate *scopeGate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gates[scope] != gate || gate.active == 0 {
		return
	}
	gate.active--
	c.signalGateLocked(gate)
	c.cleanupGateLocked(scope, gate)
}

func (c *Coordinator) releaseTeardown(scope sessionctx.SessionScope, gate *scopeGate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gates[scope] != gate || !gate.teardown {
		return
	}
	gate.teardown = false
	c.signalGateLocked(gate)
	c.cleanupGateLocked(scope, gate)
}

func (c *Coordinator) markGateFenced(scope sessionctx.SessionScope, gate *scopeGate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gates[scope] != gate || !gate.teardown {
		return
	}
	gate.fenced = true
	c.signalGateLocked(gate)
}

func (c *Coordinator) signalGateLocked(gate *scopeGate) {
	close(gate.changed)
	gate.changed = make(chan struct{})
}

func (c *Coordinator) cleanupGateLocked(scope sessionctx.SessionScope, gate *scopeGate) {
	if c.gates[scope] == gate && gate.active == 0 && !gate.teardown && gate.waiters == 0 {
		delete(c.gates, scope)
	}
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
