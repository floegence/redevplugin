package stream

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/executionbinding"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type Direction string

const (
	DirectionRead   Direction = "read"
	DirectionWrite  Direction = "write"
	DirectionDuplex Direction = "duplex"
)

type Status string

const (
	StatusOpen             Status = "open"
	StatusClosed           Status = "closed"
	StatusCanceled         Status = "canceled"
	StatusFailed           Status = "failed"
	StatusOrphanedDisabled Status = "orphaned_after_disable"
	StatusOrphanedRemoved  Status = "orphaned_after_uninstall"
)

var (
	ErrNotFound        = errors.New("plugin stream not found")
	ErrInvalidStream   = errors.New("plugin stream is invalid")
	ErrAlreadyExists   = errors.New("plugin stream already exists")
	ErrStreamClosed    = errors.New("plugin stream is closed")
	ErrStoreClosed     = errors.New("plugin stream store is closed")
	ErrStreamInvariant = errors.New("plugin stream storage invariant violated")
	ErrBackpressure    = errors.New("plugin stream backpressure limit exceeded")
	ErrDeliveryInvalid = errors.New("plugin stream delivery is invalid")
)

const streamEventOverheadBytes int64 = 32

var readIDPattern = regexp.MustCompile(`^read_[A-Za-z0-9_-]{8,128}$`)

type Record struct {
	StreamID string `json:"stream_id"`
	capability.ExecutionBinding
	Direction        Direction                       `json:"direction"`
	Status           Status                          `json:"status"`
	FailureCode      capability.ExecutionFailureCode `json:"failure_code,omitempty"`
	Reason           string                          `json:"reason,omitempty"`
	ContentType      string                          `json:"content_type,omitempty"`
	MaxBufferedBytes int64                           `json:"max_buffered_bytes,omitempty"`
	BufferedBytes    int64                           `json:"buffered_bytes,omitempty"`
	CreatedAt        time.Time                       `json:"created_at"`
	UpdatedAt        time.Time                       `json:"updated_at"`
	ClosedAt         *time.Time                      `json:"closed_at,omitempty"`
}

type Event struct {
	StreamID string    `json:"stream_id"`
	Sequence uint64    `json:"sequence"`
	Kind     string    `json:"kind"`
	Data     []byte    `json:"data,omitempty"`
	Error    string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
}

type RegisterRequest struct {
	StreamID         string                      `json:"stream_id"`
	ExecutionBinding capability.ExecutionBinding `json:"execution_binding"`
	Direction        Direction                   `json:"direction,omitempty"`
	ContentType      string                      `json:"content_type,omitempty"`
	MaxBufferedBytes int64                       `json:"max_buffered_bytes,omitempty"`
	Now              time.Time                   `json:"-"`
}

type AppendRequest struct {
	StreamID string    `json:"stream_id"`
	Kind     string    `json:"kind,omitempty"`
	Data     []byte    `json:"data,omitempty"`
	Error    string    `json:"error,omitempty"`
	Now      time.Time `json:"-"`
}

type DeliverRequest struct {
	StreamID  string `json:"stream_id"`
	ReadID    string `json:"read_id"`
	MaxEvents int    `json:"max_events,omitempty"`
	MaxBytes  int64  `json:"max_bytes,omitempty"`
}

type Delivery struct {
	DeliveryID      string  `json:"delivery_id,omitempty"`
	ReadID          string  `json:"read_id"`
	StreamID        string  `json:"stream_id"`
	ThroughSequence uint64  `json:"through_sequence,omitempty"`
	Events          []Event `json:"events,omitempty"`
	Done            bool    `json:"done"`
	TerminalStatus  Status  `json:"terminal_status,omitempty"`
}

type AcknowledgeRequest struct {
	StreamID   string `json:"stream_id"`
	DeliveryID string `json:"delivery_id"`
}

type CloseRequest struct {
	StreamID    string                          `json:"stream_id"`
	Status      Status                          `json:"status,omitempty"`
	FailureCode capability.ExecutionFailureCode `json:"failure_code,omitempty"`
	Reason      string                          `json:"reason,omitempty"`
	Now         time.Time                       `json:"-"`
}

type PluginTransitionRequest struct {
	PluginInstanceID string                          `json:"plugin_instance_id"`
	ResourceScope    sessionctx.ResourceScope        `json:"-"`
	Status           Status                          `json:"status"`
	FailureCode      capability.ExecutionFailureCode `json:"failure_code,omitempty"`
	Reason           string                          `json:"reason,omitempty"`
	Now              time.Time                       `json:"-"`
}

type PluginTransitionResult struct {
	Changed int `json:"changed"`
}

type RevokeSessionScopeRequest struct {
	SessionScope sessionctx.SessionScope `json:"-"`
	Now          time.Time               `json:"-"`
}

type RevokeSessionScopeResult struct {
	Revoked int `json:"revoked"`
}

type PruneRequest struct {
	Before                      time.Time `json:"before"`
	Limit                       int       `json:"limit,omitempty"`
	MaxTerminalRecordsPerPlugin int       `json:"max_terminal_records_per_plugin,omitempty"`
}

type PruneResult struct {
	Deleted int `json:"deleted"`
}

type ListRequest struct {
	PluginInstanceID string     `json:"plugin_instance_id,omitempty"`
	Owner            OwnerScope `json:"-"`
	AllOwners        bool       `json:"-"`
}

type OwnerScope = capability.ExecutionOwnerScope

type Store interface {
	Durable() bool
	Register(ctx context.Context, req RegisterRequest) (Record, error)
	List(ctx context.Context, req ListRequest) ([]Record, error)
	Get(ctx context.Context, streamID string) (Record, error)
	Append(ctx context.Context, req AppendRequest) (Event, error)
	Wait(ctx context.Context, streamID string) error
	Deliver(ctx context.Context, req DeliverRequest) (Record, Delivery, error)
	Acknowledge(ctx context.Context, req AcknowledgeRequest) (Record, error)
	Close(ctx context.Context, req CloseRequest) (Record, error)
	MarkPluginTransition(ctx context.Context, req PluginTransitionRequest) (PluginTransitionResult, error)
	RevokeSessionScope(ctx context.Context, req RevokeSessionScopeRequest) (RevokeSessionScopeResult, error)
	Prune(ctx context.Context, req PruneRequest) (PruneResult, error)
}

type MemoryStore struct {
	mu                   sync.Mutex
	now                  func() time.Time
	records              map[string]Record
	events               map[string][]Event
	nextSeq              map[string]uint64
	notify               map[string]*streamNotification
	pending              map[string]Delivery
	lastAck              map[string]string
	terminalAcknowledged map[string]bool
	ownerIndex           map[OwnerScope]map[string]struct{}
	sessionRevokeScanned uint64
}

type streamNotification struct {
	ready    chan struct{}
	waiters  int
	revision uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		now:                  func() time.Time { return time.Now().UTC() },
		records:              map[string]Record{},
		events:               map[string][]Event{},
		nextSeq:              map[string]uint64{},
		notify:               map[string]*streamNotification{},
		pending:              map[string]Delivery{},
		lastAck:              map[string]string{},
		terminalAcknowledged: map[string]bool{},
		ownerIndex:           map[OwnerScope]map[string]struct{}{},
	}
}

func (*MemoryStore) Durable() bool { return false }

func (s *MemoryStore) Register(_ context.Context, req RegisterRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	pluginInstanceID := strings.TrimSpace(req.ExecutionBinding.PluginInstanceID)
	method := strings.TrimSpace(req.ExecutionBinding.Method)
	owner := req.ExecutionBinding.OwnerScope()
	if streamID == "" || pluginInstanceID == "" || method == "" || !owner.Valid() {
		return Record{}, ErrInvalidStream
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	direction := req.Direction
	if direction == "" {
		direction = DirectionRead
	}
	if !validDirection(direction) {
		return Record{}, ErrInvalidStream
	}
	maxBuffered := req.MaxBufferedBytes
	if maxBuffered <= 0 {
		maxBuffered = DefaultMaxBufferedBytes
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[streamID]; ok {
		return Record{}, ErrAlreadyExists
	}
	binding, err := cloneExecutionBinding(req.ExecutionBinding)
	if err != nil {
		return Record{}, ErrInvalidStream
	}
	if embeddedID := strings.TrimSpace(binding.StreamID); embeddedID != "" && embeddedID != streamID {
		return Record{}, ErrInvalidStream
	}
	binding.StreamID = streamID
	record := Record{
		StreamID:         streamID,
		ExecutionBinding: binding,
		Direction:        direction,
		Status:           StatusOpen,
		ContentType:      req.ContentType,
		MaxBufferedBytes: maxBuffered,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	s.records[streamID] = record
	owner = owner.Normalized()
	ids := s.ownerIndex[owner]
	if ids == nil {
		ids = map[string]struct{}{}
		s.ownerIndex[owner] = ids
	}
	ids[streamID] = struct{}{}
	return cloneRecord(record)
}

func (s *MemoryStore) Get(_ context.Context, streamID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[strings.TrimSpace(streamID)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record)
}

func (s *MemoryStore) List(_ context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("stream store is nil")
	}
	if err := normalizeListRequest(&req); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		if req.PluginInstanceID != "" && record.PluginInstanceID != req.PluginInstanceID {
			continue
		}
		if !req.AllOwners && record.ExecutionBinding.OwnerScope() != req.Owner {
			continue
		}
		cloned, err := cloneRecord(record)
		if err != nil {
			return nil, err
		}
		records = append(records, cloned)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].StreamID < records[j].StreamID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
	return records, nil
}

func (s *MemoryStore) Append(_ context.Context, req AppendRequest) (Event, error) {
	if s == nil {
		return Event{}, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return Event{}, ErrInvalidStream
	}
	kind := strings.TrimSpace(req.Kind)
	if kind == "" {
		kind = "data"
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[streamID]
	if !ok {
		return Event{}, ErrNotFound
	}
	if record.Status != StatusOpen {
		return Event{}, ErrStreamClosed
	}
	event := Event{
		StreamID: streamID,
		Sequence: s.nextSeq[streamID] + 1,
		Kind:     kind,
		Data:     append([]byte(nil), req.Data...),
		Error:    req.Error,
		At:       now,
	}
	nextBuffered := record.BufferedBytes + streamEventCost(event)
	if record.MaxBufferedBytes > 0 && nextBuffered > record.MaxBufferedBytes {
		return Event{}, ErrBackpressure
	}
	s.nextSeq[streamID] = event.Sequence
	s.events[streamID] = append(s.events[streamID], event)
	record.BufferedBytes = nextBuffered
	record.UpdatedAt = now
	s.records[streamID] = record
	s.notifyLocked(streamID)
	return cloneEvent(event), nil
}

func (s *MemoryStore) Wait(ctx context.Context, streamID string) error {
	if s == nil {
		return errors.New("stream store is nil")
	}
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		return ErrInvalidStream
	}
	s.mu.Lock()
	record, ok := s.records[streamID]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	if _, pending := s.pending[streamID]; pending || len(s.events[streamID]) > 0 || terminalStatus(record.Status) {
		s.mu.Unlock()
		return nil
	}
	notification := s.notify[streamID]
	if notification == nil {
		notification = &streamNotification{ready: make(chan struct{})}
		s.notify[streamID] = notification
	}
	notification.waiters++
	s.mu.Unlock()
	defer s.releaseNotification(streamID, notification)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-notification.ready:
		return nil
	}
}

func (s *MemoryStore) Deliver(_ context.Context, req DeliverRequest) (Record, Delivery, error) {
	if s == nil {
		return Record{}, Delivery{}, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	readID := strings.TrimSpace(req.ReadID)
	if streamID == "" || !readIDPattern.MatchString(readID) {
		return Record{}, Delivery{}, ErrInvalidStream
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[streamID]
	if !ok {
		return Record{}, Delivery{}, ErrNotFound
	}
	if pending, ok := s.pending[streamID]; ok {
		return cloneRecordDelivery(record, pending)
	}
	events := s.events[streamID]
	if len(events) == 0 {
		if terminalStatus(record.Status) && !s.terminalAcknowledged[streamID] {
			deliveryID, err := newDeliveryID()
			if err != nil {
				return Record{}, Delivery{}, err
			}
			delivery := Delivery{DeliveryID: deliveryID, ReadID: readID, StreamID: streamID, Done: true, TerminalStatus: record.Status}
			s.pending[streamID] = delivery
			return cloneRecordDelivery(record, delivery)
		}
		return cloneRecordDelivery(record, Delivery{ReadID: readID, StreamID: streamID})
	}
	limit := streamReadLimit(events, req.MaxEvents, req.MaxBytes)
	if limit <= 0 {
		return cloneRecordDelivery(record, Delivery{ReadID: readID, StreamID: streamID})
	}
	deliveryID, err := newDeliveryID()
	if err != nil {
		return Record{}, Delivery{}, err
	}
	delivery := Delivery{
		DeliveryID:      deliveryID,
		ReadID:          readID,
		StreamID:        streamID,
		ThroughSequence: events[limit-1].Sequence,
		Events:          cloneEvents(events[:limit]),
		Done:            terminalStatus(record.Status) && limit == len(events),
	}
	if delivery.Done {
		delivery.TerminalStatus = record.Status
	}
	s.pending[streamID] = delivery
	return cloneRecordDelivery(record, delivery)
}

func (s *MemoryStore) Acknowledge(_ context.Context, req AcknowledgeRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	deliveryID := strings.TrimSpace(req.DeliveryID)
	if streamID == "" || deliveryID == "" {
		return Record{}, ErrInvalidStream
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[streamID]
	if !ok {
		return Record{}, ErrNotFound
	}
	pending, hasPending := s.pending[streamID]
	if !hasPending {
		if s.lastAck[streamID] == deliveryID {
			return cloneRecord(record)
		}
		return Record{}, ErrDeliveryInvalid
	}
	if pending.DeliveryID != deliveryID {
		if s.lastAck[streamID] == deliveryID {
			return cloneRecord(record)
		}
		return Record{}, ErrDeliveryInvalid
	}
	if pending.ThroughSequence > 0 {
		events := s.events[streamID]
		limit := 0
		for limit < len(events) && events[limit].Sequence <= pending.ThroughSequence {
			limit++
		}
		acknowledged := events[:limit]
		s.events[streamID] = append([]Event(nil), events[limit:]...)
		record.BufferedBytes -= eventsCost(acknowledged)
		if record.BufferedBytes < 0 {
			record.BufferedBytes = 0
		}
	}
	record.UpdatedAt = s.now()
	s.records[streamID] = record
	delete(s.pending, streamID)
	s.lastAck[streamID] = deliveryID
	if pending.Done {
		s.terminalAcknowledged[streamID] = true
	}
	s.notifyLocked(streamID)
	return cloneRecord(record)
}

func (s *MemoryStore) Close(_ context.Context, req CloseRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	status := req.Status
	if status == "" {
		status = StatusClosed
	}
	if !terminalStatus(status) {
		return Record{}, ErrInvalidStream
	}
	failureCode, reason, err := normalizeTerminalOutcome(status, req.FailureCode, req.Reason)
	if err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[strings.TrimSpace(req.StreamID)]
	if !ok {
		return Record{}, ErrNotFound
	}
	if record.Status != StatusOpen {
		return cloneRecord(record)
	}
	record.Status = status
	record.FailureCode = failureCode
	record.Reason = reason
	record.UpdatedAt = now
	record.ClosedAt = &now
	s.records[record.StreamID] = record
	s.notifyLocked(record.StreamID)
	return cloneRecord(record)
}

func (s *MemoryStore) MarkPluginTransition(_ context.Context, req PluginTransitionRequest) (PluginTransitionResult, error) {
	if s == nil {
		return PluginTransitionResult{}, errors.New("stream store is nil")
	}
	if !terminalStatus(req.Status) {
		return PluginTransitionResult{}, ErrInvalidStream
	}
	failureCode, reason, err := normalizeTerminalOutcome(req.Status, req.FailureCode, req.Reason)
	if err != nil {
		return PluginTransitionResult{}, err
	}
	pluginInstanceID, ownerEnvHash, err := normalizePluginTransition(req)
	if err != nil {
		return PluginTransitionResult{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := 0
	for id, record := range s.records {
		if record.PluginInstanceID != pluginInstanceID || record.OwnerEnvHash != ownerEnvHash || record.Status != StatusOpen {
			continue
		}
		record.Status = req.Status
		record.FailureCode = failureCode
		record.Reason = reason
		record.UpdatedAt = now
		record.ClosedAt = &now
		s.records[id] = record
		s.notifyLocked(id)
		changed++
	}
	return PluginTransitionResult{Changed: changed}, nil
}

func (s *MemoryStore) RevokeSessionScope(_ context.Context, req RevokeSessionScopeRequest) (RevokeSessionScopeResult, error) {
	if s == nil {
		return RevokeSessionScopeResult{}, errors.New("stream store is nil")
	}
	if err := req.SessionScope.Validate(); err != nil {
		return RevokeSessionScopeResult{}, ErrInvalidStream
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	owner := OwnerScope{
		OwnerSessionHash:     req.SessionScope.OwnerSessionHash,
		OwnerUserHash:        req.SessionScope.OwnerUserHash,
		OwnerEnvHash:         req.SessionScope.OwnerEnvHash,
		SessionChannelIDHash: req.SessionScope.SessionChannelIDHash,
	}.Normalized()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionRevokeScanned = 0
	revoked := 0
	for streamID := range s.ownerIndex[owner] {
		s.sessionRevokeScanned++
		record, ok := s.records[streamID]
		if !ok {
			continue
		}
		revoked++
		if record.Status == StatusOpen {
			record.Status = StatusCanceled
			record.FailureCode = ""
			record.Reason = SessionRevokedReason
			record.UpdatedAt = now
			record.ClosedAt = &now
		}
		record.BufferedBytes = 0
		s.records[streamID] = record
		delete(s.events, streamID)
		delete(s.pending, streamID)
		delete(s.lastAck, streamID)
		s.terminalAcknowledged[streamID] = true
		s.notifyLocked(streamID)
	}
	return RevokeSessionScopeResult{Revoked: revoked}, nil
}

func normalizeTerminalOutcome(status Status, failureCode capability.ExecutionFailureCode, reason string) (capability.ExecutionFailureCode, string, error) {
	if status == StatusFailed {
		if !failureCode.Valid() || strings.TrimSpace(reason) != "" {
			return "", "", ErrInvalidStream
		}
		return failureCode, capability.ExecutionFailureMessage, nil
	}
	if failureCode != "" {
		return "", "", ErrInvalidStream
	}
	return "", reason, nil
}

func (s *MemoryStore) Prune(_ context.Context, req PruneRequest) (PruneResult, error) {
	if s == nil {
		return PruneResult{}, errors.New("stream store is nil")
	}
	before, limit, maxRecordsPerPlugin, err := normalizePruneRequest(req)
	if err != nil {
		return PruneResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	type retentionKey struct {
		OwnerEnvHash     string
		PluginInstanceID string
	}
	terminalByPlugin := make(map[retentionKey][]Record)
	for streamID, record := range s.records {
		if !terminalStatus(record.Status) || record.ClosedAt == nil ||
			!s.terminalAcknowledged[streamID] || len(s.events[streamID]) != 0 || s.pending[streamID].DeliveryID != "" || record.BufferedBytes != 0 {
			continue
		}
		key := retentionKey{OwnerEnvHash: record.OwnerEnvHash, PluginInstanceID: record.PluginInstanceID}
		terminalByPlugin[key] = append(terminalByPlugin[key], record)
	}
	candidates := make([]Record, 0)
	for _, records := range terminalByPlugin {
		sort.Slice(records, func(i, j int) bool {
			if records[i].ClosedAt.Equal(*records[j].ClosedAt) {
				return records[i].StreamID > records[j].StreamID
			}
			return records[i].ClosedAt.After(*records[j].ClosedAt)
		})
		for index, record := range records {
			if record.ClosedAt.Before(before) || index >= maxRecordsPerPlugin {
				candidates = append(candidates, record)
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ClosedAt.Equal(*candidates[j].ClosedAt) {
			return candidates[i].StreamID < candidates[j].StreamID
		}
		return candidates[i].ClosedAt.Before(*candidates[j].ClosedAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	for _, record := range candidates {
		streamID := record.StreamID
		delete(s.records, streamID)
		owner := record.ExecutionBinding.OwnerScope().Normalized()
		delete(s.ownerIndex[owner], streamID)
		if len(s.ownerIndex[owner]) == 0 {
			delete(s.ownerIndex, owner)
		}
		delete(s.events, streamID)
		delete(s.nextSeq, streamID)
		delete(s.pending, streamID)
		delete(s.lastAck, streamID)
		delete(s.terminalAcknowledged, streamID)
		if notification := s.notify[streamID]; notification != nil {
			delete(s.notify, streamID)
			close(notification.ready)
		}
	}
	return PruneResult{Deleted: len(candidates)}, nil
}

func normalizeListRequest(req *ListRequest) error {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	req.Owner = req.Owner.Normalized()
	if (req.AllOwners && req.Owner.Valid()) || (!req.AllOwners && !req.Owner.Valid()) {
		return ErrInvalidStream
	}
	return nil
}

func normalizePluginTransition(req PluginTransitionRequest) (string, string, error) {
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" || req.ResourceScope.Kind != sessionctx.ScopeEnvironment || req.ResourceScope.Validate() != nil {
		return "", "", ErrInvalidStream
	}
	return pluginInstanceID, req.ResourceScope.OwnerEnvHash, nil
}

func (s *MemoryStore) notifyLocked(streamID string) {
	notification := s.notify[streamID]
	if notification == nil {
		return
	}
	delete(s.notify, streamID)
	close(notification.ready)
}

func (s *MemoryStore) releaseNotification(streamID string, notification *streamNotification) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if notification.waiters > 0 {
		notification.waiters--
	}
	if notification.waiters == 0 && s.notify[streamID] == notification {
		delete(s.notify, streamID)
	}
}

const (
	DefaultMaxBufferedBytes            int64 = 1 << 20
	DefaultPruneLimit                        = 500
	MaxPruneLimit                            = 5000
	DefaultMaxTerminalRecordsPerPlugin       = 1000
	MaxTerminalRecordsPerPlugin              = 100_000
	DefaultTerminalRetention                 = 7 * 24 * time.Hour
	SessionRevokedReason                     = "session revoked"
)

func normalizePruneRequest(req PruneRequest) (time.Time, int, int, error) {
	if req.Before.IsZero() {
		return time.Time{}, 0, 0, ErrInvalidStream
	}
	limit := req.Limit
	if limit == 0 {
		limit = DefaultPruneLimit
	}
	if limit < 1 || limit > MaxPruneLimit {
		return time.Time{}, 0, 0, ErrInvalidStream
	}
	maxRecordsPerPlugin := req.MaxTerminalRecordsPerPlugin
	if maxRecordsPerPlugin == 0 {
		maxRecordsPerPlugin = DefaultMaxTerminalRecordsPerPlugin
	}
	if maxRecordsPerPlugin < 1 || maxRecordsPerPlugin > MaxTerminalRecordsPerPlugin {
		return time.Time{}, 0, 0, ErrInvalidStream
	}
	return req.Before.UTC(), limit, maxRecordsPerPlugin, nil
}

func validDirection(direction Direction) bool {
	switch direction {
	case DirectionRead, DirectionWrite, DirectionDuplex:
		return true
	default:
		return false
	}
}

func terminalStatus(status Status) bool {
	switch status {
	case StatusClosed, StatusCanceled, StatusFailed, StatusOrphanedDisabled, StatusOrphanedRemoved:
		return true
	default:
		return false
	}
}

func cloneEvents(events []Event) []Event {
	out := make([]Event, len(events))
	for i, event := range events {
		out[i] = cloneEvent(event)
	}
	return out
}

func cloneDelivery(delivery Delivery) Delivery {
	delivery.Events = cloneEvents(delivery.Events)
	return delivery
}

func newDeliveryID() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "delivery_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func cloneEvent(event Event) Event {
	event.Data = append([]byte(nil), event.Data...)
	return event
}

func cloneExecutionBinding(binding capability.ExecutionBinding) (capability.ExecutionBinding, error) {
	return capability.CloneExecutionBinding(binding)
}

func cloneRecord(record Record) (Record, error) {
	record.ExecutionBinding = executionbinding.CloneTrusted(record.ExecutionBinding)
	if record.ClosedAt != nil {
		value := *record.ClosedAt
		record.ClosedAt = &value
	}
	return record, nil
}

func cloneRecordDelivery(record Record, delivery Delivery) (Record, Delivery, error) {
	cloned, err := cloneRecord(record)
	if err != nil {
		return Record{}, Delivery{}, err
	}
	return cloned, cloneDelivery(delivery), nil
}

func eventsCost(events []Event) int64 {
	var total int64
	for _, event := range events {
		total += streamEventCost(event)
	}
	return total
}

func streamEventCost(event Event) int64 {
	return streamEventOverheadBytes + int64(len(event.Kind)) + int64(len(event.Data)) + int64(len(event.Error))
}

func streamReadLimit(events []Event, maxEvents int, maxBytes int64) int {
	limit := len(events)
	if maxEvents > 0 && maxEvents < limit {
		limit = maxEvents
	}
	if maxBytes <= 0 {
		return limit
	}
	var total int64
	for index := 0; index < limit; index++ {
		size := streamEventCost(events[index])
		if index > 0 && total+size > maxBytes {
			return index
		}
		total += size
	}
	return limit
}
