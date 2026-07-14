package stream

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
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
	ErrNotFound      = errors.New("plugin stream not found")
	ErrInvalidStream = errors.New("plugin stream is invalid")
	ErrAlreadyExists = errors.New("plugin stream already exists")
	ErrStreamClosed  = errors.New("plugin stream is closed")
	ErrBackpressure  = errors.New("plugin stream backpressure limit exceeded")
)

type Record struct {
	StreamID string `json:"stream_id"`
	capability.ExecutionBinding
	Direction        Direction  `json:"direction"`
	Status           Status     `json:"status"`
	Reason           string     `json:"reason,omitempty"`
	ContentType      string     `json:"content_type,omitempty"`
	MaxBufferedBytes int64      `json:"max_buffered_bytes,omitempty"`
	BufferedBytes    int64      `json:"buffered_bytes,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ClosedAt         *time.Time `json:"closed_at,omitempty"`
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
	Now              time.Time                   `json:"now,omitempty"`
}

type AppendRequest struct {
	StreamID string    `json:"stream_id"`
	Kind     string    `json:"kind,omitempty"`
	Data     []byte    `json:"data,omitempty"`
	Error    string    `json:"error,omitempty"`
	Now      time.Time `json:"now,omitempty"`
}

type ReadRequest struct {
	StreamID  string `json:"stream_id"`
	MaxEvents int    `json:"max_events,omitempty"`
	MaxBytes  int64  `json:"max_bytes,omitempty"`
}

type CloseRequest struct {
	StreamID string    `json:"stream_id"`
	Status   Status    `json:"status,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Now      time.Time `json:"now,omitempty"`
}

type PluginTransitionRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	Status           Status    `json:"status"`
	Reason           string    `json:"reason,omitempty"`
	Now              time.Time `json:"now,omitempty"`
}

type ListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type Store interface {
	Register(ctx context.Context, req RegisterRequest) (Record, error)
	List(ctx context.Context, req ListRequest) ([]Record, error)
	Get(ctx context.Context, streamID string) (Record, error)
	Append(ctx context.Context, req AppendRequest) (Event, error)
	Peek(ctx context.Context, req ReadRequest) (Record, []Event, error)
	Read(ctx context.Context, req ReadRequest) (Record, []Event, error)
	Close(ctx context.Context, req CloseRequest) (Record, error)
	MarkPluginTransition(ctx context.Context, req PluginTransitionRequest) ([]Record, error)
}

type MemoryStore struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[string]Record
	events  map[string][]Event
	nextSeq map[string]uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		now:     func() time.Time { return time.Now().UTC() },
		records: map[string]Record{},
		events:  map[string][]Event{},
		nextSeq: map[string]uint64{},
	}
}

func (s *MemoryStore) Register(_ context.Context, req RegisterRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	pluginInstanceID := strings.TrimSpace(req.ExecutionBinding.PluginInstanceID)
	method := strings.TrimSpace(req.ExecutionBinding.Method)
	if streamID == "" || pluginInstanceID == "" || method == "" {
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
	return cloneRecord(record), nil
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
	return cloneRecord(record), nil
}

func (s *MemoryStore) List(_ context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("stream store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		if req.PluginInstanceID != "" && record.PluginInstanceID != req.PluginInstanceID {
			continue
		}
		records = append(records, cloneRecord(record))
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
	nextBuffered := record.BufferedBytes + int64(len(req.Data))
	if record.MaxBufferedBytes > 0 && nextBuffered > record.MaxBufferedBytes {
		return Event{}, ErrBackpressure
	}
	seq := s.nextSeq[streamID] + 1
	s.nextSeq[streamID] = seq
	event := Event{
		StreamID: streamID,
		Sequence: seq,
		Kind:     kind,
		Data:     append([]byte(nil), req.Data...),
		Error:    req.Error,
		At:       now,
	}
	s.events[streamID] = append(s.events[streamID], event)
	record.BufferedBytes = nextBuffered
	record.UpdatedAt = now
	s.records[streamID] = record
	return cloneEvent(event), nil
}

func (s *MemoryStore) Read(_ context.Context, req ReadRequest) (Record, []Event, error) {
	if s == nil {
		return Record{}, nil, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return Record{}, nil, ErrInvalidStream
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[streamID]
	if !ok {
		return Record{}, nil, ErrNotFound
	}
	events := s.events[streamID]
	if len(events) == 0 {
		return cloneRecord(record), nil, nil
	}
	limit := streamReadLimit(events, req.MaxEvents, req.MaxBytes)
	if limit <= 0 {
		return cloneRecord(record), nil, nil
	}
	out := cloneEvents(events[:limit])
	remaining := append([]Event(nil), events[limit:]...)
	s.events[streamID] = remaining
	record.BufferedBytes -= eventsBytes(out)
	if record.BufferedBytes < 0 {
		record.BufferedBytes = 0
	}
	record.UpdatedAt = s.now()
	s.records[streamID] = record
	return cloneRecord(record), out, nil
}

func (s *MemoryStore) Peek(_ context.Context, req ReadRequest) (Record, []Event, error) {
	if s == nil {
		return Record{}, nil, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return Record{}, nil, ErrInvalidStream
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[streamID]
	if !ok {
		return Record{}, nil, ErrNotFound
	}
	events := s.events[streamID]
	limit := streamReadLimit(events, req.MaxEvents, req.MaxBytes)
	return cloneRecord(record), cloneEvents(events[:limit]), nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[strings.TrimSpace(req.StreamID)]
	if !ok {
		return Record{}, ErrNotFound
	}
	if record.Status != StatusOpen {
		return cloneRecord(record), nil
	}
	record.Status = status
	record.Reason = req.Reason
	record.UpdatedAt = now
	record.ClosedAt = &now
	s.records[record.StreamID] = record
	return cloneRecord(record), nil
}

func (s *MemoryStore) MarkPluginTransition(_ context.Context, req PluginTransitionRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("stream store is nil")
	}
	if !terminalStatus(req.Status) {
		return nil, ErrInvalidStream
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var changed []Record
	for id, record := range s.records {
		if record.PluginInstanceID != req.PluginInstanceID || record.Status != StatusOpen {
			continue
		}
		record.Status = req.Status
		record.Reason = req.Reason
		record.UpdatedAt = now
		record.ClosedAt = &now
		s.records[id] = record
		changed = append(changed, cloneRecord(record))
	}
	sort.Slice(changed, func(i, j int) bool {
		return changed[i].StreamID < changed[j].StreamID
	})
	return changed, nil
}

const DefaultMaxBufferedBytes int64 = 1 << 20

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

func cloneEvent(event Event) Event {
	event.Data = append([]byte(nil), event.Data...)
	return event
}

func cloneExecutionBinding(binding capability.ExecutionBinding) (capability.ExecutionBinding, error) {
	raw, err := json.Marshal(binding)
	if err != nil {
		return capability.ExecutionBinding{}, err
	}
	var cloned capability.ExecutionBinding
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return capability.ExecutionBinding{}, err
	}
	return cloned, nil
}

func cloneRecord(record Record) Record {
	binding, err := cloneExecutionBinding(record.ExecutionBinding)
	if err == nil {
		record.ExecutionBinding = binding
	}
	if record.ClosedAt != nil {
		value := *record.ClosedAt
		record.ClosedAt = &value
	}
	return record
}

func eventsBytes(events []Event) int64 {
	var total int64
	for _, event := range events {
		total += int64(len(event.Data))
	}
	return total
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
		size := int64(len(events[index].Data))
		if index > 0 && total+size > maxBytes {
			return index
		}
		total += size
	}
	return limit
}
