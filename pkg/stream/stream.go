package stream

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
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
	StatusOrphanedDisabled Status = "orphaned_after_disable"
	StatusOrphanedRemoved  Status = "orphaned_after_uninstall"
)

var (
	ErrNotFound      = errors.New("plugin stream not found")
	ErrInvalidStream = errors.New("plugin stream is invalid")
	ErrStreamClosed  = errors.New("plugin stream is closed")
	ErrBackpressure  = errors.New("plugin stream backpressure limit exceeded")
)

type Record struct {
	StreamID             string     `json:"stream_id"`
	PluginID             string     `json:"plugin_id"`
	PluginInstanceID     string     `json:"plugin_instance_id"`
	Method               string     `json:"method"`
	Effect               string     `json:"effect,omitempty"`
	Execution            string     `json:"execution"`
	SurfaceInstanceID    string     `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string     `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string     `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string     `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string     `json:"bridge_channel_id,omitempty"`
	Direction            Direction  `json:"direction"`
	Status               Status     `json:"status"`
	ContentType          string     `json:"content_type,omitempty"`
	MaxBufferedBytes     int64      `json:"max_buffered_bytes,omitempty"`
	BufferedBytes        int64      `json:"buffered_bytes,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	ClosedAt             *time.Time `json:"closed_at,omitempty"`
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
	StreamID             string    `json:"stream_id"`
	PluginID             string    `json:"plugin_id"`
	PluginInstanceID     string    `json:"plugin_instance_id"`
	Method               string    `json:"method"`
	Effect               string    `json:"effect,omitempty"`
	Execution            string    `json:"execution"`
	SurfaceInstanceID    string    `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string    `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string    `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string    `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string    `json:"bridge_channel_id,omitempty"`
	Direction            Direction `json:"direction,omitempty"`
	ContentType          string    `json:"content_type,omitempty"`
	MaxBufferedBytes     int64     `json:"max_buffered_bytes,omitempty"`
	Now                  time.Time `json:"now,omitempty"`
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
	Now              time.Time `json:"now,omitempty"`
}

type Store interface {
	Register(ctx context.Context, req RegisterRequest) (Record, error)
	Get(ctx context.Context, streamID string) (Record, error)
	Append(ctx context.Context, req AppendRequest) (Event, error)
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
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	method := strings.TrimSpace(req.Method)
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
	if existing, ok := s.records[streamID]; ok {
		return existing, nil
	}
	record := Record{
		StreamID:             streamID,
		PluginID:             req.PluginID,
		PluginInstanceID:     pluginInstanceID,
		Method:               method,
		Effect:               req.Effect,
		Execution:            req.Execution,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Direction:            direction,
		Status:               StatusOpen,
		ContentType:          req.ContentType,
		MaxBufferedBytes:     maxBuffered,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	s.records[streamID] = record
	return record, nil
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
	return record, nil
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
	return event, nil
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
		return record, nil, nil
	}
	limit := len(events)
	if req.MaxEvents > 0 && req.MaxEvents < limit {
		limit = req.MaxEvents
	}
	var total int64
	if req.MaxBytes > 0 {
		for i := 0; i < limit; i++ {
			size := int64(len(events[i].Data))
			if i > 0 && total+size > req.MaxBytes {
				limit = i
				break
			}
			total += size
		}
	}
	if limit <= 0 {
		return record, nil, nil
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
	return record, out, nil
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
		return record, nil
	}
	record.Status = status
	record.UpdatedAt = now
	record.ClosedAt = &now
	s.records[record.StreamID] = record
	return record, nil
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
		record.UpdatedAt = now
		record.ClosedAt = &now
		s.records[id] = record
		changed = append(changed, record)
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
	case StatusClosed, StatusCanceled, StatusOrphanedDisabled, StatusOrphanedRemoved:
		return true
	default:
		return false
	}
}

func cloneEvents(events []Event) []Event {
	out := make([]Event, len(events))
	for i, event := range events {
		out[i] = event
		out[i].Data = append([]byte(nil), event.Data...)
	}
	return out
}

func eventsBytes(events []Event) int64 {
	var total int64
	for _, event := range events {
		total += int64(len(event.Data))
	}
	return total
}
