package stream

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1

type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite stream store path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) CloseDatabase() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) Register(ctx context.Context, req RegisterRequest) (Record, error) {
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
		now = time.Now().UTC()
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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)

	existing, exists, err := getSQLiteStream(ctx, tx, streamID)
	if err != nil {
		return Record{}, err
	}
	if exists {
		return existing, nil
	}
	record := Record{
		StreamID:             streamID,
		PluginID:             strings.TrimSpace(req.PluginID),
		PluginInstanceID:     pluginInstanceID,
		Method:               method,
		Effect:               strings.TrimSpace(req.Effect),
		Execution:            strings.TrimSpace(req.Execution),
		SurfaceInstanceID:    strings.TrimSpace(req.SurfaceInstanceID),
		OwnerSessionHash:     strings.TrimSpace(req.OwnerSessionHash),
		OwnerUserHash:        strings.TrimSpace(req.OwnerUserHash),
		SessionChannelIDHash: strings.TrimSpace(req.SessionChannelIDHash),
		BridgeChannelID:      strings.TrimSpace(req.BridgeChannelID),
		Direction:            direction,
		Status:               StatusOpen,
		ContentType:          strings.TrimSpace(req.ContentType),
		MaxBufferedBytes:     maxBuffered,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := upsertSQLiteStream(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) Get(ctx context.Context, streamID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLiteStream(ctx, s.db, strings.TrimSpace(streamID))
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrNotFound
	}
	return record, nil
}

func (s *SQLiteStore) Append(ctx context.Context, req AppendRequest) (Event, error) {
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
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Event{}, err
	}
	defer rollbackUnlessCommitted(tx)

	record, exists, err := getSQLiteStream(ctx, tx, streamID)
	if err != nil {
		return Event{}, err
	}
	if !exists {
		return Event{}, ErrNotFound
	}
	if record.Status != StatusOpen {
		return Event{}, ErrStreamClosed
	}
	nextBuffered := record.BufferedBytes + int64(len(req.Data))
	if record.MaxBufferedBytes > 0 && nextBuffered > record.MaxBufferedBytes {
		return Event{}, ErrBackpressure
	}
	sequence, err := nextSQLiteStreamSequence(ctx, tx, streamID)
	if err != nil {
		return Event{}, err
	}
	event := Event{
		StreamID: streamID,
		Sequence: sequence,
		Kind:     kind,
		Data:     append([]byte(nil), req.Data...),
		Error:    req.Error,
		At:       now,
	}
	if err := insertSQLiteStreamEvent(ctx, tx, event); err != nil {
		return Event{}, err
	}
	record.BufferedBytes = nextBuffered
	record.UpdatedAt = now
	if err := upsertSQLiteStream(ctx, tx, record); err != nil {
		return Event{}, err
	}
	if err := tx.Commit(); err != nil {
		return Event{}, err
	}
	return event, nil
}

func (s *SQLiteStore) Read(ctx context.Context, req ReadRequest) (Record, []Event, error) {
	if s == nil {
		return Record{}, nil, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return Record{}, nil, ErrInvalidStream
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, nil, err
	}
	defer rollbackUnlessCommitted(tx)

	record, exists, err := getSQLiteStream(ctx, tx, streamID)
	if err != nil {
		return Record{}, nil, err
	}
	if !exists {
		return Record{}, nil, ErrNotFound
	}
	events, err := listSQLiteStreamEvents(ctx, tx, streamID)
	if err != nil {
		return Record{}, nil, err
	}
	if len(events) == 0 {
		if err := tx.Commit(); err != nil {
			return Record{}, nil, err
		}
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
		if err := tx.Commit(); err != nil {
			return Record{}, nil, err
		}
		return record, nil, nil
	}
	out := cloneEvents(events[:limit])
	if err := deleteSQLiteStreamEvents(ctx, tx, streamID, out); err != nil {
		return Record{}, nil, err
	}
	record.BufferedBytes -= eventsBytes(out)
	if record.BufferedBytes < 0 {
		record.BufferedBytes = 0
	}
	record.UpdatedAt = time.Now().UTC()
	if err := upsertSQLiteStream(ctx, tx, record); err != nil {
		return Record{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, nil, err
	}
	return record, out, nil
}

func (s *SQLiteStore) Close(ctx context.Context, req CloseRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status := req.Status
	if status == "" {
		status = StatusClosed
	}
	if !terminalStatus(status) {
		return Record{}, ErrInvalidStream
	}
	return s.update(ctx, strings.TrimSpace(req.StreamID), now, func(record Record) Record {
		if record.Status != StatusOpen {
			return record
		}
		record.Status = status
		record.UpdatedAt = now
		record.ClosedAt = &now
		return record
	})
}

func (s *SQLiteStore) MarkPluginTransition(ctx context.Context, req PluginTransitionRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("stream store is nil")
	}
	if !terminalStatus(req.Status) {
		return nil, ErrInvalidStream
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return nil, ErrInvalidStream
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollbackUnlessCommitted(tx)

	records, err := listSQLiteStreamsByPluginInstance(ctx, tx, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	changed := []Record{}
	for _, record := range records {
		if record.Status != StatusOpen {
			continue
		}
		record.Status = req.Status
		record.UpdatedAt = now
		record.ClosedAt = &now
		if err := upsertSQLiteStream(ctx, tx, record); err != nil {
			return nil, err
		}
		changed = append(changed, record)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	sortStreams(changed)
	return changed, nil
}

func (s *SQLiteStore) update(ctx context.Context, streamID string, now time.Time, mutate func(Record) Record) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)

	record, exists, err := getSQLiteStream(ctx, tx, streamID)
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrNotFound
	}
	record = mutate(record)
	record.UpdatedAt = now
	if err := upsertSQLiteStream(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_stream_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_stream_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqliteSchemaVersion {
		return fmt.Errorf("sqlite stream schema version %d is newer than supported version %d", maxVersion, sqliteSchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_streams (
	stream_id TEXT PRIMARY KEY,
	plugin_id TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	method TEXT NOT NULL,
	effect TEXT NOT NULL,
	execution TEXT NOT NULL,
	surface_instance_id TEXT NOT NULL,
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	bridge_channel_id TEXT NOT NULL,
	direction TEXT NOT NULL,
	status TEXT NOT NULL,
	content_type TEXT NOT NULL,
	max_buffered_bytes INTEGER NOT NULL,
	buffered_bytes INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	closed_at INTEGER
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_stream_events (
	stream_id TEXT NOT NULL,
	sequence INTEGER NOT NULL,
	kind TEXT NOT NULL,
	data BLOB,
	error TEXT NOT NULL,
	at INTEGER NOT NULL,
	PRIMARY KEY(stream_id, sequence),
	FOREIGN KEY(stream_id) REFERENCES plugin_streams(stream_id) ON DELETE CASCADE
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_streams_plugin_instance ON plugin_streams(plugin_instance_id, created_at, stream_id)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_streams_status ON plugin_streams(status)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_stream_events_stream_sequence ON plugin_stream_events(stream_id, sequence)`); err != nil {
		return err
	}
	if maxVersion < sqliteSchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_stream_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteSchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const streamSelectColumns = `
SELECT
	stream_id, plugin_id, plugin_instance_id, method, effect, execution,
	surface_instance_id, owner_session_hash, owner_user_hash,
	session_channel_id_hash, bridge_channel_id, direction, status, content_type,
	max_buffered_bytes, buffered_bytes, created_at, updated_at, closed_at`

func getSQLiteStream(ctx context.Context, q sqliteQuerier, streamID string) (Record, bool, error) {
	row := q.QueryRowContext(ctx, streamSelectColumns+` FROM plugin_streams WHERE stream_id = ?`, streamID)
	record, err := scanSQLiteStream(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return record, true, nil
}

func listSQLiteStreamsByPluginInstance(ctx context.Context, q sqliteQuerier, pluginInstanceID string) ([]Record, error) {
	rows, err := q.QueryContext(ctx, streamSelectColumns+` FROM plugin_streams WHERE plugin_instance_id = ? ORDER BY created_at ASC, stream_id ASC`, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []Record{}
	for rows.Next() {
		record, err := scanSQLiteStream(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortStreams(records)
	return records, nil
}

func upsertSQLiteStream(ctx context.Context, tx *sql.Tx, record Record) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_streams (
	stream_id, plugin_id, plugin_instance_id, method, effect, execution,
	surface_instance_id, owner_session_hash, owner_user_hash,
	session_channel_id_hash, bridge_channel_id, direction, status, content_type,
	max_buffered_bytes, buffered_bytes, created_at, updated_at, closed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(stream_id) DO UPDATE SET
	plugin_id = excluded.plugin_id,
	plugin_instance_id = excluded.plugin_instance_id,
	method = excluded.method,
	effect = excluded.effect,
	execution = excluded.execution,
	surface_instance_id = excluded.surface_instance_id,
	owner_session_hash = excluded.owner_session_hash,
	owner_user_hash = excluded.owner_user_hash,
	session_channel_id_hash = excluded.session_channel_id_hash,
	bridge_channel_id = excluded.bridge_channel_id,
	direction = excluded.direction,
	status = excluded.status,
	content_type = excluded.content_type,
	max_buffered_bytes = excluded.max_buffered_bytes,
	buffered_bytes = excluded.buffered_bytes,
	created_at = excluded.created_at,
	updated_at = excluded.updated_at,
	closed_at = excluded.closed_at`,
		record.StreamID,
		record.PluginID,
		record.PluginInstanceID,
		record.Method,
		record.Effect,
		record.Execution,
		record.SurfaceInstanceID,
		record.OwnerSessionHash,
		record.OwnerUserHash,
		record.SessionChannelIDHash,
		record.BridgeChannelID,
		string(record.Direction),
		string(record.Status),
		record.ContentType,
		record.MaxBufferedBytes,
		record.BufferedBytes,
		record.CreatedAt.UTC().UnixNano(),
		record.UpdatedAt.UTC().UnixNano(),
		timePtrToNullableUnix(record.ClosedAt),
	)
	return err
}

func nextSQLiteStreamSequence(ctx context.Context, q sqliteQuerier, streamID string) (uint64, error) {
	var sequence uint64
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence), 0) + 1 FROM plugin_stream_events WHERE stream_id = ?`, streamID).Scan(&sequence); err != nil {
		return 0, err
	}
	return sequence, nil
}

func insertSQLiteStreamEvent(ctx context.Context, tx *sql.Tx, event Event) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_stream_events(stream_id, sequence, kind, data, error, at)
VALUES(?, ?, ?, ?, ?, ?)`,
		event.StreamID,
		event.Sequence,
		event.Kind,
		event.Data,
		event.Error,
		event.At.UTC().UnixNano(),
	)
	return err
}

func listSQLiteStreamEvents(ctx context.Context, q sqliteQuerier, streamID string) ([]Event, error) {
	rows, err := q.QueryContext(ctx, `SELECT stream_id, sequence, kind, data, error, at FROM plugin_stream_events WHERE stream_id = ? ORDER BY sequence ASC`, streamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		event, err := scanSQLiteStreamEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func deleteSQLiteStreamEvents(ctx context.Context, tx *sql.Tx, streamID string, events []Event) error {
	for _, event := range events {
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_stream_events WHERE stream_id = ? AND sequence = ?`, streamID, event.Sequence); err != nil {
			return err
		}
	}
	return nil
}

type sqliteQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqliteStreamScanner interface {
	Scan(...any) error
}

func scanSQLiteStream(scanner sqliteStreamScanner) (Record, error) {
	var record Record
	var direction string
	var status string
	var createdAt int64
	var updatedAt int64
	var closedAt sql.NullInt64
	if err := scanner.Scan(
		&record.StreamID,
		&record.PluginID,
		&record.PluginInstanceID,
		&record.Method,
		&record.Effect,
		&record.Execution,
		&record.SurfaceInstanceID,
		&record.OwnerSessionHash,
		&record.OwnerUserHash,
		&record.SessionChannelIDHash,
		&record.BridgeChannelID,
		&direction,
		&status,
		&record.ContentType,
		&record.MaxBufferedBytes,
		&record.BufferedBytes,
		&createdAt,
		&updatedAt,
		&closedAt,
	); err != nil {
		return Record{}, err
	}
	record.Direction = Direction(direction)
	record.Status = Status(status)
	record.CreatedAt = unixToTime(createdAt)
	record.UpdatedAt = unixToTime(updatedAt)
	record.ClosedAt = nullableUnixToTimePtr(closedAt)
	return record, nil
}

func scanSQLiteStreamEvent(scanner sqliteStreamScanner) (Event, error) {
	var event Event
	var at int64
	if err := scanner.Scan(&event.StreamID, &event.Sequence, &event.Kind, &event.Data, &event.Error, &at); err != nil {
		return Event{}, err
	}
	event.Data = append([]byte(nil), event.Data...)
	event.At = unixToTime(at)
	return event, nil
}

func sortStreams(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].StreamID < records[j].StreamID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
}

func timePtrToNullableUnix(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixNano()
}

func nullableUnixToTimePtr(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	converted := unixToTime(value.Int64)
	return &converted
}

func unixToTime(value int64) time.Time {
	return time.Unix(0, value).UTC()
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ Store = (*SQLiteStore)(nil)
