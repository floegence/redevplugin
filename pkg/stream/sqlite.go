package stream

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/internal/jsonvalue"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/mutation"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const maxSQLiteReadEvents = 1000

type SQLiteStore struct {
	db                 *sql.DB
	queryObserver      func(sqliteQueryKind)
	notifyMu           sync.Mutex
	notify             map[string]*streamNotification
	transitionMu       sync.Mutex
	transitionRevision uint64
	transitionReady    chan struct{}
	waitObservations   int
	observationsReady  chan struct{}
	pluginNotify       map[string]*streamNotification
	closed             bool
	lockTableMu        sync.Mutex
	locks              map[string]*sqliteStreamLock
	writeGate          chan struct{}
}

type sqliteQueryKind string

const (
	sqliteQueryWaitObservation  sqliteQueryKind = "wait_observation"
	sqliteQueryDeliverySnapshot sqliteQueryKind = "delivery_snapshot"
	sqliteQueryDeliveryMutation sqliteQueryKind = "delivery_mutation"
	sqliteQueryDeliveryReplay   sqliteQueryKind = "delivery_replay"
	sqliteQueryDeliveryCAS      sqliteQueryKind = "delivery_cas"
	sqliteQueryBoundedEvents    sqliteQueryKind = "bounded_event_select"
	sqliteQueryRangeDelete      sqliteQueryKind = "range_delete"
)

func (s *SQLiteStore) observeQuery(kind sqliteQueryKind) {
	if s.queryObserver != nil {
		s.queryObserver(kind)
	}
}

type sqliteStreamLock struct {
	token chan struct{}
	refs  int
}

type sqliteDeliveryState struct {
	Pending              Delivery
	LastAcknowledgedID   string
	TerminalAcknowledged bool
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite stream store path is required")
	}
	dsn := (&url.URL{
		Scheme:   "file",
		Path:     path,
		RawQuery: "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)",
	}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)
	writeGate := make(chan struct{}, 1)
	writeGate <- struct{}{}
	store := &SQLiteStore{
		db:              db,
		notify:          map[string]*streamNotification{},
		transitionReady: make(chan struct{}),
		pluginNotify:    map[string]*streamNotification{},
		locks:           map[string]*sqliteStreamLock{},
		writeGate:       writeGate,
	}
	if err := store.initializeSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) CloseDatabase() error {
	if s == nil || s.db == nil {
		return nil
	}
	if observationsReady := s.closeNotifications(); observationsReady != nil {
		<-observationsReady
	}
	return s.db.Close()
}

func (s *SQLiteStore) Register(ctx context.Context, req RegisterRequest) (Record, error) {
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
		now = time.Now().UTC()
	}
	direction := req.Direction
	if direction == "" {
		direction = DirectionRead
	}
	if !validDirection(direction) {
		return Record{}, ErrInvalidStream
	}
	binding, err := cloneExecutionBinding(req.ExecutionBinding)
	if err != nil {
		return Record{}, ErrInvalidStream
	}
	if embeddedID := strings.TrimSpace(binding.StreamID); embeddedID != "" && embeddedID != streamID {
		return Record{}, ErrInvalidStream
	}
	binding.StreamID = streamID
	maxBuffered := req.MaxBufferedBytes
	if maxBuffered <= 0 {
		maxBuffered = DefaultMaxBufferedBytes
	}

	release, err := s.lockStream(ctx, streamID)
	if err != nil {
		return Record{}, err
	}
	defer release()
	releaseWrite, err := s.lockWrite(ctx)
	if err != nil {
		return Record{}, err
	}
	defer releaseWrite()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)

	_, exists, err := getSQLiteStream(ctx, tx, streamID)
	if err != nil {
		return Record{}, err
	}
	if exists {
		return Record{}, ErrAlreadyExists
	}
	record := Record{
		StreamID:         streamID,
		ExecutionBinding: binding,
		Direction:        direction,
		Status:           StatusOpen,
		ContentType:      strings.TrimSpace(req.ContentType),
		MaxBufferedBytes: maxBuffered,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := insertSQLiteStream(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, mutation.Unknown(err)
	}
	return record, nil
}

func (s *SQLiteStore) Get(ctx context.Context, streamID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	release, err := s.lockStream(ctx, strings.TrimSpace(streamID))
	if err != nil {
		return Record{}, err
	}
	defer release()

	record, exists, err := getSQLiteStream(ctx, s.db, strings.TrimSpace(streamID))
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrNotFound
	}
	return record, nil
}

func (s *SQLiteStore) List(ctx context.Context, req ListRequest) ([]Record, error) {
	if s == nil {
		return nil, errors.New("stream store is nil")
	}
	if err := normalizeListRequest(&req); err != nil {
		return nil, err
	}
	query := streamSelectColumns + ` FROM plugin_streams`
	args := []any{}
	conditions := []string{}
	if req.PluginInstanceID != "" {
		conditions = append(conditions, `plugin_instance_id = ?`)
		args = append(args, req.PluginInstanceID)
	}
	if !req.AllOwners {
		conditions = append(conditions, `owner_session_hash = ?`, `owner_user_hash = ?`, `owner_env_hash = ?`, `session_channel_id_hash = ?`)
		args = append(args, req.Owner.OwnerSessionHash, req.Owner.OwnerUserHash, req.Owner.OwnerEnvHash, req.Owner.SessionChannelIDHash)
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY created_at ASC, stream_id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
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
	return records, nil
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

	release, err := s.lockStream(ctx, streamID)
	if err != nil {
		return Event{}, err
	}
	defer release()
	releaseWrite, err := s.lockWrite(ctx)
	if err != nil {
		return Event{}, err
	}
	defer releaseWrite()

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
	nextBuffered := record.BufferedBytes + streamEventCost(event)
	if record.MaxBufferedBytes > 0 && nextBuffered > record.MaxBufferedBytes {
		return Event{}, ErrBackpressure
	}
	if err := insertSQLiteStreamEvent(ctx, tx, event); err != nil {
		return Event{}, err
	}
	record.BufferedBytes = nextBuffered
	record.UpdatedAt = now
	if err := updateSQLiteStreamState(ctx, tx, record); err != nil {
		return Event{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE plugin_streams SET next_sequence = ? WHERE stream_id = ?`, sequence+1, streamID); err != nil {
		return Event{}, err
	}
	if err := tx.Commit(); err != nil {
		return Event{}, err
	}
	s.notifyStream(streamID)
	return event, nil
}

func (s *SQLiteStore) Wait(ctx context.Context, streamID string) error {
	if s == nil {
		return errors.New("stream store is nil")
	}
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		return ErrInvalidStream
	}
	release, err := s.lockStream(ctx, streamID)
	if err != nil {
		return err
	}
	releaseLocks := release
	defer func() { releaseLocks() }()
	transitionRevision, transitionReady, finishObservation, err := s.beginWaitObservation()
	if err != nil {
		return err
	}
	defer finishObservation()
	notification, revision := s.notification(streamID)
	defer s.releaseNotification(streamID, notification)
	s.observeQuery(sqliteQueryWaitObservation)
	record, exists, err := getSQLiteStream(ctx, s.db, streamID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	pluginKey := pluginTransitionKey(record.OwnerEnvHash, record.PluginInstanceID)
	pluginNotification, pluginRevision, err := s.pluginNotification(pluginKey)
	if err != nil {
		return err
	}
	defer s.releasePluginNotification(pluginKey, pluginNotification)
	s.observeQuery(sqliteQueryWaitObservation)
	deliveryState, err := getSQLiteDeliveryState(ctx, s.db, streamID)
	if err != nil {
		return err
	}
	var eventExists bool
	s.observeQuery(sqliteQueryWaitObservation)
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM plugin_stream_events WHERE stream_id = ? LIMIT 1)`, streamID).Scan(&eventExists); err != nil {
		return err
	}
	if deliveryState.Pending.DeliveryID != "" ||
		eventExists ||
		terminalStatus(record.Status) ||
		s.notificationChanged(streamID, notification, revision) ||
		s.transitionChanged(transitionRevision, transitionReady) ||
		s.pluginNotificationChanged(pluginKey, pluginNotification, pluginRevision) {
		return nil
	}
	releaseLocks()
	releaseLocks = func() {}
	finishObservation()
	return waitForStreamNotification(ctx, notification.ready, pluginNotification.ready)
}

func waitForStreamNotification(ctx context.Context, streamReady, pluginReady <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-streamReady:
		return nil
	case <-pluginReady:
		return nil
	}
}

func (s *SQLiteStore) Deliver(ctx context.Context, req DeliverRequest) (Record, Delivery, error) {
	if s == nil {
		return Record{}, Delivery{}, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	readID := strings.TrimSpace(req.ReadID)
	if streamID == "" || !readIDPattern.MatchString(readID) {
		return Record{}, Delivery{}, ErrInvalidStream
	}

	release, err := s.lockStream(ctx, streamID)
	if err != nil {
		return Record{}, Delivery{}, err
	}
	defer release()

	for {
		if err := ctx.Err(); err != nil {
			return Record{}, Delivery{}, err
		}
		s.observeQuery(sqliteQueryDeliverySnapshot)
		record, deliveryState, eventExists, exists, err := getSQLiteDeliverySnapshot(ctx, s.db, streamID)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Record{}, Delivery{}, ctxErr
			}
			if sqliteDeliveryRetryable(err) {
				continue
			}
			return Record{}, Delivery{}, err
		}
		if !exists {
			return Record{}, Delivery{}, ErrNotFound
		}
		if deliveryState.Pending.DeliveryID != "" {
			delivery, retry, err := s.replaySQLiteDelivery(ctx, streamID, deliveryState)
			if err != nil {
				return Record{}, Delivery{}, err
			}
			if retry {
				continue
			}
			return record, delivery, nil
		}
		if !eventExists && (!terminalStatus(record.Status) || deliveryState.TerminalAcknowledged) {
			return record, Delivery{ReadID: readID, StreamID: streamID}, nil
		}

		s.observeQuery(sqliteQueryDeliveryMutation)
		delivery, retry, err := s.installSQLiteDelivery(ctx, req, record, deliveryState, eventExists)
		if err != nil {
			return Record{}, Delivery{}, err
		}
		if retry {
			continue
		}
		return record, delivery, nil
	}
}

func (s *SQLiteStore) replaySQLiteDelivery(ctx context.Context, streamID string, state sqliteDeliveryState) (Delivery, bool, error) {
	pending := state.Pending
	if pending.ThroughSequence == 0 {
		return cloneDelivery(pending), false, nil
	}
	s.observeQuery(sqliteQueryDeliveryReplay)
	events, err := listSQLiteStreamEventsThrough(ctx, s.db, streamID, pending.ThroughSequence)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Delivery{}, false, ctxErr
		}
		if sqliteDeliveryRetryable(err) {
			return Delivery{}, true, nil
		}
		return Delivery{}, false, err
	}
	matches, err := sqliteDeliveryStateMatches(ctx, s.db, streamID, state)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Delivery{}, false, ctxErr
		}
		if sqliteDeliveryRetryable(err) {
			return Delivery{}, true, nil
		}
		return Delivery{}, false, err
	}
	if !matches {
		return Delivery{}, true, nil
	}
	pending.Events = events
	return cloneDelivery(pending), false, nil
}

func (s *SQLiteStore) installSQLiteDelivery(ctx context.Context, req DeliverRequest, record Record, state sqliteDeliveryState, eventExists bool) (Delivery, bool, error) {
	releaseWrite, err := s.lockWrite(ctx)
	if err != nil {
		return Delivery{}, false, err
	}
	defer releaseWrite()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return sqliteDeliveryMutationError(ctx, err)
	}
	defer rollbackUnlessCommitted(tx)

	var events []Event
	if eventExists {
		s.observeQuery(sqliteQueryBoundedEvents)
		events, err = listSQLiteStreamEvents(ctx, tx, record.StreamID, req.MaxEvents, req.MaxBytes)
		if err != nil {
			return sqliteDeliveryMutationError(ctx, err)
		}
	}
	delivery := Delivery{ReadID: strings.TrimSpace(req.ReadID), StreamID: record.StreamID}
	if len(events) == 0 {
		if !terminalStatus(record.Status) || state.TerminalAcknowledged {
			return delivery, false, nil
		}
		deliveryID, err := newDeliveryID()
		if err != nil {
			return Delivery{}, false, err
		}
		delivery.DeliveryID = deliveryID
		delivery.Done = true
		delivery.TerminalStatus = record.Status
	} else {
		deliveryID, err := newDeliveryID()
		if err != nil {
			return Delivery{}, false, err
		}
		throughSequence := events[len(events)-1].Sequence
		var remaining bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM plugin_stream_events WHERE stream_id = ? AND sequence > ? LIMIT 1)`, record.StreamID, throughSequence).Scan(&remaining); err != nil {
			return sqliteDeliveryMutationError(ctx, err)
		}
		delivery.DeliveryID = deliveryID
		delivery.ThroughSequence = throughSequence
		delivery.Events = cloneEvents(events)
		delivery.Done = terminalStatus(record.Status) && !remaining
		if delivery.Done {
			delivery.TerminalStatus = record.Status
		}
	}

	s.observeQuery(sqliteQueryDeliveryCAS)
	updated, err := compareAndSetSQLitePendingDelivery(ctx, tx, record, state, delivery)
	if err != nil {
		return sqliteDeliveryMutationError(ctx, err)
	}
	if !updated {
		return Delivery{}, true, nil
	}
	if err := tx.Commit(); err != nil {
		return sqliteDeliveryMutationError(ctx, err)
	}
	return cloneDelivery(delivery), false, nil
}

func sqliteDeliveryMutationError(ctx context.Context, err error) (Delivery, bool, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Delivery{}, false, ctxErr
	}
	if sqliteDeliveryRetryable(err) {
		return Delivery{}, true, nil
	}
	return Delivery{}, false, err
}

func sqliteDeliveryRetryable(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	switch sqliteErr.Code() & 0xff {
	case sqlite3.SQLITE_BUSY:
		return true
	default:
		return false
	}
}

func (s *SQLiteStore) Acknowledge(ctx context.Context, req AcknowledgeRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("stream store is nil")
	}
	streamID := strings.TrimSpace(req.StreamID)
	deliveryID := strings.TrimSpace(req.DeliveryID)
	if streamID == "" || deliveryID == "" {
		return Record{}, ErrInvalidStream
	}
	release, err := s.lockStream(ctx, streamID)
	if err != nil {
		return Record{}, err
	}
	defer release()
	releaseWrite, err := s.lockWrite(ctx)
	if err != nil {
		return Record{}, err
	}
	defer releaseWrite()
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
	deliveryState, err := getSQLiteDeliveryState(ctx, tx, streamID)
	if err != nil {
		return Record{}, err
	}
	if deliveryState.Pending.DeliveryID != deliveryID {
		if deliveryState.LastAcknowledgedID == deliveryID {
			if err := tx.Commit(); err != nil {
				return Record{}, err
			}
			return record, nil
		}
		return Record{}, ErrDeliveryInvalid
	}
	if deliveryState.Pending.ThroughSequence > 0 {
		s.observeQuery(sqliteQueryRangeDelete)
		acknowledgedBytes, deleteErr := deleteSQLiteStreamEvents(ctx, tx, streamID, deliveryState.Pending.ThroughSequence)
		if deleteErr != nil {
			return Record{}, deleteErr
		}
		record.BufferedBytes -= acknowledgedBytes
		if record.BufferedBytes < 0 {
			return Record{}, ErrStreamInvariant
		}
		record.UpdatedAt = time.Now().UTC()
		if err := updateSQLiteStreamState(ctx, tx, record); err != nil {
			return Record{}, err
		}
	}
	deliveryState.LastAcknowledgedID = deliveryID
	if deliveryState.Pending.Done {
		deliveryState.TerminalAcknowledged = true
	}
	deliveryState.Pending = Delivery{}
	if err := updateSQLiteDeliveryState(ctx, tx, streamID, deliveryState); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, mutation.Unknown(err)
	}
	s.notifyStream(streamID)
	return record, nil
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
	failureCode, reason, err := normalizeTerminalOutcome(status, req.FailureCode, req.Reason)
	if err != nil {
		return Record{}, err
	}
	return s.update(ctx, strings.TrimSpace(req.StreamID), now, func(record Record) Record {
		if record.Status != StatusOpen {
			return record
		}
		record.Status = status
		record.FailureCode = failureCode
		record.Reason = reason
		record.UpdatedAt = now
		record.ClosedAt = &now
		return record
	})
}

func (s *SQLiteStore) MarkPluginTransition(ctx context.Context, req PluginTransitionRequest) (PluginTransitionResult, error) {
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
		now = time.Now().UTC()
	}
	releaseWrite, err := s.lockWrite(ctx)
	if err != nil {
		return PluginTransitionResult{}, err
	}
	defer releaseWrite()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PluginTransitionResult{}, err
	}
	defer rollbackUnlessCommitted(tx)

	result, err := tx.ExecContext(ctx, `
		UPDATE plugin_streams
		SET status = ?, failure_code = ?, reason = ?, updated_at = ?, closed_at = ?
		WHERE owner_env_hash = ? AND plugin_instance_id = ? AND status = ?`,
		string(req.Status),
		string(failureCode),
		reason,
		now.UnixNano(),
		now.UnixNano(),
		ownerEnvHash,
		pluginInstanceID,
		string(StatusOpen),
	)
	if err != nil {
		return PluginTransitionResult{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return PluginTransitionResult{}, err
	}
	if changed < 0 || uint64(changed) > uint64(^uint(0)>>1) {
		return PluginTransitionResult{}, ErrStreamInvariant
	}
	if err := tx.Commit(); err != nil {
		return PluginTransitionResult{}, mutation.Unknown(err)
	}
	if changed > 0 {
		s.notifyPluginTransition(pluginTransitionKey(ownerEnvHash, pluginInstanceID))
	}
	return PluginTransitionResult{Changed: int(changed)}, nil
}

func (s *SQLiteStore) Prune(ctx context.Context, req PruneRequest) (PruneResult, error) {
	if s == nil {
		return PruneResult{}, errors.New("stream store is nil")
	}
	before, limit, maxRecordsPerPlugin, err := normalizePruneRequest(req)
	if err != nil {
		return PruneResult{}, err
	}
	releaseWrite, err := s.lockWrite(ctx)
	if err != nil {
		return PruneResult{}, err
	}
	defer releaseWrite()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PruneResult{}, err
	}
	defer rollbackUnlessCommitted(tx)
	rows, err := tx.QueryContext(ctx, `
WITH ranked_terminal AS (
	SELECT
		stream_id,
		closed_at,
		ROW_NUMBER() OVER (
			PARTITION BY owner_env_hash, plugin_instance_id
			ORDER BY closed_at DESC, stream_id DESC
		) AS terminal_rank
	FROM plugin_streams
	WHERE status IN (?, ?, ?, ?, ?)
		AND closed_at IS NOT NULL
		AND terminal_acknowledged = 1
		AND pending_delivery_id = ''
		AND buffered_bytes = 0
		AND NOT EXISTS (
			SELECT 1 FROM plugin_stream_events WHERE plugin_stream_events.stream_id = plugin_streams.stream_id
		)
)
SELECT stream_id
FROM ranked_terminal
WHERE closed_at < ? OR terminal_rank > ?
ORDER BY closed_at ASC, stream_id ASC
LIMIT ?`,
		string(StatusClosed),
		string(StatusCanceled),
		string(StatusFailed),
		string(StatusOrphanedDisabled),
		string(StatusOrphanedRemoved),
		before.UnixNano(),
		maxRecordsPerPlugin,
		limit,
	)
	if err != nil {
		return PruneResult{}, err
	}
	streamIDs := make([]string, 0)
	for rows.Next() {
		var streamID string
		if err := rows.Scan(&streamID); err != nil {
			_ = rows.Close()
			return PruneResult{}, err
		}
		streamIDs = append(streamIDs, streamID)
	}
	if err := rows.Close(); err != nil {
		return PruneResult{}, err
	}
	if err := rows.Err(); err != nil {
		return PruneResult{}, err
	}
	for _, streamID := range streamIDs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_streams WHERE stream_id = ?`, streamID); err != nil {
			return PruneResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return PruneResult{}, mutation.Unknown(err)
	}
	for _, streamID := range streamIDs {
		s.removeNotification(streamID)
	}
	return PruneResult{Deleted: len(streamIDs)}, nil
}

func (s *SQLiteStore) update(ctx context.Context, streamID string, now time.Time, mutate func(Record) Record) (Record, error) {
	release, err := s.lockStream(ctx, streamID)
	if err != nil {
		return Record{}, err
	}
	defer release()
	releaseWrite, err := s.lockWrite(ctx)
	if err != nil {
		return Record{}, err
	}
	defer releaseWrite()

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
	previousStatus := record.Status
	record = mutate(record)
	record.UpdatedAt = now
	if err := updateSQLiteStreamState(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	if previousStatus != record.Status {
		s.notifyStream(record.StreamID)
	}
	return record, nil
}

func (s *SQLiteStore) initializeSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return err
	}
	var journalMode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode = WAL`).Scan(&journalMode); err != nil {
		return err
	}
	if !strings.EqualFold(journalMode, "wal") {
		return errors.New("sqlite stream store requires WAL journal mode")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)

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
	owner_env_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	bridge_channel_id TEXT NOT NULL,
	execution_binding_json TEXT NOT NULL DEFAULT '{}',
	direction TEXT NOT NULL,
		status TEXT NOT NULL,
		failure_code TEXT NOT NULL,
		reason TEXT NOT NULL DEFAULT '',
	content_type TEXT NOT NULL,
		max_buffered_bytes INTEGER NOT NULL,
		buffered_bytes INTEGER NOT NULL,
		next_sequence INTEGER NOT NULL,
		pending_delivery_id TEXT NOT NULL,
		pending_read_id TEXT NOT NULL,
		pending_through_sequence INTEGER NOT NULL,
		pending_done INTEGER NOT NULL,
		pending_terminal_status TEXT NOT NULL,
		last_acknowledged_delivery_id TEXT NOT NULL,
		terminal_acknowledged INTEGER NOT NULL,
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
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_streams_owner_plugin_instance ON plugin_streams(owner_env_hash, plugin_instance_id, created_at, stream_id)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_streams_terminal_retention ON plugin_streams(plugin_instance_id, closed_at DESC, stream_id DESC) WHERE terminal_acknowledged = 1`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_streams_owner_terminal_retention ON plugin_streams(owner_env_hash, plugin_instance_id, closed_at DESC, stream_id DESC) WHERE terminal_acknowledged = 1`); err != nil {
		return err
	}
	return tx.Commit()
}

const streamSelectColumns = `
SELECT
	stream_id, plugin_id, plugin_instance_id, method, effect, execution,
	surface_instance_id, owner_session_hash, owner_user_hash, owner_env_hash,
	session_channel_id_hash, bridge_channel_id, execution_binding_json, direction, status, failure_code, reason, content_type,
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

func getSQLiteDeliverySnapshot(ctx context.Context, q sqliteQuerier, streamID string) (Record, sqliteDeliveryState, bool, bool, error) {
	row := q.QueryRowContext(ctx, streamSelectColumns+`,
	pending_delivery_id, pending_read_id, pending_through_sequence, pending_done,
	pending_terminal_status, last_acknowledged_delivery_id, terminal_acknowledged,
	EXISTS(
		SELECT 1 FROM plugin_stream_events
		WHERE plugin_stream_events.stream_id = plugin_streams.stream_id
		LIMIT 1
	)
FROM plugin_streams WHERE stream_id = ?`, streamID)
	record, state, eventExists, err := scanSQLiteDeliverySnapshot(row, streamID)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, sqliteDeliveryState{}, false, false, nil
	}
	if err != nil {
		return Record{}, sqliteDeliveryState{}, false, false, err
	}
	return record, state, eventExists, true, nil
}

func insertSQLiteStream(ctx context.Context, tx *sql.Tx, record Record) error {
	bindingJSON, err := json.Marshal(record.ExecutionBinding)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO plugin_streams (
	stream_id, plugin_id, plugin_instance_id, method, effect, execution,
	surface_instance_id, owner_session_hash, owner_user_hash, owner_env_hash,
			session_channel_id_hash, bridge_channel_id, execution_binding_json, direction, status, failure_code, reason, content_type,
		max_buffered_bytes, buffered_bytes, next_sequence,
		pending_delivery_id, pending_read_id, pending_through_sequence, pending_done, pending_terminal_status,
		last_acknowledged_delivery_id, terminal_acknowledged,
		created_at, updated_at, closed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.StreamID,
		record.PluginID,
		record.PluginInstanceID,
		record.Method,
		record.Effect,
		record.Execution,
		record.SurfaceInstanceID,
		record.OwnerSessionHash,
		record.OwnerUserHash,
		record.OwnerEnvHash,
		record.SessionChannelIDHash,
		record.BridgeChannelID,
		string(bindingJSON),
		string(record.Direction),
		string(record.Status),
		string(record.FailureCode),
		record.Reason,
		record.ContentType,
		record.MaxBufferedBytes,
		record.BufferedBytes,
		1,
		"",
		"",
		0,
		false,
		"",
		"",
		false,
		record.CreatedAt.UTC().UnixNano(),
		record.UpdatedAt.UTC().UnixNano(),
		timePtrToNullableUnix(record.ClosedAt),
	)
	return err
}

func updateSQLiteStreamState(ctx context.Context, tx *sql.Tx, record Record) error {
	_, err := tx.ExecContext(ctx, `
UPDATE plugin_streams
SET status = ?, failure_code = ?, reason = ?, buffered_bytes = ?, updated_at = ?, closed_at = ?
WHERE stream_id = ?`,
		string(record.Status),
		string(record.FailureCode),
		record.Reason,
		record.BufferedBytes,
		record.UpdatedAt.UTC().UnixNano(),
		timePtrToNullableUnix(record.ClosedAt),
		record.StreamID,
	)
	return err
}

func nextSQLiteStreamSequence(ctx context.Context, q sqliteQuerier, streamID string) (uint64, error) {
	var sequence uint64
	if err := q.QueryRowContext(ctx, `SELECT next_sequence FROM plugin_streams WHERE stream_id = ?`, streamID).Scan(&sequence); err != nil {
		return 0, err
	}
	return sequence, nil
}

func getSQLiteDeliveryState(ctx context.Context, q sqliteQuerier, streamID string) (sqliteDeliveryState, error) {
	var state sqliteDeliveryState
	if err := q.QueryRowContext(ctx, `
SELECT pending_delivery_id, pending_read_id, pending_through_sequence, pending_done,
	pending_terminal_status, last_acknowledged_delivery_id, terminal_acknowledged
FROM plugin_streams WHERE stream_id = ?`, streamID).Scan(
		&state.Pending.DeliveryID,
		&state.Pending.ReadID,
		&state.Pending.ThroughSequence,
		&state.Pending.Done,
		&state.Pending.TerminalStatus,
		&state.LastAcknowledgedID,
		&state.TerminalAcknowledged,
	); err != nil {
		return sqliteDeliveryState{}, err
	}
	state.Pending.StreamID = streamID
	return state, nil
}

func updateSQLiteDeliveryState(ctx context.Context, tx *sql.Tx, streamID string, state sqliteDeliveryState) error {
	_, err := tx.ExecContext(ctx, `
UPDATE plugin_streams
SET pending_delivery_id = ?, pending_read_id = ?, pending_through_sequence = ?, pending_done = ?,
	pending_terminal_status = ?, last_acknowledged_delivery_id = ?, terminal_acknowledged = ?
WHERE stream_id = ?`,
		state.Pending.DeliveryID,
		state.Pending.ReadID,
		state.Pending.ThroughSequence,
		state.Pending.Done,
		string(state.Pending.TerminalStatus),
		state.LastAcknowledgedID,
		state.TerminalAcknowledged,
		streamID,
	)
	return err
}

func compareAndSetSQLitePendingDelivery(ctx context.Context, tx *sql.Tx, record Record, expected sqliteDeliveryState, pending Delivery) (bool, error) {
	result, err := tx.ExecContext(ctx, `
	UPDATE plugin_streams
	SET pending_delivery_id = ?, pending_read_id = ?, pending_through_sequence = ?, pending_done = ?,
		pending_terminal_status = ?
	WHERE stream_id = ?
		AND status = ?
		AND buffered_bytes = ?
		AND pending_delivery_id = ?
		AND pending_read_id = ?
		AND pending_through_sequence = ?
		AND pending_done = ?
		AND pending_terminal_status = ?
		AND last_acknowledged_delivery_id = ?
		AND terminal_acknowledged = ?`,
		pending.DeliveryID,
		pending.ReadID,
		pending.ThroughSequence,
		pending.Done,
		string(pending.TerminalStatus),
		record.StreamID,
		string(record.Status),
		record.BufferedBytes,
		expected.Pending.DeliveryID,
		expected.Pending.ReadID,
		expected.Pending.ThroughSequence,
		expected.Pending.Done,
		string(expected.Pending.TerminalStatus),
		expected.LastAcknowledgedID,
		expected.TerminalAcknowledged,
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected < 0 || affected > 1 {
		return false, ErrStreamInvariant
	}
	return affected == 1, nil
}

func sqliteDeliveryStateMatches(ctx context.Context, q sqliteQuerier, streamID string, expected sqliteDeliveryState) (bool, error) {
	var matches bool
	err := q.QueryRowContext(ctx, `
	SELECT EXISTS(
		SELECT 1 FROM plugin_streams
		WHERE stream_id = ?
			AND pending_delivery_id = ?
			AND pending_read_id = ?
			AND pending_through_sequence = ?
			AND pending_done = ?
			AND pending_terminal_status = ?
			AND last_acknowledged_delivery_id = ?
			AND terminal_acknowledged = ?
	)`,
		streamID,
		expected.Pending.DeliveryID,
		expected.Pending.ReadID,
		expected.Pending.ThroughSequence,
		expected.Pending.Done,
		string(expected.Pending.TerminalStatus),
		expected.LastAcknowledgedID,
		expected.TerminalAcknowledged,
	).Scan(&matches)
	return matches, err
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

func listSQLiteStreamEvents(ctx context.Context, q sqliteQuerier, streamID string, maxEvents int, maxBytes int64) ([]Event, error) {
	limit := maxEvents
	if limit <= 0 || limit > maxSQLiteReadEvents {
		limit = maxSQLiteReadEvents
	}
	rows, err := q.QueryContext(ctx, `SELECT stream_id, sequence, kind, data, error, at FROM plugin_stream_events WHERE stream_id = ? ORDER BY sequence ASC LIMIT ?`, streamID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []Event{}
	var totalBytes int64
	for rows.Next() {
		event, err := scanSQLiteStreamEvent(rows)
		if err != nil {
			return nil, err
		}
		eventBytes := streamEventCost(event)
		if maxBytes > 0 && len(events) > 0 && totalBytes+eventBytes > maxBytes {
			break
		}
		events = append(events, event)
		totalBytes += eventBytes
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func listSQLiteStreamEventsThrough(ctx context.Context, q sqliteQuerier, streamID string, throughSequence uint64) ([]Event, error) {
	rows, err := q.QueryContext(ctx, `SELECT stream_id, sequence, kind, data, error, at FROM plugin_stream_events WHERE stream_id = ? AND sequence <= ? ORDER BY sequence ASC`, streamID, throughSequence)
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

func deleteSQLiteStreamEvents(ctx context.Context, tx *sql.Tx, streamID string, throughSequence uint64) (int64, error) {
	rows, err := tx.QueryContext(ctx, `
DELETE FROM plugin_stream_events
WHERE stream_id = ? AND sequence <= ?
RETURNING kind, data, error`, streamID, throughSequence)
	if err != nil {
		return 0, err
	}
	var total int64
	for rows.Next() {
		var kind string
		var data []byte
		var eventError string
		if err := rows.Scan(&kind, &data, &eventError); err != nil {
			_ = rows.Close()
			return 0, err
		}
		total += streamEventOverheadBytes + int64(len(kind)+len(data)+len(eventError))
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	return total, nil
}

func (s *SQLiteStore) notification(streamID string) (*streamNotification, uint64) {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	notification := s.notify[streamID]
	if notification == nil {
		notification = &streamNotification{ready: make(chan struct{})}
		s.notify[streamID] = notification
	}
	notification.waiters++
	return notification, notification.revision
}

func (s *SQLiteStore) notificationChanged(streamID string, notification *streamNotification, revision uint64) bool {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	return s.notify[streamID] != notification || notification.revision != revision
}

func (s *SQLiteStore) beginWaitObservation() (uint64, <-chan struct{}, func(), error) {
	s.transitionMu.Lock()
	if s.closed {
		s.transitionMu.Unlock()
		return 0, nil, nil, ErrStoreClosed
	}
	if s.waitObservations == 0 {
		s.observationsReady = make(chan struct{})
	}
	s.waitObservations++
	revision := s.transitionRevision
	ready := s.transitionReady
	s.transitionMu.Unlock()
	finished := false
	finish := func() {
		if finished {
			return
		}
		finished = true
		s.transitionMu.Lock()
		s.waitObservations--
		if s.waitObservations == 0 {
			close(s.observationsReady)
			s.observationsReady = nil
		}
		s.transitionMu.Unlock()
	}
	return revision, ready, finish, nil
}

func (s *SQLiteStore) transitionSnapshot() (uint64, <-chan struct{}, error) {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	if s.closed {
		return 0, nil, ErrStoreClosed
	}
	return s.transitionRevision, s.transitionReady, nil
}

func (s *SQLiteStore) transitionChanged(revision uint64, ready <-chan struct{}) bool {
	select {
	case <-ready:
		return true
	default:
	}
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	return s.closed || s.transitionRevision != revision
}

func (s *SQLiteStore) pluginNotification(pluginKey string) (*streamNotification, uint64, error) {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	if s.closed {
		return nil, 0, ErrStoreClosed
	}
	notification := s.pluginNotify[pluginKey]
	if notification == nil {
		notification = &streamNotification{ready: make(chan struct{})}
		s.pluginNotify[pluginKey] = notification
	}
	notification.waiters++
	return notification, notification.revision, nil
}

func (s *SQLiteStore) pluginNotificationChanged(pluginKey string, notification *streamNotification, revision uint64) bool {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	return s.closed || s.pluginNotify[pluginKey] != notification || notification.revision != revision
}

func (s *SQLiteStore) releasePluginNotification(pluginKey string, notification *streamNotification) {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	if notification.waiters > 0 {
		notification.waiters--
	}
	if notification.waiters == 0 && s.pluginNotify[pluginKey] == notification {
		delete(s.pluginNotify, pluginKey)
	}
}

func (s *SQLiteStore) notifyPluginTransition(pluginKey string) {
	s.transitionMu.Lock()
	if s.closed {
		s.transitionMu.Unlock()
		return
	}
	s.transitionRevision++
	close(s.transitionReady)
	s.transitionReady = make(chan struct{})
	if notification := s.pluginNotify[pluginKey]; notification != nil {
		notification.revision++
		delete(s.pluginNotify, pluginKey)
		close(notification.ready)
	}
	s.transitionMu.Unlock()
}

func (s *SQLiteStore) closeNotifications() <-chan struct{} {
	s.transitionMu.Lock()
	if s.closed {
		observationsReady := s.observationsReady
		s.transitionMu.Unlock()
		return observationsReady
	}
	s.closed = true
	s.transitionRevision++
	close(s.transitionReady)
	observationsReady := s.observationsReady
	for pluginKey, notification := range s.pluginNotify {
		notification.revision++
		delete(s.pluginNotify, pluginKey)
		close(notification.ready)
	}
	s.transitionMu.Unlock()

	s.notifyMu.Lock()
	for streamID, notification := range s.notify {
		notification.revision++
		delete(s.notify, streamID)
		close(notification.ready)
	}
	s.notifyMu.Unlock()
	return observationsReady
}

func pluginTransitionKey(ownerEnvHash, pluginInstanceID string) string {
	return ownerEnvHash + "\x00" + pluginInstanceID
}

func (s *SQLiteStore) releaseNotification(streamID string, notification *streamNotification) {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	if notification.waiters > 0 {
		notification.waiters--
	}
	if notification.waiters == 0 && s.notify[streamID] == notification {
		delete(s.notify, streamID)
	}
}

func (s *SQLiteStore) notifyStream(streamID string) {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	notification := s.notify[streamID]
	if notification == nil {
		return
	}
	notification.revision++
	delete(s.notify, streamID)
	close(notification.ready)
}

func (s *SQLiteStore) removeNotification(streamID string) {
	s.notifyMu.Lock()
	notification := s.notify[streamID]
	delete(s.notify, streamID)
	if notification != nil {
		notification.revision++
		close(notification.ready)
	}
	s.notifyMu.Unlock()
}

func (s *SQLiteStore) lockStream(ctx context.Context, streamID string) (func(), error) {
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		return nil, ErrInvalidStream
	}
	s.lockTableMu.Lock()
	lock := s.locks[streamID]
	if lock == nil {
		lock = &sqliteStreamLock{token: make(chan struct{}, 1)}
		lock.token <- struct{}{}
		s.locks[streamID] = lock
	}
	lock.refs++
	s.lockTableMu.Unlock()

	select {
	case <-ctx.Done():
		s.releaseStreamLockRef(streamID, lock)
		return nil, ctx.Err()
	case <-lock.token:
		return func() {
			lock.token <- struct{}{}
			s.releaseStreamLockRef(streamID, lock)
		}, nil
	}
}

func (s *SQLiteStore) releaseStreamLockRef(streamID string, lock *sqliteStreamLock) {
	s.lockTableMu.Lock()
	defer s.lockTableMu.Unlock()
	lock.refs--
	if lock.refs == 0 && s.locks[streamID] == lock {
		delete(s.locks, streamID)
	}
}

func (s *SQLiteStore) lockWrite(ctx context.Context) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.writeGate:
		return func() { s.writeGate <- struct{}{} }, nil
	}
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
	var bindingJSON string
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
		&record.OwnerEnvHash,
		&record.SessionChannelIDHash,
		&record.BridgeChannelID,
		&bindingJSON,
		&direction,
		&status,
		&record.FailureCode,
		&record.Reason,
		&record.ContentType,
		&record.MaxBufferedBytes,
		&record.BufferedBytes,
		&createdAt,
		&updatedAt,
		&closedAt,
	); err != nil {
		return Record{}, err
	}
	return finishSQLiteStreamScan(record, bindingJSON, direction, status, createdAt, updatedAt, closedAt)
}

func scanSQLiteDeliverySnapshot(scanner sqliteStreamScanner, streamID string) (Record, sqliteDeliveryState, bool, error) {
	var record Record
	var state sqliteDeliveryState
	var eventExists bool
	var bindingJSON string
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
		&record.OwnerEnvHash,
		&record.SessionChannelIDHash,
		&record.BridgeChannelID,
		&bindingJSON,
		&direction,
		&status,
		&record.FailureCode,
		&record.Reason,
		&record.ContentType,
		&record.MaxBufferedBytes,
		&record.BufferedBytes,
		&createdAt,
		&updatedAt,
		&closedAt,
		&state.Pending.DeliveryID,
		&state.Pending.ReadID,
		&state.Pending.ThroughSequence,
		&state.Pending.Done,
		&state.Pending.TerminalStatus,
		&state.LastAcknowledgedID,
		&state.TerminalAcknowledged,
		&eventExists,
	); err != nil {
		return Record{}, sqliteDeliveryState{}, false, err
	}
	record, err := finishSQLiteStreamScan(record, bindingJSON, direction, status, createdAt, updatedAt, closedAt)
	if err != nil {
		return Record{}, sqliteDeliveryState{}, false, err
	}
	state.Pending.StreamID = streamID
	return record, state, eventExists, nil
}

func finishSQLiteStreamScan(record Record, bindingJSON, direction, status string, createdAt, updatedAt int64, closedAt sql.NullInt64) (Record, error) {
	indexedStreamID := record.StreamID
	indexedPluginID := record.PluginID
	indexedPluginInstanceID := record.PluginInstanceID
	indexedMethod := record.Method
	indexedEffect := record.Effect
	indexedExecution := record.Execution
	indexedSurfaceInstanceID := record.SurfaceInstanceID
	indexedOwner := record.ExecutionBinding.OwnerScope()
	indexedBridgeChannelID := record.BridgeChannelID
	if strings.TrimSpace(bindingJSON) == "" || strings.TrimSpace(bindingJSON) == "{}" {
		return Record{}, ErrInvalidStream
	}
	var decodedBinding capability.ExecutionBinding
	if err := jsonvalue.DecodeClosed([]byte(bindingJSON), &decodedBinding); err != nil {
		return Record{}, ErrInvalidStream
	}
	binding, err := cloneExecutionBinding(decodedBinding)
	if err != nil {
		return Record{}, ErrInvalidStream
	}
	record.ExecutionBinding = binding
	if record.ExecutionBinding.StreamID != indexedStreamID || record.PluginID != indexedPluginID || record.PluginInstanceID != indexedPluginInstanceID ||
		record.Method != indexedMethod || record.Effect != indexedEffect || record.Execution != indexedExecution ||
		record.SurfaceInstanceID != indexedSurfaceInstanceID || record.BridgeChannelID != indexedBridgeChannelID ||
		record.ExecutionBinding.OwnerScope() != indexedOwner {
		return Record{}, ErrInvalidStream
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
