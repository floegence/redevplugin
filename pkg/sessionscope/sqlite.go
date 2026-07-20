package sessionscope

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
	_ "modernc.org/sqlite"
)

const sessionScopeSQLiteSchemaVersion = 1

type SQLiteStore struct {
	db      *sql.DB
	mu      sync.Mutex
	options StoreOptions
}

func NewSQLiteStore(ctx context.Context, path string, options StoreOptions) (*SQLiteStore, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite session scope path is required")
	}
	normalized, err := normalizeStoreOptions(options)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db, options: normalized}
	if err := store.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) Durable() bool { return s != nil && s.db != nil }

func (s *SQLiteStore) Get(ctx context.Context, scope sessionctx.SessionScope) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists, err := getSQLiteSessionScope(ctx, s.db, scope)
	if err != nil {
		return record{}, err
	}
	if !exists {
		return record{}, ErrScopeNotFound
	}
	return current, nil
}

func (s *SQLiteStore) ListRetained(ctx context.Context) ([]record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, sqliteSessionScopeSelect+` ORDER BY owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]record, 0)
	for rows.Next() {
		current, err := scanSQLiteSessionScope(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, current)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SQLiteStore) BeginTeardown(
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
	now = normalizedStoreTime(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return record{}, err
	}
	defer rollbackSQLiteStore(tx)
	current, exists, err := getSQLiteSessionScope(ctx, tx, scope)
	if err != nil {
		return record{}, err
	}
	if !exists {
		if err := s.requireCapacity(ctx, tx); err != nil {
			return record{}, err
		}
		current = record{
			Scope:               scope,
			State:               StateDraining,
			TeardownOperationID: operationID,
			ProofSHA256:         proof,
			HasProof:            true,
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if err := insertSQLiteSessionScope(ctx, tx, current); err != nil {
			return record{}, err
		}
	} else {
		if !recordMatchesTeardownIdentity(current, operationID, proof) {
			return record{}, ErrTeardownIdentityMismatch
		}
		switch current.State {
		case StateIncomplete, StateDraining:
			current.State = StateDraining
			current.UpdatedAt = now
			if err := updateSQLiteSessionScope(ctx, tx, current); err != nil {
				return record{}, err
			}
		case StateComplete:
		default:
			return record{}, ErrInvalidState
		}
	}
	if err := tx.Commit(); err != nil {
		return record{}, err
	}
	return current, nil
}

func (s *SQLiteStore) Accumulate(ctx context.Context, scope sessionctx.SessionScope, delta Counts, now time.Time) (record, error) {
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

func (s *SQLiteStore) AccumulatePhase(ctx context.Context, scope sessionctx.SessionScope, phase Phase, delta Counts, now time.Time) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	if !phase.Valid() || !delta.Valid() {
		return record{}, ErrInvalidCounts
	}
	now = normalizedStoreTime(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return record{}, err
	}
	defer rollbackSQLiteStore(tx)
	current, exists, err := getSQLiteSessionScope(ctx, tx, scope)
	if err != nil {
		return record{}, err
	}
	if !exists {
		return record{}, ErrScopeNotFound
	}
	if current.State != StateDraining {
		return record{}, ErrInvalidState
	}
	var persisted []byte
	err = tx.QueryRowContext(ctx, `
SELECT counts_json
FROM plugin_session_scope_teardown_phases
WHERE owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ? AND phase = ?`,
		scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, phase,
	).Scan(&persisted)
	if err == nil {
		_, decodeErr := decodePhaseCounts(persisted)
		if decodeErr != nil {
			return record{}, ErrInvalidCounts
		}
		return current, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return record{}, err
	}
	counts, err := current.Counts.Add(delta)
	if err != nil {
		return record{}, err
	}
	current.Counts = counts
	current.UpdatedAt = now
	if err := updateSQLiteSessionScope(ctx, tx, current); err != nil {
		return record{}, err
	}
	encoded, err := json.Marshal(delta)
	if err != nil {
		return record{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_session_scope_teardown_phases (
    owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, phase, counts_json
) VALUES (?, ?, ?, ?, ?, ?)`,
		scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash, phase, encoded,
	); err != nil {
		return record{}, err
	}
	if err := tx.Commit(); err != nil {
		return record{}, err
	}
	return current, nil
}

func (s *SQLiteStore) MarkIncomplete(ctx context.Context, scope sessionctx.SessionScope, now time.Time) (record, error) {
	return s.transition(ctx, scope, now, func(current *record) error {
		if current.State != StateDraining && current.State != StateIncomplete {
			return ErrInvalidState
		}
		current.State = StateIncomplete
		return nil
	})
}

func (s *SQLiteStore) MarkComplete(ctx context.Context, scope sessionctx.SessionScope, now time.Time) (record, error) {
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

func (s *SQLiteStore) Finalize(ctx context.Context, scope sessionctx.SessionScope, operationID string, proof [sha256.Size]byte) error {
	if err := validateStoreCall(ctx, scope); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackSQLiteStore(tx)
	current, exists, err := getSQLiteSessionScope(ctx, tx, scope)
	if err != nil {
		return err
	}
	if !exists || current.State != StateComplete || !recordMatchesTeardownIdentity(current, operationID, proof) {
		return ErrClosedSessionProofInvalid
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM plugin_session_scope_teardown_phases
WHERE owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ?`,
		scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash,
	); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
DELETE FROM plugin_session_scope_fences
WHERE owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ?
	  AND state = ? AND teardown_operation_id = ? AND proof_sha256 = ?`,
		scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash,
		StateComplete, operationID, proof[:],
	)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrClosedSessionProofInvalid
	}
	return tx.Commit()
}

func (s *SQLiteStore) transition(ctx context.Context, scope sessionctx.SessionScope, now time.Time, apply func(*record) error) (record, error) {
	if err := validateStoreCall(ctx, scope); err != nil {
		return record{}, err
	}
	now = normalizedStoreTime(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return record{}, err
	}
	defer rollbackSQLiteStore(tx)
	current, exists, err := getSQLiteSessionScope(ctx, tx, scope)
	if err != nil {
		return record{}, err
	}
	if !exists {
		return record{}, ErrScopeNotFound
	}
	if err := apply(&current); err != nil {
		return record{}, err
	}
	current.UpdatedAt = now
	if err := updateSQLiteSessionScope(ctx, tx, current); err != nil {
		return record{}, err
	}
	if err := tx.Commit(); err != nil {
		return record{}, err
	}
	return current, nil
}

func (s *SQLiteStore) requireCapacity(ctx context.Context, tx *sql.Tx) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_session_scope_fences`).Scan(&count); err != nil {
		return err
	}
	if count >= s.options.MaxScopes {
		return ErrFenceCapacity
	}
	return nil
}

func (s *SQLiteStore) initialize(ctx context.Context) error {
	for _, statement := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA synchronous = FULL`,
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	var schemaVersion int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&schemaVersion); err != nil {
		return err
	}
	if schemaVersion != 0 && schemaVersion != sessionScopeSQLiteSchemaVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrSchemaVersion, schemaVersion, sessionScopeSQLiteSchemaVersion)
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_session_scope_fences (
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	owner_env_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('draining', 'incomplete', 'complete')),
	teardown_operation_id TEXT NOT NULL,
	surfaces INTEGER NOT NULL CHECK (surfaces BETWEEN 0 AND 9007199254740991),
	asset_tickets INTEGER NOT NULL CHECK (asset_tickets BETWEEN 0 AND 9007199254740991),
	asset_sessions INTEGER NOT NULL CHECK (asset_sessions BETWEEN 0 AND 9007199254740991),
	plugin_gateway_tokens INTEGER NOT NULL CHECK (plugin_gateway_tokens BETWEEN 0 AND 9007199254740991),
	confirmation_tokens INTEGER NOT NULL CHECK (confirmation_tokens BETWEEN 0 AND 9007199254740991),
	stream_tickets INTEGER NOT NULL CHECK (stream_tickets BETWEEN 0 AND 9007199254740991),
	handle_grants INTEGER NOT NULL CHECK (handle_grants BETWEEN 0 AND 9007199254740991),
	confirmations INTEGER NOT NULL CHECK (confirmations BETWEEN 0 AND 9007199254740991),
	operations INTEGER NOT NULL CHECK (operations BETWEEN 0 AND 9007199254740991),
	streams INTEGER NOT NULL CHECK (streams BETWEEN 0 AND 9007199254740991),
	runtime_executions INTEGER NOT NULL CHECK (runtime_executions BETWEEN 0 AND 9007199254740991),
	active_network_requests INTEGER NOT NULL CHECK (active_network_requests BETWEEN 0 AND 9007199254740991),
	sockets INTEGER NOT NULL CHECK (sockets BETWEEN 0 AND 9007199254740991),
	network_streams INTEGER NOT NULL CHECK (network_streams BETWEEN 0 AND 9007199254740991),
	storage_hostcalls INTEGER NOT NULL CHECK (storage_hostcalls BETWEEN 0 AND 9007199254740991),
	proof_sha256 BLOB,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash),
	CHECK (length(teardown_operation_id) BETWEEN 1 AND 256 AND length(proof_sha256) = 32)
)`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_session_scope_teardown_phases (
	owner_session_hash TEXT NOT NULL,
	owner_user_hash TEXT NOT NULL,
	owner_env_hash TEXT NOT NULL,
	session_channel_id_hash TEXT NOT NULL,
	phase TEXT NOT NULL CHECK (phase IN ('bridge', 'confirmation', 'execution', 'operation', 'stream', 'runtime')),
	counts_json BLOB NOT NULL CHECK (length(counts_json) BETWEEN 2 AND 4096),
	PRIMARY KEY (owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash, phase),
	FOREIGN KEY (owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash)
		REFERENCES plugin_session_scope_fences (owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash)
		ON DELETE RESTRICT
)`); err != nil {
		return err
	}
	if schemaVersion == 0 {
		if _, err := s.db.ExecContext(ctx, `PRAGMA user_version = 1`); err != nil {
			return err
		}
	}
	rows, err := s.db.QueryContext(ctx, sqliteSessionScopeSelect+` ORDER BY owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash`)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		if _, err := scanSQLiteSessionScope(rows); err != nil {
			return err
		}
		count++
		if count > s.options.MaxScopes {
			return ErrFenceCapacity
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	phaseRows, err := s.db.QueryContext(ctx, `SELECT phase, counts_json FROM plugin_session_scope_teardown_phases`)
	if err != nil {
		return err
	}
	defer phaseRows.Close()
	for phaseRows.Next() {
		var phase Phase
		var encoded []byte
		if err := phaseRows.Scan(&phase, &encoded); err != nil {
			return err
		}
		if !phase.Valid() {
			return ErrInvalidCounts
		}
		if _, err := decodePhaseCounts(encoded); err != nil {
			return err
		}
	}
	return phaseRows.Err()
}

func decodePhaseCounts(encoded []byte) (Counts, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var counts Counts
	if err := decoder.Decode(&counts); err != nil {
		return Counts{}, ErrInvalidCounts
	}
	if decoder.More() || !counts.Valid() {
		return Counts{}, ErrInvalidCounts
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Counts{}, ErrInvalidCounts
	}
	return counts, nil
}

const sqliteSessionScopeSelect = `
SELECT owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash,
       state, teardown_operation_id, surfaces, asset_tickets, asset_sessions, plugin_gateway_tokens,
       confirmation_tokens, stream_tickets, handle_grants, confirmations, operations,
       streams, runtime_executions, active_network_requests, sockets, network_streams,
       storage_hostcalls, proof_sha256, created_at, updated_at
FROM plugin_session_scope_fences`

type sqliteSessionScopeQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqliteSessionScopeScanner interface {
	Scan(...any) error
}

func getSQLiteSessionScope(ctx context.Context, query sqliteSessionScopeQuerier, scope sessionctx.SessionScope) (record, bool, error) {
	row := query.QueryRowContext(ctx, sqliteSessionScopeSelect+`
WHERE owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ?`,
		scope.OwnerSessionHash, scope.OwnerUserHash, scope.OwnerEnvHash, scope.SessionChannelIDHash,
	)
	current, err := scanSQLiteSessionScope(row)
	if errors.Is(err, sql.ErrNoRows) {
		return record{}, false, nil
	}
	return current, err == nil, err
}

func scanSQLiteSessionScope(scanner sqliteSessionScopeScanner) (record, error) {
	var current record
	var state string
	var proof []byte
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&current.Scope.OwnerSessionHash, &current.Scope.OwnerUserHash, &current.Scope.OwnerEnvHash, &current.Scope.SessionChannelIDHash,
		&state, &current.TeardownOperationID, &current.Counts.Surfaces, &current.Counts.AssetTickets, &current.Counts.AssetSessions,
		&current.Counts.PluginGatewayTokens, &current.Counts.ConfirmationTokens, &current.Counts.StreamTickets,
		&current.Counts.HandleGrants, &current.Counts.Confirmations, &current.Counts.Operations,
		&current.Counts.Streams, &current.Counts.RuntimeExecutions, &current.Counts.ActiveNetworkRequests,
		&current.Counts.Sockets, &current.Counts.NetworkStreams, &current.Counts.StorageHostcalls,
		&proof, &createdAt, &updatedAt,
	)
	if err != nil {
		return record{}, err
	}
	current.State = State(state)
	if err := current.Scope.Validate(); err != nil {
		return record{}, err
	}
	if !current.State.Valid() {
		return record{}, ErrInvalidState
	}
	if !current.Counts.Valid() {
		return record{}, ErrInvalidCounts
	}
	if current.State == StateActive || !validTeardownOperationID(current.TeardownOperationID) {
		return record{}, ErrTeardownIdentityInvalid
	}
	if len(proof) == 0 && current.State == StateComplete {
		current.HasProof = false
	} else {
		if len(proof) != sha256.Size {
			return record{}, ErrClosedSessionProofInvalid
		}
		copy(current.ProofSHA256[:], proof)
		current.HasProof = true
	}
	current.CreatedAt = time.Unix(0, createdAt).UTC()
	current.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if current.CreatedAt.IsZero() || current.UpdatedAt.IsZero() || current.UpdatedAt.Before(current.CreatedAt) {
		return record{}, ErrInvalidState
	}
	return current, nil
}

func insertSQLiteSessionScope(ctx context.Context, tx *sql.Tx, current record) error {
	if err := validateSQLiteSessionScopeRecord(current); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_session_scope_fences (
	owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash,
	state, teardown_operation_id, surfaces, asset_tickets, asset_sessions, plugin_gateway_tokens,
	confirmation_tokens, stream_tickets, handle_grants, confirmations, operations,
	streams, runtime_executions, active_network_requests, sockets, network_streams,
	storage_hostcalls, proof_sha256, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, sqliteSessionScopeArguments(current)...)
	return err
}

func updateSQLiteSessionScope(ctx context.Context, tx *sql.Tx, current record) error {
	if err := validateSQLiteSessionScopeRecord(current); err != nil {
		return err
	}
	args := sqliteSessionScopeArguments(current)
	result, err := tx.ExecContext(ctx, `
UPDATE plugin_session_scope_fences SET
	state = ?, teardown_operation_id = ?, surfaces = ?, asset_tickets = ?, asset_sessions = ?, plugin_gateway_tokens = ?,
	confirmation_tokens = ?, stream_tickets = ?, handle_grants = ?, confirmations = ?, operations = ?,
	streams = ?, runtime_executions = ?, active_network_requests = ?, sockets = ?, network_streams = ?,
	storage_hostcalls = ?, proof_sha256 = ?, created_at = ?, updated_at = ?
WHERE owner_session_hash = ? AND owner_user_hash = ? AND owner_env_hash = ? AND session_channel_id_hash = ?`,
		append(args[4:], args[:4]...)...,
	)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrScopeNotFound
	}
	return nil
}

func sqliteSessionScopeArguments(current record) []any {
	var proof any
	if current.HasProof {
		proof = current.ProofSHA256[:]
	}
	return []any{
		current.Scope.OwnerSessionHash, current.Scope.OwnerUserHash, current.Scope.OwnerEnvHash, current.Scope.SessionChannelIDHash,
		current.State, current.TeardownOperationID, current.Counts.Surfaces, current.Counts.AssetTickets, current.Counts.AssetSessions,
		current.Counts.PluginGatewayTokens, current.Counts.ConfirmationTokens, current.Counts.StreamTickets,
		current.Counts.HandleGrants, current.Counts.Confirmations, current.Counts.Operations,
		current.Counts.Streams, current.Counts.RuntimeExecutions, current.Counts.ActiveNetworkRequests,
		current.Counts.Sockets, current.Counts.NetworkStreams, current.Counts.StorageHostcalls,
		proof, current.CreatedAt.UTC().UnixNano(), current.UpdatedAt.UTC().UnixNano(),
	}
}

func validateSQLiteSessionScopeRecord(current record) error {
	if err := current.Scope.Validate(); err != nil {
		return err
	}
	if !current.State.Valid() {
		return ErrInvalidState
	}
	if !current.Counts.Valid() {
		return ErrInvalidCounts
	}
	if current.CreatedAt.IsZero() || current.UpdatedAt.IsZero() || current.UpdatedAt.Before(current.CreatedAt) {
		return ErrInvalidState
	}
	if current.State == StateActive || !validTeardownOperationID(current.TeardownOperationID) || !current.HasProof {
		return ErrClosedSessionProofInvalid
	}
	return nil
}

func normalizedStoreTime(now time.Time) time.Time {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return now.UTC()
}

func rollbackSQLiteStore(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ Store = (*SQLiteStore)(nil)
