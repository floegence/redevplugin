package installstage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
	_ "modernc.org/sqlite"
)

const installStageSelectColumns = `
SELECT owner_env_hash, stage_id, action, status, plugin_instance_id, publisher_id, plugin_id, version,
       package_hash, manifest_hash, entries_hash, requested_trust, resolved_trust,
       validation_summary_json, error_code, error_message, expires_at, created_at,
       updated_at, finished_at`

type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite install stage store path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.initializeSchema(ctx); err != nil {
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

func (s *SQLiteStore) Create(ctx context.Context, req CreateRequest) (Record, error) {
	if s == nil {
		return Record{}, errors.New("install stage store is nil")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record, err := recordFromCreate(req, now)
	if err != nil {
		return Record{}, err
	}
	ownerEnvHash, err := ownerEnvironment(ctx)
	if err != nil {
		return Record{}, err
	}
	record.OwnerEnvHash = ownerEnvHash

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)

	existing, exists, err := getSQLiteStage(ctx, tx, ownerEnvHash, record.StageID)
	if err != nil {
		return Record{}, err
	}
	if exists {
		return existing, nil
	}
	if err := upsertSQLiteStage(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) Get(ctx context.Context, stageID string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("install stage store is nil")
	}
	stageID = normalizeID(stageID)
	if stageID == "" {
		return Record{}, ErrInvalidStage
	}
	ownerEnvHash, err := ownerEnvironment(ctx)
	if err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLiteStage(ctx, s.db, ownerEnvHash, stageID)
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
		return nil, errors.New("install stage store is nil")
	}
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	if req.Status != "" && !validStatus(req.Status) {
		return nil, ErrInvalidStage
	}
	ownerEnvHash, err := ownerEnvironment(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	query := installStageSelectColumns + ` FROM plugin_install_stages`
	args := []any{ownerEnvHash}
	conditions := []string{`owner_env_hash = ?`}
	if pluginInstanceID != "" {
		conditions = append(conditions, `plugin_instance_id = ?`)
		args = append(args, pluginInstanceID)
	}
	if req.Status != "" {
		conditions = append(conditions, `status = ?`)
		args = append(args, string(req.Status))
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY created_at ASC, stage_id ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []Record{}
	for rows.Next() {
		record, err := scanSQLiteStage(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortRecords(records)
	return records, nil
}

func (s *SQLiteStore) MarkPrepared(ctx context.Context, req MarkPreparedRequest) (Record, error) {
	return s.update(ctx, normalizeID(req.StageID), req.Now, func(record Record, now time.Time) (Record, error) {
		if terminalStatus(record.Status) {
			return record, nil
		}
		record.Status = StatusPrepared
		record.ResolvedTrust = normalizeID(req.ResolvedTrust)
		record.ValidationSummary = mergeStringMap(record.ValidationSummary, req.ValidationSummary)
		record.UpdatedAt = now
		return record, nil
	})
}

func (s *SQLiteStore) MarkCommitted(ctx context.Context, req MarkCommittedRequest) (Record, error) {
	return s.update(ctx, normalizeID(req.StageID), req.Now, func(record Record, now time.Time) (Record, error) {
		if terminalStatus(record.Status) {
			return record, nil
		}
		record.Status = StatusCommitted
		record.UpdatedAt = now
		record.FinishedAt = &now
		return record, nil
	})
}

func (s *SQLiteStore) MarkFailed(ctx context.Context, req MarkFailedRequest) (Record, error) {
	return s.update(ctx, normalizeID(req.StageID), req.Now, func(record Record, now time.Time) (Record, error) {
		if terminalStatus(record.Status) {
			return record, nil
		}
		record.Status = StatusFailed
		record.ErrorCode = normalizeID(req.ErrorCode)
		record.ErrorMessage = strings.TrimSpace(req.ErrorMessage)
		record.UpdatedAt = now
		record.FinishedAt = &now
		return record, nil
	})
}

func (s *SQLiteStore) ExpireBefore(ctx context.Context, now time.Time) ([]Record, error) {
	if s == nil {
		return nil, errors.New("install stage store is nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ownerEnvHash, err := ownerEnvironment(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollbackUnlessCommitted(tx)

	rows, err := tx.QueryContext(ctx, installStageSelectColumns+` FROM plugin_install_stages WHERE owner_env_hash = ? AND status IN (?, ?) AND expires_at <= ? ORDER BY created_at ASC, stage_id ASC`, ownerEnvHash, string(StatusStaged), string(StatusPrepared), now.UTC().UnixNano())
	if err != nil {
		return nil, err
	}
	records := []Record{}
	for rows.Next() {
		record, err := scanSQLiteStage(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	changed := make([]Record, 0, len(records))
	for _, record := range records {
		record.Status = StatusExpired
		record.ErrorCode = "stage_expired"
		record.ErrorMessage = "install stage expired"
		record.UpdatedAt = now.UTC()
		finishedAt := record.UpdatedAt
		record.FinishedAt = &finishedAt
		if err := upsertSQLiteStage(ctx, tx, record); err != nil {
			return nil, err
		}
		changed = append(changed, cloneRecord(record))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	sortRecords(changed)
	return changed, nil
}

func (s *SQLiteStore) Delete(ctx context.Context, stageID string) error {
	if s == nil {
		return errors.New("install stage store is nil")
	}
	stageID = normalizeID(stageID)
	if stageID == "" {
		return ErrInvalidStage
	}
	ownerEnvHash, err := ownerEnvironment(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `DELETE FROM plugin_install_stages WHERE owner_env_hash = ? AND stage_id = ?`, ownerEnvHash, stageID)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) update(ctx context.Context, stageID string, now time.Time, mutate func(Record, time.Time) (Record, error)) (Record, error) {
	if s == nil {
		return Record{}, errors.New("install stage store is nil")
	}
	if stageID == "" {
		return Record{}, ErrInvalidStage
	}
	ownerEnvHash, err := ownerEnvironment(ctx)
	if err != nil {
		return Record{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer rollbackUnlessCommitted(tx)

	record, exists, err := getSQLiteStage(ctx, tx, ownerEnvHash, stageID)
	if err != nil {
		return Record{}, err
	}
	if !exists {
		return Record{}, ErrNotFound
	}
	updated, err := mutate(record, now.UTC())
	if err != nil {
		return Record{}, err
	}
	if err := upsertSQLiteStage(ctx, tx, updated); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

func (s *SQLiteStore) initializeSchema(ctx context.Context) error {
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
	legacy, err := installStageSchemaNeedsOwnerMigration(ctx, tx)
	if err != nil {
		return err
	}
	if legacy {
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_install_stages`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return sessionctx.ErrOwnerScopeMigrationRequired
		}
		if _, err := tx.ExecContext(ctx, `DROP TABLE plugin_install_stages`); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_install_stages (
	owner_env_hash TEXT NOT NULL,
	stage_id TEXT NOT NULL,
	action TEXT NOT NULL,
	status TEXT NOT NULL,
	plugin_instance_id TEXT NOT NULL,
	publisher_id TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	version TEXT NOT NULL,
	package_hash TEXT NOT NULL,
	manifest_hash TEXT NOT NULL,
	entries_hash TEXT NOT NULL,
	requested_trust TEXT NOT NULL,
	resolved_trust TEXT NOT NULL,
	validation_summary_json TEXT NOT NULL,
	error_code TEXT NOT NULL,
	error_message TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	finished_at INTEGER,
	PRIMARY KEY(owner_env_hash, stage_id)
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_install_stages_plugin ON plugin_install_stages(owner_env_hash, plugin_instance_id, created_at)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_install_stages_status_expiry ON plugin_install_stages(owner_env_hash, status, expires_at)`); err != nil {
		return err
	}
	return tx.Commit()
}

func installStageSchemaNeedsOwnerMigration(ctx context.Context, tx *sql.Tx) (bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(plugin_install_stages)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	foundTable := false
	foundOwner := false
	for rows.Next() {
		foundTable = true
		var (
			columnID    int
			name        string
			columnType  string
			notNull     int
			defaultExpr sql.NullString
			primaryKey  int
		)
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultExpr, &primaryKey); err != nil {
			return false, err
		}
		if name == "owner_env_hash" {
			foundOwner = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return foundTable && !foundOwner, nil
}

func getSQLiteStage(ctx context.Context, q sqliteQuerier, ownerEnvHash, stageID string) (Record, bool, error) {
	row := q.QueryRowContext(ctx, installStageSelectColumns+` FROM plugin_install_stages WHERE owner_env_hash = ? AND stage_id = ?`, ownerEnvHash, stageID)
	record, err := scanSQLiteStage(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	return record, true, nil
}

func upsertSQLiteStage(ctx context.Context, tx *sql.Tx, record Record) error {
	if strings.TrimSpace(record.OwnerEnvHash) == "" {
		return ErrInvalidStage
	}
	validationSummaryJSON, err := encodeStringMap(record.ValidationSummary)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO plugin_install_stages(
	owner_env_hash, stage_id, action, status, plugin_instance_id, publisher_id, plugin_id, version,
	package_hash, manifest_hash, entries_hash, requested_trust, resolved_trust,
	validation_summary_json, error_code, error_message, expires_at, created_at,
	updated_at, finished_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(owner_env_hash, stage_id) DO UPDATE SET
	action = excluded.action,
	status = excluded.status,
	plugin_instance_id = excluded.plugin_instance_id,
	publisher_id = excluded.publisher_id,
	plugin_id = excluded.plugin_id,
	version = excluded.version,
	package_hash = excluded.package_hash,
	manifest_hash = excluded.manifest_hash,
	entries_hash = excluded.entries_hash,
	requested_trust = excluded.requested_trust,
	resolved_trust = excluded.resolved_trust,
	validation_summary_json = excluded.validation_summary_json,
	error_code = excluded.error_code,
	error_message = excluded.error_message,
	expires_at = excluded.expires_at,
	created_at = excluded.created_at,
	updated_at = excluded.updated_at,
	finished_at = excluded.finished_at`,
		record.OwnerEnvHash,
		record.StageID,
		string(record.Action),
		string(record.Status),
		record.PluginInstanceID,
		record.PublisherID,
		record.PluginID,
		record.Version,
		record.PackageHash,
		record.ManifestHash,
		record.EntriesHash,
		record.RequestedTrust,
		record.ResolvedTrust,
		validationSummaryJSON,
		record.ErrorCode,
		record.ErrorMessage,
		record.ExpiresAt.UTC().UnixNano(),
		record.CreatedAt.UTC().UnixNano(),
		record.UpdatedAt.UTC().UnixNano(),
		nullableTimeToUnix(record.FinishedAt),
	)
	return err
}

func scanSQLiteStage(scanner sqliteScanner) (Record, error) {
	var record Record
	var action string
	var status string
	var validationSummaryJSON string
	var expiresAt int64
	var createdAt int64
	var updatedAt int64
	var finishedAt sql.NullInt64
	if err := scanner.Scan(
		&record.OwnerEnvHash,
		&record.StageID,
		&action,
		&status,
		&record.PluginInstanceID,
		&record.PublisherID,
		&record.PluginID,
		&record.Version,
		&record.PackageHash,
		&record.ManifestHash,
		&record.EntriesHash,
		&record.RequestedTrust,
		&record.ResolvedTrust,
		&validationSummaryJSON,
		&record.ErrorCode,
		&record.ErrorMessage,
		&expiresAt,
		&createdAt,
		&updatedAt,
		&finishedAt,
	); err != nil {
		return Record{}, err
	}
	record.Action = Action(action)
	record.Status = Status(status)
	if strings.TrimSpace(record.OwnerEnvHash) == "" || !validAction(record.Action) || !validStatus(record.Status) {
		return Record{}, ErrInvalidStage
	}
	validationSummary, err := decodeStringMap(validationSummaryJSON)
	if err != nil {
		return Record{}, err
	}
	record.ValidationSummary = validationSummary
	record.ExpiresAt = time.Unix(0, expiresAt).UTC()
	record.CreatedAt = time.Unix(0, createdAt).UTC()
	record.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if finishedAt.Valid {
		finished := time.Unix(0, finishedAt.Int64).UTC()
		record.FinishedAt = &finished
	}
	return cloneRecord(record), nil
}

func encodeStringMap(values map[string]string) (string, error) {
	values = cloneStringMap(values)
	if values == nil {
		values = map[string]string{}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func decodeStringMap(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	values := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	return cloneStringMap(values), nil
}

func nullableTimeToUnix(value *time.Time) sql.NullInt64 {
	if value == nil || value.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: value.UTC().UnixNano(), Valid: true}
}

type sqliteScanner interface {
	Scan(dest ...any) error
}

type sqliteQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ Store = (*SQLiteStore)(nil)
