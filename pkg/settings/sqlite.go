package settings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
		return nil, errors.New("sqlite settings store path is required")
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

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) Ensure(ctx context.Context, req EnsureRequest) (Snapshot, error) {
	return s.mutateSnapshot(ctx, func(store *MemoryStore) (Snapshot, error) {
		return store.Ensure(ctx, req)
	})
}

func (s *SQLiteStore) Get(ctx context.Context, req GetRequest) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, errors.New("settings store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadMemoryStore(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	return store.Get(ctx, req)
}

func (s *SQLiteStore) Patch(ctx context.Context, req PatchRequest) (Snapshot, error) {
	return s.mutateSnapshot(ctx, func(store *MemoryStore) (Snapshot, error) {
		return store.Patch(ctx, req)
	})
}

func (s *SQLiteStore) MarkSecret(ctx context.Context, req MarkSecretRequest) (Snapshot, error) {
	return s.mutateSnapshot(ctx, func(store *MemoryStore) (Snapshot, error) {
		return store.MarkSecret(ctx, req)
	})
}

func (s *SQLiteStore) Export(ctx context.Context, req ExportRequest) (string, error) {
	if s == nil {
		return "", errors.New("settings store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadMemoryStore(ctx)
	if err != nil {
		return "", err
	}
	ref, err := store.Export(ctx, req)
	if err != nil {
		return "", err
	}
	if err := s.saveState(ctx, store.State()); err != nil {
		return "", err
	}
	return ref, nil
}

func (s *SQLiteStore) Import(ctx context.Context, req ImportRequest) (Snapshot, error) {
	return s.mutateSnapshot(ctx, func(store *MemoryStore) (Snapshot, error) {
		return store.Import(ctx, req)
	})
}

func (s *SQLiteStore) Delete(ctx context.Context, req DeleteRequest) error {
	if s == nil {
		return errors.New("settings store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadMemoryStore(ctx)
	if err != nil {
		return err
	}
	if err := store.Delete(ctx, req); err != nil {
		return err
	}
	return s.saveState(ctx, store.State())
}

func (s *SQLiteStore) BindRetained(ctx context.Context, req BindRetainedRequest) (Snapshot, error) {
	if req.DryRun {
		if s == nil {
			return Snapshot{}, errors.New("settings store is nil")
		}
		s.mu.Lock()
		defer s.mu.Unlock()

		store, err := s.loadMemoryStore(ctx)
		if err != nil {
			return Snapshot{}, err
		}
		return store.BindRetained(ctx, req)
	}
	return s.mutateSnapshot(ctx, func(store *MemoryStore) (Snapshot, error) {
		return store.BindRetained(ctx, req)
	})
}

func (s *SQLiteStore) mutateSnapshot(ctx context.Context, mutate func(*MemoryStore) (Snapshot, error)) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, errors.New("settings store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadMemoryStore(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := mutate(store)
	if err != nil {
		return Snapshot{}, err
	}
	if err := s.saveState(ctx, store.State()); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s *SQLiteStore) loadMemoryStore(ctx context.Context) (*MemoryStore, error) {
	state, err := s.loadState(ctx)
	if err != nil {
		return nil, err
	}
	return NewMemoryStoreFromState(state), nil
}

func (s *SQLiteStore) loadState(ctx context.Context) (MemoryState, error) {
	state := MemoryState{
		Records:  map[string]Record{},
		Archives: map[string]ArchiveRecord{},
	}
	if err := s.db.QueryRowContext(ctx, `SELECT next_export FROM plugin_settings_meta WHERE id = 1`).Scan(&state.NextExport); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return MemoryState{}, err
	}

	rows, err := s.db.QueryContext(ctx, `SELECT payload_json FROM plugin_settings_records ORDER BY plugin_instance_id ASC`)
	if err != nil {
		return MemoryState{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return MemoryState{}, err
		}
		var record Record
		if err := json.Unmarshal(raw, &record); err != nil {
			return MemoryState{}, fmt.Errorf("decode settings record: %w", err)
		}
		record = normalizeLoadedRecord(record)
		state.Records[record.PluginInstanceID] = record
	}
	if err := rows.Err(); err != nil {
		return MemoryState{}, err
	}

	archiveRows, err := s.db.QueryContext(ctx, `SELECT payload_json FROM plugin_settings_archives ORDER BY archive_ref ASC`)
	if err != nil {
		return MemoryState{}, err
	}
	defer archiveRows.Close()
	for archiveRows.Next() {
		var raw []byte
		if err := archiveRows.Scan(&raw); err != nil {
			return MemoryState{}, err
		}
		var archive ArchiveRecord
		if err := json.Unmarshal(raw, &archive); err != nil {
			return MemoryState{}, fmt.Errorf("decode settings archive: %w", err)
		}
		archive = normalizeLoadedArchive(archive)
		state.Archives[archive.ArchiveRef] = archive
	}
	if err := archiveRows.Err(); err != nil {
		return MemoryState{}, err
	}
	return state, nil
}

func (s *SQLiteStore) saveState(ctx context.Context, state MemoryState) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)

	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_settings_records`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_settings_archives`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_settings_meta(id, next_export) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET next_export = excluded.next_export`, state.NextExport); err != nil {
		return err
	}
	for _, record := range state.Records {
		raw, err := json.Marshal(normalizeLoadedRecord(record))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_settings_records(plugin_instance_id, state, schema_version, settings_revision, updated_at, retained_at, payload_json)
VALUES(?, ?, ?, ?, ?, ?, ?)`,
			record.PluginInstanceID,
			string(record.State),
			record.SchemaVersion,
			record.SettingsRevision,
			record.UpdatedAt.UTC().UnixNano(),
			timePtrToNullableUnix(record.RetainedAt),
			raw,
		); err != nil {
			return err
		}
	}
	for _, archive := range state.Archives {
		raw, err := json.Marshal(normalizeLoadedArchive(archive))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_settings_archives(archive_ref, source_plugin_instance_id, include_secrets, schema_version, settings_revision, created_at, updated_at, payload_json)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
			archive.ArchiveRef,
			archive.SourcePluginInstanceID,
			boolToInt(archive.IncludeSecrets),
			archive.SchemaVersion,
			archive.SettingsRevision,
			archive.CreatedAt.UTC().UnixNano(),
			archive.UpdatedAt.UTC().UnixNano(),
			raw,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
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
CREATE TABLE IF NOT EXISTS plugin_settings_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_settings_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqliteSchemaVersion {
		return fmt.Errorf("sqlite settings schema version %d is newer than supported version %d", maxVersion, sqliteSchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_settings_meta (
	id INTEGER PRIMARY KEY CHECK(id = 1),
	next_export INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_settings_meta(id, next_export) VALUES(1, 0)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_settings_records (
	plugin_instance_id TEXT PRIMARY KEY,
	state TEXT NOT NULL,
	schema_version INTEGER NOT NULL,
	settings_revision INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	retained_at INTEGER,
	payload_json BLOB NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_settings_archives (
	archive_ref TEXT PRIMARY KEY,
	source_plugin_instance_id TEXT NOT NULL,
	include_secrets INTEGER NOT NULL,
	schema_version INTEGER NOT NULL,
	settings_revision INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	payload_json BLOB NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_settings_records_state ON plugin_settings_records(state, retained_at)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_settings_archives_source ON plugin_settings_archives(source_plugin_instance_id, created_at)`); err != nil {
		return err
	}
	if maxVersion < sqliteSchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_settings_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteSchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func normalizeLoadedRecord(record Record) Record {
	record.Fields = cloneFields(record.Fields)
	record.Values = normalizedValuesForFields(record.Fields, record.Values)
	record.Secrets = normalizedSecretsForFields(record.Fields, record.Secrets)
	record.RetainedAt = cloneTimePtr(record.RetainedAt)
	return record
}

func normalizeLoadedArchive(archive ArchiveRecord) ArchiveRecord {
	archive.Fields = cloneFields(archive.Fields)
	archive.Values = cloneMap(archive.Values)
	archive.Secrets = cloneSecrets(archive.Secrets)
	return archive
}

func timePtrToNullableUnix(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().UnixNano()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

var _ Store = (*SQLiteStore)(nil)
