package controlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	executionmodel "github.com/floegence/redevplugin/v3/pkg/execution"
	_ "modernc.org/sqlite"
)

const (
	schemaKind    = "redevplugin_control_v3"
	schemaVersion = 1
)

var (
	ErrIncompatible    = errors.New("control store is incompatible")
	ErrRequestsBlocked = errors.New("control store is not ready; requests are blocked")
)

type Config struct {
	Path string
}

type Store struct {
	db         *sql.DB
	generation uint64
	ready      bool
	mu         sync.RWMutex
}

type Execution = executionmodel.Execution
type Event = executionmodel.Event

func Open(ctx context.Context, cfg Config) (*Store, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, fmt.Errorf("%w: path is required", ErrIncompatible)
	}
	path, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, err
	}
	if _, statErr := os.Stat(path); statErr == nil {
		if err := validateExistingControlFile(ctx, path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// The control database is one transaction authority. Serializing its single
	// connection also avoids cross-connection SQLite file-lock promotion while
	// lifecycle jobs and management readback run concurrently.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	if err := s.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL`); err != nil {
		return err
	}
	var schemaObjects int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&schemaObjects); err != nil {
		return err
	}
	if schemaObjects == 0 {
		if err := createSchema(ctx, s.db); err != nil {
			return err
		}
	} else if err := validateSchema(ctx, s.db); err != nil {
		return err
	}
	var generation uint64
	if err := s.db.QueryRowContext(ctx, `SELECT generation FROM control_generation WHERE id=1`).Scan(&generation); err != nil {
		return fmt.Errorf("%w: generation: %v", ErrIncompatible, err)
	}
	if generation == 0 {
		return fmt.Errorf("%w: zero generation", ErrIncompatible)
	}
	s.generation, s.ready = generation, true
	return nil
}

func validateExistingControlFile(ctx context.Context, path string) error {
	db, err := openSQLiteReadOnly(path)
	if err != nil {
		return fmt.Errorf("%w: open existing control database: %v", ErrIncompatible, err)
	}
	defer db.Close()
	return validateSchema(ctx, db)
}

func openSQLiteReadOnly(path string) (*sql.DB, error) {
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	return sql.Open("sqlite", uri)
}

func createSchema(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS control_schema (id INTEGER PRIMARY KEY CHECK(id=1), kind TEXT NOT NULL, version INTEGER NOT NULL CHECK(version > 0))`,
		`CREATE TABLE IF NOT EXISTS control_generation (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL CHECK(generation > 0), created_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS plugin_records (owner_env_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, publisher_id TEXT NOT NULL, plugin_id TEXT NOT NULL, version TEXT NOT NULL, active_fingerprint TEXT NOT NULL, package_sha256 TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, entries_sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('enabled','disabled_by_user')), disabled_reason TEXT NOT NULL, policy_revision INTEGER NOT NULL, management_revision INTEGER NOT NULL, revoke_epoch INTEGER NOT NULL, installed_at INTEGER NOT NULL, enabled_at INTEGER, updated_at INTEGER NOT NULL, deleted_at INTEGER, record_json TEXT NOT NULL, PRIMARY KEY(owner_env_hash, plugin_instance_id))`,
		`CREATE TABLE IF NOT EXISTS plugin_data_bindings (owner_env_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, generation_id TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, shape_hash TEXT NOT NULL, retained_at INTEGER, expires_at INTEGER, PRIMARY KEY(owner_env_hash, plugin_instance_id), FOREIGN KEY(owner_env_hash, plugin_instance_id) REFERENCES plugin_records(owner_env_hash, plugin_instance_id) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS plugin_data_objects (scope_kind TEXT NOT NULL, owner_env_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, object_id TEXT NOT NULL, content_hash TEXT NOT NULL, shape_hash TEXT NOT NULL, size_bytes INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(scope_kind, owner_env_hash, owner_user_hash, plugin_instance_id, object_id))`,
		`CREATE TABLE IF NOT EXISTS permission_grants (owner_env_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, capability_id TEXT NOT NULL, grant_json TEXT NOT NULL, revision INTEGER NOT NULL, PRIMARY KEY(owner_env_hash, plugin_instance_id, capability_id))`,
		`CREATE TABLE IF NOT EXISTS security_policies (owner_env_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, policy_json TEXT NOT NULL, revision INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(owner_env_hash,plugin_instance_id))`,
		`CREATE TABLE IF NOT EXISTS execution (execution_id TEXT PRIMARY KEY, plugin_instance_id TEXT NOT NULL, owner_session_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, cursor INTEGER NOT NULL, failure_code TEXT NOT NULL DEFAULT '', cancelable INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0, cancel_requested_at INTEGER, terminal_at INTEGER, operation_json TEXT NOT NULL, stream_json TEXT NOT NULL DEFAULT 'null')`,
		`CREATE TABLE IF NOT EXISTS execution_events (execution_id TEXT NOT NULL, sequence INTEGER NOT NULL, kind TEXT NOT NULL, payload_json TEXT NOT NULL, error_json TEXT NOT NULL DEFAULT 'null', PRIMARY KEY(execution_id, sequence), FOREIGN KEY(execution_id) REFERENCES execution(execution_id) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS confirmation_intents (confirmation_id TEXT PRIMARY KEY, plugin_instance_id TEXT NOT NULL, owner_session_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL, status TEXT NOT NULL, expires_at INTEGER NOT NULL, confirmation_json TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS confirmation_session_revocations (owner_session_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL, teardown_operation_id TEXT NOT NULL, revoked_count INTEGER NOT NULL, revocation_json TEXT NOT NULL, PRIMARY KEY(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,teardown_operation_id))`,
		`CREATE TABLE IF NOT EXISTS session_fences (owner_session_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL, state TEXT NOT NULL, fence_json TEXT NOT NULL, proof_sha256 BLOB, updated_at INTEGER NOT NULL, PRIMARY KEY(owner_session_hash, owner_user_hash, owner_env_hash, session_channel_id_hash))`,
		`CREATE TABLE IF NOT EXISTS session_teardown_phases (owner_session_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, owner_env_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL, phase TEXT NOT NULL, phase_json TEXT NOT NULL, PRIMARY KEY(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,phase))`,
		`CREATE TABLE IF NOT EXISTS control_metadata (key TEXT PRIMARY KEY, value_json TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_execution_owner_plugin ON execution(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,plugin_instance_id,created_at,execution_id)`,
	} {
		if _, err := q.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := q.ExecContext(ctx, `INSERT OR IGNORE INTO control_schema(id,kind,version) VALUES(1,?,?)`, schemaKind, schemaVersion); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, `INSERT OR IGNORE INTO control_generation(id,generation,created_at) VALUES(1,1,?)`, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	return nil
}

func validateSchema(ctx context.Context, db *sql.DB) error {
	var kind string
	var version int
	if err := db.QueryRowContext(ctx, `SELECT kind, version FROM control_schema WHERE id=1`).Scan(&kind, &version); err != nil {
		return fmt.Errorf("%w: control_schema: %v", ErrIncompatible, err)
	}
	if kind != schemaKind || version != schemaVersion {
		return fmt.Errorf("%w: schema identity %q version %d", ErrIncompatible, kind, version)
	}
	var generation int
	if err := db.QueryRowContext(ctx, `SELECT generation FROM control_generation WHERE id=1`).Scan(&generation); err != nil {
		return fmt.Errorf("%w: control_generation: %v", ErrIncompatible, err)
	}
	if generation <= 0 {
		return fmt.Errorf("%w: generation metadata", ErrIncompatible)
	}
	expected, err := expectedSchemaShape(ctx)
	if err != nil {
		return fmt.Errorf("%w: build expected schema: %v", ErrIncompatible, err)
	}
	actual, err := readSchemaShape(ctx, db)
	if err != nil {
		return fmt.Errorf("%w: inspect schema: %v", ErrIncompatible, err)
	}
	if !schemaShapesEqual(actual, expected) {
		return fmt.Errorf("%w: exact schema shape mismatch", ErrIncompatible)
	}
	return nil
}

type schemaObject struct {
	kind, name, table, sql string
	columns                []schemaColumn
}

type schemaColumn struct {
	name       string
	typeName   string
	notNull    int
	defaultSQL string
	primaryKey int
}

func expectedSchemaShape(ctx context.Context) ([]schemaObject, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := createSchema(ctx, db); err != nil {
		return nil, err
	}
	return readSchemaShape(ctx, db)
}

func readSchemaShape(ctx context.Context, db *sql.DB) ([]schemaObject, error) {
	rows, err := db.QueryContext(ctx, `SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []schemaObject
	for rows.Next() {
		var object schemaObject
		if err := rows.Scan(&object.kind, &object.name, &object.table, &object.sql); err != nil {
			return nil, err
		}
		result = append(result, object)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for index := range result {
		if result[index].kind != "table" {
			continue
		}
		columns, err := readSchemaColumns(ctx, db, result[index].name)
		if err != nil {
			return nil, err
		}
		result[index].columns = columns
	}
	return result, nil
}

func readSchemaColumns(ctx context.Context, db *sql.DB, table string) ([]schemaColumn, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []schemaColumn
	for rows.Next() {
		var position int
		var column schemaColumn
		var defaultValue sql.NullString
		if err := rows.Scan(&position, &column.name, &column.typeName, &column.notNull, &defaultValue, &column.primaryKey); err != nil {
			return nil, err
		}
		column.typeName = strings.ToUpper(column.typeName)
		column.defaultSQL = defaultValue.String
		result = append(result, column)
	}
	return result, rows.Err()
}

func schemaShapesEqual(left, right []schemaObject) bool {
	return reflect.DeepEqual(left, right)
}

func (s *Store) Generation() uint64 { s.mu.RLock(); defer s.mu.RUnlock(); return s.generation }
func (s *Store) Ready() bool        { s.mu.RLock(); defer s.mu.RUnlock(); return s.ready }

func (s *Store) CreateExecution(ctx context.Context, execution Execution) error {
	return s.Executions().Create(ctx, execution)
}

func (s *Store) AppendEvent(ctx context.Context, event Event) error {
	return s.Executions().Append(ctx, event)
}

func (s *Store) GetExecution(ctx context.Context, id string) (Execution, error) {
	return s.Executions().Get(ctx, id)
}
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.mu.Lock()
	s.ready = false
	s.mu.Unlock()
	return s.db.Close()
}
