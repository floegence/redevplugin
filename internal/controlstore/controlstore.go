package controlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	executionmodel "github.com/floegence/redevplugin/v2/pkg/execution"
	"github.com/floegence/redevplugin/v2/pkg/registry"
	"github.com/floegence/redevplugin/v2/pkg/security"
	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
	"github.com/floegence/redevplugin/v2/pkg/sessionscope"
	_ "modernc.org/sqlite"
)

const schemaVersion = 1
const generationVersion = 1

var (
	ErrIncompatible    = errors.New("control store is incompatible")
	ErrMigration       = errors.New("control store migration failed")
	ErrRequestsBlocked = errors.New("control store is not ready; requests are blocked")
)

type Faults struct {
	AfterImport   error
	BeforePublish error
	AfterPublish  error
	SyncDirectory func(string) error
}

type Config struct {
	Path    string
	Sources []Source
	Faults  Faults
}

type Source struct {
	Name    string
	Path    string
	Kind    string
	Version int
}

type Store struct {
	db         *sql.DB
	path       string
	generation uint64
	ready      bool
	mu         sync.RWMutex
}

type descriptor struct {
	Stage            string         `json:"stage"`
	SourceDigest     string         `json:"source_digest"`
	TargetGeneration uint64         `json:"target_generation"`
	VerifiedCounts   map[string]int `json:"verified_counts"`
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
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// The control database is one transaction authority. Serializing its single
	// connection also avoids cross-connection SQLite file-lock promotion while
	// lifecycle jobs and management readback run concurrently.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, path: path}
	if err := s.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func Migrate(ctx context.Context, cfg Config) (*Store, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, fmt.Errorf("%w: path is required", ErrMigration)
	}
	path, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		return resumeMigration(ctx, path, cfg)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := inspectSources(cfg.Sources); err != nil {
		return nil, err
	}
	sourceDigest, err := sourcesDigest(cfg.Sources)
	if err != nil {
		return nil, err
	}
	canonicalRoot, err := os.MkdirTemp(filepath.Dir(path), ".control-migration-")
	if err != nil {
		return nil, fmt.Errorf("%w: temp source copies: %v", ErrMigration, err)
	}
	defer os.RemoveAll(canonicalRoot)
	canonicalSources, err := canonicalizeSources(ctx, cfg.Sources, canonicalRoot)
	if err != nil {
		return nil, err
	}
	next := path + ".next"
	_ = os.Remove(next)
	if err := createSchemaFile(ctx, next); err != nil {
		return nil, fmt.Errorf("%w: create target: %v", ErrMigration, err)
	}
	if err := importSources(ctx, next, canonicalSources); err != nil {
		_ = os.Remove(next)
		return nil, err
	}
	postImportDigest, err := sourcesDigest(cfg.Sources)
	if err != nil || postImportDigest != sourceDigest {
		_ = os.Remove(next)
		return nil, fmt.Errorf("%w: source changed during import", ErrMigration)
	}
	if cfg.Faults.AfterImport != nil {
		_ = os.Remove(next)
		return nil, fmt.Errorf("%w: %v", ErrMigration, cfg.Faults.AfterImport)
	}
	counts, err := verifyFile(ctx, next, 1)
	if err != nil {
		_ = os.Remove(next)
		return nil, fmt.Errorf("%w: verify target: %v", ErrMigration, err)
	}
	markerPath := path + ".migration.json"
	state := descriptor{Stage: "prepared", SourceDigest: sourceDigest, TargetGeneration: 1, VerifiedCounts: counts}
	if err := writeDescriptor(markerPath, state); err != nil {
		_ = os.Remove(next)
		return nil, fmt.Errorf("%w: descriptor: %v", ErrMigration, err)
	}
	if err := syncParentDirectory(path, cfg.Faults.SyncDirectory); err != nil {
		_ = os.Remove(next)
		return nil, fmt.Errorf("%w: sync prepared descriptor: %v", ErrMigration, err)
	}
	if cfg.Faults.BeforePublish != nil {
		_ = os.Remove(next)
		return nil, fmt.Errorf("%w: %v", ErrMigration, cfg.Faults.BeforePublish)
	}
	if err := os.Rename(next, path); err != nil {
		_ = os.Remove(next)
		return nil, fmt.Errorf("%w: publish: %v", ErrMigration, err)
	}
	state.Stage = "published_pending_verify"
	if err := writeDescriptor(markerPath, state); err != nil {
		return nil, fmt.Errorf("%w: publish marker: %v", ErrMigration, err)
	}
	if err := syncParentDirectory(path, cfg.Faults.SyncDirectory); err != nil {
		return nil, fmt.Errorf("%w: sync published generation: %v", ErrMigration, err)
	}
	if cfg.Faults.AfterPublish != nil {
		return nil, fmt.Errorf("%w: %v", ErrMigration, cfg.Faults.AfterPublish)
	}
	reopenedCounts, err := verifyFile(ctx, path, state.TargetGeneration)
	if err != nil || !equalCounts(reopenedCounts, state.VerifiedCounts) {
		return nil, fmt.Errorf("%w: reopen: %v", ErrMigration, err)
	}
	state.Stage = "complete"
	if err := writeDescriptor(markerPath, state); err != nil {
		return nil, fmt.Errorf("%w: complete marker: %v", ErrMigration, err)
	}
	if err := syncParentDirectory(path, cfg.Faults.SyncDirectory); err != nil {
		return nil, fmt.Errorf("%w: sync complete marker: %v", ErrMigration, err)
	}
	return Open(ctx, Config{Path: path})
}

func resumeMigration(ctx context.Context, path string, cfg Config) (*Store, error) {
	markerPath := path + ".migration.json"
	data, err := os.ReadFile(markerPath)
	if os.IsNotExist(err) {
		return Open(ctx, Config{Path: path})
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read migration marker: %v", ErrMigration, err)
	}
	var state descriptor
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("%w: decode migration marker: %v", ErrMigration, err)
	}
	if state.Stage == "complete" {
		return Open(ctx, Config{Path: path})
	}
	if state.Stage != "prepared" && state.Stage != "published_pending_verify" {
		return nil, fmt.Errorf("%w: invalid migration stage %q", ErrMigration, state.Stage)
	}
	if err := inspectSources(cfg.Sources); err != nil {
		return nil, err
	}
	digest, err := sourcesDigest(cfg.Sources)
	if err != nil {
		return nil, err
	}
	if digest != state.SourceDigest {
		return nil, fmt.Errorf("%w: source digest changed", ErrMigration)
	}
	counts, err := verifyFile(ctx, path, state.TargetGeneration)
	if err != nil {
		return nil, fmt.Errorf("%w: verify published generation: %v", ErrMigration, err)
	}
	if !equalCounts(counts, state.VerifiedCounts) {
		return nil, fmt.Errorf("%w: published row counts changed", ErrMigration)
	}
	state.Stage = "complete"
	if err := writeDescriptor(markerPath, state); err != nil {
		return nil, fmt.Errorf("%w: complete marker: %v", ErrMigration, err)
	}
	if err := syncParentDirectory(path, cfg.Faults.SyncDirectory); err != nil {
		return nil, fmt.Errorf("%w: sync complete marker: %v", ErrMigration, err)
	}
	return Open(ctx, Config{Path: path})
}

func sourcesDigest(sources []Source) (string, error) {
	digestParts := make([]string, 0, len(sources))
	for _, source := range sources {
		digest, err := sqliteSnapshotDigest(source.Path)
		if err != nil {
			return "", fmt.Errorf("%w: source digest: %v", ErrMigration, err)
		}
		digestParts = append(digestParts, fmt.Sprintf("%s:%s:v%d=%s", source.Name, source.Kind, source.Version, digest))
	}
	sort.Strings(digestParts)
	digest := sha256.Sum256([]byte(strings.Join(digestParts, "\n")))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func createSchemaFile(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := createSchema(ctx, db); err != nil {
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func canonicalizeSources(ctx context.Context, sources []Source, root string) ([]Source, error) {
	result := make([]Source, 0, len(sources))
	for _, source := range sources {
		target := filepath.Join(root, source.Name+".sqlite")
		if err := snapshotSQLite(ctx, source.Path, target); err != nil {
			return nil, fmt.Errorf("%w: snapshot %s: %v", ErrMigration, source.Name, err)
		}
		canonical := source
		canonical.Path = target
		if source.Kind == "operation" || source.Kind == "stream" {
			if err := validateLegacyExecutionSource(ctx, canonical); err != nil {
				return nil, err
			}
			result = append(result, canonical)
			continue
		}
		switch source.Kind {
		case "registry":
			if err := normalizeLegacyRegistryTransientTables(ctx, target); err != nil {
				return nil, err
			}
			store, err := registry.NewSQLiteStore(ctx, target)
			if err != nil {
				return nil, fmt.Errorf("%w: canonicalize registry v%d: %v", ErrMigration, source.Version, err)
			}
			if err := store.Close(); err != nil {
				return nil, err
			}
			canonical.Version = registry.SQLiteSchemaVersion
		case "session":
			store, err := sessionscope.NewSQLiteStore(ctx, target, sessionscope.StoreOptions{})
			if err != nil {
				return nil, fmt.Errorf("%w: canonicalize session v%d: %v", ErrMigration, source.Version, err)
			}
			if err := store.Close(); err != nil {
				return nil, err
			}
			canonical.Version = 2
		case "confirmation":
			store, err := security.NewSQLiteConfirmationIntentStore(ctx, target)
			if err != nil {
				return nil, fmt.Errorf("%w: canonicalize confirmation v%d: %v", ErrMigration, source.Version, err)
			}
			if err := store.Close(); err != nil {
				return nil, err
			}
			canonical.Version = 0
		}
		result = append(result, canonical)
	}
	return result, nil
}

func snapshotSQLite(ctx context.Context, source, target string) error {
	db, err := openSQLiteReadOnly(source)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("target already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	quoted := strings.ReplaceAll(target, "'", "''")
	if _, err := db.ExecContext(ctx, `VACUUM INTO '`+quoted+`'`); err != nil {
		return err
	}
	handle, err := os.Open(target)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func sqliteSnapshotDigest(path string) (string, error) {
	root, err := os.MkdirTemp(filepath.Dir(path), ".control-digest-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(root)
	target := filepath.Join(root, "snapshot.sqlite")
	if err := snapshotSQLite(context.Background(), path, target); err != nil {
		return "", err
	}
	logical, err := SourceDigest(target)
	if err != nil {
		return "", err
	}
	physical := []string{logical}
	for _, candidate := range []string{path, path + "-wal"} {
		digest, err := SourceDigest(candidate)
		if os.IsNotExist(err) {
			physical = append(physical, "absent")
			continue
		}
		if err != nil {
			return "", err
		}
		physical = append(physical, digest)
	}
	combined := sha256.Sum256([]byte(strings.Join(physical, "\n")))
	return "sha256:" + hex.EncodeToString(combined[:]), nil
}

type legacyColumn struct {
	name       string
	typeName   string
	notNull    int
	defaultSQL string
	primaryKey int
}

func validateLegacyExecutionSource(ctx context.Context, source Source) error {
	db, err := openSQLiteReadOnly(source.Path)
	if err != nil {
		return fmt.Errorf("%w: open %s source: %v", ErrMigration, source.Kind, err)
	}
	defer db.Close()
	var tables map[string][]legacyColumn
	var indexes []string
	switch source.Kind {
	case "operation":
		columns := legacyOperationColumns()
		if source.Version == 0 {
			columns = columns[:len(columns)-1]
		}
		tables = map[string][]legacyColumn{"plugin_operations": columns}
		indexes = []string{
			"idx_plugin_operations_created", "idx_plugin_operations_owner", "idx_plugin_operations_owner_plugin_instance",
			"idx_plugin_operations_owner_plugin_session", "idx_plugin_operations_owner_terminal_retention",
			"idx_plugin_operations_plugin_instance", "idx_plugin_operations_plugin_owner", "idx_plugin_operations_terminal_retention",
		}
	case "stream":
		tables = map[string][]legacyColumn{
			"plugin_streams":       legacyStreamColumns(),
			"plugin_stream_events": legacyStreamEventColumns(),
		}
		indexes = []string{
			"idx_plugin_streams_owner_plugin_instance", "idx_plugin_streams_owner_terminal_retention",
			"idx_plugin_streams_plugin_instance", "idx_plugin_streams_session_scope", "idx_plugin_streams_terminal_retention",
		}
	default:
		return fmt.Errorf("%w: unsupported legacy execution source %q", ErrMigration, source.Kind)
	}
	if err := validateLegacyObjects(ctx, db, tables, indexes); err != nil {
		return fmt.Errorf("%w: %s v%d schema drift: %v", ErrMigration, source.Kind, source.Version, err)
	}
	return nil
}

func openSQLiteReadOnly(path string) (*sql.DB, error) {
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	return sql.Open("sqlite", uri)
}

func validateLegacyObjects(ctx context.Context, db *sql.DB, tables map[string][]legacyColumn, indexes []string) error {
	rows, err := db.QueryContext(ctx, `SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return err
		}
		got = append(got, kind+":"+name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	want := make([]string, 0, len(tables)+len(indexes))
	for table := range tables {
		want = append(want, "table:"+table)
	}
	for _, index := range indexes {
		want = append(want, "index:"+index)
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("objects = %v, want %v", got, want)
	}
	for table, expected := range tables {
		actual, err := legacyColumns(ctx, db, table)
		if err != nil {
			return err
		}
		if len(actual) != len(expected) {
			return fmt.Errorf("%s has %d columns, want %d", table, len(actual), len(expected))
		}
		for i := range expected {
			if actual[i] != expected[i] {
				return fmt.Errorf("%s column %d = %#v, want %#v", table, i, actual[i], expected[i])
			}
		}
	}
	return nil
}

func legacyColumns(ctx context.Context, db *sql.DB, table string) ([]legacyColumn, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []legacyColumn
	for rows.Next() {
		var position int
		var column legacyColumn
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

func legacyOperationColumns() []legacyColumn {
	return []legacyColumn{
		{"operation_id", "TEXT", 0, "", 1}, {"plugin_id", "TEXT", 1, "", 0}, {"plugin_instance_id", "TEXT", 1, "", 0},
		{"method", "TEXT", 1, "", 0}, {"effect", "TEXT", 1, "", 0}, {"execution", "TEXT", 1, "", 0},
		{"surface_instance_id", "TEXT", 1, "", 0}, {"owner_session_hash", "TEXT", 1, "", 0}, {"owner_user_hash", "TEXT", 1, "", 0},
		{"owner_env_hash", "TEXT", 1, "", 0}, {"session_channel_id_hash", "TEXT", 1, "", 0}, {"bridge_channel_id", "TEXT", 1, "", 0},
		{"execution_binding_json", "TEXT", 1, "'{}'", 0}, {"status", "TEXT", 1, "", 0}, {"cancelable", "INTEGER", 1, "1", 0},
		{"cancel_ack_timeout_ms", "INTEGER", 1, "0", 0}, {"disable_behavior", "TEXT", 1, "", 0}, {"uninstall_behavior", "TEXT", 1, "", 0},
		{"failure_code", "TEXT", 1, "", 0}, {"reason", "TEXT", 1, "", 0}, {"created_at", "INTEGER", 1, "", 0},
		{"updated_at", "INTEGER", 1, "", 0}, {"cancel_requested_at", "INTEGER", 0, "", 0}, {"orphaned_at", "INTEGER", 0, "", 0},
		{"terminal_at", "INTEGER", 0, "", 0}, {"progress_json", "TEXT", 1, "''", 0},
	}
}

func legacyStreamColumns() []legacyColumn {
	return []legacyColumn{
		{"stream_id", "TEXT", 0, "", 1}, {"plugin_id", "TEXT", 1, "", 0}, {"plugin_instance_id", "TEXT", 1, "", 0},
		{"method", "TEXT", 1, "", 0}, {"effect", "TEXT", 1, "", 0}, {"execution", "TEXT", 1, "", 0},
		{"surface_instance_id", "TEXT", 1, "", 0}, {"owner_session_hash", "TEXT", 1, "", 0}, {"owner_user_hash", "TEXT", 1, "", 0},
		{"owner_env_hash", "TEXT", 1, "", 0}, {"session_channel_id_hash", "TEXT", 1, "", 0}, {"bridge_channel_id", "TEXT", 1, "", 0},
		{"execution_binding_json", "TEXT", 1, "'{}'", 0}, {"direction", "TEXT", 1, "", 0}, {"status", "TEXT", 1, "", 0},
		{"failure_code", "TEXT", 1, "", 0}, {"reason", "TEXT", 1, "''", 0}, {"content_type", "TEXT", 1, "", 0},
		{"max_buffered_bytes", "INTEGER", 1, "", 0}, {"buffered_bytes", "INTEGER", 1, "", 0}, {"next_sequence", "INTEGER", 1, "", 0},
		{"pending_delivery_id", "TEXT", 1, "", 0}, {"pending_read_id", "TEXT", 1, "", 0}, {"pending_through_sequence", "INTEGER", 1, "", 0},
		{"pending_done", "INTEGER", 1, "", 0}, {"pending_terminal_status", "TEXT", 1, "", 0}, {"last_acknowledged_delivery_id", "TEXT", 1, "", 0},
		{"terminal_acknowledged", "INTEGER", 1, "", 0}, {"created_at", "INTEGER", 1, "", 0}, {"updated_at", "INTEGER", 1, "", 0},
		{"closed_at", "INTEGER", 0, "", 0},
	}
}

func legacyStreamEventColumns() []legacyColumn {
	return []legacyColumn{
		{"stream_id", "TEXT", 1, "", 1}, {"sequence", "INTEGER", 1, "", 2}, {"kind", "TEXT", 1, "", 0},
		{"data", "BLOB", 0, "", 0}, {"error", "TEXT", 1, "", 0}, {"at", "INTEGER", 1, "", 0},
	}
}

func (s *Store) initialize(ctx context.Context) error {
	var migrationState *descriptor
	if marker, err := os.ReadFile(s.path + ".migration.json"); err == nil {
		var state descriptor
		if json.Unmarshal(marker, &state) != nil || state.Stage != "complete" || state.TargetGeneration == 0 || state.SourceDigest == "" || len(state.VerifiedCounts) == 0 {
			return fmt.Errorf("%w: migration verification is incomplete", ErrRequestsBlocked)
		}
		migrationState = &state
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("%w: migration marker: %v", ErrIncompatible, err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL`); err != nil {
		return err
	}
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("%w: future schema version %d", ErrIncompatible, version)
	}
	if version == 0 {
		if migrationState != nil {
			return fmt.Errorf("%w: migrated database has no schema", ErrIncompatible)
		}
		var schemaObjects int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&schemaObjects); err != nil {
			return err
		}
		if schemaObjects != 0 {
			return fmt.Errorf("%w: version-zero database contains unknown schema objects", ErrIncompatible)
		}
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
	if migrationState != nil {
		if generation != migrationState.TargetGeneration {
			return fmt.Errorf("%w: marker generation = %d, database generation = %d", ErrIncompatible, migrationState.TargetGeneration, generation)
		}
	}
	s.generation, s.ready = generation, true
	return nil
}

func createSchema(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS control_generation (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL CHECK(generation > 0), schema_version INTEGER NOT NULL CHECK(schema_version = 1), created_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS plugin_records (owner_env_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, publisher_id TEXT NOT NULL, plugin_id TEXT NOT NULL, version TEXT NOT NULL, active_fingerprint TEXT NOT NULL, package_sha256 TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, entries_sha256 TEXT NOT NULL, state TEXT NOT NULL, disabled_reason TEXT NOT NULL, policy_revision INTEGER NOT NULL, management_revision INTEGER NOT NULL, revoke_epoch INTEGER NOT NULL, installed_at INTEGER NOT NULL, enabled_at INTEGER, updated_at INTEGER NOT NULL, deleted_at INTEGER, record_json TEXT NOT NULL, PRIMARY KEY(owner_env_hash, plugin_instance_id))`,
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
	_, err := q.ExecContext(ctx, `INSERT OR IGNORE INTO control_generation(id,generation,schema_version,created_at) VALUES(1,1,1,?)`, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `PRAGMA user_version = 1`)
	return err
}

func validateSchema(ctx context.Context, db *sql.DB) error {
	var generation, version int
	if err := db.QueryRowContext(ctx, `SELECT generation, schema_version FROM control_generation WHERE id=1`).Scan(&generation, &version); err != nil {
		return fmt.Errorf("%w: control_generation: %v", ErrIncompatible, err)
	}
	if generation <= 0 || version != generationVersion {
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
	columns                []legacyColumn
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
		columns, err := legacyColumns(ctx, db, result[index].name)
		if err != nil {
			return nil, err
		}
		result[index].columns = columns
	}
	return result, nil
}

func schemaShapesEqual(left, right []schemaObject) bool {
	return reflect.DeepEqual(left, right)
}

func inspectSources(sources []Source) error {
	seen := map[string]bool{}
	for _, source := range sources {
		if source.Name == "" || source.Path == "" || source.Kind == "" || source.Version < 0 || seen[source.Name] || !supportedSourceVersion(source.Kind, source.Version) {
			return fmt.Errorf("%w: invalid source descriptor", ErrMigration)
		}
		seen[source.Name] = true
		if _, err := os.Stat(source.Path); err != nil {
			return fmt.Errorf("%w: source %s: %v", ErrMigration, source.Name, err)
		}
		if source.Kind != "confirmation" {
			db, err := openSQLiteReadOnly(source.Path)
			if err != nil {
				return fmt.Errorf("%w: source %s version: %v", ErrMigration, source.Name, err)
			}
			var actual int
			err = db.QueryRow(`PRAGMA user_version`).Scan(&actual)
			db.Close()
			if err != nil || actual != source.Version {
				return fmt.Errorf("%w: source %s version = %d, want %d", ErrMigration, source.Name, actual, source.Version)
			}
		}
		if source.Kind == "external_inspection" || source.Kind == "installstage" || source.Kind == "receipt" {
			return fmt.Errorf("%w: source %s is not durable control state", ErrMigration, source.Name)
		}
	}
	return nil
}

func supportedSourceVersion(kind string, version int) bool {
	switch kind {
	case "registry":
		return version >= 0 && version <= registry.SQLiteSchemaVersion
	case "operation":
		return version == 0 || version == 1
	case "stream":
		return version == 0
	case "session":
		return version == 1 || version == 2
	case "confirmation":
		return version == 0
	default:
		return false
	}
}

func importSources(ctx context.Context, target string, sources []Source) error {
	db, err := sql.Open("sqlite", target)
	if err != nil {
		return fmt.Errorf("%w: open target: %v", ErrMigration, err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin import: %v", ErrMigration, err)
	}
	defer tx.Rollback()
	type legacyExecution struct {
		id, plugin, binding, status, operationID, execution, recordJSON, sourcePath string
		ownerSession, ownerUser, ownerEnv, ownerChannel                             string
		failureCode                                                                 string
		cancelable                                                                  bool
		createdAt, updatedAt                                                        int64
		cancelRequestedAt, terminalAt                                               sql.NullInt64
	}
	operations := map[string]legacyExecution{}
	streams := map[string]legacyExecution{}
	for _, source := range sources {
		if source.Kind == "registry" {
			legacy, err := sql.Open("sqlite", source.Path)
			if err != nil {
				return fmt.Errorf("%w: open source: %v", ErrMigration, err)
			}
			var version int
			if err := legacy.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != source.Version {
				legacy.Close()
				return fmt.Errorf("%w: registry version = %d, want %d", ErrMigration, version, source.Version)
			}
			// Read the canonical registry representation through its released
			// decoder so current control rows retain valid RFC3339/time and
			// nested security facts instead of legacy SQL-shaped JSON.
			legacyStore, err := registry.NewSQLiteStore(ctx, source.Path)
			if err != nil {
				legacy.Close()
				return fmt.Errorf("%w: open canonical registry: %v", ErrMigration, err)
			}
			defer legacyStore.Close()
			rows, queryErr := legacy.QueryContext(ctx, `SELECT owner_env_hash, plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint, package_hash, manifest_hash, entries_hash, enable_state, disabled_reason, policy_revision, management_revision, revoke_epoch, installed_at, enabled_at, updated_at, deleted_at FROM plugin_records`)
			if queryErr != nil {
				legacy.Close()
				return fmt.Errorf("%w: registry schema: %v", ErrMigration, queryErr)
			}
			if queryErr == nil {
				for rows.Next() {
					var owner, id, publisher, pluginID, pluginVersion, fingerprint, packageHash, manifestHash, entriesHash, enableState, disabledReason string
					var policyRevision, managementRevision, revokeEpoch uint64
					var installedAt, updatedAt int64
					var enabledAt, deletedAt sql.NullInt64
					if err := rows.Scan(&owner, &id, &publisher, &pluginID, &pluginVersion, &fingerprint, &packageHash, &manifestHash, &entriesHash, &enableState, &disabledReason, &policyRevision, &managementRevision, &revokeEpoch, &installedAt, &enabledAt, &updatedAt, &deletedAt); err != nil {
						rows.Close()
						legacy.Close()
						return fmt.Errorf("%w: scan registry: %v", ErrMigration, err)
					}
					state, err := migrateEnableState(enableState, deletedAt.Valid)
					if err != nil {
						rows.Close()
						legacy.Close()
						return fmt.Errorf("%w: plugin %s state: %v", ErrMigration, id, err)
					}
					migrationContext := sessionctx.WithContext(ctx, sessionctx.Context{OwnerSessionHash: "migration", OwnerUserHash: "migration", OwnerEnvHash: owner, SessionChannelIDHash: "migration"})
					decodedRecord, err := legacyStore.GetPlugin(migrationContext, id)
					if err != nil {
						rows.Close()
						legacy.Close()
						return fmt.Errorf("%w: decode plugin row: %v", ErrMigration, err)
					}
					recordJSONBytes, err := json.Marshal(decodedRecord)
					if err != nil {
						rows.Close()
						legacy.Close()
						return fmt.Errorf("%w: encode plugin row: %v", ErrMigration, err)
					}
					recordJSON := string(recordJSONBytes)
					if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_records(owner_env_hash,plugin_instance_id,publisher_id,plugin_id,version,active_fingerprint,package_sha256,manifest_sha256,entries_sha256,state,disabled_reason,policy_revision,management_revision,revoke_epoch,installed_at,enabled_at,updated_at,deleted_at,record_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, owner, id, publisher, pluginID, pluginVersion, fingerprint, packageHash, manifestHash, entriesHash, state, disabledReason, policyRevision, managementRevision, revokeEpoch, installedAt, enabledAt, updatedAt, deletedAt, recordJSON); err != nil {
						rows.Close()
						legacy.Close()
						return fmt.Errorf("%w: import registry: %v", ErrMigration, err)
					}
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					legacy.Close()
					return fmt.Errorf("%w: registry rows: %v", ErrMigration, err)
				}
				rows.Close()
			}
			grantRows, err := legacy.QueryContext(ctx, `SELECT owner_env_hash, plugin_instance_id, permission_id, effect, granted_by, granted_at, expires_at, revoked_at, revoked_by, revoked_reason FROM plugin_permission_grants`)
			if err != nil {
				legacy.Close()
				return fmt.Errorf("%w: permission schema: %v", ErrMigration, err)
			}
			for grantRows.Next() {
				var owner, id, permission, effect, grantedBy, revokedBy, revokedReason string
				var grantedAt int64
				var expiresAt, revokedAt sql.NullInt64
				if err := grantRows.Scan(&owner, &id, &permission, &effect, &grantedBy, &grantedAt, &expiresAt, &revokedAt, &revokedBy, &revokedReason); err != nil {
					grantRows.Close()
					legacy.Close()
					return fmt.Errorf("%w: permission row: %v", ErrMigration, err)
				}
				raw, err := canonicalRowJSON(ctx, legacy, "plugin_permission_grants", `owner_env_hash=? AND plugin_instance_id=? AND permission_id=?`, owner, id, permission)
				if err != nil {
					grantRows.Close()
					legacy.Close()
					return fmt.Errorf("%w: canonical grant row: %v", ErrMigration, err)
				}
				revision, err := pluginPolicyRevision(ctx, legacy, owner, id)
				if err != nil {
					grantRows.Close()
					legacy.Close()
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO permission_grants(owner_env_hash,plugin_instance_id,capability_id,grant_json,revision) VALUES(?,?,?,?,?)`, owner, id, permission, raw, revision); err != nil {
					grantRows.Close()
					legacy.Close()
					return fmt.Errorf("%w: import permission: %v", ErrMigration, err)
				}
			}
			if err := grantRows.Err(); err != nil {
				grantRows.Close()
				legacy.Close()
				return fmt.Errorf("%w: permission rows: %v", ErrMigration, err)
			}
			grantRows.Close()
			policyRows, err := legacy.QueryContext(ctx, `SELECT owner_env_hash,plugin_instance_id,allowed_permissions_json,denied_methods_json,updated_at FROM plugin_security_policies`)
			if err != nil {
				legacy.Close()
				return fmt.Errorf("%w: policy schema: %v", ErrMigration, err)
			}
			for policyRows.Next() {
				var owner, id, allowed, denied string
				var updated int64
				if err := policyRows.Scan(&owner, &id, &allowed, &denied, &updated); err != nil {
					policyRows.Close()
					legacy.Close()
					return fmt.Errorf("%w: policy row: %v", ErrMigration, err)
				}
				raw, err := canonicalRowJSON(ctx, legacy, "plugin_security_policies", `owner_env_hash=? AND plugin_instance_id=?`, owner, id)
				if err != nil {
					policyRows.Close()
					legacy.Close()
					return fmt.Errorf("%w: canonical policy row: %v", ErrMigration, err)
				}
				revision, err := pluginPolicyRevision(ctx, legacy, owner, id)
				if err != nil {
					policyRows.Close()
					legacy.Close()
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO security_policies(owner_env_hash,plugin_instance_id,policy_json,revision,updated_at) VALUES(?,?,?,?,?)`, owner, id, raw, revision, updated); err != nil {
					policyRows.Close()
					legacy.Close()
					return fmt.Errorf("%w: import policy: %v", ErrMigration, err)
				}
			}
			if err := policyRows.Err(); err != nil {
				policyRows.Close()
				legacy.Close()
				return fmt.Errorf("%w: policy rows: %v", ErrMigration, err)
			}
			policyRows.Close()
			if err := importRegistryPluginData(ctx, tx, legacy); err != nil {
				legacy.Close()
				return err
			}
			if err := rejectAmbiguousRegistryReleaseInstallOperations(ctx, legacy); err != nil {
				legacy.Close()
				return err
			}
			legacy.Close()
		}
		if source.Kind == "session" {
			if err := importSessionFences(ctx, tx, source); err != nil {
				return err
			}
		}
		if source.Kind == "confirmation" {
			if err := importConfirmations(ctx, tx, source); err != nil {
				return err
			}
		}
		if source.Kind == "operation" || source.Kind == "stream" {
			old, err := openSQLiteReadOnly(source.Path)
			if err != nil {
				return fmt.Errorf("%w: open %s: %v", ErrMigration, source.Kind, err)
			}
			table, idColumn := "plugin_operations", "operation_id"
			if source.Kind == "stream" {
				table, idColumn = "plugin_streams", "stream_id"
			}
			rows, err := old.QueryContext(ctx, `SELECT `+idColumn+`, plugin_instance_id, execution_binding_json, status FROM `+table)
			if err != nil {
				old.Close()
				return fmt.Errorf("%w: read %s: %v", ErrMigration, source.Kind, err)
			}
			for rows.Next() {
				var id, plugin, binding, status string
				if err := rows.Scan(&id, &plugin, &binding, &status); err != nil {
					rows.Close()
					old.Close()
					return fmt.Errorf("%w: scan %s: %v", ErrMigration, source.Kind, err)
				}
				operationID, executionMode, owner, err := bindingIdentity(binding)
				if err != nil {
					rows.Close()
					old.Close()
					return fmt.Errorf("%w: binding %s: %v", ErrMigration, id, err)
				}
				recordJSON, err := canonicalRowJSON(ctx, old, table, idColumn+`=?`, id)
				if err != nil {
					rows.Close()
					old.Close()
					return fmt.Errorf("%w: canonical %s row: %v", ErrMigration, source.Kind, err)
				}
				item := legacyExecution{id: id, plugin: plugin, binding: binding, status: status, operationID: operationID, execution: executionMode, recordJSON: recordJSON, sourcePath: source.Path,
					ownerSession: owner.OwnerSessionHash, ownerUser: owner.OwnerUserHash, ownerEnv: owner.OwnerEnvHash, ownerChannel: owner.SessionChannelIDHash}
				if source.Kind == "operation" {
					if err := old.QueryRowContext(ctx, `SELECT cancelable,failure_code,created_at,updated_at,cancel_requested_at,terminal_at FROM plugin_operations WHERE operation_id=?`, id).Scan(&item.cancelable, &item.failureCode, &item.createdAt, &item.updatedAt, &item.cancelRequestedAt, &item.terminalAt); err != nil {
						rows.Close()
						old.Close()
						return fmt.Errorf("%w: operation lifecycle: %v", ErrMigration, err)
					}
				} else {
					if err := old.QueryRowContext(ctx, `SELECT failure_code,created_at,updated_at,closed_at FROM plugin_streams WHERE stream_id=?`, id).Scan(&item.failureCode, &item.createdAt, &item.updatedAt, &item.terminalAt); err != nil {
						rows.Close()
						old.Close()
						return fmt.Errorf("%w: stream lifecycle: %v", ErrMigration, err)
					}
				}
				if source.Kind == "operation" {
					if _, exists := operations[operationID]; exists {
						rows.Close()
						old.Close()
						return fmt.Errorf("%w: duplicate operation binding %s", ErrMigration, operationID)
					}
					operations[operationID] = item
				} else {
					if _, exists := streams[operationID]; exists {
						rows.Close()
						old.Close()
						return fmt.Errorf("%w: duplicate stream binding %s", ErrMigration, operationID)
					}
					streams[operationID] = item
				}
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				old.Close()
				return fmt.Errorf("%w: rows %s: %v", ErrMigration, source.Kind, err)
			}
			rows.Close()
			old.Close()
		}
	}
	// A stream is a subscription only when it has an exact operation counterpart.
	// Importing either half alone would create an ambiguous public identity.
	for operationID, item := range operations {
		if item.execution == "operation" {
			if _, ok := streams[operationID]; ok {
				return fmt.Errorf("%w: operation %s unexpectedly has stream", ErrMigration, operationID)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO execution(execution_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,kind,status,cursor,failure_code,cancelable,created_at,updated_at,cancel_requested_at,terminal_at,operation_json,stream_json) VALUES(?,?,?,?,?,?,?, ?,0,?,?,?,?,?,?,?,'null')`, operationID, item.plugin, item.ownerSession, item.ownerUser, item.ownerEnv, item.ownerChannel, "operation", migrateOperationStatus(item.status), item.failureCode, item.cancelable, item.createdAt, item.updatedAt, item.cancelRequestedAt, item.terminalAt, item.recordJSON); err != nil {
				return fmt.Errorf("%w: import operation: %v", ErrMigration, err)
			}
			continue
		}
		if item.execution != "subscription" {
			return fmt.Errorf("%w: operation %s has execution %q", ErrMigration, operationID, item.execution)
		}
		stream, ok := streams[operationID]
		if !ok || stream.execution != "subscription" || stream.plugin != item.plugin || stream.binding == "" || item.binding == "" || stream.operationID != operationID || stream.binding != item.binding {
			return fmt.Errorf("%w: operation %s has no exact stream binding", ErrMigration, operationID)
		}
		if !compatibleLegacyExecutionLifecycle(item.status, item.terminalAt.Valid, stream.status, stream.terminalAt.Valid) {
			return fmt.Errorf("%w: operation %s lifecycle status conflicts", ErrMigration, operationID)
		}
		terminalAt := item.terminalAt
		if !terminalAt.Valid {
			terminalAt = stream.terminalAt
		}
		failureCode := item.failureCode
		if failureCode == "" {
			failureCode = stream.failureCode
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO execution(execution_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,kind,status,cursor,failure_code,cancelable,created_at,updated_at,cancel_requested_at,terminal_at,operation_json,stream_json) VALUES(?,?,?,?,?,?,?, ?,0,?,?,?,?,?,?,?,?)`, operationID, item.plugin, item.ownerSession, item.ownerUser, item.ownerEnv, item.ownerChannel, "subscription", migrateOperationStatus(item.status), failureCode, item.cancelable, item.createdAt, item.updatedAt, item.cancelRequestedAt, terminalAt, item.recordJSON, stream.recordJSON); err != nil {
			return fmt.Errorf("%w: import execution: %v", ErrMigration, err)
		}
		if err := importStreamEvents(ctx, tx, stream.sourcePath, stream.id, operationID); err != nil {
			return err
		}
		if isTerminalExecutionStatus(migrateOperationStatus(item.status)) {
			var terminalEvents int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM execution_events WHERE execution_id=? AND kind=?`, operationID, executionmodel.EventTerminal).Scan(&terminalEvents); err != nil {
				return fmt.Errorf("%w: terminal event check: %v", ErrMigration, err)
			}
			if terminalEvents != 1 {
				return fmt.Errorf("%w: terminal execution %s has no unique terminal event", ErrMigration, operationID)
			}
		}
	}
	for operationID := range streams {
		if _, ok := operations[operationID]; !ok {
			return fmt.Errorf("%w: stream %s has no operation binding", ErrMigration, operationID)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit import: %v", ErrMigration, err)
	}
	return nil
}

func rejectAmbiguousRegistryReleaseInstallOperations(ctx context.Context, legacy *sql.DB) error {
	var exists int
	if err := legacy.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='release_install_operations'`).Scan(&exists); err != nil {
		return fmt.Errorf("%w: inspect release install schema: %v", ErrMigration, err)
	}
	if exists == 0 {
		return nil
	}
	if err := validateLegacyReleaseInstallOperationSchema(ctx, legacy); err != nil {
		return err
	}
	var count int
	if err := legacy.QueryRowContext(ctx, `SELECT COUNT(*) FROM release_install_operations`).Scan(&count); err != nil {
		return fmt.Errorf("%w: release install schema: %v", ErrMigration, err)
	}
	if count != 0 {
		return fmt.Errorf("%w: %d release install operations lack exact session owner identity; source is preserved", ErrMigration, count)
	}
	return nil
}

type legacyReleaseInstallColumn struct {
	typeName string
	notNull  int
	primary  int
	defaultV string
}

func validateLegacyReleaseInstallOperationSchema(ctx context.Context, legacy *sql.DB) error {
	base := map[string]legacyReleaseInstallColumn{
		"owner_env_hash": {"TEXT", 1, 1, ""}, "request_id": {"TEXT", 1, 2, ""},
		"operation_id": {"TEXT", 1, 0, ""}, "plugin_instance_id": {"TEXT", 1, 0, ""},
		"request_sha256": {"TEXT", 1, 0, ""}, "release_identity_json": {"TEXT", 1, 0, ""},
		"status": {"TEXT", 1, 0, ""}, "phase": {"TEXT", 1, 0, ""}, "progress_kind": {"TEXT", 1, 0, ""},
		"progress_completed": {"INTEGER", 1, 0, ""}, "progress_total": {"INTEGER", 1, 0, ""},
		"attempt": {"INTEGER", 1, 0, ""}, "retry_after_ms": {"INTEGER", 1, 0, ""},
		"mutation_outcome": {"TEXT", 1, 0, ""}, "failure_code": {"TEXT", 1, 0, ""},
		"failure_retryable": {"INTEGER", 1, 0, ""}, "plugin_record_json": {"TEXT", 1, 0, "'null'"},
		"revision": {"INTEGER", 1, 0, ""}, "created_at": {"INTEGER", 1, 0, ""},
		"updated_at": {"INTEGER", 1, 0, ""}, "terminal_at": {"INTEGER", 0, 0, ""},
	}
	current := make(map[string]legacyReleaseInstallColumn, len(base)+3)
	for name, column := range base {
		current[name] = column
	}
	current["activation_request_json"] = legacyReleaseInstallColumn{"TEXT", 1, 0, `'{"mode":"disabled"}'`}
	current["activation_json"] = legacyReleaseInstallColumn{"TEXT", 1, 0, `'{"status":"not_requested"}'`}
	current["phase_diagnostics_json"] = legacyReleaseInstallColumn{"TEXT", 1, 0, "'[]'"}

	rows, err := legacy.QueryContext(ctx, `PRAGMA table_info(release_install_operations)`)
	if err != nil {
		return fmt.Errorf("%w: release install schema: %v", ErrMigration, err)
	}
	defer rows.Close()
	got := map[string]legacyReleaseInstallColumn{}
	for rows.Next() {
		var position int
		var name, typeName string
		var notNull, primary int
		var defaultValue sql.NullString
		if err := rows.Scan(&position, &name, &typeName, &notNull, &defaultValue, &primary); err != nil {
			return fmt.Errorf("%w: release install schema: %v", ErrMigration, err)
		}
		got[name] = legacyReleaseInstallColumn{typeName: strings.ToUpper(typeName), notNull: notNull, primary: primary, defaultV: defaultValue.String}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: release install schema: %v", ErrMigration, err)
	}
	if !equalLegacyReleaseInstallColumns(got, base) && !equalLegacyReleaseInstallColumns(got, current) {
		return fmt.Errorf("%w: release install schema drift; source is preserved", ErrMigration)
	}
	return nil
}

func equalLegacyReleaseInstallColumns(got, want map[string]legacyReleaseInstallColumn) bool {
	if len(got) != len(want) {
		return false
	}
	for name, expected := range want {
		if actual, ok := got[name]; !ok || actual != expected {
			return false
		}
	}
	return true
}

func importStreamEvents(ctx context.Context, tx *sql.Tx, path, streamID, executionID string) error {
	db, err := openSQLiteReadOnly(path)
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT sequence,kind,data,error,at FROM plugin_stream_events WHERE stream_id=? ORDER BY sequence`, streamID)
	if err != nil {
		return fmt.Errorf("%w: stream events: %v", ErrMigration, err)
	}
	defer rows.Close()
	var cursor uint64
	for rows.Next() {
		var sequence uint64
		var kind, errorText string
		var data []byte
		var at int64
		if err := rows.Scan(&sequence, &kind, &data, &errorText, &at); err != nil {
			return err
		}
		eventKind := migrateEventKind(kind)
		payload, _ := json.Marshal(map[string]any{"data": data, "at": at, "legacy_kind": kind})
		errorJSON := "null"
		if errorText != "" {
			raw, _ := json.Marshal(map[string]string{"message": errorText})
			errorJSON = string(raw)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO execution_events(execution_id,sequence,kind,payload_json,error_json) VALUES(?,?,?,?,?)`, executionID, sequence, eventKind, string(payload), errorJSON); err != nil {
			return err
		}
		cursor = sequence
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE execution SET cursor=? WHERE execution_id=?`, cursor, executionID)
	return err
}

func migrateEventKind(value string) string {
	switch value {
	case executionmodel.EventProgress, executionmodel.EventData, executionmodel.EventDiagnostic, executionmodel.EventTerminal:
		return value
	default:
		return executionmodel.EventDiagnostic
	}
}

func migrateEnableState(value string, deleted bool) (string, error) {
	if deleted {
		return "removed", nil
	}
	switch value {
	case "enabled":
		return "enabled", nil
	case "disabled":
		return "installed_disabled", nil
	case "disabled_by_policy", "disabled_incompatible":
		return "needs_attention", nil
	default:
		return "", fmt.Errorf("unknown enable state %q", value)
	}
}
func canonicalRowJSON(ctx context.Context, db *sql.DB, table, condition string, args ...any) (string, error) {
	rows, err := db.QueryContext(ctx, `SELECT * FROM `+table+` WHERE `+condition, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return "", err
	}
	if !rows.Next() {
		return "", sql.ErrNoRows
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	if err := rows.Scan(pointers...); err != nil {
		return "", err
	}
	record := make(map[string]any, len(columns))
	for i, column := range columns {
		switch value := values[i].(type) {
		case []byte:
			record[column] = string(value)
		default:
			record[column] = value
		}
	}
	raw, err := json.Marshal(record)
	return string(raw), err
}

func pluginPolicyRevision(ctx context.Context, db *sql.DB, owner, id string) (uint64, error) {
	var revision uint64
	if err := db.QueryRowContext(ctx, `SELECT policy_revision FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, id).Scan(&revision); err != nil {
		return 0, fmt.Errorf("%w: plugin policy revision: %v", ErrMigration, err)
	}
	return revision, nil
}

func importSessionFences(ctx context.Context, tx *sql.Tx, source Source) error {
	old, err := sql.Open("sqlite", source.Path)
	if err != nil {
		return fmt.Errorf("%w: open session source: %v", ErrMigration, err)
	}
	defer old.Close()
	var version int
	if err := old.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != source.Version {
		return fmt.Errorf("%w: session version = %d, want %d", ErrMigration, version, source.Version)
	}
	rows, err := old.QueryContext(ctx, `SELECT owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,state,teardown_operation_id,surfaces,asset_tickets,asset_sessions,plugin_gateway_tokens,confirmation_tokens,handle_grants,confirmations,executions,active_network_requests,sockets,network_streams,storage_hostcalls,proof_sha256,created_at,updated_at FROM plugin_session_scope_fences`)
	if err != nil {
		return fmt.Errorf("%w: session schema: %v", ErrMigration, err)
	}
	defer rows.Close()
	for rows.Next() {
		var ownerSession, ownerUser, ownerEnv, channel, state, teardown string
		var surfaces, assetTickets, assetSessions, gatewayTokens, confirmationTokens, handleGrants, confirmations, executions, networkRequests, sockets, networkStreams, storageCalls uint64
		var proof []byte
		var createdAt, updatedAt int64
		if err := rows.Scan(&ownerSession, &ownerUser, &ownerEnv, &channel, &state, &teardown, &surfaces, &assetTickets, &assetSessions, &gatewayTokens, &confirmationTokens, &handleGrants, &confirmations, &executions, &networkRequests, &sockets, &networkStreams, &storageCalls, &proof, &createdAt, &updatedAt); err != nil {
			return fmt.Errorf("%w: session row: %v", ErrMigration, err)
		}
		raw, err := canonicalRowJSON(ctx, old, "plugin_session_scope_fences", `owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=?`, ownerSession, ownerUser, ownerEnv, channel)
		if err != nil {
			return fmt.Errorf("%w: canonical session fence: %v", ErrMigration, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO session_fences(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,state,fence_json,proof_sha256,updated_at) VALUES(?,?,?,?,?,?,?,?)`, ownerSession, ownerUser, ownerEnv, channel, state, string(raw), proof, updatedAt); err != nil {
			return fmt.Errorf("%w: import session: %v", ErrMigration, err)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	phaseRows, err := old.QueryContext(ctx, `SELECT owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,phase FROM plugin_session_scope_teardown_phases`)
	if err != nil {
		return fmt.Errorf("%w: session phases: %v", ErrMigration, err)
	}
	defer phaseRows.Close()
	for phaseRows.Next() {
		var ownerSession, ownerUser, ownerEnv, channel, phase string
		if err := phaseRows.Scan(&ownerSession, &ownerUser, &ownerEnv, &channel, &phase); err != nil {
			return err
		}
		raw, err := canonicalRowJSON(ctx, old, "plugin_session_scope_teardown_phases", `owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND phase=?`, ownerSession, ownerUser, ownerEnv, channel, phase)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO session_teardown_phases(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,phase,phase_json) VALUES(?,?,?,?,?,?)`, ownerSession, ownerUser, ownerEnv, channel, phase, raw); err != nil {
			return err
		}
	}
	return phaseRows.Err()
}

func importConfirmations(ctx context.Context, tx *sql.Tx, source Source) error {
	old, err := sql.Open("sqlite", source.Path)
	if err != nil {
		return fmt.Errorf("%w: open confirmation source: %v", ErrMigration, err)
	}
	defer old.Close()
	var ambiguous int
	if err := old.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_confirmation_intents WHERE migration_required!=0`).Scan(&ambiguous); err != nil {
		return fmt.Errorf("%w: confirmation migration flags: %v", ErrMigration, err)
	}
	if ambiguous != 0 {
		return fmt.Errorf("%w: %d confirmation intents require ambiguous owner migration", ErrMigration, ambiguous)
	}
	rows, err := old.QueryContext(ctx, `SELECT confirmation_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,expires_at FROM plugin_confirmation_intents WHERE migration_required=0`)
	if err != nil {
		return fmt.Errorf("%w: confirmation schema: %v", ErrMigration, err)
	}
	for rows.Next() {
		var id, plugin, ownerSession, ownerUser, ownerEnv, channel string
		var expiresAt int64
		if err := rows.Scan(&id, &plugin, &ownerSession, &ownerUser, &ownerEnv, &channel, &expiresAt); err != nil {
			rows.Close()
			return err
		}
		raw, err := canonicalRowJSON(ctx, old, "plugin_confirmation_intents", `confirmation_id=?`, id)
		if err != nil {
			rows.Close()
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO confirmation_intents(confirmation_id,plugin_instance_id,owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,status,expires_at,confirmation_json) VALUES(?,?,?,?,?,?,'pending',?,?)`, id, plugin, ownerSession, ownerUser, ownerEnv, channel, expiresAt, raw); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	revocations, err := old.QueryContext(ctx, `SELECT owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,teardown_operation_id,revoked_count FROM plugin_confirmation_session_revocations`)
	if err != nil {
		return fmt.Errorf("%w: confirmation revocations: %v", ErrMigration, err)
	}
	defer revocations.Close()
	for revocations.Next() {
		var ownerSession, ownerUser, ownerEnv, channel, operationID string
		var revokedCount int
		if err := revocations.Scan(&ownerSession, &ownerUser, &ownerEnv, &channel, &operationID, &revokedCount); err != nil {
			return err
		}
		raw, err := canonicalRowJSON(ctx, old, "plugin_confirmation_session_revocations", `owner_session_hash=? AND owner_user_hash=? AND owner_env_hash=? AND session_channel_id_hash=? AND teardown_operation_id=?`, ownerSession, ownerUser, ownerEnv, channel, operationID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO confirmation_session_revocations(owner_session_hash,owner_user_hash,owner_env_hash,session_channel_id_hash,teardown_operation_id,revoked_count,revocation_json) VALUES(?,?,?,?,?,?,?)`, ownerSession, ownerUser, ownerEnv, channel, operationID, revokedCount, raw); err != nil {
			return err
		}
	}
	return revocations.Err()
}

func bindingIdentity(binding string) (string, string, ExecutionOwner, error) {
	var value struct {
		ExecutionID          string `json:"execution_id"`
		Execution            string `json:"execution"`
		OwnerSessionHash     string `json:"owner_session_hash"`
		OwnerUserHash        string `json:"owner_user_hash"`
		OwnerEnvHash         string `json:"owner_env_hash"`
		SessionChannelIDHash string `json:"session_channel_id_hash"`
	}
	if err := json.Unmarshal([]byte(binding), &value); err != nil {
		return "", "", ExecutionOwner{}, err
	}
	if strings.TrimSpace(value.ExecutionID) == "" {
		return "", "", ExecutionOwner{}, errors.New("execution_id is required")
	}
	owner := ExecutionOwner{OwnerSessionHash: value.OwnerSessionHash, OwnerUserHash: value.OwnerUserHash, OwnerEnvHash: value.OwnerEnvHash, SessionChannelIDHash: value.SessionChannelIDHash}
	if !owner.Valid() {
		return "", "", ExecutionOwner{}, errors.New("execution owner is required")
	}
	return strings.TrimSpace(value.ExecutionID), strings.TrimSpace(value.Execution), owner, nil
}

func migrateOperationStatus(value string) string {
	switch value {
	case "orphaned_after_disable", "orphaned_after_uninstall":
		return "orphaned"
	default:
		return value
	}
}

func compatibleLegacyExecutionLifecycle(operationStatus string, operationTerminal bool, streamStatus string, streamTerminal bool) bool {
	opTerminal := isTerminalExecutionStatus(migrateOperationStatus(operationStatus)) || operationTerminal
	streamClosed := streamTerminal || (streamStatus != "" && streamStatus != "open")
	return opTerminal == streamClosed
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

func sqliteTableExists(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, name string) (bool, error) {
	var count int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&count); err != nil {
		return false, err
	}
	return count != 0, nil
}

func isTerminalExecutionStatus(status string) bool {
	switch status {
	case executionmodel.StatusCompleted, executionmodel.StatusCanceled, executionmodel.StatusFailed, executionmodel.StatusOrphaned:
		return true
	default:
		return false
	}
}

func normalizeLegacyRegistryTransientTables(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("%w: open registry copy: %v", ErrMigration, err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: registry copy transaction: %v", ErrMigration, err)
	}
	defer rollbackUnlessCommitted(tx)
	for _, table := range []string{"external_package_inspections"} {
		exists, err := sqliteTableExists(ctx, tx, table)
		if err != nil {
			return fmt.Errorf("%w: inspect registry transient table: %v", ErrMigration, err)
		}
		if !exists {
			continue
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			return fmt.Errorf("%w: inspect registry transient rows: %v", ErrMigration, err)
		}
		if count != 0 {
			return fmt.Errorf("%w: registry transient table %q contains durable rows", ErrMigration, table)
		}
		if _, err := tx.ExecContext(ctx, `DROP TABLE `+table); err != nil {
			return fmt.Errorf("%w: drop registry transient table: %v", ErrMigration, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit registry transient cleanup: %v", ErrMigration, err)
	}
	return nil
}

func verifyFile(ctx context.Context, path string, generation uint64) (map[string]int, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := validateSchema(ctx, db); err != nil {
		return nil, err
	}
	var got uint64
	if err := db.QueryRowContext(ctx, `SELECT generation FROM control_generation WHERE id=1`).Scan(&got); err != nil {
		return nil, err
	}
	if got != generation {
		return nil, fmt.Errorf("generation = %d, want %d", got, generation)
	}
	return databaseCounts(ctx, db)
}

func databaseCounts(ctx context.Context, db *sql.DB) (map[string]int, error) {
	counts := map[string]int{}
	for _, table := range controlTables() {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			return nil, err
		}
		counts[table] = count
	}
	return counts, nil
}

func controlTables() []string {
	return []string{"control_generation", "plugin_records", "plugin_data_bindings", "plugin_data_objects", "permission_grants", "security_policies", "execution", "execution_events", "confirmation_intents", "confirmation_session_revocations", "session_fences", "session_teardown_phases", "control_metadata"}
}

func equalCounts(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func syncParentDirectory(path string, override func(string) error) error {
	directory := filepath.Dir(path)
	if override != nil {
		return override(directory)
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func writeDescriptor(path string, value descriptor) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp := path + ".next"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func SourceDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
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
