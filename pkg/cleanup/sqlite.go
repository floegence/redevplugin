package cleanup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1

type SQLiteOrchestrator struct {
	db  *sql.DB
	mu  sync.Mutex
	now func() time.Time
}

func NewSQLiteOrchestrator(ctx context.Context, path string) (*SQLiteOrchestrator, error) {
	if path == "" {
		return nil, errors.New("sqlite cleanup path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	orchestrator := &SQLiteOrchestrator{
		db:  db,
		now: func() time.Time { return time.Now().UTC() },
	}
	if err := orchestrator.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return orchestrator, nil
}

func (o *SQLiteOrchestrator) Close() error {
	if o == nil || o.db == nil {
		return nil
	}
	return o.db.Close()
}

func (o *SQLiteOrchestrator) PlanUninstall(_ context.Context, pluginInstanceID string, deleteData bool) (Plan, error) {
	return buildUninstallPlan(pluginInstanceID, deleteData)
}

func (o *SQLiteOrchestrator) Execute(ctx context.Context, plan Plan) error {
	if o == nil {
		return errors.New("cleanup orchestrator is nil")
	}
	if err := validatePlan(plan); err != nil {
		return err
	}
	now := o.now()

	o.mu.Lock()
	defer o.mu.Unlock()

	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	for _, phase := range plan.Phases {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_cleanup_operations(plugin_instance_id, delete_data, phase, executed_at)
VALUES(?, ?, ?, ?)`,
			plan.PluginInstanceID,
			boolToInt(plan.DeleteData),
			string(phase),
			now.UTC().UnixNano(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (o *SQLiteOrchestrator) ForceCleanup(ctx context.Context, pluginInstanceID string) error {
	plan, err := o.PlanUninstall(ctx, pluginInstanceID, true)
	if err != nil {
		return err
	}
	return o.Execute(ctx, plan)
}

func (o *SQLiteOrchestrator) ListExecutions(ctx context.Context, pluginInstanceID string) ([]ExecutionRecord, error) {
	if o == nil {
		return nil, errors.New("cleanup orchestrator is nil")
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)

	o.mu.Lock()
	defer o.mu.Unlock()

	query := cleanupSelectColumns + ` FROM plugin_cleanup_operations`
	args := []any{}
	if pluginInstanceID != "" {
		query += ` WHERE plugin_instance_id = ?`
		args = append(args, pluginInstanceID)
	}
	query += ` ORDER BY id ASC`
	rows, err := o.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []ExecutionRecord{}
	for rows.Next() {
		record, err := scanCleanupExecution(rows)
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

func (o *SQLiteOrchestrator) migrate(ctx context.Context) error {
	if _, err := o.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}
	if _, err := o.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return err
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_cleanup_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	maxVersion := 0
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM plugin_cleanup_schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}
	if maxVersion > sqliteSchemaVersion {
		return fmt.Errorf("sqlite cleanup schema version %d is newer than supported version %d", maxVersion, sqliteSchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_cleanup_operations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	plugin_instance_id TEXT NOT NULL,
	delete_data INTEGER NOT NULL,
	phase TEXT NOT NULL,
	executed_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_cleanup_operations_plugin ON plugin_cleanup_operations(plugin_instance_id, id)`); err != nil {
		return err
	}
	if maxVersion < sqliteSchemaVersion {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_cleanup_schema_migrations(version, applied_at) VALUES(?, ?)`, sqliteSchemaVersion, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const cleanupSelectColumns = `
SELECT plugin_instance_id, delete_data, phase, executed_at`

type cleanupScanner interface {
	Scan(...any) error
}

func scanCleanupExecution(scanner cleanupScanner) (ExecutionRecord, error) {
	var record ExecutionRecord
	var deleteData int
	var phase string
	var executedAt int64
	if err := scanner.Scan(&record.PluginInstanceID, &deleteData, &phase, &executedAt); err != nil {
		return ExecutionRecord{}, err
	}
	record.DeleteData = deleteData != 0
	record.Phase = Phase(phase)
	record.ExecutedAt = time.Unix(0, executedAt).UTC()
	return record, nil
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

var _ Orchestrator = (*SQLiteOrchestrator)(nil)
var _ Inspector = (*SQLiteOrchestrator)(nil)
