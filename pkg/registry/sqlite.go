package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	platformversion "github.com/floegence/redevplugin/pkg/version"
	_ "modernc.org/sqlite"
)

const maxRegistrySQLiteConnections = 8

type SQLiteStore struct {
	db       *sql.DB
	mu       sync.Mutex
	commitTx func(*sql.Tx) error
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite registry path is required")
	}
	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxRegistrySQLiteConnections)
	db.SetMaxIdleConns(maxRegistrySQLiteConnections)
	store := &SQLiteStore{db: db, commitTx: func(tx *sql.Tx) error { return tx.Commit() }}
	if err := store.initializeSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func registrySQLiteDSN(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(ON)")
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(absPath), RawQuery: query.Encode()}).String(), nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) PutPlugin(ctx context.Context, record PluginRecord, opts PutOptions) (PluginRecord, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return PluginRecord{}, err
	}
	if record.OwnerEnvHash != "" && record.OwnerEnvHash != ownerEnvHash {
		return PluginRecord{}, ErrOwnerScopeMismatch
	}
	record.OwnerEnvHash = ownerEnvHash
	s.mu.Lock()
	defer s.mu.Unlock()

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if record.PluginInstanceID == "" {
		return PluginRecord{}, errors.New("plugin_instance_id is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PluginRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)

	existing, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, record.PluginInstanceID, true)
	if err != nil {
		return PluginRecord{}, err
	}
	if exists {
		record.InstalledAt = existing.InstalledAt
		record.ManagementRevision = existing.ManagementRevision + 1
		record.PolicyRevision = existing.PolicyRevision
		record.RevokeEpoch = existing.RevokeEpoch + 1
	} else {
		record.InstalledAt = now
		if record.PolicyRevision == 0 {
			record.PolicyRevision = 1
		}
		if record.ManagementRevision == 0 {
			record.ManagementRevision = 1
		}
	}
	record.UpdatedAt = now
	if err := upsertSQLitePlugin(ctx, tx, record); err != nil {
		return PluginRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return PluginRecord{}, err
	}
	return record, nil
}

func (s *SQLiteStore) GetPlugin(ctx context.Context, pluginInstanceID string) (PluginRecord, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return PluginRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLitePlugin(ctx, s.db, ownerEnvHash, pluginInstanceID, false)
	if err != nil {
		return PluginRecord{}, err
	}
	if !exists {
		return PluginRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *SQLiteStore) ListPlugins(ctx context.Context) ([]PluginRecord, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, `
	SELECT
		owner_env_hash, plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
		package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
		source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
		disabled_reason, policy_revision, management_revision,
		revoke_epoch, manifest_json, package_entries_json, version_history_json,
		runtime_requirement_json, installed_at, enabled_at, updated_at, deleted_at, metadata_json
FROM plugin_records
WHERE owner_env_hash = ? AND deleted_at IS NULL
ORDER BY plugin_id ASC, plugin_instance_id ASC`, ownerEnvHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []PluginRecord{}
	for rows.Next() {
		record, err := scanSQLitePlugin(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].PluginID == records[j].PluginID {
			return records[i].PluginInstanceID < records[j].PluginInstanceID
		}
		return records[i].PluginID < records[j].PluginID
	})
	return records, nil
}

func (s *SQLiteStore) SetEnableState(ctx context.Context, pluginInstanceID string, state EnableState, reason string, now time.Time) (PluginRecord, error) {
	return s.updatePlugin(ctx, pluginInstanceID, now, func(record PluginRecord, now time.Time) PluginRecord {
		record.EnableState = state
		record.DisabledReason = reason
		record.ManagementRevision++
		record.RevokeEpoch++
		record.UpdatedAt = now
		if state == EnableEnabled {
			record.EnabledAt = &now
		} else {
			record.EnabledAt = nil
		}
		return record
	})
}

func (s *SQLiteStore) CommitUninstall(ctx context.Context, req plugindata.CommitUninstallRequest) (plugindata.CommitUninstallResult, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return plugindata.CommitUninstallResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return plugindata.CommitUninstallResult{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, req.PluginInstanceID, false)
	if err != nil {
		return plugindata.CommitUninstallResult{}, err
	}
	if !exists {
		return plugindata.CommitUninstallResult{}, ErrNotFound
	}
	if req.ExpectedManagementRevision == 0 || record.ManagementRevision != req.ExpectedManagementRevision {
		return plugindata.CommitUninstallResult{}, &ManagementRevisionConflictError{PluginInstanceID: req.PluginInstanceID, Expected: req.ExpectedManagementRevision, Actual: record.ManagementRevision}
	}
	record.EnableState = EnableDisabled
	record.DisabledReason = "uninstalled"
	record.ManagementRevision++
	record.RevokeEpoch++
	record.UpdatedAt = now
	record.DeletedAt = &now
	record.EnabledAt = nil
	if err := upsertSQLitePlugin(ctx, tx, record); err != nil {
		return plugindata.CommitUninstallResult{}, err
	}
	if err := deleteSQLiteAuthorization(ctx, tx, ownerEnvHash, req.PluginInstanceID); err != nil {
		return plugindata.CommitUninstallResult{}, err
	}
	if req.DeleteData {
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, req.PluginInstanceID); err != nil {
			return plugindata.CommitUninstallResult{}, err
		}
	} else if _, err := tx.ExecContext(ctx, `
UPDATE plugin_data_bindings
SET state = ?, revision = revision + 1, retained_at = ?, expires_at = ?
WHERE owner_env_hash = ? AND plugin_instance_id = ?`,
		string(plugindata.BindingRetained), now.UnixNano(), timePtrToNullableUnix(req.RetainUntil), ownerEnvHash, req.PluginInstanceID,
	); err != nil {
		return plugindata.CommitUninstallResult{}, err
	}
	if err := s.commitTx(tx); err != nil {
		return plugindata.CommitUninstallResult{}, mutation.Unknown(err)
	}
	return plugindata.CommitUninstallResult{ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, DeletedAt: now}, nil
}

func (s *SQLiteStore) AbortInstall(ctx context.Context, pluginInstanceID string) error {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, pluginInstanceID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM plugin_records WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return mutation.Unknown(err)
	}
	return nil
}

func (s *SQLiteStore) PutSourceSecurityFloor(ctx context.Context, floor SourceSecurityFloor, opts PutOptions) (SourceSecurityFloor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	floor.UpdatedAt = now
	if err := validateSourceSecurityFloor(floor); err != nil {
		return SourceSecurityFloor{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SourceSecurityFloor{}, err
	}
	defer rollbackUnlessCommitted(tx)

	existing, exists, err := getSQLiteSourceSecurityFloor(ctx, tx, floor.SourceID)
	if err != nil {
		return SourceSecurityFloor{}, err
	}
	if exists {
		if err := ensureSourceSecurityFloorMonotonic(existing, floor); err != nil {
			return SourceSecurityFloor{}, err
		}
	}
	if err := upsertSQLiteSourceSecurityFloor(ctx, tx, floor); err != nil {
		return SourceSecurityFloor{}, err
	}
	if err := tx.Commit(); err != nil {
		return SourceSecurityFloor{}, err
	}
	return floor, nil
}

func (s *SQLiteStore) GetSourceSecurityFloor(ctx context.Context, sourceID string) (SourceSecurityFloor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	floor, exists, err := getSQLiteSourceSecurityFloor(ctx, s.db, sourceID)
	if err != nil {
		return SourceSecurityFloor{}, err
	}
	if !exists {
		return SourceSecurityFloor{}, ErrNotFound
	}
	return floor, nil
}

func (s *SQLiteStore) updatePlugin(ctx context.Context, pluginInstanceID string, now time.Time, mutate func(PluginRecord, time.Time) PluginRecord) (PluginRecord, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return PluginRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PluginRecord{}, err
	}
	defer rollbackUnlessCommitted(tx)

	record, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, pluginInstanceID, false)
	if err != nil {
		return PluginRecord{}, err
	}
	if !exists {
		return PluginRecord{}, ErrNotFound
	}
	record = mutate(record, now)
	if err := upsertSQLitePlugin(ctx, tx, record); err != nil {
		return PluginRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return PluginRecord{}, err
	}
	return record, nil
}

func (s *SQLiteStore) initializeSchema(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var journalMode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode = WAL`).Scan(&journalMode); err != nil {
		return err
	}
	if !strings.EqualFold(journalMode, "wal") {
		return errors.New("sqlite registry requires WAL journal mode")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	if err := prepareOwnerScopedTables(ctx, tx); err != nil {
		return err
	}
	policyPermissionRelationsExist, err := sqliteTableExists(ctx, tx, "plugin_security_policy_allowed_permissions")
	if err != nil {
		return err
	}
	policyMethodRelationsExist, err := sqliteTableExists(ctx, tx, "plugin_security_policy_denied_methods")
	if err != nil {
		return err
	}
	if policyPermissionRelationsExist != policyMethodRelationsExist {
		return fmt.Errorf("%w: security policy relation tables must both exist or both be absent", ErrAuthorizationSchemaIncomplete)
	}
	migrateSecurityPolicyRelations := !policyPermissionRelationsExist

	if _, err := tx.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS plugin_records (
		owner_env_hash TEXT NOT NULL,
		plugin_instance_id TEXT NOT NULL,
	publisher_id TEXT NOT NULL,
	plugin_id TEXT NOT NULL,
	version TEXT NOT NULL,
	active_fingerprint TEXT NOT NULL,
	package_hash TEXT NOT NULL,
	manifest_hash TEXT NOT NULL,
	entries_hash TEXT NOT NULL,
		trust_state TEXT NOT NULL,
		trust_assessment_json TEXT NOT NULL DEFAULT '{}',
		source_policy_snapshot_hash TEXT NOT NULL DEFAULT '',
		source_policy_snapshot_json TEXT NOT NULL DEFAULT '{}',
		local_import_provenance_json TEXT NOT NULL DEFAULT '{}',
		capability_contracts_json TEXT NOT NULL DEFAULT '[]',
		enable_state TEXT NOT NULL,
	disabled_reason TEXT NOT NULL,
	policy_revision INTEGER NOT NULL,
	management_revision INTEGER NOT NULL,
	revoke_epoch INTEGER NOT NULL,
	manifest_json TEXT NOT NULL,
	package_entries_json TEXT NOT NULL,
	version_history_json TEXT NOT NULL,
	runtime_requirement_json TEXT NOT NULL DEFAULT 'null',
	installed_at INTEGER NOT NULL,
	enabled_at INTEGER,
	updated_at INTEGER NOT NULL,
	deleted_at INTEGER,
		metadata_json TEXT NOT NULL,
		PRIMARY KEY(owner_env_hash, plugin_instance_id)
	)`); err != nil {
		return err
	}
	addedRuntimeRequirementColumn, err := ensureRuntimeRequirementColumn(ctx, tx)
	if err != nil {
		return err
	}
	if addedRuntimeRequirementColumn {
		if err := migrateLegacyRuntimeRequirements(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_records_plugin_id ON plugin_records(owner_env_hash, plugin_id)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_records_deleted_at ON plugin_records(owner_env_hash, deleted_at)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS plugin_permission_grants (
		owner_env_hash TEXT NOT NULL,
		plugin_instance_id TEXT NOT NULL,
	permission_id TEXT NOT NULL,
	effect TEXT NOT NULL,
	granted_by TEXT NOT NULL,
	granted_at INTEGER NOT NULL,
	expires_at INTEGER,
	revoked_at INTEGER,
	revoked_by TEXT NOT NULL,
	revoked_reason TEXT NOT NULL,
		PRIMARY KEY(owner_env_hash, plugin_instance_id, permission_id),
		FOREIGN KEY(owner_env_hash, plugin_instance_id) REFERENCES plugin_records(owner_env_hash, plugin_instance_id) ON DELETE CASCADE
	)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS plugin_security_policies (
		owner_env_hash TEXT NOT NULL,
		plugin_instance_id TEXT NOT NULL,
		allowed_permissions_json TEXT NOT NULL,
		denied_methods_json TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY(owner_env_hash, plugin_instance_id),
		FOREIGN KEY(owner_env_hash, plugin_instance_id) REFERENCES plugin_records(owner_env_hash, plugin_instance_id) ON DELETE CASCADE
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS plugin_security_policy_allowed_permissions (
		owner_env_hash TEXT NOT NULL,
		plugin_instance_id TEXT NOT NULL,
		permission_id TEXT NOT NULL,
		PRIMARY KEY(owner_env_hash, plugin_instance_id, permission_id),
		FOREIGN KEY(owner_env_hash, plugin_instance_id) REFERENCES plugin_security_policies(owner_env_hash, plugin_instance_id) ON DELETE CASCADE
	)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS plugin_security_policy_denied_methods (
		owner_env_hash TEXT NOT NULL,
		plugin_instance_id TEXT NOT NULL,
		method TEXT NOT NULL,
		PRIMARY KEY(owner_env_hash, plugin_instance_id, method),
		FOREIGN KEY(owner_env_hash, plugin_instance_id) REFERENCES plugin_security_policies(owner_env_hash, plugin_instance_id) ON DELETE CASCADE
	)`); err != nil {
		return err
	}
	for _, index := range []string{
		"idx_registry_permission_grants_plugin",
		"idx_registry_security_policy_allowed_permission",
		"idx_registry_security_policy_denied_method",
	} {
		if _, err := tx.ExecContext(ctx, `DROP INDEX IF EXISTS `+index); err != nil {
			return err
		}
	}
	if migrateSecurityPolicyRelations {
		if err := migrateSQLiteSecurityPolicyRelations(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS plugin_data_bindings (
		owner_env_hash TEXT NOT NULL,
		plugin_instance_id TEXT NOT NULL,
	generation_id TEXT NOT NULL,
	state TEXT NOT NULL,
	revision INTEGER NOT NULL,
	shape_hash TEXT NOT NULL,
	retained_at INTEGER,
		expires_at INTEGER,
		PRIMARY KEY(owner_env_hash, plugin_instance_id),
		FOREIGN KEY(owner_env_hash, plugin_instance_id) REFERENCES plugin_records(owner_env_hash, plugin_instance_id) ON DELETE CASCADE
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS plugin_data_objects (
		scope_kind TEXT NOT NULL,
		owner_env_hash TEXT NOT NULL,
		owner_user_hash TEXT NOT NULL,
		plugin_instance_id TEXT NOT NULL,
		object_id TEXT NOT NULL,
	content_hash TEXT NOT NULL,
	shape_hash TEXT NOT NULL,
	size_bytes INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY(scope_kind, owner_env_hash, owner_user_hash, plugin_instance_id, object_id)
	)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_source_security_floors (
	source_id TEXT PRIMARY KEY,
	policy_epoch TEXT NOT NULL,
	key_rotation_epoch TEXT NOT NULL,
	revocation_epoch TEXT NOT NULL,
	source_policy_snapshot_hash TEXT NOT NULL,
	revocation_metadata_sha256 TEXT NOT NULL,
	updated_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if err := validateSQLiteAuthorizationData(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

type ownerScopedTableSpec struct {
	name            string
	primaryKey      map[string]int
	foreignKeyTable string
}

var ownerScopedTableSpecs = []ownerScopedTableSpec{
	{name: "plugin_records", primaryKey: map[string]int{"owner_env_hash": 1, "plugin_instance_id": 2}},
	{name: "plugin_permission_grants", primaryKey: map[string]int{"owner_env_hash": 1, "plugin_instance_id": 2, "permission_id": 3}, foreignKeyTable: "plugin_records"},
	{name: "plugin_security_policies", primaryKey: map[string]int{"owner_env_hash": 1, "plugin_instance_id": 2}, foreignKeyTable: "plugin_records"},
	{name: "plugin_security_policy_allowed_permissions", primaryKey: map[string]int{"owner_env_hash": 1, "plugin_instance_id": 2, "permission_id": 3}, foreignKeyTable: "plugin_security_policies"},
	{name: "plugin_security_policy_denied_methods", primaryKey: map[string]int{"owner_env_hash": 1, "plugin_instance_id": 2, "method": 3}, foreignKeyTable: "plugin_security_policies"},
	{name: "plugin_data_bindings", primaryKey: map[string]int{"owner_env_hash": 1, "plugin_instance_id": 2}, foreignKeyTable: "plugin_records"},
	{name: "plugin_data_objects", primaryKey: map[string]int{"scope_kind": 1, "owner_env_hash": 2, "owner_user_hash": 3, "plugin_instance_id": 4, "object_id": 5}},
}

func prepareOwnerScopedTables(ctx context.Context, tx *sql.Tx) error {
	type tableState struct {
		exists     bool
		compatible bool
		rowCount   int64
	}
	states := make(map[string]tableState, len(ownerScopedTableSpecs))
	for _, spec := range ownerScopedTableSpecs {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, spec.name).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			continue
		}
		compatible, err := ownerScopedTableCompatible(ctx, tx, spec)
		if err != nil {
			return err
		}
		var rowCount int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+spec.name).Scan(&rowCount); err != nil {
			return err
		}
		states[spec.name] = tableState{exists: true, compatible: compatible, rowCount: rowCount}
	}
	parent := states["plugin_records"]
	if parent.exists && !parent.compatible {
		for _, state := range states {
			if state.rowCount != 0 {
				return sessionctx.ErrOwnerScopeMigrationRequired
			}
		}
		for i := len(ownerScopedTableSpecs) - 1; i >= 0; i-- {
			if !states[ownerScopedTableSpecs[i].name].exists {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DROP TABLE `+ownerScopedTableSpecs[i].name); err != nil {
				return err
			}
		}
		return nil
	}

	for _, spec := range ownerScopedTableSpecs {
		state := states[spec.name]
		if !state.exists || state.compatible {
			continue
		}
		if state.rowCount != 0 {
			return sessionctx.ErrOwnerScopeMigrationRequired
		}
	}
	for i := len(ownerScopedTableSpecs) - 1; i >= 0; i-- {
		state := states[ownerScopedTableSpecs[i].name]
		if !state.exists || state.compatible {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DROP TABLE `+ownerScopedTableSpecs[i].name); err != nil {
			return err
		}
	}
	return nil
}

func ownerScopedTableCompatible(ctx context.Context, tx *sql.Tx, spec ownerScopedTableSpec) (bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+spec.name+`)`)
	if err != nil {
		return false, err
	}
	primaryKey := make(map[string]int, len(spec.primaryKey))
	notNull := make(map[string]bool, len(spec.primaryKey))
	columnTypes := make(map[string]string, len(spec.primaryKey))
	primaryKeyColumns := 0
	for rows.Next() {
		var (
			columnID    int
			name        string
			columnType  string
			required    int
			defaultExpr sql.NullString
			position    int
		)
		if err := rows.Scan(&columnID, &name, &columnType, &required, &defaultExpr, &position); err != nil {
			return false, err
		}
		if _, ok := spec.primaryKey[name]; ok {
			primaryKey[name] = position
			notNull[name] = required == 1
			columnTypes[name] = columnType
		}
		if position != 0 {
			primaryKeyColumns++
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	if primaryKeyColumns != len(spec.primaryKey) {
		return false, nil
	}
	for name, position := range spec.primaryKey {
		if primaryKey[name] != position || !notNull[name] || !strings.EqualFold(columnTypes[name], "TEXT") {
			return false, nil
		}
	}
	if spec.foreignKeyTable != "" {
		return ownerScopedForeignKeyCompatible(ctx, tx, spec.name, spec.foreignKeyTable)
	}
	return true, nil
}

func ownerScopedForeignKeyCompatible(ctx context.Context, tx *sql.Tx, table, targetTable string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_list(`+table+`)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	type foreignKey struct {
		table    string
		onDelete string
		columns  map[string]string
	}
	foreignKeys := map[int]foreignKey{}
	for rows.Next() {
		var (
			id       int
			sequence int
			target   string
			from     string
			to       string
			onUpdate string
			onDelete string
			match    string
		)
		if err := rows.Scan(&id, &sequence, &target, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return false, err
		}
		key := foreignKeys[id]
		if key.columns == nil {
			key.columns = map[string]string{}
		}
		key.table = target
		key.onDelete = onDelete
		key.columns[from] = to
		foreignKeys[id] = key
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(foreignKeys) != 1 {
		return false, nil
	}
	for _, key := range foreignKeys {
		return key.table == targetTable && strings.EqualFold(key.onDelete, "CASCADE") && len(key.columns) == 2 && key.columns["owner_env_hash"] == "owner_env_hash" && key.columns["plugin_instance_id"] == "plugin_instance_id", nil
	}
	return false, nil
}

func sqliteTableExists(ctx context.Context, q sqliteQuerier, table string) (bool, error) {
	var count int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func ensureRuntimeRequirementColumn(ctx context.Context, tx *sql.Tx) (bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(plugin_records)`)
	if err != nil {
		return false, err
	}
	found := false
	for rows.Next() {
		var (
			columnID    int
			name        string
			columnType  string
			notNull     int
			defaultExpr sql.NullString
			primaryKey  int
		)
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultExpr, &primaryKey); err != nil {
			_ = rows.Close()
			return false, err
		}
		if name != "runtime_requirement_json" {
			continue
		}
		if !strings.EqualFold(columnType, "TEXT") || notNull != 1 || !defaultExpr.Valid || defaultExpr.String != "'null'" || primaryKey != 0 {
			_ = rows.Close()
			return false, fmt.Errorf("plugin_records.runtime_requirement_json has an incompatible schema")
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	if found {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_records ADD COLUMN runtime_requirement_json TEXT NOT NULL DEFAULT 'null'`); err != nil {
		return false, err
	}
	return true, nil
}

func migrateLegacyRuntimeRequirements(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT owner_env_hash, plugin_instance_id, manifest_json, version_history_json FROM plugin_records`)
	if err != nil {
		return err
	}
	type migration struct {
		ownerEnvHash           string
		pluginInstanceID       string
		runtimeRequirementJSON string
		versionHistoryJSON     string
	}
	migrations := make([]migration, 0)
	for rows.Next() {
		var ownerEnvHash string
		var pluginInstanceID string
		var manifestJSON string
		var versionHistoryJSON string
		if err := rows.Scan(&ownerEnvHash, &pluginInstanceID, &manifestJSON, &versionHistoryJSON); err != nil {
			_ = rows.Close()
			return err
		}
		var pluginManifest manifest.Manifest
		if err := decodeRegistryJSON(manifestJSON, &pluginManifest); err != nil {
			_ = rows.Close()
			return fmt.Errorf("migrate runtime requirement for plugin %q: %w", pluginInstanceID, err)
		}
		requirement, err := legacyRuntimeRequirement(pluginManifest)
		if err != nil {
			_ = rows.Close()
			return fmt.Errorf("migrate runtime requirement for plugin %q: %w", pluginInstanceID, err)
		}
		var history []PluginVersion
		if err := decodeRegistryJSON(versionHistoryJSON, &history); err != nil {
			_ = rows.Close()
			return fmt.Errorf("migrate runtime requirement history for plugin %q: %w", pluginInstanceID, err)
		}
		for index := range history {
			if history[index].RuntimeRequirement != nil {
				continue
			}
			history[index].RuntimeRequirement, err = legacyRuntimeRequirement(history[index].Manifest)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("migrate runtime requirement history for plugin %q version %q: %w", pluginInstanceID, history[index].Version, err)
			}
		}
		runtimeRequirementJSON, err := encodeRegistryJSON(requirement)
		if err != nil {
			_ = rows.Close()
			return err
		}
		migratedHistoryJSON, err := encodeRegistryJSON(history)
		if err != nil {
			_ = rows.Close()
			return err
		}
		migrations = append(migrations, migration{
			ownerEnvHash:           ownerEnvHash,
			pluginInstanceID:       pluginInstanceID,
			runtimeRequirementJSON: runtimeRequirementJSON,
			versionHistoryJSON:     migratedHistoryJSON,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, migrated := range migrations {
		if _, err := tx.ExecContext(ctx, `
UPDATE plugin_records
SET runtime_requirement_json = ?, version_history_json = ?
WHERE owner_env_hash = ? AND plugin_instance_id = ?`, migrated.runtimeRequirementJSON, migrated.versionHistoryJSON, migrated.ownerEnvHash, migrated.pluginInstanceID); err != nil {
			return err
		}
	}
	return nil
}

func legacyRuntimeRequirement(pluginManifest manifest.Manifest) (*RuntimeRequirement, error) {
	if len(pluginManifest.Workers) == 0 {
		return nil, nil
	}
	minimumVersion, err := platformversion.ParseSemVer(pluginManifest.Plugin.MinRuntimeVersion)
	if err != nil {
		return nil, err
	}
	return &RuntimeRequirement{MinVersion: minimumVersion.String()}, nil
}

func getSQLitePlugin(ctx context.Context, q sqliteQuerier, ownerEnvHash, pluginInstanceID string, includeDeleted bool) (PluginRecord, bool, error) {
	query := `
SELECT
		owner_env_hash, plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
		package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
		source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
		disabled_reason, policy_revision, management_revision,
		revoke_epoch, manifest_json, package_entries_json, version_history_json,
		runtime_requirement_json, installed_at, enabled_at, updated_at, deleted_at, metadata_json
FROM plugin_records
WHERE owner_env_hash = ? AND plugin_instance_id = ?`
	if !includeDeleted {
		query += ` AND deleted_at IS NULL`
	}
	row := q.QueryRowContext(ctx, query, ownerEnvHash, pluginInstanceID)
	record, err := scanSQLitePlugin(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PluginRecord{}, false, nil
	}
	if err != nil {
		return PluginRecord{}, false, err
	}
	return record, true, nil
}

func upsertSQLitePlugin(ctx context.Context, tx *sql.Tx, record PluginRecord) error {
	record = normalizeTrustAssessment(record)
	manifestJSON, err := encodeRegistryJSON(record.Manifest)
	if err != nil {
		return err
	}
	packageEntriesJSON, err := encodeRegistryJSON(record.PackageEntries)
	if err != nil {
		return err
	}
	versionHistoryJSON, err := encodeRegistryJSON(record.VersionHistory)
	if err != nil {
		return err
	}
	runtimeRequirementJSON, err := encodeRegistryJSON(record.RuntimeRequirement)
	if err != nil {
		return err
	}
	metadataJSON, err := encodeRegistryJSON(record.Metadata)
	if err != nil {
		return err
	}
	trustAssessmentJSON, err := encodeRegistryJSON(record.TrustAssessment)
	if err != nil {
		return err
	}
	sourcePolicySnapshotJSON, err := encodeRegistryJSON(record.SourcePolicySnapshot)
	if err != nil {
		return err
	}
	localImportProvenanceJSON, err := encodeRegistryJSON(record.LocalImportProvenance)
	if err != nil {
		return err
	}
	capabilityContractsJSON, err := encodeRegistryJSON(record.CapabilityContracts)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
	INSERT INTO plugin_records (
		owner_env_hash, plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
		package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
		source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
		disabled_reason, policy_revision, management_revision,
		revoke_epoch, manifest_json, package_entries_json, version_history_json,
		runtime_requirement_json, installed_at, enabled_at, updated_at, deleted_at, metadata_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(owner_env_hash, plugin_instance_id) DO UPDATE SET
	publisher_id = excluded.publisher_id,
	plugin_id = excluded.plugin_id,
	version = excluded.version,
	active_fingerprint = excluded.active_fingerprint,
	package_hash = excluded.package_hash,
	manifest_hash = excluded.manifest_hash,
	entries_hash = excluded.entries_hash,
	trust_state = excluded.trust_state,
		trust_assessment_json = excluded.trust_assessment_json,
		source_policy_snapshot_hash = excluded.source_policy_snapshot_hash,
		source_policy_snapshot_json = excluded.source_policy_snapshot_json,
		local_import_provenance_json = excluded.local_import_provenance_json,
		capability_contracts_json = excluded.capability_contracts_json,
		enable_state = excluded.enable_state,
	disabled_reason = excluded.disabled_reason,
	policy_revision = excluded.policy_revision,
	management_revision = excluded.management_revision,
	revoke_epoch = excluded.revoke_epoch,
	manifest_json = excluded.manifest_json,
	package_entries_json = excluded.package_entries_json,
	version_history_json = excluded.version_history_json,
	runtime_requirement_json = excluded.runtime_requirement_json,
	installed_at = excluded.installed_at,
	enabled_at = excluded.enabled_at,
	updated_at = excluded.updated_at,
	deleted_at = excluded.deleted_at,
	metadata_json = excluded.metadata_json`,
		record.OwnerEnvHash,
		record.PluginInstanceID,
		record.PublisherID,
		record.PluginID,
		record.Version,
		record.ActiveFingerprint,
		record.PackageHash,
		record.ManifestHash,
		record.EntriesHash,
		string(record.TrustState),
		trustAssessmentJSON,
		record.SourcePolicySnapshotHash,
		sourcePolicySnapshotJSON,
		localImportProvenanceJSON,
		capabilityContractsJSON,
		string(record.EnableState),
		record.DisabledReason,
		record.PolicyRevision,
		record.ManagementRevision,
		record.RevokeEpoch,
		manifestJSON,
		packageEntriesJSON,
		versionHistoryJSON,
		runtimeRequirementJSON,
		timeToNullableUnix(record.InstalledAt),
		timePtrToNullableUnix(record.EnabledAt),
		timeToNullableUnix(record.UpdatedAt),
		timePtrToNullableUnix(record.DeletedAt),
		metadataJSON,
	)
	return err
}

type sqliteQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqlitePluginScanner interface {
	Scan(...any) error
}

func scanSQLitePlugin(scanner sqlitePluginScanner) (PluginRecord, error) {
	var record PluginRecord
	var trustState string
	var trustAssessmentJSON string
	var sourcePolicySnapshotJSON string
	var localImportProvenanceJSON string
	var capabilityContractsJSON string
	var enableState string
	var manifestJSON string
	var packageEntriesJSON string
	var versionHistoryJSON string
	var runtimeRequirementJSON string
	var metadataJSON string
	var installedAt int64
	var enabledAt sql.NullInt64
	var updatedAt int64
	var deletedAt sql.NullInt64
	if err := scanner.Scan(
		&record.OwnerEnvHash,
		&record.PluginInstanceID,
		&record.PublisherID,
		&record.PluginID,
		&record.Version,
		&record.ActiveFingerprint,
		&record.PackageHash,
		&record.ManifestHash,
		&record.EntriesHash,
		&trustState,
		&trustAssessmentJSON,
		&record.SourcePolicySnapshotHash,
		&sourcePolicySnapshotJSON,
		&localImportProvenanceJSON,
		&capabilityContractsJSON,
		&enableState,
		&record.DisabledReason,
		&record.PolicyRevision,
		&record.ManagementRevision,
		&record.RevokeEpoch,
		&manifestJSON,
		&packageEntriesJSON,
		&versionHistoryJSON,
		&runtimeRequirementJSON,
		&installedAt,
		&enabledAt,
		&updatedAt,
		&deletedAt,
		&metadataJSON,
	); err != nil {
		return PluginRecord{}, err
	}
	record.TrustState = TrustState(trustState)
	record.EnableState = EnableState(enableState)
	if err := decodeRegistryJSON(manifestJSON, &record.Manifest); err != nil {
		return PluginRecord{}, err
	}
	if err := decodeRegistryJSON(packageEntriesJSON, &record.PackageEntries); err != nil {
		return PluginRecord{}, err
	}
	if err := decodeRegistryJSON(versionHistoryJSON, &record.VersionHistory); err != nil {
		return PluginRecord{}, err
	}
	if runtimeRequirementJSON != "null" {
		var requirement RuntimeRequirement
		if err := decodeRegistryJSON(runtimeRequirementJSON, &requirement); err != nil {
			return PluginRecord{}, err
		}
		record.RuntimeRequirement = &requirement
	}
	if err := decodeRegistryJSON(metadataJSON, &record.Metadata); err != nil {
		return PluginRecord{}, err
	}
	if strings.TrimSpace(trustAssessmentJSON) != "" && strings.TrimSpace(trustAssessmentJSON) != "{}" {
		if err := decodeRegistryJSON(trustAssessmentJSON, &record.TrustAssessment); err != nil {
			return PluginRecord{}, err
		}
	}
	if strings.TrimSpace(sourcePolicySnapshotJSON) != "" && strings.TrimSpace(sourcePolicySnapshotJSON) != "{}" {
		if err := decodeRegistryJSON(sourcePolicySnapshotJSON, &record.SourcePolicySnapshot); err != nil {
			return PluginRecord{}, err
		}
	}
	if strings.TrimSpace(localImportProvenanceJSON) != "" && strings.TrimSpace(localImportProvenanceJSON) != "{}" && strings.TrimSpace(localImportProvenanceJSON) != "null" {
		var provenance LocalImportProvenance
		if err := decodeRegistryJSON(localImportProvenanceJSON, &provenance); err != nil {
			return PluginRecord{}, err
		}
		record.LocalImportProvenance = &provenance
	}
	if strings.TrimSpace(capabilityContractsJSON) != "" && strings.TrimSpace(capabilityContractsJSON) != "[]" {
		if err := decodeRegistryJSON(capabilityContractsJSON, &record.CapabilityContracts); err != nil {
			return PluginRecord{}, err
		}
	}
	record.InstalledAt = unixToTime(installedAt)
	record.UpdatedAt = unixToTime(updatedAt)
	record.EnabledAt = nullableUnixToTimePtr(enabledAt)
	record.DeletedAt = nullableUnixToTimePtr(deletedAt)
	return normalizeTrustAssessment(record), nil
}

func getSQLiteSourceSecurityFloor(ctx context.Context, q sqliteQuerier, sourceID string) (SourceSecurityFloor, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT
	source_id, policy_epoch, key_rotation_epoch, revocation_epoch,
	source_policy_snapshot_hash, revocation_metadata_sha256, updated_at
FROM plugin_source_security_floors
WHERE source_id = ?`, sourceID)
	var floor SourceSecurityFloor
	var updatedAt int64
	if err := row.Scan(
		&floor.SourceID,
		&floor.PolicyEpoch,
		&floor.KeyRotationEpoch,
		&floor.RevocationEpoch,
		&floor.SourcePolicySnapshotHash,
		&floor.RevocationMetadataSHA256,
		&updatedAt,
	); errors.Is(err, sql.ErrNoRows) {
		return SourceSecurityFloor{}, false, nil
	} else if err != nil {
		return SourceSecurityFloor{}, false, err
	}
	floor.UpdatedAt = unixToTime(updatedAt)
	return floor, true, nil
}

func upsertSQLiteSourceSecurityFloor(ctx context.Context, tx *sql.Tx, floor SourceSecurityFloor) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_source_security_floors (
	source_id, policy_epoch, key_rotation_epoch, revocation_epoch,
	source_policy_snapshot_hash, revocation_metadata_sha256, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(source_id) DO UPDATE SET
	policy_epoch = excluded.policy_epoch,
	key_rotation_epoch = excluded.key_rotation_epoch,
	revocation_epoch = excluded.revocation_epoch,
	source_policy_snapshot_hash = excluded.source_policy_snapshot_hash,
	revocation_metadata_sha256 = excluded.revocation_metadata_sha256,
	updated_at = excluded.updated_at`,
		floor.SourceID,
		floor.PolicyEpoch,
		floor.KeyRotationEpoch,
		floor.RevocationEpoch,
		floor.SourcePolicySnapshotHash,
		floor.RevocationMetadataSHA256,
		timeToNullableUnix(floor.UpdatedAt),
	)
	return err
}

func encodeRegistryJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func decodeRegistryJSON(raw string, value any) error {
	return json.Unmarshal([]byte(raw), value)
}

func timeToNullableUnix(value time.Time) int64 {
	return value.UTC().UnixNano()
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
