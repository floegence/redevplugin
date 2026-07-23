package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
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
const registrySQLiteSchemaVersion = 2

type SQLiteStore struct {
	db       *sql.DB
	mu       sync.Mutex
	commitTx func(*sql.Tx) error
}

func (*SQLiteStore) Durable() bool { return true }

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
	record = normalizePluginSecurityFacts(record)
	if err := validatePersistedPluginSecurityFacts(record); err != nil {
		return PluginRecord{}, err
	}
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
		signature_assessment_json, package_source_provenance_json, execution_approval_json,
		update_eligibility, security_capability_summary_json,
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

	var schemaVersion int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&schemaVersion); err != nil {
		return err
	}
	if schemaVersion < 0 || schemaVersion > registrySQLiteSchemaVersion {
		return fmt.Errorf("registry sqlite schema version %d is not supported by version %d", schemaVersion, registrySQLiteSchemaVersion)
	}
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
	if schemaVersion >= 1 {
		if err := validateCurrentRegistrySQLiteSchema(ctx, tx); err != nil {
			return err
		}
		if err := validateSQLiteAuthorizationData(ctx, tx); err != nil {
			return err
		}
		if err := validateSQLitePluginSecurityFacts(ctx, tx); err != nil {
			return err
		}
		if err := reconcileInterruptedExternalPackageCommits(ctx, tx); err != nil {
			return err
		}
		if err := validateSQLitePluginSecurityFacts(ctx, tx); err != nil {
			return err
		}
		if schemaVersion != registrySQLiteSchemaVersion {
			if _, err := tx.ExecContext(ctx, `PRAGMA user_version = `+fmt.Sprint(registrySQLiteSchemaVersion)); err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	if err := prepareOwnerScopedTables(ctx, tx, true); err != nil {
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
		signature_assessment_json TEXT NOT NULL DEFAULT '{}',
		package_source_provenance_json TEXT NOT NULL DEFAULT '{}',
		execution_approval_json TEXT NOT NULL DEFAULT '{}',
		update_eligibility TEXT NOT NULL DEFAULT '',
		security_capability_summary_json TEXT NOT NULL DEFAULT '{}',
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
	addedExternalFactsColumns, err := ensureExternalPackageFactsColumns(ctx, tx, true)
	if err != nil {
		return err
	}
	addedRuntimeRequirementColumn, err := ensureRuntimeRequirementColumn(ctx, tx, true)
	if err != nil {
		return err
	}
	if addedRuntimeRequirementColumn {
		if err := migrateLegacyRuntimeRequirements(ctx, tx); err != nil {
			return err
		}
	}
	if addedExternalFactsColumns {
		if err := migrateLegacyExternalPackageFacts(ctx, tx); err != nil {
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
	CREATE TABLE IF NOT EXISTS external_package_commit_receipts (
		owner_env_hash TEXT NOT NULL,
		inspection_id TEXT NOT NULL,
		commit_id TEXT NOT NULL,
		intent TEXT NOT NULL,
		confirmation_digest TEXT NOT NULL,
		request_sha256 TEXT NOT NULL,
		expected_management_revision INTEGER NOT NULL,
		intended_fingerprint TEXT NOT NULL,
		intended_package_sha256 TEXT NOT NULL,
		plugin_instance_id TEXT NOT NULL,
		status TEXT NOT NULL,
		mutation_outcome TEXT NOT NULL,
		record_snapshot_json TEXT NOT NULL DEFAULT 'null',
		failure_code TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY(owner_env_hash, inspection_id),
		UNIQUE(owner_env_hash, commit_id)
	)`); err != nil {
		return err
	}
	if err := validateExternalPackageCommitReceiptSchema(ctx, tx); err != nil {
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
	if err := validateSQLiteAuthorizationData(ctx, tx); err != nil {
		return err
	}
	if err := validateCurrentRegistrySQLiteSchema(ctx, tx); err != nil {
		return err
	}
	if err := validateSQLitePluginSecurityFacts(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA user_version = `+fmt.Sprint(registrySQLiteSchemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

func reconcileInterruptedExternalPackageCommits(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
UPDATE external_package_commit_receipts
SET status = ?, mutation_outcome = ?, failure_code = ?
WHERE status = ?`,
		string(ExternalPackageFailed), string(mutation.OutcomeNotCommitted), ExternalPackageFailureHostRestarted,
		string(ExternalPackageCommitting),
	)
	return err
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
	{name: "external_package_commit_receipts", primaryKey: map[string]int{"owner_env_hash": 1, "inspection_id": 2}},
}

func prepareOwnerScopedTables(ctx context.Context, tx *sql.Tx, allowMigration bool) error {
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
	if !allowMigration {
		for _, spec := range ownerScopedTableSpecs {
			state := states[spec.name]
			if !state.exists {
				if spec.name == "plugin_security_policy_allowed_permissions" || spec.name == "plugin_security_policy_denied_methods" {
					return fmt.Errorf("%w: table %s is missing", ErrAuthorizationSchemaIncomplete, spec.name)
				}
				return fmt.Errorf("registry sqlite schema is incomplete: table %s is missing", spec.name)
			}
			if !state.compatible {
				return fmt.Errorf("registry sqlite schema is incompatible: table %s", spec.name)
			}
		}
		return nil
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

type registrySQLiteColumnSpec struct {
	typeName     string
	notNull      int
	defaultValue string
	hasDefault   bool
	primaryKey   int
}

func sqliteColumn(typeName string, notNull, primaryKey int) registrySQLiteColumnSpec {
	return registrySQLiteColumnSpec{typeName: typeName, notNull: notNull, primaryKey: primaryKey}
}

func sqliteColumnDefault(typeName string, notNull, primaryKey int, value string) registrySQLiteColumnSpec {
	return registrySQLiteColumnSpec{typeName: typeName, notNull: notNull, primaryKey: primaryKey, defaultValue: value, hasDefault: true}
}

func validateCurrentRegistrySQLiteSchema(ctx context.Context, tx *sql.Tx) error {
	if err := prepareOwnerScopedTables(ctx, tx, false); err != nil {
		return err
	}
	tableSpecs := map[string]map[string]registrySQLiteColumnSpec{
		"plugin_records": {
			"owner_env_hash": sqliteColumn("TEXT", 1, 1), "plugin_instance_id": sqliteColumn("TEXT", 1, 2),
			"publisher_id": sqliteColumn("TEXT", 1, 0), "plugin_id": sqliteColumn("TEXT", 1, 0),
			"version": sqliteColumn("TEXT", 1, 0), "active_fingerprint": sqliteColumn("TEXT", 1, 0),
			"package_hash": sqliteColumn("TEXT", 1, 0), "manifest_hash": sqliteColumn("TEXT", 1, 0), "entries_hash": sqliteColumn("TEXT", 1, 0),
			"trust_state": sqliteColumn("TEXT", 1, 0), "trust_assessment_json": sqliteColumnDefault("TEXT", 1, 0, "'{}'"),
			"signature_assessment_json": sqliteColumnDefault("TEXT", 1, 0, "'{}'"), "package_source_provenance_json": sqliteColumnDefault("TEXT", 1, 0, "'{}'"),
			"execution_approval_json": sqliteColumnDefault("TEXT", 1, 0, "'{}'"), "update_eligibility": sqliteColumnDefault("TEXT", 1, 0, "''"),
			"security_capability_summary_json": sqliteColumnDefault("TEXT", 1, 0, "'{}'"),
			"source_policy_snapshot_hash":      sqliteColumnDefault("TEXT", 1, 0, "''"), "source_policy_snapshot_json": sqliteColumnDefault("TEXT", 1, 0, "'{}'"),
			"local_import_provenance_json": sqliteColumnDefault("TEXT", 1, 0, "'{}'"), "capability_contracts_json": sqliteColumnDefault("TEXT", 1, 0, "'[]'"),
			"enable_state": sqliteColumn("TEXT", 1, 0), "disabled_reason": sqliteColumn("TEXT", 1, 0),
			"policy_revision": sqliteColumn("INTEGER", 1, 0), "management_revision": sqliteColumn("INTEGER", 1, 0), "revoke_epoch": sqliteColumn("INTEGER", 1, 0),
			"manifest_json": sqliteColumn("TEXT", 1, 0), "package_entries_json": sqliteColumn("TEXT", 1, 0), "version_history_json": sqliteColumn("TEXT", 1, 0),
			"runtime_requirement_json": sqliteColumnDefault("TEXT", 1, 0, "'null'"), "installed_at": sqliteColumn("INTEGER", 1, 0),
			"enabled_at": sqliteColumn("INTEGER", 0, 0), "updated_at": sqliteColumn("INTEGER", 1, 0), "deleted_at": sqliteColumn("INTEGER", 0, 0),
			"metadata_json": sqliteColumn("TEXT", 1, 0),
		},
		"plugin_permission_grants": {
			"owner_env_hash": sqliteColumn("TEXT", 1, 1), "plugin_instance_id": sqliteColumn("TEXT", 1, 2), "permission_id": sqliteColumn("TEXT", 1, 3),
			"effect": sqliteColumn("TEXT", 1, 0), "granted_by": sqliteColumn("TEXT", 1, 0), "granted_at": sqliteColumn("INTEGER", 1, 0),
			"expires_at": sqliteColumn("INTEGER", 0, 0), "revoked_at": sqliteColumn("INTEGER", 0, 0), "revoked_by": sqliteColumn("TEXT", 1, 0), "revoked_reason": sqliteColumn("TEXT", 1, 0),
		},
		"plugin_security_policies": {
			"owner_env_hash": sqliteColumn("TEXT", 1, 1), "plugin_instance_id": sqliteColumn("TEXT", 1, 2),
			"allowed_permissions_json": sqliteColumn("TEXT", 1, 0), "denied_methods_json": sqliteColumn("TEXT", 1, 0), "updated_at": sqliteColumn("INTEGER", 1, 0),
		},
		"plugin_security_policy_allowed_permissions": {
			"owner_env_hash": sqliteColumn("TEXT", 1, 1), "plugin_instance_id": sqliteColumn("TEXT", 1, 2), "permission_id": sqliteColumn("TEXT", 1, 3),
		},
		"plugin_security_policy_denied_methods": {
			"owner_env_hash": sqliteColumn("TEXT", 1, 1), "plugin_instance_id": sqliteColumn("TEXT", 1, 2), "method": sqliteColumn("TEXT", 1, 3),
		},
		"plugin_data_bindings": {
			"owner_env_hash": sqliteColumn("TEXT", 1, 1), "plugin_instance_id": sqliteColumn("TEXT", 1, 2), "generation_id": sqliteColumn("TEXT", 1, 0),
			"state": sqliteColumn("TEXT", 1, 0), "revision": sqliteColumn("INTEGER", 1, 0), "shape_hash": sqliteColumn("TEXT", 1, 0),
			"retained_at": sqliteColumn("INTEGER", 0, 0), "expires_at": sqliteColumn("INTEGER", 0, 0),
		},
		"plugin_data_objects": {
			"scope_kind": sqliteColumn("TEXT", 1, 1), "owner_env_hash": sqliteColumn("TEXT", 1, 2), "owner_user_hash": sqliteColumn("TEXT", 1, 3),
			"plugin_instance_id": sqliteColumn("TEXT", 1, 4), "object_id": sqliteColumn("TEXT", 1, 5), "content_hash": sqliteColumn("TEXT", 1, 0),
			"shape_hash": sqliteColumn("TEXT", 1, 0), "size_bytes": sqliteColumn("INTEGER", 1, 0), "created_at": sqliteColumn("INTEGER", 1, 0),
		},
	}
	for table, expected := range tableSpecs {
		if err := validateRegistrySQLiteTableColumns(ctx, tx, table, expected); err != nil {
			return err
		}
	}
	if err := validateExternalPackageCommitReceiptSchema(ctx, tx); err != nil {
		return err
	}
	return validateCurrentRegistrySQLiteIndexes(ctx, tx)
}

func validateRegistrySQLiteTableColumns(ctx context.Context, tx *sql.Tx, table string, expected map[string]registrySQLiteColumnSpec) error {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(expected))
	for rows.Next() {
		var id, notNull, primaryKey int
		var name, typeName string
		var defaultExpr sql.NullString
		if err := rows.Scan(&id, &name, &typeName, &notNull, &defaultExpr, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		spec, ok := expected[name]
		if !ok || !strings.EqualFold(typeName, spec.typeName) || notNull != spec.notNull || primaryKey != spec.primaryKey || defaultExpr.Valid != spec.hasDefault || defaultExpr.String != spec.defaultValue {
			_ = rows.Close()
			return fmt.Errorf("registry sqlite table %s has incompatible column %s", table, name)
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("registry sqlite table %s has an incomplete schema", table)
	}
	return nil
}

func validateCurrentRegistrySQLiteIndexes(ctx context.Context, tx *sql.Tx) error {
	tables := []string{
		"plugin_records", "external_package_commit_receipts", "plugin_permission_grants", "plugin_security_policies",
		"plugin_security_policy_allowed_permissions", "plugin_security_policy_denied_methods", "plugin_data_bindings", "plugin_data_objects",
	}
	required := map[string][]string{
		"idx_plugin_records_plugin_id":  {"owner_env_hash", "plugin_id"},
		"idx_plugin_records_deleted_at": {"owner_env_hash", "deleted_at"},
	}
	seen := make(map[string]bool, len(required))
	for _, table := range tables {
		rows, err := tx.QueryContext(ctx, `PRAGMA index_list(`+table+`)`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var sequence, unique, partial int
			var name, origin string
			if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
				_ = rows.Close()
				return err
			}
			if origin != "c" {
				continue
			}
			columns, ok := required[name]
			if !ok || table != "plugin_records" || unique != 0 || partial != 0 {
				_ = rows.Close()
				return fmt.Errorf("registry sqlite has unexpected explicit index %s", name)
			}
			actual, err := registrySQLiteIndexColumns(ctx, tx, name)
			if err != nil {
				_ = rows.Close()
				return err
			}
			if !slices.Equal(actual, columns) {
				_ = rows.Close()
				return fmt.Errorf("registry sqlite index %s has incompatible columns", name)
			}
			seen[name] = true
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	if len(seen) != len(required) {
		return errors.New("registry sqlite required indexes are incomplete")
	}
	return nil
}

func registrySQLiteIndexColumns(ctx context.Context, tx *sql.Tx, name string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA index_info(`+name+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var sequence, columnID int
		var column string
		if err := rows.Scan(&sequence, &columnID, &column); err != nil {
			return nil, err
		}
		columns = append(columns, column)
	}
	return columns, rows.Err()
}

func ensureRuntimeRequirementColumn(ctx context.Context, tx *sql.Tx, allowMigration bool) (bool, error) {
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
	if !allowMigration {
		return false, errors.New("plugin_records.runtime_requirement_json is missing from the current schema")
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_records ADD COLUMN runtime_requirement_json TEXT NOT NULL DEFAULT 'null'`); err != nil {
		return false, err
	}
	return true, nil
}

func ensureExternalPackageFactsColumns(ctx context.Context, tx *sql.Tx, allowMigration bool) (bool, error) {
	type columnSpec struct {
		name         string
		defaultValue string
	}
	specs := []columnSpec{
		{name: "signature_assessment_json", defaultValue: "'{}'"},
		{name: "package_source_provenance_json", defaultValue: "'{}'"},
		{name: "execution_approval_json", defaultValue: "'{}'"},
		{name: "update_eligibility", defaultValue: "''"},
		{name: "security_capability_summary_json", defaultValue: "'{}'"},
	}
	found := make(map[string]bool, len(specs))
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(plugin_records)`)
	if err != nil {
		return false, err
	}
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
		for _, spec := range specs {
			if name != spec.name {
				continue
			}
			if !strings.EqualFold(columnType, "TEXT") || notNull != 1 || !defaultExpr.Valid || defaultExpr.String != spec.defaultValue || primaryKey != 0 {
				_ = rows.Close()
				return false, fmt.Errorf("plugin_records.%s has an incompatible schema", name)
			}
			found[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	added := false
	for _, spec := range specs {
		if found[spec.name] {
			continue
		}
		if !allowMigration {
			return false, fmt.Errorf("plugin_records.%s is missing from the current schema", spec.name)
		}
		if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_records ADD COLUMN `+spec.name+` TEXT NOT NULL DEFAULT `+spec.defaultValue); err != nil {
			return false, err
		}
		added = true
	}
	return added, nil
}

func validateExternalPackageCommitReceiptSchema(ctx context.Context, tx *sql.Tx) error {
	type columnSpec struct {
		typeName     string
		notNull      int
		defaultValue string
		primaryKey   int
	}
	expected := map[string]columnSpec{
		"owner_env_hash": {"TEXT", 1, "", 1}, "inspection_id": {"TEXT", 1, "", 2},
		"commit_id": {"TEXT", 1, "", 0}, "intent": {"TEXT", 1, "", 0},
		"confirmation_digest": {"TEXT", 1, "", 0}, "request_sha256": {"TEXT", 1, "", 0},
		"expected_management_revision": {"INTEGER", 1, "", 0}, "intended_fingerprint": {"TEXT", 1, "", 0},
		"intended_package_sha256": {"TEXT", 1, "", 0}, "plugin_instance_id": {"TEXT", 1, "", 0},
		"status": {"TEXT", 1, "", 0}, "mutation_outcome": {"TEXT", 1, "", 0},
		"record_snapshot_json": {"TEXT", 1, "'null'", 0}, "failure_code": {"TEXT", 1, "''", 0},
		"created_at": {"INTEGER", 1, "", 0}, "updated_at": {"INTEGER", 1, "", 0},
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(external_package_commit_receipts)`)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(expected))
	for rows.Next() {
		var id, notNull, primaryKey int
		var name, typeName string
		var defaultExpr sql.NullString
		if err := rows.Scan(&id, &name, &typeName, &notNull, &defaultExpr, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		spec, ok := expected[name]
		if !ok || !strings.EqualFold(typeName, spec.typeName) || notNull != spec.notNull || primaryKey != spec.primaryKey || defaultExpr.String != spec.defaultValue || defaultExpr.Valid != (spec.defaultValue != "") {
			_ = rows.Close()
			return fmt.Errorf("external_package_commit_receipts.%s has an incompatible schema", name)
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("external_package_commit_receipts has an incomplete schema")
	}
	indexRows, err := tx.QueryContext(ctx, `PRAGMA index_list(external_package_commit_receipts)`)
	if err != nil {
		return err
	}
	uniqueCommitBinding := false
	for indexRows.Next() {
		var sequence, unique, partial int
		var name, origin string
		if err := indexRows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			_ = indexRows.Close()
			return err
		}
		if origin != "u" {
			continue
		}
		if unique != 1 || partial != 0 {
			_ = indexRows.Close()
			return fmt.Errorf("external_package_commit_receipts unique constraint %s is incompatible", name)
		}
		columns, err := registrySQLiteIndexColumns(ctx, tx, name)
		if err != nil {
			_ = indexRows.Close()
			return err
		}
		if !slices.Equal(columns, []string{"owner_env_hash", "commit_id"}) || uniqueCommitBinding {
			_ = indexRows.Close()
			return fmt.Errorf("external_package_commit_receipts has an unexpected unique constraint %s", name)
		}
		uniqueCommitBinding = true
	}
	if err := indexRows.Err(); err != nil {
		_ = indexRows.Close()
		return err
	}
	if err := indexRows.Close(); err != nil {
		return err
	}
	if !uniqueCommitBinding {
		return errors.New("external_package_commit_receipts is missing the owner-and-commit unique constraint")
	}
	return nil
}

func validateSQLitePluginSecurityFacts(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
SELECT
    owner_env_hash, plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
    package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
    signature_assessment_json, package_source_provenance_json, execution_approval_json,
    update_eligibility, security_capability_summary_json,
    source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
    disabled_reason, policy_revision, management_revision,
    revoke_epoch, manifest_json, package_entries_json, version_history_json,
    runtime_requirement_json, installed_at, enabled_at, updated_at, deleted_at, metadata_json
FROM plugin_records`)
	if err != nil {
		return err
	}
	for rows.Next() {
		if _, err := scanSQLitePlugin(rows); err != nil {
			_ = rows.Close()
			return fmt.Errorf("validate persisted plugin security facts: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	receiptRows, err := tx.QueryContext(ctx, `SELECT owner_env_hash, inspection_id FROM external_package_commit_receipts`)
	if err != nil {
		return err
	}
	type receiptIdentity struct{ ownerEnvHash, inspectionID string }
	var receipts []receiptIdentity
	for receiptRows.Next() {
		var identity receiptIdentity
		if err := receiptRows.Scan(&identity.ownerEnvHash, &identity.inspectionID); err != nil {
			_ = receiptRows.Close()
			return err
		}
		receipts = append(receipts, identity)
	}
	if err := receiptRows.Err(); err != nil {
		_ = receiptRows.Close()
		return err
	}
	if err := receiptRows.Close(); err != nil {
		return err
	}
	for _, identity := range receipts {
		if _, exists, err := getSQLiteExternalPackageCommit(ctx, tx, identity.ownerEnvHash, identity.inspectionID); err != nil {
			return fmt.Errorf("validate external package receipt %q: %w", identity.inspectionID, err)
		} else if !exists {
			return fmt.Errorf("external package receipt %q disappeared during validation", identity.inspectionID)
		}
	}
	return nil
}

func migrateLegacyExternalPackageFacts(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
SELECT owner_env_hash, plugin_instance_id, package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
       enable_state, signature_assessment_json, package_source_provenance_json,
       execution_approval_json, update_eligibility, version_history_json
FROM plugin_records`)
	if err != nil {
		return err
	}
	type migratedRecord struct {
		ownerEnvHash, pluginInstanceID string
		signatureAssessmentJSON        string
		packageSourceProvenanceJSON    string
		executionApprovalJSON          string
		updateEligibility              string
		versionHistoryJSON             string
	}
	var migrations []migratedRecord
	for rows.Next() {
		var record PluginRecord
		var trustState, enableState string
		var trustJSON, signatureJSON, provenanceJSON, approvalJSON, updateEligibility, historyJSON string
		if err := rows.Scan(
			&record.OwnerEnvHash, &record.PluginInstanceID, &record.PackageHash, &record.ManifestHash, &record.EntriesHash, &trustState, &trustJSON,
			&enableState, &signatureJSON, &provenanceJSON, &approvalJSON, &updateEligibility, &historyJSON,
		); err != nil {
			_ = rows.Close()
			return err
		}
		record.TrustState = TrustState(trustState)
		record.EnableState = EnableState(enableState)
		record.UpdateEligibility = UpdateEligibility(updateEligibility)
		if trustJSON != "" && trustJSON != "{}" {
			if err := decodeRegistryJSON(trustJSON, &record.TrustAssessment); err != nil {
				_ = rows.Close()
				return fmt.Errorf("migrate external facts for plugin %q: %w", record.PluginInstanceID, err)
			}
		}
		if signatureJSON != "" && signatureJSON != "{}" {
			if err := decodeRegistryJSON(signatureJSON, &record.SignatureAssessment); err != nil {
				_ = rows.Close()
				return err
			}
		}
		if provenanceJSON != "" && provenanceJSON != "{}" {
			if err := decodeRegistryJSON(provenanceJSON, &record.PackageSourceProvenance); err != nil {
				_ = rows.Close()
				return err
			}
		}
		if approvalJSON != "" && approvalJSON != "{}" {
			if err := decodeRegistryJSON(approvalJSON, &record.ExecutionApproval); err != nil {
				_ = rows.Close()
				return err
			}
		}
		if err := decodeRegistryJSON(historyJSON, &record.VersionHistory); err != nil {
			_ = rows.Close()
			return fmt.Errorf("migrate external facts history for plugin %q: %w", record.PluginInstanceID, err)
		}
		record = normalizePluginSecurityFacts(record)
		signatureJSON, err = encodeRegistryJSON(record.SignatureAssessment)
		if err != nil {
			_ = rows.Close()
			return err
		}
		provenanceJSON, err = encodeRegistryJSON(record.PackageSourceProvenance)
		if err != nil {
			_ = rows.Close()
			return err
		}
		approvalJSON, err = encodeRegistryJSON(record.ExecutionApproval)
		if err != nil {
			_ = rows.Close()
			return err
		}
		historyJSON, err = encodeRegistryJSON(record.VersionHistory)
		if err != nil {
			_ = rows.Close()
			return err
		}
		migrations = append(migrations, migratedRecord{
			ownerEnvHash: record.OwnerEnvHash, pluginInstanceID: record.PluginInstanceID,
			signatureAssessmentJSON: signatureJSON, packageSourceProvenanceJSON: provenanceJSON,
			executionApprovalJSON: approvalJSON, updateEligibility: string(record.UpdateEligibility),
			versionHistoryJSON: historyJSON,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, record := range migrations {
		if _, err := tx.ExecContext(ctx, `
UPDATE plugin_records
SET signature_assessment_json = ?, package_source_provenance_json = ?, execution_approval_json = ?,
    update_eligibility = ?, version_history_json = ?
WHERE owner_env_hash = ? AND plugin_instance_id = ?`,
			record.signatureAssessmentJSON, record.packageSourceProvenanceJSON, record.executionApprovalJSON,
			record.updateEligibility, record.versionHistoryJSON, record.ownerEnvHash, record.pluginInstanceID,
		); err != nil {
			return err
		}
	}
	return nil
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
		signature_assessment_json, package_source_provenance_json, execution_approval_json,
		update_eligibility, security_capability_summary_json,
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
	record = normalizePluginSecurityFacts(record)
	if err := validatePersistedPluginSecurityFacts(record); err != nil {
		return err
	}
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
	signatureAssessmentJSON, err := encodeRegistryJSON(record.SignatureAssessment)
	if err != nil {
		return err
	}
	packageSourceProvenanceJSON, err := encodeRegistryJSON(record.PackageSourceProvenance)
	if err != nil {
		return err
	}
	executionApprovalJSON, err := encodeRegistryJSON(record.ExecutionApproval)
	if err != nil {
		return err
	}
	securityCapabilitySummaryJSON, err := encodeRegistryJSON(record.SecurityCapabilitySummary)
	if err != nil {
		return err
	}
	releaseTrustBindingJSON, err := encodeRegistryJSON(record.ReleaseTrustBinding)
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
		signature_assessment_json, package_source_provenance_json, execution_approval_json,
		update_eligibility, security_capability_summary_json,
		source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
		disabled_reason, policy_revision, management_revision,
		revoke_epoch, manifest_json, package_entries_json, version_history_json,
		runtime_requirement_json, installed_at, enabled_at, updated_at, deleted_at, metadata_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		signature_assessment_json = excluded.signature_assessment_json,
		package_source_provenance_json = excluded.package_source_provenance_json,
		execution_approval_json = excluded.execution_approval_json,
		update_eligibility = excluded.update_eligibility,
		security_capability_summary_json = excluded.security_capability_summary_json,
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
		signatureAssessmentJSON,
		packageSourceProvenanceJSON,
		executionApprovalJSON,
		string(record.UpdateEligibility),
		securityCapabilitySummaryJSON,
		releaseTrustBindingStateSHA256(record.ReleaseTrustBinding),
		releaseTrustBindingJSON,
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
	var signatureAssessmentJSON string
	var packageSourceProvenanceJSON string
	var executionApprovalJSON string
	var updateEligibility string
	var securityCapabilitySummaryJSON string
	var releaseTrustBindingStateSHA256 string
	var releaseTrustBindingJSON string
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
		&signatureAssessmentJSON,
		&packageSourceProvenanceJSON,
		&executionApprovalJSON,
		&updateEligibility,
		&securityCapabilitySummaryJSON,
		&releaseTrustBindingStateSHA256,
		&releaseTrustBindingJSON,
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
	record.UpdateEligibility = UpdateEligibility(updateEligibility)
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
	if strings.TrimSpace(signatureAssessmentJSON) != "" && strings.TrimSpace(signatureAssessmentJSON) != "{}" {
		if err := decodeRegistryJSON(signatureAssessmentJSON, &record.SignatureAssessment); err != nil {
			return PluginRecord{}, err
		}
	}
	if strings.TrimSpace(packageSourceProvenanceJSON) != "" && strings.TrimSpace(packageSourceProvenanceJSON) != "{}" {
		if err := decodeRegistryJSON(packageSourceProvenanceJSON, &record.PackageSourceProvenance); err != nil {
			return PluginRecord{}, err
		}
	}
	if strings.TrimSpace(executionApprovalJSON) != "" && strings.TrimSpace(executionApprovalJSON) != "{}" {
		if err := decodeRegistryJSON(executionApprovalJSON, &record.ExecutionApproval); err != nil {
			return PluginRecord{}, err
		}
	}
	if strings.TrimSpace(securityCapabilitySummaryJSON) != "" && strings.TrimSpace(securityCapabilitySummaryJSON) != "{}" {
		if err := decodeRegistryJSON(securityCapabilitySummaryJSON, &record.SecurityCapabilitySummary); err != nil {
			return PluginRecord{}, err
		}
	}
	if strings.TrimSpace(releaseTrustBindingJSON) != "" && strings.TrimSpace(releaseTrustBindingJSON) != "{}" && strings.TrimSpace(releaseTrustBindingJSON) != "null" {
		var binding ReleaseTrustBinding
		if err := decodeRegistryJSON(releaseTrustBindingJSON, &binding); err != nil {
			return PluginRecord{}, err
		}
		if binding.VerifiedStateSHA256 != releaseTrustBindingStateSHA256 {
			return PluginRecord{}, errors.New("release trust binding state digest mismatch")
		}
		record.ReleaseTrustBinding = &binding
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
	if err := validatePersistedPluginSecurityFacts(record); err != nil {
		return PluginRecord{}, err
	}
	return record, nil
}

func releaseTrustBindingStateSHA256(binding *ReleaseTrustBinding) string {
	if binding == nil {
		return ""
	}
	return binding.VerifiedStateSHA256
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
