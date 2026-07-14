package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 6

type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite registry path is required")
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

func (s *SQLiteStore) PutPlugin(ctx context.Context, record PluginRecord, opts PutOptions) (PluginRecord, error) {
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

	existing, exists, err := getSQLitePlugin(ctx, tx, record.PluginInstanceID, true)
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
	if record.RetainedDataState == "" {
		record.RetainedDataState = RetainedDataNone
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
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists, err := getSQLitePlugin(ctx, s.db, pluginInstanceID, false)
	if err != nil {
		return PluginRecord{}, err
	}
	if !exists {
		return PluginRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *SQLiteStore) ListPlugins(ctx context.Context) ([]PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, `
	SELECT
		plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
		package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
		source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
		disabled_reason, retained_data_state, policy_revision, management_revision,
		revoke_epoch, manifest_json, package_entries_json, version_history_json,
	installed_at, enabled_at, updated_at, deleted_at, metadata_json
FROM plugin_records
WHERE deleted_at IS NULL
ORDER BY plugin_id ASC, plugin_instance_id ASC`)
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

func (s *SQLiteStore) BumpPolicyRevision(ctx context.Context, pluginInstanceID string, revoke bool, now time.Time) (PluginRecord, error) {
	return s.updatePlugin(ctx, pluginInstanceID, now, func(record PluginRecord, now time.Time) PluginRecord {
		record.PolicyRevision++
		if revoke {
			record.RevokeEpoch++
		}
		record.UpdatedAt = now
		return record
	})
}

func (s *SQLiteStore) MarkUninstalled(ctx context.Context, pluginInstanceID string, retained RetainedDataState, now time.Time) (PluginRecord, error) {
	return s.updatePlugin(ctx, pluginInstanceID, now, func(record PluginRecord, now time.Time) PluginRecord {
		record.EnableState = EnableDisabled
		record.DisabledReason = "uninstalled"
		record.RetainedDataState = retained
		record.ManagementRevision++
		record.RevokeEpoch++
		record.UpdatedAt = now
		record.DeletedAt = &now
		record.EnabledAt = nil
		return record
	})
}

func (s *SQLiteStore) DeletePlugin(ctx context.Context, pluginInstanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `DELETE FROM plugin_records WHERE plugin_instance_id = ?`, pluginInstanceID)
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

	record, exists, err := getSQLitePlugin(ctx, tx, pluginInstanceID, false)
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

func (s *SQLiteStore) migrate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)

	var userVersion int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&userVersion); err != nil {
		return err
	}
	if userVersion > sqliteSchemaVersion {
		return fmt.Errorf("sqlite registry schema version %d is newer than supported version %d", userVersion, sqliteSchemaVersion)
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_registry_schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS plugin_records (
	plugin_instance_id TEXT PRIMARY KEY,
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
	retained_data_state TEXT NOT NULL,
	policy_revision INTEGER NOT NULL,
	management_revision INTEGER NOT NULL,
	revoke_epoch INTEGER NOT NULL,
	manifest_json TEXT NOT NULL,
	package_entries_json TEXT NOT NULL,
	version_history_json TEXT NOT NULL,
	installed_at INTEGER NOT NULL,
	enabled_at INTEGER,
	updated_at INTEGER NOT NULL,
	deleted_at INTEGER,
	metadata_json TEXT NOT NULL
)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_records_plugin_id ON plugin_records(plugin_id)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_plugin_records_deleted_at ON plugin_records(deleted_at)`); err != nil {
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
	if userVersion < 2 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_records ADD COLUMN trust_assessment_json TEXT NOT NULL DEFAULT '{}'`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_registry_schema_migrations(version, applied_at) VALUES(?, ?)`, 2, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	if userVersion < 3 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_records ADD COLUMN source_policy_snapshot_hash TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
		if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_records ADD COLUMN source_policy_snapshot_json TEXT NOT NULL DEFAULT '{}'`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_registry_schema_migrations(version, applied_at) VALUES(?, ?)`, 3, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	if userVersion < 4 {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_registry_schema_migrations(version, applied_at) VALUES(?, ?)`, 4, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	if userVersion < 5 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_records ADD COLUMN local_import_provenance_json TEXT NOT NULL DEFAULT '{}'`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_registry_schema_migrations(version, applied_at) VALUES(?, ?)`, 5, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	if userVersion < 6 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE plugin_records ADD COLUMN capability_contracts_json TEXT NOT NULL DEFAULT '[]'`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_registry_schema_migrations(version, applied_at) VALUES(?, ?)`, 6, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	if userVersion < 1 {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_registry_schema_migrations(version, applied_at) VALUES(?, ?)`, 1, time.Now().UTC().UnixNano()); err != nil {
			return err
		}
	}
	if userVersion < sqliteSchemaVersion {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, sqliteSchemaVersion)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func getSQLitePlugin(ctx context.Context, q sqliteQuerier, pluginInstanceID string, includeDeleted bool) (PluginRecord, bool, error) {
	query := `
SELECT
		plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
		package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
		source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
		disabled_reason, retained_data_state, policy_revision, management_revision,
		revoke_epoch, manifest_json, package_entries_json, version_history_json,
	installed_at, enabled_at, updated_at, deleted_at, metadata_json
FROM plugin_records
WHERE plugin_instance_id = ?`
	if !includeDeleted {
		query += ` AND deleted_at IS NULL`
	}
	row := q.QueryRowContext(ctx, query, pluginInstanceID)
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
		plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
		package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
		source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
		disabled_reason, retained_data_state, policy_revision, management_revision,
		revoke_epoch, manifest_json, package_entries_json, version_history_json,
		installed_at, enabled_at, updated_at, deleted_at, metadata_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(plugin_instance_id) DO UPDATE SET
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
	retained_data_state = excluded.retained_data_state,
	policy_revision = excluded.policy_revision,
	management_revision = excluded.management_revision,
	revoke_epoch = excluded.revoke_epoch,
	manifest_json = excluded.manifest_json,
	package_entries_json = excluded.package_entries_json,
	version_history_json = excluded.version_history_json,
	installed_at = excluded.installed_at,
	enabled_at = excluded.enabled_at,
	updated_at = excluded.updated_at,
	deleted_at = excluded.deleted_at,
	metadata_json = excluded.metadata_json`,
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
		string(record.RetainedDataState),
		record.PolicyRevision,
		record.ManagementRevision,
		record.RevokeEpoch,
		manifestJSON,
		packageEntriesJSON,
		versionHistoryJSON,
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
	var retainedDataState string
	var manifestJSON string
	var packageEntriesJSON string
	var versionHistoryJSON string
	var metadataJSON string
	var installedAt int64
	var enabledAt sql.NullInt64
	var updatedAt int64
	var deletedAt sql.NullInt64
	if err := scanner.Scan(
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
		&retainedDataState,
		&record.PolicyRevision,
		&record.ManagementRevision,
		&record.RevokeEpoch,
		&manifestJSON,
		&packageEntriesJSON,
		&versionHistoryJSON,
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
	record.RetainedDataState = RetainedDataState(retainedDataState)
	if err := decodeRegistryJSON(manifestJSON, &record.Manifest); err != nil {
		return PluginRecord{}, err
	}
	if err := decodeRegistryJSON(packageEntriesJSON, &record.PackageEntries); err != nil {
		return PluginRecord{}, err
	}
	if err := decodeRegistryJSON(versionHistoryJSON, &record.VersionHistory); err != nil {
		return PluginRecord{}, err
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
