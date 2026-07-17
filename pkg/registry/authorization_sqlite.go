package registry

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/security"
)

func (s *SQLiteStore) GrantPermission(ctx context.Context, req permissions.GrantRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	grant, err := permissions.NewGrant(req)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := validateAuthorizationRevisions(expected); err != nil {
		return AuthorizationSnapshot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, err := advanceSQLiteAuthorizationRevisions(ctx, tx, grant.PluginInstanceID, expected, false, grant.GrantedAt)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := upsertSQLitePermissionGrant(ctx, tx, grant); err != nil {
		return AuthorizationSnapshot{}, err
	}
	snapshot, err := getSQLiteAuthorizationSnapshot(ctx, tx, record)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationSnapshot{}, mutation.Unknown(err)
	}
	return snapshot, nil
}

func (s *SQLiteStore) RevokePermission(ctx context.Context, req permissions.RevokeRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	if err := permissions.ValidateRevokeRequest(req); err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := validateAuthorizationRevisions(expected); err != nil {
		return AuthorizationSnapshot{}, err
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, err := advanceSQLiteAuthorizationRevisions(ctx, tx, pluginInstanceID, expected, true, req.Now)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	grants, err := listSQLitePermissionGrants(ctx, tx, pluginInstanceID)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	var existing permissions.Record
	found := false
	for _, grant := range grants {
		if grant.PermissionID == strings.TrimSpace(req.PermissionID) {
			existing = grant
			found = true
			break
		}
	}
	if !found {
		return AuthorizationSnapshot{}, permissions.ErrGrantNotFound
	}
	revoked, err := permissions.Revoke(existing, req)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := upsertSQLitePermissionGrant(ctx, tx, revoked); err != nil {
		return AuthorizationSnapshot{}, err
	}
	snapshot, err := getSQLiteAuthorizationSnapshot(ctx, tx, record)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationSnapshot{}, mutation.Unknown(err)
	}
	return snapshot, nil
}

func (s *SQLiteStore) PutSecurityPolicy(ctx context.Context, req security.PutPolicyRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	policy, err := security.NewPolicy(req)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := validateAuthorizationRevisions(expected); err != nil {
		return AuthorizationSnapshot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, err := advanceSQLiteAuthorizationRevisions(ctx, tx, policy.PluginInstanceID, expected, true, policy.UpdatedAt)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := upsertSQLiteSecurityPolicy(ctx, tx, policy); err != nil {
		return AuthorizationSnapshot{}, err
	}
	snapshot, err := getSQLiteAuthorizationSnapshot(ctx, tx, record)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationSnapshot{}, mutation.Unknown(err)
	}
	return snapshot, nil
}

func (s *SQLiteStore) DeleteSecurityPolicy(ctx context.Context, pluginInstanceID string, now time.Time, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	if err := security.ValidatePolicyID(pluginInstanceID); err != nil {
		return AuthorizationSnapshot{}, err
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if err := validateAuthorizationRevisions(expected); err != nil {
		return AuthorizationSnapshot{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, err := advanceSQLiteAuthorizationRevisions(ctx, tx, pluginInstanceID, expected, true, now)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policies WHERE plugin_instance_id = ?`, pluginInstanceID); err != nil {
		return AuthorizationSnapshot{}, err
	}
	snapshot, err := getSQLiteAuthorizationSnapshot(ctx, tx, record)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationSnapshot{}, mutation.Unknown(err)
	}
	return snapshot, nil
}

func (s *SQLiteStore) GetAuthorization(ctx context.Context, pluginInstanceID string) (AuthorizationSnapshot, error) {
	return s.readSQLiteAuthorization(ctx, strings.TrimSpace(pluginInstanceID), nil)
}

func (s *SQLiteStore) readSQLiteAuthorization(ctx context.Context, pluginInstanceID string, expected *AuthorizationRevisions) (AuthorizationSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, exists, err := getSQLitePlugin(ctx, tx, pluginInstanceID, false)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if !exists {
		return AuthorizationSnapshot{}, ErrNotFound
	}
	if expected != nil {
		if err := ensureAuthorizationRevisions(pluginInstanceID, *expected, record); err != nil {
			return AuthorizationSnapshot{}, err
		}
	}
	snapshot, err := getSQLiteAuthorizationSnapshot(ctx, tx, record)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationSnapshot{}, err
	}
	return snapshot, nil
}

func (s *SQLiteStore) ListAuthorization(ctx context.Context) ([]AuthorizationSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer rollbackUnlessCommitted(tx)
	rows, err := tx.QueryContext(ctx, registryPluginSelectColumns+` FROM plugin_records WHERE deleted_at IS NULL ORDER BY plugin_id, plugin_instance_id`)
	if err != nil {
		return nil, err
	}
	records := []PluginRecord{}
	for rows.Next() {
		record, err := scanSQLitePlugin(rows)
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
	grantsByPlugin, err := listAllSQLitePermissionGrants(ctx, tx)
	if err != nil {
		return nil, err
	}
	policiesByPlugin, err := listAllSQLiteSecurityPolicies(ctx, tx)
	if err != nil {
		return nil, err
	}
	snapshots := make([]AuthorizationSnapshot, 0, len(records))
	for _, record := range records {
		grants := grantsByPlugin[record.PluginInstanceID]
		if grants == nil {
			grants = []permissions.Record{}
		}
		snapshot := AuthorizationSnapshot{
			Plugin: record,
			Grants: grants,
		}
		if policy, exists := policiesByPlugin[record.PluginInstanceID]; exists {
			cloned := security.ClonePolicy(policy)
			snapshot.Policy = &cloned
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snapshots, nil
}

func listAllSQLitePermissionGrants(ctx context.Context, q sqliteAuthorizationQuerier) (map[string][]permissions.Record, error) {
	rows, err := q.QueryContext(ctx, `
SELECT grants.plugin_instance_id, grants.permission_id, grants.effect, grants.granted_by,
       grants.granted_at, grants.expires_at, grants.revoked_at, grants.revoked_by, grants.revoked_reason
FROM plugin_permission_grants AS grants
JOIN plugin_records AS plugins ON plugins.plugin_instance_id = grants.plugin_instance_id
WHERE plugins.deleted_at IS NULL
ORDER BY grants.plugin_instance_id, grants.permission_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grantsByPlugin := map[string][]permissions.Record{}
	for rows.Next() {
		var record permissions.Record
		var effect string
		var grantedAt int64
		var expiresAt sql.NullInt64
		var revokedAt sql.NullInt64
		if err := rows.Scan(
			&record.PluginInstanceID,
			&record.PermissionID,
			&effect,
			&record.GrantedBy,
			&grantedAt,
			&expiresAt,
			&revokedAt,
			&record.RevokedBy,
			&record.RevokedReason,
		); err != nil {
			return nil, err
		}
		record.Effect = permissions.Effect(effect)
		record.GrantedAt = unixToTime(grantedAt)
		record.ExpiresAt = nullableUnixToTimePtr(expiresAt)
		record.RevokedAt = nullableUnixToTimePtr(revokedAt)
		grantsByPlugin[record.PluginInstanceID] = append(grantsByPlugin[record.PluginInstanceID], record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return grantsByPlugin, nil
}

func listAllSQLiteSecurityPolicies(ctx context.Context, q sqliteAuthorizationQuerier) (map[string]security.PolicyRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT policies.plugin_instance_id, policies.allowed_permissions_json,
       policies.denied_methods_json, policies.updated_at
FROM plugin_security_policies AS policies
JOIN plugin_records AS plugins ON plugins.plugin_instance_id = policies.plugin_instance_id
WHERE plugins.deleted_at IS NULL
ORDER BY policies.plugin_instance_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policiesByPlugin := map[string]security.PolicyRecord{}
	for rows.Next() {
		var record security.PolicyRecord
		var allowedJSON string
		var deniedJSON string
		var updatedAt int64
		if err := rows.Scan(&record.PluginInstanceID, &allowedJSON, &deniedJSON, &updatedAt); err != nil {
			return nil, err
		}
		if err := decodeRegistryJSON(allowedJSON, &record.AllowedPermissions); err != nil {
			return nil, err
		}
		if err := decodeRegistryJSON(deniedJSON, &record.DeniedMethods); err != nil {
			return nil, err
		}
		record.UpdatedAt = unixToTime(updatedAt)
		policiesByPlugin[record.PluginInstanceID] = record
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return policiesByPlugin, nil
}

func (s *SQLiteStore) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizationDecision, error) {
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if err := security.ValidatePolicyEvaluationRequest(security.EvaluatePolicyRequest{
		PluginInstanceID:    pluginInstanceID,
		Method:              req.Method,
		RequiredPermissions: req.PermissionIDs,
	}); err != nil {
		return AuthorizationDecision{}, err
	}
	if err := validateAuthorizationRevisions(req.Expected); err != nil {
		return AuthorizationDecision{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AuthorizationDecision{}, err
	}
	defer rollbackUnlessCommitted(tx)
	state, exists, err := getSQLiteAuthorizationState(ctx, tx, pluginInstanceID)
	if err != nil {
		return AuthorizationDecision{}, err
	}
	if !exists {
		return AuthorizationDecision{}, ErrNotFound
	}
	if req.Expected != state.Revisions {
		return AuthorizationDecision{}, &AuthorizationRevisionConflictError{
			PluginInstanceID: pluginInstanceID,
			Expected:         req.Expected,
			Actual:           state.Revisions,
		}
	}
	grants, err := listSQLitePermissionGrants(ctx, tx, pluginInstanceID)
	if err != nil {
		return AuthorizationDecision{}, err
	}
	policy, hasPolicy, err := getSQLiteSecurityPolicy(ctx, tx, pluginInstanceID)
	if err != nil {
		return AuthorizationDecision{}, err
	}
	var policyPtr *security.PolicyRecord
	if hasPolicy {
		policyPtr = &policy
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationDecision{}, err
	}
	return evaluateAuthorization(state, grants, policyPtr, req)
}

func getSQLiteAuthorizationState(ctx context.Context, q sqliteAuthorizationQuerier, pluginInstanceID string) (AuthorizationState, bool, error) {
	var state AuthorizationState
	var trustState string
	var enableState string
	err := q.QueryRowContext(ctx, `
SELECT plugin_instance_id, version, active_fingerprint, trust_state, enable_state,
       policy_revision, management_revision, revoke_epoch
FROM plugin_records
WHERE plugin_instance_id = ? AND deleted_at IS NULL`, pluginInstanceID).Scan(
		&state.PluginInstanceID,
		&state.PluginVersion,
		&state.ActiveFingerprint,
		&trustState,
		&enableState,
		&state.Revisions.PolicyRevision,
		&state.Revisions.ManagementRevision,
		&state.Revisions.RevokeEpoch,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthorizationState{}, false, nil
	}
	if err != nil {
		return AuthorizationState{}, false, err
	}
	state.TrustState = TrustState(trustState)
	state.EnableState = EnableState(enableState)
	return state, true, nil
}

func advanceSQLiteAuthorizationRevisions(ctx context.Context, tx *sql.Tx, pluginInstanceID string, expected AuthorizationRevisions, revoke bool, now time.Time) (PluginRecord, error) {
	revokeIncrement := 0
	if revoke {
		revokeIncrement = 1
	}
	result, err := tx.ExecContext(ctx, `
UPDATE plugin_records
SET policy_revision = policy_revision + 1,
	revoke_epoch = revoke_epoch + ?,
	updated_at = ?
WHERE plugin_instance_id = ?
	AND deleted_at IS NULL
	AND policy_revision = ?
	AND management_revision = ?
	AND revoke_epoch = ?`,
		revokeIncrement,
		now.UTC().UnixNano(),
		pluginInstanceID,
		expected.PolicyRevision,
		expected.ManagementRevision,
		expected.RevokeEpoch,
	)
	if err != nil {
		return PluginRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return PluginRecord{}, err
	}
	if affected == 1 {
		record, exists, err := getSQLitePlugin(ctx, tx, pluginInstanceID, false)
		if err != nil {
			return PluginRecord{}, err
		}
		if !exists {
			return PluginRecord{}, ErrNotFound
		}
		return record, nil
	}
	actualRecord, exists, err := getSQLitePlugin(ctx, tx, pluginInstanceID, false)
	if err != nil {
		return PluginRecord{}, err
	}
	if !exists {
		return PluginRecord{}, ErrNotFound
	}
	return PluginRecord{}, &AuthorizationRevisionConflictError{
		PluginInstanceID: pluginInstanceID,
		Expected:         expected,
		Actual:           AuthorizationRevisionsFromRecord(actualRecord),
	}
}

func getSQLiteAuthorizationSnapshot(ctx context.Context, q sqliteAuthorizationQuerier, record PluginRecord) (AuthorizationSnapshot, error) {
	plugin, err := clonePluginRecord(record)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	grants, err := listSQLitePermissionGrants(ctx, q, record.PluginInstanceID)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	policy, exists, err := getSQLiteSecurityPolicy(ctx, q, record.PluginInstanceID)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	snapshot := AuthorizationSnapshot{Plugin: plugin, Grants: grants}
	if exists {
		snapshot.Policy = &policy
	}
	return snapshot, nil
}

func listSQLitePermissionGrants(ctx context.Context, q sqliteAuthorizationQuerier, pluginInstanceID string) ([]permissions.Record, error) {
	rows, err := q.QueryContext(ctx, `
SELECT permission_id, effect, granted_by, granted_at, expires_at, revoked_at, revoked_by, revoked_reason
FROM plugin_permission_grants
WHERE plugin_instance_id = ?
ORDER BY permission_id`, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []permissions.Record{}
	for rows.Next() {
		var record permissions.Record
		var effect string
		var grantedAt int64
		var expiresAt sql.NullInt64
		var revokedAt sql.NullInt64
		record.PluginInstanceID = pluginInstanceID
		if err := rows.Scan(
			&record.PermissionID,
			&effect,
			&record.GrantedBy,
			&grantedAt,
			&expiresAt,
			&revokedAt,
			&record.RevokedBy,
			&record.RevokedReason,
		); err != nil {
			return nil, err
		}
		record.Effect = permissions.Effect(effect)
		record.GrantedAt = unixToTime(grantedAt)
		record.ExpiresAt = nullableUnixToTimePtr(expiresAt)
		record.RevokedAt = nullableUnixToTimePtr(revokedAt)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func upsertSQLitePermissionGrant(ctx context.Context, tx *sql.Tx, record permissions.Record) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_permission_grants (
	plugin_instance_id, permission_id, effect, granted_by, granted_at,
	expires_at, revoked_at, revoked_by, revoked_reason
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(plugin_instance_id, permission_id) DO UPDATE SET
	effect = excluded.effect,
	granted_by = excluded.granted_by,
	granted_at = excluded.granted_at,
	expires_at = excluded.expires_at,
	revoked_at = excluded.revoked_at,
	revoked_by = excluded.revoked_by,
	revoked_reason = excluded.revoked_reason`,
		record.PluginInstanceID,
		record.PermissionID,
		string(record.Effect),
		record.GrantedBy,
		record.GrantedAt.UTC().UnixNano(),
		timePtrToNullableUnix(record.ExpiresAt),
		timePtrToNullableUnix(record.RevokedAt),
		record.RevokedBy,
		record.RevokedReason,
	)
	return err
}

func getSQLiteSecurityPolicy(ctx context.Context, q sqliteAuthorizationQuerier, pluginInstanceID string) (security.PolicyRecord, bool, error) {
	var allowedJSON string
	var deniedJSON string
	var updatedAt int64
	err := q.QueryRowContext(ctx, `
SELECT allowed_permissions_json, denied_methods_json, updated_at
FROM plugin_security_policies
WHERE plugin_instance_id = ?`, pluginInstanceID).Scan(&allowedJSON, &deniedJSON, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return security.PolicyRecord{}, false, nil
	}
	if err != nil {
		return security.PolicyRecord{}, false, err
	}
	record := security.PolicyRecord{PluginInstanceID: pluginInstanceID, UpdatedAt: unixToTime(updatedAt)}
	if err := decodeRegistryJSON(allowedJSON, &record.AllowedPermissions); err != nil {
		return security.PolicyRecord{}, false, err
	}
	if err := decodeRegistryJSON(deniedJSON, &record.DeniedMethods); err != nil {
		return security.PolicyRecord{}, false, err
	}
	return security.ClonePolicy(record), true, nil
}

func upsertSQLiteSecurityPolicy(ctx context.Context, tx *sql.Tx, record security.PolicyRecord) error {
	allowedJSON, err := encodeRegistryJSON(record.AllowedPermissions)
	if err != nil {
		return err
	}
	deniedJSON, err := encodeRegistryJSON(record.DeniedMethods)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO plugin_security_policies (
	plugin_instance_id, allowed_permissions_json, denied_methods_json, updated_at
) VALUES (?, ?, ?, ?)
ON CONFLICT(plugin_instance_id) DO UPDATE SET
	allowed_permissions_json = excluded.allowed_permissions_json,
	denied_methods_json = excluded.denied_methods_json,
	updated_at = excluded.updated_at`,
		record.PluginInstanceID,
		allowedJSON,
		deniedJSON,
		record.UpdatedAt.UTC().UnixNano(),
	)
	return err
}

func deleteSQLiteAuthorization(ctx context.Context, tx *sql.Tx, pluginInstanceID string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_permission_grants WHERE plugin_instance_id = ?`, pluginInstanceID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policies WHERE plugin_instance_id = ?`, pluginInstanceID)
	return err
}

type sqliteAuthorizationQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const registryPluginSelectColumns = `
SELECT
	plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
	package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
	source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
	disabled_reason, policy_revision, management_revision,
	revoke_epoch, manifest_json, package_entries_json, version_history_json,
	runtime_requirement_json, installed_at, enabled_at, updated_at, deleted_at, metadata_json`
