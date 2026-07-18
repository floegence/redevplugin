package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/security"
)

func (s *SQLiteStore) GrantPermission(ctx context.Context, req permissions.GrantRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
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
	record, err := advanceSQLiteAuthorizationRevisions(ctx, tx, ownerEnvHash, grant.PluginInstanceID, expected, false, grant.GrantedAt)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := upsertSQLitePermissionGrant(ctx, tx, ownerEnvHash, grant); err != nil {
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
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
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
	record, err := advanceSQLiteAuthorizationRevisions(ctx, tx, ownerEnvHash, pluginInstanceID, expected, true, req.Now)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	existing, found, err := getSQLitePermissionGrant(ctx, tx, ownerEnvHash, pluginInstanceID, strings.TrimSpace(req.PermissionID))
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if !found {
		return AuthorizationSnapshot{}, permissions.ErrGrantNotFound
	}
	revoked, err := permissions.Revoke(existing, req)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := upsertSQLitePermissionGrant(ctx, tx, ownerEnvHash, revoked); err != nil {
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
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
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
	record, err := advanceSQLiteAuthorizationRevisions(ctx, tx, ownerEnvHash, policy.PluginInstanceID, expected, true, policy.UpdatedAt)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if err := upsertSQLiteSecurityPolicy(ctx, tx, ownerEnvHash, policy); err != nil {
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
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
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
	record, err := advanceSQLiteAuthorizationRevisions(ctx, tx, ownerEnvHash, pluginInstanceID, expected, true, now)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policies WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, pluginInstanceID); err != nil {
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
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	return s.readSQLiteAuthorization(ctx, ownerEnvHash, strings.TrimSpace(pluginInstanceID), nil)
}

func (s *SQLiteStore) readSQLiteAuthorization(ctx context.Context, ownerEnvHash, pluginInstanceID string, expected *AuthorizationRevisions) (AuthorizationSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	defer rollbackUnlessCommitted(tx)
	record, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, pluginInstanceID, false)
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
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer rollbackUnlessCommitted(tx)
	rows, err := tx.QueryContext(ctx, registryPluginSelectColumns+` FROM plugin_records WHERE owner_env_hash = ? AND deleted_at IS NULL ORDER BY plugin_id, plugin_instance_id`, ownerEnvHash)
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
	grantsByPlugin, err := listAllSQLitePermissionGrants(ctx, tx, ownerEnvHash)
	if err != nil {
		return nil, err
	}
	policiesByPlugin, err := listAllSQLiteSecurityPolicies(ctx, tx, ownerEnvHash)
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

func listAllSQLitePermissionGrants(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash string) (map[string][]permissions.Record, error) {
	rows, err := q.QueryContext(ctx, `
SELECT grants.plugin_instance_id, grants.permission_id, grants.effect, grants.granted_by,
       grants.granted_at, grants.expires_at, grants.revoked_at, grants.revoked_by, grants.revoked_reason
FROM plugin_permission_grants AS grants
JOIN plugin_records AS plugins
	ON plugins.owner_env_hash = grants.owner_env_hash AND plugins.plugin_instance_id = grants.plugin_instance_id
WHERE grants.owner_env_hash = ? AND plugins.deleted_at IS NULL
ORDER BY grants.plugin_instance_id, grants.permission_id`, ownerEnvHash)
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

func listAllSQLiteSecurityPolicies(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash string) (map[string]security.PolicyRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT policies.plugin_instance_id, policies.allowed_permissions_json,
       policies.denied_methods_json, policies.updated_at
FROM plugin_security_policies AS policies
JOIN plugin_records AS plugins
	ON plugins.owner_env_hash = policies.owner_env_hash AND plugins.plugin_instance_id = policies.plugin_instance_id
WHERE policies.owner_env_hash = ? AND plugins.deleted_at IS NULL
ORDER BY policies.plugin_instance_id`, ownerEnvHash)
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

type sqliteSecurityPolicyRelations struct {
	allowedPermissions []string
	deniedMethods      []string
}

func listAllSQLiteSecurityPolicyRelations(ctx context.Context, q sqliteAuthorizationQuerier) (map[string]sqliteSecurityPolicyRelations, error) {
	relations := map[string]sqliteSecurityPolicyRelations{}
	permissionRows, err := q.QueryContext(ctx, `
SELECT owner_env_hash, plugin_instance_id, permission_id
FROM plugin_security_policy_allowed_permissions
ORDER BY owner_env_hash, plugin_instance_id, permission_id`)
	if err != nil {
		return nil, err
	}
	for permissionRows.Next() {
		var ownerEnvHash string
		var pluginInstanceID string
		var permissionID string
		if err := permissionRows.Scan(&ownerEnvHash, &pluginInstanceID, &permissionID); err != nil {
			_ = permissionRows.Close()
			return nil, err
		}
		key := environmentRecordKey(ownerEnvHash, pluginInstanceID)
		relation := relations[key]
		relation.allowedPermissions = append(relation.allowedPermissions, permissionID)
		relations[key] = relation
	}
	if err := permissionRows.Err(); err != nil {
		_ = permissionRows.Close()
		return nil, err
	}
	if err := permissionRows.Close(); err != nil {
		return nil, err
	}
	methodRows, err := q.QueryContext(ctx, `
SELECT owner_env_hash, plugin_instance_id, method
FROM plugin_security_policy_denied_methods
ORDER BY owner_env_hash, plugin_instance_id, method`)
	if err != nil {
		return nil, err
	}
	defer methodRows.Close()
	for methodRows.Next() {
		var ownerEnvHash string
		var pluginInstanceID string
		var method string
		if err := methodRows.Scan(&ownerEnvHash, &pluginInstanceID, &method); err != nil {
			return nil, err
		}
		key := environmentRecordKey(ownerEnvHash, pluginInstanceID)
		relation := relations[key]
		relation.deniedMethods = append(relation.deniedMethods, method)
		relations[key] = relation
	}
	if err := methodRows.Err(); err != nil {
		return nil, err
	}
	return relations, nil
}

func validateSQLiteAuthorizationData(ctx context.Context, q sqliteAuthorizationQuerier) error {
	grantRows, err := q.QueryContext(ctx, `
SELECT plugin_instance_id, permission_id, effect, granted_by, granted_at,
	expires_at, revoked_at, revoked_by, revoked_reason
FROM plugin_permission_grants
ORDER BY plugin_instance_id, permission_id`)
	if err != nil {
		return err
	}
	for grantRows.Next() {
		var record permissions.Record
		var effect string
		var grantedAt int64
		var expiresAt sql.NullInt64
		var revokedAt sql.NullInt64
		if err := grantRows.Scan(
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
			_ = grantRows.Close()
			return err
		}
		record.Effect = permissions.Effect(effect)
		record.GrantedAt = unixToTime(grantedAt)
		record.ExpiresAt = nullableUnixToTimePtr(expiresAt)
		record.RevokedAt = nullableUnixToTimePtr(revokedAt)
		if err := permissions.ValidateRecord(permissions.NormalizeRecord(record)); err != nil {
			_ = grantRows.Close()
			return fmt.Errorf("validate persisted permission grant: %w", err)
		}
	}
	if err := grantRows.Err(); err != nil {
		_ = grantRows.Close()
		return err
	}
	if err := grantRows.Close(); err != nil {
		return err
	}

	relationsByPolicy, err := listAllSQLiteSecurityPolicyRelations(ctx, q)
	if err != nil {
		return err
	}
	policyRows, err := q.QueryContext(ctx, `
SELECT owner_env_hash, plugin_instance_id, allowed_permissions_json, denied_methods_json, updated_at
FROM plugin_security_policies
ORDER BY owner_env_hash, plugin_instance_id`)
	if err != nil {
		return err
	}
	defer policyRows.Close()
	for policyRows.Next() {
		var ownerEnvHash string
		var record security.PolicyRecord
		var allowedJSON string
		var deniedJSON string
		var updatedAt int64
		if err := policyRows.Scan(&ownerEnvHash, &record.PluginInstanceID, &allowedJSON, &deniedJSON, &updatedAt); err != nil {
			return err
		}
		if err := decodeRegistryJSON(allowedJSON, &record.AllowedPermissions); err != nil {
			return err
		}
		if err := decodeRegistryJSON(deniedJSON, &record.DeniedMethods); err != nil {
			return err
		}
		record.UpdatedAt = unixToTime(updatedAt)
		record = security.NormalizePolicy(record)
		if err := security.ValidatePolicy(record); err != nil {
			return fmt.Errorf("validate persisted security policy: %w", err)
		}
		key := environmentRecordKey(ownerEnvHash, record.PluginInstanceID)
		relation := relationsByPolicy[key]
		if !slices.Equal(record.AllowedPermissions, relation.allowedPermissions) || !slices.Equal(record.DeniedMethods, relation.deniedMethods) {
			return fmt.Errorf("validate persisted security policy relations: policy %q relations do not match snapshot", record.PluginInstanceID)
		}
		delete(relationsByPolicy, key)
	}
	if err := policyRows.Err(); err != nil {
		return err
	}
	if len(relationsByPolicy) != 0 {
		return errors.New("validate persisted security policy relations: orphaned relation rows")
	}
	return nil
}

func (s *SQLiteStore) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizationDecision, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return AuthorizationDecision{}, err
	}
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
	state, exists, err := getSQLiteAuthorizationState(ctx, tx, ownerEnvHash, pluginInstanceID)
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
	requiredPermissionIDs := permissions.NormalizePermissionIDs(req.PermissionIDs)
	grants, err := listSQLitePermissionGrantsByID(ctx, tx, ownerEnvHash, pluginInstanceID, requiredPermissionIDs)
	if err != nil {
		return AuthorizationDecision{}, err
	}
	policyEvaluation, err := evaluateSQLiteSecurityPolicy(ctx, tx, ownerEnvHash, pluginInstanceID, req.Method, requiredPermissionIDs)
	if err != nil {
		return AuthorizationDecision{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationDecision{}, err
	}
	return evaluateAuthorizationDecision(state, grants, policyEvaluation, req)
}

func getSQLiteAuthorizationState(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash, pluginInstanceID string) (AuthorizationState, bool, error) {
	var state AuthorizationState
	var trustState string
	var enableState string
	err := q.QueryRowContext(ctx, `
SELECT plugin_instance_id, version, active_fingerprint, trust_state, enable_state,
       policy_revision, management_revision, revoke_epoch
FROM plugin_records
WHERE owner_env_hash = ? AND plugin_instance_id = ? AND deleted_at IS NULL`, ownerEnvHash, pluginInstanceID).Scan(
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

func advanceSQLiteAuthorizationRevisions(ctx context.Context, tx *sql.Tx, ownerEnvHash, pluginInstanceID string, expected AuthorizationRevisions, revoke bool, now time.Time) (PluginRecord, error) {
	revokeIncrement := 0
	if revoke {
		revokeIncrement = 1
	}
	result, err := tx.ExecContext(ctx, `
UPDATE plugin_records
SET policy_revision = policy_revision + 1,
	revoke_epoch = revoke_epoch + ?,
	updated_at = ?
WHERE owner_env_hash = ?
	AND plugin_instance_id = ?
	AND deleted_at IS NULL
	AND policy_revision = ?
	AND management_revision = ?
	AND revoke_epoch = ?`,
		revokeIncrement,
		now.UTC().UnixNano(),
		ownerEnvHash,
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
		record, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, pluginInstanceID, false)
		if err != nil {
			return PluginRecord{}, err
		}
		if !exists {
			return PluginRecord{}, ErrNotFound
		}
		return record, nil
	}
	actualRecord, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, pluginInstanceID, false)
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
	grants, err := listSQLitePermissionGrants(ctx, q, record.OwnerEnvHash, record.PluginInstanceID)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	policy, exists, err := getSQLiteSecurityPolicy(ctx, q, record.OwnerEnvHash, record.PluginInstanceID)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	snapshot := AuthorizationSnapshot{Plugin: plugin, Grants: grants}
	if exists {
		snapshot.Policy = &policy
	}
	return snapshot, nil
}

func listSQLitePermissionGrants(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash, pluginInstanceID string) ([]permissions.Record, error) {
	rows, err := q.QueryContext(ctx, `
SELECT permission_id, effect, granted_by, granted_at, expires_at, revoked_at, revoked_by, revoked_reason
FROM plugin_permission_grants
WHERE owner_env_hash = ? AND plugin_instance_id = ?
ORDER BY permission_id`, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []permissions.Record{}
	for rows.Next() {
		record, err := scanSQLitePermissionGrant(rows, pluginInstanceID)
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

func listSQLitePermissionGrantsByID(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash, pluginInstanceID string, permissionIDs []string) ([]permissions.Record, error) {
	if len(permissionIDs) == 0 {
		return []permissions.Record{}, nil
	}
	if len(permissionIDs) == 1 {
		record, found, err := getSQLitePermissionGrant(ctx, q, ownerEnvHash, pluginInstanceID, permissionIDs[0])
		if err != nil {
			return nil, err
		}
		if !found {
			return []permissions.Record{}, nil
		}
		return []permissions.Record{record}, nil
	}
	requiredJSON, err := encodeRegistryJSON(permissionIDs)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `
WITH required(permission_id) AS (
	SELECT value FROM json_each(?)
)
SELECT grants.permission_id, grants.effect, grants.granted_by, grants.granted_at,
	grants.expires_at, grants.revoked_at, grants.revoked_by, grants.revoked_reason
FROM required
JOIN plugin_permission_grants AS grants
	ON grants.owner_env_hash = ? AND grants.plugin_instance_id = ? AND grants.permission_id = required.permission_id
ORDER BY grants.permission_id`, requiredJSON, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]permissions.Record, 0, len(permissionIDs))
	for rows.Next() {
		record, err := scanSQLitePermissionGrant(rows, pluginInstanceID)
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

func getSQLitePermissionGrant(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash, pluginInstanceID, permissionID string) (permissions.Record, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT permission_id, effect, granted_by, granted_at, expires_at, revoked_at, revoked_by, revoked_reason
FROM plugin_permission_grants
WHERE owner_env_hash = ? AND plugin_instance_id = ? AND permission_id = ?`, ownerEnvHash, pluginInstanceID, permissionID)
	record, err := scanSQLitePermissionGrant(row, pluginInstanceID)
	if errors.Is(err, sql.ErrNoRows) {
		return permissions.Record{}, false, nil
	}
	if err != nil {
		return permissions.Record{}, false, err
	}
	return record, true, nil
}

func scanSQLitePermissionGrant(scanner sqliteAuthorizationScanner, pluginInstanceID string) (permissions.Record, error) {
	var record permissions.Record
	var effect string
	var grantedAt int64
	var expiresAt sql.NullInt64
	var revokedAt sql.NullInt64
	record.PluginInstanceID = pluginInstanceID
	if err := scanner.Scan(
		&record.PermissionID,
		&effect,
		&record.GrantedBy,
		&grantedAt,
		&expiresAt,
		&revokedAt,
		&record.RevokedBy,
		&record.RevokedReason,
	); err != nil {
		return permissions.Record{}, err
	}
	record.Effect = permissions.Effect(effect)
	record.GrantedAt = unixToTime(grantedAt)
	record.ExpiresAt = nullableUnixToTimePtr(expiresAt)
	record.RevokedAt = nullableUnixToTimePtr(revokedAt)
	return record, nil
}

func upsertSQLitePermissionGrant(ctx context.Context, tx *sql.Tx, ownerEnvHash string, record permissions.Record) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO plugin_permission_grants (
	owner_env_hash, plugin_instance_id, permission_id, effect, granted_by, granted_at,
	expires_at, revoked_at, revoked_by, revoked_reason
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(owner_env_hash, plugin_instance_id, permission_id) DO UPDATE SET
	effect = excluded.effect,
	granted_by = excluded.granted_by,
	granted_at = excluded.granted_at,
	expires_at = excluded.expires_at,
	revoked_at = excluded.revoked_at,
	revoked_by = excluded.revoked_by,
	revoked_reason = excluded.revoked_reason`,
		ownerEnvHash,
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

func evaluateSQLiteSecurityPolicy(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash, pluginInstanceID, method string, requiredPermissionIDs []string) (security.PolicyEvaluation, error) {
	method = strings.TrimSpace(method)
	var hasPolicy bool
	var methodDenied bool
	var hasAllowedPermissions bool
	if err := q.QueryRowContext(ctx, `
SELECT
	EXISTS(
		SELECT 1 FROM plugin_security_policies
		WHERE owner_env_hash = ? AND plugin_instance_id = ?
	),
	EXISTS(
		SELECT 1 FROM plugin_security_policy_denied_methods
		WHERE owner_env_hash = ? AND plugin_instance_id = ? AND method = ?
	),
	EXISTS(
		SELECT 1 FROM plugin_security_policy_allowed_permissions
		WHERE owner_env_hash = ? AND plugin_instance_id = ?
		LIMIT 1
	)`,
		ownerEnvHash, pluginInstanceID,
		ownerEnvHash, pluginInstanceID, method,
		ownerEnvHash, pluginInstanceID,
	).Scan(&hasPolicy, &methodDenied, &hasAllowedPermissions); err != nil {
		return security.PolicyEvaluation{}, err
	}
	if !hasPolicy {
		return security.PolicyEvaluation{Allowed: true}, nil
	}
	if methodDenied {
		return security.PolicyEvaluation{Allowed: false, Reason: security.PolicyDenyReasonMethodDenied, DeniedMethod: method}, nil
	}
	if !hasAllowedPermissions {
		return security.PolicyEvaluation{Allowed: true}, nil
	}
	allowedPermissionIDs, err := listSQLiteSecurityPolicyPermissionsByID(ctx, q, ownerEnvHash, pluginInstanceID, requiredPermissionIDs)
	if err != nil {
		return security.PolicyEvaluation{}, err
	}
	missing := make([]string, 0, len(requiredPermissionIDs))
	for _, permissionID := range requiredPermissionIDs {
		if _, allowed := allowedPermissionIDs[permissionID]; !allowed {
			missing = append(missing, permissionID)
		}
	}
	if len(missing) != 0 {
		return security.PolicyEvaluation{
			Allowed:            false,
			Reason:             security.PolicyDenyReasonPermissionNotAllowed,
			MissingPermissions: missing,
		}, nil
	}
	return security.PolicyEvaluation{Allowed: true}, nil
}

func listSQLiteSecurityPolicyPermissionsByID(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash, pluginInstanceID string, permissionIDs []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(permissionIDs))
	if len(permissionIDs) == 0 {
		return allowed, nil
	}
	if len(permissionIDs) == 1 {
		var found bool
		if err := q.QueryRowContext(ctx, `
SELECT EXISTS(
	SELECT 1 FROM plugin_security_policy_allowed_permissions
	WHERE owner_env_hash = ? AND plugin_instance_id = ? AND permission_id = ?
)`, ownerEnvHash, pluginInstanceID, permissionIDs[0]).Scan(&found); err != nil {
			return nil, err
		}
		if found {
			allowed[permissionIDs[0]] = struct{}{}
		}
		return allowed, nil
	}
	requiredJSON, err := encodeRegistryJSON(permissionIDs)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `
WITH required(permission_id) AS (
	SELECT value FROM json_each(?)
)
SELECT policy.permission_id
FROM required
JOIN plugin_security_policy_allowed_permissions AS policy
	ON policy.owner_env_hash = ? AND policy.plugin_instance_id = ? AND policy.permission_id = required.permission_id
ORDER BY policy.permission_id`, requiredJSON, ownerEnvHash, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var permissionID string
		if err := rows.Scan(&permissionID); err != nil {
			return nil, err
		}
		allowed[permissionID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return allowed, nil
}

func getSQLiteSecurityPolicy(ctx context.Context, q sqliteAuthorizationQuerier, ownerEnvHash, pluginInstanceID string) (security.PolicyRecord, bool, error) {
	var allowedJSON string
	var deniedJSON string
	var updatedAt int64
	err := q.QueryRowContext(ctx, `
SELECT allowed_permissions_json, denied_methods_json, updated_at
FROM plugin_security_policies
WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, pluginInstanceID).Scan(&allowedJSON, &deniedJSON, &updatedAt)
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

func upsertSQLiteSecurityPolicy(ctx context.Context, tx *sql.Tx, ownerEnvHash string, record security.PolicyRecord) error {
	record = security.NormalizePolicy(record)
	allowedJSON, err := encodeRegistryJSON(record.AllowedPermissions)
	if err != nil {
		return err
	}
	deniedJSON, err := encodeRegistryJSON(record.DeniedMethods)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `
INSERT INTO plugin_security_policies (
	owner_env_hash, plugin_instance_id, allowed_permissions_json, denied_methods_json, updated_at
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(owner_env_hash, plugin_instance_id) DO UPDATE SET
	allowed_permissions_json = excluded.allowed_permissions_json,
	denied_methods_json = excluded.denied_methods_json,
	updated_at = excluded.updated_at`,
		ownerEnvHash,
		record.PluginInstanceID,
		allowedJSON,
		deniedJSON,
		record.UpdatedAt.UTC().UnixNano(),
	); err != nil {
		return err
	}
	return replaceSQLiteSecurityPolicyRelations(ctx, tx, ownerEnvHash, record)
}

func replaceSQLiteSecurityPolicyRelations(ctx context.Context, tx *sql.Tx, ownerEnvHash string, record security.PolicyRecord) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policy_allowed_permissions WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, record.PluginInstanceID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policy_denied_methods WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, record.PluginInstanceID); err != nil {
		return err
	}
	return insertSQLiteSecurityPolicyRelations(ctx, tx, ownerEnvHash, record)
}

func insertSQLiteSecurityPolicyRelations(ctx context.Context, tx *sql.Tx, ownerEnvHash string, record security.PolicyRecord) error {
	for _, permissionID := range record.AllowedPermissions {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_security_policy_allowed_permissions(owner_env_hash, plugin_instance_id, permission_id)
VALUES (?, ?, ?)`, ownerEnvHash, record.PluginInstanceID, permissionID); err != nil {
			return err
		}
	}
	for _, method := range record.DeniedMethods {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO plugin_security_policy_denied_methods(owner_env_hash, plugin_instance_id, method)
VALUES (?, ?, ?)`, ownerEnvHash, record.PluginInstanceID, method); err != nil {
			return err
		}
	}
	return nil
}

func migrateSQLiteSecurityPolicyRelations(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
SELECT owner_env_hash, plugin_instance_id, allowed_permissions_json, denied_methods_json, updated_at
FROM plugin_security_policies
ORDER BY owner_env_hash, plugin_instance_id`)
	if err != nil {
		return err
	}
	policies := make([]struct {
		ownerEnvHash string
		record       security.PolicyRecord
	}, 0)
	for rows.Next() {
		var policy struct {
			ownerEnvHash string
			record       security.PolicyRecord
		}
		var allowedJSON string
		var deniedJSON string
		var updatedAt int64
		if err := rows.Scan(&policy.ownerEnvHash, &policy.record.PluginInstanceID, &allowedJSON, &deniedJSON, &updatedAt); err != nil {
			_ = rows.Close()
			return err
		}
		if err := decodeRegistryJSON(allowedJSON, &policy.record.AllowedPermissions); err != nil {
			_ = rows.Close()
			return err
		}
		if err := decodeRegistryJSON(deniedJSON, &policy.record.DeniedMethods); err != nil {
			_ = rows.Close()
			return err
		}
		policy.record.UpdatedAt = unixToTime(updatedAt)
		policy.record = security.NormalizePolicy(policy.record)
		if err := security.ValidatePolicy(policy.record); err != nil {
			_ = rows.Close()
			return fmt.Errorf("migrate security policy relations: %w", err)
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policy_allowed_permissions`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policy_denied_methods`); err != nil {
		return err
	}
	for _, policy := range policies {
		if err := insertSQLiteSecurityPolicyRelations(ctx, tx, policy.ownerEnvHash, policy.record); err != nil {
			return err
		}
	}
	return nil
}

func deleteSQLiteAuthorization(ctx context.Context, tx *sql.Tx, ownerEnvHash, pluginInstanceID string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_permission_grants WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, pluginInstanceID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM plugin_security_policies WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, pluginInstanceID)
	return err
}

type sqliteAuthorizationQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqliteAuthorizationScanner interface {
	Scan(...any) error
}

const registryPluginSelectColumns = `
SELECT
	owner_env_hash, plugin_instance_id, publisher_id, plugin_id, version, active_fingerprint,
	package_hash, manifest_hash, entries_hash, trust_state, trust_assessment_json,
	source_policy_snapshot_hash, source_policy_snapshot_json, local_import_provenance_json, capability_contracts_json, enable_state,
	disabled_reason, policy_revision, management_revision,
	revoke_epoch, manifest_json, package_entries_json, version_history_json,
	runtime_requirement_json, installed_at, enabled_at, updated_at, deleted_at, metadata_json`
