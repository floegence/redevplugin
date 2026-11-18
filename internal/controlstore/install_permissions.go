package controlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// Schema eight fences older writers from the explicit permission choices in
// inspected-install receipts. Existing receipts and grants remain byte-identical.
func migrateInstallPermissions(ctx context.Context, q dataHistoryMigrator) error {
	var count int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM execution WHERE json_extract(operation_json,'$.kind')='inspected_install_v1' AND json_type(operation_json,'$.approved_permissions') IS NOT NULL`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrIncompatible
	}
	_, err := q.ExecContext(ctx, "UPDATE control_schema SET version=8 WHERE id=1 AND version=7")
	return err
}

func validInstallPermissionChoice(ids []string, automatic bool) bool {
	if len(ids) > 128 || automatic && len(ids) != 0 || !slices.IsSorted(ids) {
		return false
	}
	for i, id := range ids {
		if id == "" || len(id) > 256 || strings.TrimSpace(id) != id || permissions.ResourceScoped(id) || i > 0 && ids[i-1] == id {
			return false
		}
	}
	return true
}

// The caller's package/data transaction is also the only grant commit point.
func insertInstallGrants(ctx context.Context, tx *sql.Tx, record registry.PluginRecord, grants []permissions.Record) error {
	if len(grants) == 0 {
		return nil
	}
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, grant := range grants {
		if permissions.ValidateRecord(grant) != nil || grant.PluginInstanceID != record.PluginInstanceID || grant.GrantedBy != session.OwnerUserHash || record.OwnerEnvHash != session.OwnerEnvHash || grant.Effect != permissions.EffectGrant || grant.RevokedAt != nil || grant.ExpiresAt != nil || permissions.ResourceScoped(grant.PermissionID) || seen[grant.PermissionID] {
			return permissions.ErrInvalidPermission
		}
		seen[grant.PermissionID] = true
		raw, err := json.Marshal(grant)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO permission_grants(owner_env_hash,plugin_instance_id,capability_id,grant_json,revision) VALUES(?,?,?,?,?) ON CONFLICT(owner_env_hash,plugin_instance_id,capability_id) DO UPDATE SET grant_json=excluded.grant_json,revision=excluded.revision`, record.OwnerEnvHash, record.PluginInstanceID, grant.PermissionID, string(raw), record.PolicyRevision); err != nil {
			return err
		}
	}
	return nil
}
