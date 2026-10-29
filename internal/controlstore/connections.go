package controlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

// Connection records one approved target per connector and resource owner.
// Evidence is private Host state and may contain secret references, never values.
type ConnectionKey struct{ OwnerEnvHash, OwnerUserHash, PluginInstanceID, ConnectorID string }
type Connection struct {
	ConnectionKey
	ConnectionID          string
	ActiveFingerprint     string
	RevokeEpoch, Revision uint64
	ExpiresAt             int64
	RevokedAt             *int64
	Evidence              json.RawMessage
}

func (k ConnectionKey) valid() bool {
	for _, value := range []string{k.OwnerEnvHash, k.PluginInstanceID, k.ConnectorID} {
		if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
			return false
		}
	}
	return len(k.OwnerUserHash) <= 256 && strings.TrimSpace(k.OwnerUserHash) == k.OwnerUserHash
}
func (c Connection) valid() bool {
	return c.ConnectionKey.valid() && c.ConnectionID != "" && len(c.ConnectionID) <= 128 && c.ActiveFingerprint != "" && c.Revision > 0 && c.Revision < math.MaxInt64 && c.RevokeEpoch < math.MaxInt64 && c.ExpiresAt > 0 && len(c.Evidence) <= 64<<10 && validRawJSON(c.Evidence)
}

func (s *Store) PutConnection(ctx context.Context, c Connection, expected uint64, revisions registry.AuthorizationRevisions, now time.Time) error {
	if err := viewReady(s); err != nil {
		return err
	}
	if !c.valid() || expected >= math.MaxInt64 || c.Revision != expected+1 || c.RevokedAt != nil || c.ExpiresAt <= now.UnixNano() || now.IsZero() {
		return ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var fingerprint, state string
	var current registry.AuthorizationRevisions
	err = tx.QueryRowContext(ctx, "SELECT active_fingerprint,state,policy_revision,management_revision,revoke_epoch FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=? AND deleted_at IS NULL", c.OwnerEnvHash, c.PluginInstanceID).Scan(&fingerprint, &state, &current.PolicyRevision, &current.ManagementRevision, &current.RevokeEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRecordNotFound
	}
	if err != nil {
		return err
	}
	if current != revisions || fingerprint != c.ActiveFingerprint || current.RevokeEpoch != c.RevokeEpoch {
		return ErrRevisionConflict
	}
	if state != string(registry.EnableEnabled) {
		return ErrStateConflict
	}
	var actual uint64
	err = tx.QueryRowContext(ctx, "SELECT revision FROM network_connections WHERE owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND connector_id=?", c.OwnerEnvHash, c.OwnerUserHash, c.PluginInstanceID, c.ConnectorID).Scan(&actual)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if actual != expected {
		return ErrRevisionConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO network_connections(owner_env_hash,owner_user_hash,plugin_instance_id,connector_id,connection_id,active_fingerprint,revoke_epoch,revision,expires_at,revoked_at,evidence_json) VALUES(?,?,?,?,?,?,?,?,?,NULL,?) ON CONFLICT(owner_env_hash,owner_user_hash,plugin_instance_id,connector_id) DO UPDATE SET connection_id=excluded.connection_id,active_fingerprint=excluded.active_fingerprint,revoke_epoch=excluded.revoke_epoch,revision=excluded.revision,expires_at=excluded.expires_at,revoked_at=NULL,evidence_json=excluded.evidence_json", c.OwnerEnvHash, c.OwnerUserHash, c.PluginInstanceID, c.ConnectorID, c.ConnectionID, c.ActiveFingerprint, c.RevokeEpoch, c.Revision, c.ExpiresAt, string(c.Evidence))
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return mutation.Unknown(err)
	}
	return nil
}
func (s *Store) GetConnection(ctx context.Context, key ConnectionKey) (Connection, error) {
	if err := viewReady(s); err != nil {
		return Connection{}, err
	}
	if !key.valid() {
		return Connection{}, ErrRecordNotFound
	}
	c := Connection{ConnectionKey: key}
	var revoked sql.NullInt64
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT connection_id,active_fingerprint,revoke_epoch,revision,expires_at,revoked_at,evidence_json FROM network_connections WHERE owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND connector_id=?", key.OwnerEnvHash, key.OwnerUserHash, key.PluginInstanceID, key.ConnectorID).Scan(&c.ConnectionID, &c.ActiveFingerprint, &c.RevokeEpoch, &c.Revision, &c.ExpiresAt, &revoked, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrRecordNotFound
	}
	if err != nil {
		return c, err
	}
	c.RevokedAt = nullIntPointer(revoked)
	c.Evidence = json.RawMessage(raw)
	if !c.valid() {
		return c, ErrIncompatible
	}
	return c, nil
}
func (s *Store) RevokeConnection(ctx context.Context, key ConnectionKey, expected uint64, now time.Time) error {
	if err := viewReady(s); err != nil {
		return err
	}
	if !key.valid() || expected == 0 || expected >= math.MaxInt64 || now.IsZero() {
		return ErrRevisionConflict
	}
	result, err := s.db.ExecContext(ctx, "UPDATE network_connections SET revoked_at=?,revision=revision+1 WHERE owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND connector_id=? AND revision=? AND revoked_at IS NULL", now.UnixNano(), key.OwnerEnvHash, key.OwnerUserHash, key.PluginInstanceID, key.ConnectorID, expected)
	if err != nil {
		return mutation.Unknown(err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return mutation.Unknown(err)
	}
	if changed == 1 {
		return nil
	}
	current, err := s.GetConnection(ctx, key)
	if err == nil && current.RevokedAt != nil && current.Revision == expected+1 {
		return nil
	}
	return ErrRevisionConflict
}

func migrateConnections(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	_, err := q.ExecContext(ctx, "CREATE TABLE network_connections (owner_env_hash TEXT NOT NULL,owner_user_hash TEXT NOT NULL,plugin_instance_id TEXT NOT NULL,connector_id TEXT NOT NULL,connection_id TEXT NOT NULL,active_fingerprint TEXT NOT NULL,revoke_epoch INTEGER NOT NULL,revision INTEGER NOT NULL CHECK(revision>0),expires_at INTEGER NOT NULL,revoked_at INTEGER,evidence_json TEXT NOT NULL,PRIMARY KEY(owner_env_hash,owner_user_hash,plugin_instance_id,connector_id),FOREIGN KEY(owner_env_hash,plugin_instance_id) REFERENCES plugin_records(owner_env_hash,plugin_instance_id) ON DELETE CASCADE)")
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, "UPDATE control_schema SET version=3 WHERE id=1 AND version=2")
	return err
}
