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

var ErrSelectedResourceLimit = errors.New("selected file resource limit exceeded")

const SelectedResourceActiveLimit = 128
const SelectedResourceRetainedLimit = 256

// SelectedResource is Host-owned authority. RawJSON contains private object
// evidence and must never be projected to a plugin or management response.
type SelectedResource struct {
	CurrentManagementRevision                                 uint64
	OwnerEnvHash, OwnerUserHash, PluginInstanceID, ResourceID string
	ActiveFingerprint                                         string
	RevokeEpoch, Revision                                     uint64
	ExpiresAt                                                 int64
	RevokedAt                                                 *int64
	RawJSON                                                   json.RawMessage
}

type SelectedResourceKey struct {
	OwnerEnvHash, OwnerUserHash, PluginInstanceID, ResourceID string
}

func (r SelectedResource) Key() SelectedResourceKey {
	return SelectedResourceKey{r.OwnerEnvHash, r.OwnerUserHash, r.PluginInstanceID, r.ResourceID}
}

func (k SelectedResourceKey) valid() bool {
	for _, v := range []string{k.OwnerEnvHash, k.OwnerUserHash, k.PluginInstanceID, k.ResourceID} {
		if v == "" || strings.TrimSpace(v) != v || len(v) > 256 {
			return false
		}
	}
	return true
}

func (s *Store) CreateSelectedResource(ctx context.Context, r SelectedResource, expected registry.AuthorizationRevisions, now time.Time) error {
	if err := viewReady(s); err != nil {
		return err
	}
	if !r.Key().valid() || r.ActiveFingerprint == "" || r.Revision != 1 || r.RevokeEpoch > math.MaxInt64 || r.RevokedAt != nil || now.IsZero() || r.ExpiresAt <= now.UnixNano() || !validRawJSON(r.RawJSON) || len(r.RawJSON) > 64<<10 {
		return ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var actual registry.AuthorizationRevisions
	var fingerprint, state string
	err = tx.QueryRowContext(ctx, `SELECT active_fingerprint,state,policy_revision,management_revision,revoke_epoch FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=? AND deleted_at IS NULL`, r.OwnerEnvHash, r.PluginInstanceID).Scan(&fingerprint, &state, &actual.PolicyRevision, &actual.ManagementRevision, &actual.RevokeEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRecordNotFound
	}
	if err != nil {
		return err
	}
	if actual != expected || fingerprint != r.ActiveFingerprint || actual.RevokeEpoch != r.RevokeEpoch {
		return ErrRevisionConflict
	}
	if state != string(registry.EnableEnabled) {
		return ErrStateConflict
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM selected_file_resources WHERE owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND revoked_at IS NULL AND expires_at>? AND active_fingerprint=? AND revoke_epoch=?`, r.OwnerEnvHash, r.OwnerUserHash, r.PluginInstanceID, now.UnixNano(), fingerprint, actual.RevokeEpoch).Scan(&active); err != nil {
		return err
	}
	if active >= SelectedResourceActiveLimit {
		return ErrSelectedResourceLimit
	}
	// Retain a bounded set of inactive records for reconciliation and display.
	// The security audit owns history; these rows only own current file grants.
	_, err = tx.ExecContext(ctx, `DELETE FROM selected_file_resources WHERE rowid IN (SELECT rowid FROM selected_file_resources WHERE owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND (revoked_at IS NOT NULL OR expires_at<=? OR active_fingerprint<>? OR revoke_epoch<>?) ORDER BY COALESCE(revoked_at,expires_at) DESC, resource_id LIMIT -1 OFFSET ?)`, r.OwnerEnvHash, r.OwnerUserHash, r.PluginInstanceID, now.UnixNano(), fingerprint, actual.RevokeEpoch, SelectedResourceRetainedLimit-active-1)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO selected_file_resources(owner_env_hash,owner_user_hash,plugin_instance_id,resource_id,active_fingerprint,revoke_epoch,revision,expires_at,revoked_at,resource_json) VALUES(?,?,?,?,?,?,?,?,NULL,?)`, r.OwnerEnvHash, r.OwnerUserHash, r.PluginInstanceID, r.ResourceID, r.ActiveFingerprint, r.RevokeEpoch, r.Revision, r.ExpiresAt, string(r.RawJSON))
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return mutation.Unknown(err)
	}
	return nil
}

type selectedResourceReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readSelectedResource(ctx context.Context, q selectedResourceReader, key SelectedResourceKey) (SelectedResource, error) {
	if !key.valid() {
		return SelectedResource{}, ErrRecordNotFound
	}
	r := SelectedResource{OwnerEnvHash: key.OwnerEnvHash, OwnerUserHash: key.OwnerUserHash, PluginInstanceID: key.PluginInstanceID, ResourceID: key.ResourceID}
	var revoked sql.NullInt64
	var raw string
	err := q.QueryRowContext(ctx, `SELECT active_fingerprint,revoke_epoch,revision,expires_at,revoked_at,resource_json FROM selected_file_resources WHERE owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND resource_id=?`, key.OwnerEnvHash, key.OwnerUserHash, key.PluginInstanceID, key.ResourceID).Scan(&r.ActiveFingerprint, &r.RevokeEpoch, &r.Revision, &r.ExpiresAt, &revoked, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SelectedResource{}, ErrRecordNotFound
	}
	if err != nil {
		return SelectedResource{}, err
	}
	r.RevokedAt = nullIntPointer(revoked)
	r.RawJSON = json.RawMessage(raw)
	if !validSelectedResource(r) {
		return SelectedResource{}, ErrIncompatible
	}
	return r, nil
}

func validSelectedResource(r SelectedResource) bool {
	return r.Key().valid() && r.Revision > 0 && r.Revision <= math.MaxInt64 && r.RevokeEpoch <= math.MaxInt64 && r.ExpiresAt > 0 && (r.RevokedAt == nil || *r.RevokedAt > 0) && r.ActiveFingerprint != "" && len(r.RawJSON) <= 64<<10 && validRawJSON(r.RawJSON)
}

// WithSelectedResource holds the control authority transaction through a bounded
// file operation. Revocation, disable and version changes cannot commit between
// the authority check and that operation. The callback must not reenter Store.
func (s *Store) WithSelectedResource(ctx context.Context, key SelectedResourceKey, now time.Time, use func(SelectedResource) error) error {
	if err := viewReady(s); err != nil {
		return err
	}
	if now.IsZero() || use == nil {
		return ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	r, err := readSelectedResource(ctx, tx, key)
	if err != nil {
		return err
	}
	if r.RevokedAt != nil || r.ExpiresAt <= now.UnixNano() {
		return ErrStateConflict
	}
	var fingerprint, state string
	var epoch uint64
	err = tx.QueryRowContext(ctx, `SELECT active_fingerprint,state,revoke_epoch,management_revision FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=? AND deleted_at IS NULL`, key.OwnerEnvHash, key.PluginInstanceID).Scan(&fingerprint, &state, &epoch, &r.CurrentManagementRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRecordNotFound
	}
	if err != nil {
		return err
	}
	if fingerprint != r.ActiveFingerprint || epoch != r.RevokeEpoch || state != string(registry.EnableEnabled) {
		return ErrStateConflict
	}
	return use(r)
}

func (s *Store) RevokeSelectedResource(ctx context.Context, key SelectedResourceKey, expected uint64, now time.Time) error {
	if err := viewReady(s); err != nil {
		return err
	}
	if expected == 0 || expected >= math.MaxInt64 || now.IsZero() {
		return ErrRevisionConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	r, err := readSelectedResource(ctx, tx, key)
	if err != nil {
		return err
	}
	if r.RevokedAt != nil && r.Revision == expected+1 {
		return nil
	}
	if r.Revision != expected || r.RevokedAt != nil {
		return ErrRevisionConflict
	}
	_, err = tx.ExecContext(ctx, `UPDATE selected_file_resources SET revoked_at=?,revision=revision+1 WHERE owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND resource_id=? AND revision=? AND revoked_at IS NULL`, now.UnixNano(), key.OwnerEnvHash, key.OwnerUserHash, key.PluginInstanceID, key.ResourceID, expected)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return mutation.Unknown(err)
	}
	return nil
}

func (s *Store) ListSelectedResources(ctx context.Context, ownerEnvHash, ownerUserHash, pluginInstanceID string) ([]SelectedResource, error) {
	if err := viewReady(s); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT resource_id,active_fingerprint,revoke_epoch,revision,expires_at,revoked_at,resource_json FROM selected_file_resources WHERE owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? ORDER BY resource_id`, ownerEnvHash, ownerUserHash, pluginInstanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []SelectedResource{}
	for rows.Next() {
		r := SelectedResource{OwnerEnvHash: ownerEnvHash, OwnerUserHash: ownerUserHash, PluginInstanceID: pluginInstanceID}
		var revoked sql.NullInt64
		var raw string
		if err := rows.Scan(&r.ResourceID, &r.ActiveFingerprint, &r.RevokeEpoch, &r.Revision, &r.ExpiresAt, &revoked, &raw); err != nil {
			return nil, err
		}
		r.RevokedAt = nullIntPointer(revoked)
		r.RawJSON = json.RawMessage(raw)
		if !validSelectedResource(r) {
			return nil, ErrIncompatible
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func migrateSelectedResources(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	const statement = "CREATE TABLE selected_file_resources (owner_env_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, resource_id TEXT NOT NULL, active_fingerprint TEXT NOT NULL, revoke_epoch INTEGER NOT NULL, revision INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER, resource_json TEXT NOT NULL, PRIMARY KEY(owner_env_hash,owner_user_hash,plugin_instance_id,resource_id), FOREIGN KEY(owner_env_hash,plugin_instance_id) REFERENCES plugin_records(owner_env_hash,plugin_instance_id) ON DELETE CASCADE)"
	if _, err := q.ExecContext(ctx, statement); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, "UPDATE control_schema SET version=2 WHERE id=1 AND version=1")
	return err
}
