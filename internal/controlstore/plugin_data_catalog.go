package controlstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/plugindata"
	"github.com/floegence/redevplugin/v2/pkg/registry"
	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
)

var _ plugindata.Catalog = (*Store)(nil)

func (s *Store) GetBinding(ctx context.Context, pluginInstanceID string) (plugindata.Binding, bool, error) {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return plugindata.Binding{}, false, err
	}
	return getControlDataBinding(ctx, s.db, owner, strings.TrimSpace(pluginInstanceID))
}

func (s *Store) ListBindings(ctx context.Context, cursor string, limit int) ([]plugindata.Binding, string, error) {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return nil, "", err
	}
	return listControlDataBindings(ctx, s.db, owner, cursor, limit)
}

func (s *Store) ListAllBindingsForMaintenance(ctx context.Context, cursor string, limit int) ([]plugindata.MaintenanceBinding, string, error) {
	if err := s.pluginDataReady(); err != nil {
		return nil, "", err
	}
	limit = normalizePluginDataPageLimit(limit)
	parts := parsePluginDataCursor(cursor, 2)
	rows, err := s.db.QueryContext(ctx, `SELECT owner_env_hash,plugin_instance_id,generation_id,state,revision,shape_hash,retained_at,expires_at FROM plugin_data_bindings WHERE (owner_env_hash,plugin_instance_id) > (?,?) ORDER BY owner_env_hash,plugin_instance_id LIMIT ?`, parts[0], parts[1], limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	type entry struct {
		owner   string
		binding plugindata.Binding
	}
	entries := make([]entry, 0, limit+1)
	for rows.Next() {
		var item entry
		if err := scanControlDataBinding(rows, &item.binding, &item.owner); err != nil {
			return nil, "", err
		}
		entries = append(entries, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	more := len(entries) > limit
	if more {
		entries = entries[:limit]
	}
	result := make([]plugindata.MaintenanceBinding, 0, len(entries))
	for _, item := range entries {
		result = append(result, plugindata.MaintenanceBinding{Scope: sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: item.owner}, Binding: item.binding})
	}
	if more {
		last := entries[len(entries)-1]
		return result, pluginDataCursor(last.owner, last.binding.PluginInstanceID), nil
	}
	return result, "", nil
}

func (s *Store) CommitEnable(ctx context.Context, expectedManagementRevision uint64, expected *plugindata.Binding, next plugindata.Binding, shape plugindata.Shape, now time.Time) error {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return err
	}
	if err := validateControlDataBinding(next); err != nil || next.State != plugindata.BindingActive {
		return plugindata.ErrInvalidArgument
	}
	return s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		record, err := getControlPluginRecord(ctx, tx, owner, next.PluginInstanceID)
		if err != nil {
			return err
		}
		if err := validateControlRecordDataShape(record, next, shape); err != nil {
			return err
		}
		if record.ManagementRevision != expectedManagementRevision {
			return &registry.ManagementRevisionConflictError{PluginInstanceID: next.PluginInstanceID, Expected: expectedManagementRevision, Actual: record.ManagementRevision}
		}
		actual, found, err := getControlDataBinding(ctx, tx, owner, next.PluginInstanceID)
		if err != nil {
			return err
		}
		if expected == nil {
			if found || next.Revision != 1 {
				return plugindata.ErrBindingConflict
			}
			if err := insertControlDataBinding(ctx, tx, owner, next); err != nil {
				return err
			}
		} else {
			if !found || !sameControlDataBinding(actual, *expected) || !validControlEnableTransition(*expected, next) {
				return plugindata.ErrBindingConflict
			}
			if !sameControlDataBinding(actual, next) {
				if err := updateControlDataBinding(ctx, tx, owner, next); err != nil {
					return err
				}
			}
		}
		record = registry.PrepareEnableState(record, registry.EnableEnabled, "", now)
		return persistControlPluginRecord(ctx, tx, record)
	})
}

func (s *Store) SwapImport(ctx context.Context, expectedManagementRevision uint64, expected *plugindata.Binding, next plugindata.Binding, shape plugindata.Shape, now time.Time) error {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return err
	}
	if err := validateControlDataBinding(next); err != nil || next.State != plugindata.BindingActive {
		return plugindata.ErrInvalidArgument
	}
	return s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		record, err := getControlPluginRecord(ctx, tx, owner, next.PluginInstanceID)
		if err != nil {
			return err
		}
		if err := validateControlRecordDataShape(record, next, shape); err != nil {
			return err
		}
		if record.ManagementRevision != expectedManagementRevision {
			return &registry.ManagementRevisionConflictError{PluginInstanceID: next.PluginInstanceID, Expected: expectedManagementRevision, Actual: record.ManagementRevision}
		}
		if record.EnableState == registry.EnableEnabled {
			return plugindata.ErrBindingConflict
		}
		actual, found, err := getControlDataBinding(ctx, tx, owner, next.PluginInstanceID)
		if err != nil {
			return err
		}
		if expected == nil {
			if found || next.Revision != 1 {
				return plugindata.ErrBindingConflict
			}
			if err := insertControlDataBinding(ctx, tx, owner, next); err != nil {
				return err
			}
		} else {
			if !found || !sameControlDataBinding(actual, *expected) || next.Revision != expected.Revision+1 {
				return plugindata.ErrBindingConflict
			}
			if err := updateControlDataBinding(ctx, tx, owner, next); err != nil {
				return err
			}
		}
		if now.IsZero() {
			now = time.Now().UTC()
		}
		record.ManagementRevision++
		record.RevokeEpoch++
		record.UpdatedAt = now
		return persistControlPluginRecord(ctx, tx, record)
	})
}

func (s *Store) BindRetained(ctx context.Context, expected plugindata.Binding, targetPluginInstanceID string, targetExpectedManagementRevision uint64, targetShape plugindata.Shape, now time.Time) (plugindata.Binding, error) {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return plugindata.Binding{}, err
	}
	var active plugindata.Binding
	err = s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		actual, found, err := getControlDataBinding(ctx, tx, owner, expected.PluginInstanceID)
		if err != nil {
			return err
		}
		targetHash, err := plugindata.HashShape(targetShape)
		if err != nil {
			return err
		}
		if !found || !sameControlDataBinding(actual, expected) || actual.State != plugindata.BindingRetained || actual.ShapeHash != targetHash {
			return plugindata.ErrBindingConflict
		}
		targetPluginInstanceID = strings.TrimSpace(targetPluginInstanceID)
		if targetPluginInstanceID == "" || targetPluginInstanceID == expected.PluginInstanceID {
			return plugindata.ErrInvalidArgument
		}
		target, err := getControlPluginRecord(ctx, tx, owner, targetPluginInstanceID)
		if err != nil {
			return err
		}
		probe := expected
		probe.PluginInstanceID = targetPluginInstanceID
		if err := validateControlRecordDataShape(target, probe, targetShape); err != nil {
			return err
		}
		if target.ManagementRevision != targetExpectedManagementRevision {
			return &registry.ManagementRevisionConflictError{PluginInstanceID: targetPluginInstanceID, Expected: targetExpectedManagementRevision, Actual: target.ManagementRevision}
		}
		if target.EnableState == registry.EnableEnabled {
			return plugindata.ErrBindingConflict
		}
		if _, found, err := getControlDataBinding(ctx, tx, owner, targetPluginInstanceID); err != nil {
			return err
		} else if found {
			return plugindata.ErrBindingConflict
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, expected.PluginInstanceID); err != nil {
			return err
		}
		actual.PluginInstanceID = targetPluginInstanceID
		actual.State = plugindata.BindingActive
		actual.Revision++
		actual.RetainedAt = nil
		actual.ExpiresAt = nil
		active = actual
		if err := insertControlDataBinding(ctx, tx, owner, active); err != nil {
			return err
		}
		if now.IsZero() {
			now = time.Now().UTC()
		}
		target.ManagementRevision++
		target.RevokeEpoch++
		target.UpdatedAt = now
		return persistControlPluginRecord(ctx, tx, target)
	})
	return active, err
}

func (s *Store) DeleteRetained(ctx context.Context, expected plugindata.Binding) error {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return err
	}
	return s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		actual, found, err := getControlDataBinding(ctx, tx, owner, expected.PluginInstanceID)
		if err != nil {
			return err
		}
		if !found || !sameControlDataBinding(actual, expected) || actual.State != plugindata.BindingRetained {
			return plugindata.ErrBindingConflict
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, expected.PluginInstanceID)
		return err
	})
}

func (s *Store) CleanupExpired(ctx context.Context, now time.Time, expected []plugindata.Binding) ([]plugindata.Binding, error) {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	deleted := make([]plugindata.Binding, 0, len(expected))
	err = s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		for _, binding := range expected {
			actual, found, err := getControlDataBinding(ctx, tx, owner, binding.PluginInstanceID)
			if err != nil {
				return err
			}
			if !found || !sameControlDataBinding(actual, binding) || actual.State != plugindata.BindingRetained || actual.ExpiresAt == nil || actual.ExpiresAt.After(now) {
				return plugindata.ErrBindingConflict
			}
		}
		for _, binding := range expected {
			if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, binding.PluginInstanceID); err != nil {
				return err
			}
			deleted = append(deleted, cloneControlDataBinding(binding))
		}
		return nil
	})
	return deleted, err
}

func (s *Store) CommitUninstall(ctx context.Context, req plugindata.CommitUninstallRequest) (plugindata.CommitUninstallResult, error) {
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return plugindata.CommitUninstallResult{}, err
	}
	var result plugindata.CommitUninstallResult
	err = s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		record, err := getControlPluginRecord(ctx, tx, owner, req.PluginInstanceID)
		if err != nil {
			return err
		}
		if req.ExpectedManagementRevision == 0 || record.ManagementRevision != req.ExpectedManagementRevision {
			return &registry.ManagementRevisionConflictError{PluginInstanceID: req.PluginInstanceID, Expected: req.ExpectedManagementRevision, Actual: record.ManagementRevision}
		}
		now := req.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		record.EnableState = registry.EnableDisabled
		record.DisabledReason = "uninstalled"
		record.ManagementRevision++
		record.RevokeEpoch++
		record.UpdatedAt = now
		record.DeletedAt = &now
		record.EnabledAt = nil
		if err := persistControlPluginRecord(ctx, tx, record); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM permission_grants WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, req.PluginInstanceID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM security_policies WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, req.PluginInstanceID); err != nil {
			return err
		}
		if req.DeleteData {
			if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, req.PluginInstanceID); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE plugin_data_bindings SET state=?,revision=revision+1,retained_at=?,expires_at=? WHERE owner_env_hash=? AND plugin_instance_id=?`, string(plugindata.BindingRetained), now.UnixNano(), nullableControlTime(req.RetainUntil), owner, req.PluginInstanceID); err != nil {
			return err
		}
		result = plugindata.CommitUninstallResult{ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, DeletedAt: now}
		return nil
	})
	return result, err
}

func (s *Store) GetObject(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, objectID string) (plugindata.Object, bool, error) {
	owner, err := pluginDataResourceOwner(ctx, scope)
	if err != nil {
		return plugindata.Object{}, false, err
	}
	pluginInstanceID, objectID, err = validateControlDataObjectIdentity(pluginInstanceID, objectID)
	if err != nil {
		return plugindata.Object{}, false, err
	}
	return getControlDataObject(ctx, s.db, owner, pluginInstanceID, objectID)
}

func (s *Store) ListObjects(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, cursor string, limit int) ([]plugindata.Object, string, error) {
	owner, err := pluginDataResourceOwner(ctx, scope)
	if err != nil {
		return nil, "", err
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return nil, "", plugindata.ErrInvalidArgument
	}
	limit = normalizePluginDataPageLimit(limit)
	rows, err := s.db.QueryContext(ctx, `SELECT plugin_instance_id,object_id,content_hash,shape_hash,size_bytes,created_at FROM plugin_data_objects WHERE scope_kind=? AND owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND object_id>? ORDER BY object_id LIMIT ?`, string(owner.Kind), owner.OwnerEnvHash, owner.OwnerUserHash, pluginInstanceID, cursor, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	objects := make([]plugindata.Object, 0, limit+1)
	for rows.Next() {
		var object plugindata.Object
		var createdAt int64
		if err := rows.Scan(&object.PluginInstanceID, &object.ObjectID, &object.ContentHash, &object.ShapeHash, &object.SizeBytes, &createdAt); err != nil {
			return nil, "", err
		}
		object.CreatedAt = time.Unix(0, createdAt).UTC()
		objects = append(objects, object)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(objects) > limit {
		objects = objects[:limit]
		return objects, objects[len(objects)-1].ObjectID, nil
	}
	return objects, "", nil
}

func (s *Store) ListAllObjectsForMaintenance(ctx context.Context, cursor string, limit int) ([]plugindata.MaintenanceObject, string, error) {
	if err := s.pluginDataReady(); err != nil {
		return nil, "", err
	}
	limit = normalizePluginDataPageLimit(limit)
	parts := parsePluginDataCursor(cursor, 5)
	rows, err := s.db.QueryContext(ctx, `SELECT scope_kind,owner_env_hash,owner_user_hash,plugin_instance_id,object_id,content_hash,shape_hash,size_bytes,created_at FROM plugin_data_objects WHERE (scope_kind,owner_env_hash,owner_user_hash,plugin_instance_id,object_id) > (?,?,?,?,?) ORDER BY scope_kind,owner_env_hash,owner_user_hash,plugin_instance_id,object_id LIMIT ?`, parts[0], parts[1], parts[2], parts[3], parts[4], limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := make([]plugindata.MaintenanceObject, 0, limit+1)
	for rows.Next() {
		var item plugindata.MaintenanceObject
		var kind string
		var createdAt int64
		if err := rows.Scan(&kind, &item.Scope.OwnerEnvHash, &item.Scope.OwnerUserHash, &item.Object.PluginInstanceID, &item.Object.ObjectID, &item.Object.ContentHash, &item.Object.ShapeHash, &item.Object.SizeBytes, &createdAt); err != nil {
			return nil, "", err
		}
		item.Scope.Kind = sessionctx.ScopeKind(kind)
		item.Object.CreatedAt = time.Unix(0, createdAt).UTC()
		if err := item.Scope.Validate(); err != nil {
			return nil, "", err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(result) > limit {
		result = result[:limit]
		last := result[len(result)-1]
		return result, pluginDataCursor(string(last.Scope.Kind), last.Scope.OwnerEnvHash, last.Scope.OwnerUserHash, last.Object.PluginInstanceID, last.Object.ObjectID), nil
	}
	return result, "", nil
}

func (s *Store) CreateObject(ctx context.Context, scope sessionctx.ScopeKind, object plugindata.Object) error {
	owner, err := pluginDataResourceOwner(ctx, scope)
	if err != nil {
		return err
	}
	if err := validateControlDataObject(object); err != nil {
		return err
	}
	return s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		if _, found, err := getControlDataObject(ctx, tx, owner, object.PluginInstanceID, object.ObjectID); err != nil {
			return err
		} else if found {
			return plugindata.ErrBindingConflict
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO plugin_data_objects(scope_kind,owner_env_hash,owner_user_hash,plugin_instance_id,object_id,content_hash,shape_hash,size_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, string(owner.Kind), owner.OwnerEnvHash, owner.OwnerUserHash, object.PluginInstanceID, object.ObjectID, object.ContentHash, object.ShapeHash, object.SizeBytes, object.CreatedAt.UnixNano())
		return err
	})
}

func (s *Store) DeleteObject(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, objectID string) error {
	owner, err := pluginDataResourceOwner(ctx, scope)
	if err != nil {
		return err
	}
	pluginInstanceID, objectID, err = validateControlDataObjectIdentity(pluginInstanceID, objectID)
	if err != nil {
		return err
	}
	return s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_objects WHERE scope_kind=? AND owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND object_id=?`, string(owner.Kind), owner.OwnerEnvHash, owner.OwnerUserHash, pluginInstanceID, objectID)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed == 0 {
			return plugindata.ErrExportNotFound
		}
		return nil
	})
}

func (s *Store) pluginDataMutation(ctx context.Context, mutate func(*sql.Tx) error) error {
	if err := s.pluginDataReady(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := mutate(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) pluginDataReady() error {
	if s == nil || !s.Ready() {
		return ErrRequestsBlocked
	}
	return nil
}

func pluginDataEnvironmentOwner(ctx context.Context) (string, error) {
	scope, err := pluginDataResourceOwner(ctx, sessionctx.ScopeEnvironment)
	return scope.OwnerEnvHash, err
}

func pluginDataResourceOwner(ctx context.Context, kind sessionctx.ScopeKind) (sessionctx.ResourceScope, error) {
	session, err := sessionctx.Require(ctx)
	if err != nil {
		return sessionctx.ResourceScope{}, err
	}
	return session.ResourceScope(kind)
}

type controlDataQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getControlPluginRecord(ctx context.Context, q controlDataQuerier, owner, pluginInstanceID string) (registry.PluginRecord, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT record_json FROM plugin_records WHERE owner_env_hash=? AND plugin_instance_id=? AND deleted_at IS NULL`, owner, pluginInstanceID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	if err != nil {
		return registry.PluginRecord{}, err
	}
	record, err := decodeRegistryPluginRecord([]byte(raw))
	if err != nil {
		return registry.PluginRecord{}, err
	}
	record.OwnerEnvHash = owner
	return record, nil
}

func persistControlPluginRecord(ctx context.Context, tx *sql.Tx, record registry.PluginRecord) error {
	raw, err := encodeRegistryPluginRecord(record)
	if err != nil {
		return err
	}
	return upsertControlPlugin(ctx, tx, controlPluginRecord(record, raw))
}

func getControlDataBinding(ctx context.Context, q controlDataQuerier, owner, pluginInstanceID string) (plugindata.Binding, bool, error) {
	var binding plugindata.Binding
	var state string
	var retainedAt, expiresAt sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT plugin_instance_id,generation_id,state,revision,shape_hash,retained_at,expires_at FROM plugin_data_bindings WHERE owner_env_hash=? AND plugin_instance_id=?`, owner, pluginInstanceID).Scan(&binding.PluginInstanceID, &binding.GenerationID, &state, &binding.Revision, &binding.ShapeHash, &retainedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return plugindata.Binding{}, false, nil
	}
	if err != nil {
		return plugindata.Binding{}, false, err
	}
	binding.State = plugindata.BindingState(state)
	binding.RetainedAt = nullableControlTimePtr(retainedAt)
	binding.ExpiresAt = nullableControlTimePtr(expiresAt)
	return binding, true, validateControlDataBinding(binding)
}

func listControlDataBindings(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, owner, cursor string, limit int) ([]plugindata.Binding, string, error) {
	limit = normalizePluginDataPageLimit(limit)
	rows, err := q.QueryContext(ctx, `SELECT plugin_instance_id,generation_id,state,revision,shape_hash,retained_at,expires_at FROM plugin_data_bindings WHERE owner_env_hash=? AND plugin_instance_id>? ORDER BY plugin_instance_id LIMIT ?`, owner, cursor, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	bindings := make([]plugindata.Binding, 0, limit+1)
	for rows.Next() {
		var binding plugindata.Binding
		if err := scanControlDataBinding(rows, &binding, nil); err != nil {
			return nil, "", err
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(bindings) > limit {
		bindings = bindings[:limit]
		return bindings, bindings[len(bindings)-1].PluginInstanceID, nil
	}
	return bindings, "", nil
}

func scanControlDataBinding(scanner interface{ Scan(...any) error }, binding *plugindata.Binding, owner *string) error {
	var state string
	var retainedAt, expiresAt sql.NullInt64
	targets := []any{&binding.PluginInstanceID, &binding.GenerationID, &state, &binding.Revision, &binding.ShapeHash, &retainedAt, &expiresAt}
	if owner != nil {
		targets = append([]any{owner}, targets...)
	}
	if err := scanner.Scan(targets...); err != nil {
		return err
	}
	binding.State = plugindata.BindingState(state)
	binding.RetainedAt = nullableControlTimePtr(retainedAt)
	binding.ExpiresAt = nullableControlTimePtr(expiresAt)
	return validateControlDataBinding(*binding)
}

func insertControlDataBinding(ctx context.Context, tx *sql.Tx, owner string, binding plugindata.Binding) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO plugin_data_bindings(owner_env_hash,plugin_instance_id,generation_id,state,revision,shape_hash,retained_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`, owner, binding.PluginInstanceID, binding.GenerationID, string(binding.State), binding.Revision, binding.ShapeHash, nullableControlTime(binding.RetainedAt), nullableControlTime(binding.ExpiresAt))
	return err
}

func updateControlDataBinding(ctx context.Context, tx *sql.Tx, owner string, binding plugindata.Binding) error {
	result, err := tx.ExecContext(ctx, `UPDATE plugin_data_bindings SET generation_id=?,state=?,revision=?,shape_hash=?,retained_at=?,expires_at=? WHERE owner_env_hash=? AND plugin_instance_id=?`, binding.GenerationID, string(binding.State), binding.Revision, binding.ShapeHash, nullableControlTime(binding.RetainedAt), nullableControlTime(binding.ExpiresAt), owner, binding.PluginInstanceID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return plugindata.ErrBindingConflict
	}
	return nil
}

func getControlDataObject(ctx context.Context, q controlDataQuerier, owner sessionctx.ResourceScope, pluginInstanceID, objectID string) (plugindata.Object, bool, error) {
	var object plugindata.Object
	var createdAt int64
	err := q.QueryRowContext(ctx, `SELECT plugin_instance_id,object_id,content_hash,shape_hash,size_bytes,created_at FROM plugin_data_objects WHERE scope_kind=? AND owner_env_hash=? AND owner_user_hash=? AND plugin_instance_id=? AND object_id=?`, string(owner.Kind), owner.OwnerEnvHash, owner.OwnerUserHash, pluginInstanceID, objectID).Scan(&object.PluginInstanceID, &object.ObjectID, &object.ContentHash, &object.ShapeHash, &object.SizeBytes, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return plugindata.Object{}, false, nil
	}
	if err != nil {
		return plugindata.Object{}, false, err
	}
	object.CreatedAt = time.Unix(0, createdAt).UTC()
	return object, true, validateControlDataObject(object)
}

func validateControlDataBinding(binding plugindata.Binding) error {
	if strings.TrimSpace(binding.PluginInstanceID) == "" || strings.TrimSpace(binding.GenerationID) == "" || strings.TrimSpace(binding.ShapeHash) == "" || binding.Revision == 0 {
		return plugindata.ErrInvalidArgument
	}
	switch binding.State {
	case plugindata.BindingActive:
		if binding.RetainedAt != nil || binding.ExpiresAt != nil {
			return plugindata.ErrInvalidArgument
		}
	case plugindata.BindingRetained:
		if binding.RetainedAt == nil || binding.ExpiresAt != nil && !binding.ExpiresAt.After(*binding.RetainedAt) {
			return plugindata.ErrInvalidArgument
		}
	default:
		return plugindata.ErrInvalidArgument
	}
	return nil
}

func validateControlDataObject(object plugindata.Object) error {
	if strings.TrimSpace(object.PluginInstanceID) == "" || strings.TrimSpace(object.ObjectID) == "" || !validControlDataHash(object.ContentHash) || !validControlDataHash(object.ShapeHash) || object.SizeBytes <= 0 || object.CreatedAt.IsZero() {
		return plugindata.ErrInvalidArgument
	}
	return nil
}

func validateControlDataObjectIdentity(pluginInstanceID, objectID string) (string, string, error) {
	pluginInstanceID, objectID = strings.TrimSpace(pluginInstanceID), strings.TrimSpace(objectID)
	if pluginInstanceID == "" || objectID == "" {
		return "", "", plugindata.ErrInvalidArgument
	}
	return pluginInstanceID, objectID, nil
}

func validControlDataHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func validateControlRecordDataShape(record registry.PluginRecord, binding plugindata.Binding, shape plugindata.Shape) error {
	hash, err := plugindata.HashShape(shape)
	if err != nil {
		return err
	}
	declared, err := plugindata.ShapeFromManifest(record.Manifest)
	if err != nil {
		return err
	}
	declaredHash, err := plugindata.HashShape(declared)
	if err != nil {
		return err
	}
	if record.PublisherID != shape.PublisherID || record.PluginID != shape.PluginID || hash != declaredHash || binding.ShapeHash != declaredHash {
		return plugindata.ErrShapeMismatch
	}
	return nil
}

func validControlEnableTransition(expected, next plugindata.Binding) bool {
	if expected.State == plugindata.BindingActive {
		return sameControlDataBinding(expected, next)
	}
	if expected.State != plugindata.BindingRetained {
		return false
	}
	reactivated := expected
	reactivated.State = plugindata.BindingActive
	reactivated.Revision++
	reactivated.RetainedAt = nil
	reactivated.ExpiresAt = nil
	return sameControlDataBinding(reactivated, next)
}

func sameControlDataBinding(left, right plugindata.Binding) bool {
	return left.PluginInstanceID == right.PluginInstanceID && left.GenerationID == right.GenerationID && left.State == right.State && left.Revision == right.Revision && left.ShapeHash == right.ShapeHash && equalControlTimes(left.RetainedAt, right.RetainedAt) && equalControlTimes(left.ExpiresAt, right.ExpiresAt)
}

func equalControlTimes(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func cloneControlDataBinding(binding plugindata.Binding) plugindata.Binding {
	if binding.RetainedAt != nil {
		value := *binding.RetainedAt
		binding.RetainedAt = &value
	}
	if binding.ExpiresAt != nil {
		value := *binding.ExpiresAt
		binding.ExpiresAt = &value
	}
	return binding
}

func nullableControlTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UnixNano()
}

func nullableControlTimePtr(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	result := time.Unix(0, value.Int64).UTC()
	return &result
}

func normalizePluginDataPageLimit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 256
	}
	return limit
}

func pluginDataCursor(parts ...string) string { return strings.Join(parts, "\x00") }

func parsePluginDataCursor(cursor string, count int) []string {
	if cursor == "" {
		return make([]string, count)
	}
	parts := strings.Split(cursor, "\x00")
	if len(parts) != count {
		return make([]string, count)
	}
	return parts
}

func importRegistryPluginData(ctx context.Context, tx *sql.Tx, legacy *sql.DB) error {
	tables := []struct {
		name  string
		query string
		copy  func(*sql.Rows) error
	}{
		{name: "plugin_data_bindings", query: `SELECT owner_env_hash,plugin_instance_id,generation_id,state,revision,shape_hash,retained_at,expires_at FROM plugin_data_bindings`, copy: func(rows *sql.Rows) error {
			for rows.Next() {
				var owner, plugin, generation, state, shape string
				var revision uint64
				var retainedAt, expiresAt sql.NullInt64
				if err := rows.Scan(&owner, &plugin, &generation, &state, &revision, &shape, &retainedAt, &expiresAt); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_data_bindings(owner_env_hash,plugin_instance_id,generation_id,state,revision,shape_hash,retained_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`, owner, plugin, generation, state, revision, shape, nullableSQLInt(retainedAt), nullableSQLInt(expiresAt)); err != nil {
					return err
				}
			}
			return rows.Err()
		}},
		{name: "plugin_data_objects", query: `SELECT scope_kind,owner_env_hash,owner_user_hash,plugin_instance_id,object_id,content_hash,shape_hash,size_bytes,created_at FROM plugin_data_objects`, copy: func(rows *sql.Rows) error {
			for rows.Next() {
				var values [7]string
				var sizeBytes, createdAt int64
				if err := rows.Scan(&values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &sizeBytes, &createdAt); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_data_objects(scope_kind,owner_env_hash,owner_user_hash,plugin_instance_id,object_id,content_hash,shape_hash,size_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, values[0], values[1], values[2], values[3], values[4], values[5], values[6], sizeBytes, createdAt); err != nil {
					return err
				}
			}
			return rows.Err()
		}},
	}
	for _, table := range tables {
		var exists int
		if err := legacy.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table.name).Scan(&exists); err != nil {
			return fmt.Errorf("%w: inspect registry %s: %v", ErrMigration, table.name, err)
		}
		if exists == 0 {
			continue
		}
		rows, err := legacy.QueryContext(ctx, table.query)
		if err != nil {
			return fmt.Errorf("%w: read registry %s: %v", ErrMigration, table.name, err)
		}
		err = table.copy(rows)
		rows.Close()
		if err != nil {
			return fmt.Errorf("%w: import registry %s: %v", ErrMigration, table.name, err)
		}
	}
	return nil
}

func nullableSQLInt(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}
