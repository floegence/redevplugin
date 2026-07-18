package registry

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

var ErrManagementRevisionConflict = errors.New("management revision conflict")

type ManagementRevisionConflictError struct {
	PluginInstanceID string
	Expected         uint64
	Actual           uint64
}

func (e *ManagementRevisionConflictError) Error() string {
	return fmt.Sprintf("%s for plugin %q: expected %d, actual %d", ErrManagementRevisionConflict, e.PluginInstanceID, e.Expected, e.Actual)
}

func (e *ManagementRevisionConflictError) Unwrap() error { return ErrManagementRevisionConflict }

func (s *MemoryStore) GetBinding(ctx context.Context, pluginInstanceID string) (plugindata.Binding, bool, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return plugindata.Binding{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, ok := s.dataBindings[environmentRecordKey(ownerEnvHash, pluginInstanceID)]
	return cloneDataBinding(binding), ok, nil
}

func (s *MemoryStore) ListBindings(ctx context.Context, cursor string, limit int) ([]plugindata.Binding, string, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, "", err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	bindings := sortedDataBindings(s.dataBindings, ownerEnvHash)
	start := sort.Search(len(bindings), func(i int) bool { return bindings[i].PluginInstanceID > cursor })
	bindings = bindings[start:]
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	if len(bindings) > limit {
		return bindings[:limit], bindings[limit-1].PluginInstanceID, nil
	}
	return bindings, "", nil
}

func (s *MemoryStore) ListAllBindingsForMaintenance(_ context.Context, cursor string, limit int) ([]plugindata.MaintenanceBinding, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.dataBindings))
	for key := range s.dataBindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	start := sort.SearchStrings(keys, cursor)
	for start < len(keys) && keys[start] <= cursor {
		start++
	}
	keys = keys[start:]
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	more := len(keys) > limit
	if more {
		keys = keys[:limit]
	}
	bindings := make([]plugindata.MaintenanceBinding, 0, len(keys))
	for _, key := range keys {
		ownerEnvHash, _, ok := strings.Cut(key, "\x00")
		if !ok {
			return nil, "", ErrOwnerScopeMismatch
		}
		bindings = append(bindings, plugindata.MaintenanceBinding{
			Scope:   sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: ownerEnvHash},
			Binding: cloneDataBinding(s.dataBindings[key]),
		})
	}
	if more {
		return bindings, keys[len(keys)-1], nil
	}
	return bindings, "", nil
}

func (s *MemoryStore) CommitEnable(ctx context.Context, expectedManagementRevision uint64, expected *plugindata.Binding, next plugindata.Binding, shape plugindata.Shape, now time.Time) error {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return err
	}
	if err := validateDataBinding(next); err != nil || next.State != plugindata.BindingActive {
		return plugindata.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := environmentRecordKey(ownerEnvHash, next.PluginInstanceID)
	record, ok := s.records[key]
	if !ok || record.DeletedAt != nil {
		return ErrNotFound
	}
	if err := validateRecordDataShape(record, next, shape); err != nil {
		return err
	}
	if record.ManagementRevision != expectedManagementRevision {
		return &ManagementRevisionConflictError{PluginInstanceID: next.PluginInstanceID, Expected: expectedManagementRevision, Actual: record.ManagementRevision}
	}
	actual, exists := s.dataBindings[key]
	if expected == nil {
		if exists || next.Revision != 1 {
			return plugindata.ErrBindingConflict
		}
	} else if !exists || !sameDataBinding(actual, *expected) || !sameDataBinding(next, *expected) {
		return plugindata.ErrBindingConflict
	}
	s.dataBindings[key] = cloneDataBinding(next)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.EnableState = EnableEnabled
	record.DisabledReason = ""
	record.ManagementRevision++
	record.RevokeEpoch++
	record.EnabledAt = &now
	record.UpdatedAt = now
	s.records[key] = record
	return nil
}

func (s *MemoryStore) SwapImport(ctx context.Context, expectedManagementRevision uint64, expected *plugindata.Binding, next plugindata.Binding, shape plugindata.Shape, now time.Time) error {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return err
	}
	if err := validateDataBinding(next); err != nil || next.State != plugindata.BindingActive {
		return plugindata.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := environmentRecordKey(ownerEnvHash, next.PluginInstanceID)
	record, ok := s.records[key]
	if !ok || record.DeletedAt != nil {
		return ErrNotFound
	}
	if err := validateRecordDataShape(record, next, shape); err != nil {
		return err
	}
	if record.ManagementRevision != expectedManagementRevision {
		return &ManagementRevisionConflictError{PluginInstanceID: next.PluginInstanceID, Expected: expectedManagementRevision, Actual: record.ManagementRevision}
	}
	if record.EnableState == EnableEnabled {
		return plugindata.ErrBindingConflict
	}
	actual, exists := s.dataBindings[key]
	if expected == nil {
		if exists || next.Revision != 1 {
			return plugindata.ErrBindingConflict
		}
	} else if !exists || !sameDataBinding(actual, *expected) || next.Revision != expected.Revision+1 {
		return plugindata.ErrBindingConflict
	}
	s.dataBindings[key] = cloneDataBinding(next)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.ManagementRevision++
	record.RevokeEpoch++
	record.UpdatedAt = now
	s.records[key] = record
	return nil
}

func (s *MemoryStore) BindRetained(ctx context.Context, expected plugindata.Binding, targetPluginInstanceID string, targetExpectedManagementRevision uint64, targetShape plugindata.Shape, now time.Time) (plugindata.Binding, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return plugindata.Binding{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	targetShapeHash, err := plugindata.HashShape(targetShape)
	if err != nil {
		return plugindata.Binding{}, err
	}
	sourceKey := environmentRecordKey(ownerEnvHash, expected.PluginInstanceID)
	actual, exists := s.dataBindings[sourceKey]
	if !exists || !sameDataBinding(actual, expected) || actual.State != plugindata.BindingRetained || actual.ShapeHash != targetShapeHash {
		return plugindata.Binding{}, plugindata.ErrBindingConflict
	}
	targetPluginInstanceID = strings.TrimSpace(targetPluginInstanceID)
	if targetPluginInstanceID == expected.PluginInstanceID {
		return plugindata.Binding{}, plugindata.ErrInvalidArgument
	}
	targetKey := environmentRecordKey(ownerEnvHash, targetPluginInstanceID)
	target, ok := s.records[targetKey]
	if !ok || target.DeletedAt != nil {
		return plugindata.Binding{}, ErrNotFound
	}
	declaredShape, err := plugindata.ShapeFromManifest(target.Manifest)
	if err != nil {
		return plugindata.Binding{}, err
	}
	declaredShapeHash, err := plugindata.HashShape(declaredShape)
	if err != nil {
		return plugindata.Binding{}, err
	}
	if target.PublisherID != targetShape.PublisherID || target.PluginID != targetShape.PluginID || targetShapeHash != declaredShapeHash {
		return plugindata.Binding{}, plugindata.ErrShapeMismatch
	}
	if target.ManagementRevision != targetExpectedManagementRevision {
		return plugindata.Binding{}, &ManagementRevisionConflictError{PluginInstanceID: targetPluginInstanceID, Expected: targetExpectedManagementRevision, Actual: target.ManagementRevision}
	}
	if target.EnableState == EnableEnabled {
		return plugindata.Binding{}, plugindata.ErrBindingConflict
	}
	if targetPluginInstanceID != expected.PluginInstanceID {
		if _, exists := s.dataBindings[targetKey]; exists {
			return plugindata.Binding{}, plugindata.ErrBindingConflict
		}
		delete(s.dataBindings, sourceKey)
	}
	actual.PluginInstanceID = targetPluginInstanceID
	actual.State = plugindata.BindingActive
	actual.Revision++
	actual.RetainedAt = nil
	actual.ExpiresAt = nil
	s.dataBindings[targetKey] = actual
	if now.IsZero() {
		now = time.Now().UTC()
	}
	target.ManagementRevision++
	target.RevokeEpoch++
	target.UpdatedAt = now
	s.records[targetKey] = target
	return cloneDataBinding(actual), nil
}

func (s *MemoryStore) DeleteRetained(ctx context.Context, expected plugindata.Binding) error {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := environmentRecordKey(ownerEnvHash, expected.PluginInstanceID)
	actual, exists := s.dataBindings[key]
	if !exists || !sameDataBinding(actual, expected) || actual.State != plugindata.BindingRetained {
		return plugindata.ErrBindingConflict
	}
	delete(s.dataBindings, key)
	return nil
}

func (s *MemoryStore) CleanupExpired(ctx context.Context, now time.Time, expected []plugindata.Binding) ([]plugindata.Binding, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, binding := range expected {
		actual, exists := s.dataBindings[environmentRecordKey(ownerEnvHash, binding.PluginInstanceID)]
		if !exists || !sameDataBinding(actual, binding) || actual.State != plugindata.BindingRetained || actual.ExpiresAt == nil || actual.ExpiresAt.After(now) {
			return nil, plugindata.ErrBindingConflict
		}
	}
	deleted := make([]plugindata.Binding, 0, len(expected))
	for _, binding := range expected {
		delete(s.dataBindings, environmentRecordKey(ownerEnvHash, binding.PluginInstanceID))
		deleted = append(deleted, cloneDataBinding(binding))
	}
	return deleted, nil
}

func (s *MemoryStore) GetObject(ctx context.Context, objectID string) (plugindata.Object, bool, error) {
	owner, err := userOwner(ctx)
	if err != nil {
		return plugindata.Object{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	object, ok := s.dataObjects[scopedObjectKey(owner, objectID)]
	return object, ok, nil
}

func (s *MemoryStore) ListObjects(ctx context.Context, cursor string, limit int) ([]plugindata.Object, string, error) {
	owner, err := userOwner(ctx)
	if err != nil {
		return nil, "", err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	objects := make([]plugindata.Object, 0, len(s.dataObjects))
	prefix := scopedObjectKey(owner, "")
	for key, object := range s.dataObjects {
		if strings.HasPrefix(key, prefix) {
			objects = append(objects, object)
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ObjectID < objects[j].ObjectID })
	start := sort.Search(len(objects), func(i int) bool { return objects[i].ObjectID > cursor })
	objects = objects[start:]
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	if len(objects) > limit {
		return objects[:limit], objects[limit-1].ObjectID, nil
	}
	return objects, "", nil
}

func (s *MemoryStore) ListAllObjectsForMaintenance(_ context.Context, cursor string, limit int) ([]plugindata.MaintenanceObject, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.dataObjects))
	for key := range s.dataObjects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	start := sort.SearchStrings(keys, cursor)
	for start < len(keys) && keys[start] <= cursor {
		start++
	}
	keys = keys[start:]
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	more := len(keys) > limit
	if more {
		keys = keys[:limit]
	}
	objects := make([]plugindata.MaintenanceObject, 0, len(keys))
	for _, key := range keys {
		parts := strings.Split(key, "\x00")
		if len(parts) != 4 || sessionctx.ScopeKind(parts[0]) != sessionctx.ScopeUser {
			return nil, "", ErrOwnerScopeMismatch
		}
		objects = append(objects, plugindata.MaintenanceObject{
			Scope: sessionctx.ResourceScope{
				Kind:          sessionctx.ScopeUser,
				OwnerEnvHash:  parts[1],
				OwnerUserHash: parts[2],
			},
			Object: s.dataObjects[key],
		})
	}
	if more {
		return objects, keys[len(keys)-1], nil
	}
	return objects, "", nil
}

func (s *MemoryStore) CreateObject(ctx context.Context, object plugindata.Object) error {
	owner, err := userOwner(ctx)
	if err != nil {
		return err
	}
	if err := validateDataObject(object); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopedObjectKey(owner, object.ObjectID)
	if _, exists := s.dataObjects[key]; exists {
		return plugindata.ErrBindingConflict
	}
	s.dataObjects[key] = object
	return nil
}

func (s *MemoryStore) DeleteObject(ctx context.Context, objectID string) error {
	owner, err := userOwner(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	objectID = strings.TrimSpace(objectID)
	key := scopedObjectKey(owner, objectID)
	if _, exists := s.dataObjects[key]; !exists {
		return plugindata.ErrExportNotFound
	}
	delete(s.dataObjects, key)
	return nil
}

func (s *SQLiteStore) GetBinding(ctx context.Context, pluginInstanceID string) (plugindata.Binding, bool, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return plugindata.Binding{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return getSQLiteDataBinding(ctx, s.db, ownerEnvHash, strings.TrimSpace(pluginInstanceID))
}

func (s *SQLiteStore) ListBindings(ctx context.Context, cursor string, limit int) ([]plugindata.Binding, string, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return listSQLiteDataBindings(ctx, s.db, ownerEnvHash, cursor, limit)
}

func (s *SQLiteStore) ListAllBindingsForMaintenance(ctx context.Context, cursor string, limit int) ([]plugindata.MaintenanceBinding, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	parts := parseMaintenanceCursor(cursor, 2)
	rows, err := s.db.QueryContext(ctx, `
SELECT owner_env_hash, plugin_instance_id, generation_id, state, revision, shape_hash, retained_at, expires_at
FROM plugin_data_bindings
WHERE (owner_env_hash, plugin_instance_id) > (?, ?)
ORDER BY owner_env_hash, plugin_instance_id
LIMIT ?`, parts[0], parts[1], limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	type entry struct {
		ownerEnvHash string
		binding      plugindata.Binding
	}
	entries := make([]entry, 0, limit+1)
	for rows.Next() {
		var item entry
		var state string
		var retainedAt sql.NullInt64
		var expiresAt sql.NullInt64
		if err := rows.Scan(&item.ownerEnvHash, &item.binding.PluginInstanceID, &item.binding.GenerationID, &state, &item.binding.Revision, &item.binding.ShapeHash, &retainedAt, &expiresAt); err != nil {
			return nil, "", err
		}
		item.binding.State = plugindata.BindingState(state)
		item.binding.RetainedAt = nullableUnixToTimePtr(retainedAt)
		item.binding.ExpiresAt = nullableUnixToTimePtr(expiresAt)
		if err := validateDataBinding(item.binding); err != nil {
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
	bindings := make([]plugindata.MaintenanceBinding, 0, len(entries))
	for _, item := range entries {
		bindings = append(bindings, plugindata.MaintenanceBinding{
			Scope:   sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: item.ownerEnvHash},
			Binding: item.binding,
		})
	}
	if more {
		last := entries[len(entries)-1]
		return bindings, maintenanceCursor(last.ownerEnvHash, last.binding.PluginInstanceID), nil
	}
	return bindings, "", nil
}

func (s *SQLiteStore) CommitEnable(ctx context.Context, expectedManagementRevision uint64, expected *plugindata.Binding, next plugindata.Binding, shape plugindata.Shape, now time.Time) error {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return err
	}
	if err := validateDataBinding(next); err != nil || next.State != plugindata.BindingActive {
		return plugindata.ErrInvalidArgument
	}
	return s.sqliteCatalogMutation(ctx, func(tx *sql.Tx) error {
		record, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, next.PluginInstanceID, false)
		if err != nil {
			return err
		} else if !exists {
			return ErrNotFound
		}
		if err := validateRecordDataShape(record, next, shape); err != nil {
			return err
		}
		if record.ManagementRevision != expectedManagementRevision {
			return &ManagementRevisionConflictError{PluginInstanceID: next.PluginInstanceID, Expected: expectedManagementRevision, Actual: record.ManagementRevision}
		}
		actual, exists, err := getSQLiteDataBinding(ctx, tx, ownerEnvHash, next.PluginInstanceID)
		if err != nil {
			return err
		}
		if expected == nil {
			if exists || next.Revision != 1 {
				return plugindata.ErrBindingConflict
			}
			if err := insertSQLiteDataBinding(ctx, tx, ownerEnvHash, next); err != nil {
				return err
			}
		} else {
			if !exists || !sameDataBinding(actual, *expected) || !sameDataBinding(next, *expected) {
				return plugindata.ErrBindingConflict
			}
		}
		if now.IsZero() {
			now = time.Now().UTC()
		}
		record.EnableState = EnableEnabled
		record.DisabledReason = ""
		record.ManagementRevision++
		record.RevokeEpoch++
		record.EnabledAt = &now
		record.UpdatedAt = now
		return upsertSQLitePlugin(ctx, tx, record)
	})
}

func (s *SQLiteStore) SwapImport(ctx context.Context, expectedManagementRevision uint64, expected *plugindata.Binding, next plugindata.Binding, shape plugindata.Shape, now time.Time) error {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return err
	}
	if err := validateDataBinding(next); err != nil || next.State != plugindata.BindingActive {
		return plugindata.ErrInvalidArgument
	}
	return s.sqliteCatalogMutation(ctx, func(tx *sql.Tx) error {
		record, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, next.PluginInstanceID, false)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		if err := validateRecordDataShape(record, next, shape); err != nil {
			return err
		}
		if record.ManagementRevision != expectedManagementRevision {
			return &ManagementRevisionConflictError{PluginInstanceID: next.PluginInstanceID, Expected: expectedManagementRevision, Actual: record.ManagementRevision}
		}
		if record.EnableState == EnableEnabled {
			return plugindata.ErrBindingConflict
		}
		actual, exists, err := getSQLiteDataBinding(ctx, tx, ownerEnvHash, next.PluginInstanceID)
		if err != nil {
			return err
		}
		if expected == nil {
			if exists || next.Revision != 1 {
				return plugindata.ErrBindingConflict
			}
			if err := insertSQLiteDataBinding(ctx, tx, ownerEnvHash, next); err != nil {
				return err
			}
		} else {
			if !exists || !sameDataBinding(actual, *expected) || next.Revision != expected.Revision+1 {
				return plugindata.ErrBindingConflict
			}
			if err := updateSQLiteDataBinding(ctx, tx, ownerEnvHash, next); err != nil {
				return err
			}
		}
		if now.IsZero() {
			now = time.Now().UTC()
		}
		record.ManagementRevision++
		record.RevokeEpoch++
		record.UpdatedAt = now
		return upsertSQLitePlugin(ctx, tx, record)
	})
}

func (s *SQLiteStore) BindRetained(ctx context.Context, expected plugindata.Binding, targetPluginInstanceID string, targetExpectedManagementRevision uint64, targetShape plugindata.Shape, now time.Time) (plugindata.Binding, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return plugindata.Binding{}, err
	}
	var active plugindata.Binding
	err = s.sqliteCatalogMutation(ctx, func(tx *sql.Tx) error {
		targetShapeHash, err := plugindata.HashShape(targetShape)
		if err != nil {
			return err
		}
		actual, exists, err := getSQLiteDataBinding(ctx, tx, ownerEnvHash, expected.PluginInstanceID)
		if err != nil {
			return err
		}
		if !exists || !sameDataBinding(actual, expected) || actual.State != plugindata.BindingRetained || actual.ShapeHash != targetShapeHash {
			return plugindata.ErrBindingConflict
		}
		targetPluginInstanceID = strings.TrimSpace(targetPluginInstanceID)
		if targetPluginInstanceID == expected.PluginInstanceID {
			return plugindata.ErrInvalidArgument
		}
		target, exists, err := getSQLitePlugin(ctx, tx, ownerEnvHash, targetPluginInstanceID, false)
		if err != nil {
			return err
		} else if !exists {
			return ErrNotFound
		}
		declaredShape, err := plugindata.ShapeFromManifest(target.Manifest)
		if err != nil {
			return err
		}
		declaredShapeHash, err := plugindata.HashShape(declaredShape)
		if err != nil {
			return err
		}
		if target.PublisherID != targetShape.PublisherID || target.PluginID != targetShape.PluginID || targetShapeHash != declaredShapeHash {
			return plugindata.ErrShapeMismatch
		}
		if target.ManagementRevision != targetExpectedManagementRevision {
			return &ManagementRevisionConflictError{PluginInstanceID: targetPluginInstanceID, Expected: targetExpectedManagementRevision, Actual: target.ManagementRevision}
		}
		if target.EnableState == EnableEnabled {
			return plugindata.ErrBindingConflict
		}
		if targetPluginInstanceID != expected.PluginInstanceID {
			if _, exists, err := getSQLiteDataBinding(ctx, tx, ownerEnvHash, targetPluginInstanceID); err != nil {
				return err
			} else if exists {
				return plugindata.ErrBindingConflict
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, expected.PluginInstanceID); err != nil {
				return err
			}
		}
		actual.PluginInstanceID = targetPluginInstanceID
		actual.State = plugindata.BindingActive
		actual.Revision++
		actual.RetainedAt = nil
		actual.ExpiresAt = nil
		active = actual
		if err := insertSQLiteDataBinding(ctx, tx, ownerEnvHash, actual); err != nil {
			return err
		}
		if now.IsZero() {
			now = time.Now().UTC()
		}
		target.ManagementRevision++
		target.RevokeEpoch++
		target.UpdatedAt = now
		return upsertSQLitePlugin(ctx, tx, target)
	})
	return active, err
}

func (s *SQLiteStore) DeleteRetained(ctx context.Context, expected plugindata.Binding) error {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return err
	}
	return s.sqliteCatalogMutation(ctx, func(tx *sql.Tx) error {
		actual, exists, err := getSQLiteDataBinding(ctx, tx, ownerEnvHash, expected.PluginInstanceID)
		if err != nil {
			return err
		}
		if !exists || !sameDataBinding(actual, expected) || actual.State != plugindata.BindingRetained {
			return plugindata.ErrBindingConflict
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, expected.PluginInstanceID)
		return err
	})
}

func (s *SQLiteStore) CleanupExpired(ctx context.Context, now time.Time, expected []plugindata.Binding) ([]plugindata.Binding, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	deleted := make([]plugindata.Binding, 0, len(expected))
	err = s.sqliteCatalogMutation(ctx, func(tx *sql.Tx) error {
		for _, binding := range expected {
			actual, exists, err := getSQLiteDataBinding(ctx, tx, ownerEnvHash, binding.PluginInstanceID)
			if err != nil {
				return err
			}
			if !exists || !sameDataBinding(actual, binding) || actual.State != plugindata.BindingRetained || actual.ExpiresAt == nil || actual.ExpiresAt.After(now) {
				return plugindata.ErrBindingConflict
			}
		}
		for _, binding := range expected {
			if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_bindings WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, binding.PluginInstanceID); err != nil {
				return err
			}
			deleted = append(deleted, cloneDataBinding(binding))
		}
		return nil
	})
	return deleted, err
}

func (s *SQLiteStore) GetObject(ctx context.Context, objectID string) (plugindata.Object, bool, error) {
	owner, err := userOwner(ctx)
	if err != nil {
		return plugindata.Object{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return getSQLiteDataObject(ctx, s.db, owner.OwnerEnvHash, owner.OwnerUserHash, strings.TrimSpace(objectID))
}

func (s *SQLiteStore) ListObjects(ctx context.Context, cursor string, limit int) ([]plugindata.Object, string, error) {
	owner, err := userOwner(ctx)
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	rows, err := s.db.QueryContext(ctx, `SELECT object_id, content_hash, shape_hash, size_bytes, created_at FROM plugin_data_objects WHERE owner_env_hash = ? AND owner_user_hash = ? AND object_id > ? ORDER BY object_id LIMIT ?`, owner.OwnerEnvHash, owner.OwnerUserHash, cursor, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	objects := []plugindata.Object{}
	for rows.Next() {
		var object plugindata.Object
		var createdAt int64
		if err := rows.Scan(&object.ObjectID, &object.ContentHash, &object.ShapeHash, &object.SizeBytes, &createdAt); err != nil {
			return nil, "", err
		}
		object.CreatedAt = unixToTime(createdAt)
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

func (s *SQLiteStore) ListAllObjectsForMaintenance(ctx context.Context, cursor string, limit int) ([]plugindata.MaintenanceObject, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	parts := parseMaintenanceCursor(cursor, 3)
	rows, err := s.db.QueryContext(ctx, `
SELECT owner_env_hash, owner_user_hash, object_id, content_hash, shape_hash, size_bytes, created_at
FROM plugin_data_objects
WHERE (owner_env_hash, owner_user_hash, object_id) > (?, ?, ?)
ORDER BY owner_env_hash, owner_user_hash, object_id
LIMIT ?`, parts[0], parts[1], parts[2], limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	type entry struct {
		ownerEnvHash  string
		ownerUserHash string
		object        plugindata.Object
	}
	entries := make([]entry, 0, limit+1)
	for rows.Next() {
		var item entry
		var createdAt int64
		if err := rows.Scan(&item.ownerEnvHash, &item.ownerUserHash, &item.object.ObjectID, &item.object.ContentHash, &item.object.ShapeHash, &item.object.SizeBytes, &createdAt); err != nil {
			return nil, "", err
		}
		item.object.CreatedAt = unixToTime(createdAt)
		if err := validateDataObject(item.object); err != nil {
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
	objects := make([]plugindata.MaintenanceObject, 0, len(entries))
	for _, item := range entries {
		objects = append(objects, plugindata.MaintenanceObject{
			Scope: sessionctx.ResourceScope{
				Kind:          sessionctx.ScopeUser,
				OwnerEnvHash:  item.ownerEnvHash,
				OwnerUserHash: item.ownerUserHash,
			},
			Object: item.object,
		})
	}
	if more {
		last := entries[len(entries)-1]
		return objects, maintenanceCursor(last.ownerEnvHash, last.ownerUserHash, last.object.ObjectID), nil
	}
	return objects, "", nil
}

func (s *SQLiteStore) CreateObject(ctx context.Context, object plugindata.Object) error {
	owner, err := userOwner(ctx)
	if err != nil {
		return err
	}
	if err := validateDataObject(object); err != nil {
		return err
	}
	return s.sqliteCatalogMutation(ctx, func(tx *sql.Tx) error {
		if _, exists, err := getSQLiteDataObject(ctx, tx, owner.OwnerEnvHash, owner.OwnerUserHash, object.ObjectID); err != nil {
			return err
		} else if exists {
			return plugindata.ErrBindingConflict
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO plugin_data_objects (owner_env_hash, owner_user_hash, object_id, content_hash, shape_hash, size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, owner.OwnerEnvHash, owner.OwnerUserHash, object.ObjectID, object.ContentHash, object.ShapeHash, object.SizeBytes, object.CreatedAt.UnixNano())
		return err
	})
}

func (s *SQLiteStore) DeleteObject(ctx context.Context, objectID string) error {
	owner, err := userOwner(ctx)
	if err != nil {
		return err
	}
	return s.sqliteCatalogMutation(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM plugin_data_objects WHERE owner_env_hash = ? AND owner_user_hash = ? AND object_id = ?`, owner.OwnerEnvHash, owner.OwnerUserHash, strings.TrimSpace(objectID))
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return plugindata.ErrExportNotFound
		}
		return nil
	})
}

func (s *SQLiteStore) sqliteCatalogMutation(ctx context.Context, mutate func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollbackUnlessCommitted(tx)
	if err := mutate(tx); err != nil {
		return err
	}
	if err := s.commitTx(tx); err != nil {
		return mutation.Unknown(err)
	}
	return nil
}

func getSQLiteDataBinding(ctx context.Context, q sqliteQuerier, ownerEnvHash, pluginInstanceID string) (plugindata.Binding, bool, error) {
	var binding plugindata.Binding
	var state string
	var retainedAt sql.NullInt64
	var expiresAt sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT plugin_instance_id, generation_id, state, revision, shape_hash, retained_at, expires_at FROM plugin_data_bindings WHERE owner_env_hash = ? AND plugin_instance_id = ?`, ownerEnvHash, pluginInstanceID).Scan(&binding.PluginInstanceID, &binding.GenerationID, &state, &binding.Revision, &binding.ShapeHash, &retainedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return plugindata.Binding{}, false, nil
	}
	if err != nil {
		return plugindata.Binding{}, false, err
	}
	binding.State = plugindata.BindingState(state)
	binding.RetainedAt = nullableUnixToTimePtr(retainedAt)
	binding.ExpiresAt = nullableUnixToTimePtr(expiresAt)
	return binding, true, validateDataBinding(binding)
}

func listSQLiteDataBindings(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, ownerEnvHash, cursor string, limit int) ([]plugindata.Binding, string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 256
	}
	rows, err := q.QueryContext(ctx, `SELECT plugin_instance_id, generation_id, state, revision, shape_hash, retained_at, expires_at FROM plugin_data_bindings WHERE owner_env_hash = ? AND plugin_instance_id > ? ORDER BY plugin_instance_id LIMIT ?`, ownerEnvHash, cursor, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	bindings := []plugindata.Binding{}
	for rows.Next() {
		var binding plugindata.Binding
		var state string
		var retainedAt sql.NullInt64
		var expiresAt sql.NullInt64
		if err := rows.Scan(&binding.PluginInstanceID, &binding.GenerationID, &state, &binding.Revision, &binding.ShapeHash, &retainedAt, &expiresAt); err != nil {
			return nil, "", err
		}
		binding.State = plugindata.BindingState(state)
		binding.RetainedAt = nullableUnixToTimePtr(retainedAt)
		binding.ExpiresAt = nullableUnixToTimePtr(expiresAt)
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

func insertSQLiteDataBinding(ctx context.Context, tx *sql.Tx, ownerEnvHash string, binding plugindata.Binding) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO plugin_data_bindings (owner_env_hash, plugin_instance_id, generation_id, state, revision, shape_hash, retained_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ownerEnvHash, binding.PluginInstanceID, binding.GenerationID, string(binding.State), binding.Revision, binding.ShapeHash, timePtrToNullableUnix(binding.RetainedAt), timePtrToNullableUnix(binding.ExpiresAt))
	return err
}

func updateSQLiteDataBinding(ctx context.Context, tx *sql.Tx, ownerEnvHash string, binding plugindata.Binding) error {
	_, err := tx.ExecContext(ctx, `UPDATE plugin_data_bindings SET generation_id = ?, state = ?, revision = ?, shape_hash = ?, retained_at = ?, expires_at = ? WHERE owner_env_hash = ? AND plugin_instance_id = ?`, binding.GenerationID, string(binding.State), binding.Revision, binding.ShapeHash, timePtrToNullableUnix(binding.RetainedAt), timePtrToNullableUnix(binding.ExpiresAt), ownerEnvHash, binding.PluginInstanceID)
	return err
}

func getSQLiteDataObject(ctx context.Context, q sqliteQuerier, ownerEnvHash, ownerUserHash, objectID string) (plugindata.Object, bool, error) {
	var object plugindata.Object
	var createdAt int64
	err := q.QueryRowContext(ctx, `SELECT object_id, content_hash, shape_hash, size_bytes, created_at FROM plugin_data_objects WHERE owner_env_hash = ? AND owner_user_hash = ? AND object_id = ?`, ownerEnvHash, ownerUserHash, objectID).Scan(&object.ObjectID, &object.ContentHash, &object.ShapeHash, &object.SizeBytes, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return plugindata.Object{}, false, nil
	}
	if err != nil {
		return plugindata.Object{}, false, err
	}
	object.CreatedAt = unixToTime(createdAt)
	return object, true, validateDataObject(object)
}

func validateDataBinding(binding plugindata.Binding) error {
	if strings.TrimSpace(binding.PluginInstanceID) == "" || strings.TrimSpace(binding.GenerationID) == "" || strings.TrimSpace(binding.ShapeHash) == "" || binding.Revision == 0 {
		return plugindata.ErrInvalidArgument
	}
	switch binding.State {
	case plugindata.BindingActive:
		if binding.RetainedAt != nil || binding.ExpiresAt != nil {
			return plugindata.ErrInvalidArgument
		}
	case plugindata.BindingRetained:
		if binding.RetainedAt == nil || (binding.ExpiresAt != nil && !binding.ExpiresAt.After(*binding.RetainedAt)) {
			return plugindata.ErrInvalidArgument
		}
	default:
		return plugindata.ErrInvalidArgument
	}
	return nil
}

func validateDataObject(object plugindata.Object) error {
	if strings.TrimSpace(object.ObjectID) == "" || !validDataHash(object.ContentHash) || !validDataHash(object.ShapeHash) || object.SizeBytes <= 0 || object.CreatedAt.IsZero() {
		return plugindata.ErrInvalidArgument
	}
	return nil
}

func validDataHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validateRecordDataShape(record PluginRecord, binding plugindata.Binding, shape plugindata.Shape) error {
	hash, err := plugindata.HashShape(shape)
	if err != nil {
		return err
	}
	expectedShape, err := plugindata.ShapeFromManifest(record.Manifest)
	if err != nil {
		return err
	}
	expectedHash, err := plugindata.HashShape(expectedShape)
	if err != nil {
		return err
	}
	if record.PublisherID != shape.PublisherID || record.PluginID != shape.PluginID || hash != expectedHash || binding.ShapeHash != expectedHash {
		return plugindata.ErrShapeMismatch
	}
	return nil
}

func sortedDataBindings(bindings map[string]plugindata.Binding, ownerEnvHash string) []plugindata.Binding {
	result := make([]plugindata.Binding, 0, len(bindings))
	prefix := environmentRecordKey(ownerEnvHash, "")
	for key, binding := range bindings {
		if strings.HasPrefix(key, prefix) {
			result = append(result, cloneDataBinding(binding))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PluginInstanceID < result[j].PluginInstanceID })
	return result
}

func sameDataBinding(left, right plugindata.Binding) bool {
	return left.PluginInstanceID == right.PluginInstanceID && left.GenerationID == right.GenerationID && left.State == right.State && left.Revision == right.Revision && left.ShapeHash == right.ShapeHash && timesEqual(left.RetainedAt, right.RetainedAt) && timesEqual(left.ExpiresAt, right.ExpiresAt)
}

func timesEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func cloneDataBinding(binding plugindata.Binding) plugindata.Binding {
	binding.RetainedAt = cloneRegistryTime(binding.RetainedAt)
	binding.ExpiresAt = cloneRegistryTime(binding.ExpiresAt)
	return binding
}

func cloneRegistryTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
