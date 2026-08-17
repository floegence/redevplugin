package registry

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
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

func (s *MemoryStore) GetObject(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, objectID string) (plugindata.Object, bool, error) {
	owner, err := resourceOwner(ctx, scope)
	if err != nil {
		return plugindata.Object{}, false, err
	}
	pluginInstanceID, objectID, err = validateDataObjectIdentity(pluginInstanceID, objectID)
	if err != nil {
		return plugindata.Object{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	object, ok := s.dataObjects[scopedObjectKey(owner, pluginInstanceID, objectID)]
	return object, ok, nil
}

func (s *MemoryStore) ListObjects(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, cursor string, limit int) ([]plugindata.Object, string, error) {
	owner, err := resourceOwner(ctx, scope)
	if err != nil {
		return nil, "", err
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return nil, "", plugindata.ErrInvalidArgument
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	objects := make([]plugindata.Object, 0, len(s.dataObjects))
	prefix := scopedObjectKey(owner, pluginInstanceID, "")
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
		if len(parts) != 5 {
			return nil, "", ErrOwnerScopeMismatch
		}
		scope := sessionctx.ResourceScope{Kind: sessionctx.ScopeKind(parts[0]), OwnerEnvHash: parts[1], OwnerUserHash: parts[2]}
		if scope.Validate() != nil {
			return nil, "", ErrOwnerScopeMismatch
		}
		objects = append(objects, plugindata.MaintenanceObject{
			Scope:  scope,
			Object: s.dataObjects[key],
		})
	}
	if more {
		return objects, keys[len(keys)-1], nil
	}
	return objects, "", nil
}

func (s *MemoryStore) CreateObject(ctx context.Context, scope sessionctx.ScopeKind, object plugindata.Object) error {
	owner, err := resourceOwner(ctx, scope)
	if err != nil {
		return err
	}
	if err := validateDataObject(object); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopedObjectKey(owner, object.PluginInstanceID, object.ObjectID)
	if _, exists := s.dataObjects[key]; exists {
		return plugindata.ErrBindingConflict
	}
	s.dataObjects[key] = object
	return nil
}

func (s *MemoryStore) DeleteObject(ctx context.Context, scope sessionctx.ScopeKind, pluginInstanceID, objectID string) error {
	owner, err := resourceOwner(ctx, scope)
	if err != nil {
		return err
	}
	pluginInstanceID, objectID, err = validateDataObjectIdentity(pluginInstanceID, objectID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	objectID = strings.TrimSpace(objectID)
	key := scopedObjectKey(owner, pluginInstanceID, objectID)
	if _, exists := s.dataObjects[key]; !exists {
		return plugindata.ErrExportNotFound
	}
	delete(s.dataObjects, key)
	return nil
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
	if strings.TrimSpace(object.PluginInstanceID) == "" || strings.TrimSpace(object.ObjectID) == "" || !validDataHash(object.ContentHash) || !validDataHash(object.ShapeHash) || object.SizeBytes <= 0 || object.CreatedAt.IsZero() {
		return plugindata.ErrInvalidArgument
	}
	return nil
}

func validateDataObjectIdentity(pluginInstanceID, objectID string) (string, string, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	objectID = strings.TrimSpace(objectID)
	if pluginInstanceID == "" || objectID == "" {
		return "", "", plugindata.ErrInvalidArgument
	}
	return pluginInstanceID, objectID, nil
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
