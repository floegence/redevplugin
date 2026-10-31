package plugindata

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	settingsdomain "github.com/floegence/redevplugin/v3/pkg/settings"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

// UpgradeRequest names the frozen source and the verified target package shape.
// MaxBytes bounds the physical snapshot and each completed output generation.
type UpgradeRequest struct {
	Expected    Binding
	TargetShape Shape
	MaxBytes    int64
}

// RestoreVersionRequest binds the active generation and a Host-verified former
// package generation. The catalog callback revalidates the historical binding.
type RestoreVersionRequest struct {
	Expected Binding
	Retained Binding
	Shape    Shape
}

func (s *FileStore) RestoreVersion(ctx context.Context, req RestoreVersionRequest, commit func(context.Context, Binding, Binding) error) (Dataset, error) {
	release, err := s.begin()
	if err != nil {
		return Dataset{}, err
	}
	defer release()
	if commit == nil || req.Expected.PluginInstanceID != req.Retained.PluginInstanceID || req.Expected.GenerationID == req.Retained.GenerationID || req.Expected.State != BindingActive || req.Retained.State != BindingActive || req.Expected.Revision >= 9007199254740991 {
		return Dataset{}, ErrInvalidArgument
	}
	for _, binding := range []Binding{req.Expected, req.Retained} {
		if err := validateBinding(binding); err != nil {
			return Dataset{}, err
		}
	}
	shape, err := normalizeShape(req.Shape)
	if err != nil {
		return Dataset{}, err
	}
	if shapeHash(shape) != req.Retained.ShapeHash {
		return Dataset{}, ErrShapeMismatch
	}
	environment, err := environmentScope(ctx)
	if err != nil {
		return Dataset{}, err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, req.Expected.PluginInstanceID))
	defer unlock()
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	actual, found, err := s.catalog.GetBinding(ctx, req.Expected.PluginInstanceID)
	if err != nil {
		return Dataset{}, err
	}
	if !found || !SameBinding(actual, req.Expected) {
		return Dataset{}, ErrBindingRevisionConflict
	}
	for _, binding := range []Binding{req.Expected, req.Retained} {
		if err := s.closeNamespaceDatabases(generationCachePrefix(environment.OwnerEnvHash, binding.GenerationID)); err != nil {
			return Dataset{}, err
		}
		w, manifest, err := s.workspaceForBinding(environment, binding)
		if err != nil {
			return Dataset{}, err
		}
		if w.shape.PublisherID != shape.PublisherID || w.shape.PluginID != shape.PluginID {
			return Dataset{}, ErrShapeMismatch
		}
		snapshot, err := snapshotRootedTree(w.root, rootedTreeSnapshotOptions{hashContents: true, syncContents: true})
		if err != nil {
			return Dataset{}, err
		}
		if err := validateWorkspaceContentsSnapshot(ctx, w.root, manifest, snapshot); err != nil {
			return Dataset{}, err
		}
	}
	next := req.Retained
	next.Revision = actual.Revision + 1
	if err := commit(ctx, actual, next); err != nil {
		return Dataset{}, err
	}
	return Dataset{Binding: next, Shape: cloneShape(shape)}, nil
}

// UpgradeWorkspace is short-lived Host authority over a read-only source and an
// unpublished output. It never changes the catalog while conversion is running.
type UpgradeWorkspace struct {
	mu            sync.RWMutex
	outputMu      sync.Mutex
	limitErr      error
	maxBytes      int64
	closed        bool
	store         *FileStore
	owner         sessionctx.ResourceScope
	input, output workspace
	scopes        []sessionctx.ResourceScope
}

type upgradeContextKey struct{}
type upgradeNamespaceContext struct {
	workspace *UpgradeWorkspace
	scope     sessionctx.ResourceScope
	output    bool
}

func (w *UpgradeWorkspace) Scopes() []sessionctx.ResourceScope {
	return append([]sessionctx.ResourceScope(nil), w.scopes...)
}

func (w *UpgradeWorkspace) InputContext(ctx context.Context, scope sessionctx.ResourceScope) (context.Context, error) {
	return w.scopedContext(ctx, scope, false)
}

func (w *UpgradeWorkspace) OutputContext(ctx context.Context, scope sessionctx.ResourceScope) (context.Context, error) {
	return w.scopedContext(ctx, scope, true)
}

func (w *UpgradeWorkspace) scopedContext(ctx context.Context, scope sessionctx.ResourceScope, output bool) (context.Context, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed || scope.Validate() != nil || scope.OwnerEnvHash != w.owner.OwnerEnvHash {
		return nil, ErrBindingConflict
	}
	for _, allowed := range w.scopes {
		if allowed.Matches(scope) {
			return context.WithValue(ctx, upgradeContextKey{}, upgradeNamespaceContext{workspace: w, scope: scope, output: output}), nil
		}
	}
	return nil, ErrStorageScopeMismatch
}

func (w *UpgradeWorkspace) close() {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
}

func (access upgradeNamespaceContext) acquire(store *FileStore, instanceID string, exactScope *sessionctx.ResourceScope, write bool) (workspace, sessionctx.ResourceScope, func(), error) {
	w := access.workspace
	w.mu.RLock()
	if w.closed || w.store != store || w.input.binding.PluginInstanceID != instanceID || write && !access.output || exactScope != nil && !exactScope.Matches(access.scope) {
		w.mu.RUnlock()
		return workspace{}, sessionctx.ResourceScope{}, nil, ErrBindingConflict
	}
	selected := w.input
	if access.output {
		w.outputMu.Lock()
		if w.limitErr != nil {
			err := w.limitErr
			w.outputMu.Unlock()
			w.mu.RUnlock()
			return workspace{}, sessionctx.ResourceScope{}, nil, err
		}
		selected = w.output
		return selected, access.scope, func() { w.outputMu.Unlock(); w.mu.RUnlock() }, nil
	}
	return selected, access.scope, w.mu.RUnlock, nil
}

// ReadSettings reads the selected frozen or output scope without touching the
// active generation's settings mutation API. Secret settings are never present.
func (w *UpgradeWorkspace) ReadSettings(ctx context.Context, output bool, scope sessionctx.ResourceScope) (Settings, error) {
	access := upgradeNamespaceContext{workspace: w, scope: scope, output: output}
	if _, err := w.scopedContext(ctx, scope, output); err != nil {
		return Settings{}, err
	}
	selected, _, release, err := access.acquire(w.store, w.input.binding.PluginInstanceID, &scope, false)
	if err != nil {
		return Settings{}, err
	}
	defer release()
	unlock := w.store.namespaceLocks.lock(scopedGenerationCacheKey(scope, selected.binding.GenerationID)+"\x00scope", false)
	defer unlock()
	if err := ctx.Err(); err != nil {
		return Settings{}, err
	}
	document, err := readSettings(filepath.Join(workspaceScopeRoot(selected.root, scope), settingsFileName))
	if err != nil {
		return Settings{}, err
	}
	return Settings{Scope: scope.Kind, Revision: document.Revision, Values: cloneRawMap(document.Values)}, nil
}

func (w *UpgradeWorkspace) WriteSettings(ctx context.Context, scope sessionctx.ResourceScope, values map[string]json.RawMessage) error {
	if _, err := w.scopedContext(ctx, scope, true); err != nil {
		return err
	}
	selected, _, release, err := (upgradeNamespaceContext{workspace: w, scope: scope, output: true}).acquire(w.store, w.input.binding.PluginInstanceID, &scope, true)
	if err != nil {
		return err
	}
	defer release()
	unlock := w.store.namespaceLocks.lock(scopedGenerationCacheKey(scope, selected.binding.GenerationID)+"\x00scope", true)
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, err := settingsdomain.NormalizeRawValues(settingsFieldsForScope(selected.shape.Settings.Fields, scope.Kind), values)
	if err != nil {
		return err
	}
	if err := writeSettings(filepath.Join(workspaceScopeRoot(selected.root, scope), settingsFileName), settingsDocument{Scope: scope, Revision: 1, Values: normalized}); err != nil {
		return err
	}
	return w.checkOutputLimit()
}

// Called with outputMu held after each output mutation. An over-limit staging
// generation is permanently rejected even when untrusted code ignores the error.
func (w *UpgradeWorkspace) checkOutputLimit() error {
	snapshot, err := snapshotRootedTree(w.output.root, rootedTreeSnapshotOptions{})
	if err == nil && snapshot.sizeBytes > w.maxBytes {
		err = fmt.Errorf("%w: upgrade output exceeds its byte limit", storage.ErrQuotaExceeded)
	}
	if err != nil {
		w.limitErr = err
	}
	return err
}

// Upgrade runs a Host-controlled converter on an isolated generation. The commit
// callback must atomically retain the source and switch package plus binding.
func (s *FileStore) Upgrade(ctx context.Context, req UpgradeRequest, convert func(context.Context, *UpgradeWorkspace) error, commit func(context.Context, Binding, Binding) error) (Dataset, error) {
	release, err := s.begin()
	if err != nil {
		return Dataset{}, err
	}
	defer release()
	if convert == nil || commit == nil || req.MaxBytes <= 0 || req.Expected.State != BindingActive || req.Expected.Revision >= 9007199254740991 {
		return Dataset{}, ErrInvalidArgument
	}
	if err := validateBinding(req.Expected); err != nil {
		return Dataset{}, err
	}
	shape, err := normalizeShape(req.TargetShape)
	if err != nil {
		return Dataset{}, err
	}
	environment, err := environmentScope(ctx)
	if err != nil {
		return Dataset{}, err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, req.Expected.PluginInstanceID))
	defer unlock()
	actual, found, err := s.catalog.GetBinding(ctx, req.Expected.PluginInstanceID)
	if err != nil {
		return Dataset{}, err
	}
	if !found || !SameBinding(actual, req.Expected) {
		return Dataset{}, ErrBindingRevisionConflict
	}
	source, sourceManifest, err := s.workspaceForBinding(environment, actual)
	if err != nil {
		return Dataset{}, err
	}
	if shape.PublisherID != source.shape.PublisherID || shape.PluginID != source.shape.PluginID {
		return Dataset{}, ErrShapeMismatch
	}
	if err := s.closeNamespaceDatabases(generationCachePrefix(environment.OwnerEnvHash, actual.GenerationID)); err != nil {
		return Dataset{}, err
	}
	snapshot, err := snapshotRootedTree(source.root, rootedTreeSnapshotOptions{hashContents: true, syncContents: true})
	if err != nil {
		return Dataset{}, err
	}
	if snapshot.sizeBytes > req.MaxBytes {
		return Dataset{}, fmt.Errorf("%w: upgrade snapshot exceeds its byte limit", ErrInvalidArgument)
	}
	if err := validateWorkspaceContentsSnapshot(ctx, source.root, sourceManifest, snapshot); err != nil {
		return Dataset{}, err
	}
	stage, err := s.newStage("upgrade")
	if err != nil {
		return Dataset{}, err
	}
	defer os.RemoveAll(stage)
	scopes, err := s.prepareUpgradeOutput(ctx, source, stage, shape, environment)
	if err != nil {
		return Dataset{}, err
	}
	if err := snapshot.revalidate(source.root); err != nil {
		return Dataset{}, err
	}
	generation, err := newID("gen")
	if err != nil {
		return Dataset{}, err
	}
	next := Binding{PluginInstanceID: actual.PluginInstanceID, GenerationID: generation, State: BindingActive, Revision: actual.Revision + 1, ShapeHash: shapeHash(shape)}
	conversion := &UpgradeWorkspace{store: s, owner: environment, input: source, output: workspace{root: stage, binding: next, shape: shape}, scopes: scopes, maxBytes: req.MaxBytes}
	defer func() {
		// Revoke and drain escaped accesses before closing databases or removing
		// the staging directory on every exit, including converter failures.
		conversion.close()
		_ = s.closeNamespaceDatabases(generationCachePrefix(environment.OwnerEnvHash, next.GenerationID))
		s.dropGenerationUsage(environment, next.GenerationID)
	}()
	if err := conversion.checkOutputLimit(); err != nil {
		return Dataset{}, err
	}
	if err := convert(ctx, conversion); err != nil {
		// A converter can have an unknown execution result, but it only writes
		// staging data. The package/data transaction has not started.
		return Dataset{}, &mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: err}
	}
	conversion.close()
	if conversion.limitErr != nil {
		return Dataset{}, conversion.limitErr
	}
	if err := ctx.Err(); err != nil {
		return Dataset{}, err
	}
	for _, binding := range []Binding{actual, next} {
		if err := s.closeNamespaceDatabases(generationCachePrefix(environment.OwnerEnvHash, binding.GenerationID)); err != nil {
			return Dataset{}, err
		}
	}
	if err := snapshot.revalidate(source.root); err != nil {
		return Dataset{}, err
	}
	if _, err := s.finalizeWorkspace(ctx, stage, generation, shape, environment); err != nil {
		return Dataset{}, err
	}
	outputSnapshot, err := snapshotRootedTree(stage, rootedTreeSnapshotOptions{hashContents: true})
	if err != nil {
		return Dataset{}, err
	}
	if outputSnapshot.sizeBytes > req.MaxBytes {
		return Dataset{}, fmt.Errorf("%w: upgrade output exceeds its byte limit", ErrInvalidArgument)
	}
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	destination := s.scopedWorkspacePath(environment, generation)
	if err := s.publishStage(stage, destination); err != nil {
		return Dataset{}, err
	}
	if err := commit(ctx, actual, next); err != nil {
		if outcome := mutation.ForError(err); outcome == mutation.OutcomeUnknown || outcome == mutation.OutcomeCommitted {
			return Dataset{}, err
		}
		return Dataset{}, s.rollbackPublishedDirectory(destination, filepath.Dir(destination), err)
	}
	return Dataset{Binding: next, Shape: cloneShape(shape)}, nil
}

func (s *FileStore) prepareUpgradeOutput(ctx context.Context, source workspace, stage string, target Shape, environment sessionctx.ResourceScope) ([]sessionctx.ResourceScope, error) {
	scopes := []sessionctx.ResourceScope{environment}
	users, err := os.ReadDir(filepath.Join(source.root, workspaceScopesDirName, workspaceUsersDirName))
	if err != nil {
		return nil, err
	}
	for _, entry := range users {
		scopes = append(scopes, sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: environment.OwnerEnvHash, OwnerUserHash: entry.Name()})
	}
	if err := ensurePrivateDirectory(filepath.Join(stage, workspaceScopesDirName, workspaceUsersDirName)); err != nil {
		return nil, err
	}
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sourceRoot, targetRoot := workspaceScopeRoot(source.root, scope), workspaceScopeRoot(stage, scope)
		settings, err := readSettings(filepath.Join(sourceRoot, settingsFileName))
		if err != nil {
			return nil, err
		}
		// Preserve compatible values; changed types start from target defaults.
		// The converter still reads every original value through input settings.
		compatible := make(map[string]json.RawMessage)
		for _, field := range settingsFieldsForScope(target.Settings.Fields, scope.Kind) {
			if value, ok := settings.Values[field.Key]; ok {
				if normalized, err := settingsdomain.NormalizeRawValues([]settingsdomain.Field{field}, map[string]json.RawMessage{field.Key: value}); err == nil {
					compatible[field.Key] = normalized[field.Key]
				}
			}
		}
		if err := initializeWorkspaceScope(ctx, targetRoot, target, scope, compatible); err != nil {
			return nil, err
		}
		for _, namespace := range namespacesForScope(target.Namespaces, scope.Kind) {
			for _, previous := range source.shape.Namespaces {
				if previous.ID != namespace.ID || previous.Kind != namespace.Kind || previous.Scope != namespace.Scope {
					continue
				}
				output := filepath.Join(targetRoot, namespacesDirName, namespace.ID, namespaceDataName)
				if err := os.RemoveAll(output); err != nil {
					return nil, err
				}
				if err := s.ops.copyDir(filepath.Join(sourceRoot, namespacesDirName, namespace.ID, namespaceDataName), output); err != nil {
					return nil, err
				}
			}
		}
	}
	return scopes, nil
}
