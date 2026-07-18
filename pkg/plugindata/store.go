package plugindata

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	settingsdomain "github.com/floegence/redevplugin/pkg/settings"
)

const (
	datasetManifestName = "dataset.json"
	settingsFileName    = "settings.json"
	namespacesDirName   = "namespaces"
	namespaceMetaName   = "namespace.json"
	namespaceDataName   = "data"
	exportManifestName  = "export.json"
	exportPayloadName   = "payload"
	workspacesDirName   = "workspaces"
	objectsDirName      = "objects"
	stagingDirName      = "staging"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type datasetManifest struct {
	GenerationID string    `json:"generation_id"`
	OwnerEnvHash string    `json:"owner_env_hash"`
	CreatedAt    time.Time `json:"created_at"`
	Shape        Shape     `json:"shape"`
	ShapeHash    string    `json:"shape_hash"`
}

type settingsDocument struct {
	Scope    sessionctx.ResourceScope   `json:"scope"`
	Revision uint64                     `json:"revision"`
	Values   map[string]json.RawMessage `json:"values"`
}

type exportManifest struct {
	ObjectID    string                   `json:"object_id"`
	Scope       sessionctx.ResourceScope `json:"scope"`
	ContentHash string                   `json:"content_hash"`
	ShapeHash   string                   `json:"shape_hash"`
	CreatedAt   time.Time                `json:"created_at"`
}

type namespaceDocument struct {
	Scope     sessionctx.ResourceScope `json:"scope"`
	Namespace Namespace                `json:"namespace"`
}

type workspace struct {
	binding Binding
	root    string
	shape   Shape
}

type fileOps struct {
	rename    func(string, string) error
	copyDir   func(string, string) error
	removeAll func(string) error
	syncDir   func(string) error
}

type keyedLock struct {
	mu   sync.RWMutex
	refs int
}

type keyedLocks struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

const maxNamespaceDatabaseCacheEntries = 128

type namespaceDBEntry struct {
	db           *sql.DB
	root         *os.Root
	rootPath     string
	rootInfo     os.FileInfo
	databaseInfo os.FileInfo
	refs         int
	lastUse      uint64
	opening      bool
	ready        chan struct{}
	err          error
}

type namespaceUsageFlight struct {
	ready chan struct{}
	usage namespaceUsage
	err   error
}

type namespaceUsageLoader func(context.Context, string, NamespaceKind, *sql.DB) (namespaceUsage, error)

type FileStore struct {
	root        string
	catalog     Catalog
	now         func() time.Time
	locks       keyedLocks
	objectLocks keyedLocks
	ops         fileOps
	rootLock    rootLock
	rootHandle  *os.Root
	lifecycle   sync.RWMutex
	// Keeps orphan collection from observing a directory before its catalog commit.
	publicationMu   sync.Mutex
	closed          bool
	usageMu         sync.Mutex
	usage           map[string]namespaceUsage
	usageFlights    map[string]*namespaceUsageFlight
	namespaceDBMu   sync.Mutex
	namespaceDB     map[string]*namespaceDBEntry
	namespaceDBTick uint64
	namespaceDBWake chan struct{}
	namespaceLocks  keyedLocks
	sqliteQueries   sync.Map
}

func Open(ctx context.Context, root string, catalog Catalog) (*FileStore, error) {
	root = strings.TrimSpace(root)
	if root == "" || catalog == nil {
		return nil, fmt.Errorf("%w: root and catalog are required", ErrInvalidArgument)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve plugin data root: %w", err)
	}
	if err := ensurePrivateDirectory(absRoot); err != nil {
		return nil, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, err
	}
	resolvedRoot = filepath.Clean(resolvedRoot)
	lock, err := acquireRootLock(resolvedRoot)
	if err != nil {
		return nil, err
	}
	rootHandle, err := os.OpenRoot(resolvedRoot)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	store := &FileStore{
		root:            resolvedRoot,
		catalog:         catalog,
		now:             func() time.Time { return time.Now().UTC() },
		locks:           keyedLocks{locks: map[string]*keyedLock{}},
		objectLocks:     keyedLocks{locks: map[string]*keyedLock{}},
		rootLock:        lock,
		rootHandle:      rootHandle,
		usage:           map[string]namespaceUsage{},
		usageFlights:    map[string]*namespaceUsageFlight{},
		namespaceDB:     map[string]*namespaceDBEntry{},
		namespaceDBWake: make(chan struct{}),
		namespaceLocks:  keyedLocks{locks: map[string]*keyedLock{}},
	}
	store.ops.rename = os.Rename
	store.ops.copyDir = store.copyDirectory
	store.ops.removeAll = os.RemoveAll
	store.ops.syncDir = syncDirectory
	if err := prepareResourceScopeLayout(store.root); err != nil {
		_ = store.Close()
		return nil, err
	}
	for _, path := range []string{
		filepath.Join(store.workspacesRoot(), environmentOwnersDirName),
		filepath.Join(store.objectsRoot(), userOwnersDirName),
		store.stagingRoot(),
	} {
		if err := ensurePrivateDirectory(path); err != nil {
			_ = store.Close()
			return nil, err
		}
	}
	if err := store.cleanupOnOpen(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (s *FileStore) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var closeErr error
	closeErr = s.closeNamespaceDatabases("")
	if s.rootHandle != nil {
		closeErr = errors.Join(closeErr, s.rootHandle.Close())
		s.rootHandle = nil
	}
	if s.rootLock != nil {
		closeErr = errors.Join(closeErr, s.rootLock.Close())
		s.rootLock = nil
	}
	return closeErr
}

func (s *FileStore) begin() (func(), error) {
	if s == nil {
		return nil, errors.New("plugin data store is nil")
	}
	s.lifecycle.RLock()
	if s.closed {
		s.lifecycle.RUnlock()
		return nil, errors.New("plugin data store is closed")
	}
	return s.lifecycle.RUnlock, nil
}

func (s *FileStore) CommitEnable(ctx context.Context, req CommitEnableRequest) (Dataset, error) {
	release, err := s.begin()
	if err != nil {
		return Dataset{}, err
	}
	defer release()
	if req.ExpectedManagementRevision == 0 {
		return Dataset{}, fmt.Errorf("%w: expected management revision is required", ErrInvalidArgument)
	}
	pluginID, shape, initialSettings, err := normalizeEnable(req)
	if err != nil {
		return Dataset{}, err
	}
	environment, user, err := requestScopes(ctx)
	if err != nil {
		return Dataset{}, err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, pluginID))
	defer unlock()
	existing, found, err := s.catalog.GetBinding(ctx, pluginID)
	if err != nil {
		return Dataset{}, err
	}
	var expected *Binding
	var next Binding
	var publishedWorkspace string
	if found {
		if existing.State != BindingActive {
			return Dataset{}, ErrNotActive
		}
		_, manifest, err := s.workspaceForBinding(environment, existing)
		if err != nil {
			return Dataset{}, err
		}
		if manifest.ShapeHash != shapeHash(shape) {
			return Dataset{}, ErrShapeMismatch
		}
		expected = &existing
		next = existing
	} else {
		s.publicationMu.Lock()
		defer s.publicationMu.Unlock()
		generationID, err := newID("gen")
		if err != nil {
			return Dataset{}, err
		}
		stage, err := s.newStage("workspace")
		if err != nil {
			return Dataset{}, err
		}
		defer os.RemoveAll(stage)
		if err := initializeWorkspaceScopes(ctx, stage, shape, environment, user, initialSettings); err != nil {
			return Dataset{}, err
		}
		manifest, err := s.finalizeWorkspace(ctx, stage, generationID, shape, environment)
		if err != nil {
			return Dataset{}, err
		}
		publishedWorkspace = s.scopedWorkspacePath(environment, generationID)
		if err := s.publishStage(stage, publishedWorkspace); err != nil {
			return Dataset{}, err
		}
		next = Binding{PluginInstanceID: pluginID, GenerationID: generationID, State: BindingActive, Revision: 1, ShapeHash: manifest.ShapeHash}
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	if err := s.catalog.CommitEnable(ctx, req.ExpectedManagementRevision, expected, next, shape, now); err != nil {
		cause := fmt.Errorf("commit plugin enable: %w", err)
		if publishedWorkspace != "" {
			cause = s.rollbackPublishedDirectory(publishedWorkspace, filepath.Dir(publishedWorkspace), cause)
		}
		return Dataset{}, cause
	}
	return Dataset{Binding: cloneBinding(next), Shape: cloneShape(shape)}, nil
}

func (s *FileStore) Export(ctx context.Context, req ExportRequest) (Export, error) {
	release, err := s.begin()
	if err != nil {
		return Export{}, err
	}
	defer release()
	pluginID, err := normalizeIdentifier("plugin instance ID", req.PluginInstanceID)
	if err != nil {
		return Export{}, err
	}
	environment, user, err := requestScopes(ctx)
	if err != nil {
		return Export{}, err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, pluginID))
	defer unlock()
	binding, err := s.getBinding(ctx, pluginID)
	if err != nil {
		return Export{}, err
	}
	if binding.State != BindingActive {
		return Export{}, fmt.Errorf("%w: %s", ErrNotActive, pluginID)
	}
	workspace, manifest, err := s.workspaceForBinding(environment, binding)
	if err != nil {
		return Export{}, err
	}
	if err := s.closeNamespaceDatabases(generationCachePrefix(environment.OwnerEnvHash, binding.GenerationID)); err != nil {
		return Export{}, fmt.Errorf("prepare plugin data export snapshot: %w", err)
	}
	objectID, err := newID("obj")
	if err != nil {
		return Export{}, err
	}
	stage, err := s.newStage("export")
	if err != nil {
		return Export{}, err
	}
	defer os.RemoveAll(stage)
	payload := filepath.Join(stage, exportPayloadName)
	if err := s.createExportPayload(ctx, workspace.root, payload, user, manifest); err != nil {
		return Export{}, err
	}
	contentHash, err := hashTree(payload, "")
	if err != nil {
		return Export{}, err
	}
	createdAt := s.now()
	if err := writeJSON(filepath.Join(stage, exportManifestName), exportManifest{ObjectID: objectID, Scope: user, ContentHash: contentHash, ShapeHash: manifest.ShapeHash, CreatedAt: createdAt}); err != nil {
		return Export{}, err
	}
	if err := validateTree(stage); err != nil {
		return Export{}, err
	}
	if err := syncTree(stage); err != nil {
		return Export{}, err
	}
	destination := s.scopedObjectPath(user, objectID)
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	if err := s.publishStage(stage, destination); err != nil {
		return Export{}, err
	}
	size, err := directorySize(destination)
	if err != nil {
		return Export{}, s.rollbackPublishedDirectory(destination, filepath.Dir(destination), err)
	}
	object := Object{ObjectID: objectID, ContentHash: contentHash, ShapeHash: manifest.ShapeHash, SizeBytes: size, CreatedAt: createdAt}
	if err := s.catalog.CreateObject(ctx, object); err != nil {
		return Export{}, s.rollbackPublishedDirectory(destination, filepath.Dir(destination), fmt.Errorf("publish export object: %w", err))
	}
	return Export{ObjectID: objectID, ContentHash: contentHash, SizeBytes: size, CreatedAt: createdAt}, nil
}

func (s *FileStore) DeleteExport(ctx context.Context, objectID string) error {
	release, err := s.begin()
	if err != nil {
		return err
	}
	defer release()
	objectID, err = normalizeIdentifier("object ID", objectID)
	if err != nil {
		return err
	}
	owner, err := userScope(ctx)
	if err != nil {
		return err
	}
	unlock := s.objectLocks.lockWrite(scopedLockKey(owner, objectID))
	defer unlock()
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	if err := s.catalog.DeleteObject(ctx, objectID); err != nil {
		return err
	}
	objectPath := s.scopedObjectPath(owner, objectID)
	if err := s.removePublishedDirectory(objectPath, filepath.Dir(objectPath)); err != nil {
		return err
	}
	return s.collectAfterCommit(ctx)
}

func (s *FileStore) Import(ctx context.Context, req ImportRequest) (Dataset, error) {
	release, err := s.begin()
	if err != nil {
		return Dataset{}, err
	}
	defer release()
	if req.ExpectedManagementRevision == 0 {
		return Dataset{}, fmt.Errorf("%w: expected management revision is required", ErrInvalidArgument)
	}
	pluginID, err := normalizeIdentifier("plugin instance ID", req.PluginInstanceID)
	if err != nil {
		return Dataset{}, err
	}
	objectID, err := normalizeIdentifier("object ID", req.ObjectID)
	if err != nil {
		return Dataset{}, err
	}
	expectedShape, err := normalizeShape(req.ExpectedShape)
	if err != nil {
		return Dataset{}, err
	}
	expectedShapeHash := shapeHash(expectedShape)
	environment, user, err := requestScopes(ctx)
	if err != nil {
		return Dataset{}, err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, pluginID))
	defer unlock()
	objectUnlock := s.objectLocks.lockRead(scopedLockKey(user, objectID))
	defer objectUnlock()

	current, found, err := s.catalog.GetBinding(ctx, pluginID)
	if err != nil {
		return Dataset{}, fmt.Errorf("read import target binding: %w", err)
	}
	if found && current.State != BindingActive {
		return Dataset{}, fmt.Errorf("%w: %s", ErrNotActive, pluginID)
	}
	object, catalogObject, sourceManifest, err := s.validateObject(ctx, user, objectID)
	if err != nil {
		return Dataset{}, err
	}
	if sourceManifest.ShapeHash != expectedShapeHash || catalogObject.ShapeHash != expectedShapeHash {
		return Dataset{}, fmt.Errorf("%w: import object shape differs from target declaration", ErrShapeMismatch)
	}
	stage, err := s.newStage("workspace")
	if err != nil {
		return Dataset{}, err
	}
	defer os.RemoveAll(stage)
	payloadRoot := filepath.Join(object, exportPayloadName)
	copiedHash, err := hashTree(payloadRoot, "")
	if err != nil {
		return Dataset{}, err
	}
	if copiedHash != catalogObject.ContentHash {
		return Dataset{}, fmt.Errorf("%w: export changed while importing", ErrDatasetCorrupt)
	}
	var currentWorkspace string
	if found {
		if err := s.closeNamespaceDatabases(generationCachePrefix(environment.OwnerEnvHash, current.GenerationID)); err != nil {
			return Dataset{}, fmt.Errorf("prepare plugin data import snapshot: %w", err)
		}
		currentWorkspace = s.scopedWorkspacePath(environment, current.GenerationID)
	}
	if err := s.createImportedWorkspace(ctx, currentWorkspace, payloadRoot, stage, user); err != nil {
		return Dataset{}, err
	}
	generationID, err := newID("gen")
	if err != nil {
		return Dataset{}, err
	}
	manifest, err := s.finalizeWorkspace(ctx, stage, generationID, expectedShape, environment)
	if err != nil {
		return Dataset{}, err
	}
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	publishedWorkspace := s.scopedWorkspacePath(environment, generationID)
	if err := s.publishStage(stage, publishedWorkspace); err != nil {
		return Dataset{}, err
	}
	next := Binding{PluginInstanceID: pluginID, GenerationID: generationID, State: BindingActive, Revision: 1, ShapeHash: expectedShapeHash}
	if found {
		next.Revision = current.Revision + 1
	}
	var expected *Binding
	if found {
		expected = &current
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	if err := s.catalog.SwapImport(ctx, req.ExpectedManagementRevision, expected, next, expectedShape, now); err != nil {
		return Dataset{}, s.rollbackPublishedDirectory(publishedWorkspace, filepath.Dir(publishedWorkspace), fmt.Errorf("publish imported dataset: %w", err))
	}
	if found && current.GenerationID != generationID {
		currentPath := s.scopedWorkspacePath(environment, current.GenerationID)
		if err := s.removePublishedDirectory(currentPath, filepath.Dir(currentPath)); err != nil {
			s.dropGenerationUsage(environment, current.GenerationID)
			return Dataset{}, err
		}
		s.dropGenerationUsage(environment, current.GenerationID)
	}
	if err := s.collectAfterCommit(ctx); err != nil {
		return Dataset{}, err
	}
	return Dataset{Binding: next, Shape: cloneShape(manifest.Shape)}, nil
}

func (s *FileStore) BindRetained(ctx context.Context, req BindRetainedRequest) (Dataset, error) {
	release, err := s.begin()
	if err != nil {
		return Dataset{}, err
	}
	defer release()
	if req.ExpectedSourceBindingRevision == 0 || req.TargetExpectedManagementRevision == 0 {
		return Dataset{}, fmt.Errorf("%w: target expected management revision is required", ErrInvalidArgument)
	}
	sourceID, err := normalizeIdentifier("source plugin instance ID", req.SourcePluginInstanceID)
	if err != nil {
		return Dataset{}, err
	}
	targetID, err := normalizeIdentifier("target plugin instance ID", req.TargetPluginInstanceID)
	if err != nil {
		return Dataset{}, err
	}
	if sourceID == targetID {
		return Dataset{}, fmt.Errorf("%w: retained source and target must differ", ErrInvalidArgument)
	}
	expectedShape, err := normalizeShape(req.ExpectedShape)
	if err != nil {
		return Dataset{}, err
	}
	expectedShapeHash := shapeHash(expectedShape)
	environment, err := environmentScope(ctx)
	if err != nil {
		return Dataset{}, err
	}
	unlock := s.locks.lockMany(scopedLockKey(environment, sourceID), scopedLockKey(environment, targetID))
	defer unlock()
	sourceBinding, err := s.getBinding(ctx, sourceID)
	if err != nil {
		return Dataset{}, err
	}
	if sourceBinding.State != BindingRetained {
		return Dataset{}, fmt.Errorf("%w: %s", ErrNotRetained, sourceID)
	}
	if sourceBinding.Revision != req.ExpectedSourceBindingRevision {
		return Dataset{}, &BindingRevisionConflictError{PluginInstanceID: sourceID, Expected: req.ExpectedSourceBindingRevision, Actual: sourceBinding.Revision}
	}
	_, sourceManifest, err := s.workspaceForBinding(environment, sourceBinding)
	if err != nil {
		return Dataset{}, err
	}
	if sourceManifest.ShapeHash != expectedShapeHash {
		return Dataset{}, fmt.Errorf("%w: retained data shape differs from target declaration", ErrShapeMismatch)
	}
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	active, err := s.catalog.BindRetained(ctx, sourceBinding, targetID, req.TargetExpectedManagementRevision, expectedShape, now)
	if err != nil {
		return Dataset{}, fmt.Errorf("bind retained plugin data: %w", err)
	}
	return Dataset{Binding: active, Shape: cloneShape(expectedShape)}, nil
}

func (s *FileStore) DeleteRetained(ctx context.Context, req DeleteRetainedRequest) error {
	release, err := s.begin()
	if err != nil {
		return err
	}
	defer release()
	if req.ExpectedBindingRevision == 0 {
		return fmt.Errorf("%w: expected retained revision is required", ErrInvalidArgument)
	}
	pluginID, err := normalizeIdentifier("plugin instance ID", req.PluginInstanceID)
	if err != nil {
		return err
	}
	environment, err := environmentScope(ctx)
	if err != nil {
		return err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, pluginID))
	defer unlock()
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	current, found, err := s.catalog.GetBinding(ctx, pluginID)
	if err != nil {
		return err
	}
	if !found {
		return ErrBindingNotFound
	}
	if current.State != BindingRetained {
		return ErrNotRetained
	}
	if current.Revision != req.ExpectedBindingRevision {
		return &BindingRevisionConflictError{PluginInstanceID: pluginID, Expected: req.ExpectedBindingRevision, Actual: current.Revision}
	}
	if err := s.catalog.DeleteRetained(ctx, current); err != nil {
		return fmt.Errorf("delete retained plugin data: %w", err)
	}
	workspacePath := s.scopedWorkspacePath(environment, current.GenerationID)
	if err := s.removePublishedDirectory(workspacePath, filepath.Dir(workspacePath)); err != nil {
		s.dropGenerationUsage(environment, current.GenerationID)
		return err
	}
	s.dropGenerationUsage(environment, current.GenerationID)
	return s.collectAfterCommit(ctx)
}

func (s *FileStore) CommitUninstall(ctx context.Context, req CommitUninstallRequest) (CommitUninstallResult, error) {
	release, err := s.begin()
	if err != nil {
		return CommitUninstallResult{}, err
	}
	defer release()
	pluginID, err := normalizeIdentifier("plugin instance ID", req.PluginInstanceID)
	if err != nil {
		return CommitUninstallResult{}, err
	}
	if req.ExpectedManagementRevision == 0 {
		return CommitUninstallResult{}, fmt.Errorf("%w: expected management revision is required", ErrInvalidArgument)
	}
	if req.Now.IsZero() {
		req.Now = s.now()
	}
	if req.RetainUntil != nil && !req.RetainUntil.After(req.Now) {
		return CommitUninstallResult{}, fmt.Errorf("%w: retain deadline must be after uninstall time", ErrInvalidArgument)
	}
	req.PluginInstanceID = pluginID
	environment, err := environmentScope(ctx)
	if err != nil {
		return CommitUninstallResult{}, err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, pluginID))
	defer unlock()
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	current, found, err := s.catalog.GetBinding(ctx, pluginID)
	if err != nil {
		return CommitUninstallResult{}, err
	}
	result, err := s.catalog.CommitUninstall(ctx, req)
	if err != nil {
		return CommitUninstallResult{}, fmt.Errorf("commit plugin uninstall: %w", err)
	}
	if req.DeleteData && found {
		workspacePath := s.scopedWorkspacePath(environment, current.GenerationID)
		if err := s.removePublishedDirectory(workspacePath, filepath.Dir(workspacePath)); err != nil {
			s.dropGenerationUsage(environment, current.GenerationID)
			return CommitUninstallResult{}, err
		}
		s.dropGenerationUsage(environment, current.GenerationID)
	}
	if req.DeleteData {
		if err := s.collectAfterCommit(ctx); err != nil {
			return CommitUninstallResult{}, err
		}
	}
	return result, nil
}

func (s *FileStore) dropGenerationUsage(environment sessionctx.ResourceScope, generationID string) {
	prefix := generationCachePrefix(environment.OwnerEnvHash, generationID)
	s.usageMu.Lock()
	for key := range s.usage {
		if strings.HasPrefix(key, prefix) {
			delete(s.usage, key)
		}
	}
	s.usageMu.Unlock()
	s.sqliteQueries.Range(func(key, _ any) bool {
		if strings.HasPrefix(key.(string), prefix) {
			s.sqliteQueries.Delete(key)
		}
		return true
	})
}

func (s *FileStore) ListRetained(ctx context.Context, filter RetainedFilter) ([]Binding, error) {
	release, err := s.begin()
	if err != nil {
		return nil, err
	}
	defer release()
	if filter.PluginInstanceID != "" {
		if _, err := normalizeIdentifier("plugin instance ID", filter.PluginInstanceID); err != nil {
			return nil, err
		}
	}
	bindings, err := s.listAllBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list retained plugin data: %w", err)
	}
	retained := make([]Binding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.State == BindingRetained && (filter.PluginInstanceID == "" || binding.PluginInstanceID == filter.PluginInstanceID) {
			retained = append(retained, cloneBinding(binding))
		}
	}
	slices.SortFunc(retained, func(a, b Binding) int { return strings.Compare(a.PluginInstanceID, b.PluginInstanceID) })
	return retained, nil
}

func (s *FileStore) CleanupExpired(ctx context.Context, now time.Time) (CleanupResult, error) {
	release, err := s.begin()
	if err != nil {
		return CleanupResult{}, err
	}
	defer release()
	if now.IsZero() {
		return CleanupResult{}, fmt.Errorf("%w: cleanup time is required", ErrInvalidArgument)
	}
	bindings, err := s.listAllBindings(ctx)
	if err != nil {
		return CleanupResult{}, fmt.Errorf("read expired plugin data: %w", err)
	}
	candidates := make([]Binding, 0)
	keys := make([]string, 0)
	environment, err := environmentScope(ctx)
	if err != nil {
		return CleanupResult{}, err
	}
	for _, binding := range bindings {
		if binding.State == BindingRetained && binding.ExpiresAt != nil && !binding.ExpiresAt.After(now) {
			candidates = append(candidates, binding)
			keys = append(keys, scopedLockKey(environment, binding.PluginInstanceID))
		}
	}
	unlock := s.locks.lockMany(keys...)
	defer unlock()
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	deleted, err := s.catalog.CleanupExpired(ctx, now, candidates)
	if err != nil {
		return CleanupResult{}, fmt.Errorf("cleanup expired plugin data: %w", err)
	}
	result := CleanupResult{Deleted: deleted}
	slices.SortFunc(result.Deleted, func(a, b Binding) int { return strings.Compare(a.PluginInstanceID, b.PluginInstanceID) })
	var removalErr error
	for _, binding := range deleted {
		workspacePath := s.scopedWorkspacePath(environment, binding.GenerationID)
		if err := s.removePublishedDirectory(workspacePath, filepath.Dir(workspacePath)); err != nil {
			removalErr = errors.Join(removalErr, err)
		}
		s.dropGenerationUsage(environment, binding.GenerationID)
	}
	if removalErr != nil {
		return result, mutation.Unknown(removalErr)
	}
	if err := s.collectAfterCommit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

func (s *FileStore) GetSettings(ctx context.Context, pluginInstanceID string, kind sessionctx.ScopeKind) (Settings, error) {
	release, err := s.begin()
	if err != nil {
		return Settings{}, err
	}
	defer release()
	pluginID, err := normalizeIdentifier("plugin instance ID", pluginInstanceID)
	if err != nil {
		return Settings{}, err
	}
	kind, err = normalizedScopeKind(kind)
	if err != nil {
		return Settings{}, err
	}
	environment, err := environmentScope(ctx)
	if err != nil {
		return Settings{}, err
	}
	owner, err := resourceScope(ctx, kind)
	if err != nil {
		return Settings{}, err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, pluginID))
	defer unlock()
	binding, err := s.getBinding(ctx, pluginID)
	if err != nil {
		return Settings{}, err
	}
	workspace, manifest, err := s.workspaceForBinding(environment, binding)
	if err != nil {
		return Settings{}, err
	}
	if err := s.ensureWorkspaceScope(ctx, workspace.root, manifest.Shape, owner, nil); err != nil {
		return Settings{}, err
	}
	document, err := readSettings(workspaceSettingsPath(workspace.root, owner))
	if err != nil {
		return Settings{}, err
	}
	if !document.Scope.Matches(owner) {
		return Settings{}, ErrDatasetCorrupt
	}
	return Settings{Scope: kind, Revision: document.Revision, Values: cloneRawMap(document.Values)}, nil
}

func (s *FileStore) PatchSettings(ctx context.Context, req PatchSettingsRequest) (Settings, error) {
	release, err := s.begin()
	if err != nil {
		return Settings{}, err
	}
	defer release()
	pluginID, err := normalizeIdentifier("plugin instance ID", req.PluginInstanceID)
	if err != nil {
		return Settings{}, err
	}
	kind, err := normalizedScopeKind(req.Scope)
	if err != nil {
		return Settings{}, err
	}
	environment, err := environmentScope(ctx)
	if err != nil {
		return Settings{}, err
	}
	owner, err := resourceScope(ctx, kind)
	if err != nil {
		return Settings{}, err
	}
	unlock := s.locks.lockWrite(scopedLockKey(environment, pluginID))
	defer unlock()
	binding, err := s.getBinding(ctx, pluginID)
	if err != nil {
		return Settings{}, err
	}
	if binding.State != BindingActive {
		return Settings{}, fmt.Errorf("%w: %s", ErrNotActive, pluginID)
	}
	workspace, manifest, err := s.workspaceForBinding(environment, binding)
	if err != nil {
		return Settings{}, err
	}
	allowed := make(map[string]struct{}, len(manifest.Shape.Settings.Fields))
	declared := make(map[string]sessionctx.ScopeKind, len(manifest.Shape.Settings.Fields))
	for _, field := range manifest.Shape.Settings.Fields {
		fieldScope := sessionctx.ScopeKind(field.Scope)
		declared[field.Key] = fieldScope
		if fieldScope == kind {
			allowed[field.Key] = struct{}{}
		}
	}
	if err := s.ensureWorkspaceScope(ctx, workspace.root, manifest.Shape, owner, nil); err != nil {
		return Settings{}, err
	}
	path := workspaceSettingsPath(workspace.root, owner)
	document, err := readSettings(path)
	if err != nil {
		return Settings{}, err
	}
	if !document.Scope.Matches(owner) {
		return Settings{}, ErrDatasetCorrupt
	}
	if req.ExpectedValuesRevision == 0 || req.ExpectedValuesRevision != document.Revision {
		return Settings{}, fmt.Errorf("%w: expected %d, actual %d", ErrRevisionConflict, req.ExpectedValuesRevision, document.Revision)
	}
	removeSet := make(map[string]struct{}, len(req.Remove))
	for _, key := range req.Remove {
		if _, exists := removeSet[key]; exists {
			return Settings{}, fmt.Errorf("%w: duplicate remove key %s", ErrInvalidArgument, key)
		}
		removeSet[key] = struct{}{}
		if _, overlaps := req.Set[key]; overlaps {
			return Settings{}, fmt.Errorf("%w: setting %s appears in both set and remove", ErrInvalidArgument, key)
		}
	}
	for key, raw := range req.Set {
		if _, ok := allowed[key]; !ok {
			if declaredScope, exists := declared[key]; exists && declaredScope != kind {
				return Settings{}, fmt.Errorf("%w: setting %s is declared for %s scope", ErrSettingScopeMismatch, key, declaredScope)
			}
			return Settings{}, fmt.Errorf("%w: %s", ErrUnknownSetting, key)
		}
		normalized, err := normalizeRawJSON(raw)
		if err != nil {
			return Settings{}, fmt.Errorf("%w: setting %s: %v", ErrInvalidArgument, key, err)
		}
		document.Values[key] = normalized
	}
	for _, key := range req.Remove {
		if _, ok := allowed[key]; !ok {
			if declaredScope, exists := declared[key]; exists && declaredScope != kind {
				return Settings{}, fmt.Errorf("%w: setting %s is declared for %s scope", ErrSettingScopeMismatch, key, declaredScope)
			}
			return Settings{}, fmt.Errorf("%w: %s", ErrUnknownSetting, key)
		}
		delete(document.Values, key)
	}
	document.Values, err = settingsdomain.NormalizeRawValues(settingsFieldsForScope(manifest.Shape.Settings.Fields, kind), document.Values)
	if err != nil {
		return Settings{}, err
	}
	document.Revision++
	if err := writeSettingsWithSync(path, document, s.ops.syncDir); err != nil {
		return Settings{}, err
	}
	return Settings{Scope: kind, Revision: document.Revision, Values: cloneRawMap(document.Values)}, nil
}

func (s *FileStore) getBinding(ctx context.Context, pluginInstanceID string) (Binding, error) {
	pluginID, err := normalizeIdentifier("plugin instance ID", pluginInstanceID)
	if err != nil {
		return Binding{}, err
	}
	binding, found, err := s.catalog.GetBinding(ctx, pluginID)
	if err != nil {
		return Binding{}, fmt.Errorf("read plugin data binding: %w", err)
	}
	if !found {
		return Binding{}, fmt.Errorf("%w: %s", ErrBindingNotFound, pluginID)
	}
	return cloneBinding(binding), nil
}

func (s *FileStore) workspaceForBinding(environment sessionctx.ResourceScope, binding Binding) (workspace, datasetManifest, error) {
	if err := validateBinding(binding); err != nil {
		return workspace{}, datasetManifest{}, err
	}
	if err := environment.Validate(); err != nil || environment.Kind != sessionctx.ScopeEnvironment {
		return workspace{}, datasetManifest{}, ErrDatasetCorrupt
	}
	root := s.scopedWorkspacePath(environment, binding.GenerationID)
	manifest, err := readDatasetManifest(filepath.Join(root, datasetManifestName))
	if err != nil {
		return workspace{}, datasetManifest{}, err
	}
	if manifest.GenerationID != binding.GenerationID || manifest.OwnerEnvHash != environment.OwnerEnvHash {
		return workspace{}, datasetManifest{}, fmt.Errorf("%w: catalog binding does not match generation", ErrDatasetCorrupt)
	}
	if manifest.ShapeHash != binding.ShapeHash {
		return workspace{}, datasetManifest{}, fmt.Errorf("%w: catalog shape does not match generation", ErrDatasetCorrupt)
	}
	return s.workspaceForManifest(environment, binding, manifest), manifest, nil
}

func (s *FileStore) workspaceForManifest(environment sessionctx.ResourceScope, binding Binding, manifest datasetManifest) workspace {
	root := s.scopedWorkspacePath(environment, binding.GenerationID)
	return workspace{binding: cloneBinding(binding), root: root, shape: cloneShape(manifest.Shape)}
}

func (s *FileStore) finalizeWorkspace(ctx context.Context, stage, generationID string, shape Shape, environment sessionctx.ResourceScope) (datasetManifest, error) {
	if err := environment.Validate(); err != nil || environment.Kind != sessionctx.ScopeEnvironment {
		return datasetManifest{}, ErrDatasetCorrupt
	}
	manifest := datasetManifest{GenerationID: generationID, OwnerEnvHash: environment.OwnerEnvHash, CreatedAt: s.now(), Shape: cloneShape(shape), ShapeHash: shapeHash(shape)}
	if err := writeJSON(filepath.Join(stage, datasetManifestName), manifest); err != nil {
		return datasetManifest{}, err
	}
	if err := validateWorkspaceContents(ctx, stage, manifest); err != nil {
		return datasetManifest{}, err
	}
	if _, err := hashTree(stage, ""); err != nil {
		return datasetManifest{}, err
	}
	if err := syncTree(stage); err != nil {
		return datasetManifest{}, err
	}
	return manifest, nil
}

func (s *FileStore) validateObject(ctx context.Context, owner sessionctx.ResourceScope, objectID string) (string, Object, datasetManifest, error) {
	catalogObject, found, err := s.catalog.GetObject(ctx, objectID)
	if err != nil {
		return "", Object{}, datasetManifest{}, err
	}
	if !found {
		return "", Object{}, datasetManifest{}, fmt.Errorf("%w: %s", ErrExportNotFound, objectID)
	}
	if err := validateObjectMetadata(catalogObject); err != nil {
		return "", Object{}, datasetManifest{}, err
	}
	object := s.scopedObjectPath(owner, objectID)
	var exported exportManifest
	if err := readJSON(filepath.Join(object, exportManifestName), &exported); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", Object{}, datasetManifest{}, fmt.Errorf("%w: %s", ErrExportNotFound, objectID)
		}
		return "", Object{}, datasetManifest{}, err
	}
	if exported.ObjectID != objectID || !exported.Scope.Matches(owner) || exported.ContentHash != catalogObject.ContentHash || exported.ShapeHash != catalogObject.ShapeHash {
		return "", Object{}, datasetManifest{}, fmt.Errorf("%w: export catalog metadata mismatch", ErrDatasetCorrupt)
	}
	payload := filepath.Join(object, exportPayloadName)
	if err := validateExportableWorkspace(ctx, payload); err != nil {
		return "", Object{}, datasetManifest{}, err
	}
	hash, err := hashTree(payload, "")
	if err != nil {
		return "", Object{}, datasetManifest{}, err
	}
	if hash != exported.ContentHash {
		return "", Object{}, datasetManifest{}, fmt.Errorf("%w: export content hash mismatch", ErrDatasetCorrupt)
	}
	manifest, err := readDatasetManifest(filepath.Join(payload, datasetManifestName))
	if err != nil {
		return "", Object{}, datasetManifest{}, err
	}
	return object, catalogObject, manifest, nil
}

func validateObjectMetadata(object Object) error {
	if object.ObjectID == "" || object.SizeBytes <= 0 || object.CreatedAt.IsZero() || !canonicalHash(object.ContentHash) || !canonicalHash(object.ShapeHash) {
		return fmt.Errorf("%w: invalid export object metadata", ErrDatasetCorrupt)
	}
	return nil
}

func canonicalHash(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateExportableWorkspace(ctx context.Context, root string) error {
	manifest, err := readDatasetManifest(filepath.Join(root, datasetManifestName))
	if err != nil {
		return err
	}
	return validateWorkspaceContents(ctx, root, manifest)
}

func (s *FileStore) createExportPayload(ctx context.Context, source, destination string, user sessionctx.ResourceScope, manifest datasetManifest) error {
	if err := s.ensureWorkspaceScope(ctx, source, manifest.Shape, user, nil); err != nil {
		return err
	}
	if err := s.ops.copyDir(source, destination); err != nil {
		return fmt.Errorf("copy export dataset: %w", err)
	}
	usersRoot := filepath.Join(destination, workspaceScopesDirName, workspaceUsersDirName)
	if err := os.RemoveAll(usersRoot); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(usersRoot); err != nil {
		return err
	}
	userDestination := workspaceScopeRoot(destination, user)
	if err := s.ops.copyDir(workspaceScopeRoot(source, user), userDestination); err != nil {
		return fmt.Errorf("copy user-scoped export data: %w", err)
	}
	return validateExportableWorkspace(ctx, destination)
}

func (s *FileStore) createImportedWorkspace(ctx context.Context, currentWorkspace, payloadRoot, stage string, user sessionctx.ResourceScope) error {
	if err := validateExportableWorkspace(ctx, payloadRoot); err != nil {
		return err
	}
	if currentWorkspace == "" {
		if err := s.ops.copyDir(payloadRoot, stage); err != nil {
			return fmt.Errorf("copy imported dataset: %w", err)
		}
		return nil
	}
	if err := s.ops.copyDir(currentWorkspace, stage); err != nil {
		return fmt.Errorf("copy current dataset: %w", err)
	}
	for _, scope := range []sessionctx.ResourceScope{
		{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: user.OwnerEnvHash},
		user,
	} {
		target := workspaceScopeRoot(stage, scope)
		if err := os.RemoveAll(target); err != nil {
			return err
		}
		if err := s.ops.copyDir(workspaceScopeRoot(payloadRoot, scope), target); err != nil {
			return fmt.Errorf("merge imported %s data: %w", scope.Kind, err)
		}
	}
	return nil
}

func (s *FileStore) publishStage(stage, destination string) error {
	parent := filepath.Dir(destination)
	if err := ensurePrivateDirectory(parent); err != nil {
		return fmt.Errorf("prepare immutable dataset parent: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("%w: destination already exists", ErrBindingConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := s.ops.rename(stage, destination); err != nil {
		return fmt.Errorf("publish immutable dataset: %w", err)
	}
	if err := s.ops.syncDir(parent); err != nil {
		return s.rollbackPublishedDirectory(destination, parent, mutation.Unknown(fmt.Errorf("sync immutable dataset parent: %w", err)))
	}
	return nil
}

func (s *FileStore) removePublishedDirectory(path, parent string) error {
	workspaceOwnersRoot := filepath.Join(s.workspacesRoot(), environmentOwnersDirName)
	if relative, err := filepath.Rel(workspaceOwnersRoot, path); err == nil {
		parts := strings.Split(relative, string(filepath.Separator))
		if len(parts) == 2 && parts[0] != ".." {
			environment := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: parts[0]}
			if environment.Validate() == nil {
				if err := s.closeNamespaceDatabases(generationCachePrefix(environment.OwnerEnvHash, parts[1])); err != nil {
					return mutation.Unknown(fmt.Errorf("close published plugin data databases: %w", err))
				}
			}
		}
	}
	if err := s.ops.removeAll(path); err != nil {
		return mutation.Unknown(fmt.Errorf("remove published plugin data: %w", err))
	}
	if err := s.ops.syncDir(parent); err != nil {
		return mutation.Unknown(fmt.Errorf("sync published plugin data parent: %w", err))
	}
	return nil
}

func (s *FileStore) rollbackPublishedDirectory(path, parent string, cause error) error {
	if err := s.removePublishedDirectory(path, parent); err != nil {
		return mutation.Unknown(errors.Join(cause, fmt.Errorf("roll back unpublished plugin data: %w", err)))
	}
	return cause
}

// collectAfterCommit runs under publicationMu after the requested catalog mutation commits.
func (s *FileStore) collectAfterCommit(ctx context.Context) error {
	if err := s.collectUnreferenced(ctx); err != nil {
		return mutation.Unknown(fmt.Errorf("collect unreferenced plugin data: %w", err))
	}
	return nil
}

func (s *FileStore) newStage(kind string) (string, error) {
	path, err := os.MkdirTemp(s.stagingRoot(), kind+"-")
	if err != nil {
		return "", fmt.Errorf("create plugin data staging directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		os.RemoveAll(path)
		return "", err
	}
	return path, nil
}

func (s *FileStore) cleanupOnOpen(ctx context.Context) error {
	if err := removeDirectoryContents(s.stagingRoot()); err != nil {
		return fmt.Errorf("clean plugin data staging directory: %w", err)
	}
	bindings, err := s.listAllBindingsForMaintenance(ctx)
	if err != nil {
		return fmt.Errorf("read plugin data catalog during reopen: %w", err)
	}
	for _, item := range bindings {
		if err := validateMaintenanceBinding(item); err != nil {
			return err
		}
		if _, _, err := s.workspaceForBinding(item.Scope, item.Binding); err != nil {
			return err
		}
	}
	objects, err := s.listAllObjectsForMaintenance(ctx)
	if err != nil {
		return err
	}
	for _, item := range objects {
		if err := validateMaintenanceObject(item); err != nil {
			return err
		}
		object := item.Object
		var manifest exportManifest
		if err := readJSON(filepath.Join(s.scopedObjectPath(item.Scope, object.ObjectID), exportManifestName), &manifest); err != nil {
			return fmt.Errorf("%w: missing export object %s", ErrDatasetCorrupt, object.ObjectID)
		}
		if manifest.ObjectID != object.ObjectID || !manifest.Scope.Matches(item.Scope) || manifest.ContentHash != object.ContentHash || manifest.ShapeHash != object.ShapeHash {
			return fmt.Errorf("%w: export object metadata mismatch", ErrDatasetCorrupt)
		}
	}
	return s.collectUnreferenced(ctx)
}

func (s *FileStore) collectUnreferenced(ctx context.Context) error {
	bindings, err := s.listAllBindingsForMaintenance(ctx)
	if err != nil {
		return err
	}
	referencedWorkspaces := make(map[string]struct{}, len(bindings))
	for _, item := range bindings {
		if err := validateMaintenanceBinding(item); err != nil {
			return err
		}
		referencedWorkspaces[persistentPathKey(item.Scope.OwnerEnvHash, item.Binding.GenerationID)] = struct{}{}
	}
	objects, err := s.listAllObjectsForMaintenance(ctx)
	if err != nil {
		return err
	}
	referencedObjects := make(map[string]struct{}, len(objects))
	for _, item := range objects {
		if err := validateMaintenanceObject(item); err != nil {
			return err
		}
		referencedObjects[persistentPathKey(item.Scope.OwnerEnvHash, item.Scope.OwnerUserHash, item.Object.ObjectID)] = struct{}{}
	}
	if err := s.removeUnreferencedWorkspaces(referencedWorkspaces); err != nil {
		return err
	}
	return s.removeUnreferencedObjects(referencedObjects)
}

func (s *FileStore) removeUnreferencedWorkspaces(referenced map[string]struct{}) error {
	ownersRoot := filepath.Join(s.workspacesRoot(), environmentOwnersDirName)
	owners, err := os.ReadDir(ownersRoot)
	if err != nil {
		return err
	}
	for _, ownerEntry := range owners {
		scope := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: ownerEntry.Name()}
		if ownerEntry.Type()&os.ModeSymlink != 0 || !ownerEntry.IsDir() || scope.Validate() != nil {
			return fmt.Errorf("%w: invalid workspace owner %s", ErrUnsafeFilesystem, ownerEntry.Name())
		}
		ownerRoot := filepath.Join(ownersRoot, ownerEntry.Name())
		generations, err := os.ReadDir(ownerRoot)
		if err != nil {
			return err
		}
		for _, generation := range generations {
			if generation.Type()&os.ModeSymlink != 0 || !generation.IsDir() || !identifierPattern.MatchString(generation.Name()) {
				return fmt.Errorf("%w: invalid workspace entry %s", ErrUnsafeFilesystem, generation.Name())
			}
			if _, ok := referenced[persistentPathKey(scope.OwnerEnvHash, generation.Name())]; ok {
				continue
			}
			if err := s.removePublishedDirectory(filepath.Join(ownerRoot, generation.Name()), ownerRoot); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *FileStore) removeUnreferencedObjects(referenced map[string]struct{}) error {
	environmentsRoot := filepath.Join(s.objectsRoot(), userOwnersDirName)
	environments, err := os.ReadDir(environmentsRoot)
	if err != nil {
		return err
	}
	for _, environmentEntry := range environments {
		if environmentEntry.Type()&os.ModeSymlink != 0 || !environmentEntry.IsDir() {
			return fmt.Errorf("%w: invalid object environment owner", ErrUnsafeFilesystem)
		}
		usersRoot := filepath.Join(environmentsRoot, environmentEntry.Name())
		users, err := os.ReadDir(usersRoot)
		if err != nil {
			return err
		}
		for _, userEntry := range users {
			scope := sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: environmentEntry.Name(), OwnerUserHash: userEntry.Name()}
			if userEntry.Type()&os.ModeSymlink != 0 || !userEntry.IsDir() || scope.Validate() != nil {
				return fmt.Errorf("%w: invalid object user owner", ErrUnsafeFilesystem)
			}
			userRoot := filepath.Join(usersRoot, userEntry.Name())
			objects, err := os.ReadDir(userRoot)
			if err != nil {
				return err
			}
			for _, object := range objects {
				if object.Type()&os.ModeSymlink != 0 || !object.IsDir() || !identifierPattern.MatchString(object.Name()) {
					return fmt.Errorf("%w: invalid object entry %s", ErrUnsafeFilesystem, object.Name())
				}
				if _, ok := referenced[persistentPathKey(scope.OwnerEnvHash, scope.OwnerUserHash, object.Name())]; ok {
					continue
				}
				if err := s.removePublishedDirectory(filepath.Join(userRoot, object.Name()), userRoot); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *FileStore) listAllBindings(ctx context.Context) ([]Binding, error) {
	var result []Binding
	cursor := ""
	for {
		page, next, err := s.catalog.ListBindings(ctx, cursor, 256)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if next == "" {
			return result, nil
		}
		if next <= cursor {
			return nil, fmt.Errorf("%w: binding catalog cursor did not advance", ErrDatasetCorrupt)
		}
		cursor = next
	}
}

func (s *FileStore) listAllObjects(ctx context.Context) ([]Object, error) {
	var result []Object
	cursor := ""
	for {
		page, next, err := s.catalog.ListObjects(ctx, cursor, 256)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if next == "" {
			return result, nil
		}
		if next <= cursor {
			return nil, fmt.Errorf("%w: object catalog cursor did not advance", ErrDatasetCorrupt)
		}
		cursor = next
	}
}

func (s *FileStore) listAllBindingsForMaintenance(ctx context.Context) ([]MaintenanceBinding, error) {
	var result []MaintenanceBinding
	cursor := ""
	for {
		page, next, err := s.catalog.ListAllBindingsForMaintenance(ctx, cursor, 256)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if next == "" {
			return result, nil
		}
		if next <= cursor {
			return nil, fmt.Errorf("%w: binding maintenance cursor did not advance", ErrDatasetCorrupt)
		}
		cursor = next
	}
}

func (s *FileStore) listAllObjectsForMaintenance(ctx context.Context) ([]MaintenanceObject, error) {
	var result []MaintenanceObject
	cursor := ""
	for {
		page, next, err := s.catalog.ListAllObjectsForMaintenance(ctx, cursor, 256)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if next == "" {
			return result, nil
		}
		if next <= cursor {
			return nil, fmt.Errorf("%w: object maintenance cursor did not advance", ErrDatasetCorrupt)
		}
		cursor = next
	}
}

func validateMaintenanceBinding(item MaintenanceBinding) error {
	if err := item.Scope.Validate(); err != nil || item.Scope.Kind != sessionctx.ScopeEnvironment {
		return fmt.Errorf("%w: invalid binding owner scope", ErrDatasetCorrupt)
	}
	return validateBinding(item.Binding)
}

func validateMaintenanceObject(item MaintenanceObject) error {
	if err := item.Scope.Validate(); err != nil || item.Scope.Kind != sessionctx.ScopeUser {
		return fmt.Errorf("%w: invalid object owner scope", ErrDatasetCorrupt)
	}
	return validateObjectMetadata(item.Object)
}

func normalizeEnable(req CommitEnableRequest) (string, Shape, map[string]json.RawMessage, error) {
	pluginID, err := normalizeIdentifier("plugin instance ID", req.PluginInstanceID)
	if err != nil {
		return "", Shape{}, nil, err
	}
	shape, err := normalizeShape(req.Shape)
	if err != nil {
		return "", Shape{}, nil, err
	}
	allowed := make(map[string]struct{}, len(shape.Settings.Fields))
	for _, field := range shape.Settings.Fields {
		allowed[field.Key] = struct{}{}
	}
	settings := make(map[string]json.RawMessage, len(req.InitialSettings))
	for key, raw := range req.InitialSettings {
		if _, ok := allowed[key]; !ok {
			return "", Shape{}, nil, fmt.Errorf("%w: %s", ErrUnknownSetting, key)
		}
		normalized, err := normalizeRawJSON(raw)
		if err != nil {
			return "", Shape{}, nil, fmt.Errorf("%w: setting %s: %v", ErrInvalidArgument, key, err)
		}
		settings[key] = normalized
	}
	settings, err = settingsdomain.NormalizeRawValues(shape.Settings.Fields, settings)
	if err != nil {
		return "", Shape{}, nil, err
	}
	return pluginID, shape, settings, nil
}

func normalizeShape(shape Shape) (Shape, error) {
	publisherID, err := normalizeIdentifier("publisher ID", shape.PublisherID)
	if err != nil {
		return Shape{}, err
	}
	pluginID := strings.TrimSpace(shape.PluginID)
	if pluginID == "" || strings.ContainsAny(pluginID, "\x00\r\n") {
		return Shape{}, fmt.Errorf("%w: invalid plugin ID", ErrInvalidArgument)
	}
	canonicalSettings, err := settingsdomain.CanonicalizeSchema(shape.Settings)
	if err != nil {
		return Shape{}, fmt.Errorf("%w: invalid non-secret settings contract", ErrInvalidArgument)
	}
	namespaces := slices.Clone(shape.Namespaces)
	for i := range namespaces {
		normalized, err := normalizeIdentifier("namespace ID", namespaces[i].ID)
		if err != nil {
			return Shape{}, err
		}
		namespaces[i].ID = normalized
		if err := validateNamespace(namespaces[i]); err != nil {
			return Shape{}, err
		}
	}
	slices.SortFunc(namespaces, func(a, b Namespace) int { return strings.Compare(a.ID, b.ID) })
	for i := 1; i < len(namespaces); i++ {
		if namespaces[i-1].ID == namespaces[i].ID {
			return Shape{}, fmt.Errorf("%w: duplicate namespace ID %s", ErrInvalidArgument, namespaces[i].ID)
		}
	}
	return Shape{PublisherID: publisherID, PluginID: pluginID, Settings: canonicalSettings, Namespaces: namespaces}, nil
}

func shapeHash(shape Shape) string {
	raw, _ := json.Marshal(shape)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func HashShape(shape Shape) (string, error) {
	normalized, err := normalizeShape(shape)
	if err != nil {
		return "", err
	}
	return shapeHash(normalized), nil
}

func cloneShape(shape Shape) Shape {
	raw, _ := json.Marshal(shape)
	var cloned Shape
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func initializeWorkspaceScopes(ctx context.Context, root string, shape Shape, environment, user sessionctx.ResourceScope, initialSettings map[string]json.RawMessage) error {
	for _, scope := range []sessionctx.ResourceScope{environment, user} {
		if err := initializeWorkspaceScope(ctx, workspaceScopeRoot(root, scope), shape, scope, initialSettings); err != nil {
			return err
		}
	}
	return nil
}

func (s *FileStore) ensureWorkspaceScope(ctx context.Context, root string, shape Shape, scope sessionctx.ResourceScope, initialSettings map[string]json.RawMessage) error {
	target, err := s.ensureWorkspaceScopeRoot(ctx, root, shape, scope, initialSettings)
	if err != nil {
		return err
	}
	return validateWorkspaceScope(ctx, target, shape, scope)
}

func (s *FileStore) ensureWorkspaceScopeMetadata(ctx context.Context, root string, shape Shape, scope sessionctx.ResourceScope) error {
	target, err := s.ensureWorkspaceScopeRoot(ctx, root, shape, scope, nil)
	if err != nil {
		return err
	}
	return validateWorkspaceScopeMetadata(target, shape, scope)
}

func (s *FileStore) ensureWorkspaceScopeRoot(ctx context.Context, root string, shape Shape, scope sessionctx.ResourceScope, initialSettings map[string]json.RawMessage) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}
	target := workspaceScopeRoot(root, scope)
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("%w: invalid workspace scope root", ErrUnsafeFilesystem)
		}
		return target, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(target)
	if err := ensurePrivateDirectory(parent); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(parent, ".scope-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return "", err
	}
	if err := initializeWorkspaceScope(ctx, stage, shape, scope, initialSettings); err != nil {
		return "", err
	}
	if err := syncTree(stage); err != nil {
		return "", err
	}
	if err := os.Rename(stage, target); err != nil {
		return "", err
	}
	if err := s.ops.syncDir(parent); err != nil {
		return "", mutation.Unknown(err)
	}
	return target, nil
}

func initializeWorkspaceScope(ctx context.Context, root string, shape Shape, scope sessionctx.ResourceScope, initialSettings map[string]json.RawMessage) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return err
	}
	fields := settingsFieldsForScope(shape.Settings.Fields, scope.Kind)
	values, err := settingsdomain.DefaultValues(fields)
	if err != nil {
		return err
	}
	for key, value := range initialSettings {
		for _, field := range fields {
			if field.Key == key {
				values[key] = bytes.Clone(value)
				break
			}
		}
	}
	if err := writeSettings(filepath.Join(root, settingsFileName), settingsDocument{Scope: scope, Revision: 1, Values: values}); err != nil {
		return err
	}
	return createNamespaces(ctx, root, scope, namespacesForScope(shape.Namespaces, scope.Kind))
}

func settingsFieldsForScope(fields []settingsdomain.Field, kind sessionctx.ScopeKind) []settingsdomain.Field {
	result := make([]settingsdomain.Field, 0, len(fields))
	for _, field := range fields {
		if sessionctx.ScopeKind(field.Scope) == kind {
			result = append(result, field)
		}
	}
	return result
}

func namespacesForScope(namespaces []Namespace, kind sessionctx.ScopeKind) []Namespace {
	result := make([]Namespace, 0, len(namespaces))
	for _, namespace := range namespaces {
		if sessionctx.ScopeKind(namespace.Scope) == kind {
			result = append(result, namespace)
		}
	}
	return result
}

func validateWorkspaceContents(ctx context.Context, root string, manifest datasetManifest) error {
	if err := validateTree(root); err != nil {
		return err
	}
	environment := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: manifest.OwnerEnvHash}
	if err := environment.Validate(); err != nil {
		return fmt.Errorf("%w: invalid dataset owner", ErrDatasetCorrupt)
	}
	scopesRoot := filepath.Join(root, workspaceScopesDirName)
	entries, err := os.ReadDir(scopesRoot)
	if err != nil {
		return fmt.Errorf("read dataset scopes: %w", err)
	}
	if len(entries) != 2 || entries[0].Name() != environmentOwnersDirName || entries[1].Name() != workspaceUsersDirName {
		return fmt.Errorf("%w: workspace scope roots do not match the owner layout", ErrDatasetCorrupt)
	}
	if err := validateWorkspaceScope(ctx, workspaceScopeRoot(root, environment), manifest.Shape, environment); err != nil {
		return err
	}
	userEntries, err := os.ReadDir(filepath.Join(scopesRoot, workspaceUsersDirName))
	if err != nil {
		return err
	}
	for _, entry := range userEntries {
		user := sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: manifest.OwnerEnvHash, OwnerUserHash: entry.Name()}
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() || user.Validate() != nil {
			return fmt.Errorf("%w: invalid user workspace scope", ErrUnsafeFilesystem)
		}
		if err := validateWorkspaceScope(ctx, filepath.Join(scopesRoot, workspaceUsersDirName, entry.Name()), manifest.Shape, user); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkspaceScope(ctx context.Context, root string, shape Shape, scope sessionctx.ResourceScope) error {
	if err := validateWorkspaceScopeMetadata(root, shape, scope); err != nil {
		return err
	}
	for _, namespace := range namespacesForScope(shape.Namespaces, scope.Kind) {
		dataRoot := filepath.Join(root, namespacesDirName, namespace.ID, namespaceDataName)
		var usage namespaceUsage
		var err error
		if namespace.Kind == NamespaceFiles || namespace.Kind == NamespaceKV {
			usage, err = validateNamespaceDatabase(ctx, dataRoot, namespace.Kind)
		} else {
			usage, err = scanNamespaceUsage(dataRoot)
		}
		if err != nil {
			return err
		}
		if usage.bytes > namespace.QuotaBytes || (namespace.QuotaFiles > 0 && usage.files > namespace.QuotaFiles) {
			return fmt.Errorf("%w: namespace %s exceeds declared quota", ErrDatasetCorrupt, namespace.ID)
		}
	}
	return nil
}

func validateWorkspaceScopeMetadata(root string, shape Shape, scope sessionctx.ResourceScope) error {
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("%w: invalid workspace scope", ErrDatasetCorrupt)
	}
	document, err := readSettings(filepath.Join(root, settingsFileName))
	if err != nil {
		return err
	}
	if !document.Scope.Matches(scope) {
		return fmt.Errorf("%w: settings owner scope mismatch", ErrDatasetCorrupt)
	}
	if _, err := settingsdomain.NormalizeRawValues(settingsFieldsForScope(shape.Settings.Fields, scope.Kind), document.Values); err != nil {
		return fmt.Errorf("%w: %v", ErrDatasetCorrupt, err)
	}
	namespaces := namespacesForScope(shape.Namespaces, scope.Kind)
	namespaceRoot := filepath.Join(root, namespacesDirName)
	if info, err := os.Lstat(namespaceRoot); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: invalid namespace root", ErrUnsafeFilesystem)
	}
	entries, err := os.ReadDir(namespaceRoot)
	if err != nil {
		return fmt.Errorf("read dataset namespaces: %w", err)
	}
	if len(entries) != len(namespaces) {
		return fmt.Errorf("%w: namespace count mismatch", ErrDatasetCorrupt)
	}
	for _, namespace := range namespaces {
		base := filepath.Join(namespaceRoot, namespace.ID)
		if info, err := os.Lstat(base); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: invalid namespace directory %s", ErrUnsafeFilesystem, namespace.ID)
		}
		baseEntries, err := os.ReadDir(base)
		if err != nil {
			return err
		}
		if len(baseEntries) != 2 || baseEntries[0].Name() != namespaceDataName || baseEntries[1].Name() != namespaceMetaName {
			return fmt.Errorf("%w: namespace layout mismatch for %s", ErrDatasetCorrupt, namespace.ID)
		}
		var stored namespaceDocument
		if err := readJSON(filepath.Join(base, namespaceMetaName), &stored); err != nil {
			return err
		}
		if !stored.Scope.Matches(scope) || stored.Namespace != namespace {
			return fmt.Errorf("%w: namespace metadata mismatch for %s", ErrDatasetCorrupt, namespace.ID)
		}
		info, err := os.Lstat(filepath.Join(base, namespaceDataName))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: namespace data directory %s", ErrDatasetCorrupt, namespace.ID)
		}
	}
	return nil
}

type namespaceUsage struct {
	bytes int64
	files int64
}

func scanNamespaceUsage(root string) (namespaceUsage, error) {
	var usage namespaceUsage
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !validPathRegular(path, info)) {
			return fmt.Errorf("%w: unsafe namespace entry %s", ErrUnsafeFilesystem, path)
		}
		usage.files++
		if info.Mode().IsRegular() {
			usage.bytes += info.Size()
		}
		return nil
	})
	return usage, err
}

func createNamespaces(ctx context.Context, root string, scope sessionctx.ResourceScope, namespaces []Namespace) error {
	base := filepath.Join(root, namespacesDirName)
	if err := ensurePrivateDirectory(base); err != nil {
		return err
	}
	for _, namespace := range namespaces {
		nsRoot := filepath.Join(base, namespace.ID)
		dataRoot := filepath.Join(nsRoot, namespaceDataName)
		if err := ensurePrivateDirectory(dataRoot); err != nil {
			return err
		}
		if err := initializeNamespaceDatabase(ctx, dataRoot, namespace.Kind); err != nil {
			return fmt.Errorf("initialize namespace %s: %w", namespace.ID, err)
		}
		if sessionctx.ScopeKind(namespace.Scope) != scope.Kind {
			return ErrStorageScopeMismatch
		}
		if err := writeJSON(filepath.Join(nsRoot, namespaceMetaName), namespaceDocument{Scope: scope, Namespace: namespace}); err != nil {
			return err
		}
	}
	return nil
}

func validateNamespace(namespace Namespace) error {
	switch namespace.Kind {
	case NamespaceFiles, NamespaceKV, NamespaceSQLite:
	default:
		return fmt.Errorf("%w: unsupported namespace kind %q", ErrInvalidArgument, namespace.Kind)
	}
	if namespace.Scope != "user" && namespace.Scope != "environment" {
		return fmt.Errorf("%w: invalid namespace scope", ErrInvalidArgument)
	}
	if namespace.SchemaVersion <= 0 || namespace.QuotaBytes <= 0 || namespace.QuotaFiles < 0 {
		return fmt.Errorf("%w: namespace quota is invalid", ErrInvalidArgument)
	}
	return nil
}

func validateBinding(binding Binding) error {
	if _, err := normalizeIdentifier("plugin instance ID", binding.PluginInstanceID); err != nil {
		return err
	}
	if _, err := normalizeIdentifier("generation ID", binding.GenerationID); err != nil {
		return err
	}
	if binding.Revision == 0 {
		return fmt.Errorf("%w: incomplete catalog binding", ErrDatasetCorrupt)
	}
	switch binding.State {
	case BindingActive:
		if binding.RetainedAt != nil || binding.ExpiresAt != nil {
			return fmt.Errorf("%w: active binding contains retention state", ErrDatasetCorrupt)
		}
	case BindingRetained:
		if binding.RetainedAt == nil {
			return fmt.Errorf("%w: retained binding has no retention time", ErrDatasetCorrupt)
		}
	default:
		return fmt.Errorf("%w: unknown binding state %q", ErrDatasetCorrupt, binding.State)
	}
	return nil
}

func readDatasetManifest(path string) (datasetManifest, error) {
	var manifest datasetManifest
	if err := readJSON(path, &manifest); err != nil {
		return datasetManifest{}, err
	}
	if _, err := normalizeIdentifier("generation ID", manifest.GenerationID); err != nil {
		return datasetManifest{}, fmt.Errorf("%w: %v", ErrDatasetCorrupt, err)
	}
	if err := (sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: manifest.OwnerEnvHash}).Validate(); err != nil {
		return datasetManifest{}, fmt.Errorf("%w: invalid dataset owner", ErrDatasetCorrupt)
	}
	if manifest.CreatedAt.IsZero() {
		return datasetManifest{}, fmt.Errorf("%w: missing dataset creation time", ErrDatasetCorrupt)
	}
	normalized, err := normalizeShape(manifest.Shape)
	if err != nil || shapeHash(normalized) != shapeHash(manifest.Shape) {
		return datasetManifest{}, fmt.Errorf("%w: dataset shape is not canonical", ErrDatasetCorrupt)
	}
	if manifest.ShapeHash != shapeHash(manifest.Shape) {
		return datasetManifest{}, fmt.Errorf("%w: dataset shape hash mismatch", ErrDatasetCorrupt)
	}
	return manifest, nil
}

func writeSettings(path string, document settingsDocument) error {
	if document.Values == nil {
		document.Values = map[string]json.RawMessage{}
	}
	return writeJSON(path, document)
}

func writeSettingsWithSync(path string, document settingsDocument, syncDir func(string) error) error {
	if document.Values == nil {
		document.Values = map[string]json.RawMessage{}
	}
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileWithSync(path, data, 0o600, syncDir)
}

func readSettings(path string) (settingsDocument, error) {
	var document settingsDocument
	if err := readJSON(path, &document); err != nil {
		return settingsDocument{}, err
	}
	if document.Revision == 0 || document.Values == nil {
		return settingsDocument{}, fmt.Errorf("%w: invalid settings document", ErrDatasetCorrupt)
	}
	if err := document.Scope.Validate(); err != nil {
		return settingsDocument{}, fmt.Errorf("%w: invalid settings owner scope", ErrDatasetCorrupt)
	}
	for key, raw := range document.Values {
		if _, err := normalizeIdentifier("setting key", key); err != nil {
			return settingsDocument{}, fmt.Errorf("%w: %v", ErrDatasetCorrupt, err)
		}
		normalized, err := normalizeRawJSON(raw)
		if err != nil {
			return settingsDocument{}, fmt.Errorf("%w: invalid setting %s", ErrDatasetCorrupt, key)
		}
		document.Values[key] = normalized
	}
	return document, nil
}

func normalizeIdentifier(label, value string) (string, error) {
	value = strings.TrimSpace(value)
	if !identifierPattern.MatchString(value) || value == "." || value == ".." {
		return "", fmt.Errorf("%w: invalid %s", ErrInvalidArgument, label)
	}
	return value, nil
}

func normalizeRawJSON(raw json.RawMessage) (json.RawMessage, error) {
	if !json.Valid(raw) {
		return nil, errors.New("value is not valid JSON")
	}
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, raw); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.Clone(buffer.Bytes())), nil
}

func cloneBinding(binding Binding) Binding {
	binding.RetainedAt = cloneTime(binding.RetainedAt)
	binding.ExpiresAt = cloneTime(binding.ExpiresAt)
	return binding
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneRawMap(values map[string]json.RawMessage) map[string]json.RawMessage {
	cloned := make(map[string]json.RawMessage, len(values))
	for key, value := range values {
		cloned[key] = bytes.Clone(value)
	}
	return cloned
}

func newID(prefix string) (string, error) {
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", fmt.Errorf("generate plugin data ID: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(random[:]), nil
}

func (l *keyedLocks) lockRead(key string) func() {
	return l.lock(key, false)
}

func (l *keyedLocks) lockWrite(key string) func() {
	return l.lock(key, true)
}

func (l *keyedLocks) lock(key string, write bool) func() {
	return l.lockManyMode(write, key)
}

func (l *keyedLocks) lockMany(keys ...string) func() {
	return l.lockManyMode(true, keys...)
}

func (l *keyedLocks) lockManyMode(write bool, keys ...string) func() {
	keys = slices.Clone(keys)
	slices.Sort(keys)
	keys = slices.Compact(keys)
	acquired := make([]struct {
		key  string
		lock *keyedLock
	}, 0, len(keys))
	for _, key := range keys {
		l.mu.Lock()
		lock := l.locks[key]
		if lock == nil {
			lock = &keyedLock{}
			l.locks[key] = lock
		}
		lock.refs++
		l.mu.Unlock()
		if write {
			lock.mu.Lock()
		} else {
			lock.mu.RLock()
		}
		acquired = append(acquired, struct {
			key  string
			lock *keyedLock
		}{key: key, lock: lock})
	}
	return func() {
		for i := len(acquired) - 1; i >= 0; i-- {
			item := acquired[i]
			if write {
				item.lock.mu.Unlock()
			} else {
				item.lock.mu.RUnlock()
			}
			l.mu.Lock()
			item.lock.refs--
			if item.lock.refs == 0 {
				delete(l.locks, item.key)
			}
			l.mu.Unlock()
		}
	}
}

func (s *FileStore) workspacesRoot() string { return filepath.Join(s.root, workspacesDirName) }
func (s *FileStore) objectsRoot() string    { return filepath.Join(s.root, objectsDirName) }
func (s *FileStore) stagingRoot() string    { return filepath.Join(s.root, stagingDirName) }
