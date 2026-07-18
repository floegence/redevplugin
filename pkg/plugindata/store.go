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
	CreatedAt    time.Time `json:"created_at"`
	Shape        Shape     `json:"shape"`
	ShapeHash    string    `json:"shape_hash"`
}

type settingsDocument struct {
	Revision uint64                     `json:"revision"`
	Values   map[string]json.RawMessage `json:"values"`
}

type exportManifest struct {
	ObjectID    string    `json:"object_id"`
	ContentHash string    `json:"content_hash"`
	ShapeHash   string    `json:"shape_hash"`
	CreatedAt   time.Time `json:"created_at"`
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
	for _, path := range []string{store.workspacesRoot(), store.objectsRoot(), store.stagingRoot()} {
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
	unlock := s.locks.lockWrite(pluginID)
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
		_, manifest, err := s.workspaceForBinding(existing)
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
		if err := writeSettings(filepath.Join(stage, settingsFileName), settingsDocument{Revision: 1, Values: initialSettings}); err != nil {
			return Dataset{}, err
		}
		if err := createNamespaces(ctx, stage, shape.Namespaces); err != nil {
			return Dataset{}, err
		}
		manifest, err := s.finalizeWorkspace(stage, generationID, shape)
		if err != nil {
			return Dataset{}, err
		}
		publishedWorkspace = s.workspacePath(generationID)
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
			cause = s.rollbackPublishedDirectory(publishedWorkspace, s.workspacesRoot(), cause)
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
	unlock := s.locks.lockWrite(pluginID)
	defer unlock()
	binding, err := s.getBinding(ctx, pluginID)
	if err != nil {
		return Export{}, err
	}
	if binding.State != BindingActive {
		return Export{}, fmt.Errorf("%w: %s", ErrNotActive, pluginID)
	}
	workspace, manifest, err := s.workspaceForBinding(binding)
	if err != nil {
		return Export{}, err
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
	if err := s.ops.copyDir(workspace.root, payload); err != nil {
		return Export{}, fmt.Errorf("copy export dataset: %w", err)
	}
	if err := validateExportableWorkspace(payload); err != nil {
		return Export{}, err
	}
	contentHash, err := hashTree(payload, "")
	if err != nil {
		return Export{}, err
	}
	createdAt := s.now()
	if err := writeJSON(filepath.Join(stage, exportManifestName), exportManifest{ObjectID: objectID, ContentHash: contentHash, ShapeHash: manifest.ShapeHash, CreatedAt: createdAt}); err != nil {
		return Export{}, err
	}
	if err := validateTree(stage); err != nil {
		return Export{}, err
	}
	if err := syncTree(stage); err != nil {
		return Export{}, err
	}
	destination := s.objectPath(objectID)
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	if err := s.publishStage(stage, destination); err != nil {
		return Export{}, err
	}
	size, err := directorySize(destination)
	if err != nil {
		return Export{}, s.rollbackPublishedDirectory(destination, s.objectsRoot(), err)
	}
	object := Object{ObjectID: objectID, ContentHash: contentHash, ShapeHash: manifest.ShapeHash, SizeBytes: size, CreatedAt: createdAt}
	if err := s.catalog.CreateObject(ctx, object); err != nil {
		return Export{}, s.rollbackPublishedDirectory(destination, s.objectsRoot(), fmt.Errorf("publish export object: %w", err))
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
	unlock := s.objectLocks.lockWrite(objectID)
	defer unlock()
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	if err := s.catalog.DeleteObject(ctx, objectID); err != nil {
		return err
	}
	if err := s.removePublishedDirectory(s.objectPath(objectID), s.objectsRoot()); err != nil {
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
	unlock := s.locks.lockWrite(pluginID)
	defer unlock()
	objectUnlock := s.objectLocks.lockRead(objectID)
	defer objectUnlock()

	current, found, err := s.catalog.GetBinding(ctx, pluginID)
	if err != nil {
		return Dataset{}, fmt.Errorf("read import target binding: %w", err)
	}
	if found && current.State != BindingActive {
		return Dataset{}, fmt.Errorf("%w: %s", ErrNotActive, pluginID)
	}
	object, catalogObject, sourceManifest, err := s.validateObject(ctx, objectID)
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
	if err := s.ops.copyDir(filepath.Join(object, exportPayloadName), stage); err != nil {
		return Dataset{}, fmt.Errorf("copy imported dataset: %w", err)
	}
	copiedHash, err := hashTree(stage, "")
	if err != nil {
		return Dataset{}, err
	}
	if copiedHash != catalogObject.ContentHash {
		return Dataset{}, fmt.Errorf("%w: export changed while importing", ErrDatasetCorrupt)
	}
	generationID, err := newID("gen")
	if err != nil {
		return Dataset{}, err
	}
	manifest, err := s.finalizeWorkspace(stage, generationID, expectedShape)
	if err != nil {
		return Dataset{}, err
	}
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	publishedWorkspace := s.workspacePath(generationID)
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
		return Dataset{}, s.rollbackPublishedDirectory(publishedWorkspace, s.workspacesRoot(), fmt.Errorf("publish imported dataset: %w", err))
	}
	if found && current.GenerationID != generationID {
		if err := s.removePublishedDirectory(s.workspacePath(current.GenerationID), s.workspacesRoot()); err != nil {
			s.dropGenerationUsage(current.GenerationID)
			return Dataset{}, err
		}
		s.dropGenerationUsage(current.GenerationID)
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
	unlock := s.locks.lockMany(sourceID, targetID)
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
	_, sourceManifest, err := s.workspaceForBinding(sourceBinding)
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
	unlock := s.locks.lockWrite(pluginID)
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
	if err := s.removePublishedDirectory(s.workspacePath(current.GenerationID), s.workspacesRoot()); err != nil {
		s.dropGenerationUsage(current.GenerationID)
		return err
	}
	s.dropGenerationUsage(current.GenerationID)
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
	unlock := s.locks.lockWrite(pluginID)
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
		if err := s.removePublishedDirectory(s.workspacePath(current.GenerationID), s.workspacesRoot()); err != nil {
			s.dropGenerationUsage(current.GenerationID)
			return CommitUninstallResult{}, err
		}
		s.dropGenerationUsage(current.GenerationID)
	}
	if req.DeleteData {
		if err := s.collectAfterCommit(ctx); err != nil {
			return CommitUninstallResult{}, err
		}
	}
	return result, nil
}

func (s *FileStore) dropGenerationUsage(generationID string) {
	prefix := generationID + "\x00"
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
	for _, binding := range bindings {
		if binding.State == BindingRetained && binding.ExpiresAt != nil && !binding.ExpiresAt.After(now) {
			candidates = append(candidates, binding)
			keys = append(keys, binding.PluginInstanceID)
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
		if err := s.removePublishedDirectory(s.workspacePath(binding.GenerationID), s.workspacesRoot()); err != nil {
			removalErr = errors.Join(removalErr, err)
		}
		s.dropGenerationUsage(binding.GenerationID)
	}
	if removalErr != nil {
		return result, mutation.Unknown(removalErr)
	}
	if err := s.collectAfterCommit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

func (s *FileStore) GetSettings(ctx context.Context, pluginInstanceID string) (Settings, error) {
	release, err := s.begin()
	if err != nil {
		return Settings{}, err
	}
	defer release()
	pluginID, err := normalizeIdentifier("plugin instance ID", pluginInstanceID)
	if err != nil {
		return Settings{}, err
	}
	unlock := s.locks.lockRead(pluginID)
	defer unlock()
	binding, err := s.getBinding(ctx, pluginID)
	if err != nil {
		return Settings{}, err
	}
	document, err := readSettings(filepath.Join(s.workspacePath(binding.GenerationID), settingsFileName))
	if err != nil {
		return Settings{}, err
	}
	return Settings{Revision: document.Revision, Values: cloneRawMap(document.Values)}, nil
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
	unlock := s.locks.lockWrite(pluginID)
	defer unlock()
	binding, err := s.getBinding(ctx, pluginID)
	if err != nil {
		return Settings{}, err
	}
	if binding.State != BindingActive {
		return Settings{}, fmt.Errorf("%w: %s", ErrNotActive, pluginID)
	}
	_, manifest, err := s.workspaceForBinding(binding)
	if err != nil {
		return Settings{}, err
	}
	allowed := make(map[string]struct{}, len(manifest.Shape.Settings.Fields))
	for _, field := range manifest.Shape.Settings.Fields {
		allowed[field.Key] = struct{}{}
	}
	path := filepath.Join(s.workspacePath(binding.GenerationID), settingsFileName)
	document, err := readSettings(path)
	if err != nil {
		return Settings{}, err
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
			return Settings{}, fmt.Errorf("%w: %s", ErrUnknownSetting, key)
		}
		delete(document.Values, key)
	}
	document.Revision++
	if err := writeSettingsWithSync(path, document, s.ops.syncDir); err != nil {
		return Settings{}, err
	}
	return Settings{Revision: document.Revision, Values: cloneRawMap(document.Values)}, nil
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

func (s *FileStore) workspaceForBinding(binding Binding) (workspace, datasetManifest, error) {
	if err := validateBinding(binding); err != nil {
		return workspace{}, datasetManifest{}, err
	}
	manifest, err := readDatasetManifest(filepath.Join(s.workspacePath(binding.GenerationID), datasetManifestName))
	if err != nil {
		return workspace{}, datasetManifest{}, err
	}
	if manifest.GenerationID != binding.GenerationID {
		return workspace{}, datasetManifest{}, fmt.Errorf("%w: catalog binding does not match generation", ErrDatasetCorrupt)
	}
	if manifest.ShapeHash != binding.ShapeHash {
		return workspace{}, datasetManifest{}, fmt.Errorf("%w: catalog shape does not match generation", ErrDatasetCorrupt)
	}
	return s.workspaceForManifest(binding, manifest), manifest, nil
}

func (s *FileStore) workspaceForManifest(binding Binding, manifest datasetManifest) workspace {
	root := s.workspacePath(binding.GenerationID)
	return workspace{binding: cloneBinding(binding), root: root, shape: cloneShape(manifest.Shape)}
}

func (s *FileStore) finalizeWorkspace(stage, generationID string, shape Shape) (datasetManifest, error) {
	manifest := datasetManifest{GenerationID: generationID, CreatedAt: s.now(), Shape: cloneShape(shape), ShapeHash: shapeHash(shape)}
	if err := writeJSON(filepath.Join(stage, datasetManifestName), manifest); err != nil {
		return datasetManifest{}, err
	}
	if err := validateWorkspaceContents(stage, shape.Settings.Fields, shape.Namespaces); err != nil {
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

func (s *FileStore) validateObject(ctx context.Context, objectID string) (string, Object, datasetManifest, error) {
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
	object := s.objectPath(objectID)
	var exported exportManifest
	if err := readJSON(filepath.Join(object, exportManifestName), &exported); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", Object{}, datasetManifest{}, fmt.Errorf("%w: %s", ErrExportNotFound, objectID)
		}
		return "", Object{}, datasetManifest{}, err
	}
	if exported.ObjectID != objectID || exported.ContentHash != catalogObject.ContentHash || exported.ShapeHash != catalogObject.ShapeHash {
		return "", Object{}, datasetManifest{}, fmt.Errorf("%w: export catalog metadata mismatch", ErrDatasetCorrupt)
	}
	payload := filepath.Join(object, exportPayloadName)
	if err := validateExportableWorkspace(payload); err != nil {
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

func validateExportableWorkspace(root string) error {
	manifest, err := readDatasetManifest(filepath.Join(root, datasetManifestName))
	if err != nil {
		return err
	}
	return validateWorkspaceContents(root, manifest.Shape.Settings.Fields, manifest.Shape.Namespaces)
}

func (s *FileStore) publishStage(stage, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("%w: destination already exists", ErrBindingConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := s.ops.rename(stage, destination); err != nil {
		return fmt.Errorf("publish immutable dataset: %w", err)
	}
	if err := s.ops.syncDir(filepath.Dir(destination)); err != nil {
		return s.rollbackPublishedDirectory(destination, filepath.Dir(destination), mutation.Unknown(fmt.Errorf("sync immutable dataset parent: %w", err)))
	}
	return nil
}

func (s *FileStore) removePublishedDirectory(path, parent string) error {
	if filepath.Clean(parent) == filepath.Clean(s.workspacesRoot()) {
		if err := s.closeNamespaceDatabases(filepath.Base(path)); err != nil {
			return mutation.Unknown(fmt.Errorf("close published plugin data databases: %w", err))
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
	bindings, err := s.listAllBindings(ctx)
	if err != nil {
		return fmt.Errorf("read plugin data catalog during reopen: %w", err)
	}
	for _, binding := range bindings {
		if err := validateBinding(binding); err != nil {
			return err
		}
		if _, _, err := s.workspaceForBinding(binding); err != nil {
			return err
		}
	}
	objects, err := s.listAllObjects(ctx)
	if err != nil {
		return err
	}
	for _, object := range objects {
		if err := validateObjectMetadata(object); err != nil {
			return err
		}
		var manifest exportManifest
		if err := readJSON(filepath.Join(s.objectPath(object.ObjectID), exportManifestName), &manifest); err != nil {
			return fmt.Errorf("%w: missing export object %s", ErrDatasetCorrupt, object.ObjectID)
		}
		if manifest.ObjectID != object.ObjectID || manifest.ContentHash != object.ContentHash || manifest.ShapeHash != object.ShapeHash {
			return fmt.Errorf("%w: export object metadata mismatch", ErrDatasetCorrupt)
		}
	}
	return s.collectUnreferenced(ctx)
}

func (s *FileStore) collectUnreferenced(ctx context.Context) error {
	bindings, err := s.listAllBindings(ctx)
	if err != nil {
		return err
	}
	referencedWorkspaces := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if err := validateBinding(binding); err != nil {
			return err
		}
		referencedWorkspaces[binding.GenerationID] = struct{}{}
	}
	objects, err := s.listAllObjects(ctx)
	if err != nil {
		return err
	}
	referencedObjects := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		if err := validateObjectMetadata(object); err != nil {
			return err
		}
		referencedObjects[object.ObjectID] = struct{}{}
	}
	if err := s.removeUnreferencedDirectories(s.workspacesRoot(), "workspace", referencedWorkspaces); err != nil {
		return err
	}
	return s.removeUnreferencedDirectories(s.objectsRoot(), "object", referencedObjects)
}

func (s *FileStore) removeUnreferencedDirectories(root, kind string, referenced map[string]struct{}) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() || !identifierPattern.MatchString(entry.Name()) {
			return fmt.Errorf("%w: invalid %s entry %s", ErrUnsafeFilesystem, kind, entry.Name())
		}
		if _, ok := referenced[entry.Name()]; ok {
			continue
		}
		if err := s.removePublishedDirectory(filepath.Join(root, entry.Name()), root); err != nil {
			return err
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

func validateWorkspaceContents(root string, fields []settingsdomain.Field, namespaces []Namespace) error {
	if err := validateTree(root); err != nil {
		return err
	}
	document, err := readSettings(filepath.Join(root, settingsFileName))
	if err != nil {
		return err
	}
	if _, err := settingsdomain.NormalizeRawValues(fields, document.Values); err != nil {
		return fmt.Errorf("%w: %v", ErrDatasetCorrupt, err)
	}
	namespaceRoot := filepath.Join(root, namespacesDirName)
	entries, err := os.ReadDir(namespaceRoot)
	if err != nil {
		return fmt.Errorf("read dataset namespaces: %w", err)
	}
	if len(entries) != len(namespaces) {
		return fmt.Errorf("%w: namespace count mismatch", ErrDatasetCorrupt)
	}
	for _, namespace := range namespaces {
		base := filepath.Join(namespaceRoot, namespace.ID)
		var stored Namespace
		if err := readJSON(filepath.Join(base, namespaceMetaName), &stored); err != nil {
			return err
		}
		if stored != namespace {
			return fmt.Errorf("%w: namespace metadata mismatch for %s", ErrDatasetCorrupt, namespace.ID)
		}
		info, err := os.Lstat(filepath.Join(base, namespaceDataName))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: namespace data directory %s", ErrDatasetCorrupt, namespace.ID)
		}
		dataRoot := filepath.Join(base, namespaceDataName)
		var usage namespaceUsage
		if namespace.Kind == NamespaceFiles || namespace.Kind == NamespaceKV {
			usage, err = validateNamespaceDatabase(context.Background(), dataRoot, namespace.Kind)
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

func createNamespaces(ctx context.Context, root string, namespaces []Namespace) error {
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
		if err := writeJSON(filepath.Join(nsRoot, namespaceMetaName), namespace); err != nil {
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

func (s *FileStore) workspacesRoot() string         { return filepath.Join(s.root, workspacesDirName) }
func (s *FileStore) objectsRoot() string            { return filepath.Join(s.root, objectsDirName) }
func (s *FileStore) stagingRoot() string            { return filepath.Join(s.root, stagingDirName) }
func (s *FileStore) workspacePath(id string) string { return filepath.Join(s.workspacesRoot(), id) }
func (s *FileStore) objectPath(id string) string    { return filepath.Join(s.objectsRoot(), id) }
