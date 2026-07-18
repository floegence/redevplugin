package plugindata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	settingsdomain "github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
)

func internalTestContext() context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "owner_session_test",
		OwnerUserHash:        "owner_user_test",
		OwnerEnvHash:         "owner_env_test",
		SessionChannelIDHash: "channel_test",
	})
}

func internalEnvironmentScope() sessionctx.ResourceScope {
	return sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "owner_env_test"}
}

func internalUserScope() sessionctx.ResourceScope {
	return sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "owner_env_test", OwnerUserHash: "owner_user_test"}
}

type internalCatalog struct {
	binding         *Binding
	objects         map[string]Object
	commitEnableErr error
	swapImportErr   error
	createObjectErr error
}

func (c *internalCatalog) GetBinding(_ context.Context, pluginInstanceID string) (Binding, bool, error) {
	if c.binding == nil || c.binding.PluginInstanceID != pluginInstanceID {
		return Binding{}, false, nil
	}
	return cloneBinding(*c.binding), true, nil
}
func (c *internalCatalog) ListBindings(context.Context, string, int) ([]Binding, string, error) {
	if c.binding == nil {
		return nil, "", nil
	}
	return []Binding{cloneBinding(*c.binding)}, "", nil
}
func (c *internalCatalog) ListAllBindingsForMaintenance(ctx context.Context, cursor string, limit int) ([]MaintenanceBinding, string, error) {
	bindings, next, err := c.ListBindings(ctx, cursor, limit)
	items := make([]MaintenanceBinding, 0, len(bindings))
	for _, binding := range bindings {
		items = append(items, MaintenanceBinding{Scope: internalEnvironmentScope(), Binding: binding})
	}
	return items, next, err
}
func (c *internalCatalog) CommitEnable(_ context.Context, _ uint64, _ *Binding, next Binding, _ Shape, _ time.Time) error {
	if c.commitEnableErr != nil {
		return c.commitEnableErr
	}
	c.binding = &next
	return nil
}
func (c *internalCatalog) SwapImport(_ context.Context, _ uint64, _ *Binding, next Binding, _ Shape, _ time.Time) error {
	if c.swapImportErr != nil {
		return c.swapImportErr
	}
	c.binding = &next
	return nil
}
func (c *internalCatalog) BindRetained(_ context.Context, expected Binding, target string, _ uint64, _ Shape, _ time.Time) (Binding, error) {
	expected.PluginInstanceID = target
	expected.State = BindingActive
	expected.Revision++
	expected.RetainedAt = nil
	expected.ExpiresAt = nil
	c.binding = &expected
	return expected, nil
}
func (c *internalCatalog) DeleteRetained(context.Context, Binding) error { c.binding = nil; return nil }
func (c *internalCatalog) CleanupExpired(_ context.Context, _ time.Time, expected []Binding) ([]Binding, error) {
	if c.binding == nil {
		return nil, nil
	}
	for _, candidate := range expected {
		if candidate.PluginInstanceID == c.binding.PluginInstanceID && candidate.GenerationID == c.binding.GenerationID && candidate.Revision == c.binding.Revision {
			deleted := cloneBinding(*c.binding)
			c.binding = nil
			return []Binding{deleted}, nil
		}
	}
	return nil, nil
}
func (c *internalCatalog) CommitUninstall(_ context.Context, req CommitUninstallRequest) (CommitUninstallResult, error) {
	if req.DeleteData {
		c.binding = nil
	} else if c.binding != nil {
		now := req.Now
		c.binding.State = BindingRetained
		c.binding.Revision++
		c.binding.RetainedAt = &now
		c.binding.ExpiresAt = nil
		if req.RetainUntil != nil {
			expiresAt := *req.RetainUntil
			c.binding.ExpiresAt = &expiresAt
		}
	}
	return CommitUninstallResult{ManagementRevision: req.ExpectedManagementRevision + 1, RevokeEpoch: 1, DeletedAt: req.Now}, nil
}
func (c *internalCatalog) GetObject(_ context.Context, _ sessionctx.ScopeKind, pluginInstanceID, id string) (Object, bool, error) {
	object, ok := c.objects[persistentPathKey(pluginInstanceID, id)]
	return object, ok, nil
}
func (c *internalCatalog) ListObjects(_ context.Context, _ sessionctx.ScopeKind, pluginInstanceID, cursor string, limit int) ([]Object, string, error) {
	objects := make([]Object, 0, len(c.objects))
	for _, object := range c.objects {
		if object.PluginInstanceID == pluginInstanceID {
			objects = append(objects, object)
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ObjectID < objects[j].ObjectID })
	start := sort.Search(len(objects), func(i int) bool { return objects[i].ObjectID > cursor })
	objects = objects[start:]
	if limit > 0 && len(objects) > limit {
		return objects[:limit], objects[limit-1].ObjectID, nil
	}
	return objects, "", nil
}
func (c *internalCatalog) ListAllObjectsForMaintenance(ctx context.Context, cursor string, limit int) ([]MaintenanceObject, string, error) {
	objects := make([]Object, 0, len(c.objects))
	for _, object := range c.objects {
		objects = append(objects, object)
	}
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].PluginInstanceID == objects[j].PluginInstanceID {
			return objects[i].ObjectID < objects[j].ObjectID
		}
		return objects[i].PluginInstanceID < objects[j].PluginInstanceID
	})
	start := sort.Search(len(objects), func(i int) bool { return persistentPathKey(objects[i].PluginInstanceID, objects[i].ObjectID) > cursor })
	objects = objects[start:]
	next := ""
	if limit > 0 && len(objects) > limit {
		objects = objects[:limit]
		last := objects[len(objects)-1]
		next = persistentPathKey(last.PluginInstanceID, last.ObjectID)
	}
	items := make([]MaintenanceObject, 0, len(objects))
	for _, object := range objects {
		items = append(items, MaintenanceObject{Scope: internalUserScope(), Object: object})
	}
	return items, next, nil
}
func (c *internalCatalog) CreateObject(_ context.Context, _ sessionctx.ScopeKind, object Object) error {
	if c.createObjectErr != nil {
		return c.createObjectErr
	}
	c.objects[persistentPathKey(object.PluginInstanceID, object.ObjectID)] = object
	return nil
}
func (c *internalCatalog) DeleteObject(_ context.Context, _ sessionctx.ScopeKind, pluginInstanceID, id string) error {
	key := persistentPathKey(pluginInstanceID, id)
	if _, ok := c.objects[key]; !ok {
		return ErrExportNotFound
	}
	delete(c.objects, key)
	return nil
}

func TestWriteFileReportsUnknownAfterRenameSyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	errSentinel := errors.New("sync failed")
	err := writeFileWithSync(path, []byte("{}\n"), 0o600, func(string) error { return errSentinel })
	if outcome := mutation.ForError(err); outcome != mutation.OutcomeUnknown {
		t.Fatalf("outcome = %q, err = %v", outcome, err)
	}
	if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "{}\n" {
		t.Fatalf("committed file = %q, err = %v", data, readErr)
	}
}

func TestKeyedLocksAllowIndependentNamespaceProgress(t *testing.T) {
	locks := keyedLocks{locks: map[string]*keyedLock{}}
	releaseFiles := locks.lock("generation\x00files", true)
	done := make(chan struct{})
	go func() {
		releaseKV := locks.lock("generation\x00kv", true)
		releaseKV()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("independent namespace lock was blocked")
	}
	releaseFiles()
}

func TestBrokerAllowsIndependentNamespaceProgress(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	if _, err := store.CommitEnable(internalTestContext(), CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	binding, _, _ := catalog.GetBinding(internalTestContext(), "plugini_test")
	owner, err := resourceScope(internalTestContext(), sessionctx.ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	releaseFiles := store.namespaceLocks.lock(scopedNamespaceCacheKey(owner, binding.GenerationID, "files"), true)
	kvDone := make(chan error, 1)
	go func() {
		_, err := store.PutKV(internalTestContext(), storage.KVPutRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Key: "ready", Value: []byte("yes")})
		kvDone <- err
	}()
	select {
	case err := <-kvDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("independent KV namespace was blocked by files namespace")
	}
	fileDone := make(chan error, 1)
	go func() {
		_, err := store.WriteFile(internalTestContext(), storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "blocked", Data: []byte("x")})
		fileDone <- err
	}()
	select {
	case err := <-fileDone:
		t.Fatalf("files operation bypassed namespace lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	releaseFiles()
	if err := <-fileDone; err != nil {
		t.Fatal(err)
	}
}

func TestBrokerPersistsNamespaceTransactionsAcrossReopen(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, InitialSettings: map[string]json.RawMessage{}, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	fileWrite, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "notes/committed.txt", Data: []byte("committed")})
	if err != nil || fileWrite.Usage.UsageBytes != 9 || fileWrite.Usage.UsageFiles != 2 {
		t.Fatalf("WriteFile() = %#v, err = %v", fileWrite, err)
	}
	kvWrite, err := store.PutKV(ctx, storage.KVPutRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Key: "committed", Value: []byte("value")})
	if err != nil || kvWrite.Usage.UsageBytes != 5 || kvWrite.Usage.UsageFiles != 1 {
		t.Fatalf("PutKV() = %#v, err = %v", kvWrite, err)
	}
	root := store.root
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, root, catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	data, err := reopened.ReadFile(ctx, storage.FileReadRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "notes/committed.txt"})
	if err != nil || string(data.Data) != "committed" || data.Usage.UsageFiles != 2 {
		t.Fatalf("ReadFile() after reopen = %#v, err = %v", data, err)
	}
	value, err := reopened.GetKV(ctx, storage.KVGetRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Key: "committed"})
	if err != nil || string(value.Value) != "value" || value.Usage.UsageFiles != 1 {
		t.Fatalf("GetKV() after reopen = %#v, err = %v", value, err)
	}
}

func TestCloseWaitsForInFlightExportAndRejectsFutureCalls(t *testing.T) {
	store, _, shape := newInternalStore(t)
	if _, err := store.CommitEnable(internalTestContext(), CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	originalCopy := store.ops.copyDir
	started := make(chan struct{})
	releaseCopy := make(chan struct{})
	var blockFirstCopy sync.Once
	store.ops.copyDir = func(source, destination string) error {
		blockFirstCopy.Do(func() {
			close(started)
			<-releaseCopy
		})
		return originalCopy(source, destination)
	}
	exportDone := make(chan error, 1)
	go func() {
		_, err := store.Export(internalTestContext(), ExportRequest{PluginInstanceID: "plugini_test"})
		exportDone <- err
	}()
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close() returned before export completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseCopy)
	if err := <-exportDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSettings(internalTestContext(), "plugini_test", sessionctx.ScopeUser); err == nil {
		t.Fatal("closed store accepted GetSettings")
	}
}

func TestExportPreservesCallerCancellationDuringWorkspaceValidation(t *testing.T) {
	store, _, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Export(canceled, ExportRequest{PluginInstanceID: "plugini_test"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Export() error = %v, want context.Canceled", err)
	}
}

func TestWorkspaceSnapshotRejectsSettingsMutationBeforeSemanticValidation(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	binding, found, err := catalog.GetBinding(ctx, "plugini_test")
	if err != nil || !found {
		t.Fatalf("GetBinding() found = %v, err = %v", found, err)
	}
	workspace, manifest, err := store.workspaceForBinding(internalEnvironmentScope(), binding)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotRootedTree(workspace.root, rootedTreeSnapshotOptions{hashContents: true})
	if err != nil {
		t.Fatal(err)
	}
	settingsPath := workspaceSettingsPath(workspace.root, internalUserScope())
	settingsBytes, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(settingsBytes, []byte(`"revision":1`), []byte(`"revision":2`), 1)
	if bytes.Equal(mutated, settingsBytes) || len(mutated) != len(settingsBytes) {
		t.Fatal("settings fixture did not support a same-size valid mutation")
	}
	if err := os.WriteFile(settingsPath, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	changedAt := time.Now().Add(time.Hour)
	if err := os.Chtimes(settingsPath, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkspaceContentsSnapshot(ctx, workspace.root, manifest, snapshot); !errors.Is(err, ErrUnsafeFilesystem) {
		t.Fatalf("validateWorkspaceContentsSnapshot() error = %v, want ErrUnsafeFilesystem", err)
	}
}

func TestExportReportsSnapshotHashAndPhysicalSize(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "notes/value.txt", Data: []byte("snapshot-value")}); err != nil {
		t.Fatal(err)
	}
	exported, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
	if err != nil {
		t.Fatal(err)
	}
	objectRoot := store.scopedObjectPath(internalUserScope(), "plugini_test", exported.ObjectID)
	wantHash, err := referenceHashTree(filepath.Join(objectRoot, exportPayloadName), "")
	if err != nil {
		t.Fatal(err)
	}
	wantSize, err := regularFileTreeSize(objectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if exported.ContentHash != wantHash || exported.SizeBytes != wantSize {
		t.Fatalf("Export() = {hash:%q size:%d}, want {hash:%q size:%d}", exported.ContentHash, exported.SizeBytes, wantHash, wantSize)
	}
	object, found, err := catalog.GetObject(ctx, sessionctx.ScopeUser, "plugini_test", exported.ObjectID)
	if err != nil || !found {
		t.Fatalf("GetObject() found = %v, err = %v", found, err)
	}
	if object.ContentHash != wantHash || object.SizeBytes != wantSize {
		t.Fatalf("catalog object = {hash:%q size:%d}, want {hash:%q size:%d}", object.ContentHash, object.SizeBytes, wantHash, wantSize)
	}
}

func regularFileTreeSize(root string) (int64, error) {
	var size int64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func TestImportAndExportDeletionReclaimPublishedObjects(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	oldBinding, _, _ := catalog.GetBinding(ctx, "plugini_test")
	if _, err := store.WriteFile(ctx, storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "data.txt", Data: []byte("data")}); err != nil {
		t.Fatal(err)
	}
	exported, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(ctx, ImportRequest{PluginInstanceID: "plugini_test", ObjectID: exported.ObjectID, ExpectedShape: shape, ExpectedManagementRevision: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.scopedWorkspacePath(internalEnvironmentScope(), oldBinding.GenerationID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale generation remains after import: %v", err)
	}
	if err := store.DeleteExport(ctx, DeleteExportRequest{PluginInstanceID: "plugini_test", ObjectID: exported.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.scopedObjectPath(internalUserScope(), "plugini_test", exported.ObjectID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted export object remains: %v", err)
	}
}

func TestDeleteRetainedWaitsForReaderLeaseBeforeRemovingWorkspace(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUninstall(ctx, CommitUninstallRequest{PluginInstanceID: "plugini_test", ExpectedManagementRevision: 2, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	binding, found, err := catalog.GetBinding(ctx, "plugini_test")
	if err != nil || !found {
		t.Fatalf("retained binding found = %v, err = %v", found, err)
	}
	workspace := store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID)
	releaseReader := store.locks.lockRead(scopedLockKey(internalEnvironmentScope(), binding.PluginInstanceID))
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- store.DeleteRetained(ctx, DeleteRetainedRequest{
			PluginInstanceID:        binding.PluginInstanceID,
			ExpectedBindingRevision: binding.Revision,
		})
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("DeleteRetained() bypassed reader lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := os.Stat(workspace); err != nil {
		t.Fatalf("workspace disappeared while reader lease was active: %v", err)
	}
	releaseReader()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(workspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace remains after retained deletion: %v", err)
	}
}

func TestImportWaitsForReaderLeaseBeforeReplacingGeneration(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	oldBinding, _, _ := catalog.GetBinding(ctx, "plugini_test")
	exported, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
	if err != nil {
		t.Fatal(err)
	}
	releaseReader := store.locks.lockRead(scopedLockKey(internalEnvironmentScope(), oldBinding.PluginInstanceID))
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := store.Import(ctx, ImportRequest{
			PluginInstanceID:           oldBinding.PluginInstanceID,
			ObjectID:                   exported.ObjectID,
			ExpectedShape:              shape,
			ExpectedManagementRevision: 2,
		})
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("Import() bypassed reader lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := os.Stat(store.scopedWorkspacePath(internalEnvironmentScope(), oldBinding.GenerationID)); err != nil {
		t.Fatalf("old generation disappeared while reader lease was active: %v", err)
	}
	releaseReader()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.scopedWorkspacePath(internalEnvironmentScope(), oldBinding.GenerationID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old generation remains after import: %v", err)
	}
}

func TestCommittedDeletionFailuresAreUnknownAndCollectorConverges(t *testing.T) {
	t.Run("delete retained", func(t *testing.T) {
		store, catalog, shape := newInternalStore(t)
		ctx := internalTestContext()
		if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CommitUninstall(ctx, CommitUninstallRequest{PluginInstanceID: "plugini_test", ExpectedManagementRevision: 2, Now: time.Now()}); err != nil {
			t.Fatal(err)
		}
		binding, _, _ := catalog.GetBinding(ctx, "plugini_test")
		assertDeletionFailureConverges(t, store, store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID), func() error {
			return store.DeleteRetained(ctx, DeleteRetainedRequest{PluginInstanceID: binding.PluginInstanceID, ExpectedBindingRevision: binding.Revision})
		})
	})

	t.Run("uninstall delete", func(t *testing.T) {
		store, catalog, shape := newInternalStore(t)
		ctx := internalTestContext()
		if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
			t.Fatal(err)
		}
		binding, _, _ := catalog.GetBinding(ctx, "plugini_test")
		assertDeletionFailureConverges(t, store, store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID), func() error {
			_, err := store.CommitUninstall(ctx, CommitUninstallRequest{PluginInstanceID: binding.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: 2, Now: time.Now()})
			return err
		})
	})

	t.Run("cleanup expired", func(t *testing.T) {
		store, catalog, shape := newInternalStore(t)
		ctx := internalTestContext()
		now := time.Now().UTC()
		expiresAt := now.Add(time.Minute)
		if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CommitUninstall(ctx, CommitUninstallRequest{PluginInstanceID: "plugini_test", ExpectedManagementRevision: 2, RetainUntil: &expiresAt, Now: now}); err != nil {
			t.Fatal(err)
		}
		binding, _, _ := catalog.GetBinding(ctx, "plugini_test")
		assertDeletionFailureConverges(t, store, store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID), func() error {
			result, err := store.CleanupExpired(ctx, expiresAt.Add(time.Second))
			if len(result.Deleted) != 1 || result.Deleted[0].GenerationID != binding.GenerationID {
				t.Fatalf("CleanupExpired() result = %#v", result)
			}
			return err
		})
	})

	t.Run("delete export", func(t *testing.T) {
		store, _, shape := newInternalStore(t)
		ctx := internalTestContext()
		if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
			t.Fatal(err)
		}
		exported, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
		if err != nil {
			t.Fatal(err)
		}
		assertDeletionFailureConverges(t, store, store.scopedObjectPath(internalUserScope(), "plugini_test", exported.ObjectID), func() error {
			return store.DeleteExport(ctx, DeleteExportRequest{PluginInstanceID: "plugini_test", ObjectID: exported.ObjectID})
		})
	})

	t.Run("import replacement", func(t *testing.T) {
		store, catalog, shape := newInternalStore(t)
		ctx := internalTestContext()
		if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
			t.Fatal(err)
		}
		oldBinding, _, _ := catalog.GetBinding(ctx, "plugini_test")
		exported, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
		if err != nil {
			t.Fatal(err)
		}
		assertDeletionFailureConverges(t, store, store.scopedWorkspacePath(internalEnvironmentScope(), oldBinding.GenerationID), func() error {
			_, err := store.Import(ctx, ImportRequest{PluginInstanceID: "plugini_test", ObjectID: exported.ObjectID, ExpectedShape: shape, ExpectedManagementRevision: 2})
			return err
		})
		current, found, err := catalog.GetBinding(ctx, "plugini_test")
		if err != nil || !found || current.GenerationID == oldBinding.GenerationID {
			t.Fatalf("import did not commit replacement binding: %#v, found = %v, err = %v", current, found, err)
		}
	})
}

func TestCatalogFailureRollbackPreservesCleanupErrorAndCollectorConverges(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	catalogErr := errors.New("catalog commit failed")
	cleanupErr := errors.New("published directory cleanup failed")
	catalog.commitEnableErr = catalogErr
	originalRemoveAll := store.ops.removeAll
	var publishedWorkspace string
	store.ops.removeAll = func(path string) error {
		publishedWorkspace = path
		return cleanupErr
	}
	_, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1})
	if !errors.Is(err, catalogErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("CommitEnable() error = %v, want catalog and cleanup failures", err)
	}
	if outcome := mutation.ForError(err); outcome != mutation.OutcomeUnknown {
		t.Fatalf("CommitEnable() outcome = %q, err = %v", outcome, err)
	}
	if publishedWorkspace == "" {
		t.Fatal("rollback did not attempt to remove published workspace")
	}
	if _, err := os.Stat(publishedWorkspace); err != nil {
		t.Fatalf("failed rollback did not leave retryable orphan: %v", err)
	}
	store.ops.removeAll = originalRemoveAll
	if _, err := store.CleanupExpired(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(publishedWorkspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("collector did not remove unpublished workspace: %v", err)
	}
}

func TestCatalogFailuresRollBackUnpublishedDirectories(t *testing.T) {
	t.Run("export object", func(t *testing.T) {
		store, catalog, shape := newInternalStore(t)
		ctx := internalTestContext()
		if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
			t.Fatal(err)
		}
		catalogErr := errors.New("create object failed")
		catalog.createObjectErr = catalogErr
		if _, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"}); !errors.Is(err, catalogErr) {
			t.Fatalf("Export() error = %v, want %v", err, catalogErr)
		}
		entries, err := os.ReadDir(filepath.Dir(store.scopedObjectPath(internalUserScope(), "plugini_test", "object")))
		if err != nil || len(entries) != 0 {
			t.Fatalf("unpublished objects = %#v, err = %v", entries, err)
		}
	})

	t.Run("import workspace", func(t *testing.T) {
		store, catalog, shape := newInternalStore(t)
		ctx := internalTestContext()
		if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
			t.Fatal(err)
		}
		oldBinding, _, _ := catalog.GetBinding(ctx, "plugini_test")
		exported, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
		if err != nil {
			t.Fatal(err)
		}
		catalogErr := errors.New("swap import failed")
		catalog.swapImportErr = catalogErr
		if _, err := store.Import(ctx, ImportRequest{PluginInstanceID: "plugini_test", ObjectID: exported.ObjectID, ExpectedShape: shape, ExpectedManagementRevision: 2}); !errors.Is(err, catalogErr) {
			t.Fatalf("Import() error = %v, want %v", err, catalogErr)
		}
		current, found, err := catalog.GetBinding(ctx, "plugini_test")
		if err != nil || !found || current.GenerationID != oldBinding.GenerationID {
			t.Fatalf("binding changed after failed import: %#v, found = %v, err = %v", current, found, err)
		}
		entries, err := os.ReadDir(filepath.Dir(store.scopedWorkspacePath(internalEnvironmentScope(), "generation")))
		if err != nil || len(entries) != 1 || entries[0].Name() != oldBinding.GenerationID {
			t.Fatalf("unpublished workspaces = %#v, err = %v", entries, err)
		}
	})
}

func TestCommittedDeletionSyncFailureIsUnknownAfterDirectoryDisappears(t *testing.T) {
	store, _, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	exported, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
	if err != nil {
		t.Fatal(err)
	}
	target := store.scopedObjectPath(internalUserScope(), "plugini_test", exported.ObjectID)
	syncErr := errors.New("object directory sync failed")
	originalSyncDir := store.ops.syncDir
	store.ops.syncDir = func(path string) error {
		if path == filepath.Dir(target) {
			return syncErr
		}
		return originalSyncDir(path)
	}
	err = store.DeleteExport(ctx, DeleteExportRequest{PluginInstanceID: "plugini_test", ObjectID: exported.ObjectID})
	if !errors.Is(err, syncErr) || mutation.ForError(err) != mutation.OutcomeUnknown {
		t.Fatalf("DeleteExport() error = %v, outcome = %q", err, mutation.ForError(err))
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object remains after remove succeeded but sync failed: %v", err)
	}
}

func assertDeletionFailureConverges(t *testing.T, store *FileStore, target string, mutate func() error) {
	t.Helper()
	failure := errors.New("remove published directory failed")
	originalRemoveAll := store.ops.removeAll
	failed := false
	store.ops.removeAll = func(path string) error {
		if path == target && !failed {
			failed = true
			return failure
		}
		return originalRemoveAll(path)
	}
	err := mutate()
	if !failed {
		t.Fatal("mutation did not attempt physical directory deletion")
	}
	if !errors.Is(err, failure) || mutation.ForError(err) != mutation.OutcomeUnknown {
		t.Fatalf("mutation error = %v, outcome = %q", err, mutation.ForError(err))
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("failed deletion did not leave retryable directory: %v", err)
	}
	store.ops.removeAll = originalRemoveAll
	if _, err := store.CleanupExpired(internalTestContext(), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("collector retry failed: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("collector did not remove orphan %s: %v", target, err)
	}
}

func TestExportRejectsUnexpectedPhysicalNamespaceEntries(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	binding, _, _ := catalog.GetBinding(ctx, "plugini_test")
	workspaceRoot := store.scopedWorkspacePath(internalEnvironmentScope(), binding.GenerationID)
	dataRoot := filepath.Join(workspaceNamespaceRoot(workspaceRoot, internalUserScope()), "files", namespaceDataName)
	first := filepath.Join(dataRoot, "first.txt")
	if err := os.WriteFile(first, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, filepath.Join(dataRoot, "second.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"}); !errors.Is(err, ErrDatasetCorrupt) {
		t.Fatalf("Export() error = %v, want ErrDatasetCorrupt", err)
	}
}

func TestBindRetainedRejectsSamePluginInstance(t *testing.T) {
	store, catalog, shape := newInternalStore(t)
	ctx := internalTestContext()
	if _, err := store.CommitEnable(ctx, CommitEnableRequest{PluginInstanceID: "plugini_test", Shape: shape, ExpectedManagementRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUninstall(ctx, CommitUninstallRequest{PluginInstanceID: "plugini_test", ExpectedManagementRevision: 2, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	binding, _, _ := catalog.GetBinding(ctx, "plugini_test")
	if _, err := store.BindRetained(ctx, BindRetainedRequest{SourcePluginInstanceID: "plugini_test", ExpectedSourceBindingRevision: binding.Revision, TargetPluginInstanceID: "plugini_test", TargetExpectedManagementRevision: 3, ExpectedShape: shape}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("BindRetained() error = %v, want ErrInvalidArgument", err)
	}
}

func newInternalStore(t *testing.T) (*FileStore, *internalCatalog, Shape) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	catalog := &internalCatalog{objects: map[string]Object{}}
	store, err := Open(internalTestContext(), root, catalog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	shape := Shape{PublisherID: "example", PluginID: "com.example.test", Settings: settingsdomain.Schema{}, Namespaces: []Namespace{
		{ID: "files", Kind: NamespaceFiles, Scope: "user", SchemaVersion: 1, QuotaBytes: 1024, QuotaFiles: 16},
		{ID: "kv", Kind: NamespaceKV, Scope: "user", SchemaVersion: 1, QuotaBytes: 1024, QuotaFiles: 16},
	}}
	return store, catalog, shape
}
