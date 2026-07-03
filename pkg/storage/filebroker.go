package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fileBrokerNamespacesDir = "namespaces"
	fileBrokerArchivesDir   = "archives"
	fileBrokerDataDir       = "data"
	fileBrokerKVDir         = "kv"
	fileBrokerNamespaceFile = "namespace.json"
	fileBrokerArchiveFile   = "archive.json"
)

type NamespacePathResolver interface {
	NamespacePath(ctx context.Context, pluginInstanceID string, storeID string) (string, error)
}

type FileBroker struct {
	mu   sync.Mutex
	root string
	now  func() time.Time
}

func NewFileBroker(root string) (*FileBroker, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: storage root is required", ErrInvalidNamespace)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	b := &FileBroker{
		root: abs,
		now:  func() time.Time { return time.Now().UTC() },
	}
	if err := os.MkdirAll(b.namespacesRoot(), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(b.archivesRoot(), 0o700); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *FileBroker) EnsureNamespace(ctx context.Context, ns Namespace) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, err := normalizeNamespace(ns)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	base := b.namespaceBasePath(normalized.PluginInstanceID, normalized.StoreID)
	dataPath := filepath.Join(base, fileBrokerDataDir)
	if err := os.MkdirAll(dataPath, 0o700); err != nil {
		return err
	}
	stats, err := directoryUsageStats(dataPath)
	if err != nil {
		return err
	}
	if err := enforceNamespaceQuota(normalized, stats, "current"); err != nil {
		return err
	}

	now := b.now()
	record, err := b.readNamespaceRecordLocked(normalized.PluginInstanceID, normalized.StoreID)
	if err != nil && !errors.Is(err, ErrNamespaceNotFound) {
		return err
	}
	if errors.Is(err, ErrNamespaceNotFound) {
		record = NamespaceRecord{CreatedAt: now}
	}
	record.Namespace = normalized
	record.State = NamespaceActive
	record.UsageBytes = stats.Bytes
	record.UsageFiles = stats.Files
	record.UpdatedAt = now
	record.RetainedAt = nil
	return b.writeNamespaceRecordLocked(record)
}

func (b *FileBroker) DeleteNamespace(ctx context.Context, pluginInstanceID string, deleteData bool) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidNamespace)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	pluginPath := b.pluginBasePath(pluginInstanceID)
	if deleteData {
		if err := os.RemoveAll(pluginPath); err != nil {
			return err
		}
		return nil
	}

	records, err := b.listNamespacesLocked(pluginInstanceID)
	if err != nil {
		return err
	}
	now := b.now()
	for _, record := range records {
		record.State = NamespaceRetained
		record.UpdatedAt = now
		record.RetainedAt = &now
		if err := b.writeNamespaceRecordLocked(record); err != nil {
			return err
		}
	}
	return nil
}

func (b *FileBroker) DeleteRetainedNamespace(ctx context.Context, pluginInstanceID string) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidNamespace)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	records, err := b.listNamespacesLocked(pluginInstanceID)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.State != NamespaceRetained {
			return fmt.Errorf("%w: %s/%s is %s", ErrNamespaceNotRetained, record.PluginInstanceID, record.StoreID, record.State)
		}
	}
	return os.RemoveAll(b.pluginBasePath(pluginInstanceID))
}

func (b *FileBroker) BindRetainedNamespace(ctx context.Context, req BindRetainedRequest) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sourcePluginInstanceID := strings.TrimSpace(req.SourcePluginInstanceID)
	targetPluginInstanceID := strings.TrimSpace(req.TargetPluginInstanceID)
	if sourcePluginInstanceID == "" || targetPluginInstanceID == "" {
		return fmt.Errorf("%w: source_plugin_instance_id and target_plugin_instance_id are required", ErrInvalidNamespace)
	}
	targets, err := normalizeTargetNamespaces(req.TargetNamespaces, targetPluginInstanceID)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("%w: target namespaces are required", ErrInvalidNamespace)
	}
	now := req.Now
	if now.IsZero() {
		now = b.now()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	plans, err := b.bindRetainedPlansLocked(sourcePluginInstanceID, targetPluginInstanceID, targets, now)
	if err != nil {
		return err
	}
	if req.DryRun {
		return nil
	}
	for _, plan := range plans {
		if plan.sameNamespace {
			if err := b.writeNamespaceRecordLocked(plan.record); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(plan.targetBase), 0o700); err != nil {
			return err
		}
		if err := os.Rename(plan.sourceBase, plan.targetBase); err != nil {
			return err
		}
		if err := b.writeNamespaceRecordLocked(plan.record); err != nil {
			return err
		}
	}
	return nil
}

func (b *FileBroker) ExportData(ctx context.Context, req ExportRequest) (string, error) {
	if b == nil {
		return "", errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return "", fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidNamespace)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	namespaces, err := b.listNamespacesLocked(pluginInstanceID)
	if err != nil {
		return "", err
	}
	if len(namespaces) == 0 {
		return "", ErrNamespaceNotFound
	}

	ref, archivePath, err := b.allocateArchivePathLocked()
	if err != nil {
		return "", err
	}
	tmpPath := archivePath + ".tmp"
	if err := os.RemoveAll(tmpPath); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(tmpPath, fileBrokerNamespacesDir), 0o700); err != nil {
		return "", err
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.RemoveAll(tmpPath)
		}
	}()

	now := b.now()
	exported := make([]NamespaceRecord, 0, len(namespaces))
	for _, record := range namespaces {
		dataPath := b.namespaceDataPath(record.PluginInstanceID, record.StoreID)
		stats, err := directoryUsageStats(dataPath)
		if err != nil {
			return "", err
		}
		record.UsageBytes = stats.Bytes
		record.UsageFiles = stats.Files
		record.UpdatedAt = now
		exported = append(exported, record)

		dst := filepath.Join(tmpPath, fileBrokerNamespacesDir, pathSegment(record.StoreID), fileBrokerDataDir)
		if err := copyDir(dataPath, dst); err != nil {
			return "", err
		}
	}
	archive := ArchiveRecord{
		ArchiveRef:             ref,
		SourcePluginInstanceID: pluginInstanceID,
		IncludeSecrets:         req.IncludeSecrets,
		Namespaces:             exported,
		CreatedAt:              now,
	}
	if err := writeJSONFile(filepath.Join(tmpPath, fileBrokerArchiveFile), archive); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, archivePath); err != nil {
		return "", err
	}
	cleanupTmp = false
	return ref, nil
}

type fileBindRetainedPlan struct {
	record        NamespaceRecord
	sourceBase    string
	targetBase    string
	sameNamespace bool
}

func (b *FileBroker) bindRetainedPlansLocked(sourcePluginInstanceID string, targetPluginInstanceID string, targets map[string]Namespace, now time.Time) ([]fileBindRetainedPlan, error) {
	records, err := b.listNamespacesLocked(sourcePluginInstanceID)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, ErrNamespaceNotFound
	}
	plans := make([]fileBindRetainedPlan, 0, len(records))
	for _, record := range records {
		if record.State != NamespaceRetained {
			return nil, fmt.Errorf("%w: %s/%s is %s", ErrNamespaceNotRetained, record.PluginInstanceID, record.StoreID, record.State)
		}
		target, ok := targets[record.StoreID]
		if !ok {
			return nil, fmt.Errorf("%w: retained store %q is not declared by target manifest", ErrInvalidNamespace, record.StoreID)
		}
		if record.Kind != target.Kind {
			return nil, fmt.Errorf("%w: retained store %q kind %q does not match target kind %q", ErrInvalidNamespace, record.StoreID, record.Kind, target.Kind)
		}
		if record.SchemaVersion != target.SchemaVersion {
			return nil, fmt.Errorf("%w: retained store %q schema_version %d does not match target schema_version %d", ErrInvalidNamespace, record.StoreID, record.SchemaVersion, target.SchemaVersion)
		}
		dataPath := b.namespaceDataPath(record.PluginInstanceID, record.StoreID)
		stats, err := directoryUsageStats(dataPath)
		if err != nil {
			return nil, err
		}
		if err := enforceNamespaceQuota(target, stats, fmt.Sprintf("retained store %q", record.StoreID)); err != nil {
			return nil, err
		}
		sourceBase := b.namespaceBasePath(sourcePluginInstanceID, record.StoreID)
		targetBase := b.namespaceBasePath(targetPluginInstanceID, record.StoreID)
		sameNamespace := sourceBase == targetBase
		if !sameNamespace {
			if _, err := b.readNamespaceRecordLocked(targetPluginInstanceID, record.StoreID); err == nil {
				return nil, fmt.Errorf("%w: %s/%s", ErrNamespaceAlreadyExists, targetPluginInstanceID, record.StoreID)
			} else if !errors.Is(err, ErrNamespaceNotFound) {
				return nil, err
			}
			if _, err := os.Stat(targetBase); err == nil {
				return nil, fmt.Errorf("%w: %s/%s", ErrNamespaceAlreadyExists, targetPluginInstanceID, record.StoreID)
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
		record.Namespace = target
		record.State = NamespaceActive
		record.UsageBytes = stats.Bytes
		record.UsageFiles = stats.Files
		record.UpdatedAt = now
		record.RetainedAt = nil
		plans = append(plans, fileBindRetainedPlan{
			record:        record,
			sourceBase:    sourceBase,
			targetBase:    targetBase,
			sameNamespace: sameNamespace,
		})
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].record.StoreID < plans[j].record.StoreID })
	return plans, nil
}

func (b *FileBroker) ImportData(ctx context.Context, req ImportRequest) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidNamespace)
	}
	archiveRef := strings.TrimSpace(req.ArchiveRef)
	if archiveRef == "" || !validArchiveRef(archiveRef) {
		return ErrArchiveNotFound
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	archivePath := filepath.Join(b.archivesRoot(), archiveRef)
	var archive ArchiveRecord
	if err := readJSONFile(filepath.Join(archivePath, fileBrokerArchiveFile), &archive); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrArchiveNotFound
		}
		return err
	}
	if archive.ArchiveRef != archiveRef {
		return fmt.Errorf("%w: archive ref mismatch", ErrInvalidNamespace)
	}
	targets, err := normalizeTargetNamespaces(req.TargetNamespaces, pluginInstanceID)
	if err != nil {
		return err
	}

	type importPlan struct {
		record NamespaceRecord
		src    string
		stats  storageUsageStats
	}
	plans := make([]importPlan, 0, len(archive.Namespaces))
	now := b.now()
	for _, archived := range archive.Namespaces {
		record := archived
		if len(targets) > 0 {
			target, ok := targets[archived.StoreID]
			if !ok {
				return fmt.Errorf("%w: archive store %q is not declared by target manifest", ErrInvalidNamespace, archived.StoreID)
			}
			if err := validateArchivedNamespaceTarget(archived, target); err != nil {
				return err
			}
			record.Namespace = target
		} else {
			record.PluginInstanceID = pluginInstanceID
		}
		record.State = NamespaceActive
		record.CreatedAt = now
		record.UpdatedAt = now
		record.RetainedAt = nil

		src := filepath.Join(archivePath, fileBrokerNamespacesDir, pathSegment(archived.StoreID), fileBrokerDataDir)
		stats, err := directoryUsageStats(src)
		if err != nil {
			return err
		}
		if err := enforceNamespaceQuota(record.Namespace, stats, fmt.Sprintf("archive store %q", archived.StoreID)); err != nil {
			return err
		}
		record.UsageBytes = stats.Bytes
		record.UsageFiles = stats.Files
		plans = append(plans, importPlan{record: record, src: src, stats: stats})
	}

	if req.DeleteExisting {
		if err := os.RemoveAll(b.pluginBasePath(pluginInstanceID)); err != nil {
			return err
		}
	}
	for _, plan := range plans {
		base := b.namespaceBasePath(pluginInstanceID, plan.record.StoreID)
		dataPath := filepath.Join(base, fileBrokerDataDir)
		if err := os.RemoveAll(dataPath); err != nil {
			return err
		}
		if err := copyDir(plan.src, dataPath); err != nil {
			return err
		}
		plan.record.UsageBytes = plan.stats.Bytes
		plan.record.UsageFiles = plan.stats.Files
		if err := b.writeNamespaceRecordLocked(plan.record); err != nil {
			return err
		}
	}
	return nil
}

func (b *FileBroker) ListNamespaces(ctx context.Context, pluginInstanceID string) ([]NamespaceRecord, error) {
	if b == nil {
		return nil, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	records, err := b.listNamespacesLocked(pluginInstanceID)
	if err != nil {
		return nil, err
	}
	return cloneNamespaceRecords(records), nil
}

func (b *FileBroker) Usage(ctx context.Context, pluginInstanceID string, storeID string) (Usage, error) {
	if b == nil {
		return Usage{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return Usage{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	record, err := b.readNamespaceRecordLocked(pluginInstanceID, storeID)
	if err != nil {
		return Usage{}, err
	}
	stats, err := directoryUsageStats(b.namespaceDataPath(record.PluginInstanceID, record.StoreID))
	if err != nil {
		return Usage{}, err
	}
	if err := enforceNamespaceQuota(record.Namespace, stats, "current"); err != nil {
		return Usage{}, err
	}
	record.UsageBytes = stats.Bytes
	record.UsageFiles = stats.Files
	record.UpdatedAt = b.now()
	if err := b.writeNamespaceRecordLocked(record); err != nil {
		return Usage{}, err
	}
	return Usage{
		PluginInstanceID: record.PluginInstanceID,
		StoreID:          record.StoreID,
		UsageBytes:       stats.Bytes,
		QuotaBytes:       record.QuotaBytes,
		UsageFiles:       stats.Files,
		QuotaFiles:       record.QuotaFiles,
	}, nil
}

func (b *FileBroker) NamespacePath(ctx context.Context, pluginInstanceID string, storeID string) (string, error) {
	if b == nil {
		return "", errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	record, err := b.readNamespaceRecordLocked(pluginInstanceID, storeID)
	if err != nil {
		return "", err
	}
	if record.State != NamespaceActive {
		return "", ErrNamespaceNotFound
	}
	return b.namespaceDataPath(record.PluginInstanceID, record.StoreID), nil
}

func (b *FileBroker) ReadFile(ctx context.Context, req FileReadRequest) (FileReadResult, error) {
	if b == nil {
		return FileReadResult{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return FileReadResult{}, err
	}
	rel, err := cleanStorageFilePath(req.Path)
	if err != nil {
		return FileReadResult{}, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeFilesNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return FileReadResult{}, err
	}
	target, err := resolveStorageFilePath(dataPath, rel)
	if err != nil {
		return FileReadResult{}, err
	}
	info, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FileReadResult{}, ErrFileNotFound
		}
		return FileReadResult{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return FileReadResult{}, fmt.Errorf("%w: symlink is not allowed", ErrInvalidFilePath)
	}
	if !info.Mode().IsRegular() {
		return FileReadResult{}, fmt.Errorf("%w: path is not a regular file", ErrInvalidFilePath)
	}
	if req.MaxBytes > 0 && info.Size() > req.MaxBytes {
		return FileReadResult{}, fmt.Errorf("%w: %d > %d", ErrFileTooLarge, info.Size(), req.MaxBytes)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return FileReadResult{}, err
	}
	usage, err := b.refreshUsageLocked(record)
	if err != nil {
		return FileReadResult{}, err
	}
	return FileReadResult{Path: rel, Data: data, SizeBytes: int64(len(data)), Usage: usage}, nil
}

func (b *FileBroker) WriteFile(ctx context.Context, req FileWriteRequest) (FileWriteResult, error) {
	if b == nil {
		return FileWriteResult{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return FileWriteResult{}, err
	}
	rel, err := cleanStorageFilePath(req.Path)
	if err != nil {
		return FileWriteResult{}, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeFilesNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return FileWriteResult{}, err
	}
	target, err := resolveStorageFilePath(dataPath, rel)
	if err != nil {
		return FileWriteResult{}, err
	}
	if err := rejectSymlinkAncestors(dataPath, filepath.Dir(target)); err != nil {
		return FileWriteResult{}, err
	}
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return FileWriteResult{}, fmt.Errorf("%w: symlink is not allowed", ErrInvalidFilePath)
		}
		if !info.Mode().IsRegular() {
			return FileWriteResult{}, fmt.Errorf("%w: existing path is not a regular file", ErrInvalidFilePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return FileWriteResult{}, err
	}
	statsBefore, err := directoryUsageStats(dataPath)
	if err != nil {
		return FileWriteResult{}, err
	}
	oldSize := int64(0)
	targetExists := false
	if info, err := os.Lstat(target); err == nil && info.Mode().IsRegular() {
		oldSize = info.Size()
		targetExists = true
	}
	projected := storageUsageStats{
		Bytes: statsBefore.Bytes - oldSize + int64(len(req.Data)),
		Files: statsBefore.Files,
	}
	if !targetExists {
		missingDirs, err := missingDirectoryEntries(dataPath, filepath.Dir(target))
		if err != nil {
			return FileWriteResult{}, err
		}
		projected.Files += missingDirs + 1
	}
	if err := enforceNamespaceQuota(record.Namespace, projected, "projected"); err != nil {
		return FileWriteResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return FileWriteResult{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".redevplugin-write-*")
	if err != nil {
		return FileWriteResult{}, err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(req.Data); err != nil {
		_ = tmp.Close()
		return FileWriteResult{}, err
	}
	if err := tmp.Close(); err != nil {
		return FileWriteResult{}, err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return FileWriteResult{}, err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return FileWriteResult{}, err
	}
	cleanup = false
	usage, err := b.refreshUsageLocked(record)
	if err != nil {
		return FileWriteResult{}, err
	}
	return FileWriteResult{Path: rel, SizeBytes: int64(len(req.Data)), Usage: usage}, nil
}

func (b *FileBroker) DeleteFile(ctx context.Context, req FileDeleteRequest) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rel, err := cleanStorageFilePath(req.Path)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeFilesNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return err
	}
	target, err := resolveStorageFilePath(dataPath, rel)
	if err != nil {
		return err
	}
	info, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symlink is not allowed", ErrInvalidFilePath)
	}
	if info.IsDir() && !req.Recursive {
		return fmt.Errorf("%w: recursive delete is required for directories", ErrInvalidFilePath)
	}
	if info.IsDir() {
		if err := validateStorageTree(target); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	_, err = b.refreshUsageLocked(record)
	return err
}

func (b *FileBroker) ListFiles(ctx context.Context, req FileListRequest) (FileListResult, error) {
	if b == nil {
		return FileListResult{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return FileListResult{}, err
	}
	rel, err := cleanStorageDirPath(req.Path)
	if err != nil {
		return FileListResult{}, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeFilesNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return FileListResult{}, err
	}
	target, err := resolveStorageFilePath(dataPath, rel)
	if err != nil {
		return FileListResult{}, err
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FileListResult{}, ErrFileNotFound
		}
		return FileListResult{}, err
	}
	limit := req.MaxEntries
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	resultEntries := make([]FileEntry, 0, len(entries))
	for _, entry := range entries {
		if len(resultEntries) >= limit {
			break
		}
		info, err := entry.Info()
		if err != nil {
			return FileListResult{}, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return FileListResult{}, fmt.Errorf("%w: symlink is not allowed", ErrInvalidFilePath)
		}
		childPath := pathJoin(rel, entry.Name())
		resultEntries = append(resultEntries, FileEntry{
			Path:      childPath,
			Dir:       entry.IsDir(),
			SizeBytes: regularFileSize(info),
			UpdatedAt: info.ModTime().UTC(),
		})
	}
	sort.Slice(resultEntries, func(i, j int) bool { return resultEntries[i].Path < resultEntries[j].Path })
	usage, err := b.refreshUsageLocked(record)
	if err != nil {
		return FileListResult{}, err
	}
	return FileListResult{Path: rel, Entries: resultEntries, Usage: usage}, nil
}

func (b *FileBroker) GetKV(ctx context.Context, req KVGetRequest) (KVGetResult, error) {
	if b == nil {
		return KVGetResult{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return KVGetResult{}, err
	}
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return KVGetResult{}, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeKVNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return KVGetResult{}, err
	}
	target := filepath.Join(dataPath, fileBrokerKVDir, kvKeySegment(key))
	info, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return KVGetResult{}, ErrKVKeyNotFound
		}
		return KVGetResult{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return KVGetResult{}, fmt.Errorf("%w: symlink is not allowed", ErrInvalidFilePath)
	}
	if !info.Mode().IsRegular() {
		return KVGetResult{}, fmt.Errorf("%w: kv value is not a regular file", ErrInvalidFilePath)
	}
	if req.MaxBytes > 0 && info.Size() > req.MaxBytes {
		return KVGetResult{}, fmt.Errorf("%w: %d > %d", ErrKVValueTooLarge, info.Size(), req.MaxBytes)
	}
	value, err := os.ReadFile(target)
	if err != nil {
		return KVGetResult{}, err
	}
	usage, err := b.refreshUsageLocked(record)
	if err != nil {
		return KVGetResult{}, err
	}
	return KVGetResult{Key: key, Value: value, SizeBytes: int64(len(value)), Usage: usage}, nil
}

func (b *FileBroker) PutKV(ctx context.Context, req KVPutRequest) (KVPutResult, error) {
	if b == nil {
		return KVPutResult{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return KVPutResult{}, err
	}
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return KVPutResult{}, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeKVNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return KVPutResult{}, err
	}
	kvPath := filepath.Join(dataPath, fileBrokerKVDir)
	target := filepath.Join(kvPath, kvKeySegment(key))
	if err := rejectSymlinkAncestors(dataPath, filepath.Dir(target)); err != nil {
		return KVPutResult{}, err
	}
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return KVPutResult{}, fmt.Errorf("%w: symlink is not allowed", ErrInvalidFilePath)
		}
		if !info.Mode().IsRegular() {
			return KVPutResult{}, fmt.Errorf("%w: existing kv value is not a regular file", ErrInvalidFilePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return KVPutResult{}, err
	}
	statsBefore, err := directoryUsageStats(dataPath)
	if err != nil {
		return KVPutResult{}, err
	}
	oldSize := int64(0)
	targetExists := false
	if info, err := os.Lstat(target); err == nil && info.Mode().IsRegular() {
		oldSize = info.Size()
		targetExists = true
	}
	projected := storageUsageStats{
		Bytes: statsBefore.Bytes - oldSize + int64(len(req.Value)),
		Files: statsBefore.Files,
	}
	if !targetExists {
		missingDirs, err := missingDirectoryEntries(dataPath, kvPath)
		if err != nil {
			return KVPutResult{}, err
		}
		projected.Files += missingDirs + 1
	}
	if err := enforceNamespaceQuota(record.Namespace, projected, "projected"); err != nil {
		return KVPutResult{}, err
	}
	if err := os.MkdirAll(kvPath, 0o700); err != nil {
		return KVPutResult{}, err
	}
	tmp, err := os.CreateTemp(kvPath, ".redevplugin-kv-*")
	if err != nil {
		return KVPutResult{}, err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(req.Value); err != nil {
		_ = tmp.Close()
		return KVPutResult{}, err
	}
	if err := tmp.Close(); err != nil {
		return KVPutResult{}, err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return KVPutResult{}, err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return KVPutResult{}, err
	}
	cleanup = false
	usage, err := b.refreshUsageLocked(record)
	if err != nil {
		return KVPutResult{}, err
	}
	return KVPutResult{Key: key, SizeBytes: int64(len(req.Value)), Usage: usage}, nil
}

func (b *FileBroker) DeleteKV(ctx context.Context, req KVDeleteRequest) error {
	if b == nil {
		return errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeKVNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return err
	}
	target := filepath.Join(dataPath, fileBrokerKVDir, kvKeySegment(key))
	info, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symlink is not allowed", ErrInvalidFilePath)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: kv value is not a regular file", ErrInvalidFilePath)
	}
	if err := os.Remove(target); err != nil {
		return err
	}
	_, err = b.refreshUsageLocked(record)
	return err
}

func (b *FileBroker) ListKV(ctx context.Context, req KVListRequest) (KVListResult, error) {
	if b == nil {
		return KVListResult{}, errors.New("storage broker is nil")
	}
	if err := ctx.Err(); err != nil {
		return KVListResult{}, err
	}
	prefix := strings.TrimSpace(req.Prefix)

	b.mu.Lock()
	defer b.mu.Unlock()

	record, dataPath, err := b.activeKVNamespaceLocked(req.PluginInstanceID, req.StoreID)
	if err != nil {
		return KVListResult{}, err
	}
	kvPath := filepath.Join(dataPath, fileBrokerKVDir)
	dirEntries, err := os.ReadDir(kvPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			usage, err := b.refreshUsageLocked(record)
			if err != nil {
				return KVListResult{}, err
			}
			return KVListResult{Prefix: prefix, Usage: usage}, nil
		}
		return KVListResult{}, err
	}
	limit := req.MaxEntries
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	entries := make([]KVEntry, 0, len(dirEntries))
	for _, entry := range dirEntries {
		if len(entries) >= limit {
			break
		}
		info, err := entry.Info()
		if err != nil {
			return KVListResult{}, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return KVListResult{}, fmt.Errorf("%w: symlink is not allowed", ErrInvalidFilePath)
		}
		if !info.Mode().IsRegular() {
			return KVListResult{}, fmt.Errorf("%w: kv value is not a regular file", ErrInvalidFilePath)
		}
		key, err := kvKeySegmentValue(entry.Name())
		if err != nil {
			return KVListResult{}, err
		}
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		entries = append(entries, KVEntry{Key: key, SizeBytes: info.Size(), UpdatedAt: info.ModTime().UTC()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	usage, err := b.refreshUsageLocked(record)
	if err != nil {
		return KVListResult{}, err
	}
	return KVListResult{Prefix: prefix, Entries: entries, Usage: usage}, nil
}

func (b *FileBroker) Root() string {
	if b == nil {
		return ""
	}
	return b.root
}

func (b *FileBroker) listNamespacesLocked(pluginInstanceID string) ([]NamespaceRecord, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	roots := []string{}
	if pluginInstanceID != "" {
		roots = append(roots, b.pluginBasePath(pluginInstanceID))
	} else {
		entries, err := os.ReadDir(b.namespacesRoot())
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				roots = append(roots, filepath.Join(b.namespacesRoot(), entry.Name()))
			}
		}
	}

	records := []NamespaceRecord{}
	for _, root := range roots {
		pluginForRoot := pluginInstanceID
		if pluginForRoot == "" {
			decoded, err := pathSegmentValue(filepath.Base(root))
			if err != nil {
				return nil, err
			}
			pluginForRoot = decoded
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			storeID, err := pathSegmentValue(entry.Name())
			if err != nil {
				return nil, err
			}
			var record NamespaceRecord
			if err := readJSONFile(filepath.Join(root, entry.Name(), fileBrokerNamespaceFile), &record); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return nil, err
			}
			record, err = validateNamespaceRecord(record, pluginForRoot, storeID)
			if err != nil {
				return nil, err
			}
			stats, err := directoryUsageStats(filepath.Join(root, entry.Name(), fileBrokerDataDir))
			if err != nil {
				return nil, err
			}
			record.UsageBytes = stats.Bytes
			record.UsageFiles = stats.Files
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].PluginInstanceID == records[j].PluginInstanceID {
			return records[i].StoreID < records[j].StoreID
		}
		return records[i].PluginInstanceID < records[j].PluginInstanceID
	})
	return records, nil
}

func (b *FileBroker) readNamespaceRecordLocked(pluginInstanceID string, storeID string) (NamespaceRecord, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	storeID = strings.TrimSpace(storeID)
	if pluginInstanceID == "" || storeID == "" {
		return NamespaceRecord{}, ErrNamespaceNotFound
	}
	var record NamespaceRecord
	if err := readJSONFile(filepath.Join(b.namespaceBasePath(pluginInstanceID, storeID), fileBrokerNamespaceFile), &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NamespaceRecord{}, ErrNamespaceNotFound
		}
		return NamespaceRecord{}, err
	}
	return validateNamespaceRecord(record, pluginInstanceID, storeID)
}

func (b *FileBroker) writeNamespaceRecordLocked(record NamespaceRecord) error {
	normalized, err := normalizeNamespace(record.Namespace)
	if err != nil {
		return err
	}
	record.Namespace = normalized
	switch record.State {
	case NamespaceActive, NamespaceRetained:
	default:
		return fmt.Errorf("%w: unsupported namespace state %q", ErrInvalidNamespace, record.State)
	}
	if err := os.MkdirAll(b.namespaceDataPath(record.PluginInstanceID, record.StoreID), 0o700); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(b.namespaceBasePath(record.PluginInstanceID, record.StoreID), fileBrokerNamespaceFile), record)
}

func (b *FileBroker) activeFilesNamespaceLocked(pluginInstanceID string, storeID string) (NamespaceRecord, string, error) {
	record, err := b.readNamespaceRecordLocked(pluginInstanceID, storeID)
	if err != nil {
		return NamespaceRecord{}, "", err
	}
	if record.State != NamespaceActive {
		return NamespaceRecord{}, "", ErrNamespaceNotFound
	}
	if record.Kind != StoreFiles {
		return NamespaceRecord{}, "", fmt.Errorf("%w: store %q is %s, not files", ErrInvalidNamespace, record.StoreID, record.Kind)
	}
	dataPath := b.namespaceDataPath(record.PluginInstanceID, record.StoreID)
	if err := os.MkdirAll(dataPath, 0o700); err != nil {
		return NamespaceRecord{}, "", err
	}
	return record, dataPath, nil
}

func (b *FileBroker) activeKVNamespaceLocked(pluginInstanceID string, storeID string) (NamespaceRecord, string, error) {
	record, err := b.readNamespaceRecordLocked(pluginInstanceID, storeID)
	if err != nil {
		return NamespaceRecord{}, "", err
	}
	if record.State != NamespaceActive {
		return NamespaceRecord{}, "", ErrNamespaceNotFound
	}
	if record.Kind != StoreKV {
		return NamespaceRecord{}, "", fmt.Errorf("%w: store %q is %s, not kv", ErrInvalidNamespace, record.StoreID, record.Kind)
	}
	dataPath := b.namespaceDataPath(record.PluginInstanceID, record.StoreID)
	if err := os.MkdirAll(dataPath, 0o700); err != nil {
		return NamespaceRecord{}, "", err
	}
	return record, dataPath, nil
}

func (b *FileBroker) refreshUsageLocked(record NamespaceRecord) (Usage, error) {
	dataPath := b.namespaceDataPath(record.PluginInstanceID, record.StoreID)
	stats, err := directoryUsageStats(dataPath)
	if err != nil {
		return Usage{}, err
	}
	if err := enforceNamespaceQuota(record.Namespace, stats, "current"); err != nil {
		return Usage{}, err
	}
	record.UsageBytes = stats.Bytes
	record.UsageFiles = stats.Files
	record.UpdatedAt = b.now()
	if err := b.writeNamespaceRecordLocked(record); err != nil {
		return Usage{}, err
	}
	return Usage{
		PluginInstanceID: record.PluginInstanceID,
		StoreID:          record.StoreID,
		UsageBytes:       stats.Bytes,
		QuotaBytes:       record.QuotaBytes,
		UsageFiles:       stats.Files,
		QuotaFiles:       record.QuotaFiles,
	}, nil
}

func (b *FileBroker) allocateArchivePathLocked() (string, string, error) {
	for range 16 {
		ref, err := randomArchiveRef()
		if err != nil {
			return "", "", err
		}
		path := filepath.Join(b.archivesRoot(), ref)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return ref, path, nil
		} else if err != nil {
			return "", "", err
		}
	}
	return "", "", errors.New("could not allocate unique storage archive ref")
}

func (b *FileBroker) namespacesRoot() string {
	return filepath.Join(b.root, fileBrokerNamespacesDir)
}

func (b *FileBroker) archivesRoot() string {
	return filepath.Join(b.root, fileBrokerArchivesDir)
}

func (b *FileBroker) pluginBasePath(pluginInstanceID string) string {
	return filepath.Join(b.namespacesRoot(), pathSegment(pluginInstanceID))
}

func (b *FileBroker) namespaceBasePath(pluginInstanceID string, storeID string) string {
	return filepath.Join(b.pluginBasePath(pluginInstanceID), pathSegment(storeID))
}

func (b *FileBroker) namespaceDataPath(pluginInstanceID string, storeID string) string {
	return filepath.Join(b.namespaceBasePath(pluginInstanceID, storeID), fileBrokerDataDir)
}

func pathSegment(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(value)))
}

func pathSegmentValue(segment string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return "", fmt.Errorf("%w: invalid storage path segment", ErrInvalidNamespace)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("%w: empty storage path segment", ErrInvalidNamespace)
	}
	return value, nil
}

func kvKeySegment(key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(key))
}

func kvKeySegmentValue(segment string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return "", fmt.Errorf("%w: invalid kv key segment", ErrInvalidKVKey)
	}
	key, err := normalizeKVKey(string(raw))
	if err != nil {
		return "", err
	}
	if kvKeySegment(key) != segment {
		return "", fmt.Errorf("%w: non-canonical kv key segment", ErrInvalidKVKey)
	}
	return key, nil
}

func validateNamespaceRecord(record NamespaceRecord, pluginInstanceID string, storeID string) (NamespaceRecord, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	storeID = strings.TrimSpace(storeID)
	normalized, err := normalizeNamespace(record.Namespace)
	if err != nil {
		return NamespaceRecord{}, err
	}
	if normalized.PluginInstanceID != pluginInstanceID || normalized.StoreID != storeID {
		return NamespaceRecord{}, fmt.Errorf("%w: namespace metadata does not match storage path", ErrInvalidNamespace)
	}
	switch record.State {
	case NamespaceActive, NamespaceRetained:
	default:
		return NamespaceRecord{}, fmt.Errorf("%w: unsupported namespace state %q", ErrInvalidNamespace, record.State)
	}
	record.Namespace = normalized
	return record, nil
}

func randomArchiveRef() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "archive_" + hex.EncodeToString(raw), nil
}

func validArchiveRef(ref string) bool {
	if !strings.HasPrefix(ref, "archive_") || len(ref) != len("archive_")+32 {
		return false
	}
	for _, ch := range strings.TrimPrefix(ref, "archive_") {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func cleanStorageFilePath(raw string) (string, error) {
	cleaned, err := cleanStoragePath(raw, false)
	if err != nil {
		return "", err
	}
	if cleaned == "." {
		return "", fmt.Errorf("%w: file path is required", ErrInvalidFilePath)
	}
	return cleaned, nil
}

func cleanStorageDirPath(raw string) (string, error) {
	return cleanStoragePath(raw, true)
}

func cleanStoragePath(raw string, allowRoot bool) (string, error) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" {
		if allowRoot {
			return ".", nil
		}
		return "", fmt.Errorf("%w: path is required", ErrInvalidFilePath)
	}
	if strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("%w: absolute paths are not allowed", ErrInvalidFilePath)
	}
	cleaned := filepath.ToSlash(filepath.Clean(raw))
	if cleaned == "." {
		if allowRoot {
			return ".", nil
		}
		return "", fmt.Errorf("%w: file path is required", ErrInvalidFilePath)
	}
	for _, part := range strings.Split(cleaned, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("%w: traversal segments are not allowed", ErrInvalidFilePath)
		}
	}
	return cleaned, nil
}

func resolveStorageFilePath(root string, rel string) (string, error) {
	if rel == "." {
		return root, nil
	}
	target := filepath.Join(root, filepath.FromSlash(rel))
	rootRel, err := filepath.Rel(root, target)
	if err != nil {
		return "", err
	}
	if rootRel == "." || strings.HasPrefix(rootRel, ".."+string(filepath.Separator)) || rootRel == ".." || filepath.IsAbs(rootRel) {
		return "", fmt.Errorf("%w: path escapes namespace", ErrInvalidFilePath)
	}
	return target, nil
}

func rejectSymlinkAncestors(root string, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink ancestor is not allowed", ErrInvalidFilePath)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: path ancestor is not a directory", ErrInvalidFilePath)
		}
	}
	return nil
}

func pathJoin(parent string, child string) string {
	if parent == "." || parent == "" {
		return child
	}
	return filepath.ToSlash(filepath.Join(parent, child))
}

func regularFileSize(info fs.FileInfo) int64 {
	if info.Mode().IsRegular() {
		return info.Size()
	}
	return 0
}

func validateStorageTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink is not allowed in storage namespace: %s", ErrInvalidFilePath, path)
		}
		if entry.IsDir() || info.Mode().IsRegular() {
			return nil
		}
		return fmt.Errorf("%w: unsupported storage file mode %s at %s", ErrInvalidFilePath, info.Mode(), path)
	})
}

func readJSONFile(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

type storageUsageStats struct {
	Bytes int64
	Files int64
}

func directoryUsageStats(root string) (storageUsageStats, error) {
	var stats storageUsageStats
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink is not allowed in storage namespace: %s", ErrInvalidNamespace, path)
		}
		if path != root {
			stats.Files++
		}
		if info.Mode().IsRegular() {
			stats.Bytes += info.Size()
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return storageUsageStats{}, nil
	}
	return stats, err
}

func missingDirectoryEntries(root string, dir string) (int64, error) {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return 0, err
	}
	if rel == "." {
		return 0, nil
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return 0, fmt.Errorf("%w: path escapes namespace", ErrInvalidFilePath)
	}
	current := root
	var missing int64
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			missing++
			continue
		}
		if err != nil {
			return 0, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return 0, fmt.Errorf("%w: symlink ancestor is not allowed", ErrInvalidFilePath)
		}
		if !info.IsDir() {
			return 0, fmt.Errorf("%w: path ancestor is not a directory", ErrInvalidFilePath)
		}
	}
	return missing, nil
}

func enforceNamespaceQuota(ns Namespace, stats storageUsageStats, label string) error {
	if stats.Bytes > ns.QuotaBytes {
		return fmt.Errorf("%w: %s usage %d exceeds quota %d", ErrQuotaExceeded, label, stats.Bytes, ns.QuotaBytes)
	}
	if ns.QuotaFiles > 0 && stats.Files > ns.QuotaFiles {
		return fmt.Errorf("%w: %s file usage %d exceeds quota %d", ErrQuotaExceeded, label, stats.Files, ns.QuotaFiles)
	}
	return nil
}

func copyDir(src string, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink is not allowed in storage namespace: %s", ErrInvalidNamespace, path)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: unsupported storage file mode %s at %s", ErrInvalidNamespace, info.Mode(), path)
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func copyFile(src string, dst string, perm fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
