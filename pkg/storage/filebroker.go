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
	usage, err := directoryUsage(dataPath)
	if err != nil {
		return err
	}
	if usage > normalized.QuotaBytes {
		return fmt.Errorf("%w: current usage %d exceeds quota %d", ErrQuotaExceeded, usage, normalized.QuotaBytes)
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
	record.UsageBytes = usage
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
		usage, err := directoryUsage(dataPath)
		if err != nil {
			return "", err
		}
		record.UsageBytes = usage
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
		usage  int64
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
			record.Namespace = target
		} else {
			record.PluginInstanceID = pluginInstanceID
		}
		record.State = NamespaceActive
		record.CreatedAt = now
		record.UpdatedAt = now
		record.RetainedAt = nil

		src := filepath.Join(archivePath, fileBrokerNamespacesDir, pathSegment(archived.StoreID), fileBrokerDataDir)
		usage, err := directoryUsage(src)
		if err != nil {
			return err
		}
		if usage > record.QuotaBytes {
			return fmt.Errorf("%w: archive store %q usage %d exceeds target quota %d", ErrQuotaExceeded, archived.StoreID, usage, record.QuotaBytes)
		}
		record.UsageBytes = usage
		plans = append(plans, importPlan{record: record, src: src, usage: usage})
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
		plan.record.UsageBytes = plan.usage
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
	usage, err := directoryUsage(b.namespaceDataPath(record.PluginInstanceID, record.StoreID))
	if err != nil {
		return Usage{}, err
	}
	if usage > record.QuotaBytes {
		return Usage{}, fmt.Errorf("%w: current usage %d exceeds quota %d", ErrQuotaExceeded, usage, record.QuotaBytes)
	}
	record.UsageBytes = usage
	record.UpdatedAt = b.now()
	if err := b.writeNamespaceRecordLocked(record); err != nil {
		return Usage{}, err
	}
	return Usage{
		PluginInstanceID: record.PluginInstanceID,
		StoreID:          record.StoreID,
		UsageBytes:       usage,
		QuotaBytes:       record.QuotaBytes,
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
			usage, err := directoryUsage(filepath.Join(root, entry.Name(), fileBrokerDataDir))
			if err != nil {
				return nil, err
			}
			record.UsageBytes = usage
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

func directoryUsage(root string) (int64, error) {
	var total int64
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
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	return total, err
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
