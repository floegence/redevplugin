package plugindata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
)

const (
	fileEntryTypeFile = iota
	fileEntryTypeDirectory
)

type namespaceAccess struct {
	root      *os.Root
	absRoot   string
	db        *sql.DB
	binding   Binding
	namespace Namespace
	usage     namespaceUsage
	usageKey  string
}

func (s *FileStore) withNamespace(ctx context.Context, pluginInstanceID string, requestScope sessionctx.ResourceScope, storeID string, kind NamespaceKind, write bool, use func(*namespaceAccess) error) error {
	return s.withNamespaceAccess(ctx, pluginInstanceID, &requestScope, storeID, kind, write, use)
}

func (s *FileStore) withNamespaceForUsage(ctx context.Context, pluginInstanceID string, storeID string, kind NamespaceKind, use func(*namespaceAccess) error) error {
	return s.withNamespaceAccess(ctx, pluginInstanceID, nil, storeID, kind, false, use)
}

func (s *FileStore) withNamespaceAccess(ctx context.Context, pluginInstanceID string, exactRequestScope *sessionctx.ResourceScope, storeID string, kind NamespaceKind, write bool, use func(*namespaceAccess) error) error {
	release, err := s.begin()
	if err != nil {
		return err
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return err
	}
	pluginID, err := normalizeIdentifier("plugin instance ID", pluginInstanceID)
	if err != nil {
		return err
	}
	storeID, err = normalizeIdentifier("store ID", storeID)
	if err != nil {
		return err
	}
	environment, err := environmentScope(ctx)
	if err != nil {
		return err
	}
	unlock := s.locks.lockRead(scopedLockKey(environment, pluginID))
	defer unlock()
	binding, err := s.getBinding(ctx, pluginID)
	if err != nil {
		return err
	}
	if binding.State != BindingActive {
		return storage.ErrNamespaceNotFound
	}
	workspace, manifest, err := s.workspaceForBinding(environment, binding)
	if err != nil {
		return err
	}
	var namespace Namespace
	found := false
	for _, candidate := range workspace.shape.Namespaces {
		if candidate.ID == storeID {
			namespace = candidate
			found = true
			break
		}
	}
	if !found {
		return storage.ErrNamespaceNotFound
	}
	if namespace.Kind != kind {
		return fmt.Errorf("%w: store %q is %s, not %s", storage.ErrInvalidNamespace, storeID, namespace.Kind, kind)
	}
	owner, err := resourceScope(ctx, sessionctx.ScopeKind(namespace.Scope))
	if err != nil {
		return err
	}
	if sessionctx.ScopeKind(namespace.Scope) != owner.Kind {
		return ErrStorageScopeMismatch
	}
	if exactRequestScope != nil && !exactRequestScope.Matches(owner) {
		return ErrStorageScopeMismatch
	}
	generationScopeKey := scopedGenerationCacheKey(owner, binding.GenerationID)
	initUnlock := s.namespaceLocks.lock(generationScopeKey+"\x00scope", true)
	if err := s.ensureWorkspaceScopeMetadata(ctx, workspace.root, manifest.Shape, owner); err != nil {
		initUnlock()
		return err
	}
	initUnlock()
	namespaceKey := scopedNamespaceCacheKey(owner, binding.GenerationID, namespace.ID)
	namespaceUnlock := s.namespaceLocks.lock(namespaceKey, write)
	defer namespaceUnlock()
	absRoot := filepath.Join(workspaceNamespaceRoot(workspace.root, owner), namespace.ID, namespaceDataName)
	namespaceRoot, err := filepath.Rel(s.root, absRoot)
	if err != nil || namespaceRoot == "." || strings.HasPrefix(namespaceRoot, ".."+string(filepath.Separator)) || filepath.IsAbs(namespaceRoot) {
		return fmt.Errorf("%w: namespace root is unsafe", storage.ErrInvalidNamespace)
	}
	info, err := s.rootHandle.Lstat(namespaceRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: namespace root is unsafe", storage.ErrInvalidNamespace)
	}
	if err := rejectRootSymlinkPath(s.rootHandle, namespaceRoot); err != nil {
		return fmt.Errorf("%w: namespace root is unsafe", storage.ErrInvalidNamespace)
	}
	usageKey := namespaceKey
	var db *sql.DB
	var root *os.Root
	if namespace.Kind == NamespaceFiles || namespace.Kind == NamespaceKV {
		if err := validateNamespaceDatabaseFileLayout(absRoot, namespace.Kind); err != nil {
			return err
		}
		dbKey := namespaceDatabaseCacheKey(generationScopeKey, namespace.ID, namespace.Kind)
		var releaseDB func()
		db, root, releaseDB, err = s.acquireNamespaceDatabase(ctx, dbKey, absRoot, info)
		if err != nil {
			return err
		}
		defer releaseDB()
	} else {
		root, err = s.rootHandle.OpenRoot(namespaceRoot)
		if err != nil {
			return err
		}
		defer root.Close()
	}
	usage, err := s.cachedNamespaceUsage(ctx, usageKey, absRoot, namespace.Kind, db)
	if err != nil {
		return err
	}
	return use(&namespaceAccess{root: root, absRoot: absRoot, db: db, binding: binding, namespace: namespace, usage: usage, usageKey: usageKey})
}

func (s *FileStore) cachedNamespaceUsage(ctx context.Context, key string, root string, kind NamespaceKind, db *sql.DB) (namespaceUsage, error) {
	return s.cachedNamespaceUsageWithLoader(ctx, key, root, kind, db, loadNamespaceUsage)
}

func (s *FileStore) cachedNamespaceUsageWithLoader(ctx context.Context, key string, root string, kind NamespaceKind, db *sql.DB, loader namespaceUsageLoader) (namespaceUsage, error) {
	s.usageMu.Lock()
	cached, ok := s.usage[key]
	if ok {
		s.usageMu.Unlock()
		return cached, nil
	}
	if s.usageFlights == nil {
		s.usageFlights = make(map[string]*namespaceUsageFlight)
	}
	if flight, ok := s.usageFlights[key]; ok {
		s.usageMu.Unlock()
		select {
		case <-ctx.Done():
			return namespaceUsage{}, ctx.Err()
		case <-flight.ready:
			return flight.usage, flight.err
		}
	}
	flight := &namespaceUsageFlight{ready: make(chan struct{})}
	s.usageFlights[key] = flight
	s.usageMu.Unlock()
	usage, err := loader(ctx, root, kind, db)
	s.usageMu.Lock()
	if err == nil {
		if existing, ok := s.usage[key]; ok {
			usage = existing
		} else {
			s.usage[key] = usage
		}
	}
	flight.usage = usage
	flight.err = err
	delete(s.usageFlights, key)
	close(flight.ready)
	s.usageMu.Unlock()
	return usage, err
}

func loadNamespaceUsage(ctx context.Context, root string, kind NamespaceKind, db *sql.DB) (namespaceUsage, error) {
	if kind == NamespaceFiles || kind == NamespaceKV {
		if db == nil {
			return namespaceUsage{}, storage.ErrInvalidNamespace
		}
		return readNamespaceDatabaseUsage(ctx, db)
	}
	return scanNamespaceUsage(root)
}

func (s *FileStore) setNamespaceUsage(key string, usage namespaceUsage) {
	s.usageMu.Lock()
	s.usage[key] = usage
	s.usageMu.Unlock()
}

func (s *FileStore) invalidateNamespaceUsage(key string) {
	s.usageMu.Lock()
	delete(s.usage, key)
	s.usageMu.Unlock()
}

func (a *namespaceAccess) resultUsage() storage.Usage {
	return storage.Usage{
		PluginInstanceID: a.binding.PluginInstanceID,
		StoreID:          a.namespace.ID,
		UsageBytes:       a.usage.bytes,
		QuotaBytes:       a.namespace.QuotaBytes,
		UsageFiles:       a.usage.files,
		QuotaFiles:       a.namespace.QuotaFiles,
	}
}

func enforceQuota(namespace Namespace, usage namespaceUsage) error {
	if usage.bytes > namespace.QuotaBytes || (namespace.QuotaFiles > 0 && usage.files > namespace.QuotaFiles) {
		return storage.ErrQuotaExceeded
	}
	return nil
}

func ensureFileDirectories(ctx context.Context, tx *sql.Tx, filePath string, updatedAtNS int64) (int64, error) {
	parent := namespaceParent(filePath)
	if parent == "." {
		return 0, nil
	}
	var directories []string
	for current := parent; current != "."; current = namespaceParent(current) {
		directories = append(directories, current)
	}
	var created int64
	for i := len(directories) - 1; i >= 0; i-- {
		path := directories[i]
		var entryType int
		if err := tx.QueryRowContext(ctx, `SELECT entry_type FROM file_entries WHERE path = ?`, path).Scan(&entryType); errors.Is(err, sql.ErrNoRows) {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO file_entries(path, parent, entry_type, content, size_bytes, updated_at_ns)
VALUES (?, ?, ?, NULL, 0, ?)`, path, namespaceParent(path), fileEntryTypeDirectory, updatedAtNS); err != nil {
				return 0, err
			}
			created++
		} else if err != nil {
			return 0, err
		} else if entryType != fileEntryTypeDirectory {
			return 0, storage.ErrInvalidFilePath
		}
	}
	return created, nil
}

func (s *FileStore) ReadFile(ctx context.Context, req storage.FileReadRequest) (result storage.FileReadResult, resultErr error) {
	path, err := canonicalNamespacePath(req.Path, false)
	if err != nil {
		return result, err
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceFiles, false, func(a *namespaceAccess) error {
		db := a.db
		var entryType int
		var data []byte
		var size int64
		if err := db.QueryRowContext(ctx, `SELECT entry_type, content, size_bytes FROM file_entries WHERE path = ?`, path).Scan(&entryType, &data, &size); errors.Is(err, sql.ErrNoRows) {
			return storage.ErrFileNotFound
		} else if err != nil {
			return err
		}
		if entryType != fileEntryTypeFile {
			return storage.ErrInvalidFilePath
		}
		if req.MaxBytes > 0 && size > req.MaxBytes {
			return storage.ErrFileTooLarge
		}
		result = storage.FileReadResult{Path: path, Data: append([]byte(nil), data...), SizeBytes: size, Usage: a.resultUsage()}
		return nil
	})
	return result, err
}

func (s *FileStore) WriteFile(ctx context.Context, req storage.FileWriteRequest) (result storage.FileWriteResult, resultErr error) {
	path, err := canonicalNamespacePath(req.Path, false)
	if err != nil {
		return result, err
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceFiles, true, func(a *namespaceAccess) error {
		db := a.db
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		currentUsage, err := readNamespaceDatabaseUsage(ctx, tx)
		if err != nil {
			return err
		}
		now := s.now().UnixNano()
		missingDirectories, err := ensureFileDirectories(ctx, tx, path, now)
		if err != nil {
			return err
		}
		var entryType int
		var oldSize int64
		exists := true
		if err := tx.QueryRowContext(ctx, `SELECT entry_type, size_bytes FROM file_entries WHERE path = ?`, path).Scan(&entryType, &oldSize); errors.Is(err, sql.ErrNoRows) {
			exists = false
			oldSize = 0
		} else if err != nil {
			return err
		} else if entryType != fileEntryTypeFile {
			return storage.ErrInvalidFilePath
		}
		projected := namespaceUsage{bytes: currentUsage.bytes - oldSize + int64(len(req.Data)), files: currentUsage.files + missingDirectories}
		if !exists {
			projected.files++
		}
		if err := enforceQuota(a.namespace, projected); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO file_entries(path, parent, entry_type, content, size_bytes, updated_at_ns)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(path) DO UPDATE SET
    content = excluded.content,
    size_bytes = excluded.size_bytes,
    updated_at_ns = excluded.updated_at_ns`, path, namespaceParent(path), fileEntryTypeFile, req.Data, len(req.Data), now); err != nil {
			return err
		}
		if err := writeNamespaceDatabaseUsage(ctx, tx, projected); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		a.usage = projected
		s.setNamespaceUsage(a.usageKey, projected)
		result = storage.FileWriteResult{Path: path, SizeBytes: int64(len(req.Data)), Usage: a.resultUsage()}
		return nil
	})
	return result, err
}

func (s *FileStore) DeleteFile(ctx context.Context, req storage.FileDeleteRequest) error {
	path, err := canonicalNamespacePath(req.Path, false)
	if err != nil {
		return err
	}
	return s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceFiles, true, func(a *namespaceAccess) error {
		db := a.db
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		currentUsage, err := readNamespaceDatabaseUsage(ctx, tx)
		if err != nil {
			return err
		}
		var entryType int
		var size int64
		if err := tx.QueryRowContext(ctx, `SELECT entry_type, size_bytes FROM file_entries WHERE path = ?`, path).Scan(&entryType, &size); errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		if entryType == fileEntryTypeDirectory && !req.Recursive {
			return storage.ErrInvalidFilePath
		}
		removed := namespaceUsage{bytes: size, files: 1}
		if entryType == fileEntryTypeDirectory {
			if err := tx.QueryRowContext(ctx, `
SELECT COALESCE(SUM(size_bytes), 0), COUNT(*)
FROM file_entries
WHERE path = ? OR (path >= ? AND path < ?)`, path, path+"/", path+"0").Scan(&removed.bytes, &removed.files); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM file_entries WHERE path = ? OR (path >= ? AND path < ?)`, path, path+"/", path+"0"); err != nil {
			return err
		}
		parent := namespaceParent(path)
		if parent != "." {
			if _, err := tx.ExecContext(ctx, `UPDATE file_entries SET updated_at_ns = ? WHERE path = ? AND entry_type = ?`, s.now().UnixNano(), parent, fileEntryTypeDirectory); err != nil {
				return err
			}
		}
		projected := namespaceUsage{bytes: max64(0, currentUsage.bytes-removed.bytes), files: max64(0, currentUsage.files-removed.files)}
		if err := writeNamespaceDatabaseUsage(ctx, tx, projected); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		a.usage = projected
		s.setNamespaceUsage(a.usageKey, a.usage)
		return nil
	})
}

func (s *FileStore) ListFiles(ctx context.Context, req storage.FileListRequest) (result storage.FileListResult, resultErr error) {
	path, err := canonicalNamespacePath(req.Path, true)
	if err != nil {
		return result, err
	}
	cursor := strings.TrimSpace(req.Cursor)
	if cursor != "" {
		cursor, err = canonicalNamespacePath(cursor, false)
		if err != nil || namespaceParent(cursor) != path {
			return result, storage.ErrInvalidFilePath
		}
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceFiles, false, func(a *namespaceAccess) error {
		db := a.db
		if path != "." {
			var entryType int
			if err := db.QueryRowContext(ctx, `SELECT entry_type FROM file_entries WHERE path = ?`, path).Scan(&entryType); errors.Is(err, sql.ErrNoRows) {
				return storage.ErrFileNotFound
			} else if err != nil {
				return err
			} else if entryType != fileEntryTypeDirectory {
				return storage.ErrInvalidFilePath
			}
		}
		limit := req.MaxEntries
		if limit <= 0 || limit > 1000 {
			limit = 1000
		}
		rows, err := db.QueryContext(ctx, `
SELECT path, entry_type, size_bytes, updated_at_ns
FROM file_entries
WHERE parent = ? AND path > ?
ORDER BY path
LIMIT ?`, path, cursor, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		entries := make([]storage.FileEntry, 0, limit+1)
		for rows.Next() {
			var entry storage.FileEntry
			var entryType int
			var updatedAtNS int64
			if err := rows.Scan(&entry.Path, &entryType, &entry.SizeBytes, &updatedAtNS); err != nil {
				return err
			}
			entry.Dir = entryType == fileEntryTypeDirectory
			entry.UpdatedAt = time.Unix(0, updatedAtNS).UTC()
			entries = append(entries, entry)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		nextCursor := ""
		if len(entries) > limit {
			entries = entries[:limit]
			nextCursor = entries[len(entries)-1].Path
		}
		result = storage.FileListResult{Path: path, Entries: entries, Usage: a.resultUsage(), NextCursor: nextCursor}
		return nil
	})
	return result, err
}

func (s *FileStore) GetKV(ctx context.Context, req storage.KVGetRequest) (result storage.KVGetResult, resultErr error) {
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return result, err
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceKV, false, func(a *namespaceAccess) error {
		db := a.db
		var value []byte
		var size int64
		if err := db.QueryRowContext(ctx, `SELECT value, size_bytes FROM kv_entries WHERE key = ?`, key).Scan(&value, &size); errors.Is(err, sql.ErrNoRows) {
			return storage.ErrKVKeyNotFound
		} else if err != nil {
			return err
		}
		if req.MaxBytes > 0 && size > req.MaxBytes {
			return storage.ErrKVValueTooLarge
		}
		result = storage.KVGetResult{Key: key, Value: append([]byte(nil), value...), SizeBytes: size, Usage: a.resultUsage()}
		return nil
	})
	return result, err
}

func (s *FileStore) PutKV(ctx context.Context, req storage.KVPutRequest) (result storage.KVPutResult, resultErr error) {
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return result, err
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceKV, true, func(a *namespaceAccess) error {
		db := a.db
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		currentUsage, err := readNamespaceDatabaseUsage(ctx, tx)
		if err != nil {
			return err
		}
		oldSize := int64(0)
		exists := true
		if err := tx.QueryRowContext(ctx, `SELECT size_bytes FROM kv_entries WHERE key = ?`, key).Scan(&oldSize); errors.Is(err, sql.ErrNoRows) {
			exists = false
		} else if err != nil {
			return err
		}
		projected := namespaceUsage{bytes: currentUsage.bytes - oldSize + int64(len(req.Value)), files: currentUsage.files}
		if !exists {
			projected.files++
		}
		if err := enforceQuota(a.namespace, projected); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO kv_entries(key, value, size_bytes, updated_at_ns)
VALUES (?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    size_bytes = excluded.size_bytes,
    updated_at_ns = excluded.updated_at_ns`, key, req.Value, len(req.Value), s.now().UnixNano()); err != nil {
			return err
		}
		if err := writeNamespaceDatabaseUsage(ctx, tx, projected); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		a.usage = projected
		s.setNamespaceUsage(a.usageKey, projected)
		result = storage.KVPutResult{Key: key, SizeBytes: int64(len(req.Value)), Usage: a.resultUsage()}
		return nil
	})
	return result, err
}

func (s *FileStore) DeleteKV(ctx context.Context, req storage.KVDeleteRequest) error {
	key, err := normalizeKVKey(req.Key)
	if err != nil {
		return err
	}
	return s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceKV, true, func(a *namespaceAccess) error {
		db := a.db
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		currentUsage, err := readNamespaceDatabaseUsage(ctx, tx)
		if err != nil {
			return err
		}
		var size int64
		if err := tx.QueryRowContext(ctx, `SELECT size_bytes FROM kv_entries WHERE key = ?`, key).Scan(&size); errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM kv_entries WHERE key = ?`, key); err != nil {
			return err
		}
		projected := namespaceUsage{bytes: max64(0, currentUsage.bytes-size), files: max64(0, currentUsage.files-1)}
		if err := writeNamespaceDatabaseUsage(ctx, tx, projected); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		a.usage = projected
		s.setNamespaceUsage(a.usageKey, a.usage)
		return nil
	})
}

func (s *FileStore) ListKV(ctx context.Context, req storage.KVListRequest) (result storage.KVListResult, resultErr error) {
	prefix, err := normalizeKVPrefix(req.Prefix)
	if err != nil {
		return result, err
	}
	cursor := strings.TrimSpace(req.Cursor)
	if cursor != "" {
		cursor, err = normalizeKVKey(cursor)
		if err != nil || !strings.HasPrefix(cursor, prefix) {
			return result, storage.ErrInvalidKVKey
		}
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceKV, false, func(a *namespaceAccess) error {
		db := a.db
		limit := req.MaxEntries
		if limit <= 0 || limit > 1000 {
			limit = 1000
		}
		query := `SELECT key, size_bytes, updated_at_ns FROM kv_entries WHERE key > ? ORDER BY key LIMIT ?`
		args := []any{cursor, limit + 1}
		if prefix != "" {
			if upper, ok := keyPrefixUpperBound(prefix); ok {
				query = `SELECT key, size_bytes, updated_at_ns FROM kv_entries WHERE key > ? AND key >= ? AND key < ? ORDER BY key LIMIT ?`
				args = []any{cursor, prefix, upper, limit + 1}
			} else {
				query = `SELECT key, size_bytes, updated_at_ns FROM kv_entries WHERE key > ? AND key >= ? ORDER BY key LIMIT ?`
				args = []any{cursor, prefix, limit + 1}
			}
		}
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		values := make([]storage.KVEntry, 0, limit+1)
		for rows.Next() {
			var entry storage.KVEntry
			var updatedAtNS int64
			if err := rows.Scan(&entry.Key, &entry.SizeBytes, &updatedAtNS); err != nil {
				return err
			}
			entry.UpdatedAt = time.Unix(0, updatedAtNS).UTC()
			values = append(values, entry)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		nextCursor := ""
		if len(values) > limit {
			values = values[:limit]
			nextCursor = values[len(values)-1].Key
		}
		result = storage.KVListResult{Prefix: prefix, Entries: values, Usage: a.resultUsage(), NextCursor: nextCursor}
		return nil
	})
	return result, err
}

func (s *FileStore) Usage(ctx context.Context, pluginInstanceID string, storeID string) (result storage.Usage, resultErr error) {
	for _, kind := range []NamespaceKind{NamespaceFiles, NamespaceKV, NamespaceSQLite} {
		err := s.withNamespaceForUsage(ctx, pluginInstanceID, storeID, kind, func(a *namespaceAccess) error {
			result = a.resultUsage()
			return nil
		})
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, storage.ErrInvalidNamespace) {
			return storage.Usage{}, err
		}
	}
	return storage.Usage{}, storage.ErrNamespaceNotFound
}

func (s *FileStore) ListNamespaces(ctx context.Context, pluginInstanceID string) ([]storage.NamespaceRecord, error) {
	release, err := s.begin()
	if err != nil {
		return nil, err
	}
	defer release()
	pluginID, err := normalizeIdentifier("plugin instance ID", pluginInstanceID)
	if err != nil {
		return nil, err
	}
	environment, err := environmentScope(ctx)
	if err != nil {
		return nil, err
	}
	unlock := s.locks.lockRead(scopedLockKey(environment, pluginID))
	defer unlock()
	binding, err := s.getBinding(ctx, pluginID)
	if err != nil {
		if errors.Is(err, ErrBindingNotFound) {
			return []storage.NamespaceRecord{}, nil
		}
		return nil, err
	}
	workspace, manifest, err := s.workspaceForBinding(environment, binding)
	if err != nil {
		return nil, err
	}
	owners := make([]sessionctx.ResourceScope, len(workspace.shape.Namespaces))
	lockKeys := make([]string, 0, len(workspace.shape.Namespaces))
	initializedScopes := make(map[sessionctx.ResourceScope]struct{}, 2)
	for index, namespace := range workspace.shape.Namespaces {
		owner, err := resourceScope(ctx, sessionctx.ScopeKind(namespace.Scope))
		if err != nil {
			return nil, err
		}
		owners[index] = owner
		if _, initialized := initializedScopes[owner]; !initialized {
			generationScopeKey := scopedGenerationCacheKey(owner, binding.GenerationID)
			initUnlock := s.namespaceLocks.lock(generationScopeKey+"\x00scope", true)
			err = s.ensureWorkspaceScopeMetadata(ctx, workspace.root, manifest.Shape, owner)
			initUnlock()
			if err != nil {
				return nil, err
			}
			initializedScopes[owner] = struct{}{}
		}
		lockKeys = append(lockKeys, scopedNamespaceCacheKey(owner, binding.GenerationID, namespace.ID))
	}
	namespaceUnlock := s.namespaceLocks.lockManyMode(false, lockKeys...)
	defer namespaceUnlock()
	records := make([]storage.NamespaceRecord, 0, len(workspace.shape.Namespaces))
	for index, namespace := range workspace.shape.Namespaces {
		owner := owners[index]
		root := filepath.Join(workspaceNamespaceRoot(workspace.root, owner), namespace.ID, namespaceDataName)
		namespaceRoot, err := filepath.Rel(s.root, root)
		if err != nil || namespaceRoot == "." || strings.HasPrefix(namespaceRoot, ".."+string(filepath.Separator)) || filepath.IsAbs(namespaceRoot) {
			return nil, fmt.Errorf("%w: namespace root is unsafe", storage.ErrInvalidNamespace)
		}
		info, err := s.rootHandle.Lstat(namespaceRoot)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%w: namespace root is unsafe", storage.ErrInvalidNamespace)
		}
		if err := rejectRootSymlinkPath(s.rootHandle, namespaceRoot); err != nil {
			return nil, fmt.Errorf("%w: namespace root is unsafe", storage.ErrInvalidNamespace)
		}
		var db *sql.DB
		releaseDB := func() {}
		if namespace.Kind == NamespaceFiles || namespace.Kind == NamespaceKV {
			if err := validateNamespaceDatabaseFileLayout(root, namespace.Kind); err != nil {
				return nil, err
			}
			dbKey := namespaceDatabaseCacheKey(scopedGenerationCacheKey(owner, binding.GenerationID), namespace.ID, namespace.Kind)
			db, _, releaseDB, err = s.acquireNamespaceDatabase(ctx, dbKey, root, info)
			if err != nil {
				return nil, err
			}
		}
		usage, err := s.cachedNamespaceUsage(ctx, scopedNamespaceCacheKey(owner, binding.GenerationID, namespace.ID), root, namespace.Kind, db)
		releaseDB()
		if err != nil {
			return nil, err
		}
		records = append(records, storage.NamespaceRecord{Namespace: storage.Namespace{PluginInstanceID: pluginID, StoreID: namespace.ID, Kind: storage.StoreKind(namespace.Kind), Scope: namespace.Scope, QuotaBytes: namespace.QuotaBytes, QuotaFiles: namespace.QuotaFiles, SchemaVersion: namespace.SchemaVersion}, GenerationID: binding.GenerationID, UsageBytes: usage.bytes, UsageFiles: usage.files})
	}
	return records, nil
}

func cleanRelativePath(raw string, allowRoot bool) (string, error) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" {
		if allowRoot {
			return ".", nil
		}
		return "", storage.ErrInvalidFilePath
	}
	if strings.HasPrefix(raw, "/") {
		return "", storage.ErrInvalidFilePath
	}
	clean := filepath.Clean(filepath.FromSlash(raw))
	if clean == "." && allowRoot {
		return clean, nil
	}
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", storage.ErrInvalidFilePath
	}
	return clean, nil
}

func rejectRootSymlinkPath(root *os.Root, path string) error {
	if path == "." || path == "" {
		return nil
	}
	current := ""
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return storage.ErrInvalidFilePath
		}
	}
	return nil
}

func missingRootDirectories(root *os.Root, path string) (int64, error) {
	if path == "." || path == "" {
		return 0, nil
	}
	current := ""
	var missing int64
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			missing++
			continue
		}
		if err != nil {
			return 0, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return 0, storage.ErrInvalidFilePath
		}
	}
	return missing, nil
}

func normalizeKVKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > storage.MaxKVKeyBytes || strings.ContainsRune(key, '\x00') || !utf8.ValidString(key) {
		return "", storage.ErrInvalidKVKey
	}
	return key, nil
}

func normalizeKVPrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if len(prefix) > storage.MaxKVKeyBytes || strings.ContainsRune(prefix, '\x00') || !utf8.ValidString(prefix) {
		return "", storage.ErrInvalidKVKey
	}
	return prefix, nil
}

func keyPrefixUpperBound(prefix string) (string, bool) {
	runes := []rune(prefix)
	for i := len(runes) - 1; i >= 0; i-- {
		if runes[i] < unicode.MaxRune {
			runes[i]++
			return string(runes[:i+1]), true
		}
	}
	return "", false
}

func max64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
