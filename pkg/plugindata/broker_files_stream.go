package plugindata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

const fileStreamChunkBytes = 64 << 10

// Temporary snapshots share a per-owner namespace budget of two namespace
// quotas. It bounds concurrent staging without reducing persistent quota.
type namespaceStageWriter struct {
	store  *FileStore
	key    string
	limit  int64
	bytes  int64
	writer io.Writer
}

func (w *namespaceStageWriter) Write(p []byte) (int, error) {
	w.store.streamMu.Lock()
	if w.store.streamBytes == nil {
		w.store.streamBytes = map[string]int64{}
	}
	if int64(len(p)) > w.limit-w.store.streamBytes[w.key] {
		w.store.streamMu.Unlock()
		return 0, storage.ErrQuotaExceeded
	}
	w.store.streamBytes[w.key] += int64(len(p))
	w.bytes += int64(len(p))
	w.store.streamMu.Unlock()
	return w.writer.Write(p)
}
func (w *namespaceStageWriter) release() {
	w.store.streamMu.Lock()
	defer w.store.streamMu.Unlock()
	w.store.streamBytes[w.key] -= w.bytes
	if w.store.streamBytes[w.key] == 0 {
		delete(w.store.streamBytes, w.key)
	}
}
func streamStageKey(plugin, store string, req storage.FileReadRequest) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", plugin, store, req.ResourceScope.Kind, req.ResourceScope.OwnerEnvHash, req.ResourceScope.OwnerUserHash)
}

func (s *FileStore) ReadFileStream(ctx context.Context, req storage.FileReadRequest, destination io.Writer) (result storage.FileReadResult, resultErr error) {
	release, err := s.begin()
	if err != nil {
		return result, err
	}
	defer release()
	stage, err := s.newStage("file-download")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(stage)
	staged, err := os.OpenFile(filepath.Join(stage, "content"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return result, err
	}
	defer staged.Close()
	var quota int64
	if err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceFiles, false, func(a *namespaceAccess) error { quota = a.namespace.QuotaBytes; return nil }); err != nil {
		return result, err
	}
	budget := &namespaceStageWriter{store: s, key: streamStageKey(req.PluginInstanceID, req.StoreID, req), limit: quota * 2, writer: staged}
	defer budget.release()
	result, err = s.readFileTo(ctx, req, budget)
	if err != nil {
		return result, err
	}
	if _, err = staged.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	buffer := make([]byte, fileStreamChunkBytes)
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := staged.Read(buffer)
		if n > 0 {
			written, err := destination.Write(buffer[:n])
			if err != nil {
				return result, err
			}
			if written != n {
				return result, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return result, nil
		}
		if readErr != nil {
			return result, readErr
		}
	}
}

func (s *FileStore) readFileTo(ctx context.Context, req storage.FileReadRequest, destination io.Writer) (result storage.FileReadResult, resultErr error) {
	path, err := canonicalNamespacePath(req.Path, false)
	if err != nil {
		return result, err
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceFiles, false, func(a *namespaceAccess) error {
		var kind int
		var size int64
		var inline bool
		if err := a.db.QueryRowContext(ctx, `SELECT entry_type,size_bytes,content IS NOT NULL FROM file_entries WHERE path=?`, path).Scan(&kind, &size, &inline); errors.Is(err, sql.ErrNoRows) {
			return storage.ErrFileNotFound
		} else if err != nil {
			return err
		}
		if kind != fileEntryTypeFile {
			return storage.ErrInvalidFilePath
		}
		if req.MaxBytes > 0 && size > req.MaxBytes {
			return storage.ErrFileTooLarge
		}
		if !inline {
			rows, err := a.db.QueryContext(ctx, `SELECT ordinal,content FROM file_chunks WHERE path=? ORDER BY ordinal`, path)
			if err != nil {
				return err
			}
			defer rows.Close()
			var offset int64
			ordinal := 0
			for rows.Next() {
				var index int
				var chunk sql.RawBytes
				if err := rows.Scan(&index, &chunk); err != nil {
					return err
				}
				if index != ordinal || len(chunk) == 0 || len(chunk) > fileStreamChunkBytes || int64(len(chunk)) > size-offset {
					return ErrDatasetCorrupt
				}
				n, err := destination.Write(chunk)
				if err != nil {
					return err
				}
				if n != len(chunk) {
					return io.ErrShortWrite
				}
				offset += int64(n)
				ordinal++
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if offset != size {
				return ErrDatasetCorrupt
			}
			result = storage.FileReadResult{Path: path, SizeBytes: size, Usage: a.resultUsage()}
			return nil
		}
		for offset, ordinal := int64(0), 0; offset < size; ordinal++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			var chunk []byte
			var err error
			if inline {
				err = a.db.QueryRowContext(ctx, `SELECT substr(content,?,?) FROM file_entries WHERE path=?`, offset+1, fileStreamChunkBytes, path).Scan(&chunk)
			} else {
				err = a.db.QueryRowContext(ctx, `SELECT content FROM file_chunks WHERE path=? AND ordinal=?`, path, ordinal).Scan(&chunk)
			}
			if err != nil {
				return err
			}
			if len(chunk) == 0 || len(chunk) > fileStreamChunkBytes || int64(len(chunk)) > size-offset {
				return ErrDatasetCorrupt
			}
			n, err := destination.Write(chunk)
			if err != nil {
				return err
			}
			if n != len(chunk) {
				return io.ErrShortWrite
			}
			offset += int64(n)
		}
		result = storage.FileReadResult{Path: path, SizeBytes: size, Usage: a.resultUsage()}
		return nil
	})
	return result, err
}

func (s *FileStore) WriteFileStream(ctx context.Context, req storage.FileStreamWriteRequest, source io.Reader) (result storage.FileWriteResult, resultErr error) {
	path, err := canonicalNamespacePath(req.Path, false)
	if err != nil {
		return result, err
	}
	releaseStore, err := s.begin()
	if err != nil {
		return result, err
	}
	defer releaseStore()
	var maximum int64
	var generation string
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceFiles, false, func(a *namespaceAccess) error {
		maximum = a.namespace.QuotaBytes
		generation = a.binding.GenerationID
		return nil
	})
	if err != nil {
		return result, err
	}
	if req.MaxBytes > 0 && req.MaxBytes < maximum {
		maximum = req.MaxBytes
	}
	stage, err := s.newStage("file-upload")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(stage)
	staged, err := os.OpenFile(filepath.Join(stage, "content"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return result, err
	}
	defer staged.Close()
	budget := &namespaceStageWriter{store: s, key: streamStageKey(req.PluginInstanceID, req.StoreID, storage.FileReadRequest{ResourceScope: req.ResourceScope}), limit: maximum * 2, writer: staged}
	defer budget.release()
	buffer := make([]byte, fileStreamChunkBytes)
	var uploaded int64
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := source.Read(buffer)
		if n < 0 || n > len(buffer) {
			return result, io.ErrShortBuffer
		}
		if int64(n) > maximum-uploaded {
			return result, storage.ErrQuotaExceeded
		}
		if n > 0 {
			written, err := budget.Write(buffer[:n])
			if err != nil {
				return result, err
			}
			if written != n {
				return result, io.ErrShortWrite
			}
			uploaded += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return result, readErr
		}
		if n == 0 {
			return result, io.ErrNoProgress
		}
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	source = staged
	// Acquire the platform fence before namespace locks, never while receiving data.
	if req.BeforeCommit != nil {
		release, err := req.BeforeCommit(ctx)
		if err != nil {
			return result, err
		}
		defer release()
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceFiles, true, func(a *namespaceAccess) error {
		if a.binding.GenerationID != generation {
			return ErrBindingConflict
		}
		tx, err := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		usage, err := readNamespaceDatabaseUsage(ctx, tx)
		if err != nil {
			return err
		}
		now := s.now().UnixNano()
		dirs, err := ensureFileDirectories(ctx, tx, path, now)
		if err != nil {
			return err
		}
		var kind int
		var oldSize int64
		exists := true
		if err := tx.QueryRowContext(ctx, `SELECT entry_type,size_bytes FROM file_entries WHERE path=?`, path).Scan(&kind, &oldSize); errors.Is(err, sql.ErrNoRows) {
			exists = false
		} else if err != nil {
			return err
		} else if kind != fileEntryTypeFile {
			return storage.ErrInvalidFilePath
		}
		projected := namespaceUsage{bytes: usage.bytes - oldSize, files: usage.files + dirs}
		if !exists {
			projected.files++
		}
		if err := enforceQuota(a.namespace, projected); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO file_entries(path,parent,entry_type,content,size_bytes,updated_at_ns) VALUES(?,?,0,NULL,0,?) ON CONFLICT(path) DO UPDATE SET content=NULL,size_bytes=0,updated_at_ns=excluded.updated_at_ns`, path, namespaceParent(path), now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM file_chunks WHERE path=?`, path); err != nil {
			return err
		}
		buffer := make([]byte, fileStreamChunkBytes)
		var size int64
		for ordinal := 0; ; ordinal++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := source.Read(buffer)
			if n < 0 || n > len(buffer) {
				return io.ErrShortBuffer
			}
			if n > 0 {
				size += int64(n)
				projected.bytes += int64(n)
				if req.MaxBytes > 0 && size > req.MaxBytes {
					return storage.ErrFileTooLarge
				}
				if err := enforceQuota(a.namespace, projected); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO file_chunks(path,ordinal,content) VALUES(?,?,?)`, path, ordinal, buffer[:n]); err != nil {
					return err
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrNoProgress
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE file_entries SET size_bytes=? WHERE path=?`, size, path); err != nil {
			return err
		}
		if err := writeNamespaceDatabaseUsage(ctx, tx, projected); err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		a.usage = projected
		s.setNamespaceUsage(a.usageKey, projected)
		result = storage.FileWriteResult{Path: path, SizeBytes: size, Usage: a.resultUsage()}
		return nil
	})
	return result, err
}
