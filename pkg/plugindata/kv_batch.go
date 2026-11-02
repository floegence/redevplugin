package plugindata

import (
	"context"
	"database/sql"
	"errors"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

func (s *FileStore) BatchKV(ctx context.Context, req storage.KVBatchRequest) (result storage.KVBatchResult, err error) {
	if len(req.Mutations) == 0 || len(req.Mutations) > 64 {
		return result, storage.ErrInvalidKVKey
	}
	seen, total := map[string]bool{}, 0
	for _, item := range req.Mutations {
		key, err := normalizeKVKey(item.Key)
		if err != nil || key != item.Key || seen[key] || item.Delete && len(item.Value) != 0 {
			return result, storage.ErrInvalidKVKey
		}
		seen[key] = true
		total += len(item.Value)
		if total > 64<<10 {
			return result, storage.ErrKVValueTooLarge
		}
	}
	err = s.withNamespace(ctx, req.PluginInstanceID, req.ResourceScope, req.StoreID, NamespaceKV, true, func(a *namespaceAccess) error {
		tx, err := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		usage, err := readNamespaceDatabaseUsage(ctx, tx)
		if err != nil {
			return err
		}
		etags := map[string]string{}
		for _, item := range req.Mutations {
			var old []byte
			var size int64
			err := tx.QueryRowContext(ctx, `SELECT value,size_bytes FROM kv_entries WHERE key = ?`, item.Key).Scan(&old, &size)
			exists := !errors.Is(err, sql.ErrNoRows)
			if err != nil && exists {
				return err
			}
			actual := ""
			if exists {
				actual = kvETag(old)
			}
			if item.ExpectedETag != nil && *item.ExpectedETag != actual {
				return storage.ErrRevisionConflict
			}
			usage.bytes -= size
			if item.Delete {
				if exists {
					usage.files--
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM kv_entries WHERE key = ?`, item.Key); err != nil {
					return err
				}
			} else {
				if !exists {
					usage.files++
				}
				usage.bytes += int64(len(item.Value))
				if _, err := tx.ExecContext(ctx, `INSERT INTO kv_entries(key,value,size_bytes,updated_at_ns) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,size_bytes=excluded.size_bytes,updated_at_ns=excluded.updated_at_ns`, item.Key, item.Value, len(item.Value), s.now().UnixNano()); err != nil {
					return err
				}
				etags[item.Key] = kvETag(item.Value)
			}
		}
		if err := enforceQuota(a.namespace, usage); err != nil {
			return err
		}
		if err := writeNamespaceDatabaseUsage(ctx, tx, usage); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			s.invalidateNamespaceUsage(a.usageKey)
			return mutation.Unknown(err)
		}
		a.usage = usage
		s.setNamespaceUsage(a.usageKey, usage)
		result = storage.KVBatchResult{ETags: etags, Usage: a.resultUsage()}
		return nil
	})
	return result, err
}
