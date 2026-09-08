package remoterelease

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	documentCacheKind             = "redevplugin_release_documents"
	documentCacheVersion          = 1
	documentCacheMaxEntries       = 128
	documentCacheMaxBytes         = 8 << 20
	documentCacheMaxDocumentBytes = 1 << 20
	documentCacheMetadataSQL      = `CREATE TABLE cache_metadata (id INTEGER PRIMARY KEY CHECK(id=1), kind TEXT NOT NULL, version INTEGER NOT NULL)`
	documentCacheDocumentsSQL     = `CREATE TABLE documents (digest TEXT PRIMARY KEY, value BLOB NOT NULL, sequence INTEGER NOT NULL UNIQUE)`
)

// DocumentCache retains only content-addressed release document bytes. It never
// stores trust decisions. AssetSet rechecks the current projection's size and
// digest; ReleaseTrustService still verifies signatures, epochs and expiry.
// One cache can be shared by all release projections in a host environment.
type DocumentCache struct{ db *sql.DB }

// OpenDocumentCache opens a bounded, disposable byte cache at a host-selected
// path. Unknown or incompatible databases are left unchanged. Hosts may omit
// this optional cache if opening it fails; remote verification remains usable.
func OpenDocumentCache(ctx context.Context, path string) (*DocumentCache, error) {
	if ctx == nil || path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("document cache requires an absolute canonical path")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("document cache must be a regular file")
		}
		if info.Size() > 0 {
			// The schema/lineage never changes after creation. Inspect those pages
			// without replaying a journal; only an admitted cache may reopen
			// read/write and let SQLite recover an interrupted data transaction.
			location := &url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro&immutable=1"}
			existing, err := sql.Open("sqlite", location.String())
			if err != nil {
				return nil, err
			}
			err = validateDocumentCache(ctx, existing)
			closeErr := existing.Close()
			if err != nil || closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var tx *sql.Tx
	fail := func(err error) (*DocumentCache, error) {
		if tx != nil {
			_ = tx.Rollback()
		}
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout=100; PRAGMA synchronous=FULL; PRAGMA max_page_count=4096`); err != nil {
		return fail(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = tx.Rollback() }()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&count); err != nil {
		return fail(err)
	}
	if count == 0 {
		for _, statement := range []string{documentCacheMetadataSQL, documentCacheDocumentsSQL} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fail(err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO cache_metadata VALUES(1,?,?)`, documentCacheKind, documentCacheVersion); err != nil {
			return fail(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	if err := validateDocumentCache(ctx, db); err != nil {
		return fail(err)
	}
	return &DocumentCache{db: db}, nil
}

func validateDocumentCache(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	expected := map[string]string{"cache_metadata": documentCacheMetadataSQL, "documents": documentCacheDocumentsSQL}
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			_ = rows.Close()
			return err
		}
		if expected[name] != statement {
			_ = rows.Close()
			return errors.New("document cache schema is incompatible")
		}
		delete(expected, name)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	if len(expected) != 0 {
		return errors.New("document cache schema is incomplete")
	}
	var kind string
	var version int
	if err := db.QueryRowContext(ctx, `SELECT kind,version FROM cache_metadata WHERE id=1`).Scan(&kind, &version); err != nil {
		return err
	}
	if kind != documentCacheKind || version != documentCacheVersion {
		return errors.New("document cache lineage is incompatible")
	}
	return nil
}

func (cache *DocumentCache) Close() error {
	if cache == nil || cache.db == nil {
		return nil
	}
	return cache.db.Close()
}

func (cache *DocumentCache) read(ctx context.Context, asset Asset) []byte {
	if cache == nil || asset.Size > documentCacheMaxDocumentBytes {
		return nil
	}
	cacheCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	var value []byte
	// Bound allocation even when a cache file has been modified outside this API.
	if err := cache.db.QueryRowContext(cacheCtx, `SELECT value FROM documents WHERE digest=? AND length(value)=? AND length(value)<=?`, asset.SHA256, asset.Size, documentCacheMaxDocumentBytes).Scan(&value); err != nil {
		return nil
	}
	digest := sha256.Sum256(value)
	if hex.EncodeToString(digest[:]) != asset.SHA256 {
		return nil
	}
	return value
}

func (cache *DocumentCache) remember(ctx context.Context, asset Asset, value []byte) error {
	if cache == nil || len(value) > documentCacheMaxDocumentBytes {
		return nil
	}
	digest := sha256.Sum256(value)
	if int64(len(value)) != asset.Size || hex.EncodeToString(digest[:]) != asset.SHA256 {
		return ErrAssetMismatch
	}
	cacheCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	ctx = cacheCtx
	tx, err := cache.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(max(sequence),0)+1 FROM documents`).Scan(&sequence); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM documents WHERE digest=?`, asset.SHA256); err != nil {
		return err
	}
	var count, total int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(value)),0) FROM documents`).Scan(&count, &total); err != nil {
		return err
	}
	for count >= documentCacheMaxEntries || total+int64(len(value)) > documentCacheMaxBytes {
		var oldest string
		var size int64
		if err := tx.QueryRowContext(ctx, `SELECT digest,length(value) FROM documents ORDER BY sequence LIMIT 1`).Scan(&oldest, &size); err != nil {
			return fmt.Errorf("evict cached document: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM documents WHERE digest=?`, oldest); err != nil {
			return err
		}
		count--
		total -= size
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO documents(digest,value,sequence) VALUES(?,?,?)`, asset.SHA256, value, sequence); err != nil {
		return err
	}
	return tx.Commit()
}
