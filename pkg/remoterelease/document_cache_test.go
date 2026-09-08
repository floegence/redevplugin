package remoterelease

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDocumentCacheReopensWithoutNetworkAndRevalidatesBytes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "documents.sqlite")
	value := []byte("immutable signed document bytes")
	item := asset("sources/example/root/current.json", "https://artifacts.example.test/root", value)
	cache, err := OpenDocumentCache(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &memoryFetcher{values: map[string][]byte{item.URL: value}}
	openSet := func(cache *DocumentCache) *AssetSet {
		set, err := NewAssetSet(AssetSetOptions{SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"}, Assets: []Asset{item}, Fetcher: fetcher, DocumentCache: cache})
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	read := func(set *AssetSet) {
		t.Helper()
		got, _, err := set.fetch(ctx, item.Locator, "release_document", 1024, []string{"artifacts.example.test"}, "", nil)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("read: %q %v", got, err)
		}
	}
	read(openSet(cache))
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	cache, err = OpenDocumentCache(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	read(openSet(cache))
	if len(fetcher.requests) != 1 {
		t.Fatalf("restart downloaded cached bytes: %d", len(fetcher.requests))
	}
	if _, err := cache.db.ExecContext(ctx, `UPDATE documents SET value=?`, bytes.Repeat([]byte("x"), len(value))); err != nil {
		t.Fatal(err)
	}
	read(openSet(cache))
	if len(fetcher.requests) != 2 {
		t.Fatal("corrupt bytes were not fetched again")
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	read(openSet(cache))
	if len(fetcher.requests) != 3 {
		t.Fatal("closed cache blocked verified remote transport")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := openSet(cache).fetch(canceled, item.Locator, "release_document", 1024, []string{"artifacts.example.test"}, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestDocumentCacheOnlyReusesCurrentProjectionAndDocumentRole(t *testing.T) {
	ctx := context.Background()
	cache, err := OpenDocumentCache(ctx, filepath.Join(t.TempDir(), "documents.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	first := []byte("first")
	second := []byte("later")
	original := asset("sources/example/root/current.json", "https://artifacts.example.test/root", first)
	if err := cache.remember(ctx, original, first); err != nil {
		t.Fatal(err)
	}
	current := asset(original.Locator, original.URL, second)
	if cache.read(ctx, current) != nil {
		t.Fatal("old projection was treated as current")
	}
	wrongSize := original
	wrongSize.Size++
	if cache.read(ctx, wrongSize) != nil {
		t.Fatal("wrong size was accepted")
	}
	fetcher := &memoryFetcher{values: map[string][]byte{original.URL: first}}
	set, err := NewAssetSet(AssetSetOptions{SourceID: "example", Channel: "stable", AllowedHosts: []string{"artifacts.example.test"}, Assets: []Asset{original}, Fetcher: fetcher, DocumentCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := set.fetch(ctx, original.Locator, "package", 1024, []string{"artifacts.example.test"}, "", nil); err != nil {
		t.Fatal(err)
	}
	if len(fetcher.requests) != 1 {
		t.Fatal("package fetch reused document cache")
	}
}

func TestDocumentCacheBoundsCountAndBytes(t *testing.T) {
	for _, size := range []int{32, documentCacheMaxDocumentBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			ctx := context.Background()
			cache, err := OpenDocumentCache(ctx, filepath.Join(t.TempDir(), "documents.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer cache.Close()
			limit := min(documentCacheMaxEntries, documentCacheMaxBytes/size)
			for index := 0; index < limit+2; index++ {
				value := bytes.Repeat([]byte("x"), size)
				copy(value, fmt.Sprintf("%08d", index))
				item := asset("sources/example/root/current.json", "https://artifacts.example.test/root", value)
				if err := cache.remember(ctx, item, value); err != nil {
					t.Fatal(err)
				}
			}
			var count, total int
			if err := cache.db.QueryRowContext(ctx, `SELECT count(*),sum(length(value)) FROM documents`).Scan(&count, &total); err != nil {
				t.Fatal(err)
			}
			if count != limit || total > documentCacheMaxBytes {
				t.Fatalf("count=%d bytes=%d", count, total)
			}
		})
	}
}

func TestDocumentCacheRejectsUnknownLineageWithoutMutation(t *testing.T) {
	for _, mutation := range []string{`UPDATE cache_metadata SET version=2`, `UPDATE cache_metadata SET kind='another_application'`, `CREATE TABLE unknown(value TEXT)`} {
		t.Run(mutation, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "documents.sqlite")
			cache, err := OpenDocumentCache(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cache.db.ExecContext(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			if err := cache.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenDocumentCache(ctx, path); err == nil {
				opened.Close()
				t.Fatal("unknown cache was accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("unknown state was modified")
			}
		})
	}
}

func TestDocumentCacheRecoversInterruptedCreationAndTransactions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "documents.sqlite")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenDocumentCache(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("committed")
	item := asset("sources/example/root/current.json", "https://artifacts.example.test/root", value)
	if err := cache.remember(ctx, item, value); err != nil {
		t.Fatal(err)
	}
	tx, err := cache.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM documents`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	cache, err = OpenDocumentCache(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if !bytes.Equal(cache.read(ctx, item), value) {
		t.Fatal("interrupted transaction discarded committed bytes")
	}
}

func TestDocumentCacheCanonicalSchema(t *testing.T) {
	raw, err := os.ReadFile("../../spec/internal/release-document-cache.sql")
	if err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%s;\n%s;\nINSERT INTO cache_metadata VALUES(1,'%s',%d);\n", documentCacheMetadataSQL, documentCacheDocumentsSQL, documentCacheKind, documentCacheVersion)
	if string(raw) != expected {
		t.Fatal("released document cache schema drifted")
	}
}

func TestDocumentCacheCrashRecovery(t *testing.T) {
	ctx := context.Background()
	if path := os.Getenv("REDEVPLUGIN_CACHE_CRASH_PATH"); path != "" {
		cache, err := OpenDocumentCache(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := cache.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE documents SET value=zeroblob(1048576)`); err != nil {
			t.Fatal(err)
		}
		os.Exit(23) // Intentionally skip rollback and Close in a separate process.
	}
	path := filepath.Join(t.TempDir(), "documents.sqlite")
	cache, err := OpenDocumentCache(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var items []Asset
	for i := 0; i < 8; i++ {
		value := bytes.Repeat([]byte{byte(i + 1)}, documentCacheMaxDocumentBytes)
		item := asset("sources/example/root/current.json", "https://artifacts.example.test/root", value)
		items = append(items, item)
		if err := cache.remember(ctx, item, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestDocumentCacheCrashRecovery$")
	command.Env = append(os.Environ(), "REDEVPLUGIN_CACHE_CRASH_PATH="+path)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("crash helper: %v %s", err, output)
	}
	cache, err = OpenDocumentCache(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	for _, item := range items {
		if cache.read(ctx, item) == nil {
			t.Fatal("crash lost a committed document")
		}
	}
}
