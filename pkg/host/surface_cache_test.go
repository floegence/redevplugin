package host

import (
	"testing"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

func TestSurfaceDocumentCacheUsesFingerprintEntryPathAndDigest(t *testing.T) {
	cache := newSurfaceDocumentCache(2, 1<<20)
	document := pluginpkg.OpaqueSurfaceDocument{
		SchemaVersion: pluginpkg.OpaqueSurfaceDocumentSchemaVersion,
		EntryPath:     "ui/index.html",
		EntrySHA256:   "sha256:entry",
		Styles:        []pluginpkg.OpaqueSurfaceStyle{{Path: "ui/app.css", Content: "body{}"}},
		Assets:        []pluginpkg.OpaqueSurfaceAsset{{BindingID: "asset_1", Path: "ui/logo.png"}},
	}
	cache.Put("sha256:fingerprint", "ui/index.html", "sha256:entry", document)

	if _, ok := cache.Get("sha256:other", "ui/index.html", "sha256:entry"); ok {
		t.Fatal("cache returned a document for a different active fingerprint")
	}
	if _, ok := cache.Get("sha256:fingerprint", "ui/other.html", "sha256:entry"); ok {
		t.Fatal("cache returned a document for a different entry path")
	}
	if _, ok := cache.Get("sha256:fingerprint", "ui/index.html", "sha256:other"); ok {
		t.Fatal("cache returned a document for a different entry digest")
	}
	got, ok := cache.Get("sha256:fingerprint", "ui/index.html", "sha256:entry")
	if !ok || got.EntryPath != document.EntryPath {
		t.Fatalf("cache result = %#v, %v", got, ok)
	}

	got.Styles[0].Content = "poisoned"
	got.Assets[0].Path = "ui/poisoned.png"
	again, ok := cache.Get("sha256:fingerprint", "ui/index.html", "sha256:entry")
	if !ok || again.Styles[0].Content != "body{}" || again.Assets[0].Path != "ui/logo.png" {
		t.Fatalf("cached document was mutated through a returned value: %#v", again)
	}
}

func TestSurfaceDocumentCacheKeepsIdenticalBytesAtDistinctEntryPaths(t *testing.T) {
	cache := newSurfaceDocumentCache(2, 1<<20)
	first := pluginpkg.OpaqueSurfaceDocument{EntryPath: "ui/first.html", EntrySHA256: "sha256:same"}
	second := pluginpkg.OpaqueSurfaceDocument{EntryPath: "ui/second.html", EntrySHA256: "sha256:same"}
	cache.Put("sha256:fingerprint", first.EntryPath, first.EntrySHA256, first)
	cache.Put("sha256:fingerprint", second.EntryPath, second.EntrySHA256, second)

	gotFirst, firstOK := cache.Get("sha256:fingerprint", first.EntryPath, first.EntrySHA256)
	gotSecond, secondOK := cache.Get("sha256:fingerprint", second.EntryPath, second.EntrySHA256)
	if !firstOK || !secondOK || gotFirst.EntryPath != first.EntryPath || gotSecond.EntryPath != second.EntryPath {
		t.Fatalf("cache collapsed distinct paths: first=%#v/%v second=%#v/%v", gotFirst, firstOK, gotSecond, secondOK)
	}
}

func TestSurfaceDocumentCacheEvictsLeastRecentlyUsedEntry(t *testing.T) {
	cache := newSurfaceDocumentCache(2, 1<<20)
	cache.Put("fingerprint_1", "ui/one.html", "entry_1", pluginpkg.OpaqueSurfaceDocument{EntryPath: "ui/one.html"})
	cache.Put("fingerprint_2", "ui/two.html", "entry_2", pluginpkg.OpaqueSurfaceDocument{EntryPath: "ui/two.html"})
	if _, ok := cache.Get("fingerprint_1", "ui/one.html", "entry_1"); !ok {
		t.Fatal("expected first cache entry")
	}
	cache.Put("fingerprint_3", "ui/three.html", "entry_3", pluginpkg.OpaqueSurfaceDocument{EntryPath: "ui/three.html"})

	if _, ok := cache.Get("fingerprint_2", "ui/two.html", "entry_2"); ok {
		t.Fatal("least recently used cache entry was not evicted")
	}
	if _, ok := cache.Get("fingerprint_1", "ui/one.html", "entry_1"); !ok {
		t.Fatal("recently used cache entry was evicted")
	}
}

func TestSurfaceDocumentCacheEvictsForByteBudget(t *testing.T) {
	cache := newSurfaceDocumentCache(8, 10)
	cache.Put("fingerprint_1", "ui/one.html", "entry_1", pluginpkg.OpaqueSurfaceDocument{BodyHTML: "123456"})
	cache.Put("fingerprint_2", "ui/two.html", "entry_2", pluginpkg.OpaqueSurfaceDocument{BodyHTML: "abcdef"})

	if _, ok := cache.Get("fingerprint_1", "ui/one.html", "entry_1"); ok {
		t.Fatal("least recently used document remained above the byte budget")
	}
	if _, ok := cache.Get("fingerprint_2", "ui/two.html", "entry_2"); !ok {
		t.Fatal("newest document was evicted despite fitting the byte budget")
	}
	cache.Put("fingerprint_3", "ui/three.html", "entry_3", pluginpkg.OpaqueSurfaceDocument{BodyHTML: "01234567890"})
	if _, ok := cache.Get("fingerprint_3", "ui/three.html", "entry_3"); ok {
		t.Fatal("single document larger than the byte budget was cached")
	}
}
