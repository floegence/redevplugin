package host

import (
	"container/list"
	"sync"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

const (
	defaultSurfaceDocumentCacheEntries = 64
	defaultSurfaceDocumentCacheBytes   = 64 << 20
)

type surfaceDocumentCache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int64
	bytes      int64
	entries    map[string]*list.Element
	lru        *list.List
}

type surfaceDocumentCacheEntry struct {
	key      string
	document pluginpkg.OpaqueSurfaceDocument
	bytes    int64
}

func newSurfaceDocumentCache(maxEntries int, maxBytes int64) *surfaceDocumentCache {
	if maxEntries <= 0 {
		maxEntries = defaultSurfaceDocumentCacheEntries
	}
	if maxBytes <= 0 {
		maxBytes = defaultSurfaceDocumentCacheBytes
	}
	return &surfaceDocumentCache{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		entries:    map[string]*list.Element{},
		lru:        list.New(),
	}
}

func (c *surfaceDocumentCache) Get(activeFingerprint string, entryPath string, entrySHA256 string) (pluginpkg.OpaqueSurfaceDocument, bool) {
	if c == nil {
		return pluginpkg.OpaqueSurfaceDocument{}, false
	}
	key := surfaceDocumentCacheKey(activeFingerprint, entryPath, entrySHA256)
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[key]
	if !ok {
		return pluginpkg.OpaqueSurfaceDocument{}, false
	}
	c.lru.MoveToFront(element)
	return cloneOpaqueSurfaceDocument(element.Value.(surfaceDocumentCacheEntry).document), true
}

func (c *surfaceDocumentCache) Put(activeFingerprint string, entryPath string, entrySHA256 string, document pluginpkg.OpaqueSurfaceDocument) {
	if c == nil {
		return
	}
	key := surfaceDocumentCacheKey(activeFingerprint, entryPath, entrySHA256)
	bytes := opaqueSurfaceDocumentBytes(document)
	c.mu.Lock()
	defer c.mu.Unlock()
	if bytes > c.maxBytes {
		c.remove(key)
		return
	}
	if element, ok := c.entries[key]; ok {
		c.bytes -= element.Value.(surfaceDocumentCacheEntry).bytes
		element.Value = surfaceDocumentCacheEntry{key: key, document: cloneOpaqueSurfaceDocument(document), bytes: bytes}
		c.bytes += bytes
		c.lru.MoveToFront(element)
	} else {
		element := c.lru.PushFront(surfaceDocumentCacheEntry{key: key, document: cloneOpaqueSurfaceDocument(document), bytes: bytes})
		c.entries[key] = element
		c.bytes += bytes
	}
	for c.lru.Len() > c.maxEntries || c.bytes > c.maxBytes {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		c.remove(oldest.Value.(surfaceDocumentCacheEntry).key)
	}
}

func surfaceDocumentCacheKey(activeFingerprint string, entryPath string, entrySHA256 string) string {
	return activeFingerprint + "\x00" + entryPath + "\x00" + entrySHA256
}

func (c *surfaceDocumentCache) remove(key string) {
	element, ok := c.entries[key]
	if !ok {
		return
	}
	entry := element.Value.(surfaceDocumentCacheEntry)
	c.bytes -= entry.bytes
	delete(c.entries, key)
	c.lru.Remove(element)
}

func opaqueSurfaceDocumentBytes(document pluginpkg.OpaqueSurfaceDocument) int64 {
	bytes := int64(len(document.SchemaVersion) + len(document.EntryPath) + len(document.EntrySHA256) + len(document.Title) + len(document.Language) + len(document.Direction) + len(document.BodyHTML))
	bytes += int64(len(document.Worker.Path) + len(document.Worker.SHA256) + len(document.Worker.Type) + len(document.Worker.Content))
	for _, style := range document.Styles {
		bytes += int64(len(style.Path) + len(style.SHA256) + len(style.Content))
	}
	for _, asset := range document.Assets {
		bytes += int64(len(asset.BindingID) + len(asset.Path) + len(asset.SHA256) + len(asset.ContentType))
		for _, logicalID := range asset.LogicalIDs {
			bytes += int64(len(logicalID))
		}
	}
	if document.CriticalBytes > bytes {
		return document.CriticalBytes
	}
	return bytes
}

func cloneOpaqueSurfaceDocument(document pluginpkg.OpaqueSurfaceDocument) pluginpkg.OpaqueSurfaceDocument {
	document.Styles = append([]pluginpkg.OpaqueSurfaceStyle{}, document.Styles...)
	document.Assets = append([]pluginpkg.OpaqueSurfaceAsset{}, document.Assets...)
	for index := range document.Assets {
		document.Assets[index].LogicalIDs = append([]string{}, document.Assets[index].LogicalIDs...)
	}
	return document
}
