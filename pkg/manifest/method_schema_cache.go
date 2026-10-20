package manifest

import (
	"container/list"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

const (
	methodSchemaCacheEntries = 1024
	methodSchemaCacheBytes   = 8 << 20
)

var compiledMethodSchemaCache = newMethodSchemaCache(methodSchemaCacheEntries, methodSchemaCacheBytes)

type methodSchemaCacheKey struct {
	name string
	raw  string
}

type methodSchemaCacheEntry struct {
	key    methodSchemaCacheKey
	schema *jsonschema.Schema
}

// Cache only successfully compiled content after the caller validates the closed
// subset and size limits. Exact serialized keys own their bytes, retain resource
// identity, and cannot become stale when the caller mutates its schema maps.
type methodSchemaCache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int
	bytes      int
	entries    map[methodSchemaCacheKey]*list.Element
	order      *list.List
}

func newMethodSchemaCache(maxEntries, maxBytes int) *methodSchemaCache {
	return &methodSchemaCache{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		entries:    make(map[methodSchemaCacheKey]*list.Element),
		order:      list.New(),
	}
}

func (c *methodSchemaCache) compile(name string, raw []byte) (*jsonschema.Schema, error) {
	key := methodSchemaCacheKey{name: name, raw: string(raw)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.entries[key]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(methodSchemaCacheEntry).schema, nil
	}
	compiled, err := compileMethodSchemaBytes(name, raw)
	if err != nil {
		return nil, err
	}
	size := len(key.name) + len(key.raw)
	if c.maxEntries <= 0 || size > c.maxBytes {
		return compiled, nil
	}
	c.entries[key] = c.order.PushFront(methodSchemaCacheEntry{key: key, schema: compiled})
	c.bytes += size
	for c.order.Len() > c.maxEntries || c.bytes > c.maxBytes {
		oldest := c.order.Back()
		entry := oldest.Value.(methodSchemaCacheEntry)
		delete(c.entries, entry.key)
		c.bytes -= len(entry.key.name) + len(entry.key.raw)
		c.order.Remove(oldest)
	}
	return compiled, nil
}
