package host

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/registry"
)

const defaultMethodSchemaCacheEntries = 1024

type methodSchemaCacheEntry struct {
	key     string
	schemas *manifest.CompiledMethodSchemas
}

type methodSchemaCache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[string]*list.Element
	order      *list.List
}

func newMethodSchemaCache(maxEntries int) *methodSchemaCache {
	if maxEntries <= 0 {
		maxEntries = defaultMethodSchemaCacheEntries
	}
	return &methodSchemaCache{
		maxEntries: maxEntries,
		entries:    make(map[string]*list.Element, maxEntries),
		order:      list.New(),
	}
}

func (c *methodSchemaCache) get(record registry.PluginRecord, method manifest.MethodSpec) (*manifest.CompiledMethodSchemas, error) {
	key := record.ActiveFingerprint + "\x00" + method.Method
	c.mu.Lock()
	if elem, ok := c.entries[key]; ok {
		c.order.MoveToFront(elem)
		schemas := elem.Value.(methodSchemaCacheEntry).schemas
		c.mu.Unlock()
		return schemas, nil
	}
	c.mu.Unlock()

	compiled, err := manifest.CompileMethodSchemas(method)
	if err != nil {
		return nil, fmt.Errorf("compile method %q schemas: %w", method.Method, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.entries[key]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(methodSchemaCacheEntry).schemas, nil
	}
	elem := c.order.PushFront(methodSchemaCacheEntry{key: key, schemas: compiled})
	c.entries[key] = elem
	for c.order.Len() > c.maxEntries {
		oldest := c.order.Back()
		entry := oldest.Value.(methodSchemaCacheEntry)
		delete(c.entries, entry.key)
		c.order.Remove(oldest)
	}
	return compiled, nil
}
