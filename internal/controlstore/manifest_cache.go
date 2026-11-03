package controlstore

import (
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"sync"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

const manifestCacheEntries = 128
const manifestCacheBytes = 8 << 20

// This store-local cache contains only successfully validated immutable signed
// content. Every caller still reads current registry, grant and revocation state.
// Exact canonical bytes and the stored-reader validation mode identify an entry;
// the process lifetime binds the validator version. Invalid inputs are not cached.
type manifestDecodeCache struct {
	mu      sync.Mutex
	entries map[[32]byte]*list.Element
	recency list.List
	bytes   int
	decodes uint64
}

type manifestCacheEntry struct {
	key       [32]byte
	canonical string
	value     manifest.Manifest
}

func (c *manifestDecodeCache) decode(raw json.RawMessage) (manifest.Manifest, string, error) {
	key := sha256.Sum256(raw)
	c.mu.Lock()
	if element := c.entries[key]; element != nil {
		entry := element.Value.(*manifestCacheEntry)
		if entry.canonical == string(raw) {
			c.recency.MoveToFront(element)
			value, canonical := entry.value, entry.canonical
			c.mu.Unlock()
			return cloneCachedManifest(value), canonical, nil
		}
	}
	// Serialize misses so simultaneous readers validate identical bytes once.
	// The bounded cache does not retain errors or caller-owned mutable values.
	value, canonical, err := decodeExactCanonicalManifest(raw)
	c.decodes++
	if err != nil {
		c.mu.Unlock()
		return manifest.Manifest{}, "", err
	}
	if len(canonical) <= manifestCacheBytes {
		if c.entries == nil {
			c.entries = make(map[[32]byte]*list.Element)
		}
		if old := c.entries[key]; old != nil {
			c.remove(old)
		}
		for len(c.entries) >= manifestCacheEntries || c.bytes+len(canonical) > manifestCacheBytes {
			c.remove(c.recency.Back())
		}
		entry := &manifestCacheEntry{key: key, canonical: canonical, value: value}
		c.entries[key] = c.recency.PushFront(entry)
		c.bytes += len(canonical)
	}
	c.mu.Unlock()
	return cloneCachedManifest(value), canonical, nil
}

func (c *manifestDecodeCache) remove(element *list.Element) {
	entry := element.Value.(*manifestCacheEntry)
	delete(c.entries, entry.key)
	c.bytes -= len(entry.canonical)
	c.recency.Remove(element)
}

// Manifest is a validated JSON value graph containing exported structs, maps,
// slices, pointers and scalars. Clone containers without reparsing/normalizing
// signed content. Caller mutation must never modify another read's manifest.
func cloneCachedManifest(value manifest.Manifest) manifest.Manifest {
	return cloneManifestValue(reflect.ValueOf(value)).Interface().(manifest.Manifest)
}

func cloneManifestValue(value reflect.Value) reflect.Value {
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return value
		}
		copy := reflect.New(value.Type().Elem())
		copy.Elem().Set(cloneManifestValue(value.Elem()))
		return copy
	case reflect.Interface:
		if value.IsNil() {
			return value
		}
		copy := reflect.New(value.Type()).Elem()
		copy.Set(cloneManifestValue(value.Elem()))
		return copy
	case reflect.Slice:
		if value.IsNil() {
			return value
		}
		copy := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for i := 0; i < value.Len(); i++ {
			copy.Index(i).Set(cloneManifestValue(value.Index(i)))
		}
		return copy
	case reflect.Map:
		if value.IsNil() {
			return value
		}
		copy := reflect.MakeMapWithSize(value.Type(), value.Len())
		iter := value.MapRange()
		for iter.Next() {
			copy.SetMapIndex(iter.Key(), cloneManifestValue(iter.Value()))
		}
		return copy
	case reflect.Struct:
		copy := reflect.New(value.Type()).Elem()
		copy.Set(value)
		for i := 0; i < value.NumField(); i++ {
			if copy.Field(i).CanSet() && value.Type().Field(i).IsExported() {
				copy.Field(i).Set(cloneManifestValue(value.Field(i)))
			}
		}
		return copy
	case reflect.Array:
		copy := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			copy.Index(i).Set(cloneManifestValue(value.Index(i)))
		}
		return copy
	default:
		return value
	}
}
