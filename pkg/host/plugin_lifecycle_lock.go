package host

import (
	"errors"
	"strings"
	"sync"
)

type pluginLifecycleLockRegistry struct {
	mu      sync.Mutex
	entries map[string]*pluginLifecycleLockEntry
}

type pluginLifecycleLockEntry struct {
	mu    sync.RWMutex
	users int
}

func newPluginLifecycleLockRegistry() *pluginLifecycleLockRegistry {
	return &pluginLifecycleLockRegistry{entries: map[string]*pluginLifecycleLockEntry{}}
}

func (r *pluginLifecycleLockRegistry) acquireRead(pluginInstanceID string) (func(), error) {
	return r.acquire(pluginInstanceID, false)
}

func (r *pluginLifecycleLockRegistry) acquireWrite(pluginInstanceID string) (func(), error) {
	return r.acquire(pluginInstanceID, true)
}

func (r *pluginLifecycleLockRegistry) acquire(pluginInstanceID string, write bool) (func(), error) {
	if r == nil {
		return nil, errors.New("plugin lifecycle lock registry is nil")
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return nil, errors.New("plugin_instance_id is required")
	}
	r.mu.Lock()
	entry := r.entries[pluginInstanceID]
	if entry == nil {
		entry = &pluginLifecycleLockEntry{}
		r.entries[pluginInstanceID] = entry
	}
	entry.users++
	r.mu.Unlock()
	if write {
		entry.mu.Lock()
	} else {
		entry.mu.RLock()
	}
	return func() {
		if write {
			entry.mu.Unlock()
		} else {
			entry.mu.RUnlock()
		}
		r.mu.Lock()
		entry.users--
		if entry.users == 0 {
			delete(r.entries, pluginInstanceID)
		}
		r.mu.Unlock()
	}, nil
}
