package host

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
)

type pluginLifecycleLockRegistry struct {
	mu      sync.Mutex
	entries map[string]*pluginLifecycleLockEntry
	waiters []*pluginLifecycleWaiter
}

type pluginLifecycleLockEntry struct {
	readers int
	writer  bool
}

type pluginLifecycleWaiter struct {
	keys    []string
	write   bool
	ready   chan struct{}
	granted bool
}

func newPluginLifecycleLockRegistry() *pluginLifecycleLockRegistry {
	return &pluginLifecycleLockRegistry{entries: map[string]*pluginLifecycleLockEntry{}}
}

func (r *pluginLifecycleLockRegistry) acquireRead(ctx context.Context, pluginInstanceID string) (func(), error) {
	return r.acquire(ctx, []string{pluginInstanceID}, false)
}

func (r *pluginLifecycleLockRegistry) acquireWrite(ctx context.Context, pluginInstanceID string) (func(), error) {
	return r.acquire(ctx, []string{pluginInstanceID}, true)
}

func (r *pluginLifecycleLockRegistry) acquireWriteMany(ctx context.Context, pluginInstanceIDs ...string) (func(), error) {
	return r.acquire(ctx, pluginInstanceIDs, true)
}

func (r *pluginLifecycleLockRegistry) acquire(ctx context.Context, pluginInstanceIDs []string, write bool) (func(), error) {
	if r == nil {
		return nil, errors.New("plugin lifecycle lock registry is nil")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	keys, err := normalizePluginLifecycleKeys(pluginInstanceIDs)
	if err != nil {
		return nil, err
	}
	if !write && len(keys) != 1 {
		return nil, errors.New("read lifecycle acquisition requires exactly one plugin_instance_id")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	waiter := &pluginLifecycleWaiter{
		keys:  keys,
		write: write,
		ready: make(chan struct{}),
	}
	r.mu.Lock()
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	r.waiters = append(r.waiters, waiter)
	r.dispatchLocked()
	granted := waiter.granted
	r.mu.Unlock()

	if granted {
		return r.finishAcquisition(ctx, waiter)
	}
	select {
	case <-waiter.ready:
		return r.finishAcquisition(ctx, waiter)
	case <-ctx.Done():
		r.mu.Lock()
		if waiter.granted {
			r.mu.Unlock()
			r.release(waiter)
			return nil, ctx.Err()
		}
		r.removeWaiterLocked(waiter)
		r.dispatchLocked()
		r.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (r *pluginLifecycleLockRegistry) finishAcquisition(ctx context.Context, waiter *pluginLifecycleWaiter) (func(), error) {
	if err := ctx.Err(); err != nil {
		r.release(waiter)
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() { r.release(waiter) })
	}, nil
}

func (r *pluginLifecycleLockRegistry) release(waiter *pluginLifecycleWaiter) {
	r.mu.Lock()
	for _, key := range waiter.keys {
		entry := r.entries[key]
		if entry == nil {
			continue
		}
		if waiter.write {
			entry.writer = false
		} else {
			entry.readers--
		}
		if !entry.writer && entry.readers == 0 {
			delete(r.entries, key)
		}
	}
	r.dispatchLocked()
	r.mu.Unlock()
}

func (r *pluginLifecycleLockRegistry) dispatchLocked() {
	if len(r.waiters) == 0 {
		return
	}
	remaining := r.waiters[:0]
	reservedWriters := make(map[string]struct{})
	for _, waiter := range r.waiters {
		if waiterConflictsWithReservations(waiter, reservedWriters) || !r.canGrantLocked(waiter) {
			remaining = append(remaining, waiter)
			if waiter.write {
				for _, key := range waiter.keys {
					reservedWriters[key] = struct{}{}
				}
			}
			continue
		}
		r.grantLocked(waiter)
	}
	r.waiters = remaining
}

func (r *pluginLifecycleLockRegistry) canGrantLocked(waiter *pluginLifecycleWaiter) bool {
	for _, key := range waiter.keys {
		entry := r.entries[key]
		if entry == nil {
			continue
		}
		if waiter.write {
			if entry.writer || entry.readers > 0 {
				return false
			}
		} else if entry.writer {
			return false
		}
	}
	return true
}

func (r *pluginLifecycleLockRegistry) grantLocked(waiter *pluginLifecycleWaiter) {
	for _, key := range waiter.keys {
		entry := r.entries[key]
		if entry == nil {
			entry = &pluginLifecycleLockEntry{}
			r.entries[key] = entry
		}
		if waiter.write {
			entry.writer = true
		} else {
			entry.readers++
		}
	}
	waiter.granted = true
	close(waiter.ready)
}

func (r *pluginLifecycleLockRegistry) removeWaiterLocked(target *pluginLifecycleWaiter) {
	for index, waiter := range r.waiters {
		if waiter != target {
			continue
		}
		copy(r.waiters[index:], r.waiters[index+1:])
		r.waiters[len(r.waiters)-1] = nil
		r.waiters = r.waiters[:len(r.waiters)-1]
		return
	}
}

func waiterConflictsWithReservations(waiter *pluginLifecycleWaiter, reservations map[string]struct{}) bool {
	for _, key := range waiter.keys {
		if _, reserved := reservations[key]; reserved {
			return true
		}
	}
	return false
}

func normalizePluginLifecycleKeys(pluginInstanceIDs []string) ([]string, error) {
	if len(pluginInstanceIDs) == 0 {
		return nil, errors.New("at least one plugin_instance_id is required")
	}
	unique := make(map[string]struct{}, len(pluginInstanceIDs))
	for _, pluginInstanceID := range pluginInstanceIDs {
		pluginInstanceID = strings.TrimSpace(pluginInstanceID)
		if pluginInstanceID == "" {
			return nil, errors.New("plugin_instance_id is required")
		}
		unique[pluginInstanceID] = struct{}{}
	}
	keys := make([]string, 0, len(unique))
	for pluginInstanceID := range unique {
		keys = append(keys, pluginInstanceID)
	}
	slices.Sort(keys)
	return keys, nil
}
