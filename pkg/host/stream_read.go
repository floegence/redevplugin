package host

import (
	"context"
	"errors"
	"strings"
	"sync"
)

type streamReadLockRegistry struct {
	mu      sync.Mutex
	entries map[string]*streamReadLockEntry
}

type streamReadLockEntry struct {
	semaphore chan struct{}
	users     int
}

func newStreamReadLockRegistry() *streamReadLockRegistry {
	return &streamReadLockRegistry{entries: map[string]*streamReadLockEntry{}}
}

func (r *streamReadLockRegistry) acquire(ctx context.Context, streamID string) (func(), error) {
	if r == nil {
		return nil, errors.New("stream read lock registry is nil")
	}
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		return nil, errors.New("stream_id is required")
	}
	r.mu.Lock()
	entry := r.entries[streamID]
	if entry == nil {
		entry = &streamReadLockEntry{semaphore: make(chan struct{}, 1)}
		r.entries[streamID] = entry
	}
	entry.users++
	r.mu.Unlock()

	select {
	case entry.semaphore <- struct{}{}:
		return func() {
			<-entry.semaphore
			r.mu.Lock()
			entry.users--
			if entry.users == 0 {
				delete(r.entries, streamID)
			}
			r.mu.Unlock()
		}, nil
	case <-ctx.Done():
		r.mu.Lock()
		entry.users--
		if entry.users == 0 {
			delete(r.entries, streamID)
		}
		r.mu.Unlock()
		return nil, ctx.Err()
	}
}
