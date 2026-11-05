package host

import (
	"context"
	"sync"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
)

func (h *Host) reserveWebResource(req WebSurfaceRequest, lifetime context.Context) (func(), error) {
	h.webSurfaces.mu.Lock()
	defer h.webSurfaces.mu.Unlock()
	live := h.webSurfaces.byOrigin[req.Origin]
	if live == nil || live.resourceToken != req.Token || live.ctx != lifetime || lifetime.Err() != nil {
		return nil, bridge.ErrTokenRevoked
	}
	if live.resourceWatches >= 16 || h.webSurfaces.activeResources >= 256 {
		return nil, resourceio.ErrResourceLimit
	}
	live.resourceWatches++
	h.webSurfaces.activeResources++
	var once sync.Once
	return func() {
		once.Do(func() {
			h.webSurfaces.mu.Lock()
			defer h.webSurfaces.mu.Unlock()
			live.resourceWatches--
			h.webSurfaces.activeResources--
		})
	}, nil
}
