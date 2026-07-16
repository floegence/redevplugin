package runtimeclient

import (
	"context"
	"errors"
	"strings"
	"sync"
)

type runtimeAdmissionController struct {
	mu             sync.Mutex
	totalCapacity  int
	pluginCapacity int
	active         int
	byPlugin       map[string]int
	notify         chan struct{}
}

func newRuntimeAdmissionController(limits RuntimeLimits) *runtimeAdmissionController {
	return &runtimeAdmissionController{
		totalCapacity:  limits.WorkerCount + limits.QueueCapacity,
		pluginCapacity: limits.PerPluginConcurrency + limits.QueueCapacity,
		byPlugin:       map[string]int{},
		notify:         make(chan struct{}),
	}
}

func (c *runtimeAdmissionController) acquire(ctx context.Context, pluginInstanceID string) (func(), error) {
	if c == nil {
		return nil, errors.New("runtime admission controller is nil")
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return nil, errors.New("plugin_instance_id is required")
	}
	for {
		c.mu.Lock()
		if c.active < c.totalCapacity && c.byPlugin[pluginInstanceID] < c.pluginCapacity {
			c.active++
			c.byPlugin[pluginInstanceID]++
			c.mu.Unlock()
			return func() {
				c.mu.Lock()
				c.active--
				c.byPlugin[pluginInstanceID]--
				if c.byPlugin[pluginInstanceID] == 0 {
					delete(c.byPlugin, pluginInstanceID)
				}
				close(c.notify)
				c.notify = make(chan struct{})
				c.mu.Unlock()
			}, nil
		}
		notify := c.notify
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-notify:
		}
	}
}
