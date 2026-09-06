package host

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

type workerPreparationKey struct {
	ownerEnvHash     string
	pluginInstanceID string
}

type workerPreparationIdentity struct {
	activeFingerprint string
	revisions         registry.AuthorizationRevisions
	binding           runtimeclient.RuntimeBinding
}

type workerPreparation struct {
	gate  chan struct{}
	ready atomic.Pointer[workerPreparationIdentity]
}

func (h *Host) workerPreparation(record registry.PluginRecord) *workerPreparation {
	key := workerPreparationKey{ownerEnvHash: record.OwnerEnvHash, pluginInstanceID: record.PluginInstanceID}
	if value, ok := h.workerPreparations.Load(key); ok {
		return value.(*workerPreparation)
	}
	value, _ := h.workerPreparations.LoadOrStore(key, &workerPreparation{gate: make(chan struct{}, 1)})
	return value.(*workerPreparation)
}

func (preparation *workerPreparation) matches(record registry.PluginRecord, binding runtimeclient.RuntimeBinding) bool {
	ready := preparation.ready.Load()
	return ready != nil && *ready == (workerPreparationIdentity{
		activeFingerprint: record.ActiveFingerprint,
		revisions:         registry.AuthorizationRevisionsFromRecord(record),
		binding:           binding,
	})
}

// Preparation precedes execution admission; an executed call is never retried.
func (h *Host) bindPreparedWorkerRuntime(ctx context.Context, record registry.PluginRecord) (runtimeclient.RuntimeBinding, error) {
	if err := ctx.Err(); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	binding, err := h.bindCompatibleWorkerRuntime(ctx, record)
	if err != nil && !errors.Is(err, runtimeclient.ErrRuntimeNotReady) {
		return runtimeclient.RuntimeBinding{}, err
	}
	preparation := h.workerPreparation(record)
	if err == nil && preparation.matches(record, binding) {
		return binding, nil
	}
	// Only cold preparation needs the lifecycle lock and another catalog read.
	// Normal execution admission still revalidates authorization for every call.
	release, err := h.lifecycleLocks.acquireRead(ctx, record.PluginInstanceID)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	defer release()
	current, err := h.getPluginRecord(ctx, record.PluginInstanceID)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if current.EnableState != registry.EnableEnabled || current.ActiveFingerprint != record.ActiveFingerprint ||
		registry.AuthorizationRevisionsFromRecord(current) != registry.AuthorizationRevisionsFromRecord(record) {
		return runtimeclient.RuntimeBinding{}, registry.ErrAuthorizationRevisionConflict
	}
	if err := h.canRun(ctx, current); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	return h.prepareWorkerBinding(ctx, current, false)
}

// Lifecycle activation and first calls share one cancelable preparation gate.
// Lifecycle callers may already own the plugin write lock.
func (h *Host) prepareWorkerBinding(ctx context.Context, record registry.PluginRecord, refresh bool) (runtimeclient.RuntimeBinding, error) {
	preparation := h.workerPreparation(record)
	select {
	case preparation.gate <- struct{}{}:
		defer func() { <-preparation.gate }()
	case <-ctx.Done():
		return runtimeclient.RuntimeBinding{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if err := h.ensureWorkerRuntimeReady(ctx, record); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	binding, err := h.bindCompatibleWorkerRuntime(ctx, record)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if !refresh && preparation.matches(record, binding) {
		return binding, nil
	}
	preparation.ready.Store(nil)
	if err := h.prewarmWorkerModules(ctx, record); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if err := h.prepareEnabledRuntimeState(ctx, record); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if err := ctx.Err(); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	currentBinding, err := h.bindCompatibleWorkerRuntime(ctx, record)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if currentBinding != binding {
		return runtimeclient.RuntimeBinding{}, runtimeclient.ErrRuntimeNotReady
	}
	preparation.ready.Store(&workerPreparationIdentity{
		activeFingerprint: record.ActiveFingerprint,
		revisions:         registry.AuthorizationRevisionsFromRecord(record),
		binding:           binding,
	})
	return binding, nil
}
