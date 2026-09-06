package host

import (
	"context"
	"errors"
	"sync"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

type workerPreparationKey struct {
	ownerEnvHash     string
	pluginInstanceID string
}

type workerPreparationIdentity struct {
	activeFingerprint string
	packageHash       string
	version           string
	revisions         registry.AuthorizationRevisions
	binding           runtimeclient.RuntimeBinding
}

type workerPreparation struct {
	gate  chan struct{}
	mu    sync.RWMutex
	ready workerPreparationIdentity
}

// Preparation precedes execution admission; an executed call is never retried.
func (h *Host) bindPreparedWorkerRuntime(ctx context.Context, record registry.PluginRecord) (runtimeclient.RuntimeBinding, error) {
	if err := h.canRun(ctx, record); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}

	key := workerPreparationKey{ownerEnvHash: record.OwnerEnvHash, pluginInstanceID: record.PluginInstanceID}
	value, _ := h.workerPreparations.LoadOrStore(key, &workerPreparation{gate: make(chan struct{}, 1)})
	preparation := value.(*workerPreparation)
	if health, healthErr := h.adapters.RuntimeManager.Health(ctx); healthErr == nil {
		preparation.mu.RLock()
		cached := preparation.ready
		preparation.mu.RUnlock()
		if len(health.Shards) > 0 && cached.activeFingerprint == record.ActiveFingerprint && cached.packageHash == record.PackageHash &&
			cached.version == record.Version && cached.revisions == registry.AuthorizationRevisionsFromRecord(record) &&
			cached.binding.RuntimeGenerationID != "" && health.Ready &&
			cached.binding.RuntimeGenerationID == health.Shards[0].RuntimeGenerationID &&
			cached.binding.ArtifactIdentity == health.ArtifactIdentity {
			return cached.binding, nil
		}
	}
	select {
	case preparation.gate <- struct{}{}:
		defer func() { <-preparation.gate }()
	case <-ctx.Done():
		return runtimeclient.RuntimeBinding{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	binding, err := h.bindCompatibleWorkerRuntime(ctx, record)
	if errors.Is(err, runtimeclient.ErrRuntimeNotReady) {
		if err = h.ensureWorkerRuntimeReady(ctx, record); err == nil {
			binding, err = h.bindCompatibleWorkerRuntime(ctx, record)
		}
	}
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	identity := workerPreparationIdentity{
		activeFingerprint: record.ActiveFingerprint,
		packageHash:       record.PackageHash,
		version:           record.Version,
		revisions:         registry.AuthorizationRevisionsFromRecord(record),
		binding:           binding,
	}
	preparation.mu.Lock()
	cachedIdentity := preparation.ready
	preparation.ready = workerPreparationIdentity{}
	preparation.mu.Unlock()
	if cachedIdentity != identity {
		if err := h.prewarmWorkerModules(ctx, record); err != nil {
			return runtimeclient.RuntimeBinding{}, err
		}
		if err := h.prepareEnabledRuntimeState(ctx, record); err != nil {
			return runtimeclient.RuntimeBinding{}, err
		}
		if err := ctx.Err(); err != nil {
			return runtimeclient.RuntimeBinding{}, err
		}
		preparation.mu.Lock()
		preparation.ready = identity
		preparation.mu.Unlock()
	}
	return binding, nil
}

func (h *Host) rememberPreparedWorkerRuntime(record registry.PluginRecord, binding runtimeclient.RuntimeBinding) {
	key := workerPreparationKey{ownerEnvHash: record.OwnerEnvHash, pluginInstanceID: record.PluginInstanceID}
	value, _ := h.workerPreparations.LoadOrStore(key, &workerPreparation{gate: make(chan struct{}, 1)})
	preparation := value.(*workerPreparation)
	preparation.mu.Lock()
	preparation.ready = workerPreparationIdentity{
		activeFingerprint: record.ActiveFingerprint,
		packageHash:       record.PackageHash,
		version:           record.Version,
		revisions:         registry.AuthorizationRevisionsFromRecord(record),
		binding:           binding,
	}
	preparation.mu.Unlock()
}
