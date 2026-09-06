package host

import (
	"context"
	"errors"

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
	ready workerPreparationIdentity
}

// Preparation precedes execution admission; an executed call is never retried.
func (h *Host) bindPreparedWorkerRuntime(ctx context.Context, record registry.PluginRecord) (runtimeclient.RuntimeBinding, error) {
	release, err := h.lifecycleLocks.acquireRead(ctx, record.PluginInstanceID)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	defer release()
	current, err := h.getPluginRecord(ctx, record.PluginInstanceID)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if current.ActiveFingerprint != record.ActiveFingerprint ||
		registry.AuthorizationRevisionsFromRecord(current) != registry.AuthorizationRevisionsFromRecord(record) {
		return runtimeclient.RuntimeBinding{}, registry.ErrAuthorizationRevisionConflict
	}
	if err := h.canRun(ctx, current); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}

	key := workerPreparationKey{ownerEnvHash: record.OwnerEnvHash, pluginInstanceID: record.PluginInstanceID}
	value, _ := h.workerPreparations.LoadOrStore(key, &workerPreparation{gate: make(chan struct{}, 1)})
	preparation := value.(*workerPreparation)
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
	if preparation.ready != identity {
		preparation.ready = workerPreparationIdentity{}
		if err := h.prewarmWorkerModules(ctx, record); err != nil {
			return runtimeclient.RuntimeBinding{}, err
		}
		if err := h.prepareEnabledRuntimeState(ctx, record); err != nil {
			return runtimeclient.RuntimeBinding{}, err
		}
		if err := ctx.Err(); err != nil {
			return runtimeclient.RuntimeBinding{}, err
		}
		preparation.ready = identity
	}
	return binding, nil
}

func (h *Host) rememberPreparedWorkerRuntime(record registry.PluginRecord, binding runtimeclient.RuntimeBinding) {
	key := workerPreparationKey{ownerEnvHash: record.OwnerEnvHash, pluginInstanceID: record.PluginInstanceID}
	value, _ := h.workerPreparations.LoadOrStore(key, &workerPreparation{gate: make(chan struct{}, 1)})
	value.(*workerPreparation).ready = workerPreparationIdentity{
		activeFingerprint: record.ActiveFingerprint,
		packageHash:       record.PackageHash,
		version:           record.Version,
		revisions:         registry.AuthorizationRevisionsFromRecord(record),
		binding:           binding,
	}
}
