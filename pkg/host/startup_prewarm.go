package host

import (
	"context"
	"errors"
	"sync"

	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

// A process host usually opens before any authenticated UI session exists.
// Warm only validated worker modules here: no invocation, lease, connectivity
// activation, surface publication, recovery snapshot or synthetic session.
func (h *Host) startStartupWorkerPrewarm() {
	if h.adapters.RuntimeManager == nil {
		return
	}
	h.startLifecycleJob(func(lifecycleContext context.Context) {
		ctx, cancel := context.WithTimeout(lifecycleContext, DefaultRuntimeStartupTimeout+refreshEnabledPluginTimeout)
		defer cancel()
		records, err := h.controlStore.Registry().ListStartupPrewarmPlugins(ctx)
		if err != nil {
			h.reportLifecycleDiagnostic(ctx, registry.PluginRecord{}, "plugin.runtime.prewarm_failed", "startup worker catalog could not be read", err, observability.DiagnosticDetails{Code: string(security.ErrRuntimeUnavailable), Operation: "startup_prewarm"})
			return
		}
		if len(records) == 0 {
			return
		}
		var target runtimetarget.Target
		if h.runtimeModule != nil {
			target = h.runtimeModule.ArtifactIdentity().Target()
		} else {
			health, healthErr := h.adapters.RuntimeManager.Health(ctx)
			if healthErr != nil {
				return
			}
			target = health.ArtifactIdentity.Target()
		}
		_, err = h.startRuntimeFromCatalog(ctx, target, func(context.Context) ([]registry.PluginRecord, error) { return records, nil })
		if err != nil {
			h.reportLifecycleDiagnostic(ctx, registry.PluginRecord{}, "plugin.runtime.prewarm_failed", "startup worker runtime could not be prepared", err, observability.DiagnosticDetails{Code: string(security.ErrRuntimeUnavailable), Operation: "startup_prewarm"})
			return
		}
		jobs := make(chan registry.PluginRecord)
		var workers sync.WaitGroup
		for range min(refreshEnabledConcurrency, len(records)) {
			workers.Go(func() {
				for record := range jobs {
					if err := h.prewarmStartupPlugin(ctx, record); err != nil && ctx.Err() == nil {
						h.reportLifecycleDiagnostic(ctx, record, "plugin.runtime.prewarm_failed", "startup worker module could not be prepared", err, observability.DiagnosticDetails{Code: string(security.ErrRuntimeUnavailable), Operation: "startup_prewarm"})
					}
				}
			})
		}
		defer workers.Wait()
		defer close(jobs)
		for _, record := range records {
			select {
			case jobs <- record:
			case <-ctx.Done():
				return
			}
		}
	})
}

func (h *Host) prewarmStartupPlugin(ctx context.Context, record registry.PluginRecord) error {
	release, err := h.lifecycleLocks.acquireRead(ctx, record.PluginInstanceID)
	if err != nil {
		return err
	}
	defer release()
	// Do not compile a deleted, disabled or replaced snapshot while a lifecycle
	// mutation is changing the authoritative package or removing its assets.
	current, err := h.controlStore.Registry().GetPlugin(ctx, record.OwnerEnvHash, record.PluginInstanceID)
	if errors.Is(err, registry.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.EnableState != registry.EnableEnabled || !registry.RunnablePluginRecord(current) || current.ActiveFingerprint != record.ActiveFingerprint {
		return nil
	}
	if err := h.prewarmWorkerModules(ctx, current); err != nil {
		return err
	}
	h.diagnostic(ctx, observability.DiagnosticEvent{
		Type: "plugin.runtime.prewarmed", Severity: "info",
		Message:  "startup worker modules prepared",
		PluginID: current.PluginID, PluginInstanceID: current.PluginInstanceID,
		ActiveFingerprint: current.ActiveFingerprint,
		Details:           observability.DiagnosticDetails{Operation: "startup_prewarm"},
	})
	return nil
}
