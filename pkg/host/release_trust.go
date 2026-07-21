package host

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/releasetrust"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/stream"
)

type sourceFenceRegistry struct {
	mu     sync.RWMutex
	active map[string]uint64
}

func newSourceFenceRegistry() *sourceFenceRegistry {
	return &sourceFenceRegistry{active: make(map[string]uint64)}
}

func sourceFenceKey(sourceID, channel string) string {
	return sourceID + "\x00" + channel
}

func (registrySet *sourceFenceRegistry) begin(sourceID, channel string, generation uint64) error {
	if registrySet == nil || strings.TrimSpace(sourceID) == "" || strings.TrimSpace(channel) == "" || generation == 0 {
		return releasetrust.ErrSourceTrustFenced
	}
	key := sourceFenceKey(sourceID, channel)
	registrySet.mu.Lock()
	defer registrySet.mu.Unlock()
	if current := registrySet.active[key]; current != 0 && current != generation {
		return releasetrust.ErrSourceTrustFenced
	}
	registrySet.active[key] = generation
	return nil
}

func (registrySet *sourceFenceRegistry) end(sourceID, channel string, generation uint64) {
	if registrySet == nil {
		return
	}
	key := sourceFenceKey(sourceID, channel)
	registrySet.mu.Lock()
	if registrySet.active[key] == generation {
		delete(registrySet.active, key)
	}
	registrySet.mu.Unlock()
}

func (registrySet *sourceFenceRegistry) contains(sourceID, channel string) bool {
	if registrySet == nil {
		return false
	}
	registrySet.mu.RLock()
	generation := registrySet.active[sourceFenceKey(sourceID, channel)]
	registrySet.mu.RUnlock()
	return generation != 0
}

type hostSourceFenceCoordinator struct {
	host *Host
}

func (coordinator hostSourceFenceCoordinator) TeardownSourceTrust(ctx context.Context, request releasetrust.SourceFenceRequest) error {
	if coordinator.host == nil || ctx == nil {
		return releasetrust.ErrSourceTrustFenced
	}
	key := request.SourceTrustKey()
	if err := coordinator.host.sourceFences.begin(key.SourceID(), key.Channel(), request.Generation()); err != nil {
		return err
	}
	defer coordinator.host.sourceFences.end(key.SourceID(), key.Channel(), request.Generation())

	records, err := coordinator.host.adapters.Registry.ListPlugins(ctx)
	if err != nil {
		return err
	}
	var teardownErr error
	for _, record := range records {
		binding := record.ReleaseTrustBinding
		if binding == nil || binding.SourceID != key.SourceID() || binding.Channel != key.Channel() {
			continue
		}
		if err := coordinator.host.teardownReleaseTrustRecord(ctx, record, request); err != nil {
			teardownErr = errors.Join(teardownErr, fmt.Errorf("teardown plugin %q: %w", record.PluginInstanceID, err))
		}
	}
	return teardownErr
}

func (h *Host) teardownReleaseTrustRecord(ctx context.Context, record registry.PluginRecord, request releasetrust.SourceFenceRequest) error {
	now := time.Now().UTC()
	reason := "release trust " + string(request.Reason())
	disabled, err := h.adapters.Registry.SetEnableState(ctx, record.PluginInstanceID, registry.EnableDisabledByPolicy, reason, now)
	if err != nil {
		return err
	}
	h.releaseLeases.delete(record.PluginInstanceID)
	h.verifiedReleases.delete(record.PluginInstanceID)
	resourceScope := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: disabled.OwnerEnvHash}
	if resourceScope.Validate() != nil {
		return ErrOwnerScopeMismatch
	}
	_, operationErr := h.adapters.Operations.MarkPluginDisabled(ctx, operation.PluginTransitionRequest{
		PluginInstanceID: disabled.PluginInstanceID, ResourceScope: resourceScope, Reason: reason, Now: now,
	})
	_, streamErr := h.adapters.Streams.MarkPluginTransition(ctx, stream.PluginTransitionRequest{
		PluginInstanceID: disabled.PluginInstanceID, ResourceScope: resourceScope,
		Status: stream.StatusOrphanedDisabled, Reason: reason, Now: now,
	})
	var surfaceErr error
	if h.adapters.SurfaceCatalog != nil {
		surfaceErr = h.adapters.SurfaceCatalog.PublishSurfaces(ctx, SurfaceSnapshot{
			PluginInstanceID: disabled.PluginInstanceID, ActiveFingerprint: disabled.ActiveFingerprint,
		})
	}
	runtimeErr := h.revokePluginRuntimeCapabilities(ctx, disabled, now)
	var connectivityErr error
	if h.adapters.Connectivity != nil {
		connectivityErr = h.adapters.Connectivity.RemovePolicy(ctx, disabled.PluginInstanceID)
	}
	return errors.Join(operationErr, streamErr, surfaceErr, runtimeErr, connectivityErr)
}

type verifiedReleaseRegistry struct {
	mu       sync.RWMutex
	values   map[string]releasetrust.VerifiedPackage
	bindings map[string]registry.ReleaseTrustBinding
}

type releaseActivationSnapshot struct {
	binding     *registry.ReleaseTrustBinding
	verified    releasetrust.VerifiedPackage
	hadVerified bool
	hadLease    bool
}

func newVerifiedReleaseRegistry() *verifiedReleaseRegistry {
	return &verifiedReleaseRegistry{
		values:   make(map[string]releasetrust.VerifiedPackage),
		bindings: make(map[string]registry.ReleaseTrustBinding),
	}
}

func (registrySet *verifiedReleaseRegistry) put(pluginInstanceID string, binding registry.ReleaseTrustBinding, verified releasetrust.VerifiedPackage) {
	if registrySet == nil || pluginInstanceID == "" {
		return
	}
	registrySet.mu.Lock()
	registrySet.values[pluginInstanceID] = verified
	registrySet.bindings[pluginInstanceID] = binding
	registrySet.mu.Unlock()
}

func (registrySet *verifiedReleaseRegistry) get(pluginInstanceID string, binding registry.ReleaseTrustBinding) (releasetrust.VerifiedPackage, bool) {
	if registrySet == nil {
		return releasetrust.VerifiedPackage{}, false
	}
	registrySet.mu.RLock()
	verified, ok := registrySet.values[pluginInstanceID]
	storedBinding := registrySet.bindings[pluginInstanceID]
	registrySet.mu.RUnlock()
	return verified, ok && storedBinding == binding
}

func (registrySet *verifiedReleaseRegistry) delete(pluginInstanceID string) {
	if registrySet == nil {
		return
	}
	registrySet.mu.Lock()
	delete(registrySet.values, pluginInstanceID)
	delete(registrySet.bindings, pluginInstanceID)
	registrySet.mu.Unlock()
}

func (registrySet *verifiedReleaseRegistry) clear() {
	if registrySet == nil {
		return
	}
	registrySet.mu.Lock()
	clear(registrySet.values)
	clear(registrySet.bindings)
	registrySet.mu.Unlock()
}

type releaseLeaseRegistry struct {
	mu         sync.Mutex
	leases     map[string]*releaseLeaseEntry
	pluginKeys map[string]string
}

type releaseLeaseEntry struct {
	lease   releasetrust.ActivationLease
	plugins map[string]struct{}
}

func newReleaseLeaseRegistry() *releaseLeaseRegistry {
	return &releaseLeaseRegistry{
		leases:     make(map[string]*releaseLeaseEntry),
		pluginKeys: make(map[string]string),
	}
}

func (registrySet *releaseLeaseRegistry) ensure(
	pluginInstanceID string,
	binding registry.ReleaseTrustBinding,
	validate func(releasetrust.ActivationLease) error,
	authorize func() (releasetrust.ActivationLease, error),
) error {
	if registrySet == nil || pluginInstanceID == "" || validate == nil || authorize == nil {
		return releasetrust.ErrActivationLeaseInvalid
	}
	key := sourceFenceKey(binding.SourceID, binding.Channel)
	registrySet.mu.Lock()
	defer registrySet.mu.Unlock()
	entry := registrySet.leases[key]
	if entry == nil || validate(entry.lease) != nil {
		lease, err := authorize()
		if err != nil {
			return err
		}
		leaseKey := lease.SourceTrustKey()
		if leaseKey.SourceID() != binding.SourceID || leaseKey.Channel() != binding.Channel {
			return releasetrust.ErrActivationLeaseInvalid
		}
		if entry == nil {
			entry = &releaseLeaseEntry{plugins: make(map[string]struct{})}
			registrySet.leases[key] = entry
		}
		entry.lease = lease
	}
	if registrySet.pluginKeys[pluginInstanceID] != key {
		registrySet.detachLocked(pluginInstanceID)
	}
	entry.plugins[pluginInstanceID] = struct{}{}
	registrySet.pluginKeys[pluginInstanceID] = key
	return nil
}

func (registrySet *releaseLeaseRegistry) get(pluginInstanceID string, binding registry.ReleaseTrustBinding) (releasetrust.ActivationLease, bool) {
	if registrySet == nil || pluginInstanceID == "" {
		return releasetrust.ActivationLease{}, false
	}
	key := sourceFenceKey(binding.SourceID, binding.Channel)
	registrySet.mu.Lock()
	defer registrySet.mu.Unlock()
	entry := registrySet.leases[key]
	_, associated := entryPlugin(entry, pluginInstanceID)
	return entryLease(entry), registrySet.pluginKeys[pluginInstanceID] == key && associated
}

func (registrySet *releaseLeaseRegistry) delete(pluginInstanceID string) {
	if registrySet == nil {
		return
	}
	registrySet.mu.Lock()
	registrySet.detachLocked(pluginInstanceID)
	registrySet.mu.Unlock()
}

func (registrySet *releaseLeaseRegistry) clear() {
	if registrySet == nil {
		return
	}
	registrySet.mu.Lock()
	clear(registrySet.leases)
	clear(registrySet.pluginKeys)
	registrySet.mu.Unlock()
}

func (registrySet *releaseLeaseRegistry) detachLocked(pluginInstanceID string) {
	key := registrySet.pluginKeys[pluginInstanceID]
	delete(registrySet.pluginKeys, pluginInstanceID)
	entry := registrySet.leases[key]
	if entry == nil {
		return
	}
	delete(entry.plugins, pluginInstanceID)
	if len(entry.plugins) == 0 {
		delete(registrySet.leases, key)
	}
}

func entryPlugin(entry *releaseLeaseEntry, pluginInstanceID string) (struct{}, bool) {
	if entry == nil {
		return struct{}{}, false
	}
	value, ok := entry.plugins[pluginInstanceID]
	return value, ok
}

func entryLease(entry *releaseLeaseEntry) releasetrust.ActivationLease {
	if entry == nil {
		return releasetrust.ActivationLease{}
	}
	return entry.lease
}

func (h *Host) rememberVerifiedRelease(pluginInstanceID string, binding *registry.ReleaseTrustBinding, verified *releasetrust.VerifiedPackage) {
	if h == nil || binding == nil || verified == nil {
		return
	}
	h.verifiedReleases.put(pluginInstanceID, *binding, *verified)
}

func (h *Host) snapshotReleaseActivation(record registry.PluginRecord) releaseActivationSnapshot {
	if h == nil || record.ReleaseTrustBinding == nil {
		return releaseActivationSnapshot{}
	}
	binding := *record.ReleaseTrustBinding
	verified, hadVerified := h.verifiedReleases.get(record.PluginInstanceID, binding)
	_, hadLease := h.releaseLeases.get(record.PluginInstanceID, binding)
	return releaseActivationSnapshot{
		binding: &binding, verified: verified, hadVerified: hadVerified, hadLease: hadLease,
	}
}

func (h *Host) restoreReleaseActivation(record registry.PluginRecord, snapshot releaseActivationSnapshot) error {
	if h == nil {
		return nil
	}
	if snapshot.binding == nil {
		h.releaseLeases.delete(record.PluginInstanceID)
		h.verifiedReleases.delete(record.PluginInstanceID)
		return nil
	}
	if snapshot.hadVerified {
		h.verifiedReleases.put(record.PluginInstanceID, *snapshot.binding, snapshot.verified)
	} else {
		h.verifiedReleases.delete(record.PluginInstanceID)
	}
	if !snapshot.hadLease {
		h.releaseLeases.delete(record.PluginInstanceID)
		return nil
	}
	if !snapshot.hadVerified || h.adapters.ReleaseTrust == nil {
		h.releaseLeases.delete(record.PluginInstanceID)
		return releasetrust.ErrActivationLeaseInvalid
	}
	if err := h.releaseLeases.ensure(
		record.PluginInstanceID,
		*snapshot.binding,
		h.adapters.ReleaseTrust.ValidateActivationLease,
		snapshot.verified.AuthorizeActivation,
	); err != nil {
		h.releaseLeases.delete(record.PluginInstanceID)
		return err
	}
	return nil
}

func (h *Host) ensureReleaseActivationLease(ctx context.Context, record registry.PluginRecord) error {
	if record.ReleaseTrustBinding == nil {
		return nil
	}
	if h.adapters.ReleaseTrust == nil {
		return ErrReleaseModuleRequired
	}
	binding := *record.ReleaseTrustBinding
	verified, ok := h.verifiedReleases.get(record.PluginInstanceID, binding)
	if !ok {
		ref := releaseRefFromBinding(binding, record)
		pkg, _, _, refreshed, _, err := h.resolveReleasePackage(
			ctx, PackageTrustActionUpdate, ref, &record, record.PluginInstanceID, record.UpdatedAt,
		)
		if err != nil {
			return err
		}
		if pkg.PackageHash != record.PackageHash || pkg.ManifestHash != record.ManifestHash || pkg.EntriesHash != record.EntriesHash {
			return ErrReleaseRefVerificationFailed
		}
		verified = refreshed
		h.verifiedReleases.put(record.PluginInstanceID, binding, verified)
	}
	return h.releaseLeases.ensure(
		record.PluginInstanceID,
		binding,
		h.adapters.ReleaseTrust.ValidateActivationLease,
		verified.AuthorizeActivation,
	)
}

func (h *Host) validateReleaseActivationLease(record registry.PluginRecord) error {
	if record.ReleaseTrustBinding == nil {
		return nil
	}
	if h.adapters.ReleaseTrust == nil {
		return ErrReleaseModuleRequired
	}
	binding := *record.ReleaseTrustBinding
	lease, ok := h.releaseLeases.get(record.PluginInstanceID, binding)
	if !ok {
		return releasetrust.ErrActivationLeaseInvalid
	}
	return h.adapters.ReleaseTrust.ValidateActivationLease(lease)
}

func releaseRefFromBinding(binding registry.ReleaseTrustBinding, record registry.PluginRecord) PluginReleaseRef {
	return PluginReleaseRef{
		SourceID: binding.SourceID, Channel: binding.Channel,
		ReleaseMetadataRef: binding.ReleaseMetadataRef, ReleaseMetadataSHA256: binding.ReleaseMetadataSHA256,
		PublisherID: binding.PublisherID, PluginID: binding.PluginID, Version: binding.Version,
		ExpectedHashes: PackageHashSet{
			PackageSHA256: record.PackageHash, ManifestSHA256: record.ManifestHash, EntriesSHA256: record.EntriesHash,
		},
	}
}

func isReleaseLeaseFailure(err error) bool {
	return errors.Is(err, releasetrust.ErrActivationLeaseInvalid) ||
		errors.Is(err, releasetrust.ErrReleaseTrustExpired) ||
		errors.Is(err, releasetrust.ErrReleaseTrustRevoked)
}
