package host

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/releasetrust"
)

type verifiedReleaseRegistry struct {
	mu       sync.RWMutex
	values   map[string]releasetrust.VerifiedPackage
	bindings map[string]registry.ReleaseTrustBinding
}

func (h *Host) refreshInstalledReleaseTrust(ctx context.Context, record registry.PluginRecord) error {
	if record.ReleaseTrustBinding == nil {
		return nil
	}
	if h.adapters.ReleaseTrust == nil {
		return ErrReleaseRefVerificationFailed
	}
	binding := record.ReleaseTrustBinding
	prepared, err := h.adapters.ReleaseTrust.PrepareRelease(ctx, releasetrust.ReleaseIdentity{
		SourceID: binding.SourceID, Channel: binding.Channel,
		ReleaseMetadataRef: binding.ReleaseMetadataRef, ReleaseMetadataSHA256: binding.ReleaseMetadataSHA256,
		PublisherID: binding.PublisherID, PluginID: binding.PluginID, Version: binding.Version,
	})
	if err == nil && !prepared.AllowsPackageSigningKey(binding.PackageSigningKeyID) {
		err = releasetrust.ErrReleasePolicyDenied
	}
	if errors.Is(err, releasetrust.ErrReleaseTrustRevoked) || errors.Is(err, releasetrust.ErrReleasePolicyDenied) {
		if revokeErr := h.revokeDeniedPluginRuntime(context.WithoutCancel(ctx), record, time.Now().UTC()); revokeErr != nil {
			return errors.Join(err, revokeErr)
		}
	}
	return err
}

type verifiedReleaseSnapshot struct {
	binding     *registry.ReleaseTrustBinding
	verified    releasetrust.VerifiedPackage
	hadVerified bool
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

func (h *Host) rememberVerifiedRelease(pluginInstanceID string, binding *registry.ReleaseTrustBinding, verified *releasetrust.VerifiedPackage) {
	if h == nil || binding == nil || verified == nil {
		return
	}
	h.verifiedReleases.put(pluginInstanceID, *binding, *verified)
}

func (h *Host) snapshotVerifiedRelease(record registry.PluginRecord) verifiedReleaseSnapshot {
	if h == nil || record.ReleaseTrustBinding == nil {
		return verifiedReleaseSnapshot{}
	}
	binding := *record.ReleaseTrustBinding
	verified, hadVerified := h.verifiedReleases.get(record.PluginInstanceID, binding)
	return verifiedReleaseSnapshot{
		binding: &binding, verified: verified, hadVerified: hadVerified,
	}
}

func (h *Host) restoreVerifiedRelease(record registry.PluginRecord, snapshot verifiedReleaseSnapshot) error {
	if h == nil {
		return nil
	}
	if snapshot.binding == nil {
		h.verifiedReleases.delete(record.PluginInstanceID)
		return nil
	}
	if snapshot.hadVerified {
		h.verifiedReleases.put(record.PluginInstanceID, *snapshot.binding, snapshot.verified)
	} else {
		h.verifiedReleases.delete(record.PluginInstanceID)
	}
	return nil
}
