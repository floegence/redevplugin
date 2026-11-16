package host

import (
	"context"

	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

type ReadCapabilityViewRequest struct {
	WebSurfaceRequest
	BindingID string
	Path      string
}

// ReadCapabilityView serves a registered view only to an admitted sandbox
// declaring that exact capability contract. It neither creates a conversation
// nor grants any capability method permission.
func (h *Host) ReadCapabilityView(ctx context.Context, req ReadCapabilityViewRequest) (capability.ViewAsset, error) {
	release, err := h.ensureOpen()
	if err != nil {
		return capability.ViewAsset{}, err
	}
	defer release()
	h.webSurfaces.leaseMu.RLock()
	defer h.webSurfaces.leaseMu.RUnlock()
	live, ctx, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		return capability.ViewAsset{}, err
	}
	if !live.gatewayReady {
		return capability.ViewAsset{}, bridge.ErrAssetSessionRequired
	}
	if !capability.ValidViewPath(req.Path) {
		return capability.ViewAsset{}, pluginpkg.ErrInvalidAssetPath
	}
	request := live.request
	request.Now = req.Now
	_, record, err := h.validateSurfaceAssetSession(ctx, request)
	if err != nil {
		return capability.ViewAsset{}, err
	}
	binding, ok := manifestBinding(record.Manifest, req.BindingID)
	if !ok {
		return capability.ViewAsset{}, capability.ErrRegistrationMissing
	}
	known, err := h.resolvePinnedCapabilityContract(record.CapabilityContracts, binding)
	if err != nil {
		return capability.ViewAsset{}, err
	}
	registration, err := h.adapters.Capabilities.Resolve(known.Pin)
	if err != nil {
		return capability.ViewAsset{}, err
	}
	asset, ok := registration.View.Read(req.Path)
	if !ok {
		return capability.ViewAsset{}, pluginpkg.ErrPackageAssetNotFound
	}
	if _, _, err = h.webSurface(ctx, req.WebSurfaceRequest); err != nil {
		return capability.ViewAsset{}, err
	}
	return asset, nil
}
