package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/internal/resourceio"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// SurfaceOriginAdapter allocates a dedicated origin for one live container.
// The host mounts the platform Web handler there and owns DNS/TLS routing only.
type SurfaceOriginAdapter interface {
	AllocateSurfaceOrigin(context.Context, SurfaceOriginRequest) (SurfaceOrigin, error)
}
type SurfaceOriginRequest struct {
	SurfaceInstanceID string
	OriginKey         string
	Session           sessionctx.Context
}
type SurfaceOrigin struct {
	Origin       string
	ParentOrigin string
}
type WebModule struct{ Origins SurfaceOriginAdapter }

const WebSurfaceSchemaVersion = "redevplugin.web_surface.v1"
const WebSurfacePlatformPath = "/_redevplugin_web/"

type WebSurfaceDocument struct {
	SchemaVersion string `json:"schema_version"`
	Origin        string `json:"origin"`
	ParentOrigin  string `json:"parent_origin"`
	BootstrapURL  string `json:"bootstrap_url"`
	EntryURL      string `json:"entry_url"`
}

type webSurfaceBinding struct {
	ctx              context.Context
	cancel           context.CancelFunc
	origin           SurfaceOrigin
	owner            sessionctx.Context
	request          surfaceAssetSessionRequest
	surface          manifest.SurfaceSpec
	entryToken       string
	resourceToken    string
	entered          bool
	gatewayReady     bool
	methodReceiver   *surfaceMethodReceiver
	expiresAt        time.Time
	pluginInstanceID string
}
type webSurfaceBindings struct {
	fileMu   sync.RWMutex
	leaseMu  sync.RWMutex
	mu       sync.Mutex
	byOrigin map[string]*webSurfaceBinding
}

func newWebSurfaceBindings() *webSurfaceBindings {
	return &webSurfaceBindings{byOrigin: map[string]*webSurfaceBinding{}}
}

func validateWebOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" || u.String() != raw {
		return nil, errors.New("surface origin must be canonical")
	}
	local := u.Hostname() == "localhost" || strings.HasSuffix(u.Hostname(), ".localhost")
	if u.Scheme != "https" && (u.Scheme != "http" || !local) {
		return nil, errors.New("surface origins require HTTPS or loopback localhost")
	}
	return u, nil
}

func randomWebToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (h *Host) prepareWebSurface(ctx context.Context, session sessionctx.Context, assetSession bridge.AssetSessionResult, validation bridge.AssetSessionValidation, surface manifest.SurfaceSpec) (WebSurfaceDocument, error) {
	if h.webOrigins == nil {
		return WebSurfaceDocument{}, errors.New("web surface origin adapter is required")
	}
	originKey, err := randomWebToken()
	if err != nil {
		return WebSurfaceDocument{}, err
	}
	origin, err := h.webOrigins.AllocateSurfaceOrigin(ctx, SurfaceOriginRequest{SurfaceInstanceID: validation.Session.SurfaceInstanceID, OriginKey: originKey[:48], Session: session})
	if err != nil {
		return WebSurfaceDocument{}, err
	}
	child, err := validateWebOrigin(origin.Origin)
	if err != nil {
		return WebSurfaceDocument{}, err
	}
	parent, err := validateWebOrigin(origin.ParentOrigin)
	if err != nil {
		return WebSurfaceDocument{}, err
	}
	if child.Hostname() == parent.Hostname() || !strings.HasPrefix(child.Hostname(), originKey[:48]+".") {
		return WebSurfaceDocument{}, errors.New("surface must use a different hostname from its parent")
	}
	entryToken, err := randomWebToken()
	if err != nil {
		return WebSurfaceDocument{}, err
	}
	resourceToken, err := randomWebToken()
	if err != nil {
		return WebSurfaceDocument{}, err
	}
	binding := &webSurfaceBinding{origin: origin, owner: session, surface: surface, entryToken: entryToken, resourceToken: resourceToken, expiresAt: assetSession.ExpiresAt, pluginInstanceID: validation.Session.PluginInstanceID, request: surfaceAssetSessionRequest{SurfaceInstanceID: validation.Session.SurfaceInstanceID, AssetSession: assetSession.AssetSession, AssetSessionID: assetSession.AssetSessionID}}
	h.webSurfaces.mu.Lock()
	defer h.webSurfaces.mu.Unlock()
	now := assetSession.IssuedAt
	for key, item := range h.webSurfaces.byOrigin {
		if !item.expiresAt.After(now) {
			if item.cancel != nil {
				item.cancel()
			}
			delete(h.webSurfaces.byOrigin, key)
		}
	}
	if len(h.webSurfaces.byOrigin) >= 1024 {
		return WebSurfaceDocument{}, errors.New("web surface capacity exceeded")
	}
	if _, exists := h.webSurfaces.byOrigin[origin.Origin]; exists {
		return WebSurfaceDocument{}, errors.New("surface origin has already been allocated")
	}
	binding.ctx, binding.cancel = context.WithCancel(h.lifecycleCtx)
	h.webSurfaces.byOrigin[origin.Origin] = binding
	return WebSurfaceDocument{SchemaVersion: WebSurfaceSchemaVersion, Origin: origin.Origin, ParentOrigin: origin.ParentOrigin, BootstrapURL: origin.Origin + WebSurfacePlatformPath + "bootstrap#" + entryToken, EntryURL: origin.Origin + "/" + strings.TrimPrefix(surface.Entry, surface.Web.Root+"/")}, nil
}

// WebSurfaceRequest carries only the child-origin resource credential. It never
// accepts an owner identity, management token, or caller-selected package hash.
type WebSurfaceRequest struct {
	Origin string
	Token  string
	Entry  bool
	Now    time.Time
}
type WebSurfaceSession struct {
	Origin        string
	ParentOrigin  string
	ResourceToken string
	EntryPath     string
}

func (h *Host) webSurface(ctx context.Context, req WebSurfaceRequest) (*webSurfaceBinding, context.Context, error) {
	h.webSurfaces.mu.Lock()
	binding, ok := h.webSurfaces.byOrigin[req.Origin]
	if !ok {
		h.webSurfaces.mu.Unlock()
		return nil, ctx, bridge.ErrTokenAudience
	}
	expected := binding.resourceToken
	if req.Entry {
		expected = binding.entryToken
	}
	suppliedHash, expectedHash := sha256.Sum256([]byte(req.Token)), sha256.Sum256([]byte(expected))
	if req.Token == "" || suppliedHash != expectedHash || (req.Entry && binding.entered) || (!req.Entry && !binding.entered) {
		h.webSurfaces.mu.Unlock()
		return nil, ctx, bridge.ErrTokenAudience
	}
	snapshot := *binding
	h.webSurfaces.mu.Unlock()
	ctx = sessionctx.WithContext(ctx, snapshot.owner)
	request := snapshot.request
	request.Now = req.Now
	if _, _, err := h.validateSurfaceAssetSession(ctx, request); err != nil {
		return nil, ctx, err
	}
	return &snapshot, ctx, nil
}

func (h *Host) EnterWebSurface(ctx context.Context, req WebSurfaceRequest) (WebSurfaceSession, error) {
	release, err := h.ensureOpen()
	if err != nil {
		return WebSurfaceSession{}, err
	}
	defer release()
	h.webSurfaces.leaseMu.RLock()
	defer h.webSurfaces.leaseMu.RUnlock()

	req.Entry = true
	binding, _, err := h.webSurface(ctx, req)
	if err != nil {
		return WebSurfaceSession{}, err
	}
	h.webSurfaces.mu.Lock()
	defer h.webSurfaces.mu.Unlock()
	live := h.webSurfaces.byOrigin[req.Origin]
	if live == nil || live.entered || live.entryToken != req.Token {
		return WebSurfaceSession{}, bridge.ErrTokenAudience
	}
	live.entered = true
	live.entryToken = ""
	return WebSurfaceSession{Origin: binding.origin.Origin, ParentOrigin: binding.origin.ParentOrigin, ResourceToken: binding.resourceToken, EntryPath: "/" + strings.TrimPrefix(binding.surface.Entry, binding.surface.Web.Root+"/")}, nil
}

func (h *Host) ValidateWebSurface(ctx context.Context, req WebSurfaceRequest) (WebSurfaceSession, error) {
	release, err := h.ensureOpen()
	if err != nil {
		return WebSurfaceSession{}, err
	}
	defer release()
	h.webSurfaces.leaseMu.RLock()
	defer h.webSurfaces.leaseMu.RUnlock()

	binding, _, err := h.webSurface(ctx, req)
	if err != nil {
		return WebSurfaceSession{}, err
	}
	return WebSurfaceSession{Origin: binding.origin.Origin, ParentOrigin: binding.origin.ParentOrigin, EntryPath: "/" + strings.TrimPrefix(binding.surface.Entry, binding.surface.Web.Root+"/")}, nil
}

type ReadWebSurfaceAssetRequest struct {
	WebSurfaceRequest
	Path       string
	Navigation bool
}

func (h *Host) ReadWebSurfaceAsset(ctx context.Context, req ReadWebSurfaceAssetRequest) (WebSurfaceAsset, error) {
	release, err := h.ensureOpen()
	if err != nil {
		return WebSurfaceAsset{}, err
	}
	defer release()
	h.webSurfaces.leaseMu.RLock()
	defer h.webSurfaces.leaseMu.RUnlock()

	binding, ctx, err := h.webSurface(ctx, req.WebSurfaceRequest)
	if err != nil {
		return WebSurfaceAsset{}, err
	}
	if !binding.gatewayReady {
		return WebSurfaceAsset{}, bridge.ErrAssetSessionRequired
	}
	route := req.Path
	if route == "" || !strings.HasPrefix(route, "/") || strings.ContainsAny(route, "\\%?#\x00\r\n") || path.Clean(route) != route || strings.HasPrefix(route, WebSurfacePlatformPath) {
		return WebSurfaceAsset{}, pluginpkg.ErrInvalidAssetPath
	}
	for _, part := range strings.Split(strings.TrimPrefix(route, "/"), "/") {
		if strings.HasPrefix(part, ".") {
			return WebSurfaceAsset{}, pluginpkg.ErrInvalidAssetPath
		}
	}
	request := binding.request
	request.Now = req.Now
	validation, record, err := h.validateSurfaceAssetSession(ctx, request)
	if err != nil {
		return WebSurfaceAsset{}, err
	}
	assetPath := binding.surface.Web.Root + route
	if route == "/" {
		assetPath = binding.surface.Entry
	}
	if _, ok := packageEntryByPath(record.PackageEntries, assetPath); !ok {
		if !req.Navigation || !binding.surface.Web.SPA {
			return WebSurfaceAsset{}, pluginpkg.ErrPackageAssetNotFound
		}
		assetPath = binding.surface.Entry
	}
	asset, err := h.readValidatedSurfaceAsset(ctx, validation, record, assetPath, "")
	if err != nil {
		return WebSurfaceAsset{}, err
	}
	if (strings.HasSuffix(strings.ToLower(assetPath), ".html") || strings.HasSuffix(strings.ToLower(assetPath), ".htm")) && !req.Navigation {
		return WebSurfaceAsset{}, fmt.Errorf("HTML is available only through the document loader")
	}
	// Asset adapters may perform slow I/O. Do not return bytes using an authority
	// snapshot that was revoked, disabled, or replaced while that I/O ran.
	if _, _, err := h.webSurface(ctx, req.WebSurfaceRequest); err != nil {
		return WebSurfaceAsset{}, err
	}
	return asset, nil
}

// Resource credentials follow the existing bridge lease; there is no second
// authorization lifetime or browser-held management token.
func (h *Host) renewWebSurface(surfaceID string, result bridge.GatewayTokenResult) {
	h.webSurfaces.mu.Lock()
	defer h.webSurfaces.mu.Unlock()
	for _, binding := range h.webSurfaces.byOrigin {
		if binding.request.SurfaceInstanceID == surfaceID {
			binding.request.AssetSession = result.AssetSession
			binding.request.AssetSessionID = result.AssetSessionID
			binding.expiresAt = result.ExpiresAt
			binding.gatewayReady = true
		}
	}
}

func (h *Host) removeWebSurfaces(match func(*webSurfaceBinding) bool) {
	h.webSurfaces.fileMu.Lock()
	defer h.webSurfaces.fileMu.Unlock()
	h.webSurfaces.mu.Lock()
	defer h.webSurfaces.mu.Unlock()
	for key, binding := range h.webSurfaces.byOrigin {
		if match(binding) {
			if binding.cancel != nil {
				binding.cancel()
			}
			delete(h.webSurfaces.byOrigin, key)
			if h.runtimeIO != nil {
				_ = h.runtimeIO.service.Revoke(func(owner resourceio.Owner) bool {
					return owner.InvocationID == "surface-files:"+binding.request.SurfaceInstanceID && owner.PluginInstanceID == binding.pluginInstanceID
				})
			}
		}
	}
}
