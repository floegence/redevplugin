// Package testhost composes a real Host and HTTP adapter with explicit test
// policies. It never listens, builds source, grants plugin permissions, or
// substitutes a fake runtime for a missing verified RuntimeModule.
package testhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/httpadapter"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/trust"
	"github.com/floegence/redevplugin/v3/pkg/websecurity"
)

// Options replaces only product boundaries. Zero values deny management and
// file access and provide no runtime, resource, network, or secret adapters.
type Options struct {
	// An empty StateRoot creates an owned temporary directory. Explicit roots
	// survive Close and can be reopened with the same Session.
	StateRoot          string
	Session            *sessionctx.Context
	Actions            []host.ManagementAction
	AllowLocalPackages bool
	// ParentOrigin is an exact http://localhost:<port> listener origin. Empty
	// selects direct Go API testing without browser routes or surface origins.
	ParentOrigin string
	Runtime      *host.RuntimeModule
	Capability   *host.CapabilityModule
	IO           *host.IOModule
	Files        *host.FilesModule
	Connectivity *host.ConnectivityModule
	Secrets      *host.SecretsModule
	CoreAction   *host.CoreActionModule
	Background   *host.BackgroundModule
	// MethodPolicy can impose additional denial after exact-session validation.
	MethodPolicy func(context.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error)
	Events       observability.MemoryStoreOptions
}

// Harness owns its Host and temporary state but never a caller's listener.
// Runtime ownership transfers when Open begins; failed construction closes an
// unconsumed module, without stopping a module already owned by another Host.
type Harness struct {
	platform      *host.Host
	events        *observability.MemoryStore
	session       sessionctx.Context
	stateRoot     string
	ownedRoot     bool
	origin        string
	port          string
	token         string
	csrf          string
	cookieName    string
	actions       map[host.ManagementAction]bool
	localPackages bool
	methodPolicy  func(context.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error)
	platformHTTP  http.Handler
	childHTTP     http.Handler
	closed        atomic.Bool
	closeOnce     sync.Once
	closeErr      error
}

func Open(ctx context.Context, options Options) (opened *Harness, err error) {
	h := &Harness{actions: make(map[host.ManagementAction]bool), localPackages: options.AllowLocalPackages, methodPolicy: options.MethodPolicy}
	assets := &lazyAssets{}
	defer func() {
		if opened != nil {
			return
		}
		h.closed.Store(true)
		if h.platform != nil {
			err = errors.Join(err, h.platform.Close())
		} else {
			err = errors.Join(err, assets.Close())
			if options.Runtime != nil {
				_, closeErr := options.Runtime.Close(context.Background())
				if !errors.Is(closeErr, host.ErrRuntimeModuleConsumed) {
					err = errors.Join(err, closeErr)
				}
			}
		}
		if h.ownedRoot {
			err = errors.Join(err, os.RemoveAll(h.stateRoot))
		}
	}()
	if ctx == nil {
		return nil, errors.New("testhost context is required")
	}
	for _, action := range options.Actions {
		if !action.Valid() {
			return nil, fmt.Errorf("invalid testhost management action %q", action)
		}
		h.actions[action] = true
	}
	if options.Session != nil {
		h.session = *options.Session
		if !h.session.Valid() {
			return nil, errors.New("testhost session is invalid")
		}
	} else {
		fields := []*string{&h.session.OwnerSessionHash, &h.session.OwnerUserHash, &h.session.OwnerEnvHash, &h.session.SessionChannelIDHash}
		for _, field := range fields {
			*field, err = randomValue()
			if err != nil {
				return nil, err
			}
		}
	}
	if options.ParentOrigin != "" {
		h.port, err = validateParentOrigin(options.ParentOrigin)
		if err != nil {
			return nil, err
		}
		h.origin = options.ParentOrigin
		h.token, err = randomValue()
		if err != nil {
			return nil, err
		}
		h.csrf, err = randomValue()
		if err != nil {
			return nil, err
		}
		h.cookieName = "redevplugin_test_" + h.csrf[:16]
	}
	h.stateRoot = options.StateRoot
	if h.stateRoot == "" {
		h.stateRoot, err = os.MkdirTemp("", "redevplugin-testhost-")
		if err != nil {
			return nil, err
		}
		h.ownedRoot = true
	} else {
		h.stateRoot, err = filepath.Abs(h.stateRoot)
		if err != nil {
			return nil, err
		}
	}
	assets.path = filepath.Join(h.stateRoot, "assets")
	h.events = observability.NewMemoryStore(options.Events)
	config := host.Config{StateRoot: h.stateRoot, Core: host.CoreAdapters{
		Policy: testPolicy{h}, Authorization: testPolicy{h}, PackageTrustVerifier: trust.Ed25519Verifier{Keyring: trust.StaticKeyring{}},
		Audit: h.events, SecurityAudit: h.events, Diagnostics: h.events, Assets: assets,
	}, Runtime: options.Runtime, Capability: options.Capability, IO: options.IO, Files: options.Files, Connectivity: options.Connectivity, Secrets: options.Secrets, CoreAction: options.CoreAction, Background: options.Background}
	if h.origin != "" {
		config.Web = &host.WebModule{Origins: loopbackOrigins{h.origin, h.port}}
	}
	h.platform, err = host.Open(h.Context(ctx), config)
	if err != nil {
		return nil, err
	}
	if h.origin != "" {
		h.platformHTTP, err = httpadapter.NewHandler(httpadapter.Dependencies{Host: h.platform, Guard: testGuard{h}})
		if err != nil {
			return nil, err
		}
		h.childHTTP, err = httpadapter.NewWebSurfaceHandler(h.platform, loopbackOrigins{h.origin, h.port}.resolve)
		if err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (h *Harness) Host() *host.Host                   { return h.platform }
func (h *Harness) Events() *observability.MemoryStore { return h.events }
func (h *Harness) StateRoot() string                  { return h.stateRoot }
func (h *Harness) Session() sessionctx.Context        { return h.session }
func (h *Harness) Context(ctx context.Context) context.Context {
	return sessionctx.WithContext(ctx, h.session)
}
func (h *Harness) Origin() string    { return h.origin }
func (h *Harness) CSRFToken() string { return h.csrf }

// BrowserToken is a per-instance test credential for SessionHandler. Keep it
// out of logs and plugin documents; CLI preview uses a parent URL fragment.
func (h *Harness) BrowserToken() string     { return h.token }
func (h *Harness) Guard() websecurity.Guard { return testGuard{h} }
func (h *Harness) Close() error {
	if h == nil {
		return nil
	}
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		h.closeErr = h.platform.Close()
		if h.ownedRoot {
			h.closeErr = errors.Join(h.closeErr, os.RemoveAll(h.stateRoot))
		}
	})
	return h.closeErr
}
func (h *Harness) accepts(session sessionctx.Context) bool {
	return !h.closed.Load() && session.Valid() && session == h.session
}
func randomValue() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

type testPolicy struct{ h *Harness }

func (p testPolicy) Authorize(_ context.Context, req host.AuthorizationRequest) error {
	if !p.h.accepts(req.Session) || !req.Action.Valid() || !p.h.actions[req.Action] || req.Target.Kind != req.Action.Resource() {
		return host.ErrActionDenied
	}
	return nil
}
func (p testPolicy) EvaluateLocalPolicy(ctx context.Context, s sessionctx.Context, plugin host.PluginRef, method manifest.MethodSpec) (host.PolicyDecision, error) {
	if !p.h.accepts(s) {
		return host.PolicyDeny, host.ErrActionDenied
	}
	if p.h.methodPolicy != nil {
		return p.h.methodPolicy(ctx, plugin, method)
	}
	return host.PolicyAllow, nil
}
func (p testPolicy) DeveloperModeEnabled(_ context.Context, s sessionctx.Context) (bool, error) {
	return p.h.accepts(s) && p.h.localPackages, nil
}
func (p testPolicy) LocalGeneratedPluginsEnabled(_ context.Context, s sessionctx.Context) (bool, error) {
	return p.h.accepts(s) && p.h.localPackages, nil
}

// Delay opening package assets until Host has admitted its control root. This
// wrapper owns acquisition only; FileAssetStore owns all storage semantics.
type lazyAssets struct {
	mu     sync.Mutex
	path   string
	store  *pluginpkg.FileAssetStore
	closed bool
}

func (*lazyAssets) Durable() bool { return true }
func (s *lazyAssets) acquire() (*pluginpkg.FileAssetStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, pluginpkg.ErrAssetStoreClosed
	}
	if s.store == nil {
		store, err := pluginpkg.NewFileAssetStore(s.path)
		if err != nil {
			return nil, err
		}
		s.store = store
	}
	return s.store, nil
}
func (s *lazyAssets) PutOwnedPackage(ctx context.Context, pkg *pluginpkg.Package) error {
	store, err := s.acquire()
	if err != nil {
		if pkg != nil {
			pkg.Files = nil
			pkg.SignatureFiles = nil
		}
		return err
	}
	return store.PutOwnedPackage(ctx, pkg)
}
func (s *lazyAssets) ReadPackageMetadata(ctx context.Context, hash string) ([]pluginpkg.Entry, error) {
	store, err := s.acquire()
	if err != nil {
		return nil, err
	}
	return store.ReadPackageMetadata(ctx, hash)
}
func (s *lazyAssets) ReadAsset(ctx context.Context, hash, path string) (pluginpkg.Asset, error) {
	store, err := s.acquire()
	if err != nil {
		return pluginpkg.Asset{}, err
	}
	return store.ReadAsset(ctx, hash, path)
}
func (s *lazyAssets) DeletePackage(ctx context.Context, hash string) error {
	store, err := s.acquire()
	if err != nil {
		return err
	}
	return store.DeletePackage(ctx, hash)
}
func (s *lazyAssets) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}
