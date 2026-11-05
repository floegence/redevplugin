package authoring

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/httpadapter"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/websecurity"
)

// EnvironmentOptions supplies product adapters, never a second preview runtime.
// Configure receives the isolated root and returns ordinary Host adapters plus
// cleanup for resources which do not transfer to Host.Open. The platform always
// chooses StateRoot and the package asset store; Configure must leave them empty.
// Commands and grants are never executed or approved while opening an environment.
type EnvironmentOptions struct {
	Configure func(context.Context, string) (host.Config, func() error, error)
	Guard     websecurity.Guard
	Router    *SurfaceRouter
}

type Environment struct {
	operation sync.Mutex
	closed    bool
	store     *WorkspaceStore
	owner     Owner
	workspace Workspace
	host      *host.Host
	preview   *Preview
	handler   http.Handler
	web       http.Handler
	cleanup   func() error
	router    *SurfaceRouter
	once      sync.Once
	closeErr  error
}

// OpenEnvironment resumes one isolated preview and its immutable applied artifact.
// Its HTTP handler is mounted below a host-selected author route; callers strip
// that product prefix so the canonical platform route remains unchanged.
func (s *WorkspaceStore) OpenEnvironment(ctx context.Context, owner Owner, id string, options EnvironmentOptions) (_ *Environment, err error) {
	authenticated, failure := OwnerFromContext(ctx)
	if failure != nil || authenticated != owner {
		return nil, ErrWorkspaceNotFound
	}
	if options.Configure == nil || options.Guard == nil || options.Router == nil {
		return nil, ErrWorkspaceConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := s.get(ctx, owner, id)
	if err != nil {
		return nil, err
	}
	if s.environments == nil {
		s.environments = make(map[string]*Environment)
	}
	if _, ok := s.environments[id]; ok {
		return nil, errors.New("author environment is already open")
	}
	if err = s.files.MkdirAll(filepath.Join("projects", id, "development"), 0700); err != nil {
		return nil, err
	}
	info, err := s.files.Lstat(filepath.Join("projects", id, "development"))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrWorkspaceConflict
	}
	config, cleanup, err := options.Configure(ctx, w.DevelopmentDirectory)
	if cleanup == nil {
		cleanup = func() error { return nil }
	}
	if err != nil {
		return nil, errors.Join(err, cleanup())
	}
	env := &Environment{store: s, owner: owner, workspace: w, cleanup: cleanup, router: options.Router}
	defer func() {
		if err != nil {
			if env.host != nil {
				_ = env.host.Close()
			}
			_ = cleanup()
			options.Router.remove(env)
		}
	}()
	if config.StateRoot != "" || config.Core.Assets != nil || config.Web == nil || config.Web.Origins == nil {
		return nil, ErrWorkspaceConflict
	}
	config.StateRoot = w.DevelopmentDirectory
	assets, err := pluginpkg.NewFileAssetStore(filepath.Join(w.DevelopmentDirectory, "assets"))
	if err != nil {
		return nil, err
	}
	config.Core.Assets = assets
	origins := config.Web.Origins
	config.Web = &host.WebModule{Origins: environmentOrigins{environment: env, delegate: origins}}
	env.host, err = host.Open(ctx, config)
	if err != nil {
		_ = assets.Close()
		return nil, err
	}
	env.handler, err = httpadapter.NewHandler(httpadapter.Dependencies{Host: env.host, Guard: environmentGuard{delegate: options.Guard, owner: owner}})
	if err != nil {
		return nil, err
	}
	env.web, err = httpadapter.NewWebSurfaceHandler(env.host, options.Router.origin)
	if err != nil {
		return nil, err
	}
	env.preview, err = NewPreview(ctx, env.host, PreviewState{Mode: "web", Manual: true, Persistent: true})
	if err != nil {
		return nil, err
	}
	if config.Runtime != nil {
		env.preview.state.Mode = "real-runtime"
	}
	// Registry is the application commit point; a durable selection intent
	// recovers a crash between package commit and selection acknowledgement.
	var active, pending string
	err = s.db.QueryRowContext(ctx, "SELECT active_artifact,pending_artifact FROM preview_selection WHERE workspace_id=?", id).Scan(&active, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	} else if err != nil {
		return nil, err
	}
	if env.preview.state.PackageHash != "" {
		artifacts, e := s.listArtifacts(ctx, owner, id)
		if e != nil {
			return nil, e
		}
		for _, selected := range []string{pending, active} {
			for _, a := range artifacts {
				if a.ID == selected && a.PackageSHA256 == env.preview.state.PackageHash {
					env.preview.state.ArtifactID = a.ID
					env.preview.state.SourceHash = a.SourceSHA256
					env.preview.state.Stages = a.Stages
					break
				}
			}
			if env.preview.state.ArtifactID != "" {
				break
			}
		}
		if env.preview.state.ArtifactID == "" {
			return nil, errors.New("preview package has no exact retained selection")
		}
	}
	if _, err = s.db.ExecContext(ctx, "INSERT INTO preview_selection(workspace_id,active_artifact,pending_artifact) VALUES(?,?,'') ON CONFLICT(workspace_id) DO UPDATE SET active_artifact=excluded.active_artifact,pending_artifact=''", id, env.preview.state.ArtifactID); err != nil {
		return nil, err
	}
	s.environments[id] = env
	return env, nil
}
func (e *Environment) Host() *host.Host       { return e.host }
func (e *Environment) Handler() http.Handler  { return e.handler }
func (e *Environment) Snapshot() PreviewState { return e.preview.Snapshot() }
func (e *Environment) check(ctx context.Context) error {
	owner, err := OwnerFromContext(ctx)
	if err != nil || owner != e.owner {
		return ErrWorkspaceNotFound
	}
	return nil
}
func (e *Environment) Apply(ctx context.Context, artifactID string) error {
	e.operation.Lock()
	defer e.operation.Unlock()
	if e.closed {
		return host.ErrHostClosed
	}
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.preview.StageArtifact(ctx, e.store, e.owner, e.workspace.ID, artifactID); err != nil {
		return err
	}
	artifact, _, err := e.store.ReadArtifact(ctx, e.owner, e.workspace.ID, artifactID)
	if err != nil {
		return err
	}
	// Selecting identical bytes is only a metadata transaction. Do not create an
	// intent whose commit cannot be distinguished from the prior package record.
	if artifact.PackageSHA256 != e.preview.Snapshot().PackageHash {
		if _, err = e.store.db.ExecContext(ctx, "UPDATE preview_selection SET pending_artifact=? WHERE workspace_id=?", artifactID, e.workspace.ID); err != nil {
			return err
		}
	}
	if err := e.preview.ApplyArtifact(ctx, e.host, artifactID); err != nil {
		return err
	}
	if _, err := e.store.db.ExecContext(ctx, "UPDATE preview_selection SET active_artifact=?,pending_artifact='' WHERE workspace_id=?", artifactID, e.workspace.ID); err != nil {
		return mutation.Committed(err)
	}
	return nil
}
func (e *Environment) CloseSession(ctx context.Context, session sessionctx.Context) error {
	if session.OwnerUserHash != e.owner.User || session.OwnerEnvHash != e.owner.Environment {
		return ErrWorkspaceNotFound
	}
	return CloseSession(ctx, e.host, session)
}
func (e *Environment) Close() error {
	e.once.Do(func() {
		e.operation.Lock()
		defer e.operation.Unlock()
		e.closed = true
		e.closeErr = errors.Join(e.host.Close(), e.cleanup())
		e.router.remove(e)
		e.store.mu.Lock()
		delete(e.store.environments, e.workspace.ID)
		e.store.mu.Unlock()
	})
	return e.closeErr
}

type environmentGuard struct {
	delegate websecurity.Guard
	owner    Owner
}

func (g environmentGuard) Authenticate(r *http.Request) (sessionctx.Context, error) {
	session, err := g.delegate.Authenticate(r)
	if err != nil {
		return session, err
	}
	if session.OwnerUserHash != g.owner.User || session.OwnerEnvHash != g.owner.Environment {
		return session, ErrWorkspaceNotFound
	}
	return session, nil
}
func (g environmentGuard) ValidateOrigin(r *http.Request, s sessionctx.Context, p websecurity.OriginPolicy) error {
	return g.delegate.ValidateOrigin(r, s, p)
}
func (g environmentGuard) ValidateCSRF(r *http.Request, s sessionctx.Context, p websecurity.CSRFPolicy) error {
	return g.delegate.ValidateCSRF(r, s, p)
}
func (g environmentGuard) AuthorizeRoute(r *http.Request, s sessionctx.Context, a websecurity.RouteAction, e websecurity.RouteEffect) error {
	return g.delegate.AuthorizeRoute(r, s, a, e)
}

// SurfaceRouter selects only origins actually allocated by live environments.
// Products supply their trusted TLS routing resolver and existing production
// handler. It never accepts a browser-provided workspace ID or arbitrary URL.
type SurfaceRouter struct {
	mu        sync.RWMutex
	origin    httpadapter.WebSurfaceOrigin
	fallback  http.Handler
	allocated map[string]*Environment
}

func NewSurfaceRouter(origin httpadapter.WebSurfaceOrigin, fallback http.Handler) (*SurfaceRouter, error) {
	if origin == nil || fallback == nil {
		return nil, ErrWorkspaceConflict
	}
	return &SurfaceRouter{origin: origin, fallback: fallback, allocated: map[string]*Environment{}}, nil
}
func (r *SurfaceRouter) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	origin, err := r.origin(request)
	if err != nil {
		http.Error(w, "surface origin denied", http.StatusForbidden)
		return
	}
	r.mu.RLock()
	env := r.allocated[origin]
	r.mu.RUnlock()
	if env != nil {
		env.web.ServeHTTP(w, request)
		return
	}
	r.fallback.ServeHTTP(w, request)
}
func (r *SurfaceRouter) remove(env *Environment) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for origin, e := range r.allocated {
		if e == env {
			delete(r.allocated, origin)
		}
	}
}

type environmentOrigins struct {
	environment *Environment
	delegate    host.SurfaceOriginAdapter
}

func (o environmentOrigins) AllocateSurfaceOrigin(ctx context.Context, req host.SurfaceOriginRequest) (host.SurfaceOrigin, error) {
	if req.Session.OwnerUserHash != o.environment.owner.User || req.Session.OwnerEnvHash != o.environment.owner.Environment {
		return host.SurfaceOrigin{}, ErrWorkspaceNotFound
	}
	origin, err := o.delegate.AllocateSurfaceOrigin(ctx, req)
	if err != nil {
		return origin, err
	}
	router := o.environment.router
	router.mu.Lock()
	defer router.mu.Unlock()
	if _, used := router.allocated[origin.Origin]; used || len(router.allocated) >= 4096 {
		return host.SurfaceOrigin{}, errors.New("author surface origin capacity or identity conflict")
	}
	router.allocated[origin.Origin] = o.environment
	return origin, nil
}
