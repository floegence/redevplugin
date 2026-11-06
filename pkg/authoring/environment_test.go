package authoring

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/secrets"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/websecurity"
)

type environmentPolicy struct{}

func (environmentPolicy) Authorize(context.Context, host.AuthorizationRequest) error { return nil }
func (environmentPolicy) EvaluateLocalPolicy(context.Context, sessionctx.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error) {
	return host.PolicyAllow, nil
}

func (environmentPolicy) AllocateSurfaceOrigin(_ context.Context, r host.SurfaceOriginRequest) (host.SurfaceOrigin, error) {
	return host.SurfaceOrigin{Origin: "http://" + r.OriginKey + ".localhost:12345", ParentOrigin: "http://localhost:12345"}, nil
}

type environmentTestGuard struct{ session sessionctx.Context }

func (g environmentTestGuard) Authenticate(*http.Request) (sessionctx.Context, error) {
	return g.session, nil
}
func (environmentTestGuard) ValidateOrigin(*http.Request, sessionctx.Context, websecurity.OriginPolicy) error {
	return nil
}
func (environmentTestGuard) ValidateCSRF(*http.Request, sessionctx.Context, websecurity.CSRFPolicy) error {
	return nil
}
func (environmentTestGuard) AuthorizeRoute(*http.Request, sessionctx.Context, websecurity.RouteAction, websecurity.RouteEffect) error {
	return nil
}
func environmentOptions(t *testing.T, session sessionctx.Context) EnvironmentOptions {
	t.Helper()
	router, err := NewSurfaceRouter(func(r *http.Request) (string, error) { return "http://" + r.Host, nil }, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	return EnvironmentOptions{Router: router, Guard: environmentTestGuard{session}, Configure: func(context.Context, string) (host.Config, func() error, error) {
		events := observability.NewMemoryStore()
		policy := environmentPolicy{}
		return host.Config{Core: host.CoreAdapters{Policy: policy, Authorization: policy, Audit: events, SecurityAudit: events, Diagnostics: events}, Web: &host.WebModule{Origins: policy}, Secrets: &host.SecretsModule{Store: secrets.NewMemoryStore()}, Connectivity: &host.ConnectivityModule{Broker: connectivity.NewMemoryBroker(), NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})}}, nil, nil
	}}
}
func TestEnvironmentRecoversExactArtifactAndPreservesIsolation(t *testing.T) {
	session := sessionctx.Context{OwnerUserHash: "author", OwnerEnvHash: "environment", OwnerSessionHash: "session", SessionChannelIDHash: "channel", CanRead: true, CanWrite: true}
	ctx := sessionctx.WithContext(context.Background(), session)
	owner, _ := OwnerFromContext(ctx)
	root := filepath.Join(t.TempDir(), "authors")
	store, err := OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	workspace, err := store.Create(ctx, owner, "project")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Initialize(ctx, owner, workspace.ID, "dev-example-author", "Author", "web"); err != nil {
		t.Fatal(err)
	}
	artifact, err := store.Capture(ctx, owner, workspace.ID)
	if err != nil {
		t.Fatal(err)
	}
	options := environmentOptions(t, session)
	env, err := store.OpenEnvironment(ctx, owner, workspace.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	if err = env.Apply(ctx, artifact.ID); err != nil {
		t.Fatal(err)
	}
	original := env.Snapshot()
	if original.ArtifactID != artifact.ID || original.PluginInstanceID == "" {
		t.Fatalf("preview not applied: %+v", original)
	}
	records, err := env.Host().ListPlugins(ctx)
	if err != nil || len(records) != 1 {
		t.Fatal("preview inventory", err)
	}
	opened, err := env.Host().OpenSurface(ctx, host.OpenSurfaceRequest{PluginInstanceID: original.PluginInstanceID, ExpectedManagementRevision: records[0].ManagementRevision, SurfaceID: "dev-example-author.view"})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := env.Host().PrepareSurface(ctx, host.PrepareSurfaceRequest{SurfaceInstanceID: opened.SurfaceInstanceID, AssetTicket: opened.AssetTicket})
	if err != nil {
		t.Fatal(err)
	}
	origin, err := url.Parse(prepared.Document.Origin)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	options.Router.ServeHTTP(response, httptest.NewRequest("GET", origin.String()+"/_redevplugin_web/bootstrap", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "bootstrap.js") {
		t.Fatal("preview origin did not route to platform bootstrap", response.Code)
	}
	response = httptest.NewRecorder()
	options.Router.ServeHTTP(response, httptest.NewRequest("GET", origin.String()+"/index.html", nil))
	if response.Code != http.StatusForbidden {
		t.Fatal("package document served without asset session", response.Code)
	}
	response = httptest.NewRecorder()
	options.Router.ServeHTTP(response, httptest.NewRequest("GET", "http://unallocated.localhost:12345/_redevplugin_web/bootstrap", nil))
	if response.Code != http.StatusNotFound {
		t.Fatal("unallocated origin reached preview Host", response.Code)
	}
	if err = store.Remove(ctx, owner, workspace.ID); err == nil {
		t.Fatal("live environment deleted")
	}
	foreign := session
	foreign.OwnerUserHash = "other"
	if err = env.Apply(sessionctx.WithContext(context.Background(), foreign), artifact.ID); !errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatalf("foreign apply admitted: %v", err)
	}
	guard := environmentGuard{owner: owner, delegate: environmentTestGuard{foreign}}
	if _, err = guard.Authenticate(httptest.NewRequest("POST", "http://localhost/", nil)); err == nil {
		t.Fatal("foreign management admitted")
	}
	// A later capture can have identical package bytes but different source. It
	// must not become the selected preview solely because it sorts newest.
	if err = os.WriteFile(filepath.Join(workspace.SourceDirectory, "ui/src/application.ts"), []byte("edited source"), 0600); err != nil {
		t.Fatal(err)
	}
	later, err := store.Capture(ctx, owner, workspace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if later.ID == artifact.ID {
		t.Fatal("artifact reused")
	}
	if err = env.Close(); err != nil {
		t.Fatal(err)
	}
	session.OwnerSessionHash = "renewed"
	session.SessionChannelIDHash = "renewed-channel"
	ctx = sessionctx.WithContext(context.Background(), session)
	env, err = store.OpenEnvironment(ctx, owner, workspace.ID, environmentOptions(t, session))
	if err != nil {
		t.Fatal(err)
	}
	restored := env.Snapshot()
	if restored.ArtifactID != artifact.ID || restored.SourceHash != artifact.SourceSHA256 || restored.PluginInstanceID != original.PluginInstanceID {
		t.Fatalf("wrong selection restored: %+v", restored)
	}
	if err = env.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.Remove(ctx, owner, workspace.ID); err != nil {
		t.Fatal(err)
	}
}
