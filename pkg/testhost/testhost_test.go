package testhost_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
)

func TestDefaultsDenyAndCloseRemovesOnlyOwnedRoot(t *testing.T) {
	h, err := testhost.Open(context.Background(), testhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := h.StateRoot()
	ctx := h.Context(context.Background())
	if _, err := h.Host().ListPlugins(ctx); !errors.Is(err, host.ErrActionDenied) {
		t.Fatalf("default list = %v", err)
	}
	if h.Session().CanRead || h.Session().CanWrite {
		t.Fatal("default session grants file access")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned root survived close: %v", err)
	}
	if _, err := h.Host().ListPlugins(ctx); err == nil {
		t.Fatal("closed host accepted management")
	}
}

func TestExplicitActionsBindExactSessionAndRejectInvalidOptions(t *testing.T) {
	h, err := testhost.Open(context.Background(), testhost.Options{Actions: []host.ManagementAction{host.ManagementActionListPlugins}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err := h.Host().ListPlugins(h.Context(context.Background())); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*sessionctx.Context){
		func(s *sessionctx.Context) { s.OwnerSessionHash = "other" },
		func(s *sessionctx.Context) { s.OwnerUserHash = "other" },
		func(s *sessionctx.Context) { s.OwnerEnvHash = "other" },
		func(s *sessionctx.Context) { s.SessionChannelIDHash = "other" },
		func(s *sessionctx.Context) { s.CanWrite = true },
		func(s *sessionctx.Context) { s.CanRead = true },
	} {
		s := h.Session()
		mutate(&s)
		if _, err := h.Host().ListPlugins(sessionctx.WithContext(context.Background(), s)); !errors.Is(err, host.ErrActionDenied) {
			t.Fatalf("foreign session accepted: %v", err)
		}
	}
	for _, options := range []testhost.Options{
		{Actions: []host.ManagementAction{"invented.action"}},
		{Session: &sessionctx.Context{}},
		{ParentOrigin: "http://attacker.example:43210"},
		{ParentOrigin: "http://localhost:43210/"},
		{ParentOrigin: "http://localhost:0"},
		{Runtime: &host.RuntimeModule{}},
	} {
		if opened, err := testhost.Open(context.Background(), options); err == nil {
			_ = opened.Close()
			t.Fatalf("accepted options: %+v", options)
		}
	}
}

func TestHTTPUsesRealAuthenticationAndRejectsChildManagement(t *testing.T) {
	h, err := testhost.Open(context.Background(), testhost.Options{ParentOrigin: "http://localhost:43210", Actions: []host.ManagementAction{host.ManagementActionListPlugins}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	mux := http.NewServeMux()
	mux.Handle("/dev/session", h.SessionHandler())
	handler := h.Handler(mux)
	request := func() *http.Request {
		r, err := h.NewRequest(context.Background(), http.MethodPost, "/_redevplugin/api/plugins/catalog/query", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"valid", func(*http.Request) {}, http.StatusOK},
		{"no cookie", func(r *http.Request) { r.Header.Del("Cookie") }, http.StatusForbidden},
		{"duplicate cookie", func(r *http.Request) { r.Header.Add("Cookie", r.Header.Get("Cookie")) }, http.StatusForbidden},
		{"duplicate origin", func(r *http.Request) { r.Header.Add("Origin", h.Origin()) }, http.StatusForbidden},
		{"duplicate csrf", func(r *http.Request) { r.Header.Add("X-ReDevPlugin-CSRF", h.CSRFToken()) }, http.StatusForbidden},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "http://attacker.example") }, http.StatusForbidden},
		{"missing csrf", func(r *http.Request) { r.Header.Del("X-ReDevPlugin-CSRF") }, http.StatusForbidden},
		{"foreign host", func(r *http.Request) { r.Host = "attacker.example:43210" }, http.StatusForbidden},
		{"child management", func(r *http.Request) { r.Host = strings.Repeat("a", 48) + ".localhost:43210" }, http.StatusForbidden},
		{"wrong port", func(r *http.Request) { r.Host = "localhost:43211" }, http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := request()
			test.mutate(r)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	for _, target := range []string{"https://attacker.example/", "//attacker.example/", "http://localhost:43211/", "http://user@localhost:43210/"} {
		if _, err := h.NewRequest(context.Background(), http.MethodGet, target, nil); err == nil {
			t.Fatalf("credentials allowed to %s", target)
		}
	}
	r := httptest.NewRequest(http.MethodPost, h.Origin()+"/dev/session", strings.NewReader(h.BrowserToken()))
	r.Header.Set("Origin", h.Origin())
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("session exchange=%d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe cookie=%+v", cookies)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed HTTP=%d", w.Code)
	}
}

func TestPersistentRootRetainsVerifiedPackageAssets(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	opts := testhost.Options{StateRoot: root, ParentOrigin: "http://localhost:43210", AllowLocalPackages: true, Actions: []host.ManagementAction{host.ManagementActionImportLocalPackage, host.ManagementActionListPlugins, host.ManagementActionOpenSurface, host.ManagementActionPrepareSurface}}
	h, err := testhost.Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), "../../testdata/generated_plugins/minimal", &raw, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	record, err := host.ImportLocalPackageBytes(h.Context(context.Background()), h.Host(), "testhost_minimal", raw.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	session := h.Session()
	opts.Session = &session
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal(err)
	}
	h, err = testhost.Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx := h.Context(context.Background())
	records, err := h.Host().ListPlugins(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("reopen=%+v %v", records, err)
	}
	opened, err := h.Host().OpenSurface(ctx, host.OpenSurfaceRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: records[0].ManagementRevision, SurfaceID: "minimal.view", SurfaceInstanceID: "reopened_view"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Host().PrepareSurface(ctx, host.PrepareSurfaceRequest{SurfaceInstanceID: opened.SurfaceInstanceID, AssetTicket: opened.AssetTicket}); err != nil {
		t.Fatalf("reopened package assets unavailable: %v", err)
	}
}

func TestRejectedControlRootDoesNotCreateAssets(t *testing.T) {
	root := t.TempDir()
	marker := []byte("not a control database")
	if err := os.WriteFile(filepath.Join(root, "control.sqlite"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	if h, err := testhost.Open(context.Background(), testhost.Options{StateRoot: root}); err == nil {
		_ = h.Close()
		t.Fatal("corrupt root accepted")
	}
	after, err := os.ReadFile(filepath.Join(root, "control.sqlite"))
	if err != nil || !bytes.Equal(after, marker) {
		t.Fatal("corrupt root was changed")
	}
	if _, err := os.Stat(filepath.Join(root, "assets")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected root created assets: %v", err)
	}
}

func TestPermissionsRemainExplicitAndRevokeInvalidatesSurface(t *testing.T) {
	h, err := testhost.Open(context.Background(), testhost.Options{ParentOrigin: "http://localhost:43210", AllowLocalPackages: true, Actions: []host.ManagementAction{
		host.ManagementActionImportLocalPackage, host.ManagementActionListPlugins, host.ManagementActionListPermissionGrants,
		host.ManagementActionOpenSurface, host.ManagementActionPrepareSurface, host.ManagementActionGrantPermission, host.ManagementActionRevokePermission,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx := h.Context(context.Background())
	fixture := t.TempDir()
	if err := os.CopyFS(fixture, os.DirFS("../../testdata/generated_plugins/minimal")); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(fixture, "manifest.json")
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["permissions"] = []string{"fs.environment.read"}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, fixture, &archive, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	record, err := host.ImportLocalPackageBytes(ctx, h.Host(), "testhost_grants", archive.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	grants, err := h.Host().ListPermissionGrants(ctx, host.ListPermissionGrantsRequest{PluginInstanceID: record.PluginInstanceID, ActiveOnly: true})
	if err != nil || len(grants) != 0 {
		t.Fatalf("import silently granted permission: %+v %v", grants, err)
	}
	request := host.OpenSurfaceRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, SurfaceID: "minimal.view", SurfaceInstanceID: "protected_view"}
	if _, err := h.Host().OpenSurface(ctx, request); err != nil {
		t.Fatalf("independent page must remain usable before grant: %v", err)
	}
	request.SurfaceInstanceID = "granted_view"
	granted, err := h.Host().GrantPermission(ctx, host.GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "fs.environment.read", ExpectedPolicyRevision: record.PolicyRevision, ExpectedManagementRevision: record.ManagementRevision, ExpectedRevokeEpoch: record.RevokeEpoch})
	if err != nil {
		t.Fatal(err)
	}
	request.ExpectedManagementRevision = granted.Revisions.ManagementRevision
	opened, err := h.Host().OpenSurface(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := h.Host().PrepareSurface(ctx, host.PrepareSurfaceRequest{SurfaceInstanceID: opened.SurfaceInstanceID, AssetTicket: opened.AssetTicket})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := url.Parse(prepared.Document.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	web, err := h.Host().EnterWebSurface(context.Background(), host.WebSurfaceRequest{Origin: prepared.Document.Origin, Token: entry.Fragment})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Host().RevokePermission(ctx, host.RevokePermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "fs.environment.read", ExpectedPolicyRevision: granted.Revisions.PolicyRevision, ExpectedManagementRevision: granted.Revisions.ManagementRevision, ExpectedRevokeEpoch: granted.Revisions.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Host().ValidateWebSurface(context.Background(), host.WebSurfaceRequest{Origin: prepared.Document.Origin, Token: web.ResourceToken}); err == nil {
		t.Fatal("revoked surface remains valid")
	}
}

func TestConcurrentCloseRejectsRetainedAPIAndHTTP(t *testing.T) {
	h, err := testhost.Open(context.Background(), testhost.Options{ParentOrigin: "http://localhost:43210", Actions: []host.ManagementAction{host.ManagementActionListPlugins}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := h.Context(context.Background())
	handler := h.Handler(nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = h.Host().ListPlugins(ctx)
			}
		}()
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := h.Host().ListPlugins(ctx); !errors.Is(err, host.ErrActionDenied) {
		t.Fatalf("retained API=%v", err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, h.Origin()+"/_redevplugin/api/plugins/catalog/query", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("retained HTTP=%d", w.Code)
	}
}

func TestFutureControlRootIsRejectedWithoutMutation(t *testing.T) {
	root := t.TempDir()
	h, err := testhost.Open(context.Background(), testhost.Options{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "control.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE control_schema SET version=999 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string]string {
		t.Helper()
		files := map[string]string{}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if d.IsDir() {
				files[name] = "directory"
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[name] = fmt.Sprintf("%x", sha256.Sum256(data))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	before := snapshot()
	if opened, err := testhost.Open(context.Background(), testhost.Options{StateRoot: root}); err == nil {
		_ = opened.Close()
		t.Fatal("future state accepted")
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("future state mutated: before=%v after=%v", before, after)
	}
}
