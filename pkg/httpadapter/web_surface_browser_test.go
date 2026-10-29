package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type browserWebOrigins struct {
	port      string
	allocated sync.Map
	prepared  sync.Map
}

func (o *browserWebOrigins) AllocateSurfaceOrigin(_ context.Context, req host.SurfaceOriginRequest) (host.SurfaceOrigin, error) {
	origin := "http://" + req.OriginKey + ".localhost:" + o.port
	o.allocated.Store(origin, req.SurfaceInstanceID)
	return host.SurfaceOrigin{Origin: origin, ParentOrigin: "http://localhost:" + o.port}, nil
}

type browserFilePicker struct{ path string }

func (p browserFilePicker) SelectFile(context.Context, host.FileSelectionRequest) (host.FileSelectionResult, error) {
	return host.FileSelectionResult{Path: p.path}, nil
}

type browserPrivateNetworkPolicy struct{}

func (browserPrivateNetworkPolicy) AuthorizePrivateNetwork(context.Context, host.PrivateNetworkRequest) error {
	return nil
}

func TestNativeWebApplicationBrowser(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_RUN_BROWSER_SMOKE") != "1" {
		t.Skip("set REDEVPLUGIN_RUN_BROWSER_SMOKE=1 to run the real browser")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	fixtureFile := filepath.Join(t.TempDir(), "web-fixture.json")
	build := exec.CommandContext(ctx, "node", "internal/browserharness/web-surface-smoke.mjs", "--build", fixtureFile)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build browser fixture: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(fixtureFile)
	if err != nil {
		t.Fatal(err)
	}
	var files map[string]string
	if err := json.Unmarshal(raw, &files); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	origins := &browserWebOrigins{port: port}
	selectedPath := filepath.Join(t.TempDir(), "selected.txt")
	if err := os.WriteFile(selectedPath, []byte("Existing document"), 0600); err != nil {
		t.Fatal(err)
	}
	var networkRequests atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		networkRequests.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" {
			http.Error(w, "browser authority leaked", 500)
			return
		}
		w.Header().Set("Set-Cookie", "remote-cookie=leaked")
		w.Header().Set("Content-Security-Policy", "default-src *")
		w.Header().Set("WWW-Authenticate", "Bearer secret")
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "first")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/remote.js" {
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = io.WriteString(w, "globalThis.remoteExecuted=true")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"uri": r.URL.RequestURI(), "method": r.Method})
	}))
	defer receiver.Close()
	h := newHTTPTestHostWithOptions(t, httpTestHostOptions{connectivity: &host.ConnectivityModule{Broker: connectivity.NewMemoryBroker(), NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{}), PrivateNetwork: browserPrivateNetworkPolicy{}}, webOrigins: origins, files: &host.FilesModule{Picker: browserFilePicker{path: selectedPath}}})
	defer h.Close()
	dir := t.TempDir()
	var document map[string]any
	if err := json.Unmarshal([]byte(httpFixtureManifestJSON()), &document); err != nil {
		t.Fatal(err)
	}
	document["permissions"] = append(document["permissions"].([]any), "fs.selected.read", "fs.selected.write", "network.client")
	document["network_access"] = map[string]any{"connectors": []any{map[string]any{"connector_id": "api", "transport": "http", "scope": "user", "configurable": true}}}
	surfaces := document["surfaces"].([]any)
	surfaces[0].(map[string]any)["entry"] = "ui/文档.html"
	surfaces[0].(map[string]any)["web"].(map[string]any)["spa"] = true
	surfaces[0].(map[string]any)["web"].(map[string]any)["network"] = []any{map[string]any{"connector_id": "api", "transport": "http", "operations": []string{"http"}, "http_methods": []string{"GET"}}}
	document["surfaces"] = append(surfaces, map[string]any{
		"surface_id": "plain.view", "kind": "view", "label": "Existing application", "entry": "ui/plain.html",
		"web": map[string]any{"root": "ui", "spa": false},
	})
	manifestJSON, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	writeHTTPManifest(t, filepath.Join(dir, "manifest.json"), string(manifestJSON))
	for name, content := range files {
		if name != "host.js" {
			if name == "index.html" {
				name = "文档.html"
			}
			writeHTTPBytes(t, filepath.Join(dir, "ui", name), []byte(content))
		}
	}
	var archive bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(httpTestContext(), dir, &archive, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	installed, err := host.ImportLocalPackageBytes(httpTestContext(), h, nextHTTPTestPluginInstanceID(t), archive.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(httpTestContext(), host.EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.GrantPermission(httpTestContext(), host.GrantPermissionRequest{PluginInstanceID: installed.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: installed.PolicyRevision, ExpectedManagementRevision: installed.ManagementRevision, ExpectedRevokeEpoch: installed.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	revision := mustManagementRevision(t, h, installed.PluginInstanceID)
	fileSession, _ := sessionctx.FromContext(httpTestContext())
	fileSession.CanRead, fileSession.CanWrite = true, true
	review, err := h.ReviewConnection(sessionctx.WithContext(ctx, fileSession), host.ReviewConnectionRequest{PluginInstanceID: installed.PluginInstanceID, ConnectorID: "api", Destination: receiver.URL, HTTPMethods: []string{"GET"}, PrivatePrefixes: []string{"127.0.0.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ApproveConnection(sessionctx.WithContext(ctx, fileSession), host.ConnectionReviewRequest{PluginInstanceID: installed.PluginInstanceID, ReviewID: review.ReviewID}); err != nil {
		t.Fatal(err)
	}
	platform := mustNewHandler(t, h, &httpTestWebSecurityGuard{scope: fileSession})
	web, err := NewWebSurfaceHandler(h, func(r *http.Request) (string, error) {
		hostname, p, err := net.SplitHostPort(r.Host)
		if err != nil || p != port || !strings.HasSuffix(hostname, ".localhost") {
			return "", fmt.Errorf("wrong origin")
		}
		return "http://" + r.Host, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "localhost:"+port {
			if _, prepared := origins.prepared.Load("http://" + r.Host); !prepared {
				http.Error(w, "route not prepared", http.StatusForbidden)
				return
			}
			web.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/_redevplugin/api/") {
			platform.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case "/":
			http.SetCookie(w, &http.Cookie{Name: "fixture-parent", Value: "authenticated", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<!doctype html><title>Web host</title><script type=\"module\" src=\"/host.js\"></script>")
		case "/host.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, files["host.js"])
		case "/fixture/routes":
			cookie, err := r.Cookie("fixture-parent")
			if err != nil || cookie.Value != "authenticated" || r.Header.Get("Origin") != "http://localhost:"+port {
				http.Error(w, "parent session required", http.StatusForbidden)
				return
			}
			var request struct {
				Origin            string
				ParentOrigin      string
				PluginInstanceID  string
				SurfaceInstanceID string
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&request); err != nil {
				http.Error(w, "invalid route", http.StatusBadRequest)
				return
			}
			allocated, ok := origins.allocated.Load(request.Origin)
			if !ok || allocated != request.SurfaceInstanceID || request.ParentOrigin != "http://localhost:"+port || request.PluginInstanceID != installed.PluginInstanceID {
				http.Error(w, "route binding mismatch", http.StatusForbidden)
				return
			}
			switch r.Method {
			case http.MethodPost:
				origins.prepared.Store(request.Origin, request.SurfaceInstanceID)
			case http.MethodDelete:
				origins.prepared.Delete(request.Origin)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/fixture":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"plugin_instance_id": installed.PluginInstanceID, "management_revision": revision})
		default:
			http.NotFound(w, r)
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	mode := "--run"
	if os.Getenv("REDEVPLUGIN_WEB_PERFORMANCE_OUTPUT") != "" {
		mode = "--performance"
	}
	run := exec.CommandContext(ctx, "node", "internal/browserharness/web-surface-smoke.mjs", mode, "http://localhost:"+port)
	run.Dir = root
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("browser failed: %v\n%s", err, out)
	}
	if mode == "--run" {
		if networkRequests.Load() < 3 {
			t.Fatalf("native network receiver observed only %d requests", networkRequests.Load())
		}
		saved, err := os.ReadFile(selectedPath)
		if err != nil || string(saved) != "Saved 中文 document" {
			t.Fatalf("selected file saved bytes = %q, %v", saved, err)
		}
	}
	t.Log(string(out))
}
