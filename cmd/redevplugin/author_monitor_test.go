package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
)

func TestAuthorMonitorBrowser(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_RUN_BROWSER_SMOKE") != "1" {
		t.Skip("explicit browser acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		if c.Write(r.Context(), websocket.MessageText, []byte("fixture snapshot")) != nil {
			return
		}
		for {
			if _, _, err := c.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer remote.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	origin := "http://localhost:" + port
	options := authorHostOptions(t.TempDir(), origin, nil)
	options.Connectivity.NetworkExecutor = connectivity.NewExecutor(connectivity.ExecutorOptions{DefaultTimeout: time.Minute})
	harness, err := testhost.Open(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	defer harness.Close()
	project := filepath.Join(t.TempDir(), "monitor")
	if _, err := createPluginTemplate("dev.example.monitor", "Live Monitor", project, "monitor"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(project, "dist/manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	connector := manifest["network_access"].(map[string]any)["connectors"].([]any)[0].(map[string]any)
	connector["configurable"] = true
	connector["destinations"] = []string{}
	raw, _ = json.Marshal(manifest)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err = pluginpkg.BuildFromDir(ctx, filepath.Join(project, "dist"), &archive, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	hostContext := harness.Context(ctx)
	record, err := host.ImportLocalPackageBytes(hostContext, harness.Host(), "plugini_monitor_browser", archive.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = harness.Host().GrantPermission(hostContext, host.GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: record.PolicyRevision, ExpectedManagementRevision: record.ManagementRevision, ExpectedRevokeEpoch: record.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/dev/session", harness.SessionHandler())
	mux.HandleFunc("/dev/status", func(w http.ResponseWriter, r *http.Request) {
		if _, err := harness.Guard().Authenticate(r); err != nil {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(authorBuildState{Generation: 1, PluginInstanceID: record.PluginInstanceID, CSRF: harness.CSRFToken(), Mode: "web"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(authorHTML)
		case "/app.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write(authorJS)
		case "/styles.css":
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write(authorCSS)
		default:
			http.NotFound(w, r)
		}
	})
	server := &http.Server{Handler: harness.Handler(mux), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	command := exec.CommandContext(ctx, "node", "scripts/author_monitor_smoke.mjs", origin+"/#"+url.QueryEscape(harness.BrowserToken()), "ws"+strings.TrimPrefix(remote.URL, "http"))
	command.Dir = cliRepoRoot(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("monitor browser: %v\n%s", err, output)
	}
}
