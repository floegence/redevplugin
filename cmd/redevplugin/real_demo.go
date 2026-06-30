package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/httpadapter"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/storage"
)

const (
	realDemoPluginID   = "com.example.real.demo"
	realDemoPluginName = "Real Runtime Demo Plugin"
	realDemoSurfaceID  = realDemoPluginID + ".activity"
	realDemoHostPort   = "4175"
	realDemoPluginPort = "4176"
	realDemoOwner      = "real_demo_owner_session"
	realDemoUser       = "real_demo_owner_user"
	realDemoChannel    = "real_demo_session_channel"
)

type realDemoRuntimeResolver struct {
	path string
}

func (r realDemoRuntimeResolver) RuntimePath(context.Context, host.RuntimeTarget) (string, error) {
	return r.path, nil
}

func demoRealServer(ctx context.Context, stateRoot string, runtimePath string) error {
	stateRoot = strings.TrimSpace(stateRoot)
	runtimePath = strings.TrimSpace(runtimePath)
	if stateRoot == "" {
		return errors.New("state_root is required")
	}
	if runtimePath == "" {
		return errors.New("runtime_path is required")
	}
	if err := os.MkdirAll(stateRoot, 0o755); err != nil {
		return err
	}
	pluginDir := filepath.Join(stateRoot, "plugin")
	packageFile := filepath.Join(stateRoot, "real-demo.redevplugin")
	if err := resetDirectory(pluginDir); err != nil {
		return err
	}
	if _, err := createPluginScaffold(realDemoPluginID, realDemoPluginName, pluginDir); err != nil {
		return err
	}
	packageBytes, err := packageDirectoryBytes(ctx, pluginDir, packageFile)
	if err != nil {
		return err
	}
	storageBroker, err := storage.NewFileBroker(filepath.Join(stateRoot, "storage"))
	if err != nil {
		return err
	}
	pluginHost, err := host.New(host.Adapters{
		SessionResolver:         staticSessionResolver{},
		Policy:                  staticPolicyAdapter{},
		RuntimeArtifactResolver: realDemoRuntimeResolver{path: runtimePath},
		Storage:                 storageBroker,
	})
	if err != nil {
		return err
	}
	health, err := pluginHost.StartRuntime(ctx, host.StartRuntimeRequest{
		Target: host.RuntimeTarget{OS: runtime.GOOS, Arch: runtime.GOARCH},
	})
	if err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = pluginHost.StopRuntime(stopCtx)
	}()
	record, err := host.InstallPackageBytes(ctx, pluginHost, packageBytes, registry.TrustUnsignedLocal)
	if err != nil {
		return err
	}
	record, err = pluginHost.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return err
	}
	hostPort := demoEnv("REAL_DEMO_HOST_PORT", realDemoHostPort)
	pluginPort := demoEnv("REAL_DEMO_PLUGIN_PORT", realDemoPluginPort)
	sandboxOrigin := "http://127.0.0.1:" + pluginPort
	hostOrigin := "http://127.0.0.1:" + hostPort
	platformHandler := httpadapter.Handler{Host: pluginHost}
	hostMux := http.NewServeMux()
	hostMux.HandleFunc("/favicon.ico", noContentHandler)
	hostMux.Handle("/_redevplugin/api/plugins/", platformHandler)
	hostMux.HandleFunc("/packages/redevplugin-ui/dist/index.js", realDemoSDKHandler)
	hostMux.HandleFunc("/demo/real/index.html", func(w http.ResponseWriter, _ *http.Request) {
		bootstrap, err := pluginHost.OpenSurface(ctx, host.OpenSurfaceRequest{
			PluginInstanceID:     record.PluginInstanceID,
			SurfaceID:            realDemoSurfaceID,
			SurfaceInstanceID:    fmt.Sprintf("surface_real_demo_%d", time.Now().UnixNano()),
			OwnerSessionHash:     realDemoOwner,
			OwnerUserHash:        realDemoUser,
			SessionChannelIDHash: realDemoChannel,
			SandboxOrigin:        sandboxOrigin,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeNoStoreHTML(w, realDemoHostHTML(hostOrigin, sandboxOrigin, bootstrapJSON(realDemoBootstrap(bootstrap)), health.RuntimeGenerationID))
	})
	pluginMux := http.NewServeMux()
	pluginMux.HandleFunc("/favicon.ico", noContentHandler)
	pluginMux.HandleFunc("/", realDemoPluginAssetHandler(pluginDir))
	hostServer := &http.Server{Addr: "127.0.0.1:" + hostPort, Handler: hostMux}
	pluginServer := &http.Server{Addr: "127.0.0.1:" + pluginPort, Handler: pluginMux}
	errCh := make(chan error, 2)
	go func() {
		errCh <- hostServer.ListenAndServe()
	}()
	go func() {
		errCh <- pluginServer.ListenAndServe()
	}()
	fmt.Fprintf(os.Stdout, "ReDevPlugin real runtime demo host: %s/demo/real/index.html\n", hostOrigin)
	fmt.Fprintf(os.Stdout, "ReDevPlugin real runtime demo plugin sandbox: %s/ui/index.html\n", sandboxOrigin)
	fmt.Fprintf(os.Stdout, "ReDevPlugin real runtime demo runtime_generation_id: %s\n", health.RuntimeGenerationID)
	select {
	case <-ctx.Done():
		shutdownDemoServers(hostServer, pluginServer)
		return ctx.Err()
	case err := <-errCh:
		shutdownDemoServers(hostServer, pluginServer)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

type realDemoBootstrapPayload struct {
	PluginID             string `json:"plugin_id"`
	PluginInstanceID     string `json:"plugin_instance_id"`
	SurfaceID            string `json:"surface_id"`
	SurfaceInstanceID    string `json:"surface_instance_id"`
	ActiveFingerprint    string `json:"active_fingerprint"`
	OwnerSessionHash     string `json:"owner_session_hash"`
	OwnerUserHash        string `json:"owner_user_hash"`
	SessionChannelIDHash string `json:"session_channel_id_hash"`
	AssetTicket          string `json:"asset_ticket"`
	AssetTicketID        string `json:"asset_ticket_id"`
	BridgeNonce          string `json:"bridge_nonce"`
}

func realDemoBootstrap(bootstrap bridge.SurfaceBootstrap) realDemoBootstrapPayload {
	return realDemoBootstrapPayload{
		PluginID:             bootstrap.PluginID,
		PluginInstanceID:     bootstrap.PluginInstanceID,
		SurfaceID:            bootstrap.SurfaceID,
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		ActiveFingerprint:    bootstrap.ActiveFingerprint,
		OwnerSessionHash:     realDemoOwner,
		OwnerUserHash:        realDemoUser,
		SessionChannelIDHash: realDemoChannel,
		AssetTicket:          bootstrap.AssetTicket,
		AssetTicketID:        bootstrap.AssetTicketID,
		BridgeNonce:          bootstrap.BridgeNonce,
	}
}

func packageDirectoryBytes(ctx context.Context, pluginDir string, packageFile string) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, pluginDir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		return nil, err
	}
	if err := writeBytesFile(packageFile, buf.Bytes(), 0o600); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func resetDirectory(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, 0o755)
}

func realDemoPluginAssetHandler(pluginDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		if clean == "/" {
			clean = "/ui/index.html"
		}
		filename := filepath.Join(pluginDir, filepath.FromSlash(strings.TrimPrefix(clean, "/")))
		rel, err := filepath.Rel(pluginDir, filename)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, filename)
	}
}

func noContentHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func writeNoStoreHTML(w http.ResponseWriter, html string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, html)
}

func realDemoSDKHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	http.ServeFile(w, r, filepath.Join("packages", "redevplugin-ui", "dist", "index.js"))
}

func bootstrapJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func shutdownDemoServers(servers ...*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(ctx)
	}
}

func demoEnv(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func realDemoHostHTML(hostOrigin string, pluginOrigin string, bootstrap string, runtimeGenerationID string) string {
	return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ReDevPlugin Real Runtime Demo</title>
    <style>
      :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      body { margin: 0; background: #f6f7fb; color: #15202b; }
      main { display: grid; gap: 16px; grid-template-columns: 360px minmax(480px, 1fr); min-height: 100vh; padding: 20px; }
      section { background: #fff; border: 1px solid #d9dee8; border-radius: 8px; box-shadow: 0 18px 50px rgb(20 32 43 / 10%); padding: 16px; }
      h1, h2 { margin: 0; letter-spacing: 0; }
      h1 { font-size: 24px; }
      h2 { font-size: 18px; }
      .eyebrow, .label { color: #637083; font-size: 12px; font-weight: 800; letter-spacing: 0; text-transform: uppercase; }
      .status { display: inline-flex; align-items: center; min-height: 28px; padding: 0 10px; border: 1px solid #b8dfd7; border-radius: 999px; background: #e6f4f1; color: #0f5f58; font-size: 12px; font-weight: 800; text-transform: uppercase; }
      .metric-grid { display: grid; gap: 10px; grid-template-columns: repeat(3, 1fr); margin: 16px 0; }
      .metric { background: #f8fafc; border: 1px solid #d9dee8; border-radius: 8px; padding: 10px; }
      .metric strong { display: block; font-size: 22px; margin-top: 4px; }
      button { border: 0; border-radius: 8px; background: #0f766e; color: #fff; cursor: pointer; font: inherit; font-weight: 800; min-height: 38px; padding: 0 14px; }
      button:hover { background: #115e59; }
      iframe { width: 100%; min-height: 560px; border: 1px solid #d9dee8; border-radius: 8px; background: white; }
      pre, code { overflow-wrap: anywhere; white-space: pre-wrap; }
      pre { background: #f8fafc; border: 1px solid #d9dee8; border-radius: 8px; min-height: 180px; padding: 10px; }
      ul { display: flex; flex-direction: column; gap: 6px; list-style: none; margin: 12px 0 0; padding: 0; }
      li { background: #f8fafc; border: 1px solid #d9dee8; border-radius: 8px; font-size: 12px; padding: 8px; }
    </style>
  </head>
  <body>
    <main>
      <section aria-label="Real Host console">
        <p class="eyebrow">ReDevPlugin real demo</p>
        <h1>Host + Rust runtime</h1>
        <p><span id="host-status" class="status">booting</span></p>
        <div class="metric-grid" aria-label="Runtime counters">
          <div class="metric"><span class="label">handshakes</span><strong id="handshake-count">0</strong></div>
          <div class="metric"><span class="label">rpc calls</span><strong id="rpc-count">0</strong></div>
          <div class="metric"><span class="label">runtime</span><strong id="runtime-ready">0</strong></div>
        </div>
        <p class="label">runtime generation</p>
        <code id="runtime-generation">` + runtimeGenerationID + `</code>
        <ul id="event-log" aria-label="Real bridge event log"></ul>
      </section>
      <section aria-label="Real sandboxed plugin surface">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:12px;">
          <div>
            <p class="eyebrow">sandboxed iframe</p>
            <h2>Generated plugin</h2>
          </div>
          <button id="send-visible" type="button">Visible</button>
        </div>
        <iframe id="plugin-frame" title="Generated real runtime plugin" sandbox="allow-scripts allow-same-origin"></iframe>
        <pre id="last-result">{}</pre>
      </section>
    </main>
    <script type="module">
      import { PluginSurfaceHost } from "/packages/redevplugin-ui/dist/index.js";
      const bootstrap = ` + bootstrap + `;
      const pluginOrigin = "` + pluginOrigin + `";
      const pluginURL = new URL("/ui/index.html", pluginOrigin);
      pluginURL.searchParams.set("parent_origin", location.origin);
      pluginURL.searchParams.set("plugin_id", bootstrap.plugin_id);
      pluginURL.searchParams.set("surface_id", bootstrap.surface_id);
      pluginURL.searchParams.set("surface_instance_id", bootstrap.surface_instance_id);
      pluginURL.searchParams.set("active_fingerprint", bootstrap.active_fingerprint);
      pluginURL.searchParams.set("bridge_nonce", bootstrap.bridge_nonce);
      const iframe = document.querySelector("#plugin-frame");
      let handshakes = 0;
      let rpcCalls = 0;
      const log = (type, detail) => {
        const item = document.createElement("li");
        item.textContent = new Date().toLocaleTimeString() + " " + type + " " + JSON.stringify(detail);
        document.querySelector("#event-log").prepend(item);
      };
      const hostFetch = async (input, init) => {
        const url = String(input);
        const body = init?.body ? JSON.parse(init.body) : {};
        const trackResult = url.endsWith("/bridge-token") || url.endsWith("/rpc") || url.endsWith("/confirm");
        if (url.endsWith("/bridge-token")) {
          handshakes += 1;
          document.querySelector("#handshake-count").textContent = String(handshakes);
          log("bridge-token", { surface_instance_id: body.handshake?.surface_instance_id });
        }
        if (url.endsWith("/rpc")) {
          rpcCalls += 1;
          document.querySelector("#rpc-count").textContent = String(rpcCalls);
          log("rpc", { method: body.method });
        }
        const response = await fetch(input, init);
        if (trackResult) {
          try {
            document.querySelector("#last-result").textContent = JSON.stringify(await response.clone().json(), null, 2);
          } catch {
            document.querySelector("#last-result").textContent = String(response.status);
          }
        }
        return response;
      };
      const surfaceHost = new PluginSurfaceHost({
        bootstrap: {
          pluginId: bootstrap.plugin_id,
          pluginInstanceId: bootstrap.plugin_instance_id,
          surfaceId: bootstrap.surface_id,
          surfaceInstanceId: bootstrap.surface_instance_id,
          activeFingerprint: bootstrap.active_fingerprint,
          bridgeNonce: bootstrap.bridge_nonce,
          ownerSessionHash: bootstrap.owner_session_hash,
          ownerUserHash: bootstrap.owner_user_hash,
          sessionChannelIdHash: bootstrap.session_channel_id_hash,
        },
        iframeOrigin: pluginURL.origin,
        iframeWindow: iframe.contentWindow,
        parentWindow: window,
        fetch: hostFetch,
        apiBaseURL: "",
        onError(error) {
          document.querySelector("#host-status").textContent = "error";
          log("host-error", { error_code: error.errorCode, message: error.message });
        },
      });
      document.querySelector("#send-visible").addEventListener("click", () => {
        surfaceHost.sendLifecycle({ type: "visible" });
        log("lifecycle", { type: "visible" });
      });
      window.addEventListener("beforeunload", () => surfaceHost.dispose());
      try {
        const assetResponse = await hostFetch("/_redevplugin/api/plugins/surfaces/" + encodeURIComponent(bootstrap.surface_instance_id) + "/bootstrap", {
          method: "POST",
          headers: { "Accept": "application/json", "Content-Type": "application/json" },
          body: JSON.stringify({ asset_ticket: bootstrap.asset_ticket }),
          credentials: "same-origin",
        });
        if (!assetResponse.ok) {
          throw new Error("asset bootstrap failed with HTTP " + assetResponse.status);
        }
        iframe.src = pluginURL.href;
        document.querySelector("#host-status").textContent = "listening";
        document.querySelector("#runtime-ready").textContent = "1";
        log("host-ready", { host_origin: "` + hostOrigin + `", plugin_origin: pluginURL.origin, asset_ticket_id: bootstrap.asset_ticket_id });
      } catch (error) {
        document.querySelector("#host-status").textContent = "error";
        log("host-error", { message: String(error?.message || error) });
      }
    </script>
  </body>
</html>`
}
