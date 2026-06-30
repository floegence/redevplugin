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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/httpadapter"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/storage"
)

const (
	realDemoPluginID        = "com.example.real.demo"
	realDemoPluginName      = "Real Runtime Demo Plugin"
	realDemoSurfaceID       = realDemoPluginID + ".activity"
	realDemoHostName        = "app.redevplugin.localhost"
	realDemoSandboxHost     = "plg-real.redevplugin.localhost"
	realDemoHostPort        = "4175"
	realDemoPluginPort      = "4176"
	realDemoOwner           = "real_demo_owner_session"
	realDemoUser            = "real_demo_owner_user"
	realDemoChannel         = "real_demo_session_channel"
	realDemoCapability      = "example.capability.real_demo"
	realDemoAssetCookieName = "__Host-redevplugin-asset-session"
)

type realDemoRuntimeResolver struct {
	path string
}

func (r realDemoRuntimeResolver) RuntimePath(context.Context, host.RuntimeTarget) (string, error) {
	return r.path, nil
}

type realDemoCapabilityAdapter struct{}

func (realDemoCapabilityAdapter) InvokeCapability(_ context.Context, req capability.Invocation) (capability.Result, error) {
	return capability.Result{Data: map[string]any{
		"done":          true,
		"method":        req.Method,
		"target_method": req.TargetMethod,
		"effect":        req.Effect,
		"target":        req.Arguments["target"],
		"transport":     "real http adapter confirmation",
	}}, nil
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
	if err := addRealDemoDangerousMethod(filepath.Join(pluginDir, "manifest.json")); err != nil {
		return err
	}
	if err := writeBytesFile(filepath.Join(pluginDir, "ui", "index.html"), []byte(realDemoPluginHTML()), 0o644); err != nil {
		return err
	}
	if err := writeBytesFile(filepath.Join(pluginDir, "ui", "assets", "app.js"), []byte(realDemoPluginJS()), 0o644); err != nil {
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
	pluginHost.Capabilities().Register(realDemoCapability, realDemoCapabilityAdapter{})
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
	if err := grantRealDemoDeclaredPermissions(ctx, pluginHost, record); err != nil {
		return err
	}
	hostPort := demoEnv("REAL_DEMO_HOST_PORT", realDemoHostPort)
	pluginPort := demoEnv("REAL_DEMO_PLUGIN_PORT", realDemoPluginPort)
	hostName := demoEnv("REAL_DEMO_HOST_NAME", realDemoHostName)
	sandboxHost := demoEnv("REAL_DEMO_SANDBOX_HOST", realDemoSandboxHost)
	sandboxOrigin := "http://" + sandboxHost + ":" + pluginPort
	hostOrigin := "http://" + hostName + ":" + hostPort
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
	pluginMux.Handle("/_redevplugin/", realDemoSandboxHandler(hostOrigin, platformHandler))
	pluginMux.HandleFunc("/", http.NotFound)
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
	fmt.Fprintf(os.Stdout, "ReDevPlugin real runtime demo plugin sandbox assets: %s/_redevplugin/assets/ui/index.html\n", sandboxOrigin)
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

func addRealDemoDangerousMethod(manifestFile string) error {
	raw, err := os.ReadFile(manifestFile)
	if err != nil {
		return err
	}
	var doc manifest.Manifest
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	doc.CapabilityBindings = append(doc.CapabilityBindings, manifest.CapabilityBinding{
		BindingID:            "real_demo",
		CapabilityID:         realDemoCapability,
		MinCapabilityVersion: "1.0.0",
		RequiredPermissions:  []string{"execute"},
	})
	doc.Methods = append(doc.Methods, manifest.MethodSpec{
		Method:    "danger.run",
		Effect:    manifest.MethodEffectExecute,
		Execution: manifest.MethodExecutionSync,
		Dangerous: true,
		Confirmation: &manifest.ConfirmationSpec{
			Mode:              manifest.ConfirmationRequired,
			RequestHashFields: []string{"target"},
		},
		Route: manifest.MethodRouteSpec{
			Kind:         manifest.MethodRouteCapability,
			BindingID:    "real_demo",
			TargetMethod: "danger.run",
		},
		RequestSchema:  map[string]any{"type": "object", "additionalProperties": true},
		ResponseSchema: map[string]any{"type": "object"},
	})
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeBytesFile(manifestFile, append(updated, '\n'), 0o644)
}

func grantRealDemoDeclaredPermissions(ctx context.Context, pluginHost *host.Host, record registry.PluginRecord) error {
	seen := map[string]struct{}{}
	for _, binding := range record.Manifest.CapabilityBindings {
		for _, permissionID := range binding.RequiredPermissions {
			permissionID = strings.TrimSpace(permissionID)
			if permissionID == "" {
				continue
			}
			if _, ok := seen[permissionID]; ok {
				continue
			}
			seen[permissionID] = struct{}{}
			if _, err := pluginHost.GrantPermission(ctx, host.GrantPermissionRequest{
				PluginInstanceID: record.PluginInstanceID,
				PermissionID:     permissionID,
				GrantedBy:        "real-demo",
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func noContentHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func realDemoSandboxHandler(hostOrigin string, platformHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodOptions && r.URL.Path == "/_redevplugin/bootstrap":
			if !writeRealDemoBootstrapCORS(w, r, hostOrigin) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/bootstrap":
			if !writeRealDemoBootstrapCORS(w, r, hostOrigin) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			platformHandler.ServeHTTP(w, r)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/_redevplugin/assets/"):
			platformHandler.ServeHTTP(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/csp-report":
			platformHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func writeRealDemoBootstrapCORS(w http.ResponseWriter, r *http.Request, hostOrigin string) bool {
	w.Header().Add("Vary", "Origin")
	if strings.TrimSpace(r.Header.Get("Origin")) != hostOrigin {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", hostOrigin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	return true
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

func realDemoPluginHTML() string {
	return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Real Runtime Demo Plugin</title>
    <link rel="stylesheet" href="assets/styles.css">
    <script src="assets/app.js" defer></script>
  </head>
  <body>
    <main id="app" data-plugin-title="Real Runtime Demo Plugin" data-plugin-id="` + realDemoPluginID + `" data-surface-id="` + realDemoSurfaceID + `">
      <section class="surface">
        <p class="eyebrow">Plugin surface</p>
        <h1>Real Runtime Demo Plugin</h1>
        <div class="toolbar">
          <p class="status" id="status">Ready</p>
          <button id="invoke-worker" type="button">Invoke backend</button>
          <button id="invoke-danger" type="button">Dangerous action</button>
        </div>
        <pre id="result" aria-label="Latest result">Waiting for bridge handshake...</pre>
      </section>
    </main>
  </body>
</html>
`
}

func realDemoPluginJS() string {
	return `const status = document.getElementById('status');
const invokeButton = document.getElementById('invoke-worker');
const dangerButton = document.getElementById('invoke-danger');
const result = document.getElementById('result');
const params = new URLSearchParams(window.location.search);
const parentOrigin = params.get('parent_origin');
const bootstrap = {
  pluginId: params.get('plugin_id') || document.getElementById('app')?.dataset.pluginId || '` + realDemoPluginID + `',
  surfaceId: params.get('surface_id') || document.getElementById('app')?.dataset.surfaceId || '` + realDemoSurfaceID + `',
  surfaceInstanceId: params.get('surface_instance_id') || 'surface_real_demo_preview',
  activeFingerprint: params.get('active_fingerprint') || 'sha256:real-demo-preview',
  bridgeNonce: params.get('bridge_nonce') || 'bridge_nonce_real_demo_preview',
};
let nextID = 1;
const pending = new Map();

if (!parentOrigin || parentOrigin === '*') {
  setStatus('Missing exact parent_origin');
} else {
  window.addEventListener('message', handleMessage);
  window.parent.postMessage({
    type: 'redevplugin.bridge.handshake',
    plugin_id: bootstrap.pluginId,
    surface_id: bootstrap.surfaceId,
    surface_instance_id: bootstrap.surfaceInstanceId,
    active_fingerprint: bootstrap.activeFingerprint,
    bridge_nonce: bootstrap.bridgeNonce,
    ui_protocol_version: 'plugin-ui-v1',
  }, parentOrigin);
  setStatus('Handshaking with host...');
}

invokeButton?.addEventListener('click', async () => {
  try {
    setBusy(true);
    setStatus('Calling worker.echo...');
    const response = await callHost('worker.echo', { message: 'Hello from real runtime demo' });
    setStatus('Backend responded');
    writeResult({ method: 'worker.echo', response, token_leak_check: tokenLeakCheck(response) });
  } catch (error) {
    setStatus('Backend call failed');
    writeResult({ method: 'worker.echo', error: String(error?.message || error), error_code: error?.errorCode });
  } finally {
    setBusy(false);
  }
});

dangerButton?.addEventListener('click', async () => {
  try {
    setBusy(true);
    setStatus('Waiting for confirmation...');
    const response = await callHost('danger.run', { target: 'demo-database' });
    setStatus('Dangerous action confirmed');
    writeResult({ method: 'danger.run', response, token_leak_check: tokenLeakCheck(response) });
  } catch (error) {
    setStatus('Dangerous action blocked');
    writeResult({ method: 'danger.run', error: String(error?.message || error), error_code: error?.errorCode });
  } finally {
    setBusy(false);
  }
});

function handleMessage(event) {
  if (event.origin !== parentOrigin) {
    return;
  }
  const data = event.data;
  if (data?.type === 'redevplugin.bridge.lifecycle') {
    setStatus(data.event?.type === 'ready' ? 'Ready' : ` + "`Lifecycle: ${data.event?.type || 'unknown'}`" + `);
    return;
  }
  if (data?.type !== 'redevplugin.bridge.response' || typeof data.id !== 'string') {
    return;
  }
  const call = pending.get(data.id);
  if (!call) {
    return;
  }
  pending.delete(data.id);
  window.clearTimeout(call.timer);
  if (data.ok) {
    call.resolve(data.data);
  } else {
    const error = new Error(data.error || 'Plugin call failed');
    error.errorCode = data.error_code || 'PLUGIN_CALL_FAILED';
    call.reject(error);
  }
}

function callHost(method, callParams) {
  if (!parentOrigin || parentOrigin === '*') {
    return Promise.reject(new Error('parent_origin must be an exact origin'));
  }
  const id = String(nextID++);
  const promise = new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      pending.delete(id);
      reject(new Error(` + "`Plugin bridge call ${id} timed out`" + `));
    }, 30000);
    pending.set(id, { resolve, reject, timer });
  });
  window.parent.postMessage({ type: 'redevplugin.bridge.call', request: { id, method, params: callParams } }, parentOrigin);
  return promise;
}

function tokenLeakCheck(value) {
  const serialized = JSON.stringify(value);
  return {
    asset_ticket_visible: location.href.includes('asset_ticket') || document.cookie.includes('` + realDemoAssetCookieName + `'),
    gateway_token_visible: serialized.includes('plugin_gateway_token') || serialized.includes('gateway_token'),
    confirmation_token_visible: serialized.includes('confirmation_token'),
  };
}

function setBusy(busy) {
  if (invokeButton) {
    invokeButton.disabled = busy;
  }
  if (dangerButton) {
    dangerButton.disabled = busy;
  }
}

function setStatus(value) {
  if (status) {
    status.textContent = value;
  }
}

function writeResult(value) {
  if (result) {
    result.textContent = JSON.stringify(value, null, 2);
  }
}
`
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
      button.danger { background: #b42318; }
      button.danger:hover { background: #8f1d14; }
      button.secondary { background: #eef2f7; color: #223044; }
      button.secondary:hover { background: #dfe6f0; }
      .confirmation { background: #fff7ed; border: 1px solid #fed7aa; border-radius: 8px; display: flex; gap: 12px; justify-content: space-between; margin-bottom: 12px; padding: 10px; }
      .confirmation[hidden] { display: none; }
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
        <div id="confirmation-panel" class="confirmation" hidden>
          <div>
            <span class="label">pending confirmation</span>
            <strong id="confirmation-method">-</strong>
            <code id="confirmation-hash">-</code>
          </div>
          <div>
            <button id="deny-confirmation" class="secondary" type="button">Deny</button>
            <button id="approve-confirmation" type="button">Approve</button>
          </div>
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
      const pluginURL = new URL("/_redevplugin/assets/ui/index.html", pluginOrigin);
      pluginURL.searchParams.set("parent_origin", location.origin);
      pluginURL.searchParams.set("plugin_id", bootstrap.plugin_id);
      pluginURL.searchParams.set("surface_id", bootstrap.surface_id);
      pluginURL.searchParams.set("surface_instance_id", bootstrap.surface_instance_id);
      pluginURL.searchParams.set("active_fingerprint", bootstrap.active_fingerprint);
      pluginURL.searchParams.set("bridge_nonce", bootstrap.bridge_nonce);
      const iframe = document.querySelector("#plugin-frame");
      let handshakes = 0;
      let rpcCalls = 0;
      let confirmations = 0;
      let pendingConfirmation = null;
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
          log("rpc", { method: body.method, confirmed: Boolean(body.confirmation_token) });
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
        confirm(intent) {
          confirmations += 1;
          document.querySelector("#confirmation-method").textContent = intent.method;
          document.querySelector("#confirmation-hash").textContent = intent.requestHash;
          document.querySelector("#confirmation-panel").hidden = false;
          log("confirmation-required", { method: intent.method, confirmation_token_id: intent.confirmationTokenId, count: confirmations });
          return new Promise((resolve) => {
            pendingConfirmation = resolve;
          });
        },
        onError(error) {
          document.querySelector("#host-status").textContent = "error";
          log("host-error", { error_code: error.errorCode, message: error.message });
        },
      });
      document.querySelector("#send-visible").addEventListener("click", () => {
        surfaceHost.sendLifecycle({ type: "visible" });
        log("lifecycle", { type: "visible" });
      });
      document.querySelector("#deny-confirmation").addEventListener("click", () => {
        resolvePendingConfirmation(false);
      });
      document.querySelector("#approve-confirmation").addEventListener("click", () => {
        resolvePendingConfirmation(true);
      });
      window.addEventListener("beforeunload", () => surfaceHost.dispose());
      function resolvePendingConfirmation(confirmed) {
        if (!pendingConfirmation) {
          return;
        }
        document.querySelector("#confirmation-panel").hidden = true;
        pendingConfirmation({ confirmed });
        pendingConfirmation = null;
        log("confirmation-decision", { confirmed });
      }
      try {
        const assetBootstrapURL = new URL("/_redevplugin/bootstrap", pluginOrigin);
        const assetResponse = await fetch(assetBootstrapURL.href, {
          method: "POST",
          headers: { "Accept": "application/json", "Content-Type": "application/json" },
          body: JSON.stringify({
            surface_instance_id: bootstrap.surface_instance_id,
            asset_ticket: bootstrap.asset_ticket,
          }),
          credentials: "include",
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
