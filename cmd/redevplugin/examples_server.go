package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/httpadapter"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

const (
	examplesDefaultPort     = "4175"
	examplesPublicDNSServer = "1.1.1.1:53"
	examplesOwnerHash       = "examples_owner_session"
	examplesUserHash        = "examples_owner_user"
	examplesChannelHash     = "examples_session_channel"
)

var (
	errExamplesOriginDenied       = errors.New("examples request origin is denied")
	errExamplesContentTypeInvalid = errors.New("examples request content type is invalid")
)

type examplePluginSpec struct {
	Slug             string
	PluginID         string
	PluginInstanceID string
	SurfaceID        string
	Name             string
	Category         string
	Description      string
	Icon             string
	Capabilities     []string
}

var examplePluginSpecs = []examplePluginSpec{
	{
		Slug:             "memos",
		PluginID:         "dev.redevplugin.examples.memos",
		PluginInstanceID: "plugini_examples_memos",
		SurfaceID:        "memos.view",
		Name:             "Memos",
		Category:         "Productivity",
		Description:      "A private Markdown timeline with safe drafts, search, tags, pinning, and archives.",
		Icon:             "/assets/memos-v2.webp",
		Capabilities:     []string{"Safe drafts", "Markdown timeline", "Tags and calendar"},
	},
	{
		Slug:             "weather",
		PluginID:         "dev.redevplugin.examples.weather",
		PluginInstanceID: "plugini_examples_weather",
		SurfaceID:        "weather.view",
		Name:             "Weather",
		Category:         "Utilities",
		Description:      "Saved locations, live Open-Meteo conditions, and a seven day forecast.",
		Icon:             "/assets/weather-v2.webp",
		Capabilities:     []string{"External network", "SQLite storage", "Live forecast"},
	},
	{
		Slug:             "sky-strike",
		PluginID:         "dev.redevplugin.examples.sky-strike",
		PluginInstanceID: "plugini_examples_sky_strike",
		SurfaceID:        "sky-strike.view",
		Name:             "Sky Strike",
		Category:         "Arcade",
		Description:      "A responsive aircraft shooter with touch controls, visible FPS, and persistent high scores.",
		Icon:             "/assets/sky-strike-v2.webp",
		Capabilities:     []string{"OffscreenCanvas", "Image assets", "Persistent score"},
	},
}

type examplesRuntimeResolver struct{ path string }

func (resolver examplesRuntimeResolver) RuntimePath(context.Context, host.RuntimeTarget) (string, error) {
	return resolver.path, nil
}

type examplesWebSecurityGuard struct{ origin string }

func (guard examplesWebSecurityGuard) Evaluate(r *http.Request) (websecurity.RequestContext, websecurity.OriginDecision, error) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" && origin != guard.origin {
		return websecurity.RequestContext{}, websecurity.OriginDeny, nil
	}
	return websecurity.RequestContext{
		Origin: origin,
		Route:  r.URL.Path,
		Method: r.Method,
		Scope: websecurity.RequestScope{
			OwnerSessionHash:     examplesOwnerHash,
			OwnerUserHash:        examplesUserHash,
			SessionChannelIDHash: examplesChannelHash,
		},
	}, websecurity.OriginTrustedParent, nil
}

func (examplesWebSecurityGuard) ValidateCSRF(*http.Request, string) error { return nil }

type exampleInstalledPlugin struct {
	Spec   examplePluginSpec
	Record registry.PluginRecord
}

type exampleCatalogItem struct {
	Slug               string   `json:"slug"`
	PluginID           string   `json:"plugin_id"`
	PluginInstanceID   string   `json:"plugin_instance_id"`
	PluginStateVersion uint64   `json:"plugin_state_version"`
	SurfaceID          string   `json:"surface_id"`
	Name               string   `json:"name"`
	Version            string   `json:"version"`
	Category           string   `json:"category"`
	Description        string   `json:"description"`
	Icon               string   `json:"icon"`
	Capabilities       []string `json:"capabilities"`
}

type exampleOpenRequest struct {
	Slug string `json:"slug"`
}

type examplesRuntimeHealthReader interface {
	RuntimeHealth(ctx context.Context) (runtimeclient.Health, error)
}

type examplesServerOptions struct {
	Listener        net.Listener
	NetworkExecutor connectivity.NetworkExecutor
	Output          io.Writer
	RepositoryRoot  string
	OnReady         func(*host.Host)
}

func examplesServer(ctx context.Context, stateRoot string, runtimePath string) error {
	return examplesServerWithOptions(ctx, stateRoot, runtimePath, examplesServerOptions{})
}

func examplesServerWithOptions(ctx context.Context, stateRoot string, runtimePath string, options examplesServerOptions) error {
	stateRoot = strings.TrimSpace(stateRoot)
	runtimePath = strings.TrimSpace(runtimePath)
	if stateRoot == "" {
		return errors.New("state_root is required")
	}
	if runtimePath == "" {
		return errors.New("runtime_path is required")
	}
	repositoryRoot := strings.TrimSpace(options.RepositoryRoot)
	if repositoryRoot == "" {
		var err error
		repositoryRoot, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	showcaseRoot := filepath.Join(repositoryRoot, "examples", "showcase")
	if _, err := os.Stat(filepath.Join(showcaseRoot, "index.html")); err != nil {
		return fmt.Errorf("examples showcase is unavailable from %q: %w", repositoryRoot, err)
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return err
	}

	registryStore, err := registry.NewSQLiteStore(ctx, filepath.Join(stateRoot, "registry.sqlite"))
	if err != nil {
		return err
	}
	defer registryStore.Close()
	assetStore, err := pluginpkg.NewFileAssetStore(filepath.Join(stateRoot, "assets"))
	if err != nil {
		return err
	}
	storageBroker, err := storage.NewFileBroker(filepath.Join(stateRoot, "storage"))
	if err != nil {
		return err
	}
	networkExecutor := options.NetworkExecutor
	if networkExecutor == nil {
		networkExecutor = newExamplesNetworkExecutor(examplesPublicDNSServer)
	}
	pluginHost, err := host.New(host.Adapters{
		SessionResolver:         staticSessionResolver{},
		Policy:                  staticPolicyAdapter{},
		RuntimeArtifactResolver: examplesRuntimeResolver{path: runtimePath},
		Registry:                registryStore,
		Assets:                  assetStore,
		Storage:                 storageBroker,
		Connectivity:            connectivity.NewMemoryBroker(),
		NetworkExecutor:         networkExecutor,
	})
	if err != nil {
		return err
	}
	health, err := pluginHost.StartRuntime(ctx, host.StartRuntimeRequest{Target: host.RuntimeTarget{OS: runtime.GOOS, Arch: runtime.GOARCH}})
	if err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = pluginHost.StopRuntime(stopCtx)
	}()

	installed := make(map[string]exampleInstalledPlugin, len(examplePluginSpecs))
	for _, spec := range examplePluginSpecs {
		record, err := ensureExamplePlugin(ctx, pluginHost, repositoryRoot, spec)
		if err != nil {
			return fmt.Errorf("prepare example plugin %s: %w", spec.Slug, err)
		}
		installed[spec.Slug] = exampleInstalledPlugin{Spec: spec, Record: record}
	}
	refreshed, err := pluginHost.RefreshEnabledPlugins(ctx)
	if err != nil {
		return fmt.Errorf("restore enabled example plugin runtime state: %w", err)
	}
	for _, record := range refreshed {
		for slug, plugin := range installed {
			if plugin.Record.PluginInstanceID == record.PluginInstanceID {
				plugin.Record = record
				installed[slug] = plugin
				break
			}
		}
	}
	if options.OnReady != nil {
		options.OnReady(pluginHost)
	}

	listener := options.Listener
	if listener == nil {
		port := strings.TrimSpace(os.Getenv("REDEVPLUGIN_EXAMPLES_PORT"))
		if port == "" {
			port = examplesDefaultPort
		}
		listener, err = net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			return err
		}
	}
	defer listener.Close()
	origin := "http://" + listener.Addr().String()
	platformHandler := httpadapter.Handler{Host: pluginHost, WebSecurity: examplesWebSecurityGuard{origin: origin}}
	mux := http.NewServeMux()
	mux.Handle("/_redevplugin/api/plugins/", platformHandler)
	mux.HandleFunc("/api/catalog", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		items := make([]exampleCatalogItem, 0, len(examplePluginSpecs))
		for _, spec := range examplePluginSpecs {
			plugin := installed[spec.Slug]
			items = append(items, catalogItem(plugin))
		}
		writeExampleEnvelope(w, http.StatusOK, items)
	})
	mux.HandleFunc("/api/open", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := validateExamplesJSONMutationRequest(r, origin); err != nil {
			switch {
			case errors.Is(err, errExamplesOriginDenied):
				writeExampleError(w, http.StatusForbidden, "EXAMPLE_ORIGIN_DENIED", "request origin is not allowed")
			default:
				writeExampleError(w, http.StatusUnsupportedMediaType, "EXAMPLE_CONTENT_TYPE_INVALID", "request content type must be application/json")
			}
			return
		}
		var request exampleOpenRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeExampleError(w, http.StatusBadRequest, "EXAMPLE_REQUEST_INVALID", "open request is invalid")
			return
		}
		plugin, ok := installed[strings.TrimSpace(request.Slug)]
		if !ok {
			writeExampleError(w, http.StatusNotFound, "EXAMPLE_PLUGIN_NOT_FOUND", "example plugin is unavailable")
			return
		}
		bootstrap, err := pluginHost.OpenSurface(r.Context(), host.OpenSurfaceRequest{
			PluginInstanceID:     plugin.Record.PluginInstanceID,
			PluginStateVersion:   plugin.Record.ManagementRevision,
			SurfaceID:            plugin.Spec.SurfaceID,
			SurfaceInstanceID:    fmt.Sprintf("surface_examples_%s_%d", strings.ReplaceAll(plugin.Spec.Slug, "-", "_"), time.Now().UnixNano()),
			OwnerSessionHash:     examplesOwnerHash,
			OwnerUserHash:        examplesUserHash,
			SessionChannelIDHash: examplesChannelHash,
		})
		if err != nil {
			writeExampleError(w, http.StatusInternalServerError, "EXAMPLE_SURFACE_OPEN_FAILED", err.Error())
			return
		}
		writeExampleEnvelope(w, http.StatusOK, bootstrap)
	})
	mux.HandleFunc("/api/health", examplesHealthHandler(pluginHost, len(installed)))
	mux.Handle("/", noStoreStatic(showcaseRoot))

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	output := options.Output
	if output == nil {
		output = os.Stdout
	}
	fmt.Fprintf(output, "ReDevPlugin examples: %s\n", origin)
	fmt.Fprintf(output, "Runtime generation: %s\n", health.RuntimeGenerationID)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func validateExamplesJSONMutationRequest(r *http.Request, origin string) error {
	if strings.TrimSpace(r.Header.Get("Origin")) != origin {
		return errExamplesOriginDenied
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errExamplesContentTypeInvalid
	}
	return nil
}

func examplesHealthHandler(runtimeHealth examplesRuntimeHealthReader, pluginCount int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		health, err := runtimeHealth.RuntimeHealth(r.Context())
		if err != nil {
			writeExampleError(w, http.StatusServiceUnavailable, "EXAMPLE_RUNTIME_HEALTH_FAILED", "runtime health is unavailable")
			return
		}
		writeExampleEnvelope(w, http.StatusOK, map[string]any{
			"ready":                 health.Ready,
			"runtime_generation_id": health.RuntimeGenerationID,
			"plugins":               pluginCount,
		})
	}
}

func newExamplesNetworkExecutor(dnsAddress string) connectivity.NetworkExecutor {
	resolver := newExamplesPublicResolver(dnsAddress)
	return connectivity.NewExecutor(connectivity.ExecutorOptions{
		Dialer:       &net.Dialer{Resolver: resolver},
		LookupIPAddr: resolver.LookupIPAddr,
	})
}

func newExamplesPublicResolver(dnsAddress string) *net.Resolver {
	dnsDialer := &net.Dialer{Timeout: 3 * time.Second}
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			return dnsDialer.DialContext(ctx, network, dnsAddress)
		},
	}
}

func ensureExamplePlugin(ctx context.Context, pluginHost *host.Host, repositoryRoot string, spec examplePluginSpec) (registry.PluginRecord, error) {
	var archive bytes.Buffer
	pkg, err := pluginpkg.BuildFromDir(ctx, filepath.Join(repositoryRoot, "examples", "plugins", spec.Slug), &archive, pluginpkg.DefaultReadOptions())
	if err != nil {
		return registry.PluginRecord{}, err
	}
	records, err := pluginHost.ListPlugins(ctx)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	var record registry.PluginRecord
	found := false
	for _, candidate := range records {
		if candidate.PluginInstanceID == spec.PluginInstanceID && candidate.DeletedAt == nil {
			record = candidate
			found = true
			break
		}
	}
	if !found {
		record, err = pluginHost.ImportLocalPackage(ctx, host.ImportLocalPackageRequest{
			PackageReader:    bytes.NewReader(archive.Bytes()),
			PackageSize:      int64(archive.Len()),
			PluginInstanceID: spec.PluginInstanceID,
		})
	} else if record.PackageHash != pkg.PackageHash {
		record, err = pluginHost.UpdateLocalPackage(ctx, host.UpdateLocalPackageRequest{
			PluginInstanceID:   record.PluginInstanceID,
			PluginStateVersion: record.ManagementRevision,
			PackageReader:      bytes.NewReader(archive.Bytes()),
			PackageSize:        int64(archive.Len()),
		})
	}
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		record, err = pluginHost.EnablePlugin(ctx, host.EnableRequest{
			PluginInstanceID:   record.PluginInstanceID,
			PluginStateVersion: record.ManagementRevision,
		})
	}
	return record, err
}

func catalogItem(plugin exampleInstalledPlugin) exampleCatalogItem {
	return exampleCatalogItem{
		Slug:               plugin.Spec.Slug,
		PluginID:           plugin.Record.PluginID,
		PluginInstanceID:   plugin.Record.PluginInstanceID,
		PluginStateVersion: plugin.Record.ManagementRevision,
		SurfaceID:          plugin.Spec.SurfaceID,
		Name:               plugin.Spec.Name,
		Version:            plugin.Record.Version,
		Category:           plugin.Spec.Category,
		Description:        plugin.Spec.Description,
		Icon:               plugin.Spec.Icon,
		Capabilities:       append([]string(nil), plugin.Spec.Capabilities...),
	}
}

func noStoreStatic(root string) http.Handler {
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		files.ServeHTTP(w, r)
	})
}

func writeExampleEnvelope(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
}

func writeExampleError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]string{"code": code, "message": message}})
}

var _ host.RuntimeArtifactResolver = examplesRuntimeResolver{}
var _ websecurity.Guard = examplesWebSecurityGuard{}
