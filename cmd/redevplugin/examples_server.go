package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/httpadapter"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/trust"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

const (
	examplesDefaultPort     = "4175"
	examplesPublicDNSServer = "1.1.1.1:53"
	examplesOwnerHash       = "examples_owner_session"
	examplesUserHash        = "examples_owner_user"
	examplesEnvHash         = "examples_owner_environment"
	examplesChannelHash     = "examples_session_channel"
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

const examplesCSRFHeader = "X-ReDevPlugin-CSRF"
const examplesCSRFToken = "examples-browser-csrf-v1"

type examplesWebSecurityGuard struct {
	origin    string
	csrfToken string
}

func (guard examplesWebSecurityGuard) Authenticate(r *http.Request) (sessionctx.Context, error) {
	return examplesSession(), nil
}

func (guard examplesWebSecurityGuard) ValidateOrigin(r *http.Request, _ sessionctx.Context, policy websecurity.OriginPolicy) error {
	if policy != websecurity.OriginPolicyTrustedHost {
		return websecurity.ErrOriginPolicyInvalid
	}
	values := r.Header.Values("Origin")
	if len(values) != 1 || values[0] != guard.origin || strings.Contains(values[0], ",") {
		return websecurity.ErrOriginDenied
	}
	return nil
}

func (guard examplesWebSecurityGuard) ValidateCSRF(r *http.Request, _ sessionctx.Context, policy websecurity.CSRFPolicy) error {
	if policy != websecurity.CSRFPolicyRequired {
		return websecurity.ErrCSRFPolicyInvalid
	}
	values := r.Header.Values(examplesCSRFHeader)
	if len(values) == 0 {
		return websecurity.ErrCSRFRequired
	}
	if len(values) != 1 || strings.Contains(values[0], ",") || subtle.ConstantTimeCompare([]byte(values[0]), []byte(guard.csrfToken)) != 1 {
		return websecurity.ErrCSRFInvalid
	}
	return nil
}

func (examplesWebSecurityGuard) AuthorizeRoute(_ *http.Request, _ sessionctx.Context, action websecurity.RouteAction, _ websecurity.RouteEffect) error {
	if !action.Valid() {
		return websecurity.ErrRouteActionInvalid
	}
	return nil
}

func examplesSession() sessionctx.Context {
	return sessionctx.Context{
		OwnerSessionHash:     examplesOwnerHash,
		OwnerUserHash:        examplesUserHash,
		OwnerEnvHash:         examplesEnvHash,
		SessionChannelIDHash: examplesChannelHash,
	}
}

func examplesContext(ctx context.Context) context.Context {
	return sessionctx.WithContext(ctx, examplesSession())
}

type exampleInstalledPlugin struct {
	Spec   examplePluginSpec
	Record registry.PluginRecord
}

type exampleCatalogItem struct {
	Slug               string   `json:"slug"`
	PluginID           string   `json:"plugin_id"`
	PluginInstanceID   string   `json:"plugin_instance_id"`
	ManagementRevision uint64   `json:"management_revision"`
	SurfaceID          string   `json:"surface_id"`
	Name               string   `json:"name"`
	Version            string   `json:"version"`
	Category           string   `json:"category"`
	Description        string   `json:"description"`
	Icon               string   `json:"icon"`
	Capabilities       []string `json:"capabilities"`
}

type exampleSuccessResponse struct {
	OK   bool `json:"ok"`
	Data any  `json:"data"`
}

type exampleErrorResponse struct {
	OK    bool                 `json:"ok"`
	Error examplePlatformError `json:"error"`
}

type examplePlatformError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}

type examplesRuntimeHealthReader interface {
	RuntimeHealth(ctx context.Context) (runtimeclient.ManagerHealth, error)
}

type examplesEventStore interface {
	observability.AuditSink
	observability.SecurityAuditJournal
	observability.DiagnosticsSink
	observability.DiagnosticLister
}

type examplesServerOptions struct {
	Listener          net.Listener
	NetworkExecutor   connectivity.NetworkExecutor
	Events            examplesEventStore
	Output            io.Writer
	RepositoryRoot    string
	RuntimeShardCount int
	OnReady           func(*host.Host)
}

func examplesServer(ctx context.Context, stateRoot string, runtimePath string) error {
	return examplesServerWithOptions(ctx, stateRoot, runtimePath, examplesServerOptions{RuntimeShardCount: 1})
}

func examplesServerWithOptions(ctx context.Context, stateRoot string, runtimePath string, options examplesServerOptions) error {
	ctx = examplesContext(ctx)
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
	assetStore, err := pluginpkg.NewFileAssetStore(filepath.Join(stateRoot, "assets"))
	if err != nil {
		_ = registryStore.Close()
		return err
	}
	pluginData, err := plugindata.Open(ctx, filepath.Join(stateRoot, "plugin-data"), registryStore)
	if err != nil {
		_ = registryStore.Close()
		return err
	}
	secretStore, err := secrets.NewSQLiteStore(ctx, filepath.Join(stateRoot, "secrets.sqlite"))
	if err != nil {
		_ = pluginData.Close()
		_ = registryStore.Close()
		return err
	}
	networkExecutor := options.NetworkExecutor
	if networkExecutor == nil {
		networkExecutor = newExamplesNetworkExecutor(examplesPublicDNSServer)
	}
	events := options.Events
	if events == nil {
		events = observability.NewMemoryStore()
	}
	surfaceTokens := bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{})
	connectivityBroker := connectivity.NewMemoryBroker()
	operationStore := operation.NewMemoryStore()
	confirmationIntentStore := security.NewMemoryConfirmationIntentStore()
	streamStore := stream.NewMemoryStore()
	runtimeTarget, err := runtimetarget.Current()
	if err != nil {
		return err
	}
	runtimeDescriptor, err := describeCommandRuntime(runtimePath, runtimeTarget)
	if err != nil {
		return err
	}
	runtimeManager, err := newCommandRuntimeManager(commandRuntimeDependencies{
		Path:             runtimePath,
		Descriptor:       runtimeDescriptor,
		Diagnostics:      events,
		Assets:           assetStore,
		SurfaceTokens:    surfaceTokens,
		PluginData:       pluginData,
		Connectivity:     connectivityBroker,
		NetworkExecutor:  networkExecutor,
		ShardCount:       options.RuntimeShardCount,
		HandshakeTimeout: 15 * time.Second,
	})
	if err != nil {
		return err
	}
	pluginHost, err := host.Open(ctx, host.Config{
		Core: host.CoreAdapters{
			Policy:               staticPolicyAdapter{},
			Authorization:        staticAuthorizationAdapter{},
			PackageTrustVerifier: trust.Ed25519Verifier{Keyring: trust.StaticKeyring{}},
			Registry:             registryStore,
			Audit:                events,
			SecurityAudit:        events,
			Diagnostics:          events,
			SurfaceTokens:        surfaceTokens,
			PluginData:           pluginData,
			Assets:               assetStore,
			InstallStages:        installstage.NewMemoryStore(),
			Operations:           operationStore,
			ConfirmationIntents:  confirmationIntentStore,
			Streams:              streamStore,
		},
		Runtime: &host.RuntimeModule{Manager: runtimeManager},
		Connectivity: &host.ConnectivityModule{
			Broker:          connectivityBroker,
			NetworkExecutor: networkExecutor,
		},
		Secrets: &host.SecretsModule{Store: secretStore},
	})
	if err != nil {
		_ = secretStore.Close()
		_ = pluginData.Close()
		_ = registryStore.Close()
		return err
	}
	defer func() {
		_ = pluginHost.Close()
		_ = secretStore.Close()
		_ = registryStore.Close()
	}()
	health, err := pluginHost.StartRuntime(ctx, host.StartRuntimeRequest{Target: runtimeTarget})
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
	refreshResults, err := pluginHost.RefreshEnabledPlugins(ctx)
	if err != nil {
		return fmt.Errorf("restore enabled example plugin runtime state: %w", err)
	}
	for _, result := range refreshResults {
		if result.Status == host.RefreshEnabledPluginStatusFailed {
			return fmt.Errorf("restore enabled example plugin %s runtime state: %s: %s", result.PluginInstanceID, result.Error.Code, result.Error.Message)
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
	platformHandler, err := httpadapter.NewHandler(httpadapter.Dependencies{
		Host:  pluginHost,
		Guard: examplesWebSecurityGuard{origin: origin, csrfToken: examplesCSRFToken},
	})
	if err != nil {
		return err
	}
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
	fmt.Fprintf(output, "Runtime shards: %d\n", len(health.Shards))
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

func examplesHealthHandler(runtimeHealth examplesRuntimeHealthReader, pluginCount int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		health, err := runtimeHealth.RuntimeHealth(examplesContext(r.Context()))
		if err != nil {
			writeExampleError(w, http.StatusServiceUnavailable, "EXAMPLE_RUNTIME_HEALTH_FAILED", "runtime health is unavailable")
			return
		}
		writeExampleEnvelope(w, http.StatusOK, map[string]any{
			"ready":          health.Ready,
			"runtime_shards": health.Shards,
			"plugins":        pluginCount,
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
	pkg, err := pluginpkg.BuildFromDir(ctx, filepath.Join(repositoryRoot, "examples", "plugins", spec.Slug), &archive, pluginpkg.DefaultReadLimits())
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
			PluginInstanceID:           record.PluginInstanceID,
			ExpectedManagementRevision: record.ManagementRevision,
			PackageReader:              bytes.NewReader(archive.Bytes()),
			PackageSize:                int64(archive.Len()),
		})
	}
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		record, err = pluginHost.EnablePlugin(ctx, host.EnableRequest{
			PluginInstanceID:           record.PluginInstanceID,
			ExpectedManagementRevision: record.ManagementRevision,
		})
	}
	return record, err
}

func catalogItem(plugin exampleInstalledPlugin) exampleCatalogItem {
	return exampleCatalogItem{
		Slug:               plugin.Spec.Slug,
		PluginID:           plugin.Record.PluginID,
		PluginInstanceID:   plugin.Record.PluginInstanceID,
		ManagementRevision: plugin.Record.ManagementRevision,
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
	_ = json.NewEncoder(w).Encode(exampleSuccessResponse{OK: true, Data: data})
}

func writeExampleError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(exampleErrorResponse{
		OK:    false,
		Error: examplePlatformError{Code: code, Message: message, Details: map[string]any{}},
	})
}

var _ websecurity.Guard = examplesWebSecurityGuard{}
