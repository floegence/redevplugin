package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/httpadapter"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/version"
	"github.com/floegence/redevplugin/v3/pkg/websecurity"
)

//go:embed author_assets/index.html
var authorHTML []byte

//go:embed author_assets/app.js
var authorJS []byte

//go:embed author_assets/styles.css
var authorCSS []byte

const authorCookie = "redevplugin_dev_session"

type authorWebGuard struct {
	origin, token, csrf string
	session             sessionctx.Context
}

func (g authorWebGuard) Authenticate(r *http.Request) (sessionctx.Context, error) {
	cookie, err := r.Cookie(authorCookie)
	if r.Host != strings.TrimPrefix(g.origin, "http://") || err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(g.token)) != 1 {
		return sessionctx.Context{}, host.ErrActionDenied
	}
	return g.session, nil
}
func (g authorWebGuard) ValidateOrigin(r *http.Request, s sessionctx.Context, p websecurity.OriginPolicy) error {
	return (examplesWebSecurityGuard{origin: g.origin, csrfToken: g.csrf}).ValidateOrigin(r, s, p)
}
func (g authorWebGuard) ValidateCSRF(r *http.Request, s sessionctx.Context, p websecurity.CSRFPolicy) error {
	return (examplesWebSecurityGuard{origin: g.origin, csrfToken: g.csrf}).ValidateCSRF(r, s, p)
}
func (g authorWebGuard) AuthorizeRoute(r *http.Request, s sessionctx.Context, a websecurity.RouteAction, e websecurity.RouteEffect) error {
	return (examplesWebSecurityGuard{}).AuthorizeRoute(r, s, a, e)
}

func authorRandom() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
func authorSession() (sessionctx.Context, error) {
	values := make([]string, 4)
	for i := range values {
		var err error
		values[i], err = authorRandom()
		if err != nil {
			return sessionctx.Context{}, err
		}
	}
	return sessionctx.Context{OwnerSessionHash: values[0], OwnerUserHash: values[1], OwnerEnvHash: values[2], SessionChannelIDHash: values[3], CanRead: true, CanWrite: true}, nil
}

func authorRuntime(ctx context.Context, stateRoot, path, expectedSHA string) (*host.RuntimeModule, error) {
	if path == "" || expectedSHA == "" {
		return nil, errors.New("real runtime requires --runtime and --runtime-sha256 from an independently verified build; no automatic fixture fallback")
	}
	target, err := runtimetarget.Current()
	if err != nil {
		return nil, err
	}
	digest, err := host.ParseSHA256Digest(expectedSHA)
	if err != nil {
		return nil, err
	}
	platform, err := version.ParseSemVer(version.CurrentPlatformVersion())
	if err != nil {
		return nil, err
	}
	identity, err := host.NewRuntimeArtifactIdentity(host.RuntimeArtifactIdentityOptions{PlatformVersion: platform, Target: target, BinarySHA256: digest})
	if err != nil {
		return nil, err
	}
	return newCommandRuntimeModule(ctx, path, stateRoot, identity, 15*time.Second)
}

type authorOptions struct{ runtime, sha, surface, method, params string }

func parseAuthorOptions(args []string) (string, authorOptions, error) {
	if len(args) == 0 {
		return "", authorOptions{}, errors.New("a local source directory is required")
	}
	var options authorOptions
	flags := flag.NewFlagSet("author", flag.ContinueOnError)
	flags.StringVar(&options.runtime, "runtime", "", "verified runtime executable")
	flags.StringVar(&options.sha, "runtime-sha256", "", "independently verified executable SHA-256")
	flags.StringVar(&options.surface, "surface", "", "surface for real runtime test")
	flags.StringVar(&options.method, "method", "", "method for real runtime test")
	flags.StringVar(&options.params, "params", "{}", "JSON method parameters")
	if err := flags.Parse(args[1:]); err != nil {
		return "", options, err
	}
	if flags.NArg() != 0 {
		return "", options, errors.New("unexpected author command arguments")
	}
	return args[0], options, nil
}

type authorBuildState struct {
	RestartRequired  bool   `json:"restart_required"`
	Generation       uint64 `json:"generation"`
	Building         bool   `json:"building"`
	Error            string `json:"error"`
	Output           string `json:"output"`
	PluginInstanceID string `json:"plugin_instance_id"`
	CSRF             string `json:"csrf"`
	Mode             string `json:"mode"`
}
type authorBuilds struct {
	mu     sync.Mutex
	state  authorBuildState
	record registry.PluginRecord
}

func (s *authorBuilds) snapshot() authorBuildState { s.mu.Lock(); defer s.mu.Unlock(); return s.state }
func (s *authorBuilds) build(ctx context.Context, p *authorproject.Project, h *host.Host) {
	s.mu.Lock()
	if s.state.RestartRequired {
		s.mu.Unlock()
		return
	}
	s.state.Building = true
	s.state.Error = ""
	current := s.record
	s.mu.Unlock()
	result, err := p.Run(ctx, p.Config.Build)
	var next registry.PluginRecord
	if err == nil {
		var raw []byte
		var pkgHash string
		var pkgPackageErr error
		pkg, packageBytes, pkgPackageErr := p.Package(ctx)
		raw, err = packageBytes, pkgPackageErr
		pkgHash = pkg.PackageHash
		if err == nil && current.PluginInstanceID != "" {
			records, listErr := h.ListPlugins(ctx)
			err = listErr
			found := false
			for _, candidate := range records {
				if candidate.PluginInstanceID == current.PluginInstanceID {
					current = candidate
					found = true
					break
				}
			}
			if err == nil && !found {
				err = errors.New("preview plugin was removed; restart the developer preview")
			}
		}
		if err == nil {
			if current.PluginInstanceID == "" {
				id, idErr := newCLIPluginInstanceID()
				if idErr != nil {
					err = idErr
				} else {
					next, err = host.ImportLocalPackageBytes(ctx, h, id, raw)
				}
			} else if current.PackageHash == pkgHash {
				next = current
			} else {
				next, err = h.UpdateLocalPackage(ctx, host.UpdateLocalPackageRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision, PackageReader: bytes.NewReader(raw), PackageSize: int64(len(raw))})
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Building = false
	s.state.Output = result.Output
	if err != nil {
		s.state.Error = err.Error()
		if mutation.ForError(err) != mutation.OutcomeNotCommitted {
			s.state.RestartRequired = true
			s.state.Error = "Package mutation requires reconciliation; restart the isolated preview. " + err.Error()
		}
		return
	}
	s.record = next
	s.state.PluginInstanceID = next.PluginInstanceID
	s.state.Generation++
}

// watchAuthorProject permits one build at a time and remembers edits during it.
func watchAuthorProject(ctx context.Context, p *authorproject.Project, build func(), onError func(error)) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	done := make(chan struct{}, 1)
	running := false
	pending := true
	last, err := p.Snapshot(ctx)
	if err != nil {
		onError(err)
		return
	}
	changed := time.Now().Add(-time.Second)
	snapshotFailed := false
	start := func() { running = true; pending = false; go func() { build(); done <- struct{}{} }() }
	start()
	for {
		select {
		case <-ctx.Done():
			if running {
				<-done
			}
			return
		case <-done:
			running = false
		case <-ticker.C:
			digest, err := p.Snapshot(ctx)
			if err != nil {
				snapshotFailed = true
				onError(err)
				continue
			}
			if digest != last || snapshotFailed {
				snapshotFailed = false
				pending = true
				changed = time.Now()
				last = digest
			}
		}
		if pending && !running && time.Since(changed) >= 250*time.Millisecond {
			start()
		}
	}
}

func runAuthorDev(ctx context.Context, args []string) error {
	root, options, err := parseAuthorOptions(args)
	if err != nil {
		return err
	}
	project, err := authorproject.Load(root)
	if err != nil {
		return err
	}
	if _, err := project.Snapshot(ctx); err != nil {
		return err
	}
	stateRoot, err := os.MkdirTemp("", "redevplugin-author-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stateRoot)
	session, err := authorSession()
	if err != nil {
		return err
	}
	ctx = sessionctx.WithContext(ctx, session)
	runtimeModule, err := authorRuntime(ctx, stateRoot, options.runtime, options.sha)
	if err != nil {
		return err
	}
	config, err := newEphemeralCLIAdapters(stateRoot)
	if err != nil {
		_, _ = runtimeModule.Close(context.Background())
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	_, webPort, _ := net.SplitHostPort(listener.Addr().String())
	webOrigins := localWebOrigins{port: webPort}
	origin := webOrigins.parentOrigin()
	config.Runtime = runtimeModule
	config.Web = &host.WebModule{Origins: webOrigins}
	config.Background = &host.BackgroundModule{RunnerFactory: host.NewBackgroundWorkerRunner}
	pluginHost, err := host.Open(ctx, config)
	if err != nil {
		_, _ = runtimeModule.Close(context.Background())
		return err
	}
	defer pluginHost.Close()
	target, err := runtimetarget.Current()
	if err != nil {
		return err
	}
	if _, err := pluginHost.StartRuntime(ctx, host.StartRuntimeRequest{Target: target}); err != nil {
		return err
	}
	token, err := authorRandom()
	if err != nil {
		return err
	}
	csrf, err := authorRandom()
	if err != nil {
		return err
	}
	guard := authorWebGuard{origin: origin, token: token, csrf: csrf, session: session}
	platform, err := httpadapter.NewHandler(httpadapter.Dependencies{Host: pluginHost, Guard: guard})
	if err != nil {
		return err
	}
	state := &authorBuilds{state: authorBuildState{CSRF: csrf, Mode: "real-runtime"}}
	mux := http.NewServeMux()
	mux.Handle("/_redevplugin/api/plugins/", platform)
	mux.HandleFunc("/dev/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Origin") != origin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 128))
		if err != nil || subtle.ConstantTimeCompare(raw, []byte(token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: authorCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/dev/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if _, err := guard.Authenticate(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.snapshot())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body []byte
		switch r.URL.Path {
		case "/":
			body = authorHTML
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "/app.js":
			body = authorJS
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case "/styles.css":
			body = authorCSS
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Host != "localhost:"+webPort {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
	webHandler, err := webOrigins.handler(pluginHost, handler)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: webHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		watchAuthorProject(watchCtx, project, func() { state.build(watchCtx, project, pluginHost) }, func(err error) { state.mu.Lock(); state.state.Error = err.Error(); state.mu.Unlock() })
	}()
	fmt.Fprintf(os.Stdout, "ReDevPlugin DEV (real runtime)\nSource: %s\nBuild: %q\nPreview: %s/#%s\nState is isolated and removed on exit. Permissions require explicit approval in the preview.\n", project.Root, project.Config.Build, origin, token)
	select {
	case <-ctx.Done():
		err = nil
	case err = <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	cancel()
	<-watchDone
	shutdownCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	return errors.Join(err, server.Shutdown(shutdownCtx))
}

func runAuthorTest(ctx context.Context, args []string) (runErr error) {
	report := map[string]any{"schema_version": "redevplugin.author-test.v1", "ok": false, "mode": "author-business-and-package", "commands": []authorproject.CommandResult{}}
	defer func() {
		if runErr != nil {
			report["error"] = runErr.Error()
		}
		runErr = errors.Join(runErr, writeJSON(report))
	}()
	root, options, err := parseAuthorOptions(args)
	if err != nil {
		return err
	}
	if options.runtime == "" && options.sha == "" && (options.surface != "" || options.method != "" || options.params != "{}") {
		return errors.New("runtime invocation options require --runtime and --runtime-sha256")
	}
	p, err := authorproject.Load(root)
	if err != nil {
		return err
	}
	results := []authorproject.CommandResult{}
	for _, argv := range [][]string{p.Config.Build, p.Config.Test} {
		result, err := p.Run(ctx, argv)
		results = append(results, result)
		report["commands"] = results
		if err != nil {
			return err
		}
	}
	pkg, raw, err := p.Package(ctx)
	if err != nil {
		return err
	}
	report["package_hash"] = pkg.PackageHash
	mode := "author-business-and-package"
	var runtimeResult any
	if options.runtime != "" || options.sha != "" {
		report["mode"] = "real-runtime"
		if options.surface == "" || options.method == "" {
			return errors.New("real runtime test requires --surface and --method")
		}
		runtimeResult, err = authorRuntimeCall(ctx, options, raw)
		if err != nil {
			return err
		}
		mode = "real-runtime"
	}
	report["ok"], report["mode"] = true, mode
	if runtimeResult != nil {
		report["runtime_result"] = runtimeResult
	}
	return nil
}

func authorRuntimeCall(ctx context.Context, options authorOptions, raw []byte) (any, error) {
	var params map[string]any
	if err := json.Unmarshal([]byte(options.params), &params); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp("", "redevplugin-author-test-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	session, err := authorSession()
	if err != nil {
		return nil, err
	}
	ctx = sessionctx.WithContext(ctx, session)
	module, err := authorRuntime(ctx, root, options.runtime, options.sha)
	if err != nil {
		return nil, err
	}
	config, err := newEphemeralCLIAdapters(root)
	if err != nil {
		_, _ = module.Close(context.Background())
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	config.Web = &host.WebModule{Origins: localWebOrigins{port: port}}
	config.Runtime = module
	h, err := host.Open(ctx, config)
	if err != nil {
		_, _ = module.Close(context.Background())
		return nil, err
	}
	defer h.Close()
	target, err := runtimetarget.Current()
	if err != nil {
		return nil, err
	}
	if _, err := h.StartRuntime(ctx, host.StartRuntimeRequest{Target: target}); err != nil {
		return nil, fmt.Errorf("start author runtime (platform %s, target %s): %w", version.CurrentPlatformVersion(), target.String(), err)
	}
	id, err := newCLIPluginInstanceID()
	if err != nil {
		return nil, err
	}
	record, err := host.ImportLocalPackageBytes(ctx, h, id, raw)
	if err != nil {
		return nil, err
	}
	bootstrap, err := h.OpenSurface(ctx, host.OpenSurfaceRequest{PluginInstanceID: id, ExpectedManagementRevision: record.ManagementRevision, SurfaceID: options.surface, SurfaceInstanceID: "author_test_surface"})
	if err != nil {
		return nil, err
	}
	if _, err := h.PrepareSurface(ctx, host.PrepareSurfaceRequest{SurfaceInstanceID: bootstrap.SurfaceInstanceID, AssetTicket: bootstrap.AssetTicket}); err != nil {
		return nil, err
	}
	handshake := bridge.Handshake{PluginID: bootstrap.PluginID, SurfaceID: bootstrap.SurfaceID, SurfaceInstanceID: bootstrap.SurfaceInstanceID, ActiveFingerprint: bootstrap.ActiveFingerprint, BridgeNonce: bootstrap.BridgeNonce, AssetSessionNonce: bootstrap.AssetSessionNonce, ManagementRevision: bootstrap.ManagementRevision, RevokeEpoch: bootstrap.RevokeEpoch}
	gateway, err := h.MintBridgeToken(ctx, host.MintBridgeTokenRequest{Handshake: handshake, BridgeChannelID: "author_test_bridge", HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "author_test_bridge")})
	if err != nil {
		return nil, err
	}
	return h.CallPluginMethod(ctx, host.CallMethodRequest{PluginInstanceID: id, SurfaceInstanceID: bootstrap.SurfaceInstanceID, BridgeChannelID: "author_test_bridge", GatewayToken: gateway.GatewayToken, Method: options.method, Params: params})
}
