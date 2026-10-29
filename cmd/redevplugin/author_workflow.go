package main

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/secrets"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

//go:embed author_assets/index.html
var authorHTML []byte

//go:embed author_assets/app.js
var authorJS []byte

//go:embed author_assets/styles.css
var authorCSS []byte

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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	_, webPort, _ := net.SplitHostPort(listener.Addr().String())
	origin := "http://localhost:" + webPort
	runtimeModule, err := authorRuntime(ctx, stateRoot, options.runtime, options.sha)
	if err != nil {
		return err
	}
	harness, err := testhost.Open(ctx, authorHostOptions(stateRoot, origin, runtimeModule))
	if err != nil {
		return err
	}
	defer harness.Close()
	ctx = harness.Context(ctx)
	pluginHost := harness.Host()
	target, err := runtimetarget.Current()
	if err != nil {
		return err
	}
	if _, err := pluginHost.StartRuntime(ctx, host.StartRuntimeRequest{Target: target}); err != nil {
		return err
	}
	token, csrf := harness.BrowserToken(), harness.CSRFToken()
	guard := harness.Guard()
	state := &authorBuilds{state: authorBuildState{CSRF: csrf, Mode: "real-runtime"}}
	mux := http.NewServeMux()
	mux.Handle("/dev/session", harness.SessionHandler())
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
	webHandler := harness.Handler(mux)
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	module, err := authorRuntime(ctx, root, options.runtime, options.sha)
	if err != nil {
		return nil, err
	}
	harness, err := testhost.Open(ctx, authorHostOptions(root, "http://localhost:"+port, module))
	if err != nil {
		return nil, err
	}
	defer harness.Close()
	ctx = harness.Context(ctx)
	h := harness.Host()
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

// The preview permits only actions exposed by its author workflow. Plugin
// permission grants remain explicit operations through the production Host.
func authorHostOptions(root, origin string, runtime *host.RuntimeModule) testhost.Options {
	return testhost.Options{
		StateRoot: root, ParentOrigin: origin, AllowLocalPackages: true, Runtime: runtime,
		// The isolated CLI permits private plugin storage. This ceiling does not
		// provide filesystem mounts, method access, or plugin permission grants.
		Session: &sessionctx.Context{
			OwnerSessionHash: rand.Text(), OwnerUserHash: rand.Text(),
			OwnerEnvHash: rand.Text(), SessionChannelIDHash: rand.Text(),
			CanRead: true, CanWrite: true,
		},
		Connectivity: &host.ConnectivityModule{Broker: connectivity.NewMemoryBroker(), NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})},
		Secrets:      &host.SecretsModule{Store: secrets.NewMemoryStore()},
		Background:   &host.BackgroundModule{RunnerFactory: host.NewBackgroundWorkerRunner},
		Actions: []host.ManagementAction{
			host.ManagementActionStartRuntime, host.ManagementActionListPlugins,
			host.ManagementActionImportLocalPackage, host.ManagementActionUpdateLocalPackage,
			host.ManagementActionOpenSurface, host.ManagementActionPrepareSurface,
			host.ManagementActionMintBridgeToken, host.ManagementActionDisposeSurface,
			host.ManagementActionCallPluginMethod, host.ManagementActionPrepareMethodConfirmation,
			host.ManagementActionMintStorageHandleGrant,
			host.ManagementActionRejectSurfaceConfirmation,
			host.ManagementActionGetPermissionRequirements, host.ManagementActionListPermissionGrants,
			host.ManagementActionGrantPermission, host.ManagementActionRevokePermission,
			host.ManagementActionGetSettingsSchema, host.ManagementActionGetPluginSettings,
			host.ManagementActionPatchPluginSettings, host.ManagementActionListIntents,
			host.ManagementActionInvokeIntent, host.ManagementActionGetExecution,
			host.ManagementActionListExecutionEvents, host.ManagementActionCancelExecution,
		},
	}
}
