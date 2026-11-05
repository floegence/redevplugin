// Command browser is a loopback-only reference host for browser acceptance.
// Its explicit test policies are not a production authentication implementation.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: browser <plugin-directory> <host-bundle> <state-root>")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return err
	}
	origin := "http://localhost:" + port
	// Stable owner hashes are test identities. Every process has fresh browser credentials.
	session := sessionctx.Context{OwnerUserHash: "reference-user", OwnerEnvHash: "reference-env", OwnerSessionHash: "reference-session", SessionChannelIDHash: "reference-channel", CanRead: true, CanWrite: true}
	harness, err := testhost.Open(context.Background(), testhost.Options{StateRoot: os.Args[3], ParentOrigin: origin, Session: &session, AllowLocalPackages: true, Actions: []host.ManagementAction{
		host.ManagementActionImportLocalPackage, host.ManagementActionListPlugins,
		host.ManagementActionOpenSurface, host.ManagementActionPrepareSurface, host.ManagementActionDisposeSurface,
		host.ManagementActionMintBridgeToken, host.ManagementActionSurfaceMethods, host.ManagementActionInvokeIntent,
		host.ManagementActionMintStorageHandleGrant,
	}})
	if err != nil {
		return err
	}
	defer harness.Close()
	ctx := harness.Context(context.Background())
	records, err := harness.Host().ListPlugins(ctx)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		var archive bytes.Buffer
		if _, err = pluginpkg.BuildFromDir(ctx, os.Args[1], &archive, pluginpkg.DefaultReadLimits()); err != nil {
			return err
		}
		if _, err = host.ImportLocalPackageBytes(ctx, harness.Host(), "reference_data", archive.Bytes()); err != nil {
			return err
		}
	}
	bundle, err := filepath.Abs(os.Args[2])
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/session", harness.SessionHandler())
	mux.HandleFunc("/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		session, err := harness.Guard().Authenticate(r)
		if err != nil {
			http.Error(w, "authentication required", http.StatusForbidden)
			return
		}
		records, err := harness.Host().ListPlugins(sessionctx.WithContext(r.Context(), session))
		if err != nil {
			http.Error(w, "inventory unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"csrf": harness.CSRFToken(), "plugins": records})
	})
	mux.HandleFunc("/host.js", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, bundle) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Reference plugin host</title><body><h1>Reference plugin host</h1><p id="status" role="status">Opening applications</p><main id="surfaces"></main><script type="module" src="/host.js"></script></body></html>`)
	})
	server := &http.Server{Handler: harness.Handler(mux), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Println("Reference:", origin+"/#"+harness.BrowserToken())
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-signalContext.Done():
	case err := <-done:
		if err != http.ErrServerClosed {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		return err
	}
	return harness.Close()
}
