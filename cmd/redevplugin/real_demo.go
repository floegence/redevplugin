package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/httpadapter"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

const (
	realDemoPluginID            = "com.example.real.demo"
	realDemoPluginName          = "Real Runtime Demo Plugin"
	realDemoSurfaceID           = realDemoPluginID + ".view"
	realDemoHostName            = "app.redevplugin.localhost"
	realDemoHostPort            = "4175"
	realDemoOwner               = "real_demo_owner_session"
	realDemoUser                = "real_demo_owner_user"
	realDemoChannel             = "real_demo_session_channel"
	realDemoCapability          = "example.capability.real_demo"
	realDemoBrokerStoreID       = "workspace"
	realDemoBrokerKVStoreID     = "settings"
	realDemoBrokerSQLiteStoreID = "db"
	realDemoScheduleMethod      = "worker.schedulePlan"
	realDemoScheduleWorkerID    = "schedule_backend"
	realDemoScheduleArtifact    = "workers/schedule.wasm"
	realDemoStreamMethod        = "worker.httpStream"
	realDemoStreamWorkerID      = "network_http_stream"
	realDemoStreamArtifact      = "workers/network-http-stream.wasm"
	realDemoLazyImageBase64     = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)

var realDemoHTTPStreamCase = realDemoNetworkCase{
	Method:       realDemoStreamMethod,
	WorkerID:     realDemoStreamWorkerID,
	Artifact:     realDemoStreamArtifact,
	Transport:    connectivity.TransportHTTP,
	Operation:    "http_stream",
	ConnectorID:  "api",
	Destination:  "https://api.example.com",
	MethodName:   http.MethodGet,
	Path:         "/v1/stream",
	ExpectedText: "real stream line 1\nreal stream line 2\n",
}

var realDemoNetworkMatrix = []realDemoNetworkCase{
	{
		Method:       "worker.networkHTTP",
		WorkerID:     "network_http",
		Artifact:     "workers/network-http.wasm",
		Transport:    connectivity.TransportHTTP,
		Operation:    "http",
		ConnectorID:  "api",
		Destination:  "https://api.example.com",
		MethodName:   http.MethodPost,
		Path:         "/v1/matrix",
		BodyBase64:   base64.StdEncoding.EncodeToString([]byte("hello http")),
		ExpectedText: "http:hello http",
	},
	{
		Method:        "worker.networkWebSocket",
		WorkerID:      "network_websocket",
		Artifact:      "workers/network-websocket.wasm",
		Transport:     connectivity.TransportWebSocket,
		Operation:     "websocket_round_trip",
		ConnectorID:   "stream",
		Destination:   "wss://stream.example.com",
		Path:          "/v1/socket",
		MessageType:   string(connectivity.WebSocketMessageText),
		PayloadBase64: base64.StdEncoding.EncodeToString([]byte("hello websocket")),
		ExpectedText:  "websocket:hello websocket",
	},
	{
		Method:        "worker.networkTCP",
		WorkerID:      "network_tcp",
		Artifact:      "workers/network-tcp.wasm",
		Transport:     connectivity.TransportTCP,
		Operation:     "tcp_round_trip",
		ConnectorID:   "database",
		Destination:   "tcp://db.example.com:5432",
		PayloadBase64: base64.StdEncoding.EncodeToString([]byte("hello tcp")),
		ExpectedText:  "tcp:hello tcp",
	},
	{
		Method:        "worker.networkUDP",
		WorkerID:      "network_udp",
		Artifact:      "workers/network-udp.wasm",
		Transport:     connectivity.TransportUDP,
		Operation:     "udp_round_trip",
		ConnectorID:   "metrics",
		Destination:   "udp://metrics.example.com:8125",
		PayloadBase64: base64.StdEncoding.EncodeToString([]byte("hello udp")),
		ExpectedText:  "udp:hello udp",
	},
}

type realDemoNetworkCase struct {
	Method        string
	WorkerID      string
	Artifact      string
	Transport     connectivity.Transport
	Operation     string
	ConnectorID   string
	Destination   string
	MethodName    string
	Path          string
	MessageType   string
	BodyBase64    string
	PayloadBase64 string
	ExpectedText  string
}

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

type realDemoNetworkExecutor struct{}

func (realDemoNetworkExecutor) DoHTTP(_ context.Context, req connectivity.HTTPRequest) (connectivity.HTTPResponse, error) {
	body := strings.TrimSpace(string(req.Body))
	if body == "" {
		body = "<empty>"
	}
	echo := "http:" + body
	response := map[string]any{
		"demo":         true,
		"transport":    "host-network-executor",
		"connector_id": req.Grant.ConnectorID,
		"destination":  req.Grant.Destination.Canonical(),
		"method":       req.Method,
		"path":         req.Path,
		"body":         body,
		"echo":         echo,
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return connectivity.HTTPResponse{}, err
	}
	return connectivity.HTTPResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       raw,
	}, nil
}

func (e realDemoNetworkExecutor) StreamHTTP(ctx context.Context, req connectivity.HTTPRequest, onChunk func(connectivity.HTTPResponseChunk) error) (connectivity.HTTPStreamResponse, error) {
	chunks := [][]byte{
		[]byte("real stream line 1\n"),
		[]byte("real stream line 2\n"),
	}
	var bytesRead int64
	for _, chunk := range chunks {
		if err := onChunk(connectivity.HTTPResponseChunk{Data: append([]byte(nil), chunk...)}); err != nil {
			return connectivity.HTTPStreamResponse{}, err
		}
		bytesRead += int64(len(chunk))
	}
	return connectivity.HTTPStreamResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		BytesRead:  bytesRead,
		ChunkCount: len(chunks),
	}, nil
}

func (realDemoNetworkExecutor) WebSocketRoundTrip(_ context.Context, req connectivity.WebSocketRoundTripRequest) (connectivity.WebSocketRoundTripResponse, error) {
	messageType := req.MessageType
	if messageType == "" {
		messageType = connectivity.WebSocketMessageText
	}
	return connectivity.WebSocketRoundTripResponse{
		MessageType: messageType,
		Payload:     []byte("websocket:" + string(req.Payload)),
	}, nil
}

func (realDemoNetworkExecutor) TCPRoundTrip(_ context.Context, req connectivity.TCPRoundTripRequest) (connectivity.TCPRoundTripResponse, error) {
	return connectivity.TCPRoundTripResponse{Payload: []byte("tcp:" + string(req.Payload))}, nil
}

func (realDemoNetworkExecutor) UDPRoundTrip(_ context.Context, req connectivity.UDPRoundTripRequest) (connectivity.UDPRoundTripResponse, error) {
	return connectivity.UDPRoundTripResponse{Payload: []byte("udp:" + string(req.Payload))}, nil
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
	if err := addRealDemoMethods(filepath.Join(pluginDir, "manifest.json")); err != nil {
		return err
	}
	if err := writeBytesFile(filepath.Join(pluginDir, "workers", "broker.wasm"), realDemoBrokerWorkerWASM(), 0o644); err != nil {
		return err
	}
	if err := writeBytesFile(filepath.Join(pluginDir, realDemoScheduleArtifact), realDemoScheduleWorkerWASM(), 0o644); err != nil {
		return err
	}
	for _, networkCase := range realDemoNetworkMatrix {
		if err := writeBytesFile(filepath.Join(pluginDir, networkCase.Artifact), realDemoNetworkWorkerWASM(networkCase), 0o644); err != nil {
			return err
		}
	}
	if err := writeBytesFile(filepath.Join(pluginDir, realDemoStreamArtifact), realDemoNetworkWorkerWASM(realDemoHTTPStreamCase), 0o644); err != nil {
		return err
	}
	if err := writeBytesFile(filepath.Join(pluginDir, "ui", "index.html"), []byte(realDemoPluginHTML()), 0o644); err != nil {
		return err
	}
	if err := writeBytesFile(filepath.Join(pluginDir, "ui", "assets", "app.js"), append([]byte(nil), realDemoPluginWorkerJS...), 0o644); err != nil {
		return err
	}
	lazyImage, err := base64.StdEncoding.DecodeString(realDemoLazyImageBase64)
	if err != nil {
		return err
	}
	if err := writeBytesFile(filepath.Join(pluginDir, "ui", "assets", "lazy.png"), lazyImage, 0o644); err != nil {
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
		Connectivity:            connectivity.NewMemoryBroker(),
		NetworkExecutor:         realDemoNetworkExecutor{},
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
	record, err := host.ImportLocalPackageBytes(ctx, pluginHost, packageBytes)
	if err != nil {
		return err
	}
	record, err = pluginHost.EnablePlugin(ctx, host.EnableRequest{
		PluginInstanceID:   record.PluginInstanceID,
		PluginStateVersion: record.ManagementRevision,
	})
	if err != nil {
		return err
	}
	if err := grantRealDemoDeclaredPermissions(ctx, pluginHost, record); err != nil {
		return err
	}
	record, err = currentPluginRecord(ctx, pluginHost, record.PluginInstanceID)
	if err != nil {
		return err
	}
	record, err = pluginHost.EnablePlugin(ctx, host.EnableRequest{
		PluginInstanceID:   record.PluginInstanceID,
		PluginStateVersion: record.ManagementRevision,
	})
	if err != nil {
		return err
	}
	hostPort := demoEnv("REAL_DEMO_HOST_PORT", realDemoHostPort)
	hostName := demoEnv("REAL_DEMO_HOST_NAME", realDemoHostName)
	hostOrigin := "http://" + hostName + ":" + hostPort
	platformHandler := httpadapter.Handler{Host: pluginHost, WebSecurity: realDemoWebSecurityGuard{hostOrigin: hostOrigin}}
	hostMux := http.NewServeMux()
	var prepareCompletedAt atomic.Int64
	var assetCompletedAt atomic.Int64
	var disposeCompletedAt atomic.Int64
	var assetReadCount atomic.Int64
	var disposeCount atomic.Int64
	hostMux.HandleFunc("/favicon.ico", noContentHandler)
	hostMux.Handle("/_redevplugin/api/plugins/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/prepare"):
			time.Sleep(350 * time.Millisecond)
			platformHandler.ServeHTTP(w, r)
			prepareCompletedAt.Store(time.Now().UnixMilli())
		case strings.HasSuffix(r.URL.Path, "/assets/read"):
			time.Sleep(650 * time.Millisecond)
			platformHandler.ServeHTTP(w, r)
			assetReadCount.Add(1)
			assetCompletedAt.Store(time.Now().UnixMilli())
		case strings.HasSuffix(r.URL.Path, "/dispose"):
			platformHandler.ServeHTTP(w, r)
			disposeCount.Add(1)
			disposeCompletedAt.Store(time.Now().UnixMilli())
		default:
			platformHandler.ServeHTTP(w, r)
		}
	}))
	hostMux.HandleFunc("/packages/redevplugin-ui/dist/", realDemoSDKHandler)
	hostMux.HandleFunc("/demo/real/broker-grants", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(r.Header.Get("Origin")) != hostOrigin {
			http.Error(w, "origin is not allowed", http.StatusForbidden)
			return
		}
		broker, err := mintRealDemoBrokerPayload(r.Context(), pluginHost, record.PluginInstanceID, health.RuntimeInstanceID, health.RuntimeGenerationID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": broker})
	})
	hostMux.HandleFunc("/demo/real/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(r.Header.Get("Origin")) != hostOrigin {
			http.Error(w, "origin is not allowed", http.StatusForbidden)
			return
		}
		prepareCompletedAt.Store(0)
		assetCompletedAt.Store(0)
		disposeCompletedAt.Store(0)
		assetReadCount.Store(0)
		disposeCount.Store(0)
		bootstrap, err := pluginHost.OpenSurface(r.Context(), host.OpenSurfaceRequest{
			PluginInstanceID:     record.PluginInstanceID,
			PluginStateVersion:   record.ManagementRevision,
			SurfaceID:            realDemoSurfaceID,
			SurfaceInstanceID:    fmt.Sprintf("surface_real_demo_%d", time.Now().UnixNano()),
			OwnerSessionHash:     realDemoOwner,
			OwnerUserHash:        realDemoUser,
			SessionChannelIDHash: realDemoChannel,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		payload := realDemoHostBootstrapPayload{
			Bootstrap: realDemoBootstrap(bootstrap),
			Broker:    realDemoBrokerConfig{BrokerGrantsURL: "/demo/real/broker-grants"},
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": payload})
	})
	hostMux.HandleFunc("/demo/real/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"prepare_completed_at": prepareCompletedAt.Load(),
			"asset_completed_at":   assetCompletedAt.Load(),
			"dispose_completed_at": disposeCompletedAt.Load(),
			"asset_read_count":     assetReadCount.Load(),
			"dispose_count":        disposeCount.Load(),
		})
	})
	hostMux.HandleFunc("/demo/real/index.html", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeNoStoreHTML(w, realDemoHostHTML())
	})
	hostServer := &http.Server{Addr: "127.0.0.1:" + hostPort, Handler: hostMux}
	errCh := make(chan error, 1)
	go func() {
		errCh <- hostServer.ListenAndServe()
	}()
	fmt.Fprintf(os.Stdout, "ReDevPlugin real runtime demo host: %s/demo/real/index.html\n", hostOrigin)
	fmt.Fprintf(os.Stdout, "ReDevPlugin real runtime demo runtime_generation_id: %s\n", health.RuntimeGenerationID)
	select {
	case <-ctx.Done():
		shutdownDemoServers(hostServer)
		return ctx.Err()
	case err := <-errCh:
		shutdownDemoServers(hostServer)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

type realDemoBootstrapPayload struct {
	PluginID            string `json:"plugin_id"`
	PluginInstanceID    string `json:"plugin_instance_id"`
	PluginVersion       string `json:"plugin_version"`
	SurfaceID           string `json:"surface_id"`
	SurfaceInstanceID   string `json:"surface_instance_id"`
	ActiveFingerprint   string `json:"active_fingerprint"`
	EntryPath           string `json:"entry_path"`
	EntrySHA256         string `json:"entry_sha256"`
	AssetSessionNonce   string `json:"asset_session_nonce"`
	PluginStateVersion  uint64 `json:"plugin_state_version"`
	RevokeEpoch         uint64 `json:"revoke_epoch"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	AssetTicket         string `json:"asset_ticket"`
	AssetTicketID       string `json:"asset_ticket_id"`
	BridgeNonce         string `json:"bridge_nonce"`
}

type realDemoBrokerPayload struct {
	StorageHandleGrantToken       string `json:"storage_handle_grant_token"`
	StorageKVHandleGrantToken     string `json:"storage_kv_handle_grant_token"`
	StorageSQLiteHandleGrantToken string `json:"storage_sqlite_handle_grant_token"`
}

type realDemoBrokerConfig struct {
	BrokerGrantsURL string `json:"broker_grants_url"`
}

type realDemoHostBootstrapPayload struct {
	Bootstrap realDemoBootstrapPayload `json:"bootstrap"`
	Broker    realDemoBrokerConfig     `json:"broker"`
}

func realDemoBootstrap(bootstrap bridge.SurfaceBootstrap) realDemoBootstrapPayload {
	return realDemoBootstrapPayload{
		PluginID:            bootstrap.PluginID,
		PluginInstanceID:    bootstrap.PluginInstanceID,
		PluginVersion:       bootstrap.PluginVersion,
		SurfaceID:           bootstrap.SurfaceID,
		SurfaceInstanceID:   bootstrap.SurfaceInstanceID,
		ActiveFingerprint:   bootstrap.ActiveFingerprint,
		EntryPath:           bootstrap.EntryPath,
		EntrySHA256:         bootstrap.EntrySHA256,
		AssetSessionNonce:   bootstrap.AssetSessionNonce,
		PluginStateVersion:  bootstrap.PluginStateVersion,
		RevokeEpoch:         bootstrap.RevokeEpoch,
		RuntimeGenerationID: bootstrap.RuntimeGenerationID,
		AssetTicket:         bootstrap.AssetTicket,
		AssetTicketID:       bootstrap.AssetTicketID,
		BridgeNonce:         bootstrap.BridgeNonce,
	}
}

func mintRealDemoBrokerPayload(ctx context.Context, pluginHost *host.Host, pluginInstanceID string, runtimeInstanceID string, runtimeGenerationID string) (realDemoBrokerPayload, error) {
	storageGrant, err := pluginHost.MintStorageHandleGrant(ctx, host.MintStorageHandleGrantRequest{
		PluginInstanceID:    pluginInstanceID,
		StoreID:             realDemoBrokerStoreID,
		RuntimeInstanceID:   runtimeInstanceID,
		RuntimeGenerationID: runtimeGenerationID,
	})
	if err != nil {
		return realDemoBrokerPayload{}, err
	}
	storageKVGrant, err := pluginHost.MintStorageHandleGrant(ctx, host.MintStorageHandleGrantRequest{
		PluginInstanceID:    pluginInstanceID,
		StoreID:             realDemoBrokerKVStoreID,
		RuntimeInstanceID:   runtimeInstanceID,
		RuntimeGenerationID: runtimeGenerationID,
	})
	if err != nil {
		return realDemoBrokerPayload{}, err
	}
	storageSQLiteGrant, err := pluginHost.MintStorageHandleGrant(ctx, host.MintStorageHandleGrantRequest{
		PluginInstanceID:    pluginInstanceID,
		StoreID:             realDemoBrokerSQLiteStoreID,
		RuntimeInstanceID:   runtimeInstanceID,
		RuntimeGenerationID: runtimeGenerationID,
	})
	if err != nil {
		return realDemoBrokerPayload{}, err
	}
	return realDemoBrokerPayload{
		StorageHandleGrantToken:       storageGrant.HandleGrant.HandleGrantToken,
		StorageKVHandleGrantToken:     storageKVGrant.HandleGrant.HandleGrantToken,
		StorageSQLiteHandleGrantToken: storageSQLiteGrant.HandleGrant.HandleGrantToken,
	}, nil
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

func addRealDemoMethods(manifestFile string) error {
	raw, err := os.ReadFile(manifestFile)
	if err != nil {
		return err
	}
	var doc manifest.Manifest
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	doc.Workers = appendWorkerIfMissing(doc.Workers, manifest.WorkerSpec{
		WorkerID:         "broker_backend",
		Artifact:         "workers/broker.wasm",
		ABI:              "redevplugin-wasm-worker-v1",
		Mode:             manifest.WorkerModeJob,
		Scope:            "user",
		MemoryLimitBytes: 16 << 20,
	})
	doc.Workers = appendWorkerIfMissing(doc.Workers, manifest.WorkerSpec{
		WorkerID:         realDemoScheduleWorkerID,
		Artifact:         realDemoScheduleArtifact,
		ABI:              "redevplugin-wasm-worker-v1",
		Mode:             manifest.WorkerModeJob,
		Scope:            "user",
		MemoryLimitBytes: 16 << 20,
	})
	doc.Workers = appendWorkerIfMissing(doc.Workers, manifest.WorkerSpec{
		WorkerID:         realDemoStreamWorkerID,
		Artifact:         realDemoStreamArtifact,
		ABI:              "redevplugin-wasm-worker-v1",
		Mode:             manifest.WorkerModeJob,
		Scope:            "user",
		MemoryLimitBytes: 16 << 20,
	})
	for _, networkCase := range realDemoNetworkMatrix {
		doc.Workers = appendWorkerIfMissing(doc.Workers, manifest.WorkerSpec{
			WorkerID:         networkCase.WorkerID,
			Artifact:         networkCase.Artifact,
			ABI:              "redevplugin-wasm-worker-v1",
			Mode:             manifest.WorkerModeJob,
			Scope:            "user",
			MemoryLimitBytes: 16 << 20,
		})
	}
	doc.Methods = appendMethodIfMissing(doc.Methods, manifest.MethodSpec{
		Method:    realDemoStreamMethod,
		Effect:    manifest.MethodEffectRead,
		Execution: manifest.MethodExecutionSubscription,
		CancelPolicy: &manifest.CancelPolicySpec{
			Cancelable:        true,
			DisableBehavior:   manifest.CancelDisableBehaviorOrphan,
			UninstallBehavior: manifest.CancelUninstallBehaviorForceCleanupAllowed,
			AckTimeoutMS:      2000,
		},
		Route:          manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: realDemoStreamWorkerID, Export: "redevplugin_worker_invoke"},
		RequestSchema:  closedMethodObjectSchema(nil),
		ResponseSchema: generatedWorkerResponseSchema(),
	})
	doc.Storage = &manifest.StorageSpec{
		Stores: []manifest.StoreSpec{{
			StoreID:       realDemoBrokerStoreID,
			Kind:          string(storage.StoreFiles),
			Scope:         "user",
			QuotaBytes:    1 << 20,
			SchemaVersion: 1,
			Migration: manifest.MigrationSpec{
				FromVersion:    0,
				ToVersion:      1,
				Reversible:     true,
				RequiresWorker: false,
				EstimatedBytes: 0,
				MaxDurationMS:  1000,
				DataLossRisk:   false,
				StepsHash:      "sha256:real-demo-storage",
			},
		}, {
			StoreID:       realDemoBrokerKVStoreID,
			Kind:          string(storage.StoreKV),
			Scope:         "user",
			QuotaBytes:    256 << 10,
			SchemaVersion: 1,
			Migration: manifest.MigrationSpec{
				FromVersion:    0,
				ToVersion:      1,
				Reversible:     true,
				RequiresWorker: false,
				EstimatedBytes: 0,
				MaxDurationMS:  1000,
				DataLossRisk:   false,
				StepsHash:      "sha256:real-demo-kv",
			},
		}, {
			StoreID:       realDemoBrokerSQLiteStoreID,
			Kind:          string(storage.StoreSQLite),
			Scope:         "user",
			QuotaBytes:    1 << 20,
			SchemaVersion: 1,
			Migration: manifest.MigrationSpec{
				FromVersion:    0,
				ToVersion:      1,
				Reversible:     true,
				RequiresWorker: false,
				EstimatedBytes: 0,
				MaxDurationMS:  1000,
				DataLossRisk:   false,
				StepsHash:      "sha256:real-demo-sqlite",
			},
		}},
	}
	doc.NetworkAccess = &manifest.NetworkAccessSpec{
		Connectors: realDemoNetworkConnectors(),
	}
	doc.CapabilityBindings = appendCapabilityBindingIfMissing(doc.CapabilityBindings, manifest.CapabilityBinding{
		BindingID:            "real_demo",
		CapabilityID:         realDemoCapability,
		MinCapabilityVersion: "1.0.0",
		RequiredPermissions:  []string{"execute"},
	})
	doc.Methods = appendMethodIfMissing(doc.Methods, manifest.MethodSpec{
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
		RequestSchema: closedMethodObjectSchema(map[string]any{
			"target": map[string]any{"type": "string"},
		}),
		ResponseSchema: closedMethodObjectSchema(map[string]any{
			"done":          map[string]any{"type": "boolean"},
			"method":        map[string]any{"type": "string"},
			"target_method": map[string]any{"type": "string"},
			"effect":        map[string]any{"type": "string"},
			"target":        map[string]any{"type": "string"},
			"transport":     map[string]any{"type": "string"},
		}),
	})
	doc.Methods = appendMethodIfMissing(doc.Methods, manifest.MethodSpec{
		Method:    "worker.brokerDemo",
		Effect:    manifest.MethodEffectWrite,
		Execution: manifest.MethodExecutionSync,
		Route:     manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "broker_backend", Export: "redevplugin_worker_invoke"},
		RequestSchema: closedMethodObjectSchema(map[string]any{
			"note":                              map[string]any{"type": "string"},
			"storage_handle_grant_token":        map[string]any{"type": "string"},
			"storage_kv_handle_grant_token":     map[string]any{"type": "string"},
			"storage_sqlite_handle_grant_token": map[string]any{"type": "string"},
		}),
		ResponseSchema: generatedWorkerResponseSchema(),
	})
	doc.Methods = appendMethodIfMissing(doc.Methods, manifest.MethodSpec{
		Method:    realDemoScheduleMethod,
		Effect:    manifest.MethodEffectWrite,
		Execution: manifest.MethodExecutionSync,
		Route:     manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: realDemoScheduleWorkerID, Export: "redevplugin_worker_invoke"},
		RequestSchema: closedMethodObjectSchema(map[string]any{
			"title":                             map[string]any{"type": "string"},
			"starts_at":                         map[string]any{"type": "string"},
			"location":                          map[string]any{"type": "string"},
			"storage_handle_grant_token":        map[string]any{"type": "string"},
			"storage_kv_handle_grant_token":     map[string]any{"type": "string"},
			"storage_sqlite_handle_grant_token": map[string]any{"type": "string"},
		}),
		ResponseSchema: generatedWorkerResponseSchema(),
	})
	for _, networkCase := range realDemoNetworkMatrix {
		doc.Methods = appendMethodIfMissing(doc.Methods, manifest.MethodSpec{
			Method:         networkCase.Method,
			Effect:         manifest.MethodEffectRead,
			Execution:      manifest.MethodExecutionSync,
			Route:          manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: networkCase.WorkerID, Export: "redevplugin_worker_invoke"},
			RequestSchema:  closedMethodObjectSchema(nil),
			ResponseSchema: generatedWorkerResponseSchema(),
		})
	}
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeBytesFile(manifestFile, append(updated, '\n'), 0o644)
}

func appendWorkerIfMissing(workers []manifest.WorkerSpec, worker manifest.WorkerSpec) []manifest.WorkerSpec {
	for _, existing := range workers {
		if existing.WorkerID == worker.WorkerID {
			return workers
		}
	}
	return append(workers, worker)
}

func appendMethodIfMissing(methods []manifest.MethodSpec, method manifest.MethodSpec) []manifest.MethodSpec {
	for _, existing := range methods {
		if existing.Method == method.Method {
			return methods
		}
	}
	return append(methods, method)
}

func appendCapabilityBindingIfMissing(bindings []manifest.CapabilityBinding, binding manifest.CapabilityBinding) []manifest.CapabilityBinding {
	for _, existing := range bindings {
		if existing.BindingID == binding.BindingID {
			return bindings
		}
	}
	return append(bindings, binding)
}

func realDemoNetworkConnectors() []manifest.NetworkConnectorSpec {
	connectors := make([]manifest.NetworkConnectorSpec, 0, len(realDemoNetworkMatrix)+len(scaffoldBrokerHostcalls()))
	for _, networkCase := range realDemoNetworkMatrix {
		connector := manifest.NetworkConnectorSpec{
			ConnectorID:  networkCase.ConnectorID,
			Transport:    string(networkCase.Transport),
			Scope:        string(connectivity.ScopeUser),
			Destinations: []string{networkCase.Destination},
		}
		connectors = mergeNetworkConnector(connectors, connector)
	}
	connectors = mergeNetworkConnector(connectors, manifest.NetworkConnectorSpec{
		ConnectorID:  realDemoHTTPStreamCase.ConnectorID,
		Transport:    string(realDemoHTTPStreamCase.Transport),
		Scope:        string(connectivity.ScopeUser),
		Destinations: []string{realDemoHTTPStreamCase.Destination},
	})
	for _, call := range scaffoldBrokerHostcalls() {
		if call.Module != "redevplugin.network" || call.Name != "execute" {
			continue
		}
		var request struct {
			ConnectorID string `json:"connector_id"`
			Transport   string `json:"transport"`
			Destination string `json:"destination"`
		}
		if err := json.Unmarshal(call.Request, &request); err != nil {
			continue
		}
		connectors = mergeNetworkConnector(connectors, manifest.NetworkConnectorSpec{
			ConnectorID:  request.ConnectorID,
			Transport:    request.Transport,
			Scope:        string(connectivity.ScopeUser),
			Destinations: []string{request.Destination},
		})
	}
	return connectors
}

func mergeNetworkConnector(connectors []manifest.NetworkConnectorSpec, connector manifest.NetworkConnectorSpec) []manifest.NetworkConnectorSpec {
	if strings.TrimSpace(connector.ConnectorID) == "" || strings.TrimSpace(connector.Transport) == "" || len(connector.Destinations) == 0 {
		return connectors
	}
	for i := range connectors {
		if connectors[i].ConnectorID != connector.ConnectorID {
			continue
		}
		if connectors[i].Transport != connector.Transport || connectors[i].Scope != connector.Scope {
			return connectors
		}
		for _, destination := range connector.Destinations {
			if !stringSliceContains(connectors[i].Destinations, destination) {
				connectors[i].Destinations = append(connectors[i].Destinations, destination)
			}
		}
		return connectors
	}
	return append(connectors, connector)
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func realDemoBrokerWorkerWASM() []byte {
	return scaffoldBrokerWorkerWASM()
}

func realDemoScheduleWorkerWASM() []byte {
	return importedMemoryHostcallSequenceWorkerWASM("redevplugin_worker_invoke", realDemoScheduleHostcalls())
}

func realDemoScheduleHostcalls() []memoryHostcallSpec {
	title := "Design plugin rollout"
	startsAt := "2026-07-03T09:30:00+08:00"
	location := "Focus Room A"
	source := "rust runtime storage"
	export := map[string]any{
		"source": "real-runtime-schedule-demo",
		"items": []map[string]string{{
			"title":     title,
			"starts_at": startsAt,
			"location":  location,
			"source":    source,
		}},
	}
	exportRaw := mustJSONBytes(export)
	return []memoryHostcallSpec{
		{
			Module: "redevplugin.storage",
			Name:   "files",
			Request: mustJSONBytes(map[string]any{
				"store_id":    realDemoBrokerStoreID,
				"operation":   "write",
				"path":        "schedule/agenda-export.json",
				"data_base64": base64.StdEncoding.EncodeToString(exportRaw),
			}),
			OutLen: 4096,
		},
		{
			Module: "redevplugin.storage",
			Name:   "kv",
			Request: mustJSONBytes(map[string]any{
				"store_id":     realDemoBrokerKVStoreID,
				"operation":    "put",
				"key":          "schedule/current_view",
				"value_base64": base64.StdEncoding.EncodeToString([]byte("daily-planner")),
			}),
			OutLen: 4096,
		},
		{
			Module: "redevplugin.storage",
			Name:   "sqlite",
			Request: mustJSONBytes(map[string]any{
				"store_id":   realDemoBrokerSQLiteStoreID,
				"operation":  "exec",
				"database":   "plugin.sqlite",
				"sql":        "CREATE TABLE IF NOT EXISTS schedule_items (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, starts_at TEXT NOT NULL, location TEXT NOT NULL, source TEXT NOT NULL)",
				"args":       []any{},
				"timeout_ms": 1000,
			}),
			OutLen: 4096,
		},
		{
			Module: "redevplugin.storage",
			Name:   "sqlite",
			Request: mustJSONBytes(map[string]any{
				"store_id":   realDemoBrokerSQLiteStoreID,
				"operation":  "exec",
				"database":   "plugin.sqlite",
				"sql":        "DELETE FROM schedule_items WHERE title = ?",
				"args":       []map[string]string{{"text": title}},
				"timeout_ms": 1000,
			}),
			OutLen: 4096,
		},
		{
			Module: "redevplugin.storage",
			Name:   "sqlite",
			Request: mustJSONBytes(map[string]any{
				"store_id":   realDemoBrokerSQLiteStoreID,
				"operation":  "exec",
				"database":   "plugin.sqlite",
				"sql":        "INSERT INTO schedule_items (title, starts_at, location, source) VALUES (?, ?, ?, ?)",
				"args":       []map[string]string{{"text": title}, {"text": startsAt}, {"text": location}, {"text": source}},
				"timeout_ms": 1000,
			}),
			OutLen: 4096,
		},
		{
			Module: "redevplugin.storage",
			Name:   "sqlite",
			Request: mustJSONBytes(map[string]any{
				"store_id":           realDemoBrokerSQLiteStoreID,
				"operation":          "query",
				"database":           "plugin.sqlite",
				"sql":                "SELECT title, starts_at, location, source FROM schedule_items WHERE title = ? ORDER BY id DESC LIMIT 1",
				"args":               []map[string]string{{"text": title}},
				"max_rows":           4,
				"max_response_bytes": 4096,
				"timeout_ms":         1000,
			}),
			OutLen: 8192,
		},
	}
}

func realDemoNetworkWorkerWASM(networkCase realDemoNetworkCase) []byte {
	request := map[string]any{
		"connector_id":       networkCase.ConnectorID,
		"transport":          string(networkCase.Transport),
		"destination":        networkCase.Destination,
		"operation":          networkCase.Operation,
		"method":             networkCase.MethodName,
		"path":               networkCase.Path,
		"message_type":       networkCase.MessageType,
		"body_base64":        networkCase.BodyBase64,
		"payload_base64":     networkCase.PayloadBase64,
		"max_request_bytes":  1024,
		"max_response_bytes": 4096,
		"max_chunk_bytes":    1024,
		"max_buffered_bytes": 65536,
		"timeout_ms":         1000,
	}
	if networkCase.MethodName == "" {
		delete(request, "method")
	}
	if networkCase.Path == "" {
		delete(request, "path")
	}
	if networkCase.MessageType == "" {
		delete(request, "message_type")
	}
	if networkCase.BodyBase64 == "" {
		delete(request, "body_base64")
	}
	if networkCase.PayloadBase64 == "" {
		delete(request, "payload_base64")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return realDemoMinimalWorkerWASM("redevplugin_worker_invoke")
	}
	return importedMemoryHostcallWorkerWASM("redevplugin.network", "execute", "redevplugin_worker_invoke", raw)
}

func realDemoMinimalWorkerWASM(exportName string) []byte {
	exportNameBytes := []byte(exportName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		0x03, 0x02, 0x01, 0x00,
		0x07,
	}
	exportPayload := []byte{0x01, byte(len(exportNameBytes))}
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, 0x00)
	module = append(module, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module, 0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b)
	return module
}

func importedMemoryHostcallWorkerWASM(importModuleName string, importNameName string, exportName string, request []byte) []byte {
	exportNameBytes := []byte(exportName)
	importModule := []byte(importModuleName)
	importName := []byte(importNameName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x0c, 0x02,
		0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
		0x60, 0x00, 0x00,
		0x02,
	}
	importPayload := []byte{0x01, byte(len(importModule))}
	importPayload = append(importPayload, importModule...)
	importPayload = append(importPayload, byte(len(importName)))
	importPayload = append(importPayload, importName...)
	importPayload = append(importPayload, 0x00, 0x00)
	module = appendLEBUint32(module, uint32(len(importPayload)))
	module = append(module, importPayload...)
	module = append(module,
		0x03, 0x02, 0x01, 0x01,
		0x05, 0x03, 0x01, 0x00, 0x01,
		0x07,
	)
	exportPayload := []byte{0x02, 0x06}
	exportPayload = append(exportPayload, []byte("memory")...)
	exportPayload = append(exportPayload, 0x02, 0x00, byte(len(exportNameBytes)))
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, 0x01)
	module = appendLEBUint32(module, uint32(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module, 0x0a)
	codePayload := []byte{0x01}
	body := []byte{
		0x00,
		0x41, 0x00,
		0x41,
	}
	body = appendLEBInt32(body, int32(len(request)))
	body = append(body, 0x41)
	body = appendLEBInt32(body, 1024)
	body = append(body, 0x41)
	body = appendLEBInt32(body, 4096)
	body = append(body, 0x10, 0x00, 0x1a, 0x0b)
	codePayload = appendLEBUint32(codePayload, uint32(len(body)))
	codePayload = append(codePayload, body...)
	module = appendLEBUint32(module, uint32(len(codePayload)))
	module = append(module, codePayload...)
	module = append(module, 0x0b)
	dataPayload := []byte{0x01, 0x00, 0x41}
	dataPayload = appendLEBInt32(dataPayload, 0)
	dataPayload = append(dataPayload, 0x0b)
	dataPayload = appendLEBUint32(dataPayload, uint32(len(request)))
	dataPayload = append(dataPayload, request...)
	module = appendLEBUint32(module, uint32(len(dataPayload)))
	module = append(module, dataPayload...)
	return module
}

func appendLEBUint32(out []byte, value uint32) []byte {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if value == 0 {
			return out
		}
	}
}

func appendLEBInt32(out []byte, value int32) []byte {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		done := (value == 0 && b&0x40 == 0) || (value == -1 && b&0x40 != 0)
		if !done {
			b |= 0x80
		}
		out = append(out, b)
		if done {
			return out
		}
	}
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

func currentPluginRecord(ctx context.Context, pluginHost *host.Host, pluginInstanceID string) (registry.PluginRecord, error) {
	records, err := pluginHost.ListPlugins(ctx)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	for _, record := range records {
		if record.PluginInstanceID == pluginInstanceID {
			return record, nil
		}
	}
	return registry.PluginRecord{}, fmt.Errorf("plugin %q is not installed", pluginInstanceID)
}

func noContentHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

type realDemoWebSecurityGuard struct {
	hostOrigin string
}

func (g realDemoWebSecurityGuard) Evaluate(r *http.Request) (websecurity.RequestContext, websecurity.OriginDecision, error) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" && origin != g.hostOrigin {
		return websecurity.RequestContext{}, websecurity.OriginDeny, nil
	}
	return websecurity.RequestContext{
		Origin: origin,
		Route:  r.URL.Path,
		Method: r.Method,
		Scope: websecurity.RequestScope{
			OwnerSessionHash:     realDemoOwner,
			OwnerUserHash:        realDemoUser,
			SessionChannelIDHash: realDemoChannel,
		},
	}, websecurity.OriginTrustedParent, nil
}

func (realDemoWebSecurityGuard) ValidateCSRF(*http.Request, string) error {
	return nil
}

func writeNoStoreHTML(w http.ResponseWriter, html string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, html)
}

func realDemoSDKHandler(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/packages/redevplugin-ui/dist/")
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if rel == "" || clean != rel || strings.HasPrefix(clean, "../") || clean == ".." {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	http.ServeFile(w, r, filepath.Join("packages", "redevplugin-ui", "dist", filepath.FromSlash(clean)))
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
  </head>
  <body>
    <main class="surface">
      <section class="surface">
        <p class="eyebrow">Opaque plugin surface</p>
        <h1>Real Runtime Demo Plugin</h1>
        <p class="status">Starting isolated worker...</p>
        <img src="assets/lazy.png" alt="Delayed plugin asset">
      </section>
    </main>
    <script type="text/redevplugin-worker" src="assets/app.js"></script>
  </body>
</html>
`
}

func realDemoHostHTML() string {
	return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ReDevPlugin Real Runtime Demo</title>
    <style>
      :root { color: #182026; background: #eef1f3; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      * { box-sizing: border-box; }
      body { margin: 0; min-width: 320px; min-height: 100vh; }
      main { display: grid; grid-template-columns: minmax(300px, 360px) minmax(0, 1fr); min-height: 100vh; }
      aside { display: flex; flex-direction: column; gap: 16px; min-height: 0; padding: 22px; border-right: 1px solid #c8ced2; background: #f8f9fa; }
      section { display: grid; grid-template-rows: auto minmax(0, 1fr) auto; min-width: 0; min-height: 100vh; background: #fff; }
      header, .button-row, .confirmation { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
      h1, h2 { margin: 0; letter-spacing: 0; }
      h1 { font-size: 21px; }
      h2 { font-size: 17px; }
      .eyebrow, .label { margin: 0 0 5px; color: #59666d; font-size: 11px; font-weight: 700; text-transform: uppercase; }
      .status { border: 1px solid #c4912f; border-radius: 999px; padding: 5px 9px; color: #704d0b; background: #fff5d8; font-size: 12px; font-weight: 700; }
      .status[data-state="ready"] { border-color: #46917c; color: #15594a; background: #e4f5ef; }
      .status[data-state="error"], .status[data-state="disposed"] { border-color: #cb7770; color: #7d2722; background: #fbe9e7; }
      .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px; border: 1px solid #d7dcdf; background: #d7dcdf; }
      .metric { min-width: 0; padding: 10px; background: #fff; }
      .metric strong { display: block; margin-top: 3px; font-size: 18px; }
      button { min-height: 36px; border: 1px solid #1d5e55; border-radius: 6px; padding: 0 13px; color: #fff; background: #1d5e55; font: inherit; cursor: pointer; }
      button.secondary { border-color: #aab2b8; color: #263238; background: #fff; }
      button.danger { border-color: #a53f38; background: #a53f38; }
      .button-row { flex-wrap: wrap; justify-content: flex-start; }
      .confirmation { align-items: flex-start; padding: 12px; border: 1px solid #d4b05d; background: #fff9e9; }
      .confirmation[hidden] { display: none; }
      code { overflow-wrap: anywhere; font: 10px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
      ul { flex: 1; min-height: 120px; max-height: 42vh; margin: 0; padding: 12px 12px 12px 28px; overflow: auto; border: 1px solid #d7dcdf; background: #fff; font: 11px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }
      li + li { margin-top: 7px; }
      .surface-header { min-height: 66px; padding: 14px 20px; border-bottom: 1px solid #d7dcdf; }
      #plugin-surface-mount { min-height: 0; }
      #plugin-surface-mount > iframe { display: block; width: 100%; height: 100%; min-height: 0; border: 0; background: #fff; }
      #last-result { max-height: 160px; margin: 0; padding: 10px; overflow: auto; border-top: 1px solid #d7dcdf; background: #f6f8f9; font: 10px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; }
      @media (max-width: 780px) { main { grid-template-columns: 1fr; } aside { border-right: 0; border-bottom: 1px solid #c8ced2; } section { min-height: 720px; } }
    </style>
  </head>
  <body>
    <main>
      <aside aria-label="Real host console">
        <header>
          <div><p class="eyebrow">ReDevPlugin real demo</p><h1>Host + Rust runtime</h1></div>
          <span id="host-status" class="status" data-state="opening">opening</span>
        </header>
        <div class="metrics" aria-label="Runtime counters">
          <div class="metric"><span class="label">handshakes</span><strong id="handshake-count">0</strong></div>
          <div class="metric"><span class="label">rpc calls</span><strong id="rpc-count">0</strong></div>
          <div class="metric"><span class="label">runtime</span><strong id="runtime-ready">0</strong></div>
          <div class="metric"><span class="label">opening progress</span><strong id="opening-progress">0</strong></div>
          <div class="metric"><span class="label">credentialless</span><strong id="credentialless-mode">detecting</strong></div>
        </div>
        <div class="button-row">
          <button id="send-visible" type="button">Visible</button>
          <button id="send-hidden" type="button" class="secondary">Hidden</button>
          <button id="dispose-surface" type="button" class="danger">Dispose</button>
        </div>
        <div id="confirmation-panel" class="confirmation" hidden>
          <div><p class="label">Confirmation required</p><strong id="confirmation-method">-</strong><br><code id="confirmation-hash">-</code></div>
          <div class="button-row"><button id="deny-confirmation" class="secondary" type="button">Deny</button><button id="approve-confirmation" type="button">Approve</button></div>
        </div>
        <div><p class="label">Runtime generation</p><code id="runtime-generation">-</code></div>
        <ul id="event-log" aria-label="Sanitized real bridge event log"></ul>
      </aside>
      <section aria-label="Real opaque plugin surface">
        <header class="surface-header"><div><p class="eyebrow">Opaque sandbox iframe</p><h2>Real Runtime Demo Plugin</h2></div><span>MessagePort only</span></header>
        <div id="plugin-surface-mount"></div>
        <pre id="last-result" aria-label="Last trusted host response">{}</pre>
      </section>
    </main>
    <script type="module">
      import { PluginSurfaceHost, createReDevPluginSurfaceTransport, toPluginSurfaceHostBootstrap } from "/packages/redevplugin-ui/dist/trusted-parent.js";
      const surfaceMount = document.querySelector("#plugin-surface-mount");
      const status = document.querySelector("#host-status");
      const eventLog = document.querySelector("#event-log");
      const confirmationPanel = document.querySelector("#confirmation-panel");
      let handshakes = 0;
      let rpcCalls = 0;
      let pendingConfirmation = null;
      let disposedAt = 0;
      let openedAt = 0;
      let confirmationAborted = false;
      const progressEvents = [];

      let runtimeConfig;
      try {
        runtimeConfig = await loadRuntimeConfig();
        document.querySelector("#runtime-generation").textContent = runtimeConfig.bootstrap.runtime_generation_id;
      } catch (error) {
        setStatus("error");
        log("surface-bootstrap-failed", { message: String(error && error.message || error) });
        throw error;
      }
      const bootstrap = runtimeConfig.bootstrap;
      const brokerConfig = runtimeConfig.broker;

      const hostFetch = async (input, init) => {
        const url = String(input);
        const body = init && init.body ? JSON.parse(init.body) : {};
        let nextInit = init;
        if (url.endsWith("/rpc") && isBrokeredRuntimeMethod(body.method)) {
          const grants = await fetchBrokerGrants();
          body.params = Object.assign({}, body.params || {}, {
            storage_handle_grant_token: grants.storage_handle_grant_token,
            storage_kv_handle_grant_token: grants.storage_kv_handle_grant_token,
            storage_sqlite_handle_grant_token: grants.storage_sqlite_handle_grant_token,
          });
          nextInit = Object.assign({}, init, { body: JSON.stringify(body) });
        }
        if (url.endsWith("/bridge-token")) {
          handshakes += 1;
          document.querySelector("#handshake-count").textContent = String(handshakes);
          log("bridge-token", { issued: true });
        }
        if (url.endsWith("/rpc")) {
          rpcCalls += 1;
          document.querySelector("#rpc-count").textContent = String(rpcCalls);
          log("rpc", { method: body.method, confirmed: Boolean(body.confirmation_id) });
        }
        const response = await fetch(input, nextInit);
        if (url.endsWith("/rpc")) {
          document.querySelector("#last-result").textContent = JSON.stringify({
            method: body.method,
            confirmed: Boolean(body.confirmation_id),
            ok: response.ok,
            status: response.status,
          }, null, 2);
        }
        return response;
      };

      const surfaceHost = PluginSurfaceHost.create({
        bootstrap: toPluginSurfaceHostBootstrap(bootstrap),
        hostTransport: createReDevPluginSurfaceTransport({ fetch: hostFetch }),
        confirm: confirmDangerousAction,
        onOpeningProgress: (progress) => {
          progressEvents.push(progress.elapsedMs);
          document.querySelector("#opening-progress").textContent = String(progressEvents.length);
          log("opening-progress", { elapsed_ms: progress.elapsedMs });
        },
        onError: (error) => { setStatus("error"); log("surface-error", { error_code: error.errorCode, message: error.message }); },
      });
      const iframe = surfaceHost.element;
      iframe.id = "plugin-frame";
      iframe.title = "Real runtime opaque plugin surface";
      surfaceMount.replaceChildren(iframe);

      document.querySelector("#send-visible").addEventListener("click", () => sendLifecycle("visible"));
      document.querySelector("#send-hidden").addEventListener("click", () => sendLifecycle("hidden"));
      document.querySelector("#dispose-surface").addEventListener("click", () => void closeSurface());
      document.querySelector("#deny-confirmation").addEventListener("click", () => resolveConfirmation(false));
      document.querySelector("#approve-confirmation").addEventListener("click", () => resolveConfirmation(true));
      addEventListener("beforeunload", () => surfaceHost.dispose());

      window.__redevpluginRealDemo = Object.freeze({
        close: closeSurface,
        snapshot: () => ({
          status: status.dataset.state,
          handshakes,
          rpcCalls,
          disposedAt,
          openedAt,
          progressEvents: [...progressEvents],
          confirmationAborted,
          confirmationVisible: !confirmationPanel.hidden,
          sandbox: iframe.getAttribute("sandbox"),
          credentialless: "credentialless" in iframe ? iframe.credentialless === true : false,
          iframeSrcdocEmpty: iframe.srcdoc === "",
        }),
      });

      try {
        await surfaceHost.open();
        openedAt = Date.now();
        document.querySelector("#runtime-ready").textContent = "1";
        document.querySelector("#credentialless-mode").textContent = "credentialless" in iframe && iframe.credentialless ? "enabled" : "unsupported-safe";
        setStatus("ready");
        log("surface-ready", { host_origin: location.origin, sandbox: iframe.getAttribute("sandbox") });
      } catch (error) {
        setStatus("error");
        log("surface-open-failed", { error_code: error && error.errorCode, message: String(error && error.message || error) });
      }

      async function loadRuntimeConfig() {
        const response = await fetch("/demo/real/bootstrap", {
          method: "POST",
          headers: { "Accept": "application/json", "Content-Type": "application/json" },
          body: "{}",
          credentials: "same-origin",
        });
        if (!response.ok) throw new Error("surface bootstrap failed with HTTP " + response.status);
        const envelope = await response.json();
        const value = envelope && envelope.data ? envelope.data : envelope;
        if (!value || !value.bootstrap || !value.broker || !value.bootstrap.runtime_generation_id) {
          throw new Error("surface bootstrap response is incomplete");
        }
        return value;
      }

      function isBrokeredRuntimeMethod(method) {
        return method === "worker.brokerDemo" || method === "` + realDemoScheduleMethod + `";
      }

      async function fetchBrokerGrants() {
        const response = await fetch(brokerConfig.broker_grants_url, {
          method: "POST",
          headers: { "Accept": "application/json", "Content-Type": "application/json" },
          body: JSON.stringify({ surface_instance_id: bootstrap.surface_instance_id }),
          credentials: "same-origin",
        });
        if (!response.ok) throw new Error("broker grant refresh failed with HTTP " + response.status);
        const envelope = await response.json();
        const grants = envelope && envelope.data ? envelope.data : envelope;
        if (!grants || !grants.storage_handle_grant_token || !grants.storage_kv_handle_grant_token || !grants.storage_sqlite_handle_grant_token) {
          throw new Error("broker grant refresh omitted storage grants");
        }
        log("broker-grants", { refreshed: true });
        return grants;
      }

      function confirmDangerousAction(intent) {
        document.querySelector("#confirmation-method").textContent = intent.method;
        document.querySelector("#confirmation-hash").textContent = intent.requestHash;
        confirmationPanel.hidden = false;
        log("confirmation-requested", { method: intent.method, request_hash: intent.requestHash, plan_hash: intent.planHash });
        return new Promise((resolve) => {
          const pending = { resolve };
          pendingConfirmation = pending;
          intent.signal.addEventListener("abort", () => {
            if (pendingConfirmation !== pending) return;
            pendingConfirmation = null;
            confirmationPanel.hidden = true;
            confirmationAborted = true;
            resolve({ confirmed: false });
            log("confirmation-aborted", { method: intent.method });
          }, { once: true });
        });
      }

      function resolveConfirmation(confirmed) {
        if (!pendingConfirmation) return;
        const pending = pendingConfirmation;
        pendingConfirmation = null;
        confirmationPanel.hidden = true;
        pending.resolve({ confirmed });
        log("confirmation-decided", { confirmed });
      }

      function sendLifecycle(type) {
        try { surfaceHost.sendLifecycle({ type }); log("lifecycle", { type }); }
        catch (error) { log("lifecycle-failed", { message: String(error && error.message || error) }); }
      }

      async function closeSurface() {
        await surfaceHost.close();
        disposedAt = Date.now();
        setStatus("disposed");
        log("surface-disposed", { iframe_srcdoc_empty: iframe.srcdoc === "" });
      }

      function setStatus(value) {
        status.textContent = value;
        status.dataset.state = value;
      }

      function log(type, detail) {
        const item = document.createElement("li");
        item.textContent = type + " " + JSON.stringify(detail);
        eventLog.prepend(item);
        while (eventLog.children.length > 24) eventLog.lastElementChild.remove();
      }
    </script>
  </body>
</html>`
}
