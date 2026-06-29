package httpadapter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/storage"
)

type Envelope struct {
	OK        bool   `json:"ok"`
	Data      any    `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

type Route struct {
	Method string
	Path   string
}

type Handler struct {
	Host *host.Host
}

type openSurfaceRequest struct {
	PluginInstanceID     string `json:"plugin_instance_id"`
	SurfaceID            string `json:"surface_id"`
	SurfaceInstanceID    string `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string `json:"session_channel_id_hash,omitempty"`
}

type exchangeAssetTicketRequest struct {
	AssetTicket string `json:"asset_ticket"`
}

type bridgeTokenRequest struct {
	Handshake       bridge.Handshake `json:"handshake"`
	BridgeChannelID string           `json:"bridge_channel_id"`
}

type exportDataRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	IncludeSecrets   bool   `json:"include_secrets,omitempty"`
}

type importDataRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	ArchiveRef       string `json:"archive_ref"`
	DeleteExisting   bool   `json:"delete_existing,omitempty"`
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/_redeven_proxy/api/plugins/surfaces/open":
		h.handleOpenSurface(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redeven_proxy/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/bootstrap"):
		h.handleExchangeAssetTicket(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redeven_proxy/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/bridge-token"):
		h.handleBridgeToken(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redeven_proxy/api/plugins/data/export":
		h.handleExportData(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redeven_proxy/api/plugins/data/import":
		h.handleImportData(w, r)
	default:
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
	}
}

func RouteSet() []Route {
	routes := []Route{
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/install"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/enable"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/disable"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/uninstall"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/update"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/downgrade"},
		{Method: http.MethodGet, Path: "/_redeven_proxy/api/plugins/catalog"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/surfaces/open"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/surfaces/{surface_instance_id}/bootstrap"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/surfaces/{surface_instance_id}/bridge-token"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/rpc"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/confirm"},
		{Method: http.MethodGet, Path: "/_redeven_proxy/api/plugins/operations"},
		{Method: http.MethodGet, Path: "/_redeven_proxy/api/plugins/operations/{operation_id}"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/operations/{operation_id}/cancel"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/data/export"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/data/import"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/secrets/bind"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/secrets/test"},
		{Method: http.MethodPost, Path: "/_redeven_proxy/api/plugins/secrets/delete"},
		{Method: http.MethodPost, Path: "/_redeven_plugin/bootstrap"},
		{Method: http.MethodGet, Path: "/_redeven_plugin/assets/{asset_path...}"},
		{Method: http.MethodGet, Path: "/_redeven_plugin/stream/{stream_id}"},
		{Method: http.MethodPost, Path: "/_redeven_plugin/csp-report"},
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return routes
}

func WriteJSON(w http.ResponseWriter, status int, envelope Envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope)
}

func (h Handler) handleOpenSurface(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req openSurfaceRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	bootstrap, err := h.Host.OpenSurface(r.Context(), host.OpenSurfaceRequest{
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
	})
	if err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrPermissionDenied)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: bootstrap})
}

func (h Handler) handleExchangeAssetTicket(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/bootstrap")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req exchangeAssetTicketRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.ExchangeAssetTicket(r.Context(), host.ExchangeAssetTicketRequest{
		SurfaceInstanceID: surfaceInstanceID,
		AssetTicket:       req.AssetTicket,
	})
	if err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForBridgeError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handleBridgeToken(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/bridge-token")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req bridgeTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if req.Handshake.SurfaceInstanceID != surfaceInstanceID {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "surface_instance_id mismatch", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.MintBridgeToken(r.Context(), host.MintBridgeTokenRequest{
		Handshake:       req.Handshake,
		BridgeChannelID: req.BridgeChannelID,
	})
	if err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForBridgeError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handleExportData(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req exportDataRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.ExportPluginData(r.Context(), host.ExportDataRequest{
		PluginInstanceID: req.PluginInstanceID,
		IncludeSecrets:   req.IncludeSecrets,
	})
	if err != nil {
		WriteJSON(w, httpStatusForStorageError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForStorageError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handleImportData(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req importDataRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if err := h.Host.ImportPluginData(r.Context(), host.ImportDataRequest{
		PluginInstanceID: req.PluginInstanceID,
		ArchiveRef:       req.ArchiveRef,
		DeleteExisting:   req.DeleteExisting,
	}); err != nil {
		WriteJSON(w, httpStatusForStorageError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForStorageError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]bool{"imported": true}})
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("request body contains trailing JSON values")
	}
	return nil
}

func surfaceInstanceIDFromPath(path string, suffix string) (string, bool) {
	const prefix = "/_redeven_proxy/api/plugins/surfaces/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	id = strings.Trim(id, "/")
	return id, id != ""
}

func errorCodeForBridgeError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, bridge.ErrTokenExpired):
		return security.ErrTokenExpired
	case errors.Is(err, bridge.ErrTokenReplay):
		return security.ErrTokenReplay
	case errors.Is(err, bridge.ErrTokenAlreadyBound):
		return security.ErrGatewayTokenChannelMismatch
	default:
		return security.ErrPermissionDenied
	}
}

func errorCodeForStorageError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, storage.ErrQuotaExceeded):
		return security.ErrStorageQuotaExceeded
	case errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound):
		return security.ErrInvalidRequest
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForStorageError(err error) int {
	switch {
	case errors.Is(err, storage.ErrQuotaExceeded):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}
