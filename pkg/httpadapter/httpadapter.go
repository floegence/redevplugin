package httpadapter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
	"github.com/floegence/redevplugin/pkg/websecurity"
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
	Host        *host.Host
	WebSecurity websecurity.Guard
}

type installRequest struct {
	PackageBase64    string              `json:"package_base64"`
	TrustState       registry.TrustState `json:"trust_state,omitempty"`
	PluginInstanceID string              `json:"plugin_instance_id,omitempty"`
}

type updateRequest struct {
	PluginInstanceID string              `json:"plugin_instance_id"`
	PackageBase64    string              `json:"package_base64"`
	TrustState       registry.TrustState `json:"trust_state,omitempty"`
}

type downgradeRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	Version          string `json:"version,omitempty"`
	PackageHash      string `json:"package_hash,omitempty"`
}

type enableRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
}

type disableRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	Reason           string `json:"reason,omitempty"`
}

type uninstallRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	DeleteData       bool   `json:"delete_data"`
}

type openSurfaceRequest struct {
	PluginInstanceID     string `json:"plugin_instance_id"`
	SurfaceID            string `json:"surface_id"`
	SurfaceInstanceID    string `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string `json:"session_channel_id_hash,omitempty"`
	SandboxOrigin        string `json:"sandbox_origin,omitempty"`
}

type exchangeAssetTicketRequest struct {
	AssetTicket string `json:"asset_ticket"`
}

type bridgeTokenRequest struct {
	Handshake       pluginBridgeHandshake `json:"handshake"`
	BridgeChannelID string                `json:"bridge_channel_id"`
}

type pluginBridgeHandshake struct {
	Type              string `json:"type,omitempty"`
	PluginID          string `json:"plugin_id"`
	SurfaceID         string `json:"surface_id"`
	SurfaceInstanceID string `json:"surface_instance_id"`
	ActiveFingerprint string `json:"active_fingerprint"`
	BridgeNonce       string `json:"bridge_nonce"`
	UIProtocolVersion string `json:"ui_protocol_version"`
}

type rpcRequest struct {
	PluginInstanceID     string         `json:"plugin_instance_id"`
	SurfaceInstanceID    string         `json:"surface_instance_id"`
	SessionChannelIDHash string         `json:"session_channel_id_hash,omitempty"`
	OwnerSessionHash     string         `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string         `json:"owner_user_hash,omitempty"`
	BridgeChannelID      string         `json:"bridge_channel_id"`
	GatewayToken         string         `json:"plugin_gateway_token"`
	ConfirmationToken    string         `json:"confirmation_token,omitempty"`
	Method               string         `json:"method"`
	Params               map[string]any `json:"params,omitempty"`
}

type invokeIntentRequest struct {
	PluginInstanceID     string         `json:"plugin_instance_id,omitempty"`
	IntentID             string         `json:"intent_id"`
	Params               map[string]any `json:"params,omitempty"`
	OwnerSessionHash     string         `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string         `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string         `json:"session_channel_id_hash,omitempty"`
}

type exportDataRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	IncludeSecrets   bool   `json:"include_secrets,omitempty"`
}

type importDataRequest struct {
	PluginInstanceID   string `json:"plugin_instance_id"`
	ArchiveRef         string `json:"archive_ref"`
	SettingsArchiveRef string `json:"settings_archive_ref,omitempty"`
	DeleteExisting     bool   `json:"delete_existing,omitempty"`
}

type grantPermissionRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionID     string    `json:"permission_id"`
	GrantedBy        string    `json:"granted_by,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type revokePermissionRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	PermissionID     string `json:"permission_id"`
	RevokedBy        string `json:"revoked_by,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

type secretRefRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	SecretRef        string `json:"secret_ref"`
	Scope            string `json:"scope"`
}

type patchSettingsRequest struct {
	Values map[string]any `json:"values"`
}

type sandboxBootstrapRequest struct {
	SurfaceInstanceID string `json:"surface_instance_id"`
	AssetTicket       string `json:"asset_ticket"`
}

type cancelOperationRequest struct {
	Reason string `json:"reason,omitempty"`
}

type startRuntimeRequest struct {
	Target host.RuntimeTarget `json:"target,omitempty"`
}

const assetSessionCookieName = "__Host-redevplugin-asset-session"
const pluginBridgeHandshakeType = "redevplugin.bridge.handshake"

// OwnerSessionHashHeader optionally carries the host session binding used by
// the configured WebSecurity guard for CSRF validation.
const OwnerSessionHashHeader = "X-ReDevPlugin-Owner-Session-Hash"

const maxCSPReportBytes = 64 << 10
const defaultStreamReadMaxEvents = 256
const defaultStreamReadMaxBytes = 1 << 20

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.enforceWebSecurity(w, r) {
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/install":
		h.handleInstall(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/enable":
		h.handleEnable(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/disable":
		h.handleDisable(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/uninstall":
		h.handleUninstall(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/update":
		h.handleUpdate(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/downgrade":
		h.handleDowngrade(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/catalog":
		h.handleCatalog(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/platform/compatibility":
		h.handleCompatibility(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/surfaces/open":
		h.handleOpenSurface(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/bootstrap"):
		h.handleExchangeAssetTicket(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/bridge-token"):
		h.handleBridgeToken(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/rpc":
		h.handleRPC(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/confirm":
		h.handleConfirm(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/intents":
		h.handleListIntents(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/intents/invoke":
		h.handleInvokeIntent(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/operations":
		h.handleListOperations(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/operations/"):
		h.handleGetOperation(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/operations/") && strings.HasSuffix(r.URL.Path, "/cancel"):
		h.handleCancelOperation(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/runtime/start":
		h.handleStartRuntime(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/runtime/stop":
		h.handleStopRuntime(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/runtime/health":
		h.handleRuntimeHealth(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/data/export":
		h.handleExportData(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/data/import":
		h.handleImportData(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/permissions":
		h.handleListPermissions(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/permissions/grant":
		h.handleGrantPermission(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/permissions/revoke":
		h.handleRevokePermission(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/audit":
		h.handleListAudit(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/diagnostics":
		h.handleListDiagnostics(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/secrets/bind":
		h.handleBindSecret(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/secrets/test":
		h.handleTestSecret(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/secrets/delete":
		h.handleDeleteSecret(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/") && strings.HasSuffix(r.URL.Path, "/settings/schema"):
		h.handleGetSettingsSchema(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/") && strings.HasSuffix(r.URL.Path, "/settings"):
		h.handleGetSettings(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/") && strings.HasSuffix(r.URL.Path, "/settings"):
		h.handlePatchSettings(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/bootstrap":
		h.handleSandboxBootstrap(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/_redevplugin/assets/"):
		h.handlePluginAsset(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/_redevplugin/stream/"):
		h.handlePluginStream(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/csp-report":
		h.handleCSPReport(w, r)
	default:
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
	}
}

func (h Handler) enforceWebSecurity(w http.ResponseWriter, r *http.Request) bool {
	if h.WebSecurity == nil || !isPluginHTTPPath(r.URL.Path) {
		return true
	}
	if _, decision, err := h.WebSecurity.Evaluate(r); err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrPermissionDenied)})
		return false
	} else if decision != websecurity.OriginAllow {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: "request origin is not allowed", ErrorCode: string(security.ErrPermissionDenied)})
		return false
	}
	if requiresCSRF(r) {
		if err := h.WebSecurity.ValidateCSRF(r, strings.TrimSpace(r.Header.Get(OwnerSessionHashHeader))); err != nil {
			WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrPermissionDenied)})
			return false
		}
	}
	return true
}

func isPluginHTTPPath(requestPath string) bool {
	return requestPath == "/_redevplugin/api/plugins" ||
		strings.HasPrefix(requestPath, "/_redevplugin/api/plugins/") ||
		strings.HasPrefix(requestPath, "/_redevplugin/")
}

func requiresCSRF(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	return r.URL.Path == "/_redevplugin/api/plugins" || strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/")
}

func RouteSet() []Route {
	routes := []Route{
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/install"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/enable"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/disable"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/uninstall"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/update"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/downgrade"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/catalog"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/platform/compatibility"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/open"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bootstrap"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/rpc"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/confirm"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/intents"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/intents/invoke"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/operations"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/operations/{operation_id}"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/operations/{operation_id}/cancel"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/runtime/health"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/runtime/start"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/runtime/stop"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/data/export"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/data/import"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/permissions"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/permissions/grant"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/permissions/revoke"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/audit"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/diagnostics"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/secrets/bind"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/secrets/test"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/secrets/delete"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings"},
		{Method: http.MethodPatch, Path: "/_redevplugin/api/plugins/{plugin_instance_id}/settings"},
		{Method: http.MethodPost, Path: "/_redevplugin/bootstrap"},
		{Method: http.MethodGet, Path: "/_redevplugin/assets/{asset_path...}"},
		{Method: http.MethodGet, Path: "/_redevplugin/stream/{stream_id}"},
		{Method: http.MethodPost, Path: "/_redevplugin/csp-report"},
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

func (h Handler) handleInstall(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req installRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	packageBytes, err := base64.StdEncoding.DecodeString(req.PackageBase64)
	if err != nil || len(packageBytes) == 0 {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "package_base64 is invalid", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.InstallPackage(r.Context(), host.InstallRequest{
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
		TrustState:       req.TrustState,
		PluginInstanceID: req.PluginInstanceID,
	})
	if err != nil {
		WriteJSON(w, httpStatusForManagementError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForManagementError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleEnable(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req enableRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.EnablePlugin(r.Context(), host.EnableRequest{PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		WriteJSON(w, httpStatusForManagementError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForManagementError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleDisable(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req disableRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.DisablePlugin(r.Context(), host.DisableRequest{PluginInstanceID: req.PluginInstanceID, Reason: req.Reason})
	if err != nil {
		WriteJSON(w, httpStatusForManagementError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForManagementError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleUninstall(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req uninstallRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.UninstallPlugin(r.Context(), host.UninstallRequest{PluginInstanceID: req.PluginInstanceID, DeleteData: req.DeleteData})
	if err != nil {
		WriteJSON(w, httpStatusForManagementError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForManagementError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req updateRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	packageBytes, err := base64.StdEncoding.DecodeString(req.PackageBase64)
	if err != nil || len(packageBytes) == 0 {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "package_base64 is invalid", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.UpdatePlugin(r.Context(), host.UpdateRequest{
		PluginInstanceID: req.PluginInstanceID,
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
		TrustState:       req.TrustState,
	})
	if err != nil {
		WriteJSON(w, httpStatusForManagementError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForManagementError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleDowngrade(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req downgradeRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.DowngradePlugin(r.Context(), host.DowngradeRequest{
		PluginInstanceID: req.PluginInstanceID,
		Version:          req.Version,
		PackageHash:      req.PackageHash,
	})
	if err != nil {
		WriteJSON(w, httpStatusForManagementError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForManagementError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleCatalog(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	records, err := h.Host.ListPlugins(r.Context())
	if err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrPermissionDenied)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{"plugins": records}})
}

func (h Handler) handleCompatibility(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: version.CurrentCompatibilityManifest()})
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
		SandboxOrigin:        req.SandboxOrigin,
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
	if req.Handshake.Type != "" && req.Handshake.Type != pluginBridgeHandshakeType {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "handshake type is invalid", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if req.Handshake.SurfaceInstanceID != surfaceInstanceID {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "surface_instance_id mismatch", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.MintBridgeToken(r.Context(), host.MintBridgeTokenRequest{
		Handshake:       bridgeHandshake(req.Handshake),
		BridgeChannelID: req.BridgeChannelID,
	})
	if err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForBridgeError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func bridgeHandshake(handshake pluginBridgeHandshake) bridge.Handshake {
	return bridge.Handshake{
		PluginID:          handshake.PluginID,
		SurfaceID:         handshake.SurfaceID,
		SurfaceInstanceID: handshake.SurfaceInstanceID,
		ActiveFingerprint: handshake.ActiveFingerprint,
		BridgeNonce:       handshake.BridgeNonce,
		UIProtocolVersion: handshake.UIProtocolVersion,
	}
}

func (h Handler) handleRPC(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req rpcRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.CallPluginMethod(r.Context(), host.CallMethodRequest{
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: req.SessionChannelIDHash,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		BridgeChannelID:      req.BridgeChannelID,
		GatewayToken:         req.GatewayToken,
		ConfirmationToken:    req.ConfirmationToken,
		Method:               req.Method,
		Params:               req.Params,
	})
	if err != nil {
		WriteJSON(w, httpStatusForRPCError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForRPCError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req rpcRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.PrepareMethodConfirmation(r.Context(), host.ConfirmMethodRequest{
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: req.SessionChannelIDHash,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		BridgeChannelID:      req.BridgeChannelID,
		GatewayToken:         req.GatewayToken,
		Method:               req.Method,
		Params:               req.Params,
	})
	if err != nil {
		WriteJSON(w, httpStatusForRPCError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForRPCError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handleListIntents(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	records, err := h.Host.ListIntents(r.Context(), host.ListIntentsRequest{
		IntentID:         r.URL.Query().Get("intent_id"),
		PluginInstanceID: r.URL.Query().Get("plugin_instance_id"),
	})
	if err != nil {
		WriteJSON(w, httpStatusForIntentError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForIntentError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{"intents": records}})
}

func (h Handler) handleInvokeIntent(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req invokeIntentRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.InvokeIntent(r.Context(), host.InvokeIntentRequest{
		PluginInstanceID:     req.PluginInstanceID,
		IntentID:             req.IntentID,
		Params:               req.Params,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
	})
	if err != nil {
		WriteJSON(w, httpStatusForIntentError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForIntentError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handleListOperations(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	records, err := h.Host.ListOperations(r.Context(), host.ListOperationsRequest{
		PluginInstanceID: r.URL.Query().Get("plugin_instance_id"),
	})
	if err != nil {
		WriteJSON(w, httpStatusForOperationError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForOperationError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{"operations": records}})
}

func (h Handler) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	operationID, ok := operationIDFromPath(r.URL.Path, "")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.GetOperation(r.Context(), operationID)
	if err != nil {
		WriteJSON(w, httpStatusForOperationError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForOperationError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleCancelOperation(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	operationID, ok := operationIDFromPath(r.URL.Path, "/cancel")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req cancelOperationRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.CancelOperation(r.Context(), host.CancelOperationRequest{
		OperationID: operationID,
		Reason:      req.Reason,
	})
	if err != nil {
		WriteJSON(w, httpStatusForOperationError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForOperationError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleStartRuntime(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req startRuntimeRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	health, err := h.Host.StartRuntime(r.Context(), host.StartRuntimeRequest{Target: req.Target})
	if err != nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: health})
}

func (h Handler) handleStopRuntime(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	if err := h.Host.StopRuntime(r.Context()); err != nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]bool{"stopped": true}})
}

func (h Handler) handleRuntimeHealth(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	health, err := h.Host.RuntimeHealth(r.Context())
	if err != nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: health})
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
		WriteJSON(w, httpStatusForDataLifecycleError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForDataLifecycleError(err))})
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
		PluginInstanceID:   req.PluginInstanceID,
		ArchiveRef:         req.ArchiveRef,
		SettingsArchiveRef: req.SettingsArchiveRef,
		DeleteExisting:     req.DeleteExisting,
	}); err != nil {
		WriteJSON(w, httpStatusForDataLifecycleError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForDataLifecycleError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]bool{"imported": true}})
}

func (h Handler) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	records, err := h.Host.ListPermissionGrants(r.Context(), host.ListPermissionGrantsRequest{
		PluginInstanceID: r.URL.Query().Get("plugin_instance_id"),
		ActiveOnly:       boolQuery(r, "active_only"),
	})
	if err != nil {
		WriteJSON(w, httpStatusForPermissionError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForPermissionError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{"permissions": records}})
}

func (h Handler) handleGrantPermission(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req grantPermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.GrantPermission(r.Context(), host.GrantPermissionRequest{
		PluginInstanceID: req.PluginInstanceID,
		PermissionID:     req.PermissionID,
		GrantedBy:        req.GrantedBy,
		ExpiresAt:        req.ExpiresAt,
	})
	if err != nil {
		WriteJSON(w, httpStatusForPermissionError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForPermissionError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleRevokePermission(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req revokePermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.RevokePermission(r.Context(), host.RevokePermissionRequest{
		PluginInstanceID: req.PluginInstanceID,
		PermissionID:     req.PermissionID,
		RevokedBy:        req.RevokedBy,
		Reason:           req.Reason,
	})
	if err != nil {
		WriteJSON(w, httpStatusForPermissionError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForPermissionError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	events, err := h.Host.ListAuditEvents(r.Context(), host.ListAuditEventsRequest{
		PluginID:         r.URL.Query().Get("plugin_id"),
		PluginInstanceID: r.URL.Query().Get("plugin_instance_id"),
		Type:             r.URL.Query().Get("type"),
		Limit:            intQuery(r, "limit"),
	})
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{"audit_events": events}})
}

func (h Handler) handleListDiagnostics(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	events, err := h.Host.ListDiagnosticEvents(r.Context(), host.ListDiagnosticEventsRequest{
		PluginID:          r.URL.Query().Get("plugin_id"),
		PluginInstanceID:  r.URL.Query().Get("plugin_instance_id"),
		SurfaceInstanceID: r.URL.Query().Get("surface_instance_id"),
		Type:              r.URL.Query().Get("type"),
		Severity:          r.URL.Query().Get("severity"),
		Limit:             intQuery(r, "limit"),
	})
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{"diagnostic_events": events}})
}

func (h Handler) handleBindSecret(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req secretRefRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if err := h.Host.BindSecretRef(r.Context(), host.SecretBindRequest(req)); err != nil {
		WriteJSON(w, httpStatusForSecretError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForSecretError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]bool{"bound": true}})
}

func (h Handler) handleTestSecret(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req secretRefRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if err := h.Host.TestSecretRef(r.Context(), host.SecretTestRequest(req)); err != nil {
		WriteJSON(w, httpStatusForSecretError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForSecretError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]bool{"tested": true}})
}

func (h Handler) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req secretRefRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if err := h.Host.DeleteSecretRef(r.Context(), host.SecretDeleteRequest(req)); err != nil {
		WriteJSON(w, httpStatusForSecretError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForSecretError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]bool{"deleted": true}})
}

func (h Handler) handleGetSettingsSchema(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	pluginInstanceID, ok := pluginInstanceIDFromSettingsPath(r.URL.Path, "/settings/schema")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.GetSettingsSchema(r.Context(), host.GetSettingsRequest{PluginInstanceID: pluginInstanceID})
	if err != nil {
		WriteJSON(w, httpStatusForSettingsError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForSettingsError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	pluginInstanceID, ok := pluginInstanceIDFromSettingsPath(r.URL.Path, "/settings")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.GetPluginSettings(r.Context(), host.GetSettingsRequest{PluginInstanceID: pluginInstanceID})
	if err != nil {
		WriteJSON(w, httpStatusForSettingsError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForSettingsError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	pluginInstanceID, ok := pluginInstanceIDFromSettingsPath(r.URL.Path, "/settings")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req patchSettingsRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.PatchPluginSettings(r.Context(), host.PatchSettingsRequest{
		PluginInstanceID: pluginInstanceID,
		Values:           req.Values,
	})
	if err != nil {
		WriteJSON(w, httpStatusForSettingsError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForSettingsError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) handleSandboxBootstrap(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req sandboxBootstrapRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if strings.TrimSpace(req.SurfaceInstanceID) == "" || strings.TrimSpace(req.AssetTicket) == "" {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "surface_instance_id and asset_ticket are required", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	result, err := h.Host.ExchangeAssetTicket(r.Context(), host.ExchangeAssetTicketRequest{
		SurfaceInstanceID: req.SurfaceInstanceID,
		AssetTicket:       req.AssetTicket,
	})
	if err != nil {
		WriteJSON(w, httpStatusForBridgeError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForBridgeError(err))})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     assetSessionCookieName,
		Value:    result.AssetSession,
		Path:     "/",
		Expires:  result.ExpiresAt,
		MaxAge:   maxAgeSeconds(time.Until(result.ExpiresAt)),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{
		"asset_session_id": result.AssetSessionID,
		"issued_at":        result.IssuedAt,
		"expires_at":       result.ExpiresAt,
	}})
}

func (h Handler) handlePluginAsset(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	assetPath, ok := assetPathFromSandboxPath(r.URL.Path)
	if !ok {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "asset path is invalid", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	cookie, err := r.Cookie(assetSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: "asset session is required", ErrorCode: string(security.ErrPermissionDenied)})
		return
	}
	result, err := h.Host.ReadSurfaceAsset(r.Context(), host.ReadSurfaceAssetRequest{
		AssetSession: cookie.Value,
		AssetPath:    assetPath,
	})
	if err != nil {
		WriteJSON(w, httpStatusForAssetError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForAssetError(err))})
		return
	}
	contentType := result.Entry.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.Content)
}

func (h Handler) handlePluginStream(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	streamID, ok := streamIDFromPath(r.URL.Path)
	if !ok {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "stream_id is invalid", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	streamTicket := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if streamTicket == "" {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: "stream ticket is required", ErrorCode: string(security.ErrPermissionDenied)})
		return
	}
	result, err := h.Host.ReadStream(r.Context(), host.ReadStreamRequest{
		StreamID:     streamID,
		StreamTicket: streamTicket,
		MaxEvents:    defaultStreamReadMaxEvents,
		MaxBytes:     defaultStreamReadMaxBytes,
	})
	if err != nil {
		WriteJSON(w, httpStatusForStreamError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForStreamError(err))})
		return
	}
	contentType := result.Record.ContentType
	if contentType == "" {
		contentType = "application/x-ndjson"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	for _, event := range result.Events {
		if err := encoder.Encode(event); err != nil {
			return
		}
	}
}

func (h Handler) handleCSPReport(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCSPReportBytes+1))
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if len(raw) > maxCSPReportBytes {
		WriteJSON(w, http.StatusRequestEntityTooLarge, Envelope{OK: false, Error: "csp report is too large", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	report, err := parseCSPReport(raw)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if err := h.Host.ReportCSPViolation(r.Context(), report); err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrPermissionDenied)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]bool{"reported": true}})
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
	const prefix = "/_redevplugin/api/plugins/surfaces/"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	id = strings.Trim(id, "/")
	return id, id != ""
}

func operationIDFromPath(path string, suffix string) (string, bool) {
	const prefix = "/_redevplugin/api/plugins/operations/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	operationID := strings.TrimPrefix(path, prefix)
	if suffix != "" {
		if !strings.HasSuffix(operationID, suffix) {
			return "", false
		}
		operationID = strings.TrimSuffix(operationID, suffix)
	}
	operationID = strings.Trim(operationID, "/")
	if operationID == "" || strings.Contains(operationID, "/") {
		return "", false
	}
	return operationID, true
}

func pluginInstanceIDFromSettingsPath(requestPath string, suffix string) (string, bool) {
	const prefix = "/_redevplugin/api/plugins/"
	if !strings.HasPrefix(requestPath, prefix) || !strings.HasSuffix(requestPath, suffix) {
		return "", false
	}
	pluginInstanceID := strings.TrimSuffix(strings.TrimPrefix(requestPath, prefix), suffix)
	pluginInstanceID = strings.Trim(pluginInstanceID, "/")
	if pluginInstanceID == "" || strings.Contains(pluginInstanceID, "/") || strings.HasPrefix(pluginInstanceID, ".") {
		return "", false
	}
	return pluginInstanceID, true
}

func assetPathFromSandboxPath(requestPath string) (string, bool) {
	const prefix = "/_redevplugin/assets/"
	if !strings.HasPrefix(requestPath, prefix) {
		return "", false
	}
	assetPath := strings.TrimPrefix(requestPath, prefix)
	if assetPath == "" {
		return "", false
	}
	clean := path.Clean(assetPath)
	if clean != assetPath || clean == "." || strings.HasPrefix(assetPath, "../") || strings.Contains(assetPath, "/../") || strings.HasPrefix(assetPath, ".") || strings.Contains(assetPath, "/.") {
		return "", false
	}
	if !strings.HasPrefix(assetPath, "ui/") {
		return "", false
	}
	return assetPath, true
}

func streamIDFromPath(requestPath string) (string, bool) {
	const prefix = "/_redevplugin/stream/"
	if !strings.HasPrefix(requestPath, prefix) {
		return "", false
	}
	streamID := strings.Trim(strings.TrimPrefix(requestPath, prefix), "/")
	if streamID == "" || strings.Contains(streamID, "/") || strings.HasPrefix(streamID, ".") {
		return "", false
	}
	return streamID, true
}

func boolQuery(r *http.Request, key string) bool {
	value := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key)))
	return value == "1" || value == "true" || value == "yes"
}

func intQuery(r *http.Request, key string) int {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return 0
	}
	var parsed int
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0
		}
		parsed = parsed*10 + int(ch-'0')
	}
	return parsed
}

func maxAgeSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d.Seconds())
}

func parseCSPReport(raw []byte) (host.CSPViolationReport, error) {
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return host.CSPViolationReport{}, err
	}
	body := envelope
	if cspReport, ok := envelope["csp-report"].(map[string]any); ok {
		body = cspReport
	} else if reportBody, ok := envelope["body"].(map[string]any); ok {
		body = reportBody
	}
	report := host.CSPViolationReport{
		PluginID:           stringFromAny(envelope["plugin_id"]),
		PluginInstanceID:   stringFromAny(envelope["plugin_instance_id"]),
		SurfaceID:          stringFromAny(envelope["surface_id"]),
		SurfaceInstanceID:  stringFromAny(envelope["surface_instance_id"]),
		ActiveFingerprint:  stringFromAny(envelope["active_fingerprint"]),
		BlockedURI:         stringFromAny(firstAny(body, "blocked-uri", "blockedURL", "blocked_uri")),
		DocumentURI:        stringFromAny(firstAny(body, "document-uri", "documentURL", "document_uri")),
		EffectiveDirective: stringFromAny(firstAny(body, "effective-directive", "effectiveDirective", "effective_directive")),
		ViolatedDirective:  stringFromAny(firstAny(body, "violated-directive", "violatedDirective", "violated_directive")),
		OriginalPolicy:     stringFromAny(firstAny(body, "original-policy", "originalPolicy", "original_policy")),
		Disposition:        stringFromAny(body["disposition"]),
		LineNumber:         intFromAny(firstAny(body, "line-number", "lineNumber", "line_number")),
		ColumnNumber:       intFromAny(firstAny(body, "column-number", "columnNumber", "column_number")),
		SourceFile:         stringFromAny(firstAny(body, "source-file", "sourceFile", "source_file")),
		Sample:             stringFromAny(firstAny(body, "sample", "script-sample", "scriptSample", "script_sample")),
		Raw:                body,
	}
	if report.PluginID == "" {
		report.PluginID = stringFromAny(body["plugin_id"])
	}
	if report.PluginInstanceID == "" {
		report.PluginInstanceID = stringFromAny(body["plugin_instance_id"])
	}
	if report.SurfaceID == "" {
		report.SurfaceID = stringFromAny(body["surface_id"])
	}
	if report.SurfaceInstanceID == "" {
		report.SurfaceInstanceID = stringFromAny(body["surface_instance_id"])
	}
	if report.ActiveFingerprint == "" {
		report.ActiveFingerprint = stringFromAny(body["active_fingerprint"])
	}
	return report, nil
}

func firstAny(values map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value
		}
	}
	return nil
}

func stringFromAny(value any) string {
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	}
	return 0
}

func errorCodeForBridgeError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, bridge.ErrTokenExpired):
		return security.ErrTokenExpired
	case errors.Is(err, bridge.ErrTokenReplay):
		return security.ErrTokenReplay
	case errors.Is(err, bridge.ErrTokenAlreadyBound):
		return security.ErrGatewayTokenChannelMismatch
	case errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenAudience), errors.Is(err, bridge.ErrTokenRevoked), errors.Is(err, bridge.ErrTokenKind), errors.Is(err, bridge.ErrSurfaceSessionNotFound), errors.Is(err, bridge.ErrSurfaceSessionExpired), errors.Is(err, bridge.ErrAssetSessionRequired):
		return security.ErrPermissionDenied
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForBridgeError(err error) int {
	switch {
	case errors.Is(err, bridge.ErrTokenExpired), errors.Is(err, bridge.ErrTokenReplay), errors.Is(err, bridge.ErrTokenAlreadyBound), errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenAudience), errors.Is(err, bridge.ErrTokenRevoked), errors.Is(err, bridge.ErrTokenKind), errors.Is(err, bridge.ErrSurfaceSessionNotFound), errors.Is(err, bridge.ErrSurfaceSessionExpired), errors.Is(err, bridge.ErrAssetSessionRequired):
		return http.StatusForbidden
	default:
		return http.StatusForbidden
	}
}

func errorCodeForRPCError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrConfirmationRequired):
		return security.ErrConfirmationRequired
	case errors.Is(err, permissions.ErrPermissionDenied):
		return security.ErrPermissionDenied
	case errors.Is(err, bridge.ErrTokenExpired):
		return security.ErrTokenExpired
	case errors.Is(err, bridge.ErrTokenReplay):
		return security.ErrTokenReplay
	case errors.Is(err, bridge.ErrTokenAlreadyBound):
		return security.ErrGatewayTokenChannelMismatch
	case errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenAudience), errors.Is(err, bridge.ErrTokenRevoked), errors.Is(err, bridge.ErrTokenKind):
		return security.ErrPermissionDenied
	case errors.Is(err, runtimeclient.ErrRuntimeNotReady), errors.Is(err, runtimeclient.ErrRuntimeIPCUnavailable), errors.Is(err, runtimeclient.ErrRuntimeRequestFailed), errors.Is(err, runtimeclient.ErrRuntimeHandshake):
		return security.ErrRuntimeUnavailable
	default:
		return security.ErrPermissionDenied
	}
}

func errorCodeForManagementError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound):
		return security.ErrInvalidRequest
	case errors.Is(err, host.ErrPackageTrustVerificationInvalid):
		return security.ErrTrustVerificationInvalid
	case errors.Is(err, host.ErrPackageTrustVerifierRequired):
		return security.ErrTrustVerificationRequired
	case errors.Is(err, storage.ErrQuotaExceeded):
		return security.ErrStorageQuotaExceeded
	case errors.Is(err, operation.ErrDeleteBlocked):
		return security.ErrOperationBlocked
	case errors.Is(err, connectivity.ErrInvalidConnector), errors.Is(err, connectivity.ErrTargetDenied), errors.Is(err, connectivity.ErrConnectorDenied):
		return security.ErrNetworkTargetDenied
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForManagementError(err error) int {
	switch {
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound):
		return http.StatusBadRequest
	case errors.Is(err, host.ErrPackageTrustVerificationInvalid):
		return http.StatusBadRequest
	case errors.Is(err, host.ErrPackageTrustVerifierRequired):
		return http.StatusForbidden
	case errors.Is(err, storage.ErrQuotaExceeded):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, operation.ErrDeleteBlocked):
		return http.StatusConflict
	case errors.Is(err, connectivity.ErrInvalidConnector), errors.Is(err, connectivity.ErrTargetDenied), errors.Is(err, connectivity.ErrConnectorDenied):
		return http.StatusForbidden
	default:
		return http.StatusForbidden
	}
}

func errorCodeForOperationError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, operation.ErrNotFound), errors.Is(err, operation.ErrInvalidOperation):
		return security.ErrInvalidRequest
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForOperationError(err error) int {
	switch {
	case errors.Is(err, operation.ErrNotFound), errors.Is(err, operation.ErrInvalidOperation):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}

func errorCodeForStreamError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, stream.ErrNotFound), errors.Is(err, stream.ErrInvalidStream):
		return security.ErrInvalidRequest
	case errors.Is(err, stream.ErrBackpressure):
		return security.ErrOperationBlocked
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForStreamError(err error) int {
	switch {
	case errors.Is(err, stream.ErrNotFound), errors.Is(err, stream.ErrInvalidStream):
		return http.StatusBadRequest
	case errors.Is(err, stream.ErrBackpressure):
		return http.StatusTooManyRequests
	default:
		return http.StatusForbidden
	}
}

func httpStatusForRPCError(err error) int {
	switch {
	case errors.Is(err, host.ErrConfirmationRequired):
		return http.StatusConflict
	case errors.Is(err, permissions.ErrPermissionDenied):
		return http.StatusForbidden
	case errors.Is(err, bridge.ErrTokenExpired), errors.Is(err, bridge.ErrTokenReplay), errors.Is(err, bridge.ErrTokenAlreadyBound), errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenAudience), errors.Is(err, bridge.ErrTokenRevoked), errors.Is(err, bridge.ErrTokenKind):
		return http.StatusForbidden
	case errors.Is(err, runtimeclient.ErrRuntimeNotReady), errors.Is(err, runtimeclient.ErrRuntimeIPCUnavailable), errors.Is(err, runtimeclient.ErrRuntimeRequestFailed), errors.Is(err, runtimeclient.ErrRuntimeHandshake):
		return http.StatusServiceUnavailable
	default:
		return http.StatusForbidden
	}
}

func errorCodeForIntentError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrConfirmationRequired):
		return security.ErrConfirmationRequired
	case errors.Is(err, permissions.ErrPermissionDenied):
		return security.ErrPermissionDenied
	case errors.Is(err, registry.ErrNotFound):
		return security.ErrInvalidRequest
	case errors.Is(err, runtimeclient.ErrRuntimeNotReady), errors.Is(err, runtimeclient.ErrRuntimeIPCUnavailable), errors.Is(err, runtimeclient.ErrRuntimeRequestFailed), errors.Is(err, runtimeclient.ErrRuntimeHandshake):
		return security.ErrRuntimeUnavailable
	default:
		return security.ErrInvalidRequest
	}
}

func httpStatusForIntentError(err error) int {
	switch {
	case errors.Is(err, host.ErrConfirmationRequired):
		return http.StatusConflict
	case errors.Is(err, permissions.ErrPermissionDenied):
		return http.StatusForbidden
	case errors.Is(err, registry.ErrNotFound):
		return http.StatusBadRequest
	case errors.Is(err, runtimeclient.ErrRuntimeNotReady), errors.Is(err, runtimeclient.ErrRuntimeIPCUnavailable), errors.Is(err, runtimeclient.ErrRuntimeRequestFailed), errors.Is(err, runtimeclient.ErrRuntimeHandshake):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
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

func errorCodeForDataLifecycleError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, storage.ErrQuotaExceeded):
		return security.ErrStorageQuotaExceeded
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, host.ErrPluginDataArchiveRequired), errors.Is(err, host.ErrPluginDataNotDeclared), errors.Is(err, host.ErrPluginSettingsNotDeclared), errors.Is(err, host.ErrPluginStorageNotDeclared), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound), errors.Is(err, settings.ErrArchiveNotFound), errors.Is(err, settings.ErrNotDeclared), errors.Is(err, settings.ErrInvalidSetting):
		return security.ErrInvalidRequest
	default:
		return security.ErrPermissionDenied
	}
}

func errorCodeForSecretError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrInvalidSecretRef), errors.Is(err, registry.ErrNotFound):
		return security.ErrInvalidRequest
	case errors.Is(err, host.ErrSecretStoreRequired):
		return security.ErrRuntimeUnavailable
	default:
		return security.ErrPermissionDenied
	}
}

func errorCodeForSettingsError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, settings.ErrNotDeclared), errors.Is(err, settings.ErrInvalidSetting):
		return security.ErrInvalidRequest
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForSettingsError(err error) int {
	switch {
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, settings.ErrNotDeclared), errors.Is(err, settings.ErrInvalidSetting):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}

func httpStatusForSecretError(err error) int {
	switch {
	case errors.Is(err, host.ErrInvalidSecretRef), errors.Is(err, registry.ErrNotFound):
		return http.StatusBadRequest
	case errors.Is(err, host.ErrSecretStoreRequired):
		return http.StatusServiceUnavailable
	default:
		return http.StatusForbidden
	}
}

func errorCodeForAssetError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, bridge.ErrTokenExpired):
		return security.ErrTokenExpired
	case errors.Is(err, bridge.ErrTokenReplay):
		return security.ErrTokenReplay
	case errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenAudience), errors.Is(err, bridge.ErrTokenRevoked), errors.Is(err, bridge.ErrTokenKind), errors.Is(err, bridge.ErrSurfaceSessionNotFound), errors.Is(err, bridge.ErrSurfaceSessionExpired), errors.Is(err, bridge.ErrAssetSessionRequired):
		return security.ErrPermissionDenied
	case errors.Is(err, registry.ErrNotFound):
		return security.ErrInvalidRequest
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForAssetError(err error) int {
	switch {
	case errors.Is(err, bridge.ErrTokenExpired), errors.Is(err, bridge.ErrTokenReplay), errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenAudience), errors.Is(err, bridge.ErrTokenRevoked), errors.Is(err, bridge.ErrTokenKind), errors.Is(err, bridge.ErrSurfaceSessionNotFound), errors.Is(err, bridge.ErrSurfaceSessionExpired), errors.Is(err, bridge.ErrAssetSessionRequired):
		return http.StatusForbidden
	case errors.Is(err, registry.ErrNotFound):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}

func errorCodeForPermissionError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, permissions.ErrInvalidPermission), errors.Is(err, permissions.ErrGrantNotFound):
		return security.ErrInvalidRequest
	case errors.Is(err, permissions.ErrPermissionDenied):
		return security.ErrPermissionDenied
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForPermissionError(err error) int {
	switch {
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, permissions.ErrInvalidPermission), errors.Is(err, permissions.ErrGrantNotFound):
		return http.StatusBadRequest
	case errors.Is(err, permissions.ErrPermissionDenied):
		return http.StatusForbidden
	default:
		return http.StatusForbidden
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

func httpStatusForDataLifecycleError(err error) int {
	switch {
	case errors.Is(err, storage.ErrQuotaExceeded):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, host.ErrPluginDataArchiveRequired), errors.Is(err, host.ErrPluginDataNotDeclared), errors.Is(err, host.ErrPluginSettingsNotDeclared), errors.Is(err, host.ErrPluginStorageNotDeclared), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound), errors.Is(err, settings.ErrArchiveNotFound), errors.Is(err, settings.ErrNotDeclared), errors.Is(err, settings.ErrInvalidSetting):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}
