package httpadapter

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/retaineddata"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

type Envelope struct {
	OK           bool           `json:"ok"`
	Data         any            `json:"data,omitempty"`
	Error        string         `json:"error,omitempty"`
	ErrorCode    string         `json:"error_code,omitempty"`
	ErrorDetails map[string]any `json:"error_details,omitempty"`
}

type Route struct {
	Method string
	Path   string
}

type RouteSetOptions struct {
	EnableLocalImportRoutes bool
}

type Handler struct {
	Host                    *host.Host
	WebSecurity             websecurity.Guard
	EnableLocalImportRoutes bool
}

type importLocalPackageRequest struct {
	PackageBase64      string  `json:"package_base64"`
	PluginInstanceID   string  `json:"plugin_instance_id,omitempty"`
	PluginStateVersion *uint64 `json:"plugin_state_version"`
}

type installReleaseRefRequest struct {
	ReleaseRef         host.PluginReleaseRef `json:"release_ref"`
	PluginInstanceID   string                `json:"plugin_instance_id,omitempty"`
	PluginStateVersion *uint64               `json:"plugin_state_version"`
}

type updateLocalPackageRequest struct {
	PluginInstanceID   string  `json:"plugin_instance_id"`
	PackageBase64      string  `json:"package_base64"`
	PluginStateVersion *uint64 `json:"plugin_state_version"`
}

type updateReleaseRefRequest struct {
	PluginInstanceID   string                `json:"plugin_instance_id"`
	ReleaseRef         host.PluginReleaseRef `json:"release_ref"`
	PluginStateVersion *uint64               `json:"plugin_state_version"`
}

type downgradeRequest struct {
	PluginInstanceID   string  `json:"plugin_instance_id"`
	Version            string  `json:"version,omitempty"`
	PackageHash        string  `json:"package_hash,omitempty"`
	PluginStateVersion *uint64 `json:"plugin_state_version"`
}

type enableRequest struct {
	PluginInstanceID   string  `json:"plugin_instance_id"`
	PluginStateVersion *uint64 `json:"plugin_state_version"`
}

type disableRequest struct {
	PluginInstanceID   string  `json:"plugin_instance_id"`
	Reason             string  `json:"reason,omitempty"`
	PluginStateVersion *uint64 `json:"plugin_state_version"`
}

type uninstallRequest struct {
	PluginInstanceID   string  `json:"plugin_instance_id"`
	DeleteData         bool    `json:"delete_data"`
	PluginStateVersion *uint64 `json:"plugin_state_version"`
}

type deleteRetainedDataRequest struct {
	RetainedID string `json:"retained_id"`
}

type bindRetainedDataRequest struct {
	RetainedID             string `json:"retained_id"`
	TargetPluginInstanceID string `json:"target_plugin_instance_id"`
}

type cleanupExpiredRetainedDataRequest struct {
	RetryFailed bool `json:"retry_failed,omitempty"`
	MaxRecords  *int `json:"max_records,omitempty"`
}

type openSurfaceRequest struct {
	PluginInstanceID   string  `json:"plugin_instance_id"`
	SurfaceID          string  `json:"surface_id"`
	SurfaceInstanceID  string  `json:"surface_instance_id,omitempty"`
	PluginStateVersion *uint64 `json:"plugin_state_version"`
}

type surfaceBootstrapResponse struct {
	PluginID            string    `json:"plugin_id"`
	PluginInstanceID    string    `json:"plugin_instance_id"`
	PluginVersion       string    `json:"plugin_version"`
	SurfaceID           string    `json:"surface_id"`
	SurfaceInstanceID   string    `json:"surface_instance_id"`
	ActiveFingerprint   string    `json:"active_fingerprint"`
	EntryPath           string    `json:"entry_path"`
	EntrySHA256         string    `json:"entry_sha256"`
	AssetSessionNonce   string    `json:"asset_session_nonce"`
	PluginStateVersion  uint64    `json:"plugin_state_version"`
	RevokeEpoch         uint64    `json:"revoke_epoch"`
	RuntimeGenerationID string    `json:"runtime_generation_id"`
	AssetTicket         string    `json:"asset_ticket"`
	AssetTicketID       string    `json:"asset_ticket_id"`
	BridgeNonce         string    `json:"bridge_nonce"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

func publicSurfaceBootstrap(bootstrap bridge.SurfaceBootstrap) surfaceBootstrapResponse {
	return surfaceBootstrapResponse{
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
		IssuedAt:            bootstrap.IssuedAt,
		ExpiresAt:           bootstrap.ExpiresAt,
	}
}

type prepareSurfaceRequest struct {
	AssetTicket string `json:"asset_ticket"`
}

type readSurfaceAssetRequest struct {
	AssetSession   string `json:"asset_session"`
	AssetSessionID string `json:"asset_session_id"`
	BindingID      string `json:"binding_id"`
}

type readSurfaceStreamRequest struct {
	StreamID     string `json:"stream_id"`
	StreamTicket string `json:"stream_ticket"`
}

type cancelSurfaceOperationRequest struct {
	OperationID     string `json:"operation_id"`
	BridgeChannelID string `json:"bridge_channel_id"`
	Reason          string `json:"reason,omitempty"`
}

type rejectSurfaceConfirmationRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	BridgeChannelID  string `json:"bridge_channel_id"`
	GatewayToken     string `json:"plugin_gateway_token"`
	ConfirmationID   string `json:"confirmation_id"`
}

type disposeSurfaceRequest struct {
	BridgeNonce string `json:"bridge_nonce"`
}

type revokeSurfaceScopeRequest struct{}

type bridgeTokenRequest struct {
	Handshake                 pluginBridgeHandshake `json:"handshake"`
	BridgeChannelID           string                `json:"bridge_channel_id"`
	HandshakeTranscriptSHA256 string                `json:"handshake_transcript_sha256"`
	PreviousGatewayToken      string                `json:"previous_plugin_gateway_token,omitempty"`
}

type pluginBridgeHandshake struct {
	Type               string `json:"type"`
	PluginID           string `json:"plugin_id"`
	SurfaceID          string `json:"surface_id"`
	SurfaceInstanceID  string `json:"surface_instance_id"`
	ActiveFingerprint  string `json:"active_fingerprint"`
	BridgeNonce        string `json:"bridge_nonce"`
	AssetSessionNonce  string `json:"asset_session_nonce"`
	PluginStateVersion uint64 `json:"plugin_state_version"`
	RevokeEpoch        uint64 `json:"revoke_epoch"`
	UIProtocolVersion  string `json:"ui_protocol_version"`
}

type rpcRequest struct {
	PluginInstanceID  string         `json:"plugin_instance_id"`
	SurfaceInstanceID string         `json:"surface_instance_id"`
	BridgeChannelID   string         `json:"bridge_channel_id"`
	GatewayToken      string         `json:"plugin_gateway_token"`
	ConfirmationID    string         `json:"confirmation_id,omitempty"`
	Method            string         `json:"method"`
	Params            map[string]any `json:"params,omitempty"`
}

type invokeIntentRequest struct {
	PluginInstanceID string         `json:"plugin_instance_id,omitempty"`
	IntentID         string         `json:"intent_id"`
	Params           map[string]any `json:"params,omitempty"`
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

type cancelOperationRequest struct {
	Reason string `json:"reason,omitempty"`
}

type startRuntimeRequest struct {
	Target host.RuntimeTarget `json:"target,omitempty"`
}

const pluginBridgeHandshakeType = "redevplugin.bridge.handshake"
const defaultStreamReadMaxEvents = 256
const defaultStreamReadMaxBytes = 1 << 20
const defaultStreamReadWaitTimeout = 20 * time.Second
const defaultJSONRequestMaxBytes = 1 << 20
const defaultJSONMaxDepth = 64
const maxJSONSafeInteger int64 = 1<<53 - 1
const jsonNumberPrecisionBits uint = 256

var maxJSONSafeFloat = new(big.Float).SetPrec(jsonNumberPrecisionBits).SetInt64(maxJSONSafeInteger)

type jsonLimitReason string

const (
	jsonLimitReasonPayloadBytes    jsonLimitReason = "payload_bytes"
	jsonLimitReasonDepth           jsonLimitReason = "json_depth"
	jsonLimitReasonPrototypeKey    jsonLimitReason = "prototype_key"
	jsonLimitReasonNumberPrecision jsonLimitReason = "number_precision"
)

type jsonLimitError struct {
	reason jsonLimitReason
}

func (e *jsonLimitError) Error() string {
	switch e.reason {
	case jsonLimitReasonPayloadBytes:
		return "JSON payload exceeds the maximum allowed size"
	case jsonLimitReasonDepth:
		return "JSON payload exceeds the maximum allowed depth"
	case jsonLimitReasonPrototypeKey:
		return "JSON payload contains a forbidden prototype pollution key"
	case jsonLimitReasonNumberPrecision:
		return "JSON payload contains an unsafe number"
	default:
		return "JSON payload exceeds platform limits"
	}
}

func (e *jsonLimitError) status() int {
	if e.reason == jsonLimitReasonPayloadBytes {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestContext, ok := h.enforceWebSecurity(w, r)
	if !ok {
		return
	}
	if isPluginHTTPPath(r.URL.Path) {
		r = r.WithContext(websecurity.WithRequestContext(r.Context(), requestContext))
	}
	switch {
	case h.EnableLocalImportRoutes && r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/local-import/install":
		h.handleImportLocalPackage(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/install-release-ref":
		h.handleInstallReleaseRef(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/enable":
		h.handleEnable(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/disable":
		h.handleDisable(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/uninstall":
		h.handleUninstall(w, r)
	case h.EnableLocalImportRoutes && r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/local-import/update":
		h.handleUpdateLocalPackage(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/update-release-ref":
		h.handleUpdateReleaseRef(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/downgrade":
		h.handleDowngrade(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/catalog":
		h.handleCatalog(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/platform/compatibility":
		h.handleCompatibility(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/surfaces/open":
		h.handleOpenSurface(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/surfaces/revoke-scope":
		h.handleRevokeSurfaceScope(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/prepare"):
		h.handlePrepareSurface(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/bridge-token"):
		h.handleBridgeToken(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/assets/read"):
		h.handleReadSurfaceAsset(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/streams/read"):
		h.handleReadSurfaceStream(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/operations/cancel"):
		h.handleCancelSurfaceOperation(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/confirmations/reject"):
		h.handleRejectSurfaceConfirmation(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_redevplugin/api/plugins/surfaces/") && strings.HasSuffix(r.URL.Path, "/dispose"):
		h.handleDisposeSurface(w, r)
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
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/runtime/refresh-enabled":
		h.handleRefreshEnabledRuntimeState(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/runtime/health":
		h.handleRuntimeHealth(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/data/export":
		h.handleExportData(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/data/import":
		h.handleImportData(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_redevplugin/api/plugins/retained-data":
		h.handleListRetainedData(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/retained-data/delete":
		h.handleDeleteRetainedData(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/retained-data/bind":
		h.handleBindRetainedData(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/_redevplugin/api/plugins/retained-data/cleanup-expired":
		h.handleCleanupExpiredRetainedData(w, r)
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
	default:
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
	}
}

func (h Handler) handleCancelSurfaceOperation(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/operations/cancel")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req cancelSurfaceOperationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	record, err := h.Host.CancelSurfaceOperation(r.Context(), host.CancelSurfaceOperationRequest{
		OperationID: req.OperationID, SurfaceInstanceID: surfaceInstanceID,
		OwnerSessionHash: scope.OwnerSessionHash, OwnerUserHash: scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash, BridgeChannelID: req.BridgeChannelID,
		Reason: req.Reason,
	})
	if err != nil {
		WriteJSON(w, httpStatusForOperationError(err), Envelope{OK: false, Error: publicPluginErrorMessage(errorCodeForOperationError(err)), ErrorCode: string(errorCodeForOperationError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleRejectSurfaceConfirmation(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/confirmations/reject")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req rejectSurfaceConfirmationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	result, err := h.Host.RejectMethodConfirmation(r.Context(), host.RejectMethodConfirmationRequest{
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceInstanceID:    surfaceInstanceID,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		GatewayToken:         req.GatewayToken,
		ConfirmationID:       req.ConfirmationID,
	})
	if err != nil {
		code := errorCodeForRPCError(err)
		WriteJSON(w, httpStatusForRPCError(err), Envelope{OK: false, Error: publicPluginErrorMessage(code), ErrorCode: string(code)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func (h Handler) enforceWebSecurity(w http.ResponseWriter, r *http.Request) (websecurity.RequestContext, bool) {
	if !isPluginHTTPPath(r.URL.Path) {
		return websecurity.RequestContext{}, true
	}
	if h.WebSecurity == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "web security guard is required", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return websecurity.RequestContext{}, false
	}
	requestContext, decision, err := h.WebSecurity.Evaluate(r)
	if err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrPermissionDenied)})
		return websecurity.RequestContext{}, false
	}
	if decision != websecurity.OriginTrustedParent {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: "request origin is not allowed", ErrorCode: string(security.ErrPermissionDenied)})
		return websecurity.RequestContext{}, false
	}
	if !requestContext.Scope.Valid() {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: websecurity.ErrScopeRequired.Error(), ErrorCode: string(security.ErrPermissionDenied)})
		return websecurity.RequestContext{}, false
	}
	if requiresCSRF(r) {
		if err := h.WebSecurity.ValidateCSRF(r, requestContext.Scope.OwnerSessionHash); err != nil {
			errorCode := security.ErrPermissionDenied
			if errors.Is(err, websecurity.ErrCSRFRequired) || errors.Is(err, websecurity.ErrCSRFInvalid) {
				errorCode = security.ErrCSRFRequired
			}
			WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCode)})
			return websecurity.RequestContext{}, false
		}
	}
	return requestContext, true
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
	return isPluginHTTPPath(r.URL.Path)
}

func trustedRequestScope(r *http.Request) websecurity.RequestScope {
	requestContext, ok := websecurity.RequestContextFromContext(r.Context())
	if !ok {
		return websecurity.RequestScope{}
	}
	return requestContext.Scope
}

func RouteSet() []Route {
	return RouteSetWithOptions(RouteSetOptions{})
}

func RouteSetWithOptions(options RouteSetOptions) []Route {
	routes := []Route{
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/install-release-ref"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/enable"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/disable"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/uninstall"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/update-release-ref"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/downgrade"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/catalog"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/platform/compatibility"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/open"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/revoke-scope"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/prepare"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/assets/read"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/read"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/operations/cancel"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/confirmations/reject"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/dispose"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/rpc"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/confirm"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/intents"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/intents/invoke"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/operations"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/operations/{operation_id}"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/operations/{operation_id}/cancel"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/runtime/health"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/runtime/refresh-enabled"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/runtime/start"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/runtime/stop"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/data/export"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/data/import"},
		{Method: http.MethodGet, Path: "/_redevplugin/api/plugins/retained-data"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/retained-data/delete"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/retained-data/bind"},
		{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/retained-data/cleanup-expired"},
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
	}
	if options.EnableLocalImportRoutes {
		routes = append(routes,
			Route{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/local-import/install"},
			Route{Method: http.MethodPost, Path: "/_redevplugin/api/plugins/local-import/update"},
		)
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
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope)
}

func writeInvalidRequestError(w http.ResponseWriter, err error) {
	var limitErr *jsonLimitError
	if errors.As(err, &limitErr) {
		WriteJSON(w, limitErr.status(), Envelope{
			OK:           false,
			Error:        limitErr.Error(),
			ErrorCode:    string(security.ErrJSONLimitExceeded),
			ErrorDetails: map[string]any{"reason": string(limitErr.reason)},
		})
		return
	}
	WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrInvalidRequest)})
}

func writeManagementError(w http.ResponseWriter, err error) {
	WriteJSON(w, httpStatusForManagementError(err), Envelope{
		OK:           false,
		Error:        err.Error(),
		ErrorCode:    string(errorCodeForManagementError(err)),
		ErrorDetails: errorDetailsForManagementError(err),
	})
}

func requirePluginStateVersion(w http.ResponseWriter, value *uint64, install bool) (uint64, bool) {
	if value == nil || (install && *value != 0) || (!install && *value == 0) {
		expected := "a positive integer"
		if install {
			expected = "0"
		}
		WriteJSON(w, http.StatusBadRequest, Envelope{
			OK:        false,
			Error:     "plugin_state_version must be " + expected,
			ErrorCode: string(security.ErrInvalidRequest),
		})
		return 0, false
	}
	return *value, true
}

func (h Handler) handleImportLocalPackage(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req importLocalPackageRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, true)
	if !ok {
		return
	}
	packageBytes, err := base64.StdEncoding.DecodeString(req.PackageBase64)
	if err != nil || len(packageBytes) == 0 {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "package_base64 is invalid", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.ImportLocalPackage(r.Context(), host.ImportLocalPackageRequest{
		PackageReader:      bytes.NewReader(packageBytes),
		PackageSize:        int64(len(packageBytes)),
		PluginInstanceID:   req.PluginInstanceID,
		PluginStateVersion: pluginStateVersion,
	})
	if err != nil {
		writeManagementError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleInstallReleaseRef(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req installReleaseRefRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, true)
	if !ok {
		return
	}
	record, err := h.Host.InstallReleaseRef(r.Context(), host.InstallReleaseRefRequest{
		ReleaseRef:         req.ReleaseRef,
		PluginInstanceID:   req.PluginInstanceID,
		PluginStateVersion: pluginStateVersion,
	})
	if err != nil {
		writeManagementError(w, err)
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
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, false)
	if !ok {
		return
	}
	record, err := h.Host.EnablePlugin(r.Context(), host.EnableRequest{PluginInstanceID: req.PluginInstanceID, PluginStateVersion: pluginStateVersion})
	if err != nil {
		writeManagementError(w, err)
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
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, false)
	if !ok {
		return
	}
	record, err := h.Host.DisablePlugin(r.Context(), host.DisableRequest{PluginInstanceID: req.PluginInstanceID, PluginStateVersion: pluginStateVersion, Reason: req.Reason})
	if err != nil {
		writeManagementError(w, err)
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
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, false)
	if !ok {
		return
	}
	record, err := h.Host.UninstallPlugin(r.Context(), host.UninstallRequest{PluginInstanceID: req.PluginInstanceID, PluginStateVersion: pluginStateVersion, DeleteData: req.DeleteData})
	if err != nil {
		writeManagementError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleUpdateLocalPackage(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req updateLocalPackageRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, false)
	if !ok {
		return
	}
	packageBytes, err := base64.StdEncoding.DecodeString(req.PackageBase64)
	if err != nil || len(packageBytes) == 0 {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "package_base64 is invalid", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	record, err := h.Host.UpdateLocalPackage(r.Context(), host.UpdateLocalPackageRequest{
		PluginInstanceID:   req.PluginInstanceID,
		PluginStateVersion: pluginStateVersion,
		PackageReader:      bytes.NewReader(packageBytes),
		PackageSize:        int64(len(packageBytes)),
	})
	if err != nil {
		writeManagementError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleUpdateReleaseRef(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req updateReleaseRefRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, false)
	if !ok {
		return
	}
	record, err := h.Host.UpdateReleaseRef(r.Context(), host.UpdateReleaseRefRequest{
		PluginInstanceID:   req.PluginInstanceID,
		PluginStateVersion: pluginStateVersion,
		ReleaseRef:         req.ReleaseRef,
	})
	if err != nil {
		writeManagementError(w, err)
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
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, false)
	if !ok {
		return
	}
	record, err := h.Host.DowngradePlugin(r.Context(), host.DowngradeRequest{
		PluginInstanceID:   req.PluginInstanceID,
		PluginStateVersion: pluginStateVersion,
		Version:            req.Version,
		PackageHash:        req.PackageHash,
	})
	if err != nil {
		writeManagementError(w, err)
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
		writeInvalidRequestError(w, err)
		return
	}
	pluginStateVersion, ok := requirePluginStateVersion(w, req.PluginStateVersion, false)
	if !ok {
		return
	}
	scope := trustedRequestScope(r)
	bootstrap, err := h.Host.OpenSurface(r.Context(), host.OpenSurfaceRequest{
		PluginInstanceID:     req.PluginInstanceID,
		PluginStateVersion:   pluginStateVersion,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
	})
	if err != nil {
		WriteJSON(w, httpStatusForOpenSurfaceError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForOpenSurfaceError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: publicSurfaceBootstrap(bootstrap)})
}

func (h Handler) handlePrepareSurface(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/prepare")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req prepareSurfaceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	result, err := h.Host.PrepareSurface(r.Context(), host.ExchangeAssetTicketRequest{
		SurfaceInstanceID:    surfaceInstanceID,
		AssetTicket:          req.AssetTicket,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
	})
	if err != nil {
		WriteJSON(w, httpStatusForAssetError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForAssetError(err))})
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
		writeInvalidRequestError(w, err)
		return
	}
	if req.Handshake.Type != pluginBridgeHandshakeType {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "handshake type is invalid", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	if req.Handshake.SurfaceInstanceID != surfaceInstanceID {
		WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "surface_instance_id mismatch", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	scope := trustedRequestScope(r)
	result, err := h.Host.MintBridgeToken(r.Context(), host.MintBridgeTokenRequest{
		Handshake:                 bridgeHandshake(req.Handshake),
		BridgeChannelID:           req.BridgeChannelID,
		HandshakeTranscriptSHA256: req.HandshakeTranscriptSHA256,
		PreviousGatewayToken:      req.PreviousGatewayToken,
		OwnerSessionHash:          scope.OwnerSessionHash,
		OwnerUserHash:             scope.OwnerUserHash,
		SessionChannelIDHash:      scope.SessionChannelIDHash,
	})
	if err != nil {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForBridgeTokenError(err, req.PreviousGatewayToken != ""))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
}

func bridgeHandshake(handshake pluginBridgeHandshake) bridge.Handshake {
	return bridge.Handshake{
		PluginID:           handshake.PluginID,
		SurfaceID:          handshake.SurfaceID,
		SurfaceInstanceID:  handshake.SurfaceInstanceID,
		ActiveFingerprint:  handshake.ActiveFingerprint,
		BridgeNonce:        handshake.BridgeNonce,
		AssetSessionNonce:  handshake.AssetSessionNonce,
		PluginStateVersion: handshake.PluginStateVersion,
		RevokeEpoch:        handshake.RevokeEpoch,
		UIProtocolVersion:  handshake.UIProtocolVersion,
	}
}

func (h Handler) handleReadSurfaceAsset(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/assets/read")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req readSurfaceAssetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	result, err := h.Host.ReadSurfaceAsset(r.Context(), host.ReadSurfaceAssetRequest{
		AssetSession:         req.AssetSession,
		AssetSessionID:       req.AssetSessionID,
		BindingID:            req.BindingID,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
	})
	if err != nil {
		WriteJSON(w, httpStatusForAssetError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForAssetError(err))})
		return
	}
	if result.Session.SurfaceInstanceID != surfaceInstanceID {
		WriteJSON(w, http.StatusForbidden, Envelope{OK: false, Error: bridge.ErrTokenAudience.Error(), ErrorCode: string(errorCodeForAssetError(bridge.ErrTokenAudience))})
		return
	}
	contentType := result.Entry.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{
		"path":           result.Entry.Path,
		"sha256":         result.Entry.SHA256,
		"content_type":   contentType,
		"content_base64": base64.StdEncoding.EncodeToString(result.Content),
	}})
}

func (h Handler) handleReadSurfaceStream(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/streams/read")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req readSurfaceStreamRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	result, err := h.Host.ReadStream(r.Context(), host.ReadStreamRequest{
		StreamID:             req.StreamID,
		StreamTicket:         req.StreamTicket,
		SurfaceInstanceID:    surfaceInstanceID,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
		MaxEvents:            defaultStreamReadMaxEvents,
		MaxBytes:             defaultStreamReadMaxBytes,
		WaitTimeout:          defaultStreamReadWaitTimeout,
	})
	if err != nil {
		code := errorCodeForStreamError(err)
		WriteJSON(w, httpStatusForStreamError(err), Envelope{OK: false, Error: publicPluginErrorMessage(code), ErrorCode: string(code)})
		return
	}
	data := map[string]any{
		"events": result.Events,
		"done":   result.Done,
	}
	if result.Done {
		data["terminal_status"] = result.TerminalStatus
	} else {
		data["next_stream_ticket"] = result.NextStreamTicket
		data["next_stream_ticket_id"] = result.NextStreamTicketID
		data["next_stream_expires_at"] = result.NextStreamExpiresAt
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: data})
}

func (h Handler) handleDisposeSurface(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/dispose")
	if !ok {
		WriteJSON(w, http.StatusNotFound, Envelope{OK: false, Error: "route not found", ErrorCode: string(security.ErrInvalidRequest)})
		return
	}
	var req disposeSurfaceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	if err := h.Host.DisposeSurface(r.Context(), host.DisposeSurfaceRequest{
		SurfaceInstanceID:    surfaceInstanceID,
		BridgeNonce:          req.BridgeNonce,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
	}); err != nil {
		WriteJSON(w, httpStatusForBridgeError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForBridgeError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]bool{"disposed": true}})
}

func (h Handler) handleRevokeSurfaceScope(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req revokeSurfaceScopeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	revoked, err := h.Host.RevokeSurfaceScope(r.Context(), host.RevokeSurfaceScopeRequest{
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
	})
	if err != nil {
		WriteJSON(w, httpStatusForBridgeError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForBridgeError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]int{"revoked_surface_count": revoked}})
}

func (h Handler) handleRPC(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req rpcRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	result, err := h.Host.CallPluginMethod(r.Context(), host.CallMethodRequest{
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: scope.SessionChannelIDHash,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		BridgeChannelID:      req.BridgeChannelID,
		GatewayToken:         req.GatewayToken,
		ConfirmationID:       req.ConfirmationID,
		Method:               req.Method,
		Params:               req.Params,
	})
	if err != nil {
		code := errorCodeForRPCError(err)
		WriteJSON(w, httpStatusForRPCError(err), Envelope{OK: false, Error: publicPluginErrorMessage(code), ErrorCode: string(code), ErrorDetails: errorDetailsForRPCError(err)})
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
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	result, err := h.Host.PrepareMethodConfirmation(r.Context(), host.ConfirmMethodRequest{
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: scope.SessionChannelIDHash,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		BridgeChannelID:      req.BridgeChannelID,
		GatewayToken:         req.GatewayToken,
		Method:               req.Method,
		Params:               req.Params,
	})
	if err != nil {
		code := errorCodeForRPCError(err)
		WriteJSON(w, httpStatusForRPCError(err), Envelope{OK: false, Error: publicPluginErrorMessage(code), ErrorCode: string(code)})
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
		code := errorCodeForIntentError(err)
		WriteJSON(w, httpStatusForIntentError(err), Envelope{OK: false, Error: publicPluginErrorMessage(code), ErrorCode: string(code)})
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
		writeInvalidRequestError(w, err)
		return
	}
	scope := trustedRequestScope(r)
	result, err := h.Host.InvokeIntent(r.Context(), host.InvokeIntentRequest{
		PluginInstanceID:     req.PluginInstanceID,
		IntentID:             req.IntentID,
		Params:               req.Params,
		OwnerSessionHash:     scope.OwnerSessionHash,
		OwnerUserHash:        scope.OwnerUserHash,
		SessionChannelIDHash: scope.SessionChannelIDHash,
	})
	if err != nil {
		code := errorCodeForIntentError(err)
		WriteJSON(w, httpStatusForIntentError(err), Envelope{OK: false, Error: publicPluginErrorMessage(code), ErrorCode: string(code), ErrorDetails: errorDetailsForRPCError(err)})
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
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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

func (h Handler) handleRefreshEnabledRuntimeState(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	records, err := h.Host.RefreshEnabledPlugins(r.Context())
	if err != nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: err.Error(), ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{"refreshed_plugins": records}})
}

func (h Handler) handleExportData(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req exportDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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

func (h Handler) handleListRetainedData(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	records, err := h.Host.ListRetainedData(r.Context(), host.ListRetainedDataRequest{
		PublisherID:            strings.TrimSpace(r.URL.Query().Get("publisher_id")),
		PluginID:               strings.TrimSpace(r.URL.Query().Get("plugin_id")),
		SourcePluginInstanceID: strings.TrimSpace(r.URL.Query().Get("source_plugin_instance_id")),
		State:                  retaineddata.State(strings.TrimSpace(r.URL.Query().Get("state"))),
	})
	if err != nil {
		WriteJSON(w, httpStatusForDataLifecycleError(err), Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForDataLifecycleError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: map[string]any{"retained_data": records}})
}

func (h Handler) handleDeleteRetainedData(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req deleteRetainedDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	record, err := h.Host.DeleteRetainedData(r.Context(), host.DeleteRetainedDataRequest{RetainedID: req.RetainedID})
	if err != nil {
		envelope := Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForDataLifecycleError(err))}
		if record.RetainedID != "" {
			envelope.Data = record
		}
		WriteJSON(w, httpStatusForDataLifecycleError(err), envelope)
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleBindRetainedData(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req bindRetainedDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	record, err := h.Host.BindRetainedData(r.Context(), host.BindRetainedDataRequest{
		RetainedID:             req.RetainedID,
		TargetPluginInstanceID: req.TargetPluginInstanceID,
	})
	if err != nil {
		envelope := Envelope{OK: false, Error: err.Error(), ErrorCode: string(errorCodeForDataLifecycleError(err))}
		if record.RetainedID != "" {
			envelope.Data = record
		}
		WriteJSON(w, httpStatusForDataLifecycleError(err), envelope)
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: record})
}

func (h Handler) handleCleanupExpiredRetainedData(w http.ResponseWriter, r *http.Request) {
	if h.Host == nil {
		WriteJSON(w, http.StatusServiceUnavailable, Envelope{OK: false, Error: "host is unavailable", ErrorCode: string(security.ErrRuntimeUnavailable)})
		return
	}
	var req cleanupExpiredRetainedDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	maxRecords := 0
	if req.MaxRecords != nil {
		if *req.MaxRecords < 1 {
			WriteJSON(w, http.StatusBadRequest, Envelope{OK: false, Error: "max_records must be at least 1 when provided", ErrorCode: string(security.ErrInvalidRequest)})
			return
		}
		maxRecords = *req.MaxRecords
	}
	result, err := h.Host.CleanupExpiredRetainedData(r.Context(), host.CleanupExpiredRetainedDataRequest{
		RetryFailed: req.RetryFailed,
		MaxRecords:  maxRecords,
	})
	if err != nil {
		WriteJSON(w, httpStatusForDataLifecycleError(err), Envelope{OK: false, Data: result, Error: err.Error(), ErrorCode: string(errorCodeForDataLifecycleError(err))})
		return
	}
	WriteJSON(w, http.StatusOK, Envelope{OK: true, Data: result})
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
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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
		writeInvalidRequestError(w, err)
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

func decodeJSON(r *http.Request, dst any) error {
	raw, err := readLimitedJSONBody(r, defaultJSONRequestMaxBytes)
	if err != nil {
		return err
	}
	if err := validateJSONLimits(raw, defaultJSONMaxDepth); err != nil {
		return err
	}
	return decodeStrictJSON(raw, dst)
}

func readLimitedJSONBody(r *http.Request, maxBytes int64) ([]byte, error) {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, &jsonLimitError{reason: jsonLimitReasonPayloadBytes}
	}
	return raw, nil
}

func validateJSONLimits(raw []byte, maxDepth int) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var payload any
	if err := decodeSingleJSONValue(decoder, &payload); err != nil {
		return err
	}
	return validateJSONValueLimits(payload, 1, maxDepth)
}

func decodeStrictJSON(raw []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decodeSingleJSONValue(decoder, dst)
}

func decodeSingleJSONValue(decoder *json.Decoder, dst any) error {
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

func validateJSONValueLimits(value any, depth int, maxDepth int) error {
	if depth > maxDepth {
		return &jsonLimitError{reason: jsonLimitReasonDepth}
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isForbiddenJSONKey(key) {
				return &jsonLimitError{reason: jsonLimitReasonPrototypeKey}
			}
			if err := validateJSONValueLimits(child, depth+1, maxDepth); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := validateJSONValueLimits(child, depth+1, maxDepth); err != nil {
				return err
			}
		}
	case json.Number:
		if jsonNumberExceedsSafePrecision(typed) {
			return &jsonLimitError{reason: jsonLimitReasonNumberPrecision}
		}
	}
	return nil
}

func isForbiddenJSONKey(key string) bool {
	return key == "__proto__" || key == "constructor" || key == "prototype"
}

func jsonNumberExceedsSafePrecision(number json.Number) bool {
	parsed, _, err := big.ParseFloat(number.String(), 10, jsonNumberPrecisionBits, big.ToNearestEven)
	if err != nil {
		return true
	}
	magnitude := new(big.Float).SetPrec(jsonNumberPrecisionBits).Copy(parsed)
	if magnitude.Sign() < 0 {
		magnitude.Neg(magnitude)
	}
	return magnitude.Cmp(maxJSONSafeFloat) > 0
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

func errorCodeForBridgeTokenError(err error, renewal bool) security.ErrorCode {
	if renewal && isGatewayTokenValidationError(err) {
		return errorCodeForGatewayTokenError(err)
	}
	return errorCodeForBridgeError(err)
}

func errorCodeForOpenSurfaceError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrPluginStateVersionMismatch):
		return security.ErrStateVersionMismatch
	case errors.Is(err, bridge.ErrSurfaceSessionLimitReached):
		return security.ErrRuntimeUnavailable
	case errors.Is(err, bridge.ErrSurfaceSessionAlreadyExists):
		return security.ErrContractMismatch
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForOpenSurfaceError(err error) int {
	switch {
	case errors.Is(err, host.ErrPluginStateVersionMismatch):
		return http.StatusConflict
	case errors.Is(err, bridge.ErrSurfaceSessionLimitReached):
		return http.StatusServiceUnavailable
	case errors.Is(err, bridge.ErrSurfaceSessionAlreadyExists):
		return http.StatusConflict
	default:
		return http.StatusForbidden
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
	case isCapabilityBusinessError(err):
		return security.ErrCapabilityError
	case isWorkerExecutionError(err):
		return errorCodeForWorkerExecutionError(err)
	case errors.Is(err, host.ErrMethodRequestContract):
		return security.ErrInvalidRequest
	case errors.Is(err, host.ErrMethodResponseContract):
		return security.ErrContractMismatch
	case errors.Is(err, host.ErrConfirmationRequired):
		return security.ErrConfirmationRequired
	case errors.Is(err, host.ErrConfirmationInvalid):
		return security.ErrConfirmationInvalid
	case errors.Is(err, security.ErrPolicyDenied):
		return security.ErrPermissionDenied
	case errors.Is(err, permissions.ErrPermissionDenied):
		return security.ErrPermissionDenied
	case errors.Is(err, bridge.ErrTokenExpired):
		return security.ErrTokenExpired
	case isGatewayTokenValidationError(err):
		return errorCodeForGatewayTokenError(err)
	case errors.Is(err, runtimeclient.ErrRuntimeNotReady), errors.Is(err, runtimeclient.ErrRuntimeIPCUnavailable), errors.Is(err, runtimeclient.ErrRuntimeRequestFailed), errors.Is(err, runtimeclient.ErrRuntimeHandshake):
		return security.ErrRuntimeUnavailable
	default:
		return security.ErrPermissionDenied
	}
}

func publicPluginErrorMessage(code security.ErrorCode) string {
	switch code {
	case security.ErrInvalidRequest:
		return "plugin request is invalid"
	case security.ErrPermissionDenied:
		return "plugin permission was denied"
	case security.ErrConfirmationRequired:
		return "plugin confirmation is required"
	case security.ErrConfirmationInvalid:
		return "plugin confirmation is invalid"
	case security.ErrConfirmationRejected:
		return "plugin confirmation was rejected"
	case security.ErrTokenExpired:
		return "plugin credential has expired"
	case security.ErrGatewayTokenInvalid, security.ErrGatewayTokenReplayed, security.ErrGatewayTokenChannelMismatch:
		return "plugin gateway credential is invalid"
	case security.ErrStreamTicketInvalid:
		return "plugin stream credential is invalid"
	case security.ErrStreamCancelled:
		return "plugin stream was cancelled"
	case security.ErrLeaseInvalid:
		return "plugin execution lease is invalid"
	case security.ErrGrantInvalid:
		return "plugin capability grant is invalid"
	case security.ErrRuntimeUnavailable:
		return "plugin runtime is unavailable"
	case security.ErrRuntimeVersionMismatch:
		return "plugin runtime version is incompatible"
	case security.ErrCapabilityError:
		return "host capability request failed"
	case security.ErrWorkerError:
		return "plugin operation failed"
	case security.ErrContractMismatch:
		return "plugin contract validation failed"
	default:
		return "plugin request failed"
	}
}

func errorCodeForGatewayTokenError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, bridge.ErrTokenReplay):
		return security.ErrGatewayTokenReplayed
	case errors.Is(err, bridge.ErrTokenAlreadyBound), errors.Is(err, bridge.ErrTokenAudience):
		return security.ErrGatewayTokenChannelMismatch
	case errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenRevoked), errors.Is(err, bridge.ErrTokenKind):
		return security.ErrGatewayTokenInvalid
	default:
		return security.ErrGatewayTokenInvalid
	}
}

func isGatewayTokenValidationError(err error) bool {
	return errors.Is(err, bridge.ErrTokenExpired) ||
		errors.Is(err, bridge.ErrTokenReplay) ||
		errors.Is(err, bridge.ErrTokenAlreadyBound) ||
		errors.Is(err, bridge.ErrTokenInvalid) ||
		errors.Is(err, bridge.ErrTokenAudience) ||
		errors.Is(err, bridge.ErrTokenRevoked) ||
		errors.Is(err, bridge.ErrTokenKind)
}

func errorCodeForManagementError(err error) security.ErrorCode {
	var packageValidationErr *pluginpkg.ValidationError
	if errors.As(err, &packageValidationErr) {
		switch packageValidationErr.Code {
		case pluginpkg.ValidationCodeManifestInvalid:
			return security.ErrManifestInvalid
		case pluginpkg.ValidationCodePackageInvalid:
			return security.ErrPackageInvalid
		case pluginpkg.ValidationCodePackageTooLarge:
			return security.ErrPackageTooLarge
		case pluginpkg.ValidationCodePackagePathForbidden:
			return security.ErrPackagePathForbidden
		}
	}
	switch {
	case errors.Is(err, host.ErrPluginStateVersionMismatch):
		return security.ErrStateVersionMismatch
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound):
		return security.ErrInvalidRequest
	case errors.Is(err, host.ErrPackageTrustVerificationInvalid):
		return security.ErrTrustVerificationInvalid
	case errors.Is(err, host.ErrPackageTrustVerifierRequired):
		return security.ErrTrustVerificationRequired
	case errors.Is(err, host.ErrReleaseMetadataVerifierRequired):
		return security.ErrTrustVerificationRequired
	case errors.Is(err, host.ErrReleaseArtifactResolverRequired):
		return security.ErrTrustVerificationRequired
	case errors.Is(err, host.ErrSourceRevocationVerifierRequired):
		return security.ErrTrustVerificationRequired
	case errors.Is(err, host.ErrReleaseSourcePolicyRequired):
		return security.ErrTrustVerificationRequired
	case errors.Is(err, host.ErrReleaseRefVerificationFailed):
		return security.ErrReleaseRefVerificationFailed
	case errors.Is(err, host.ErrReleaseRefPolicyDenied):
		return security.ErrReleaseRefPolicyDenied
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

func errorDetailsForManagementError(err error) map[string]any {
	var packageValidationErr *pluginpkg.ValidationError
	if errors.As(err, &packageValidationErr) {
		return packageValidationErr.Details()
	}
	return nil
}

func httpStatusForManagementError(err error) int {
	var packageValidationErr *pluginpkg.ValidationError
	if errors.As(err, &packageValidationErr) {
		if packageValidationErr.Code == pluginpkg.ValidationCodePackageTooLarge {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusBadRequest
	}
	switch {
	case errors.Is(err, host.ErrPluginStateVersionMismatch):
		return http.StatusConflict
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound):
		return http.StatusBadRequest
	case errors.Is(err, host.ErrPackageTrustVerificationInvalid):
		return http.StatusBadRequest
	case errors.Is(err, host.ErrPackageTrustVerifierRequired):
		return http.StatusForbidden
	case errors.Is(err, host.ErrReleaseMetadataVerifierRequired):
		return http.StatusForbidden
	case errors.Is(err, host.ErrReleaseArtifactResolverRequired):
		return http.StatusForbidden
	case errors.Is(err, host.ErrSourceRevocationVerifierRequired):
		return http.StatusForbidden
	case errors.Is(err, host.ErrReleaseSourcePolicyRequired):
		return http.StatusForbidden
	case errors.Is(err, host.ErrReleaseRefVerificationFailed):
		return http.StatusBadRequest
	case errors.Is(err, host.ErrReleaseRefPolicyDenied):
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
	case errors.Is(err, host.ErrOperationCancelDispatchFailed):
		return security.ErrRuntimeUnavailable
	case errors.Is(err, operation.ErrNotCancelable):
		return security.ErrOperationNotCancelable
	case errors.Is(err, operation.ErrNotFound), errors.Is(err, operation.ErrInvalidOperation):
		return security.ErrInvalidRequest
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForOperationError(err error) int {
	switch {
	case errors.Is(err, host.ErrOperationCancelDispatchFailed):
		return http.StatusServiceUnavailable
	case errors.Is(err, operation.ErrNotCancelable):
		return http.StatusConflict
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
	case errors.Is(err, host.ErrStreamTicketRequired), isSandboxTokenValidationError(err):
		return security.ErrStreamTicketInvalid
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
	case isCapabilityBusinessError(err):
		return http.StatusUnprocessableEntity
	case isWorkerExecutionError(err):
		return httpStatusForWorkerExecutionError(err)
	case errors.Is(err, host.ErrMethodRequestContract):
		return http.StatusBadRequest
	case errors.Is(err, host.ErrMethodResponseContract):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrConfirmationRequired):
		return http.StatusConflict
	case errors.Is(err, security.ErrPolicyDenied):
		return http.StatusForbidden
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
	case isCapabilityBusinessError(err):
		return security.ErrCapabilityError
	case isWorkerExecutionError(err):
		return errorCodeForWorkerExecutionError(err)
	case errors.Is(err, host.ErrMethodRequestContract):
		return security.ErrInvalidRequest
	case errors.Is(err, host.ErrMethodResponseContract):
		return security.ErrContractMismatch
	case errors.Is(err, host.ErrConfirmationRequired):
		return security.ErrConfirmationRequired
	case errors.Is(err, security.ErrPolicyDenied):
		return security.ErrPermissionDenied
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

func errorDetailsForRPCError(err error) map[string]any {
	var businessError *capability.BusinessError
	if errors.As(err, &businessError) {
		details := map[string]any{
			"capability_id":        businessError.CapabilityID,
			"capability_version":   businessError.CapabilityVersion,
			"detail_schema_sha256": businessError.DetailSchemaSHA256,
			"business_error_code":  businessError.Code,
		}
		if businessError.Details != nil {
			details["business_error_details"] = businessError.Details
		}
		return details
	}
	var workerError *runtimeclient.WorkerExecutionError
	if errors.As(err, &workerError) {
		if errorCodeForWorkerExecutionError(err) != security.ErrWorkerError {
			return nil
		}
		return map[string]any{
			"worker_error_code":    workerError.Code,
			"worker_error_message": publicWorkerErrorMessage(workerError.Message),
			"worker_error_origin":  string(workerError.Origin),
		}
	}
	return nil
}

func isCapabilityBusinessError(err error) bool {
	var businessError *capability.BusinessError
	return errors.As(err, &businessError)
}

func isWorkerExecutionError(err error) bool {
	var workerError *runtimeclient.WorkerExecutionError
	return errors.As(err, &workerError)
}

func errorCodeForWorkerExecutionError(err error) security.ErrorCode {
	var workerError *runtimeclient.WorkerExecutionError
	if !errors.As(err, &workerError) {
		return security.ErrRuntimeUnavailable
	}
	if workerError.Origin == runtimeclient.WorkerErrorOriginPlugin {
		return security.ErrWorkerError
	}
	if workerError.Origin != runtimeclient.WorkerErrorOriginRuntime && workerError.Origin != runtimeclient.WorkerErrorOriginHostcall {
		return security.ErrRuntimeUnavailable
	}
	switch workerError.Code {
	case "INVALID_REQUEST":
		return security.ErrInvalidRequest
	case "NETWORK_TARGET_DENIED":
		return security.ErrNetworkTargetDenied
	case "NETWORK_RATE_LIMITED":
		return security.ErrNetworkRateLimited
	case "STORAGE_QUOTA_EXCEEDED", "STORAGE_FILE_QUOTA_EXCEEDED", "STORAGE_KV_QUOTA_EXCEEDED", "STORAGE_SQLITE_QUOTA_EXCEEDED":
		return security.ErrStorageQuotaExceeded
	case "RUNTIME_CAPABILITY_REVOKED":
		return security.ErrGrantInvalid
	case "RUNTIME_LEASE_INVALID", "RUNTIME_LEASE_SIGNATURE_INVALID":
		return security.ErrLeaseInvalid
	case "RUNTIME_CONTROL_CHANNEL_STALE", "WASM_WORKER_FAILED", "WASM_HOSTCALL_FAILED", "HOSTCALL_FAILED":
		return security.ErrRuntimeUnavailable
	case "WASM_WORKER_INVALID":
		return security.ErrContractMismatch
	default:
		return security.ErrRuntimeUnavailable
	}
}

func httpStatusForWorkerExecutionError(err error) int {
	switch errorCodeForWorkerExecutionError(err) {
	case security.ErrInvalidRequest:
		return http.StatusBadRequest
	case security.ErrNetworkTargetDenied, security.ErrGrantInvalid, security.ErrLeaseInvalid:
		return http.StatusForbidden
	case security.ErrNetworkRateLimited:
		return http.StatusTooManyRequests
	case security.ErrStorageQuotaExceeded:
		return http.StatusRequestEntityTooLarge
	case security.ErrContractMismatch:
		return http.StatusBadGateway
	case security.ErrRuntimeUnavailable, security.ErrRuntimeVersionMismatch:
		return http.StatusServiceUnavailable
	default:
		return http.StatusUnprocessableEntity
	}
}

func publicWorkerErrorMessage(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "plugin worker operation failed"
	}
	runes := []rune(value)
	if len(runes) > 512 {
		return string(runes[:512])
	}
	return value
}

func httpStatusForIntentError(err error) int {
	switch {
	case isCapabilityBusinessError(err):
		return http.StatusUnprocessableEntity
	case isWorkerExecutionError(err):
		return httpStatusForWorkerExecutionError(err)
	case errors.Is(err, host.ErrMethodRequestContract):
		return http.StatusBadRequest
	case errors.Is(err, host.ErrMethodResponseContract):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrConfirmationRequired):
		return http.StatusConflict
	case errors.Is(err, security.ErrPolicyDenied):
		return http.StatusForbidden
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

func errorCodeForDataLifecycleError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, storage.ErrQuotaExceeded):
		return security.ErrStorageQuotaExceeded
	case errors.Is(err, host.ErrRetainedDataBindFailed):
		return security.ErrRetainedDataBindFailed
	case errors.Is(err, host.ErrRetainedDataCleanupFailed):
		return security.ErrRetainedDataCleanupFailed
	case errors.Is(err, retaineddata.ErrNotFound), errors.Is(err, retaineddata.ErrInvalidRecord), errors.Is(err, registry.ErrNotFound), errors.Is(err, host.ErrPluginDataArchiveRequired), errors.Is(err, host.ErrPluginDataNotDeclared), errors.Is(err, host.ErrPluginSettingsNotDeclared), errors.Is(err, host.ErrPluginStorageNotDeclared), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound), errors.Is(err, settings.ErrArchiveNotFound), errors.Is(err, settings.ErrNotDeclared), errors.Is(err, settings.ErrInvalidSetting):
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
	case errors.Is(err, bridge.ErrTokenReplay):
		return security.ErrTokenReplay
	case errors.Is(err, bridge.ErrTokenExpired):
		return security.ErrTokenExpired
	case isSandboxTokenValidationError(err), errors.Is(err, bridge.ErrSurfaceSessionNotFound), errors.Is(err, bridge.ErrSurfaceSessionExpired), errors.Is(err, bridge.ErrAssetSessionRequired):
		return security.ErrAssetSessionInvalid
	case errors.Is(err, registry.ErrNotFound):
		return security.ErrInvalidRequest
	default:
		return security.ErrPermissionDenied
	}
}

func isSandboxTokenValidationError(err error) bool {
	return errors.Is(err, bridge.ErrTokenExpired) ||
		errors.Is(err, bridge.ErrTokenReplay) ||
		errors.Is(err, bridge.ErrTokenInvalid) ||
		errors.Is(err, bridge.ErrTokenAudience) ||
		errors.Is(err, bridge.ErrTokenRevoked) ||
		errors.Is(err, bridge.ErrTokenKind)
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

func httpStatusForDataLifecycleError(err error) int {
	switch {
	case errors.Is(err, storage.ErrQuotaExceeded):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, host.ErrRetainedDataBindFailed):
		return http.StatusConflict
	case errors.Is(err, host.ErrRetainedDataCleanupFailed):
		return http.StatusConflict
	case errors.Is(err, retaineddata.ErrNotFound), errors.Is(err, retaineddata.ErrInvalidRecord), errors.Is(err, registry.ErrNotFound), errors.Is(err, host.ErrPluginDataArchiveRequired), errors.Is(err, host.ErrPluginDataNotDeclared), errors.Is(err, host.ErrPluginSettingsNotDeclared), errors.Is(err, host.ErrPluginStorageNotDeclared), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrArchiveNotFound), errors.Is(err, storage.ErrNamespaceNotFound), errors.Is(err, settings.ErrArchiveNotFound), errors.Is(err, settings.ErrNotDeclared), errors.Is(err, settings.ErrInvalidSetting):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}
