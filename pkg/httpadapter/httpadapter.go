package httpadapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/websecurity"
)

type successResponse struct {
	OK   bool `json:"ok"`
	Data any  `json:"data"`
}

type mutationSuccessResponse struct {
	OK   bool `json:"ok"`
	Data any  `json:"data"`
}

func (r successResponse) MarshalJSON() ([]byte, error) {
	if !r.OK {
		return nil, errors.New("success response must set ok=true")
	}
	type successAlias successResponse
	return json.Marshal(successAlias(r))
}

func (r mutationSuccessResponse) MarshalJSON() ([]byte, error) {
	if !r.OK {
		return nil, errors.New("mutation success response must set ok=true")
	}
	type successAlias mutationSuccessResponse
	return json.Marshal(successAlias(r))
}

type errorResponse struct {
	OK      bool               `json:"ok"`
	Message string             `json:"-"`
	Code    security.ErrorCode `json:"-"`
	Details errorDetails       `json:"-"`
}

type errorBody struct {
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Details errorDetails `json:"details"`
}

type mutationErrorResponse struct {
	OK              bool               `json:"ok"`
	Message         string             `json:"-"`
	Code            security.ErrorCode `json:"-"`
	Details         errorDetails       `json:"-"`
	MutationOutcome mutation.Outcome   `json:"-"`
}

type mutationErrorBody struct {
	Code            string       `json:"code"`
	Message         string       `json:"message"`
	Details         errorDetails `json:"details"`
	MutationOutcome string       `json:"mutation_outcome"`
}

type errorDetails struct {
	Reason                     string                      `json:"reason,omitempty"`
	Path                       string                      `json:"path,omitempty"`
	Pointer                    string                      `json:"pointer,omitempty"`
	CapabilityID               string                      `json:"capability_id,omitempty"`
	CapabilityVersion          string                      `json:"capability_version,omitempty"`
	DetailSchemaSHA256         string                      `json:"detail_schema_sha256,omitempty"`
	BusinessErrorCode          string                      `json:"business_error_code,omitempty"`
	BusinessErrorDetails       map[string]any              `json:"business_error_details,omitempty"`
	WorkerErrorCode            string                      `json:"worker_error_code,omitempty"`
	WorkerErrorMessage         string                      `json:"worker_error_message,omitempty"`
	WorkerErrorOrigin          string                      `json:"worker_error_origin,omitempty"`
	PluginInstanceID           string                      `json:"plugin_instance_id,omitempty"`
	ExpectedPolicyRevision     uint64                      `json:"expected_policy_revision,omitempty"`
	ActualPolicyRevision       uint64                      `json:"actual_policy_revision,omitempty"`
	ExpectedManagementRevision uint64                      `json:"expected_management_revision,omitempty"`
	ActualManagementRevision   uint64                      `json:"actual_management_revision,omitempty"`
	ExpectedRevokeEpoch        *uint64                     `json:"expected_revoke_epoch,omitempty"`
	ActualRevokeEpoch          *uint64                     `json:"actual_revoke_epoch,omitempty"`
	ExpectedBindingRevision    uint64                      `json:"expected_binding_revision,omitempty"`
	ActualBindingRevision      uint64                      `json:"actual_binding_revision,omitempty"`
	ExpectedValuesRevision     *uint64                     `json:"expected_values_revision,omitempty"`
	ActualValuesRevision       *uint64                     `json:"actual_values_revision,omitempty"`
	SessionScope               *sessionScopeRevokeResponse `json:"session_scope,omitempty"`
}

var platformErrorCodeSet = func() map[security.ErrorCode]struct{} {
	codes := security.PlatformErrorCodes()
	result := make(map[security.ErrorCode]struct{}, len(codes))
	for _, code := range codes {
		result[code] = struct{}{}
	}
	return result
}()

var platformDetailCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
var platformSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var packageValidationReasonSet = func() map[string]struct{} {
	result := map[string]struct{}{}
	for _, reason := range strings.Fields("manifest_missing manifest_field manifest_decode zip_invalid file_count duplicate_entry ambiguous_entry non_regular_entry invalid_utf8_path non_nfc_path symlink_entry directory_entry entry_bytes path_length compression_ratio total_uncompressed_bytes entry_open_failed entry_read_failed entry_close_failed entry_size_mismatch unsupported_signature_entry manifest_artifact package_asset_security package_artifact_boundary entry_path manifest_canonical_json canonical_hash package_signature empty_path slash_separator non_canonical_path path_traversal hidden_path external_icon_path unsupported_icon_format missing_icon_asset icon_magic_mismatch query_or_fragment") {
		result[reason] = struct{}{}
	}
	return result
}()

func (r errorResponse) MarshalJSON() ([]byte, error) {
	if r.OK {
		return nil, errors.New("error response must set ok=false")
	}
	if _, ok := platformErrorCodeSet[r.Code]; !ok {
		return nil, fmt.Errorf("unknown platform error code %q", r.Code)
	}
	if strings.TrimSpace(r.Message) == "" || utf8.RuneCountInString(r.Message) > 4096 {
		return nil, errors.New("platform error message is required")
	}
	if err := r.Details.validateForCode(r.Code); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		OK    bool      `json:"ok"`
		Error errorBody `json:"error"`
	}{
		OK: r.OK,
		Error: errorBody{
			Code:    string(r.Code),
			Message: r.Message,
			Details: r.Details,
		},
	})
}

func (r mutationErrorResponse) MarshalJSON() ([]byte, error) {
	if r.OK {
		return nil, errors.New("mutation error response must set ok=false")
	}
	if _, ok := platformErrorCodeSet[r.Code]; !ok {
		return nil, fmt.Errorf("unknown platform error code %q", r.Code)
	}
	if strings.TrimSpace(r.Message) == "" || utf8.RuneCountInString(r.Message) > 4096 {
		return nil, errors.New("platform error message is required")
	}
	if r.MutationOutcome != mutation.OutcomeCommitted && r.MutationOutcome != mutation.OutcomeNotCommitted && r.MutationOutcome != mutation.OutcomeUnknown {
		return nil, fmt.Errorf("unsupported mutation outcome %q", r.MutationOutcome)
	}
	if err := r.Details.validateForCode(r.Code); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		OK    bool              `json:"ok"`
		Error mutationErrorBody `json:"error"`
	}{
		OK: r.OK,
		Error: mutationErrorBody{
			Code:            string(r.Code),
			Message:         r.Message,
			Details:         r.Details,
			MutationOutcome: string(r.MutationOutcome),
		},
	})
}

func (d errorDetails) validateForCode(code security.ErrorCode) error {
	switch code {
	case security.ErrManagementRevisionMismatch:
		if d.PluginInstanceID == "" || d.ExpectedManagementRevision == 0 || d.ActualManagementRevision == 0 ||
			d.ExpectedManagementRevision > uint64(maxJSONSafeInteger) || d.ActualManagementRevision > uint64(maxJSONSafeInteger) ||
			d.hasAuthorizationRevisionDetails() || d.hasBindingRevisionDetails() || d.hasValuesRevisionDetails() || d.hasNonRevisionDetails() {
			return errors.New("management revision mismatch details are incomplete")
		}
	case security.ErrAuthorizationRevisionMismatch:
		if d.PluginInstanceID == "" || d.ExpectedPolicyRevision == 0 || d.ActualPolicyRevision == 0 ||
			d.ExpectedManagementRevision == 0 || d.ActualManagementRevision == 0 ||
			d.ExpectedRevokeEpoch == nil || d.ActualRevokeEpoch == nil ||
			d.ExpectedPolicyRevision > uint64(maxJSONSafeInteger) || d.ActualPolicyRevision > uint64(maxJSONSafeInteger) ||
			d.ExpectedManagementRevision > uint64(maxJSONSafeInteger) || d.ActualManagementRevision > uint64(maxJSONSafeInteger) ||
			*d.ExpectedRevokeEpoch > uint64(maxJSONSafeInteger) || *d.ActualRevokeEpoch > uint64(maxJSONSafeInteger) ||
			d.hasBindingRevisionDetails() || d.hasValuesRevisionDetails() || d.hasNonRevisionDetails() {
			return errors.New("authorization revision mismatch details are incomplete")
		}
	case security.ErrBindingRevisionMismatch:
		if d.PluginInstanceID == "" || d.ExpectedBindingRevision == 0 || d.ActualBindingRevision == 0 ||
			d.ExpectedBindingRevision > uint64(maxJSONSafeInteger) || d.ActualBindingRevision > uint64(maxJSONSafeInteger) ||
			d.hasAuthorizationRevisionDetails() || d.hasManagementRevisionDetails() || d.hasValuesRevisionDetails() || d.hasNonRevisionDetails() {
			return errors.New("binding revision mismatch details are incomplete")
		}
	case security.ErrValuesRevisionMismatch:
		if d.PluginInstanceID == "" || d.ExpectedValuesRevision == nil || d.ActualValuesRevision == nil ||
			*d.ExpectedValuesRevision == 0 || *d.ActualValuesRevision == 0 ||
			*d.ExpectedValuesRevision > uint64(maxJSONSafeInteger) || *d.ActualValuesRevision > uint64(maxJSONSafeInteger) ||
			d.hasAuthorizationRevisionDetails() || d.hasManagementRevisionDetails() || d.hasBindingRevisionDetails() || d.hasNonRevisionDetails() {
			return errors.New("values revision mismatch details are incomplete")
		}
	case security.ErrCapabilityError:
		if d.CapabilityID == "" || d.CapabilityVersion == "" || !platformSHA256Pattern.MatchString(d.DetailSchemaSHA256) ||
			!platformDetailCodePattern.MatchString(d.BusinessErrorCode) || d.hasNonCapabilityDetails() {
			return errors.New("capability error details are incomplete")
		}
	case security.ErrWorkerError:
		if !platformDetailCodePattern.MatchString(d.WorkerErrorCode) || d.WorkerErrorMessage == "" || utf8.RuneCountInString(d.WorkerErrorMessage) > 4096 ||
			(d.WorkerErrorOrigin != string(runtimeclient.WorkerErrorOriginRuntime) &&
				d.WorkerErrorOrigin != string(runtimeclient.WorkerErrorOriginHostcall) &&
				d.WorkerErrorOrigin != string(runtimeclient.WorkerErrorOriginPlugin)) || d.hasNonWorkerDetails() {
			return errors.New("worker error details are incomplete")
		}
	case security.ErrJSONLimitExceeded:
		if !validJSONLimitReason(d.Reason) || d.hasNonReasonDetails() {
			return errors.New("JSON limit error details are incomplete")
		}
	case security.ErrManifestInvalid, security.ErrPackageInvalid, security.ErrPackageTooLarge, security.ErrPackagePathForbidden:
		if _, ok := packageValidationReasonSet[d.Reason]; !ok || d.hasNonPackageDetails() {
			return errors.New("package validation details are incomplete")
		}
	case security.ErrSessionTeardownIncomplete:
		if d.SessionScope == nil || !d.SessionScope.validIncomplete() || d.hasPackageDetails() ||
			d.hasRevisionDetails() || d.hasCapabilityDetails() || d.hasWorkerDetails() {
			return errors.New("session teardown details are incomplete")
		}
	default:
		if !d.empty() {
			return errors.New("platform error details do not match the error code")
		}
	}
	return nil
}

func validJSONLimitReason(reason string) bool {
	switch jsonLimitReason(reason) {
	case jsonLimitReasonPayloadBytes, jsonLimitReasonDepth, jsonLimitReasonPrototypeKey, jsonLimitReasonNumberPrecision:
		return true
	default:
		return false
	}
}

func (d errorDetails) hasRevisionDetails() bool {
	return d.PluginInstanceID != "" || d.ExpectedPolicyRevision != 0 || d.ActualPolicyRevision != 0 ||
		d.ExpectedManagementRevision != 0 || d.ActualManagementRevision != 0 ||
		d.ExpectedRevokeEpoch != nil || d.ActualRevokeEpoch != nil ||
		d.ExpectedBindingRevision != 0 || d.ActualBindingRevision != 0 ||
		d.ExpectedValuesRevision != nil || d.ActualValuesRevision != nil
}

func (d errorDetails) hasAuthorizationRevisionDetails() bool {
	return d.ExpectedPolicyRevision != 0 || d.ActualPolicyRevision != 0 ||
		d.ExpectedRevokeEpoch != nil || d.ActualRevokeEpoch != nil
}

func (d errorDetails) hasManagementRevisionDetails() bool {
	return d.ExpectedManagementRevision != 0 || d.ActualManagementRevision != 0
}

func (d errorDetails) hasBindingRevisionDetails() bool {
	return d.ExpectedBindingRevision != 0 || d.ActualBindingRevision != 0
}

func (d errorDetails) hasValuesRevisionDetails() bool {
	return d.ExpectedValuesRevision != nil || d.ActualValuesRevision != nil
}

func (d errorDetails) hasCapabilityDetails() bool {
	return d.CapabilityID != "" || d.CapabilityVersion != "" || d.DetailSchemaSHA256 != "" ||
		d.BusinessErrorCode != "" || d.BusinessErrorDetails != nil
}

func (d errorDetails) hasWorkerDetails() bool {
	return d.WorkerErrorCode != "" || d.WorkerErrorMessage != "" || d.WorkerErrorOrigin != ""
}

func (d errorDetails) hasPackageDetails() bool {
	return d.Reason != "" || d.Path != "" || d.Pointer != ""
}

func (d errorDetails) hasNonRevisionDetails() bool {
	return d.hasPackageDetails() || d.hasCapabilityDetails() || d.hasWorkerDetails()
}

func (d errorDetails) hasNonCapabilityDetails() bool {
	return d.hasPackageDetails() || d.hasRevisionDetails() || d.hasWorkerDetails()
}

func (d errorDetails) hasNonWorkerDetails() bool {
	return d.hasPackageDetails() || d.hasRevisionDetails() || d.hasCapabilityDetails()
}

func (d errorDetails) hasNonReasonDetails() bool {
	return d.Path != "" || d.Pointer != "" || d.hasRevisionDetails() || d.hasCapabilityDetails() || d.hasWorkerDetails()
}

func (d errorDetails) hasNonPackageDetails() bool {
	return d.hasRevisionDetails() || d.hasCapabilityDetails() || d.hasWorkerDetails()
}

func (d errorDetails) empty() bool {
	return !d.hasPackageDetails() && !d.hasRevisionDetails() && !d.hasCapabilityDetails() && !d.hasWorkerDetails() && d.SessionScope == nil
}

func (d errorDetails) MarshalJSON() ([]byte, error) {
	type detailsAlias errorDetails
	return json.Marshal(detailsAlias(d))
}

type Route struct {
	Method string
	Path   string
	Effect websecurity.RouteEffect
}

type Handler struct {
	host        *host.Host
	guard       websecurity.Guard
	mux         *http.ServeMux
	routeEffect websecurity.RouteEffect
}

type Dependencies struct {
	Host  *host.Host
	Guard websecurity.Guard
}

type HostConfigError = host.HostConfigError

type routeSpec struct {
	Route
	action       websecurity.RouteAction
	originPolicy websecurity.OriginPolicy
	csrfPolicy   websecurity.CSRFPolicy
	bind         func(*Handler) http.HandlerFunc
}

func apiRoute(effect websecurity.RouteEffect, method, path string, action websecurity.RouteAction, bind func(*Handler) http.HandlerFunc) routeSpec {
	return routeSpec{
		Route:        Route{Method: method, Path: path, Effect: effect},
		action:       action,
		originPolicy: websecurity.OriginPolicyTrustedHost,
		csrfPolicy:   websecurity.CSRFPolicyRequired,
		bind:         bind,
	}
}

func queryRoute(path string, action websecurity.RouteAction, bind func(*Handler) http.HandlerFunc) routeSpec {
	return apiRoute(websecurity.RouteEffectQuery, http.MethodPost, path, action, bind)
}

func mutationRoute(method, path string, action websecurity.RouteAction, bind func(*Handler) http.HandlerFunc) routeSpec {
	return apiRoute(websecurity.RouteEffectMutation, method, path, action, bind)
}

func (route routeSpec) validate() error {
	if !route.action.Valid() {
		return fmt.Errorf("%w: %q", websecurity.ErrRouteActionInvalid, route.action)
	}
	if !route.Effect.Valid() {
		return fmt.Errorf("%w: %q", websecurity.ErrRouteEffectInvalid, route.Effect)
	}
	hostAction := host.ManagementAction(route.action)
	if !hostAction.Valid() {
		return fmt.Errorf("%w: route action %q has no matching Host action", websecurity.ErrRouteActionInvalid, route.action)
	}
	if !route.originPolicy.Valid() {
		return fmt.Errorf("%w: %q", websecurity.ErrOriginPolicyInvalid, route.originPolicy)
	}
	if !route.csrfPolicy.Valid() {
		return fmt.Errorf("%w: %q", websecurity.ErrCSRFPolicyInvalid, route.csrfPolicy)
	}
	if route.csrfPolicy != websecurity.CSRFPolicyRequired {
		return fmt.Errorf("route %s %s has csrf policy %q, want %q", route.Method, route.Path, route.csrfPolicy, websecurity.CSRFPolicyRequired)
	}
	switch route.Effect {
	case websecurity.RouteEffectQuery:
		if route.Method != http.MethodPost {
			return fmt.Errorf("route %s %s has query effect but is not POST", route.Method, route.Path)
		}
	case websecurity.RouteEffectMutation:
		switch route.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return fmt.Errorf("route %s %s has mutation effect with an unsupported method", route.Method, route.Path)
		}
	}
	return nil
}

type installReleaseRefRequest struct {
	ReleaseRef       releaseRefRequest `json:"release_ref"`
	PluginInstanceID string            `json:"plugin_instance_id"`
}

type updateReleaseRefRequest struct {
	PluginInstanceID           string            `json:"plugin_instance_id"`
	ReleaseRef                 releaseRefRequest `json:"release_ref"`
	ExpectedManagementRevision *uint64           `json:"expected_management_revision"`
}

type downgradeRequest struct {
	PluginInstanceID           string  `json:"plugin_instance_id"`
	Version                    string  `json:"version,omitempty"`
	PackageHash                string  `json:"package_hash,omitempty"`
	ExpectedManagementRevision *uint64 `json:"expected_management_revision"`
}

type enableRequest struct {
	PluginInstanceID           string  `json:"plugin_instance_id"`
	ExpectedManagementRevision *uint64 `json:"expected_management_revision"`
}

type disableRequest struct {
	PluginInstanceID           string  `json:"plugin_instance_id"`
	Reason                     string  `json:"reason,omitempty"`
	ExpectedManagementRevision *uint64 `json:"expected_management_revision"`
}

type uninstallRequest struct {
	PluginInstanceID           string  `json:"plugin_instance_id"`
	DeleteData                 bool    `json:"delete_data"`
	ExpectedManagementRevision *uint64 `json:"expected_management_revision"`
}

type deleteRetainedDataRequest struct {
	PluginInstanceID        string  `json:"plugin_instance_id"`
	ExpectedBindingRevision *uint64 `json:"expected_binding_revision"`
}

type bindRetainedDataRequest struct {
	SourcePluginInstanceID           string  `json:"source_plugin_instance_id"`
	ExpectedSourceBindingRevision    *uint64 `json:"expected_source_binding_revision"`
	TargetPluginInstanceID           string  `json:"target_plugin_instance_id"`
	TargetExpectedManagementRevision *uint64 `json:"target_expected_management_revision"`
}

type cleanupExpiredRetainedDataRequest struct{}

type openSurfaceRequest struct {
	PluginInstanceID           string  `json:"plugin_instance_id"`
	SurfaceID                  string  `json:"surface_id"`
	SurfaceInstanceID          string  `json:"surface_instance_id,omitempty"`
	ExpectedManagementRevision *uint64 `json:"expected_management_revision"`
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
	ManagementRevision  uint64    `json:"management_revision"`
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
		ManagementRevision:  bootstrap.ManagementRevision,
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
	ReadID       string `json:"read_id"`
}

type acknowledgeSurfaceStreamRequest struct {
	StreamID     string `json:"stream_id"`
	StreamTicket string `json:"stream_ticket"`
	DeliveryID   string `json:"delivery_id"`
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
	ManagementRevision uint64 `json:"management_revision"`
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

type prepareMethodConfirmationRequest struct {
	PluginInstanceID  string         `json:"plugin_instance_id"`
	SurfaceInstanceID string         `json:"surface_instance_id"`
	BridgeChannelID   string         `json:"bridge_channel_id"`
	GatewayToken      string         `json:"plugin_gateway_token"`
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
}

type importDataRequest struct {
	PluginInstanceID           string  `json:"plugin_instance_id"`
	BundleRef                  string  `json:"bundle_ref"`
	ExpectedManagementRevision *uint64 `json:"expected_management_revision"`
}

type deleteDataExportRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	BundleRef        string `json:"bundle_ref"`
}

type grantPermissionRequest struct {
	PluginInstanceID           string    `json:"plugin_instance_id"`
	PermissionID               string    `json:"permission_id"`
	ExpectedPolicyRevision     uint64    `json:"expected_policy_revision"`
	ExpectedManagementRevision uint64    `json:"expected_management_revision"`
	ExpectedRevokeEpoch        uint64    `json:"expected_revoke_epoch"`
	ExpiresAt                  time.Time `json:"expires_at,omitempty"`
}

type revokePermissionRequest struct {
	PluginInstanceID           string `json:"plugin_instance_id"`
	PermissionID               string `json:"permission_id"`
	ExpectedPolicyRevision     uint64 `json:"expected_policy_revision"`
	ExpectedManagementRevision uint64 `json:"expected_management_revision"`
	ExpectedRevokeEpoch        uint64 `json:"expected_revoke_epoch"`
	Reason                     string `json:"reason,omitempty"`
}

type putSecurityPolicyRequest struct {
	ExpectedPolicyRevision     *uint64   `json:"expected_policy_revision"`
	ExpectedManagementRevision *uint64   `json:"expected_management_revision"`
	ExpectedRevokeEpoch        *uint64   `json:"expected_revoke_epoch"`
	AllowedPermissions         *[]string `json:"allowed_permissions"`
	DeniedMethods              *[]string `json:"denied_methods"`
}

type deleteSecurityPolicyRequest struct {
	ExpectedPolicyRevision     *uint64 `json:"expected_policy_revision"`
	ExpectedManagementRevision *uint64 `json:"expected_management_revision"`
	ExpectedRevokeEpoch        *uint64 `json:"expected_revoke_epoch"`
}

type securityPolicyResponse struct {
	PluginInstanceID   string    `json:"plugin_instance_id"`
	AllowedPermissions []string  `json:"allowed_permissions"`
	DeniedMethods      []string  `json:"denied_methods"`
	PolicyRevision     uint64    `json:"policy_revision"`
	ManagementRevision uint64    `json:"management_revision"`
	RevokeEpoch        uint64    `json:"revoke_epoch"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type secretRefRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	SecretRef        string `json:"secret_ref"`
	Scope            string `json:"scope"`
}

type patchSettingsRequest struct {
	Scope                  string         `json:"scope"`
	ExpectedValuesRevision *uint64        `json:"expected_values_revision"`
	Set                    map[string]any `json:"set,omitempty"`
	Remove                 []string       `json:"remove,omitempty"`
}

type cancelOperationRequest struct {
	Reason string `json:"reason,omitempty"`
}

type operationPermissionEvidenceResponse struct {
	Required []string `json:"required"`
	Granted  []string `json:"granted"`
}

type operationConfirmationEvidenceResponse struct {
	Required       bool   `json:"required"`
	Confirmed      bool   `json:"confirmed"`
	ConfirmationID string `json:"confirmation_id,omitempty"`
	RequestSHA256  string `json:"request_sha256,omitempty"`
	PlanSHA256     string `json:"plan_sha256,omitempty"`
	TargetSHA256   string `json:"target_sha256,omitempty"`
}

type operationRevisionEvidenceResponse struct {
	PolicyRevision     uint64 `json:"policy_revision"`
	ManagementRevision uint64 `json:"management_revision"`
	RevokeEpoch        uint64 `json:"revoke_epoch"`
}

type operationQuotaResponse struct {
	MaxConcurrent  int        `json:"max_concurrent,omitempty"`
	MaxDurationMS  int        `json:"max_duration_ms,omitempty"`
	MaxStreamBytes int64      `json:"max_stream_bytes,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

type operationTargetResponse struct {
	Kind   string         `json:"kind"`
	Fields map[string]any `json:"fields"`
}

type operationResponse struct {
	OperationID             string                                `json:"operation_id"`
	InvocationID            string                                `json:"invocation_id"`
	AuditCorrelationID      string                                `json:"audit_correlation_id"`
	StreamID                string                                `json:"stream_id,omitempty"`
	PublisherID             string                                `json:"publisher_id"`
	PluginID                string                                `json:"plugin_id"`
	PluginInstanceID        string                                `json:"plugin_instance_id"`
	PluginVersion           string                                `json:"plugin_version"`
	ActiveFingerprint       string                                `json:"active_fingerprint"`
	SurfaceInstanceID       string                                `json:"surface_instance_id,omitempty"`
	RouteKind               string                                `json:"route_kind"`
	CapabilityID            string                                `json:"capability_id"`
	CapabilityVersion       string                                `json:"capability_version"`
	BindingID               string                                `json:"binding_id"`
	Contract                *capabilityPinResponse                `json:"contract,omitempty"`
	Method                  string                                `json:"method"`
	TargetMethod            string                                `json:"target_method"`
	Effect                  string                                `json:"effect"`
	Execution               string                                `json:"execution"`
	Permissions             operationPermissionEvidenceResponse   `json:"permissions"`
	Confirmation            operationConfirmationEvidenceResponse `json:"confirmation"`
	Revision                operationRevisionEvidenceResponse     `json:"revision"`
	Quota                   operationQuotaResponse                `json:"quota"`
	Target                  operationTargetResponse               `json:"target"`
	TargetDescriptorSHA256  string                                `json:"target_descriptor_sha256"`
	StreamEventTypeName     string                                `json:"stream_event_type_name,omitempty"`
	StreamEventSchemaSHA256 string                                `json:"stream_event_schema_sha256,omitempty"`
	Status                  string                                `json:"status"`
	Cancelable              bool                                  `json:"cancelable"`
	CancelAckTimeoutMS      int                                   `json:"cancel_ack_timeout_ms,omitempty"`
	DisableBehavior         string                                `json:"disable_behavior,omitempty"`
	UninstallBehavior       string                                `json:"uninstall_behavior,omitempty"`
	FailureCode             string                                `json:"failure_code,omitempty"`
	Reason                  string                                `json:"reason,omitempty"`
	CreatedAt               time.Time                             `json:"created_at"`
	UpdatedAt               time.Time                             `json:"updated_at"`
	CancelRequestedAt       *time.Time                            `json:"cancel_requested_at,omitempty"`
	OrphanedAt              *time.Time                            `json:"orphaned_at,omitempty"`
	TerminalAt              *time.Time                            `json:"terminal_at,omitempty"`
}

type operationListResponse struct {
	Operations []operationResponse `json:"operations"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

func publicOperationRecord(record operation.Record) (operationResponse, error) {
	binding := record.ExecutionBinding
	targetFields, err := cloneWireJSONMap(binding.Target.Fields)
	if err != nil {
		return operationResponse{}, err
	}
	var contract *capabilityPinResponse
	if binding.Contract != nil {
		mapped := publicCapabilityPin(*binding.Contract)
		contract = &mapped
	}
	var quotaExpiresAt *time.Time
	if !binding.Quota.ExpiresAt.IsZero() {
		quotaExpiresAt = cloneWireTime(&binding.Quota.ExpiresAt)
	}
	return operationResponse{
		OperationID: record.OperationID, InvocationID: binding.InvocationID, AuditCorrelationID: binding.AuditCorrelationID,
		StreamID: binding.StreamID, PublisherID: binding.PublisherID, PluginID: binding.PluginID,
		PluginInstanceID: binding.PluginInstanceID, PluginVersion: binding.PluginVersion, ActiveFingerprint: binding.ActiveFingerprint,
		SurfaceInstanceID: binding.SurfaceInstanceID, RouteKind: string(binding.RouteKind),
		CapabilityID: binding.CapabilityID, CapabilityVersion: binding.CapabilityVersion, BindingID: binding.BindingID,
		Contract: contract, Method: binding.Method, TargetMethod: binding.TargetMethod, Effect: string(binding.Effect),
		Execution: binding.Execution,
		Permissions: operationPermissionEvidenceResponse{
			Required: append([]string(nil), binding.Permissions.Required...), Granted: append([]string(nil), binding.Permissions.Granted...),
		},
		Confirmation: operationConfirmationEvidenceResponse{
			Required: binding.Confirmation.Required, Confirmed: binding.Confirmation.Confirmed,
			ConfirmationID: binding.Confirmation.ConfirmationID, RequestSHA256: binding.Confirmation.RequestSHA256,
			PlanSHA256: binding.Confirmation.PlanSHA256, TargetSHA256: binding.Confirmation.TargetSHA256,
		},
		Revision: operationRevisionEvidenceResponse{
			PolicyRevision: binding.Revision.PolicyRevision, ManagementRevision: binding.Revision.ManagementRevision,
			RevokeEpoch: binding.Revision.RevokeEpoch,
		},
		Quota: operationQuotaResponse{
			MaxConcurrent: binding.Quota.MaxConcurrent, MaxDurationMS: binding.Quota.MaxDurationMS,
			MaxStreamBytes: binding.Quota.MaxStreamBytes, ExpiresAt: quotaExpiresAt,
		},
		Target:                 operationTargetResponse{Kind: binding.Target.Kind, Fields: targetFields},
		TargetDescriptorSHA256: binding.TargetDescriptorSHA256,
		StreamEventTypeName:    binding.StreamEventTypeName, StreamEventSchemaSHA256: binding.StreamEventSchemaSHA256,
		Status: string(record.Status), Cancelable: record.Cancelable, CancelAckTimeoutMS: record.CancelAckTimeoutMS,
		DisableBehavior: record.DisableBehavior, UninstallBehavior: record.UninstallBehavior, FailureCode: string(record.FailureCode),
		Reason: record.Reason, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		CancelRequestedAt: cloneWireTime(record.CancelRequestedAt), OrphanedAt: cloneWireTime(record.OrphanedAt),
		TerminalAt: cloneWireTime(record.TerminalAt),
	}, nil
}

func publicOperationRecords(records []operation.Record) ([]operationResponse, error) {
	result := make([]operationResponse, len(records))
	for index, record := range records {
		mapped, err := publicOperationRecord(record)
		if err != nil {
			return nil, err
		}
		result[index] = mapped
	}
	return result, nil
}

type startRuntimeRequest struct {
	Target runtimeTargetRequest `json:"target"`
}

type runtimeTargetRequest struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type emptyRequest struct{}

func (*emptyRequest) UnmarshalJSON(raw []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return errors.New("request body must be an empty JSON object")
	}
	if object == nil || len(object) != 0 {
		return errors.New("request body must be an empty JSON object")
	}
	return nil
}

type optionalQueryString struct {
	value string
	set   bool
}

func (value *optionalQueryString) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("query string field must not be null")
	}
	var decoded string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return errors.New("query string field must be a string")
	}
	if decoded == "" || strings.TrimSpace(decoded) != decoded {
		return errors.New("query string field must be non-empty without surrounding whitespace")
	}
	value.value = decoded
	value.set = true
	return nil
}

func (value optionalQueryString) get() string {
	if !value.set {
		return ""
	}
	return value.value
}

type optionalQueryBool struct {
	value bool
	set   bool
}

func (value *optionalQueryBool) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("query boolean field must not be null")
	}
	if err := json.Unmarshal(raw, &value.value); err != nil {
		return errors.New("query boolean field must be a boolean")
	}
	value.set = true
	return nil
}

func (value optionalQueryBool) get() bool {
	return value.set && value.value
}

type optionalQueryInteger struct {
	value int
	set   bool
}

func (value *optionalQueryInteger) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("query integer field must not be null")
	}
	if err := json.Unmarshal(raw, &value.value); err != nil {
		return errors.New("query integer field must be an integer")
	}
	value.set = true
	return nil
}

func (value optionalQueryInteger) bounded(field string, minimum, maximum int) (int, error) {
	if !value.set {
		return 0, nil
	}
	if value.value < minimum || value.value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", field, minimum, maximum)
	}
	return value.value, nil
}

type listIntentsQueryRequest struct {
	IntentID         optionalQueryString `json:"intent_id"`
	PluginInstanceID optionalQueryString `json:"plugin_instance_id"`
}

type listOperationsQueryRequest struct {
	PluginInstanceID optionalQueryString  `json:"plugin_instance_id"`
	Cursor           optionalQueryString  `json:"cursor"`
	Limit            optionalQueryInteger `json:"limit"`
}

type listRetainedDataQueryRequest struct {
	PluginInstanceID optionalQueryString `json:"plugin_instance_id"`
}

type listPermissionsQueryRequest struct {
	PluginInstanceID optionalQueryString `json:"plugin_instance_id"`
	ActiveOnly       optionalQueryBool   `json:"active_only"`
}

type listDiagnosticsQueryRequest struct {
	PluginID          optionalQueryString  `json:"plugin_id"`
	PluginInstanceID  optionalQueryString  `json:"plugin_instance_id"`
	SurfaceInstanceID optionalQueryString  `json:"surface_instance_id"`
	Type              optionalQueryString  `json:"type"`
	Severity          optionalQueryString  `json:"severity"`
	Limit             optionalQueryInteger `json:"limit"`
}

type settingsQueryRequest struct {
	Scope sessionctx.ScopeKind `json:"scope"`
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

var routes = []routeSpec{
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/{plugin_instance_id}/local-import", websecurity.RouteActionImportLocalPackage, func(h *Handler) http.HandlerFunc { return h.handleImportLocalPackageUpload }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/install-release-ref", websecurity.RouteActionInstallReleaseRef, func(h *Handler) http.HandlerFunc { return h.handleInstallReleaseRef }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/enable", websecurity.RouteActionEnablePlugin, func(h *Handler) http.HandlerFunc { return h.handleEnable }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/disable", websecurity.RouteActionDisablePlugin, func(h *Handler) http.HandlerFunc { return h.handleDisable }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/uninstall", websecurity.RouteActionUninstallPlugin, func(h *Handler) http.HandlerFunc { return h.handleUninstall }),
	mutationRoute(http.MethodPut, "/_redevplugin/api/plugins/{plugin_instance_id}/local-import", websecurity.RouteActionUpdateLocalPackage, func(h *Handler) http.HandlerFunc { return h.handleUpdateLocalPackageUpload }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/update-release-ref", websecurity.RouteActionUpdateReleaseRef, func(h *Handler) http.HandlerFunc { return h.handleUpdateReleaseRef }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/downgrade", websecurity.RouteActionDowngradePlugin, func(h *Handler) http.HandlerFunc { return h.handleDowngrade }),
	queryRoute("/_redevplugin/api/plugins/catalog/query", websecurity.RouteActionListPlugins, func(h *Handler) http.HandlerFunc { return h.handleCatalog }),
	queryRoute("/_redevplugin/api/plugins/features/query", websecurity.RouteActionListFeatures, func(h *Handler) http.HandlerFunc { return h.handleFeatures }),
	queryRoute("/_redevplugin/api/plugins/platform/compatibility/query", websecurity.RouteActionGetCompatibility, func(h *Handler) http.HandlerFunc { return h.handleCompatibility }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/surfaces/open", websecurity.RouteActionOpenSurface, func(h *Handler) http.HandlerFunc { return h.handleOpenSurface }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/session/revoke-scope", websecurity.RouteActionRevokeSessionScope, func(h *Handler) http.HandlerFunc { return h.handleRevokeSessionScope }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/prepare", websecurity.RouteActionPrepareSurface, func(h *Handler) http.HandlerFunc { return h.handlePrepareSurface }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/bridge-token", websecurity.RouteActionMintBridgeToken, func(h *Handler) http.HandlerFunc { return h.handleBridgeToken }),
	queryRoute("/_redevplugin/api/plugins/surfaces/{surface_instance_id}/assets/read", websecurity.RouteActionReadSurfaceAsset, func(h *Handler) http.HandlerFunc { return h.handleReadSurfaceAsset }),
	queryRoute("/_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/read", websecurity.RouteActionReadSurfaceStream, func(h *Handler) http.HandlerFunc { return h.handleReadSurfaceStream }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/streams/ack", websecurity.RouteActionAcknowledgeSurfaceStream, func(h *Handler) http.HandlerFunc { return h.handleAcknowledgeSurfaceStream }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/operations/cancel", websecurity.RouteActionCancelSurfaceOperation, func(h *Handler) http.HandlerFunc { return h.handleCancelSurfaceOperation }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/confirmations/reject", websecurity.RouteActionRejectSurfaceConfirmation, func(h *Handler) http.HandlerFunc { return h.handleRejectSurfaceConfirmation }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/surfaces/{surface_instance_id}/dispose", websecurity.RouteActionDisposeSurface, func(h *Handler) http.HandlerFunc { return h.handleDisposeSurface }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/rpc", websecurity.RouteActionCallPluginMethod, func(h *Handler) http.HandlerFunc { return h.handleRPC }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/confirmations/prepare", websecurity.RouteActionPrepareMethodConfirmation, func(h *Handler) http.HandlerFunc { return h.handlePrepareMethodConfirmation }),
	queryRoute("/_redevplugin/api/plugins/intents/query", websecurity.RouteActionListIntents, func(h *Handler) http.HandlerFunc { return h.handleListIntents }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/intents/invoke", websecurity.RouteActionInvokeIntent, func(h *Handler) http.HandlerFunc { return h.handleInvokeIntent }),
	queryRoute("/_redevplugin/api/plugins/operations/query", websecurity.RouteActionListOperations, func(h *Handler) http.HandlerFunc { return h.handleListOperations }),
	queryRoute("/_redevplugin/api/plugins/operations/{operation_id}/query", websecurity.RouteActionGetOperation, func(h *Handler) http.HandlerFunc { return h.handleGetOperation }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/operations/{operation_id}/cancel", websecurity.RouteActionCancelOperation, func(h *Handler) http.HandlerFunc { return h.handleCancelOperation }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/runtime/start", websecurity.RouteActionStartRuntime, func(h *Handler) http.HandlerFunc { return h.handleStartRuntime }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/runtime/stop", websecurity.RouteActionStopRuntime, func(h *Handler) http.HandlerFunc { return h.handleStopRuntime }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/runtime/refresh-enabled", websecurity.RouteActionRefreshEnabledRuntimeState, func(h *Handler) http.HandlerFunc { return h.handleRefreshEnabledRuntimeState }),
	queryRoute("/_redevplugin/api/plugins/runtime/health/query", websecurity.RouteActionGetRuntimeHealth, func(h *Handler) http.HandlerFunc { return h.handleRuntimeHealth }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/data/export", websecurity.RouteActionExportData, func(h *Handler) http.HandlerFunc { return h.handleExportData }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/data/export/delete", websecurity.RouteActionDeleteDataExport, func(h *Handler) http.HandlerFunc { return h.handleDeleteDataExport }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/data/import", websecurity.RouteActionImportData, func(h *Handler) http.HandlerFunc { return h.handleImportData }),
	queryRoute("/_redevplugin/api/plugins/retained-data/query", websecurity.RouteActionListRetainedData, func(h *Handler) http.HandlerFunc { return h.handleListRetainedData }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/retained-data/delete", websecurity.RouteActionDeleteRetainedData, func(h *Handler) http.HandlerFunc { return h.handleDeleteRetainedData }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/retained-data/bind", websecurity.RouteActionBindRetainedData, func(h *Handler) http.HandlerFunc { return h.handleBindRetainedData }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/retained-data/cleanup-expired", websecurity.RouteActionCleanupExpiredRetainedData, func(h *Handler) http.HandlerFunc { return h.handleCleanupExpiredRetainedData }),
	queryRoute("/_redevplugin/api/plugins/permissions/query", websecurity.RouteActionListPermissions, func(h *Handler) http.HandlerFunc { return h.handleListPermissions }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/permissions/grant", websecurity.RouteActionGrantPermission, func(h *Handler) http.HandlerFunc { return h.handleGrantPermission }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/permissions/revoke", websecurity.RouteActionRevokePermission, func(h *Handler) http.HandlerFunc { return h.handleRevokePermission }),
	queryRoute("/_redevplugin/api/plugins/security-policies/query", websecurity.RouteActionListSecurityPolicies, func(h *Handler) http.HandlerFunc { return h.handleListSecurityPolicies }),
	queryRoute("/_redevplugin/api/plugins/security-policies/{plugin_instance_id}/query", websecurity.RouteActionGetSecurityPolicy, func(h *Handler) http.HandlerFunc { return h.handleGetSecurityPolicy }),
	mutationRoute(http.MethodPut, "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}", websecurity.RouteActionPutSecurityPolicy, func(h *Handler) http.HandlerFunc { return h.handlePutSecurityPolicy }),
	mutationRoute(http.MethodDelete, "/_redevplugin/api/plugins/security-policies/{plugin_instance_id}", websecurity.RouteActionDeleteSecurityPolicy, func(h *Handler) http.HandlerFunc { return h.handleDeleteSecurityPolicy }),
	queryRoute("/_redevplugin/api/plugins/diagnostics/query", websecurity.RouteActionListDiagnostics, func(h *Handler) http.HandlerFunc { return h.handleListDiagnostics }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/secrets/bind", websecurity.RouteActionBindSecret, func(h *Handler) http.HandlerFunc { return h.handleBindSecret }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/secrets/test", websecurity.RouteActionTestSecret, func(h *Handler) http.HandlerFunc { return h.handleTestSecret }),
	mutationRoute(http.MethodPost, "/_redevplugin/api/plugins/secrets/delete", websecurity.RouteActionDeleteSecret, func(h *Handler) http.HandlerFunc { return h.handleDeleteSecret }),
	queryRoute("/_redevplugin/api/plugins/{plugin_instance_id}/settings/schema/query", websecurity.RouteActionGetSettingsSchema, func(h *Handler) http.HandlerFunc { return h.handleGetSettingsSchema }),
	queryRoute("/_redevplugin/api/plugins/{plugin_instance_id}/settings/query", websecurity.RouteActionGetSettings, func(h *Handler) http.HandlerFunc { return h.handleGetSettings }),
	mutationRoute(http.MethodPatch, "/_redevplugin/api/plugins/{plugin_instance_id}/settings", websecurity.RouteActionPatchSettings, func(h *Handler) http.HandlerFunc { return h.handlePatchSettings }),
}

func NewHandler(deps Dependencies) (*Handler, error) {
	if deps.Host == nil {
		return nil, &host.HostConfigError{Module: "http", Adapter: "host"}
	}
	if isNilInterfaceValue(deps.Guard) {
		return nil, &host.HostConfigError{Module: "http", Adapter: "web security guard"}
	}
	for _, route := range routes {
		if err := route.validate(); err != nil {
			return nil, fmt.Errorf("invalid HTTP route security contract for %s %s: %w", route.Method, route.Path, err)
		}
	}
	h := &Handler{host: deps.Host, guard: deps.Guard, mux: http.NewServeMux()}
	for _, route := range routes {
		if !strings.Contains(route.Path, "{") {
			h.mux.HandleFunc(route.Method+" "+route.Path, h.bindRoute(route))
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		method := method
		h.mux.HandleFunc(method+" /_redevplugin/api/plugins/", func(w http.ResponseWriter, r *http.Request) {
			for _, route := range routes {
				if route.Method == method && strings.Contains(route.Path, "{") && routePathMatches(route.Path, r.URL.Path) {
					h.bindRoute(route)(w, r)
					return
				}
			}
			writeError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{})
		})
	}
	h.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{})
	})
	return h, nil
}

func isNilInterfaceValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (h *Handler) bindRoute(route routeSpec) http.HandlerFunc {
	routeHandler := *h
	routeHandler.routeEffect = route.Effect
	handler := route.bind(&routeHandler)
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := h.authorizeRouteRequest(w, r, route)
		if !ok {
			return
		}
		r = r.WithContext(sessionctx.WithContext(r.Context(), session))
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			err := errors.New("URL query parameters are not allowed")
			if route.Effect == websecurity.RouteEffectMutation {
				writeMutationInvalidRequestError(w, err)
			} else {
				writeInvalidRequestError(w, err)
			}
			return
		}
		handler(w, r)
	}
}

func (h *Handler) authorizeRouteRequest(w http.ResponseWriter, r *http.Request, route routeSpec) (sessionctx.Context, bool) {
	session, err := h.guard.Authenticate(r)
	if err != nil {
		h.rejectGuardRequest(w, r, route.Effect, "authenticate", security.ErrPermissionDenied, err)
		return sessionctx.Context{}, false
	}
	if !session.Valid() {
		h.rejectGuardRequest(w, r, route.Effect, "authenticate", security.ErrPermissionDenied, sessionctx.ErrSessionRequired)
		return sessionctx.Context{}, false
	}
	if err := h.guard.ValidateOrigin(r, session, route.originPolicy); err != nil {
		h.rejectGuardRequest(w, r, route.Effect, "validate_origin", security.ErrOriginDenied, err)
		return sessionctx.Context{}, false
	}
	if err := h.guard.ValidateCSRF(r, session, route.csrfPolicy); err != nil {
		code := security.ErrCSRFRequired
		if errors.Is(err, websecurity.ErrCSRFInvalid) {
			code = security.ErrCSRFInvalid
		}
		h.rejectGuardRequest(w, r, route.Effect, "validate_csrf", code, err)
		return sessionctx.Context{}, false
	}
	if err := h.guard.AuthorizeRoute(r, session, route.action, route.Effect); err != nil {
		h.rejectGuardRequest(w, r, route.Effect, "authorize_route", security.ErrActionDenied, err)
		return sessionctx.Context{}, false
	}
	return session, true
}

func (h *Handler) rejectGuardRequest(w http.ResponseWriter, r *http.Request, effect websecurity.RouteEffect, operation string, code security.ErrorCode, err error) {
	h.host.ReportHTTPAdapterFailure(r.Context(), operation, code, err)
	writeRequestErrorForEffect(w, effect, http.StatusForbidden, code, publicPluginErrorMessage(code), errorDetails{})
}

func routePathMatches(pattern, requestPath string) bool {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	requestParts := strings.Split(strings.Trim(requestPath, "/"), "/")
	if len(patternParts) != len(requestParts) {
		return false
	}
	for index := range patternParts {
		part := patternParts[index]
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if requestParts[index] == "" {
				return false
			}
			continue
		}
		if part != requestParts[index] {
			return false
		}
	}
	return true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/_redevplugin/") {
		writeError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{})
		return
	}
	h.mux.ServeHTTP(w, r)
}

func writeRequestErrorForEffect(w http.ResponseWriter, effect websecurity.RouteEffect, status int, code security.ErrorCode, message string, details errorDetails) {
	if effect != websecurity.RouteEffectQuery {
		writeMutationError(w, status, code, message, details, mutation.OutcomeNotCommitted)
		return
	}
	writeError(w, status, code, message, details)
}

func (h Handler) hasMutationEffect() bool {
	return h.routeEffect != websecurity.RouteEffectQuery
}

func (h Handler) handleCancelSurfaceOperation(w http.ResponseWriter, r *http.Request) {
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/operations/cancel")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req cancelSurfaceOperationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	record, err := h.host.CancelSurfaceOperation(r.Context(), host.CancelSurfaceOperationRequest{
		OperationID: req.OperationID, SurfaceInstanceID: surfaceInstanceID,
		BridgeChannelID: req.BridgeChannelID, Reason: req.Reason,
	})
	if err != nil {
		writeMutationError(w, httpStatusForOperationError(err), errorCodeForOperationError(err), publicPluginErrorMessage(errorCodeForOperationError(err)), errorDetails{}, mutation.ForError(err))
		return
	}
	response, err := publicOperationRecord(record)
	if err != nil {
		h.writeProjectionError(w, r, "surface.operation.cancel.response", err)
		return
	}
	writeMutationSuccess(w, response)
}

func (h Handler) handleRejectSurfaceConfirmation(w http.ResponseWriter, r *http.Request) {
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/confirmations/reject")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req rejectSurfaceConfirmationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.RejectMethodConfirmation(r.Context(), host.RejectMethodConfirmationRequest{
		PluginInstanceID:  req.PluginInstanceID,
		SurfaceInstanceID: surfaceInstanceID,
		BridgeChannelID:   req.BridgeChannelID,
		GatewayToken:      req.GatewayToken,
		ConfirmationID:    req.ConfirmationID,
	})
	if err != nil {
		code := errorCodeForRPCError(err)
		h.writeRPCMutationError(w, r, "surface.confirmation.reject", httpStatusForRPCError(err), code, publicPluginErrorMessage(code), err)
		return
	}
	writeMutationSuccess(w, confirmationRejectionResponse{Rejected: result.Rejected})
}

func RouteSet() []Route {
	result := make([]Route, 0, len(routes))
	for _, route := range routes {
		result = append(result, route.Route)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path == result[j].Path {
			return result[i].Method < result[j].Method
		}
		return result[i].Path < result[j].Path
	})
	return result
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	var encoded []byte
	var err error
	if responseStatusMatchesPayload(status, payload) {
		encoded, err = json.Marshal(payload)
	} else {
		err = errors.New("HTTP status does not match platform response envelope")
	}
	if err != nil {
		status = http.StatusInternalServerError
		switch payload.(type) {
		case mutationSuccessResponse, mutationErrorResponse:
			encoded = []byte(`{"ok":false,"error":{"code":"PLUGIN_CONTRACT_MISMATCH","message":"plugin platform response encoding failed","details":{},"mutation_outcome":"unknown"}}`)
		default:
			encoded = []byte(`{"ok":false,"error":{"code":"PLUGIN_CONTRACT_MISMATCH","message":"plugin platform response encoding failed","details":{}}}`)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(append(encoded, '\n'))
}

func responseStatusMatchesPayload(status int, payload any) bool {
	switch payload.(type) {
	case successResponse, mutationSuccessResponse:
		return status == http.StatusOK
	case errorResponse, mutationErrorResponse:
		return status >= http.StatusBadRequest && status <= 599
	default:
		return false
	}
}

func writeError(w http.ResponseWriter, status int, code security.ErrorCode, message string, details errorDetails) {
	writeJSON(w, status, errorResponse{
		OK:      false,
		Code:    code,
		Message: message,
		Details: details,
	})
}

func writeMutationError(w http.ResponseWriter, status int, code security.ErrorCode, message string, details errorDetails, outcome mutation.Outcome) {
	writeJSON(w, status, mutationErrorResponse{
		OK:              false,
		Code:            code,
		Message:         message,
		Details:         details,
		MutationOutcome: outcome,
	})
}

func writeMutationSuccess(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, mutationSuccessResponse{OK: true, Data: data})
}

func (h Handler) writeProjectionError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	message := h.publicFailureMessage(r.Context(), operation, security.ErrAdapterFailure, err)
	if h.hasMutationEffect() {
		writeMutationError(w, http.StatusBadGateway, security.ErrAdapterFailure, message, errorDetails{}, mutation.OutcomeUnknown)
		return
	}
	writeJSON(w, http.StatusBadGateway, errorResponse{
		OK: false, Message: message, Code: security.ErrAdapterFailure,
	})
}

func (h Handler) writeRPCMutationError(w http.ResponseWriter, r *http.Request, operation string, status int, code security.ErrorCode, message string, err error) {
	details, projectionErr := errorDetailsForRPCError(err)
	if projectionErr != nil {
		h.writeProjectionError(w, r, operation+".error_details", projectionErr)
		return
	}
	writeMutationError(w, status, code, message, details, mutation.ForError(err))
}

func (h Handler) writePluginMutationSuccess(w http.ResponseWriter, r *http.Request, operation string, record registry.PluginRecord) {
	response, err := publicPluginRecord(record)
	if err != nil {
		h.writeProjectionError(w, r, operation, err)
		return
	}
	writeMutationSuccess(w, response)
}

func writeInvalidRequestError(w http.ResponseWriter, err error) {
	var limitErr *jsonLimitError
	if errors.As(err, &limitErr) {
		writeJSON(w, limitErr.status(), errorResponse{
			OK:      false,
			Message: publicPluginErrorMessage(security.ErrJSONLimitExceeded),
			Code:    security.ErrJSONLimitExceeded,
			Details: errorDetails{Reason: string(limitErr.reason)},
		})
		return
	}
	writeJSON(w, http.StatusBadRequest, errorResponse{OK: false, Message: publicPluginErrorMessage(security.ErrInvalidRequest), Code: security.ErrInvalidRequest})
}

func writeMutationInvalidRequestError(w http.ResponseWriter, err error) {
	var limitErr *jsonLimitError
	if errors.As(err, &limitErr) {
		writeMutationError(w, limitErr.status(), security.ErrJSONLimitExceeded, publicPluginErrorMessage(security.ErrJSONLimitExceeded), errorDetails{Reason: string(limitErr.reason)}, mutation.OutcomeNotCommitted)
		return
	}
	writeMutationError(w, http.StatusBadRequest, security.ErrInvalidRequest, publicPluginErrorMessage(security.ErrInvalidRequest), errorDetails{}, mutation.OutcomeNotCommitted)
}

func requireExpectedManagementRevision(w http.ResponseWriter, value *uint64) (uint64, bool) {
	if value == nil || *value == 0 || *value > uint64(maxJSONSafeInteger) {
		writeMutationError(w, http.StatusBadRequest, security.ErrInvalidRequest, "expected_management_revision must be a positive safe integer", errorDetails{}, mutation.OutcomeNotCommitted)
		return 0, false
	}
	return *value, true
}

func requiredRevision(value *uint64, field string) (uint64, error) {
	if value == nil || *value == 0 || *value > uint64(maxJSONSafeInteger) {
		return 0, fmt.Errorf("%s must be a positive safe integer", field)
	}
	return *value, nil
}

const localImportContentType = "application/vnd.redevplugin.package+zip"
const localImportRevisionHeader = "X-ReDevPlugin-Expected-Management-Revision"
const maxLocalImportBytes int64 = 256 << 20

func (h Handler) handleImportLocalPackageUpload(w http.ResponseWriter, r *http.Request) {
	pluginInstanceID, ok := pluginInstanceIDFromPath(r.URL.Path, "/local-import")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	if len(r.Header.Values(localImportRevisionHeader)) != 0 {
		writeMutationInvalidRequestError(w, errors.New("expected management revision is not allowed for an install"))
		return
	}
	if err := requirePackageContentType(r); err != nil {
		writeMutationError(w, http.StatusUnsupportedMediaType, security.ErrInvalidRequest, err.Error(), errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	file, size, cleanup, err := stagePackageUpload(r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errPackageUploadTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeMutationError(w, status, security.ErrInvalidRequest, err.Error(), errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	defer cleanup()
	record, err := h.host.ImportLocalPackage(r.Context(), host.ImportLocalPackageRequest{
		PackageReader: file, PackageSize: size,
		PluginInstanceID: pluginInstanceID,
	})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "local-import.install", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "local-import.install.response", record)
}

func (h Handler) handleInstallReleaseRef(w http.ResponseWriter, r *http.Request) {
	var req installReleaseRefRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	if req.PluginInstanceID == "" {
		writeMutationInvalidRequestError(w, errors.New("plugin_instance_id is required"))
		return
	}
	record, err := h.host.InstallReleaseRef(r.Context(), host.InstallReleaseRefRequest{
		ReleaseRef:       req.ReleaseRef.domain(),
		PluginInstanceID: req.PluginInstanceID,
	})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "release.install", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "release.install.response", record)
}

func (h Handler) handleEnable(w http.ResponseWriter, r *http.Request) {
	var req enableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedManagementRevision, ok := requireExpectedManagementRevision(w, req.ExpectedManagementRevision)
	if !ok {
		return
	}
	record, err := h.host.EnablePlugin(r.Context(), host.EnableRequest{PluginInstanceID: req.PluginInstanceID, ExpectedManagementRevision: expectedManagementRevision})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "plugin.enable", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "plugin.enable.response", record)
}

func (h Handler) handleDisable(w http.ResponseWriter, r *http.Request) {
	var req disableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedManagementRevision, ok := requireExpectedManagementRevision(w, req.ExpectedManagementRevision)
	if !ok {
		return
	}
	record, err := h.host.DisablePlugin(r.Context(), host.DisableRequest{PluginInstanceID: req.PluginInstanceID, ExpectedManagementRevision: expectedManagementRevision, Reason: req.Reason})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "plugin.disable", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "plugin.disable.response", record)
}

func (h Handler) handleUninstall(w http.ResponseWriter, r *http.Request) {
	var req uninstallRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedManagementRevision, ok := requireExpectedManagementRevision(w, req.ExpectedManagementRevision)
	if !ok {
		return
	}
	record, err := h.host.UninstallPlugin(r.Context(), host.UninstallRequest{PluginInstanceID: req.PluginInstanceID, ExpectedManagementRevision: expectedManagementRevision, DeleteData: req.DeleteData})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "plugin.uninstall", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "plugin.uninstall.response", record)
}

func (h Handler) handleUpdateLocalPackageUpload(w http.ResponseWriter, r *http.Request) {
	pluginInstanceID, ok := pluginInstanceIDFromPath(r.URL.Path, "/local-import")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	revision, err := requiredLocalImportRevision(r.Header)
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := requirePackageContentType(r); err != nil {
		writeMutationError(w, http.StatusUnsupportedMediaType, security.ErrInvalidRequest, err.Error(), errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	file, size, cleanup, err := stagePackageUpload(r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errPackageUploadTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeMutationError(w, status, security.ErrInvalidRequest, err.Error(), errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	defer cleanup()
	record, err := h.host.UpdateLocalPackage(r.Context(), host.UpdateLocalPackageRequest{
		PluginInstanceID:           pluginInstanceID,
		ExpectedManagementRevision: revision, PackageReader: file, PackageSize: size,
	})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "local-import.update", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "local-import.update.response", record)
}

func requiredLocalImportRevision(header http.Header) (uint64, error) {
	values := header.Values(localImportRevisionHeader)
	if len(values) != 1 {
		return 0, errors.New("expected management revision header must be provided exactly once")
	}
	value := values[0]
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, ",") {
		return 0, errors.New("expected management revision header must be one canonical decimal value")
	}
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil || revision == 0 || revision > uint64(maxJSONSafeInteger) || strconv.FormatUint(revision, 10) != value {
		return 0, errors.New("expected management revision header must be a positive safe integer")
	}
	return revision, nil
}

var errPackageUploadTooLarge = errors.New("package upload exceeds the maximum compressed size")

func requirePackageContentType(r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != localImportContentType {
		return fmt.Errorf("content type must be %s", localImportContentType)
	}
	if r.ContentLength == 0 {
		return errors.New("package upload body is required")
	}
	if r.ContentLength > maxLocalImportBytes {
		return errPackageUploadTooLarge
	}
	return nil
}

func stagePackageUpload(r *http.Request) (*os.File, int64, func(), error) {
	tmp, err := os.CreateTemp("", "redevplugin-package-*")
	if err != nil {
		return nil, 0, func() {}, err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, 0, func() {}, err
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}
	var total int64
	buf := make([]byte, 32*1024)
	for {
		if err := r.Context().Err(); err != nil {
			cleanup()
			return nil, 0, func() {}, err
		}
		n, readErr := r.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxLocalImportBytes {
				cleanup()
				return nil, 0, func() {}, errPackageUploadTooLarge
			}
			if _, err := tmp.Write(buf[:n]); err != nil {
				cleanup()
				return nil, 0, func() {}, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			cleanup()
			return nil, 0, func() {}, readErr
		}
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, func() {}, err
	}
	return tmp, total, cleanup, nil
}

func (h Handler) handleUpdateReleaseRef(w http.ResponseWriter, r *http.Request) {
	var req updateReleaseRefRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedManagementRevision, ok := requireExpectedManagementRevision(w, req.ExpectedManagementRevision)
	if !ok {
		return
	}
	record, err := h.host.UpdateReleaseRef(r.Context(), host.UpdateReleaseRefRequest{
		PluginInstanceID:           req.PluginInstanceID,
		ExpectedManagementRevision: expectedManagementRevision,
		ReleaseRef:                 req.ReleaseRef.domain(),
	})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "release.update", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "release.update.response", record)
}

func (h Handler) handleDowngrade(w http.ResponseWriter, r *http.Request) {
	var req downgradeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedManagementRevision, ok := requireExpectedManagementRevision(w, req.ExpectedManagementRevision)
	if !ok {
		return
	}
	record, err := h.host.DowngradePlugin(r.Context(), host.DowngradeRequest{
		PluginInstanceID:           req.PluginInstanceID,
		ExpectedManagementRevision: expectedManagementRevision,
		Version:                    req.Version,
		PackageHash:                req.PackageHash,
	})
	if err != nil {
		code := errorCodeForManagementError(err)
		writeMutationError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "plugin.downgrade", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "plugin.downgrade.response", record)
}

func (h Handler) handleCatalog(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	records, err := h.host.ListPlugins(r.Context())
	if err != nil {
		code := errorCodeForManagementError(err)
		writeError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "plugin.catalog", code, err), errorDetails{})
		return
	}
	plugins, err := publicPluginRecords(records)
	if err != nil {
		h.writeProjectionError(w, r, "plugin.catalog.response", err)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: pluginCatalogResponse{Plugins: plugins}})
}

func (h Handler) handleFeatures(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	features, err := h.host.Features(r.Context())
	if err != nil {
		code := errorCodeForManagementError(err)
		writeError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "platform.list_features", code, err), errorDetails{})
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: publicFeatures(features)})
}

func (h Handler) handleCompatibility(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	compatibility, err := h.host.GetCompatibility(r.Context())
	if err != nil {
		code := errorCodeForManagementError(err)
		writeError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "platform.get_compatibility", code, err), errorDetails{})
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: publicCompatibility(compatibility)})
}

func (h Handler) handleOpenSurface(w http.ResponseWriter, r *http.Request) {
	var req openSurfaceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedManagementRevision, ok := requireExpectedManagementRevision(w, req.ExpectedManagementRevision)
	if !ok {
		return
	}
	bootstrap, err := h.host.OpenSurface(r.Context(), host.OpenSurfaceRequest{
		PluginInstanceID:           req.PluginInstanceID,
		ExpectedManagementRevision: expectedManagementRevision,
		SurfaceID:                  req.SurfaceID,
		SurfaceInstanceID:          req.SurfaceInstanceID,
	})
	if err != nil {
		code := errorCodeForOpenSurfaceError(err)
		writeMutationError(w, httpStatusForOpenSurfaceError(err), code, h.publicFailureMessage(r.Context(), "surface.open", code, err), errorDetailsForManagementError(err), mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicSurfaceBootstrap(bootstrap))
}

func (h Handler) handlePrepareSurface(w http.ResponseWriter, r *http.Request) {
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/prepare")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req prepareSurfaceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.PrepareSurface(r.Context(), host.PrepareSurfaceRequest{
		SurfaceInstanceID: surfaceInstanceID,
		AssetTicket:       req.AssetTicket,
	})
	if err != nil {
		code := errorCodeForAssetError(err)
		writeMutationError(w, httpStatusForAssetError(err), code, h.publicFailureMessage(r.Context(), "surface.prepare", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicSurfacePreparation(result))
}

func (h Handler) handleBridgeToken(w http.ResponseWriter, r *http.Request) {
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/bridge-token")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req bridgeTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if req.Handshake.Type != pluginBridgeHandshakeType {
		writeMutationError(w, http.StatusBadRequest, security.ErrInvalidRequest, "handshake type is invalid", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	if req.Handshake.SurfaceInstanceID != surfaceInstanceID {
		writeMutationError(w, http.StatusBadRequest, security.ErrInvalidRequest, "surface_instance_id mismatch", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	result, err := h.host.MintBridgeToken(r.Context(), host.MintBridgeTokenRequest{
		Handshake:                 bridgeHandshake(req.Handshake),
		BridgeChannelID:           req.BridgeChannelID,
		HandshakeTranscriptSHA256: req.HandshakeTranscriptSHA256,
		PreviousGatewayToken:      req.PreviousGatewayToken,
	})
	if err != nil {
		code := errorCodeForBridgeTokenError(err, req.PreviousGatewayToken != "")
		writeMutationError(w, http.StatusForbidden, code, h.publicFailureMessage(r.Context(), "surface.bridge-token", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicBridgeToken(result))
}

func bridgeHandshake(handshake pluginBridgeHandshake) bridge.Handshake {
	return bridge.Handshake{
		PluginID:           handshake.PluginID,
		SurfaceID:          handshake.SurfaceID,
		SurfaceInstanceID:  handshake.SurfaceInstanceID,
		ActiveFingerprint:  handshake.ActiveFingerprint,
		BridgeNonce:        handshake.BridgeNonce,
		AssetSessionNonce:  handshake.AssetSessionNonce,
		ManagementRevision: handshake.ManagementRevision,
		RevokeEpoch:        handshake.RevokeEpoch,
		UIProtocolVersion:  handshake.UIProtocolVersion,
	}
}

func (h Handler) handleReadSurfaceAsset(w http.ResponseWriter, r *http.Request) {
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/assets/read")
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{OK: false, Message: "route not found", Code: security.ErrInvalidRequest})
		return
	}
	var req readSurfaceAssetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	result, err := h.host.ReadSurfaceAsset(r.Context(), host.ReadSurfaceAssetRequest{
		SurfaceInstanceID: surfaceInstanceID,
		AssetSession:      req.AssetSession,
		AssetSessionID:    req.AssetSessionID,
		BindingID:         req.BindingID,
	})
	if err != nil {
		code := errorCodeForAssetError(err)
		writeJSON(w, httpStatusForAssetError(err), errorResponse{OK: false, Message: h.publicFailureMessage(r.Context(), "surface.asset.read", code, err), Code: code})
		return
	}
	if result.Session.SurfaceInstanceID != surfaceInstanceID {
		code := errorCodeForAssetError(bridge.ErrTokenAudience)
		writeJSON(w, http.StatusForbidden, errorResponse{OK: false, Message: publicPluginErrorMessage(code), Code: code})
		return
	}
	contentType := result.Entry.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: surfaceAssetResponse{
		Path: result.Entry.Path, SHA256: result.Entry.SHA256, ContentType: contentType,
		ContentBase64: base64.StdEncoding.EncodeToString(result.Content),
	}})
}

func (h Handler) handleReadSurfaceStream(w http.ResponseWriter, r *http.Request) {
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/streams/read")
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{OK: false, Message: "route not found", Code: security.ErrInvalidRequest})
		return
	}
	var req readSurfaceStreamRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	result, err := h.host.ReadStream(r.Context(), host.ReadStreamRequest{
		StreamID:          req.StreamID,
		StreamTicket:      req.StreamTicket,
		ReadID:            req.ReadID,
		SurfaceInstanceID: surfaceInstanceID,
		MaxEvents:         defaultStreamReadMaxEvents,
		MaxBytes:          defaultStreamReadMaxBytes,
		WaitTimeout:       defaultStreamReadWaitTimeout,
	})
	if err != nil {
		code := errorCodeForStreamError(err)
		writeJSON(w, httpStatusForStreamError(err), errorResponse{OK: false, Message: publicPluginErrorMessage(code), Code: code})
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: publicSurfaceStream(result)})
}

func (h Handler) handleAcknowledgeSurfaceStream(w http.ResponseWriter, r *http.Request) {
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/streams/ack")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req acknowledgeSurfaceStreamRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if _, err := h.host.AcknowledgeStream(r.Context(), host.AcknowledgeStreamRequest{
		StreamID: req.StreamID, StreamTicket: req.StreamTicket,
		DeliveryID: req.DeliveryID, SurfaceInstanceID: surfaceInstanceID,
	}); err != nil {
		code := errorCodeForStreamError(err)
		writeMutationError(w, httpStatusForStreamError(err), code, publicPluginErrorMessage(code), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, acknowledgementResponse{Acknowledged: true})
}

func (h Handler) handleDisposeSurface(w http.ResponseWriter, r *http.Request) {
	surfaceInstanceID, ok := surfaceInstanceIDFromPath(r.URL.Path, "/dispose")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req disposeSurfaceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := h.host.DisposeSurface(r.Context(), host.DisposeSurfaceRequest{
		SurfaceInstanceID: surfaceInstanceID,
		BridgeNonce:       req.BridgeNonce,
	}); err != nil {
		code := errorCodeForBridgeError(err)
		writeMutationError(w, httpStatusForBridgeError(err), code, h.publicFailureMessage(r.Context(), "surface.dispose", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, surfaceDisposeResponse{Disposed: true})
}

func (h Handler) handleRevokeSessionScope(w http.ResponseWriter, r *http.Request) {
	if err := decodeClosedJSONObject(r); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.RevokeSessionScope(r.Context(), host.RevokeSessionScopeRequest{})
	if err != nil {
		code, status := sessionScopeRevokeError(err)
		details := errorDetails{}
		if code == security.ErrSessionTeardownIncomplete {
			response := publicSessionScopeRevocation(result)
			details.SessionScope = &response
		}
		writeMutationError(w, status, code, h.publicFailureMessage(r.Context(), "session.revoke_scope", code, err), details, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicSessionScopeRevocation(result))
}

func sessionScopeRevokeError(err error) (security.ErrorCode, int) {
	switch {
	case errors.Is(err, host.ErrSessionTeardownIncomplete):
		return security.ErrSessionTeardownIncomplete, http.StatusServiceUnavailable
	case errors.Is(err, sessionscope.ErrFenceCapacity):
		return security.ErrSessionFenceCapacity, http.StatusServiceUnavailable
	case errors.Is(err, sessionscope.ErrSessionRevoked):
		return security.ErrSessionRevoked, http.StatusGone
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied, http.StatusForbidden
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure, http.StatusBadGateway
	default:
		return security.ErrAdapterFailure, http.StatusInternalServerError
	}
}

func (h Handler) handleRPC(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.CallPluginMethod(r.Context(), host.CallMethodRequest{
		PluginInstanceID:  req.PluginInstanceID,
		SurfaceInstanceID: req.SurfaceInstanceID,
		BridgeChannelID:   req.BridgeChannelID,
		GatewayToken:      req.GatewayToken,
		ConfirmationID:    req.ConfirmationID,
		Method:            req.Method,
		Params:            req.Params,
	})
	if err != nil {
		code := errorCodeForRPCError(err)
		h.writeRPCMutationError(w, r, "rpc", httpStatusForRPCError(err), code, publicPluginErrorMessage(code), err)
		return
	}
	response, err := publicCallMethod(result)
	if err != nil {
		h.writeProjectionError(w, r, "rpc.response", err)
		return
	}
	writeMutationSuccess(w, response)
}

func (h Handler) handlePrepareMethodConfirmation(w http.ResponseWriter, r *http.Request) {
	var req prepareMethodConfirmationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.PrepareMethodConfirmation(r.Context(), host.PrepareMethodConfirmationRequest{
		PluginInstanceID:  req.PluginInstanceID,
		SurfaceInstanceID: req.SurfaceInstanceID,
		BridgeChannelID:   req.BridgeChannelID,
		GatewayToken:      req.GatewayToken,
		Method:            req.Method,
		Params:            req.Params,
	})
	if err != nil {
		code := errorCodeForRPCError(err)
		h.writeRPCMutationError(w, r, "confirmation.prepare", httpStatusForRPCError(err), code, publicPluginErrorMessage(code), err)
		return
	}
	response, err := publicConfirmationPreparation(result)
	if err != nil {
		h.writeProjectionError(w, r, "confirmation.prepare.response", err)
		return
	}
	writeMutationSuccess(w, response)
}

func (h Handler) handleListIntents(w http.ResponseWriter, r *http.Request) {
	var req listIntentsQueryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	records, err := h.host.ListIntents(r.Context(), host.ListIntentsRequest{
		IntentID:         req.IntentID.get(),
		PluginInstanceID: req.PluginInstanceID.get(),
	})
	if err != nil {
		code := errorCodeForIntentError(err)
		writeJSON(w, httpStatusForIntentError(err), errorResponse{OK: false, Message: publicPluginErrorMessage(code), Code: code})
		return
	}
	response, err := publicIntents(records)
	if err != nil {
		h.writeProjectionError(w, r, "intent.list.response", err)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: response})
}

func (h Handler) handleInvokeIntent(w http.ResponseWriter, r *http.Request) {
	var req invokeIntentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.InvokeIntent(r.Context(), host.InvokeIntentRequest{
		PluginInstanceID: req.PluginInstanceID,
		IntentID:         req.IntentID,
		Params:           req.Params,
	})
	if err != nil {
		code := errorCodeForIntentError(err)
		h.writeRPCMutationError(w, r, "intent.invoke", httpStatusForIntentError(err), code, publicPluginErrorMessage(code), err)
		return
	}
	response, err := publicCallMethod(result)
	if err != nil {
		h.writeProjectionError(w, r, "intent.invoke.response", err)
		return
	}
	writeMutationSuccess(w, response)
}

func (h Handler) handleListOperations(w http.ResponseWriter, r *http.Request) {
	var req listOperationsQueryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	limit, err := req.Limit.bounded("limit", 1, operation.MaxListLimit)
	if err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	result, err := h.host.ListOperations(r.Context(), host.ListOperationsRequest{
		PluginInstanceID: req.PluginInstanceID.get(),
		Cursor:           req.Cursor.get(),
		Limit:            limit,
	})
	if err != nil {
		code := errorCodeForOperationError(err)
		writeJSON(w, httpStatusForOperationError(err), errorResponse{OK: false, Message: h.publicFailureMessage(r.Context(), "operation.list", code, err), Code: code})
		return
	}
	operations, err := publicOperationRecords(result.Operations)
	if err != nil {
		h.writeProjectionError(w, r, "operation.list.response", err)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: operationListResponse{
		Operations: operations,
		NextCursor: result.NextCursor,
	}})
}

func (h Handler) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	operationID, ok := operationIDFromPath(r.URL.Path, "/query")
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{OK: false, Message: "route not found", Code: security.ErrInvalidRequest})
		return
	}
	record, err := h.host.GetOperation(r.Context(), operationID)
	if err != nil {
		code := errorCodeForOperationError(err)
		writeJSON(w, httpStatusForOperationError(err), errorResponse{OK: false, Message: h.publicFailureMessage(r.Context(), "operation.get", code, err), Code: code})
		return
	}
	response, err := publicOperationRecord(record)
	if err != nil {
		h.writeProjectionError(w, r, "operation.get.response", err)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: response})
}

func (h Handler) handleCancelOperation(w http.ResponseWriter, r *http.Request) {
	operationID, ok := operationIDFromPath(r.URL.Path, "/cancel")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req cancelOperationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	record, err := h.host.CancelOperation(r.Context(), host.CancelOperationRequest{
		OperationID: operationID,
		Reason:      req.Reason,
	})
	if err != nil {
		code := errorCodeForOperationError(err)
		writeMutationError(w, httpStatusForOperationError(err), code, h.publicFailureMessage(r.Context(), "operation.cancel", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	response, err := publicOperationRecord(record)
	if err != nil {
		h.writeProjectionError(w, r, "operation.cancel.response", err)
		return
	}
	writeMutationSuccess(w, response)
}

func (h Handler) handleStartRuntime(w http.ResponseWriter, r *http.Request) {
	var req startRuntimeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	target, err := runtimetarget.FromParts(req.Target.OS, req.Target.Arch)
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	health, err := h.host.StartRuntime(r.Context(), host.StartRuntimeRequest{Target: target})
	if err != nil {
		code, status := runtimeManagementError(err)
		writeMutationError(w, status, code, h.publicFailureMessage(r.Context(), "runtime.start", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicRuntimeHealth(health))
}

func (h Handler) handleStopRuntime(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := h.host.StopRuntime(r.Context()); err != nil {
		code, status := runtimeManagementError(err)
		writeMutationError(w, status, code, h.publicFailureMessage(r.Context(), "runtime.stop", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, runtimeStopResponse{Stopped: true})
}

func (h Handler) handleRuntimeHealth(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	health, err := h.host.RuntimeHealth(r.Context())
	if err != nil {
		code, status := runtimeManagementError(err)
		writeJSON(w, status, errorResponse{OK: false, Message: h.publicFailureMessage(r.Context(), "runtime.health", code, err), Code: code})
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: publicRuntimeHealth(health)})
}

func (h Handler) handleRefreshEnabledRuntimeState(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	records, err := h.host.RefreshEnabledPlugins(r.Context())
	if err != nil {
		code, status := runtimeManagementError(err)
		writeMutationError(w, status, code, h.publicFailureMessage(r.Context(), "runtime.refresh_enabled", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicRuntimeRefresh(records))
}

func (h Handler) handleExportData(w http.ResponseWriter, r *http.Request) {
	var req exportDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.ExportPluginData(r.Context(), host.ExportDataRequest{
		PluginInstanceID: req.PluginInstanceID,
	})
	if err != nil {
		code := errorCodeForDataLifecycleError(err)
		writeMutationError(w, httpStatusForDataLifecycleError(err), code, h.publicFailureMessage(r.Context(), "data.export", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, dataExportResponse{BundleRef: result.BundleRef})
}

func (h Handler) handleDeleteDataExport(w http.ResponseWriter, r *http.Request) {
	var req deleteDataExportRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := h.host.DeleteExportedPluginData(r.Context(), host.DeleteExportDataRequest{PluginInstanceID: req.PluginInstanceID, BundleRef: req.BundleRef}); err != nil {
		code := errorCodeForDataLifecycleError(err)
		writeMutationError(w, httpStatusForDataLifecycleError(err), code, h.publicFailureMessage(r.Context(), "data.export.delete", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, deleteResponse{Deleted: true})
}

func (h Handler) handleImportData(w http.ResponseWriter, r *http.Request) {
	var req importDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedManagementRevision, err := requiredRevision(req.ExpectedManagementRevision, "expected_management_revision")
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	record, err := h.host.ImportPluginData(r.Context(), host.ImportDataRequest{
		PluginInstanceID:           req.PluginInstanceID,
		BundleRef:                  req.BundleRef,
		ExpectedManagementRevision: expectedManagementRevision,
	})
	if err != nil {
		code := errorCodeForDataLifecycleError(err)
		writeMutationError(w, httpStatusForDataLifecycleError(err), code, h.publicFailureMessage(r.Context(), "data.import", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	h.writePluginMutationSuccess(w, r, "data.import.response", record)
}

func (h Handler) handleListRetainedData(w http.ResponseWriter, r *http.Request) {
	var req listRetainedDataQueryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	records, err := h.host.ListRetainedData(r.Context(), host.ListRetainedDataRequest{
		PluginInstanceID: req.PluginInstanceID.get(),
	})
	if err != nil {
		code := errorCodeForDataLifecycleError(err)
		writeJSON(w, httpStatusForDataLifecycleError(err), errorResponse{OK: false, Message: h.publicFailureMessage(r.Context(), "retained-data.list", code, err), Code: code})
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: publicRetainedData(records)})
}

func (h Handler) handleDeleteRetainedData(w http.ResponseWriter, r *http.Request) {
	var req deleteRetainedDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedBindingRevision, err := requiredRevision(req.ExpectedBindingRevision, "expected_binding_revision")
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	record, err := h.host.DeleteRetainedData(r.Context(), host.DeleteRetainedDataRequest{
		PluginInstanceID:        req.PluginInstanceID,
		ExpectedBindingRevision: expectedBindingRevision,
	})
	if err != nil {
		details := bindingRevisionDetails(err)
		code := errorCodeForDataLifecycleError(err)
		writeMutationError(w, httpStatusForDataLifecycleError(err), code, h.publicFailureMessage(r.Context(), "retained-data.delete", code, err), details, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicPluginDataBinding(record))
}

func (h Handler) handleBindRetainedData(w http.ResponseWriter, r *http.Request) {
	var req bindRetainedDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedSourceBindingRevision, err := requiredRevision(req.ExpectedSourceBindingRevision, "expected_source_binding_revision")
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	targetExpectedManagementRevision, err := requiredRevision(req.TargetExpectedManagementRevision, "target_expected_management_revision")
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	record, err := h.host.BindRetainedData(r.Context(), host.BindRetainedDataRequest{
		SourcePluginInstanceID:           req.SourcePluginInstanceID,
		ExpectedSourceBindingRevision:    expectedSourceBindingRevision,
		TargetPluginInstanceID:           req.TargetPluginInstanceID,
		TargetExpectedManagementRevision: targetExpectedManagementRevision,
	})
	if err != nil {
		details := bindingRevisionDetails(err)
		code := errorCodeForDataLifecycleError(err)
		writeMutationError(w, httpStatusForDataLifecycleError(err), code, h.publicFailureMessage(r.Context(), "retained-data.bind", code, err), details, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicPluginDataBinding(record))
}

func (h Handler) handleCleanupExpiredRetainedData(w http.ResponseWriter, r *http.Request) {
	var req cleanupExpiredRetainedDataRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.CleanupExpiredRetainedData(r.Context(), host.CleanupExpiredRetainedDataRequest{})
	if err != nil {
		code := errorCodeForDataLifecycleError(err)
		writeMutationError(w, httpStatusForDataLifecycleError(err), code, h.publicFailureMessage(r.Context(), "retained-data.cleanup-expired", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicRetainedDataCleanup(result))
}

func (h Handler) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	var req listPermissionsQueryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	records, err := h.host.ListPermissionGrants(r.Context(), host.ListPermissionGrantsRequest{
		PluginInstanceID: req.PluginInstanceID.get(),
		ActiveOnly:       req.ActiveOnly.get(),
	})
	if err != nil {
		code := errorCodeForPermissionError(err)
		writeJSON(w, httpStatusForPermissionError(err), errorResponse{OK: false, Message: h.publicFailureMessage(r.Context(), "permission.list", code, err), Code: code})
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: permissionListResponse{Permissions: publicPermissions(records)}})
}

func (h Handler) handleGrantPermission(w http.ResponseWriter, r *http.Request) {
	var req grantPermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	record, err := h.host.GrantPermission(r.Context(), host.GrantPermissionRequest{
		PluginInstanceID:           req.PluginInstanceID,
		PermissionID:               req.PermissionID,
		ExpectedPolicyRevision:     req.ExpectedPolicyRevision,
		ExpectedManagementRevision: req.ExpectedManagementRevision,
		ExpectedRevokeEpoch:        req.ExpectedRevokeEpoch,
		ExpiresAt:                  req.ExpiresAt,
	})
	if err != nil {
		code := errorCodeForPermissionError(err)
		writeMutationError(w, httpStatusForPermissionError(err), code, h.publicFailureMessage(r.Context(), "permission.grant", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicPermissionMutation(record))
}

func (h Handler) handleRevokePermission(w http.ResponseWriter, r *http.Request) {
	var req revokePermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	record, err := h.host.RevokePermission(r.Context(), host.RevokePermissionRequest{
		PluginInstanceID:           req.PluginInstanceID,
		PermissionID:               req.PermissionID,
		ExpectedPolicyRevision:     req.ExpectedPolicyRevision,
		ExpectedManagementRevision: req.ExpectedManagementRevision,
		ExpectedRevokeEpoch:        req.ExpectedRevokeEpoch,
		Reason:                     req.Reason,
	})
	if err != nil {
		code := errorCodeForPermissionError(err)
		writeMutationError(w, httpStatusForPermissionError(err), code, h.publicFailureMessage(r.Context(), "permission.revoke", code, err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, publicPermissionMutation(record))
}

func (h Handler) handleListSecurityPolicies(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	records, err := h.host.ListSecurityPolicies(r.Context())
	if err != nil {
		code := errorCodeForSecurityPolicyError(err)
		writeError(w, httpStatusForSecurityPolicyError(err), code, h.publicFailureMessage(r.Context(), "security-policy.list", code, err), errorDetailsForSecurityPolicyError(err))
		return
	}
	responses := make([]securityPolicyResponse, 0, len(records))
	for _, record := range records {
		responses = append(responses, securityPolicyResponseFromRecord(record))
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: securityPolicyListResponse{SecurityPolicies: responses}})
}

func (h Handler) handleGetSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	var req emptyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	pluginInstanceID, ok := pluginInstanceIDFromSecurityPolicyPath(r.URL.Path, "/query")
	if !ok {
		writeError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{})
		return
	}
	record, err := h.host.GetSecurityPolicy(r.Context(), host.GetSecurityPolicyRequest{PluginInstanceID: pluginInstanceID})
	if err != nil {
		code := errorCodeForSecurityPolicyError(err)
		writeError(w, httpStatusForSecurityPolicyError(err), code, h.publicFailureMessage(r.Context(), "security-policy.get", code, err), errorDetailsForSecurityPolicyError(err))
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: securityPolicyResponseFromRecord(record)})
}

func (h Handler) handlePutSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	pluginInstanceID, ok := pluginInstanceIDFromSecurityPolicyPath(r.URL.Path, "")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req putSecurityPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	policyRevision, managementRevision, revokeEpoch, err := securityPolicyRevisions(
		req.ExpectedPolicyRevision,
		req.ExpectedManagementRevision,
		req.ExpectedRevokeEpoch,
	)
	if err != nil || req.AllowedPermissions == nil || req.DeniedMethods == nil {
		if err == nil {
			err = errors.New("allowed_permissions and denied_methods are required")
		}
		writeMutationInvalidRequestError(w, err)
		return
	}
	record, err := h.host.PutSecurityPolicy(r.Context(), host.PutSecurityPolicyRequest{
		PluginInstanceID:           pluginInstanceID,
		ExpectedPolicyRevision:     policyRevision,
		ExpectedManagementRevision: managementRevision,
		ExpectedRevokeEpoch:        revokeEpoch,
		AllowedPermissions:         *req.AllowedPermissions,
		DeniedMethods:              *req.DeniedMethods,
	})
	if err != nil {
		code := errorCodeForSecurityPolicyError(err)
		writeMutationError(w, httpStatusForSecurityPolicyError(err), code, h.publicFailureMessage(r.Context(), "security-policy.put", code, err), errorDetailsForSecurityPolicyError(err), mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, securityPolicyResponseFromRecord(record))
}

func (h Handler) handleDeleteSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	pluginInstanceID, ok := pluginInstanceIDFromSecurityPolicyPath(r.URL.Path, "")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req deleteSecurityPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	policyRevision, managementRevision, revokeEpoch, err := securityPolicyRevisions(
		req.ExpectedPolicyRevision,
		req.ExpectedManagementRevision,
		req.ExpectedRevokeEpoch,
	)
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	revisions, err := h.host.DeleteSecurityPolicy(r.Context(), host.DeleteSecurityPolicyRequest{
		PluginInstanceID:           pluginInstanceID,
		ExpectedPolicyRevision:     policyRevision,
		ExpectedManagementRevision: managementRevision,
		ExpectedRevokeEpoch:        revokeEpoch,
	})
	if err != nil {
		code := errorCodeForSecurityPolicyError(err)
		writeMutationError(w, httpStatusForSecurityPolicyError(err), code, h.publicFailureMessage(r.Context(), "security-policy.delete", code, err), errorDetailsForSecurityPolicyError(err), mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, securityPolicyDeleteResponse{
		PluginInstanceID: pluginInstanceID, Deleted: true, PolicyRevision: revisions.PolicyRevision,
		ManagementRevision: revisions.ManagementRevision, RevokeEpoch: revisions.RevokeEpoch,
	})
}

func securityPolicyRevisions(policyRevision, managementRevision, revokeEpoch *uint64) (uint64, uint64, uint64, error) {
	if policyRevision == nil || managementRevision == nil || revokeEpoch == nil {
		return 0, 0, 0, errors.New("expected_policy_revision, expected_management_revision, and expected_revoke_epoch are required")
	}
	if *policyRevision == 0 || *managementRevision == 0 {
		return 0, 0, 0, errors.New("expected_policy_revision and expected_management_revision must be greater than zero")
	}
	return *policyRevision, *managementRevision, *revokeEpoch, nil
}

func securityPolicyResponseFromRecord(result host.SecurityPolicyResult) securityPolicyResponse {
	record := result.Policy
	return securityPolicyResponse{
		PluginInstanceID:   record.PluginInstanceID,
		AllowedPermissions: append([]string{}, record.AllowedPermissions...),
		DeniedMethods:      append([]string{}, record.DeniedMethods...),
		PolicyRevision:     result.Revisions.PolicyRevision,
		ManagementRevision: result.Revisions.ManagementRevision,
		RevokeEpoch:        result.Revisions.RevokeEpoch,
		UpdatedAt:          record.UpdatedAt,
	}
}

func (h Handler) handleListDiagnostics(w http.ResponseWriter, r *http.Request) {
	var req listDiagnosticsQueryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	limit, err := req.Limit.bounded("limit", 1, 1000)
	if err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	severity := req.Severity.get()
	if severity != "" && severity != string(observability.DiagnosticSeverityInfo) && severity != string(observability.DiagnosticSeverityWarning) {
		err := errors.New("severity must be info or warning")
		writeInvalidRequestError(w, err)
		return
	}
	events, err := h.host.ListDiagnosticEvents(r.Context(), host.ListDiagnosticEventsRequest{
		PluginID:          req.PluginID.get(),
		PluginInstanceID:  req.PluginInstanceID.get(),
		SurfaceInstanceID: req.SurfaceInstanceID.get(),
		Type:              req.Type.get(),
		Severity:          observability.DiagnosticSeverity(severity),
		Limit:             limit,
	})
	if err != nil {
		if errors.Is(err, host.ErrActionDenied) || errors.Is(err, host.ErrAdapterFailure) {
			code := errorCodeForManagementError(err)
			writeError(w, httpStatusForManagementError(err), code, h.publicFailureMessage(r.Context(), "diagnostic.list", code, err), errorDetails{})
		} else {
			writeInvalidRequestError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: publicDiagnostics(events)})
}

func (h Handler) handleBindSecret(w http.ResponseWriter, r *http.Request) {
	var req secretRefRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := h.host.BindSecretRef(r.Context(), host.SecretBindRequest{
		PluginInstanceID: req.PluginInstanceID,
		SecretRef:        req.SecretRef,
		Scope:            req.Scope,
	}); err != nil {
		writeMutationError(w, httpStatusForSecretError(err), errorCodeForSecretError(err), publicSecretErrorMessage(err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, secretBindResponse{Bound: true})
}

func (h Handler) handleTestSecret(w http.ResponseWriter, r *http.Request) {
	var req secretRefRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := h.host.TestSecretRef(r.Context(), host.SecretTestRequest{
		PluginInstanceID: req.PluginInstanceID,
		SecretRef:        req.SecretRef,
		Scope:            req.Scope,
	}); err != nil {
		writeMutationError(w, httpStatusForSecretError(err), errorCodeForSecretError(err), publicSecretErrorMessage(err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, secretTestResponse{Tested: true})
}

func (h Handler) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	var req secretRefRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if err := h.host.DeleteSecretRef(r.Context(), host.SecretDeleteRequest{
		PluginInstanceID: req.PluginInstanceID,
		SecretRef:        req.SecretRef,
		Scope:            req.Scope,
	}); err != nil {
		writeMutationError(w, httpStatusForSecretError(err), errorCodeForSecretError(err), publicSecretErrorMessage(err), errorDetails{}, mutation.ForError(err))
		return
	}
	writeMutationSuccess(w, deleteResponse{Deleted: true})
}

func (h Handler) handleGetSettingsSchema(w http.ResponseWriter, r *http.Request) {
	pluginInstanceID, ok := pluginInstanceIDFromPath(r.URL.Path, "/settings/schema/query")
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{OK: false, Message: "route not found", Code: security.ErrInvalidRequest})
		return
	}
	var req settingsQueryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope, err := requiredScopeKind(req.Scope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{OK: false, Message: "settings scope is required", Code: security.ErrInvalidRequest})
		return
	}
	result, err := h.host.GetSettingsSchema(r.Context(), host.GetSettingsRequest{PluginInstanceID: pluginInstanceID, Scope: scope})
	if err != nil {
		code := errorCodeForSettingsError(err)
		writeJSON(w, httpStatusForSettingsError(err), errorResponse{OK: false, Message: h.publicFailureMessage(r.Context(), "settings.schema", code, err), Code: code})
		return
	}
	response, err := publicSettingsSchema(result)
	if err != nil {
		h.writeProjectionError(w, r, "settings.schema.response", err)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: response})
}

func (h Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	pluginInstanceID, ok := pluginInstanceIDFromPath(r.URL.Path, "/settings/query")
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{OK: false, Message: "route not found", Code: security.ErrInvalidRequest})
		return
	}
	var req settingsQueryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeInvalidRequestError(w, err)
		return
	}
	scope, err := requiredScopeKind(req.Scope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{OK: false, Message: "settings scope is required", Code: security.ErrInvalidRequest})
		return
	}
	result, err := h.host.GetPluginSettings(r.Context(), host.GetSettingsRequest{PluginInstanceID: pluginInstanceID, Scope: scope})
	if err != nil {
		code := errorCodeForSettingsError(err)
		writeJSON(w, httpStatusForSettingsError(err), errorResponse{OK: false, Message: h.publicFailureMessage(r.Context(), "settings.get", code, err), Code: code})
		return
	}
	response, err := publicSettingsSnapshot(result)
	if err != nil {
		h.writeProjectionError(w, r, "settings.get.response", err)
		return
	}
	writeJSON(w, http.StatusOK, successResponse{OK: true, Data: response})
}

func (h Handler) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	pluginInstanceID, ok := pluginInstanceIDFromPath(r.URL.Path, "/settings")
	if !ok {
		writeMutationError(w, http.StatusNotFound, security.ErrInvalidRequest, "route not found", errorDetails{}, mutation.OutcomeNotCommitted)
		return
	}
	var req patchSettingsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	expectedValuesRevision, err := requiredRevision(req.ExpectedValuesRevision, "expected_values_revision")
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	if req.Set == nil && req.Remove == nil {
		writeMutationInvalidRequestError(w, errors.New("set or remove is required"))
		return
	}
	scope, err := requiredScopeKind(sessionctx.ScopeKind(req.Scope))
	if err != nil {
		writeMutationInvalidRequestError(w, err)
		return
	}
	result, err := h.host.PatchPluginSettings(r.Context(), host.PatchSettingsRequest{
		PluginInstanceID:       pluginInstanceID,
		Scope:                  scope,
		ExpectedValuesRevision: expectedValuesRevision,
		Set:                    req.Set,
		Remove:                 req.Remove,
	})
	if err != nil {
		details := h.valuesRevisionDetails(r.Context(), pluginInstanceID, scope, expectedValuesRevision, err)
		code := errorCodeForSettingsError(err)
		writeMutationError(w, httpStatusForSettingsError(err), code, h.publicFailureMessage(r.Context(), "settings.patch", code, err), details, mutation.ForError(err))
		return
	}
	response, err := publicSettingsSnapshot(result)
	if err != nil {
		h.writeProjectionError(w, r, "settings.patch.response", err)
		return
	}
	writeMutationSuccess(w, response)
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	if err := validateJSONContentType(r.Header.Values("Content-Type")); err != nil {
		return err
	}
	raw, err := readLimitedJSONBody(r, defaultJSONRequestMaxBytes)
	if err != nil {
		return err
	}
	if err := validateJSONLimits(raw, defaultJSONMaxDepth, reflect.TypeOf(dst)); err != nil {
		return err
	}
	return decodeStrictJSON(raw, dst)
}

func decodeClosedJSONObject(r *http.Request) error {
	defer r.Body.Close()
	if err := validateJSONContentType(r.Header.Values("Content-Type")); err != nil {
		return err
	}
	raw, err := readLimitedJSONBody(r, defaultJSONRequestMaxBytes)
	if err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := validateJSONLimits(raw, defaultJSONMaxDepth, reflect.TypeOf(object)); err != nil {
		return err
	}
	if err := decodeStrictJSON(raw, &object); err != nil {
		return err
	}
	if object == nil {
		return errors.New("request body must be an object")
	}
	if len(object) != 0 {
		return errors.New("request body must be an empty object")
	}
	return nil
}

func readLimitedJSONBody(r *http.Request, maxBytes int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, &jsonLimitError{reason: jsonLimitReasonPayloadBytes}
	}
	return raw, nil
}

func validateJSONContentType(values []string) error {
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return errors.New("Content-Type application/json is required")
	}
	mediaType, params, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	for name, value := range params {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(strings.TrimSpace(value), "utf-8") {
			return errors.New("Content-Type contains unsupported parameters")
		}
	}
	return nil
}

func validateJSONLimits(raw []byte, maxDepth int, target reflect.Type) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateJSONTokenValue(decoder, 1, maxDepth, target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("request body contains trailing JSON values")
	}
	return nil
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

func validateJSONTokenValue(decoder *json.Decoder, depth int, maxDepth int, target reflect.Type) error {
	if depth > maxDepth {
		return &jsonLimitError{reason: jsonLimitReasonDepth}
	}
	target = indirectJSONType(target)
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			seenKeys := map[string]struct{}{}
			seenFields := map[int]string{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if isForbiddenJSONKey(key) {
					return &jsonLimitError{reason: jsonLimitReasonPrototypeKey}
				}
				if _, exists := seenKeys[key]; exists {
					return fmt.Errorf("JSON object contains duplicate key %q", key)
				}
				seenKeys[key] = struct{}{}

				childTarget := mapJSONValueType(target)
				if field, fieldIndex, ok := matchingJSONStructField(target, key); ok {
					if previous, exists := seenFields[fieldIndex]; exists {
						return fmt.Errorf("JSON object contains ambiguous keys %q and %q", previous, key)
					}
					seenFields[fieldIndex] = key
					childTarget = field.Type
				}
				if err := validateJSONTokenValue(decoder, depth+1, maxDepth, childTarget); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return errors.New("JSON object is not terminated")
			}
		case '[':
			childTarget := sliceJSONValueType(target)
			for decoder.More() {
				if err := validateJSONTokenValue(decoder, depth+1, maxDepth, childTarget); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return errors.New("JSON array is not terminated")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
	case json.Number:
		if jsonNumberExceedsSafePrecision(typed) {
			return &jsonLimitError{reason: jsonLimitReasonNumberPrecision}
		}
	}
	return nil
}

func indirectJSONType(target reflect.Type) reflect.Type {
	for target != nil && target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	return target
}

func mapJSONValueType(target reflect.Type) reflect.Type {
	if target != nil && target.Kind() == reflect.Map && target.Key().Kind() == reflect.String {
		return target.Elem()
	}
	return nil
}

func sliceJSONValueType(target reflect.Type) reflect.Type {
	if target != nil && (target.Kind() == reflect.Array || target.Kind() == reflect.Slice) {
		return target.Elem()
	}
	return nil
}

func matchingJSONStructField(target reflect.Type, key string) (reflect.StructField, int, bool) {
	if target == nil || target.Kind() != reflect.Struct {
		return reflect.StructField{}, 0, false
	}
	foldedIndex := -1
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		if !field.IsExported() || field.Anonymous {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		if name == key {
			return field, index, true
		}
		if foldedIndex < 0 && strings.EqualFold(name, key) {
			foldedIndex = index
		}
	}
	if foldedIndex >= 0 {
		return target.Field(foldedIndex), foldedIndex, true
	}
	return reflect.StructField{}, 0, false
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

func pluginInstanceIDFromPath(requestPath string, suffix string) (string, bool) {
	const prefix = "/_redevplugin/api/plugins/"
	if !strings.HasPrefix(requestPath, prefix) || !strings.HasSuffix(requestPath, suffix) {
		return "", false
	}
	pluginInstanceID := strings.TrimSuffix(strings.TrimPrefix(requestPath, prefix), suffix)
	pluginInstanceID = strings.Trim(pluginInstanceID, "/")
	if pluginInstanceID == "" || strings.TrimSpace(pluginInstanceID) != pluginInstanceID || strings.Contains(pluginInstanceID, "/") || strings.HasPrefix(pluginInstanceID, ".") {
		return "", false
	}
	return pluginInstanceID, true
}

func pluginInstanceIDFromSecurityPolicyPath(requestPath, suffix string) (string, bool) {
	const prefix = "/_redevplugin/api/plugins/security-policies/"
	if !strings.HasPrefix(requestPath, prefix) || (suffix != "" && !strings.HasSuffix(requestPath, suffix)) {
		return "", false
	}
	pluginInstanceID := strings.TrimPrefix(requestPath, prefix)
	if suffix != "" {
		pluginInstanceID = strings.TrimSuffix(pluginInstanceID, suffix)
	}
	pluginInstanceID = strings.Trim(pluginInstanceID, "/")
	if pluginInstanceID == "" || strings.Contains(pluginInstanceID, "/") || strings.HasPrefix(pluginInstanceID, ".") {
		return "", false
	}
	return pluginInstanceID, true
}

func requiredScopeKind(scope sessionctx.ScopeKind) (sessionctx.ScopeKind, error) {
	switch scope {
	case sessionctx.ScopeUser, sessionctx.ScopeEnvironment:
		return scope, nil
	default:
		return "", errors.New("scope must be user or environment")
	}
}

func errorCodeForBridgeError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, sessionscope.ErrSessionRevoked):
		return security.ErrSessionRevoked
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
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

func runtimeManagementError(err error) (security.ErrorCode, int) {
	if errors.Is(err, host.ErrAdapterFailure) {
		return security.ErrAdapterFailure, http.StatusBadGateway
	}
	if errors.Is(err, host.ErrActionDenied) {
		return security.ErrActionDenied, http.StatusForbidden
	}
	if errors.Is(err, runtimetarget.ErrUnsupported) {
		return security.ErrInvalidRequest, http.StatusBadRequest
	}
	return security.ErrRuntimeUnavailable, http.StatusServiceUnavailable
}

func errorCodeForBridgeTokenError(err error, renewal bool) security.ErrorCode {
	if renewal && isGatewayTokenValidationError(err) {
		return errorCodeForGatewayTokenError(err)
	}
	return errorCodeForBridgeError(err)
}

func errorCodeForOpenSurfaceError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrManagementRevisionMismatch):
		return security.ErrManagementRevisionMismatch
	case errors.Is(err, host.ErrPluginUIProtocolUnsupported):
		return security.ErrUIProtocolUnsupported
	case errors.Is(err, host.ErrPluginRuntimeNotConfigured):
		return security.ErrRuntimeUnavailable
	case errors.Is(err, host.ErrPluginRuntimeIncompatible):
		return security.ErrRuntimeVersionMismatch
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
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrManagementRevisionMismatch):
		return http.StatusConflict
	case errors.Is(err, host.ErrPluginUIProtocolUnsupported):
		return http.StatusConflict
	case errors.Is(err, host.ErrPluginRuntimeNotConfigured):
		return http.StatusServiceUnavailable
	case errors.Is(err, host.ErrPluginRuntimeIncompatible):
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
	case errors.Is(err, sessionscope.ErrSessionRevoked):
		return http.StatusGone
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, bridge.ErrTokenExpired), errors.Is(err, bridge.ErrTokenReplay), errors.Is(err, bridge.ErrTokenAlreadyBound), errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenAudience), errors.Is(err, bridge.ErrTokenRevoked), errors.Is(err, bridge.ErrTokenKind), errors.Is(err, bridge.ErrSurfaceSessionNotFound), errors.Is(err, bridge.ErrSurfaceSessionExpired), errors.Is(err, bridge.ErrAssetSessionRequired):
		return http.StatusForbidden
	default:
		return http.StatusForbidden
	}
}

func errorCodeForRPCError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrFeatureNotConfigured):
		return security.ErrFeatureNotConfigured
	case isCapabilityBusinessError(err):
		return security.ErrCapabilityError
	case isUnattestedStructuredRPCError(err):
		return security.ErrContractMismatch
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
	case errors.Is(err, host.ErrPluginRuntimeNotConfigured), errors.Is(err, runtimeclient.ErrRuntimeNotReady), errors.Is(err, runtimeclient.ErrRuntimeIPCUnavailable), errors.Is(err, runtimeclient.ErrRuntimeRequestFailed), errors.Is(err, runtimeclient.ErrRuntimeHandshake):
		return security.ErrRuntimeUnavailable
	case errors.Is(err, host.ErrPluginRuntimeIncompatible):
		return security.ErrRuntimeVersionMismatch
	default:
		return security.ErrPermissionDenied
	}
}

func publicPluginErrorMessage(code security.ErrorCode) string {
	switch code {
	case security.ErrFeatureNotConfigured:
		return "plugin host feature is not configured"
	case security.ErrInvalidRequest:
		return "plugin request is invalid"
	case security.ErrManifestInvalid:
		return "plugin manifest is invalid"
	case security.ErrPackageInvalid:
		return "plugin package is invalid"
	case security.ErrPackageTooLarge:
		return "plugin package exceeds platform limits"
	case security.ErrPackagePathForbidden:
		return "plugin package contains a forbidden path"
	case security.ErrSignatureInvalid, security.ErrTrustVerificationInvalid:
		return "plugin trust verification failed"
	case security.ErrTrustStateDenied, security.ErrReleaseRefPolicyDenied:
		return "plugin release policy denied the request"
	case security.ErrTrustVerificationRequired:
		return "plugin trust verification is unavailable"
	case security.ErrReleaseRefVerificationFailed:
		return "plugin release reference verification failed"
	case security.ErrDisabled:
		return "plugin is disabled"
	case security.ErrDisabledByPolicy:
		return "plugin is disabled by policy"
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
	case security.ErrTokenReplay:
		return "plugin credential was already used"
	case security.ErrGatewayTokenInvalid, security.ErrGatewayTokenReplayed, security.ErrGatewayTokenChannelMismatch:
		return "plugin gateway credential is invalid"
	case security.ErrAssetTicketInvalid:
		return "plugin asset ticket is invalid"
	case security.ErrAssetSessionInvalid:
		return "plugin asset session is invalid"
	case security.ErrStreamTicketInvalid:
		return "plugin stream credential is invalid"
	case security.ErrStreamDeliveryInvalid:
		return "plugin stream delivery is invalid"
	case security.ErrStreamCancelled:
		return "plugin stream was cancelled"
	case security.ErrLeaseInvalid:
		return "plugin execution lease is invalid"
	case security.ErrLeaseReplayed:
		return "plugin execution lease was already used"
	case security.ErrGrantInvalid:
		return "plugin capability grant is invalid"
	case security.ErrStorageQuotaExceeded:
		return "plugin storage quota was exceeded"
	case security.ErrOperationBlocked:
		return "plugin operation is blocked"
	case security.ErrOperationNotFound:
		return "plugin operation was not found"
	case security.ErrOperationNotCancelable:
		return "plugin operation cannot be cancelled"
	case security.ErrNetworkTargetDenied:
		return "plugin network target was denied"
	case security.ErrNetworkRateLimited:
		return "plugin network request was rate limited"
	case security.ErrRuntimeUnavailable:
		return "plugin runtime is unavailable"
	case security.ErrRuntimeVersionMismatch:
		return "plugin runtime version is incompatible"
	case security.ErrUIProtocolUnsupported:
		return "plugin UI protocol is unsupported"
	case security.ErrUIProtocolViolation:
		return "plugin UI violated the platform protocol"
	case security.ErrSurfaceQuiesceTimeout:
		return "plugin surface did not stop in time"
	case security.ErrJSONLimitExceeded:
		return "plugin request exceeds JSON limits"
	case security.ErrCapabilityError:
		return "host capability request failed"
	case security.ErrWorkerError:
		return "plugin operation failed"
	case security.ErrContractMismatch:
		return "plugin contract validation failed"
	case security.ErrManagementRevisionMismatch:
		return "plugin management revision changed"
	case security.ErrAuthorizationRevisionMismatch:
		return "plugin authorization revision changed"
	case security.ErrBindingRevisionMismatch:
		return "plugin data binding revision changed"
	case security.ErrValuesRevisionMismatch:
		return "plugin settings values revision changed"
	case security.ErrOriginDenied:
		return "request origin was denied"
	case security.ErrActionDenied:
		return "plugin platform action was denied"
	case security.ErrOwnerScopeMismatch:
		return "plugin owner scope does not match the authenticated session"
	case security.ErrSecretScopeMismatch:
		return "plugin secret scope does not match the request"
	case security.ErrStorageScopeMismatch:
		return "plugin storage scope does not match the request"
	case security.ErrAdapterFailure:
		return "plugin host adapter failed"
	case security.ErrSessionRevoked:
		return "plugin session is revoked"
	case security.ErrSessionTeardownIncomplete:
		return "plugin session teardown is incomplete"
	case security.ErrSessionFenceCapacity:
		return "plugin session fence capacity is exhausted"
	case security.ErrCSRFRequired:
		return "csrf token is required"
	case security.ErrCSRFInvalid:
		return "csrf token is invalid"
	default:
		return "plugin request failed"
	}
}

func (h Handler) publicFailureMessage(ctx context.Context, operation string, code security.ErrorCode, err error) string {
	h.host.ReportHTTPAdapterFailure(ctx, operation, code, err)
	return publicPluginErrorMessage(code)
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
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrOwnerScopeMismatch), errors.Is(err, connectivity.ErrResourceScopeMismatch):
		return security.ErrOwnerScopeMismatch
	case errors.Is(err, host.ErrStorageScopeMismatch):
		return security.ErrStorageScopeMismatch
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrManagementRevisionMismatch):
		return security.ErrManagementRevisionMismatch
	case errors.Is(err, host.ErrPluginUIProtocolUnsupported):
		return security.ErrUIProtocolUnsupported
	case errors.Is(err, host.ErrPluginRuntimeNotConfigured):
		return security.ErrRuntimeUnavailable
	case errors.Is(err, host.ErrPluginRuntimeIncompatible):
		return security.ErrRuntimeVersionMismatch
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrNamespaceNotFound):
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

func errorDetailsForManagementError(err error) errorDetails {
	var revisionErr *host.ManagementRevisionMismatchError
	if errors.As(err, &revisionErr) {
		return errorDetails{
			PluginInstanceID:           revisionErr.PluginInstanceID,
			ExpectedManagementRevision: revisionErr.Expected,
			ActualManagementRevision:   revisionErr.Actual,
		}
	}
	var packageValidationErr *pluginpkg.ValidationError
	if errors.As(err, &packageValidationErr) {
		return errorDetails{
			Reason:  packageValidationErr.Reason,
			Path:    packageValidationErr.Path,
			Pointer: packageValidationErr.Pointer,
		}
	}
	return errorDetails{}
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
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrManagementRevisionMismatch):
		return http.StatusConflict
	case errors.Is(err, host.ErrPluginUIProtocolUnsupported):
		return http.StatusConflict
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrNamespaceNotFound):
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
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
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
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
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
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, stream.ErrNotFound), errors.Is(err, stream.ErrInvalidStream):
		return security.ErrInvalidRequest
	case errors.Is(err, stream.ErrDeliveryInvalid):
		return security.ErrStreamDeliveryInvalid
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
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, stream.ErrNotFound), errors.Is(err, stream.ErrInvalidStream):
		return http.StatusBadRequest
	case errors.Is(err, stream.ErrDeliveryInvalid):
		return http.StatusConflict
	case errors.Is(err, stream.ErrBackpressure):
		return http.StatusTooManyRequests
	default:
		return http.StatusForbidden
	}
}

func httpStatusForRPCError(err error) int {
	switch {
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrFeatureNotConfigured):
		return http.StatusNotImplemented
	case isCapabilityBusinessError(err):
		return http.StatusUnprocessableEntity
	case isUnattestedStructuredRPCError(err):
		return http.StatusBadGateway
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
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrFeatureNotConfigured):
		return security.ErrFeatureNotConfigured
	case isCapabilityBusinessError(err):
		return security.ErrCapabilityError
	case isUnattestedStructuredRPCError(err):
		return security.ErrContractMismatch
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

func errorDetailsForRPCError(err error) (errorDetails, error) {
	if businessError, ok := host.AsValidatedCapabilityBusinessError(err); ok {
		details, cloneErr := cloneWireJSONMap(businessError.Details)
		if cloneErr != nil {
			return errorDetails{}, cloneErr
		}
		return errorDetails{
			CapabilityID:         businessError.CapabilityID,
			CapabilityVersion:    businessError.CapabilityVersion,
			DetailSchemaSHA256:   businessError.DetailSchemaSHA256,
			BusinessErrorCode:    businessError.Code,
			BusinessErrorDetails: details,
		}, nil
	}
	if workerError, ok := host.AsValidatedWorkerExecutionError(err); ok {
		if errorCodeForWorkerExecutionError(err) != security.ErrWorkerError {
			return errorDetails{}, nil
		}
		return errorDetails{
			WorkerErrorCode:    workerError.Code,
			WorkerErrorMessage: publicWorkerErrorMessage(workerError.Message),
			WorkerErrorOrigin:  string(workerError.Origin),
		}, nil
	}
	return errorDetails{}, nil
}

func isCapabilityBusinessError(err error) bool {
	_, ok := host.AsValidatedCapabilityBusinessError(err)
	return ok
}

func isUnattestedStructuredRPCError(err error) bool {
	return host.HasUnattestedRPCStructuredError(err)
}

func isWorkerExecutionError(err error) bool {
	_, ok := host.AsValidatedWorkerExecutionError(err)
	return ok
}

func errorCodeForWorkerExecutionError(err error) security.ErrorCode {
	workerError, ok := host.AsValidatedWorkerExecutionError(err)
	if !ok {
		return security.ErrRuntimeUnavailable
	}
	return errorCodeForWorkerExecutionErrorValue(workerError)
}

func errorCodeForWorkerExecutionErrorValue(workerError runtimeclient.WorkerExecutionError) security.ErrorCode {
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
	return httpStatusForWorkerExecutionErrorCode(errorCodeForWorkerExecutionError(err))
}

func httpStatusForWorkerExecutionErrorCode(code security.ErrorCode) int {
	switch code {
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
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrActionDenied):
		return http.StatusForbidden
	case isCapabilityBusinessError(err):
		return http.StatusUnprocessableEntity
	case isUnattestedStructuredRPCError(err):
		return http.StatusBadGateway
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
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrOwnerScopeMismatch), errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired):
		return security.ErrOwnerScopeMismatch
	case errors.Is(err, host.ErrStorageScopeMismatch), errors.Is(err, plugindata.ErrStorageScopeMismatch):
		return security.ErrStorageScopeMismatch
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, storage.ErrQuotaExceeded):
		return security.ErrStorageQuotaExceeded
	case errors.Is(err, plugindata.ErrBindingRevisionConflict):
		return security.ErrBindingRevisionMismatch
	case errors.Is(err, plugindata.ErrRevisionConflict):
		return security.ErrValuesRevisionMismatch
	case errors.Is(err, plugindata.ErrInvalidArgument), errors.Is(err, plugindata.ErrBindingNotFound),
		errors.Is(err, plugindata.ErrNotActive), errors.Is(err, plugindata.ErrNotRetained),
		errors.Is(err, plugindata.ErrExportNotFound), errors.Is(err, plugindata.ErrUnknownSetting),
		errors.Is(err, plugindata.ErrShapeMismatch),
		errors.Is(err, registry.ErrNotFound), errors.Is(err, host.ErrPluginDataNotDeclared),
		errors.Is(err, host.ErrPluginSettingsNotDeclared), errors.Is(err, host.ErrPluginStorageNotDeclared),
		errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrNamespaceNotFound),
		errors.Is(err, settings.ErrInvalidSetting):
		return security.ErrInvalidRequest
	case errors.Is(err, plugindata.ErrBindingConflict), errors.Is(err, plugindata.ErrDatasetCorrupt), errors.Is(err, plugindata.ErrUnsafeFilesystem):
		return security.ErrContractMismatch
	default:
		return security.ErrPermissionDenied
	}
}

func bindingRevisionDetails(err error) errorDetails {
	var conflict *plugindata.BindingRevisionConflictError
	if !errors.As(err, &conflict) {
		return errorDetails{}
	}
	return errorDetails{
		PluginInstanceID:        conflict.PluginInstanceID,
		ExpectedBindingRevision: conflict.Expected,
		ActualBindingRevision:   conflict.Actual,
	}
}

func (h Handler) valuesRevisionDetails(ctx context.Context, pluginInstanceID string, scope sessionctx.ScopeKind, expected uint64, err error) errorDetails {
	if !errors.Is(err, plugindata.ErrRevisionConflict) {
		return errorDetails{}
	}
	snapshot, getErr := h.host.GetPluginSettings(ctx, host.GetSettingsRequest{PluginInstanceID: pluginInstanceID, Scope: scope})
	if getErr != nil {
		return errorDetails{}
	}
	actual := snapshot.ValuesRevision
	return errorDetails{
		PluginInstanceID:       pluginInstanceID,
		ExpectedValuesRevision: &expected,
		ActualValuesRevision:   &actual,
	}
}

func errorCodeForSecretError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrSecretScopeMismatch):
		return security.ErrSecretScopeMismatch
	case errors.Is(err, host.ErrOwnerScopeMismatch), errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired):
		return security.ErrOwnerScopeMismatch
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrInvalidSecretRef), errors.Is(err, registry.ErrNotFound):
		return security.ErrInvalidRequest
	case errors.Is(err, host.ErrSecretStoreRequired):
		return security.ErrRuntimeUnavailable
	default:
		return security.ErrPermissionDenied
	}
}

func publicSecretErrorMessage(err error) string {
	switch {
	case errors.Is(err, host.ErrSecretScopeMismatch):
		return "secret reference scope does not match the request"
	case errors.Is(err, host.ErrOwnerScopeMismatch), errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired):
		return "secret owner scope does not match the authenticated session"
	case errors.Is(err, host.ErrAdapterFailure):
		return "secret adapter operation failed"
	case errors.Is(err, host.ErrInvalidSecretRef):
		return "secret reference request is invalid"
	case errors.Is(err, registry.ErrNotFound):
		return "plugin secret reference was not found"
	case errors.Is(err, host.ErrSecretStoreRequired):
		return "secret store is unavailable"
	default:
		return "secret operation failed"
	}
}

func errorCodeForSettingsError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrOwnerScopeMismatch), errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired):
		return security.ErrOwnerScopeMismatch
	case errors.Is(err, plugindata.ErrSettingScopeMismatch):
		return security.ErrOwnerScopeMismatch
	case errors.Is(err, host.ErrStorageScopeMismatch):
		return security.ErrStorageScopeMismatch
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, plugindata.ErrRevisionConflict):
		return security.ErrValuesRevisionMismatch
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, host.ErrPluginSettingsNotDeclared), errors.Is(err, plugindata.ErrUnknownSetting), errors.Is(err, settings.ErrInvalidSetting):
		return security.ErrInvalidRequest
	default:
		return security.ErrPermissionDenied
	}
}

func httpStatusForSettingsError(err error) int {
	switch {
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrOwnerScopeMismatch), errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired):
		return http.StatusForbidden
	case errors.Is(err, plugindata.ErrRevisionConflict):
		return http.StatusConflict
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, host.ErrPluginSettingsNotDeclared), errors.Is(err, plugindata.ErrUnknownSetting), errors.Is(err, settings.ErrInvalidSetting):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}

func httpStatusForSecretError(err error) int {
	switch {
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrSecretScopeMismatch), errors.Is(err, host.ErrOwnerScopeMismatch), errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired):
		return http.StatusForbidden
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
	case errors.Is(err, sessionscope.ErrSessionRevoked):
		return security.ErrSessionRevoked
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
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
	case errors.Is(err, sessionscope.ErrSessionRevoked):
		return http.StatusGone
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
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
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrOwnerScopeMismatch):
		return security.ErrOwnerScopeMismatch
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
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
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, permissions.ErrInvalidPermission), errors.Is(err, permissions.ErrGrantNotFound):
		return http.StatusBadRequest
	case errors.Is(err, permissions.ErrPermissionDenied):
		return http.StatusForbidden
	default:
		return http.StatusForbidden
	}
}

func errorCodeForSecurityPolicyError(err error) security.ErrorCode {
	switch {
	case errors.Is(err, host.ErrActionDenied):
		return security.ErrActionDenied
	case errors.Is(err, host.ErrOwnerScopeMismatch):
		return security.ErrOwnerScopeMismatch
	case errors.Is(err, host.ErrAdapterFailure):
		return security.ErrAdapterFailure
	case errors.Is(err, registry.ErrAuthorizationRevisionConflict):
		return security.ErrAuthorizationRevisionMismatch
	case errors.Is(err, registry.ErrNotFound),
		errors.Is(err, registry.ErrInvalidAuthorizationRevisions),
		errors.Is(err, security.ErrInvalidPolicy),
		errors.Is(err, security.ErrPolicyNotFound):
		return security.ErrInvalidRequest
	default:
		return security.ErrRuntimeUnavailable
	}
}

func errorDetailsForSecurityPolicyError(err error) errorDetails {
	var conflict *registry.AuthorizationRevisionConflictError
	if !errors.As(err, &conflict) {
		return errorDetails{}
	}
	expectedRevokeEpoch := conflict.Expected.RevokeEpoch
	actualRevokeEpoch := conflict.Actual.RevokeEpoch
	return errorDetails{
		PluginInstanceID:           conflict.PluginInstanceID,
		ExpectedPolicyRevision:     conflict.Expected.PolicyRevision,
		ActualPolicyRevision:       conflict.Actual.PolicyRevision,
		ExpectedManagementRevision: conflict.Expected.ManagementRevision,
		ActualManagementRevision:   conflict.Actual.ManagementRevision,
		ExpectedRevokeEpoch:        &expectedRevokeEpoch,
		ActualRevokeEpoch:          &actualRevokeEpoch,
	}
}

func httpStatusForSecurityPolicyError(err error) int {
	switch {
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrActionDenied):
		return http.StatusForbidden
	case errors.Is(err, registry.ErrAuthorizationRevisionConflict):
		return http.StatusConflict
	case errors.Is(err, security.ErrPolicyNotFound):
		return http.StatusNotFound
	case errors.Is(err, registry.ErrNotFound), errors.Is(err, registry.ErrInvalidAuthorizationRevisions), errors.Is(err, security.ErrInvalidPolicy):
		return http.StatusBadRequest
	default:
		return http.StatusServiceUnavailable
	}
}

func httpStatusForDataLifecycleError(err error) int {
	switch {
	case errors.Is(err, host.ErrAdapterFailure):
		return http.StatusBadGateway
	case errors.Is(err, host.ErrOwnerScopeMismatch), errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired), errors.Is(err, host.ErrStorageScopeMismatch):
		return http.StatusForbidden
	case errors.Is(err, storage.ErrQuotaExceeded):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, plugindata.ErrBindingRevisionConflict), errors.Is(err, plugindata.ErrRevisionConflict):
		return http.StatusConflict
	case errors.Is(err, plugindata.ErrInvalidArgument), errors.Is(err, plugindata.ErrBindingNotFound),
		errors.Is(err, plugindata.ErrNotActive), errors.Is(err, plugindata.ErrNotRetained),
		errors.Is(err, plugindata.ErrExportNotFound), errors.Is(err, plugindata.ErrUnknownSetting),
		errors.Is(err, plugindata.ErrShapeMismatch),
		errors.Is(err, registry.ErrNotFound), errors.Is(err, host.ErrPluginDataNotDeclared),
		errors.Is(err, host.ErrPluginSettingsNotDeclared), errors.Is(err, host.ErrPluginStorageNotDeclared),
		errors.Is(err, storage.ErrInvalidNamespace), errors.Is(err, storage.ErrNamespaceNotFound),
		errors.Is(err, settings.ErrInvalidSetting):
		return http.StatusBadRequest
	case errors.Is(err, plugindata.ErrBindingConflict), errors.Is(err, plugindata.ErrDatasetCorrupt), errors.Is(err, plugindata.ErrUnsafeFilesystem):
		return http.StatusInternalServerError
	default:
		return http.StatusForbidden
	}
}
