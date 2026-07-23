package websecurity

import (
	"errors"
	"net/http"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

var (
	ErrOriginDenied        = errors.New("request origin is denied")
	ErrCSRFRequired        = errors.New("csrf token is required")
	ErrCSRFInvalid         = errors.New("csrf token is invalid")
	ErrRouteActionInvalid  = errors.New("route action is invalid")
	ErrRouteEffectInvalid  = errors.New("route effect is invalid")
	ErrOriginPolicyInvalid = errors.New("origin policy is invalid")
	ErrCSRFPolicyInvalid   = errors.New("csrf policy is invalid")
)

// RouteAction identifies one host-authorized HTTP operation. The values form a
// closed contract so host products can implement an exhaustive authorization
// policy without matching raw paths.
type RouteAction string

const (
	RouteActionImportLocalPackage         RouteAction = "plugin.import_local_package"
	RouteActionInstallReleaseRef          RouteAction = "plugin.install_release_ref"
	RouteActionInspectExternalPackage     RouteAction = "plugin.inspect_external_package"
	RouteActionCommitExternalPackage      RouteAction = "plugin.commit_external_package"
	RouteActionQueryExternalPackageCommit RouteAction = "plugin.query_external_package_commit"
	RouteActionEnablePlugin               RouteAction = "plugin.enable"
	RouteActionDisablePlugin              RouteAction = "plugin.disable"
	RouteActionUninstallPlugin            RouteAction = "plugin.uninstall"
	RouteActionUpdateLocalPackage         RouteAction = "plugin.update_local_package"
	RouteActionUpdateReleaseRef           RouteAction = "plugin.update_release_ref"
	RouteActionDowngradePlugin            RouteAction = "plugin.downgrade"
	RouteActionListPlugins                RouteAction = "plugin.list"
	RouteActionListFeatures               RouteAction = "platform.list_features"
	RouteActionGetCompatibility           RouteAction = "platform.get_compatibility"
	RouteActionOpenSurface                RouteAction = "surface.open"
	RouteActionRevokeSessionScope         RouteAction = "session.revoke_scope"
	RouteActionPrepareSurface             RouteAction = "surface.prepare"
	RouteActionMintBridgeToken            RouteAction = "surface.mint_bridge_token"
	RouteActionReadSurfaceAsset           RouteAction = "surface.read_asset"
	RouteActionReadSurfaceStream          RouteAction = "surface.read_stream"
	RouteActionAcknowledgeSurfaceStream   RouteAction = "surface.acknowledge_stream"
	RouteActionCancelSurfaceOperation     RouteAction = "surface.cancel_operation"
	RouteActionRejectSurfaceConfirmation  RouteAction = "surface.reject_confirmation"
	RouteActionDisposeSurface             RouteAction = "surface.dispose"
	RouteActionCallPluginMethod           RouteAction = "plugin.call_method"
	RouteActionPrepareMethodConfirmation  RouteAction = "plugin.prepare_method_confirmation"
	RouteActionListIntents                RouteAction = "intent.list"
	RouteActionInvokeIntent               RouteAction = "intent.invoke"
	RouteActionListOperations             RouteAction = "operation.list"
	RouteActionGetOperation               RouteAction = "operation.get"
	RouteActionCancelOperation            RouteAction = "operation.cancel"
	RouteActionStartRuntime               RouteAction = "runtime.start"
	RouteActionStopRuntime                RouteAction = "runtime.stop"
	RouteActionRefreshEnabledRuntimeState RouteAction = "runtime.refresh_enabled"
	RouteActionGetRuntimeHealth           RouteAction = "runtime.get_health"
	RouteActionExportData                 RouteAction = "data.export"
	RouteActionDeleteDataExport           RouteAction = "data.delete_export"
	RouteActionImportData                 RouteAction = "data.import"
	RouteActionListRetainedData           RouteAction = "retained_data.list"
	RouteActionDeleteRetainedData         RouteAction = "retained_data.delete"
	RouteActionBindRetainedData           RouteAction = "retained_data.bind"
	RouteActionCleanupExpiredRetainedData RouteAction = "retained_data.cleanup_expired"
	RouteActionListPermissions            RouteAction = "permission.list"
	RouteActionGetPermissionRequirements  RouteAction = "permission.requirements.get"
	RouteActionGrantPermission            RouteAction = "permission.grant"
	RouteActionRevokePermission           RouteAction = "permission.revoke"
	RouteActionListSecurityPolicies       RouteAction = "security_policy.list"
	RouteActionGetSecurityPolicy          RouteAction = "security_policy.get"
	RouteActionPutSecurityPolicy          RouteAction = "security_policy.put"
	RouteActionDeleteSecurityPolicy       RouteAction = "security_policy.delete"
	RouteActionListDiagnostics            RouteAction = "diagnostic.list"
	RouteActionBindSecret                 RouteAction = "secret.bind"
	RouteActionTestSecret                 RouteAction = "secret.test"
	RouteActionDeleteSecret               RouteAction = "secret.delete"
	RouteActionGetSettingsSchema          RouteAction = "settings.get_schema"
	RouteActionGetSettings                RouteAction = "settings.get"
	RouteActionPatchSettings              RouteAction = "settings.patch"
)

func (action RouteAction) Valid() bool {
	switch action {
	case RouteActionImportLocalPackage, RouteActionInstallReleaseRef,
		RouteActionInspectExternalPackage, RouteActionCommitExternalPackage,
		RouteActionQueryExternalPackageCommit, RouteActionEnablePlugin,
		RouteActionDisablePlugin, RouteActionUninstallPlugin, RouteActionUpdateLocalPackage,
		RouteActionUpdateReleaseRef, RouteActionDowngradePlugin, RouteActionListPlugins,
		RouteActionListFeatures, RouteActionGetCompatibility, RouteActionOpenSurface,
		RouteActionRevokeSessionScope, RouteActionPrepareSurface, RouteActionMintBridgeToken,
		RouteActionReadSurfaceAsset, RouteActionReadSurfaceStream, RouteActionAcknowledgeSurfaceStream,
		RouteActionCancelSurfaceOperation, RouteActionRejectSurfaceConfirmation, RouteActionDisposeSurface,
		RouteActionCallPluginMethod, RouteActionPrepareMethodConfirmation, RouteActionListIntents,
		RouteActionInvokeIntent, RouteActionListOperations, RouteActionGetOperation,
		RouteActionCancelOperation, RouteActionStartRuntime, RouteActionStopRuntime,
		RouteActionRefreshEnabledRuntimeState, RouteActionGetRuntimeHealth, RouteActionExportData,
		RouteActionDeleteDataExport, RouteActionImportData, RouteActionListRetainedData,
		RouteActionDeleteRetainedData, RouteActionBindRetainedData, RouteActionCleanupExpiredRetainedData,
		RouteActionListPermissions, RouteActionGetPermissionRequirements, RouteActionGrantPermission, RouteActionRevokePermission,
		RouteActionListSecurityPolicies, RouteActionGetSecurityPolicy, RouteActionPutSecurityPolicy,
		RouteActionDeleteSecurityPolicy, RouteActionListDiagnostics, RouteActionBindSecret,
		RouteActionTestSecret, RouteActionDeleteSecret, RouteActionGetSettingsSchema,
		RouteActionGetSettings, RouteActionPatchSettings:
		return true
	default:
		return false
	}
}

// RouteEffect defines whether cancellation can leave a request outcome
// unknown. It is trusted route metadata and is never supplied by a caller.
type RouteEffect string

const (
	RouteEffectQuery    RouteEffect = "query"
	RouteEffectMutation RouteEffect = "mutation"
)

func (effect RouteEffect) Valid() bool {
	return effect == RouteEffectQuery || effect == RouteEffectMutation
}

type OriginPolicy string

const OriginPolicyTrustedHost OriginPolicy = "trusted_host"

func (policy OriginPolicy) Valid() bool {
	return policy == OriginPolicyTrustedHost
}

type CSRFPolicy string

const (
	CSRFPolicyNotRequired CSRFPolicy = "not_required"
	CSRFPolicyRequired    CSRFPolicy = "required"
)

func (policy CSRFPolicy) Valid() bool {
	return policy == CSRFPolicyNotRequired || policy == CSRFPolicyRequired
}

type Guard interface {
	Authenticate(r *http.Request) (sessionctx.Context, error)
	ValidateOrigin(r *http.Request, session sessionctx.Context, policy OriginPolicy) error
	ValidateCSRF(r *http.Request, session sessionctx.Context, policy CSRFPolicy) error
	AuthorizeRoute(r *http.Request, session sessionctx.Context, action RouteAction, effect RouteEffect) error
}
