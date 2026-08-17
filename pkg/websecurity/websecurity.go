package websecurity

import (
	"errors"
	"net/http"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
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

// RouteAction is the HTTP-facing name for the Host's single closed action set.
type RouteAction = host.ManagementAction

const (
	RouteActionImportLocalPackage         = host.ManagementActionImportLocalPackage
	RouteActionInstallReleaseRef          = host.ManagementActionInstallReleaseRef
	RouteActionInspectExternalPackage     = host.ManagementActionInspectExternalPackage
	RouteActionInstallInspectedPackage    = host.ManagementActionInstallInspectedPackage
	RouteActionEnablePlugin               = host.ManagementActionEnablePlugin
	RouteActionDisablePlugin              = host.ManagementActionDisablePlugin
	RouteActionUninstallPlugin            = host.ManagementActionUninstallPlugin
	RouteActionUpdateLocalPackage         = host.ManagementActionUpdateLocalPackage
	RouteActionUpdateReleaseRef           = host.ManagementActionUpdateReleaseRef
	RouteActionDowngradePlugin            = host.ManagementActionDowngradePlugin
	RouteActionListPlugins                = host.ManagementActionListPlugins
	RouteActionListFeatures               = host.ManagementActionListFeatures
	RouteActionOpenSurface                = host.ManagementActionOpenSurface
	RouteActionRevokeSessionScope         = host.ManagementActionRevokeSessionScope
	RouteActionPrepareSurface             = host.ManagementActionPrepareSurface
	RouteActionMintBridgeToken            = host.ManagementActionMintBridgeToken
	RouteActionReadSurfaceAsset           = host.ManagementActionReadSurfaceAsset
	RouteActionRejectSurfaceConfirmation  = host.ManagementActionRejectSurfaceConfirmation
	RouteActionDisposeSurface             = host.ManagementActionDisposeSurface
	RouteActionCallPluginMethod           = host.ManagementActionCallPluginMethod
	RouteActionPrepareMethodConfirmation  = host.ManagementActionPrepareMethodConfirmation
	RouteActionListIntents                = host.ManagementActionListIntents
	RouteActionInvokeIntent               = host.ManagementActionInvokeIntent
	RouteActionListExecutions             = host.ManagementActionListExecutions
	RouteActionGetExecution               = host.ManagementActionGetExecution
	RouteActionCancelExecution            = host.ManagementActionCancelExecution
	RouteActionListExecutionEvents        = host.ManagementActionListExecutionEvents
	RouteActionStartRuntime               = host.ManagementActionStartRuntime
	RouteActionStopRuntime                = host.ManagementActionStopRuntime
	RouteActionRecoverEnabledPlugins      = host.ManagementActionRecoverEnabledPlugins
	RouteActionGetRuntimeHealth           = host.ManagementActionGetRuntimeHealth
	RouteActionExportData                 = host.ManagementActionExportPluginData
	RouteActionDeleteDataExport           = host.ManagementActionDeleteExportedPluginData
	RouteActionImportData                 = host.ManagementActionImportPluginData
	RouteActionListRetainedData           = host.ManagementActionListRetainedData
	RouteActionDeleteRetainedData         = host.ManagementActionDeleteRetainedData
	RouteActionCleanupExpiredRetainedData = host.ManagementActionCleanupExpiredRetainedData
	RouteActionListPermissions            = host.ManagementActionListPermissionGrants
	RouteActionGetPermissionRequirements  = host.ManagementActionGetPermissionRequirements
	RouteActionGrantPermission            = host.ManagementActionGrantPermission
	RouteActionRevokePermission           = host.ManagementActionRevokePermission
	RouteActionListSecurityPolicies       = host.ManagementActionListSecurityPolicies
	RouteActionGetSecurityPolicy          = host.ManagementActionGetSecurityPolicy
	RouteActionPutSecurityPolicy          = host.ManagementActionPutSecurityPolicy
	RouteActionDeleteSecurityPolicy       = host.ManagementActionDeleteSecurityPolicy
	RouteActionListDiagnostics            = host.ManagementActionListDiagnosticEvents
	RouteActionBindSecret                 = host.ManagementActionBindSecretRef
	RouteActionTestSecret                 = host.ManagementActionTestSecretRef
	RouteActionDeleteSecret               = host.ManagementActionDeleteSecretRef
	RouteActionGetSettingsSchema          = host.ManagementActionGetSettingsSchema
	RouteActionGetSettings                = host.ManagementActionGetPluginSettings
	RouteActionPatchSettings              = host.ManagementActionPatchPluginSettings
)

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
