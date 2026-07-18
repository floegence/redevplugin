package host

import (
	"context"
	"errors"
	"fmt"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

var ErrActionDenied = errors.New("host management action is denied")

// ManagementAction identifies one direct Host management operation. The set is
// closed so embedding products can implement exhaustive authorization policy.
type ManagementAction string

const (
	ManagementActionOpenSurface                ManagementAction = "surface.open"
	ManagementActionListIntents                ManagementAction = "intent.list"
	ManagementActionInvokeIntent               ManagementAction = "intent.invoke"
	ManagementActionImportLocalPackage         ManagementAction = "plugin.import_local_package"
	ManagementActionInstallReleaseRef          ManagementAction = "plugin.install_release_ref"
	ManagementActionUpdateLocalPackage         ManagementAction = "plugin.update_local_package"
	ManagementActionUpdateReleaseRef           ManagementAction = "plugin.update_release_ref"
	ManagementActionDowngradePlugin            ManagementAction = "plugin.downgrade"
	ManagementActionListPlugins                ManagementAction = "plugin.list"
	ManagementActionRefreshEnabledPlugins      ManagementAction = "plugin.refresh_enabled"
	ManagementActionGrantPermission            ManagementAction = "permission.grant"
	ManagementActionRevokePermission           ManagementAction = "permission.revoke"
	ManagementActionListPermissionGrants       ManagementAction = "permission.list"
	ManagementActionPutSecurityPolicy          ManagementAction = "security_policy.put"
	ManagementActionGetSecurityPolicy          ManagementAction = "security_policy.get"
	ManagementActionListSecurityPolicies       ManagementAction = "security_policy.list"
	ManagementActionDeleteSecurityPolicy       ManagementAction = "security_policy.delete"
	ManagementActionListDiagnosticEvents       ManagementAction = "diagnostic.list"
	ManagementActionListOperations             ManagementAction = "operation.list"
	ManagementActionGetOperation               ManagementAction = "operation.get"
	ManagementActionCancelOperation            ManagementAction = "operation.cancel"
	ManagementActionStartRuntime               ManagementAction = "runtime.start"
	ManagementActionStopRuntime                ManagementAction = "runtime.stop"
	ManagementActionGetRuntimeHealth           ManagementAction = "runtime.get_health"
	ManagementActionMintConnectionGrant        ManagementAction = "connectivity.mint_grant"
	ManagementActionMintNetworkHandleGrant     ManagementAction = "connectivity.mint_handle_grant"
	ManagementActionMintStorageHandleGrant     ManagementAction = "storage.mint_handle_grant"
	ManagementActionEnablePlugin               ManagementAction = "plugin.enable"
	ManagementActionDisablePlugin              ManagementAction = "plugin.disable"
	ManagementActionUninstallPlugin            ManagementAction = "plugin.uninstall"
	ManagementActionListRetainedData           ManagementAction = "retained_data.list"
	ManagementActionDeleteRetainedData         ManagementAction = "retained_data.delete"
	ManagementActionBindRetainedData           ManagementAction = "retained_data.bind"
	ManagementActionCleanupExpiredRetainedData ManagementAction = "retained_data.cleanup_expired"
	ManagementActionExportPluginData           ManagementAction = "data.export"
	ManagementActionDeleteExportedPluginData   ManagementAction = "data.delete_export"
	ManagementActionImportPluginData           ManagementAction = "data.import"
	ManagementActionGetSettingsSchema          ManagementAction = "settings.get_schema"
	ManagementActionGetPluginSettings          ManagementAction = "settings.get"
	ManagementActionPatchPluginSettings        ManagementAction = "settings.patch"
	ManagementActionBindSecretRef              ManagementAction = "secret.bind"
	ManagementActionTestSecretRef              ManagementAction = "secret.test"
	ManagementActionDeleteSecretRef            ManagementAction = "secret.delete"
)

func (action ManagementAction) Valid() bool {
	return action.Resource().Valid()
}

func (action ManagementAction) Resource() ResourceRef {
	switch action {
	case ManagementActionOpenSurface:
		return ResourceSurface
	case ManagementActionListIntents, ManagementActionInvokeIntent:
		return ResourceIntent
	case ManagementActionImportLocalPackage, ManagementActionInstallReleaseRef,
		ManagementActionUpdateLocalPackage, ManagementActionUpdateReleaseRef,
		ManagementActionDowngradePlugin, ManagementActionListPlugins,
		ManagementActionRefreshEnabledPlugins, ManagementActionEnablePlugin,
		ManagementActionDisablePlugin, ManagementActionUninstallPlugin:
		return ResourcePlugin
	case ManagementActionGrantPermission, ManagementActionRevokePermission, ManagementActionListPermissionGrants:
		return ResourcePermission
	case ManagementActionPutSecurityPolicy, ManagementActionGetSecurityPolicy,
		ManagementActionListSecurityPolicies, ManagementActionDeleteSecurityPolicy:
		return ResourceSecurityPolicy
	case ManagementActionListDiagnosticEvents:
		return ResourceDiagnostic
	case ManagementActionListOperations, ManagementActionGetOperation, ManagementActionCancelOperation:
		return ResourceOperation
	case ManagementActionStartRuntime, ManagementActionStopRuntime, ManagementActionGetRuntimeHealth:
		return ResourceRuntime
	case ManagementActionMintConnectionGrant, ManagementActionMintNetworkHandleGrant:
		return ResourceConnectivity
	case ManagementActionMintStorageHandleGrant:
		return ResourceStorage
	case ManagementActionListRetainedData, ManagementActionDeleteRetainedData,
		ManagementActionBindRetainedData, ManagementActionCleanupExpiredRetainedData:
		return ResourceRetainedData
	case ManagementActionExportPluginData, ManagementActionImportPluginData:
		return ResourcePluginData
	case ManagementActionDeleteExportedPluginData:
		return ResourceDataExport
	case ManagementActionGetSettingsSchema, ManagementActionGetPluginSettings, ManagementActionPatchPluginSettings:
		return ResourceSettings
	case ManagementActionBindSecretRef, ManagementActionTestSecretRef, ManagementActionDeleteSecretRef:
		return ResourceSecret
	default:
		return ""
	}
}

// ResourceRef identifies the closed resource family governed by a management
// action. ResourceID carries the host-neutral instance identifier separately.
type ResourceRef string

const (
	ResourcePlugin         ResourceRef = "plugin"
	ResourceSurface        ResourceRef = "surface"
	ResourceIntent         ResourceRef = "intent"
	ResourcePermission     ResourceRef = "permission"
	ResourceSecurityPolicy ResourceRef = "security_policy"
	ResourceDiagnostic     ResourceRef = "diagnostic"
	ResourceOperation      ResourceRef = "operation"
	ResourceRuntime        ResourceRef = "runtime"
	ResourceConnectivity   ResourceRef = "connectivity"
	ResourceStorage        ResourceRef = "storage"
	ResourceRetainedData   ResourceRef = "retained_data"
	ResourcePluginData     ResourceRef = "plugin_data"
	ResourceDataExport     ResourceRef = "data_export"
	ResourceSettings       ResourceRef = "settings"
	ResourceSecret         ResourceRef = "secret"
)

func (resource ResourceRef) Valid() bool {
	switch resource {
	case ResourcePlugin, ResourceSurface, ResourceIntent, ResourcePermission,
		ResourceSecurityPolicy, ResourceDiagnostic, ResourceOperation,
		ResourceRuntime, ResourceConnectivity, ResourceStorage,
		ResourceRetainedData, ResourcePluginData, ResourceDataExport,
		ResourceSettings, ResourceSecret:
		return true
	default:
		return false
	}
}

type AuthorizationRequest struct {
	Session            sessionctx.Context `json:"-"`
	Action             ManagementAction   `json:"action"`
	Resource           ResourceRef        `json:"resource"`
	ResourceID         string             `json:"resource_id,omitempty"`
	RelatedResourceIDs []string           `json:"related_resource_ids,omitempty"`
}

type AuthorizationAdapter interface {
	Authorize(ctx context.Context, req AuthorizationRequest) error
}

type ActionDeniedError struct {
	Action     ManagementAction
	Resource   ResourceRef
	ResourceID string
}

func (e ActionDeniedError) Error() string {
	return fmt.Sprintf("%s: %s on %s", ErrActionDenied, e.Action, e.Resource)
}

func (e ActionDeniedError) Unwrap() error { return ErrActionDenied }

func (h *Host) authorizeManagement(ctx context.Context, action ManagementAction, resourceID string, relatedResourceIDs ...string) (sessionctx.Context, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return sessionctx.Context{}, err
	}
	resource := action.Resource()
	if !action.Valid() || !resource.Valid() || isNilInterfaceValue(h.adapters.Authorization) {
		return sessionctx.Context{}, ActionDeniedError{Action: action, Resource: resource, ResourceID: resourceID}
	}
	req := AuthorizationRequest{
		Session:            session,
		Action:             action,
		Resource:           resource,
		ResourceID:         resourceID,
		RelatedResourceIDs: append([]string(nil), relatedResourceIDs...),
	}
	if err := h.adapters.Authorization.Authorize(ctx, req); err != nil {
		return sessionctx.Context{}, ActionDeniedError{Action: action, Resource: resource, ResourceID: resourceID}
	}
	return session, nil
}
