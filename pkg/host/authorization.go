package host

import (
	"context"
	"errors"
	"fmt"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

var ErrActionDenied = errors.New("host platform action is denied")

// ManagementAction identifies one direct Host platform operation. The set is
// closed so embedding products can implement exhaustive authorization policy.
type ManagementAction string

const (
	ManagementActionOpenSurface                ManagementAction = "surface.open"
	ManagementActionPrepareSurface             ManagementAction = "surface.prepare"
	ManagementActionMintBridgeToken            ManagementAction = "surface.mint_bridge_token"
	ManagementActionReadSurfaceAsset           ManagementAction = "surface.read_asset"
	ManagementActionReadSurfaceStream          ManagementAction = "surface.read_stream"
	ManagementActionAcknowledgeSurfaceStream   ManagementAction = "surface.acknowledge_stream"
	ManagementActionCancelSurfaceOperation     ManagementAction = "surface.cancel_operation"
	ManagementActionRejectSurfaceConfirmation  ManagementAction = "surface.reject_confirmation"
	ManagementActionDisposeSurface             ManagementAction = "surface.dispose"
	ManagementActionRevokeSurfaceScope         ManagementAction = "surface.revoke_scope"
	ManagementActionCallPluginMethod           ManagementAction = "plugin.call_method"
	ManagementActionPrepareMethodConfirmation  ManagementAction = "plugin.prepare_method_confirmation"
	ManagementActionListIntents                ManagementAction = "intent.list"
	ManagementActionInvokeIntent               ManagementAction = "intent.invoke"
	ManagementActionImportLocalPackage         ManagementAction = "plugin.import_local_package"
	ManagementActionInstallReleaseRef          ManagementAction = "plugin.install_release_ref"
	ManagementActionUpdateLocalPackage         ManagementAction = "plugin.update_local_package"
	ManagementActionUpdateReleaseRef           ManagementAction = "plugin.update_release_ref"
	ManagementActionDowngradePlugin            ManagementAction = "plugin.downgrade"
	ManagementActionListPlugins                ManagementAction = "plugin.list"
	ManagementActionListFeatures               ManagementAction = "platform.list_features"
	ManagementActionGetCompatibility           ManagementAction = "platform.get_compatibility"
	ManagementActionRefreshEnabledPlugins      ManagementAction = "runtime.refresh_enabled"
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
	case ManagementActionOpenSurface, ManagementActionPrepareSurface,
		ManagementActionMintBridgeToken, ManagementActionReadSurfaceAsset,
		ManagementActionDisposeSurface, ManagementActionRevokeSurfaceScope:
		return ResourceSurface
	case ManagementActionReadSurfaceStream, ManagementActionAcknowledgeSurfaceStream:
		return ResourceStream
	case ManagementActionCancelSurfaceOperation:
		return ResourceOperation
	case ManagementActionRejectSurfaceConfirmation, ManagementActionPrepareMethodConfirmation:
		return ResourceConfirmation
	case ManagementActionCallPluginMethod:
		return ResourceMethod
	case ManagementActionListIntents, ManagementActionInvokeIntent:
		return ResourceIntent
	case ManagementActionImportLocalPackage, ManagementActionInstallReleaseRef,
		ManagementActionUpdateLocalPackage, ManagementActionUpdateReleaseRef,
		ManagementActionDowngradePlugin, ManagementActionListPlugins,
		ManagementActionEnablePlugin,
		ManagementActionDisablePlugin, ManagementActionUninstallPlugin:
		return ResourcePlugin
	case ManagementActionListFeatures, ManagementActionGetCompatibility:
		return ResourcePlatform
	case ManagementActionGrantPermission, ManagementActionRevokePermission, ManagementActionListPermissionGrants:
		return ResourcePermission
	case ManagementActionPutSecurityPolicy, ManagementActionGetSecurityPolicy,
		ManagementActionListSecurityPolicies, ManagementActionDeleteSecurityPolicy:
		return ResourceSecurityPolicy
	case ManagementActionListDiagnosticEvents:
		return ResourceDiagnostic
	case ManagementActionListOperations, ManagementActionGetOperation, ManagementActionCancelOperation:
		return ResourceOperation
	case ManagementActionStartRuntime, ManagementActionStopRuntime, ManagementActionGetRuntimeHealth,
		ManagementActionRefreshEnabledPlugins:
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
	ResourcePlatform       ResourceRef = "platform"
	ResourceSurface        ResourceRef = "surface"
	ResourceStream         ResourceRef = "stream"
	ResourceConfirmation   ResourceRef = "confirmation"
	ResourceMethod         ResourceRef = "method"
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
	case ResourcePlugin, ResourcePlatform, ResourceSurface, ResourceStream,
		ResourceConfirmation, ResourceMethod, ResourceIntent, ResourcePermission,
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
	// Session is derived from the authenticated context by Host and is never
	// accepted from a command, HTTP payload, or plugin IPC request.
	Session            sessionctx.Context `json:"-"`
	Action             ManagementAction   `json:"action"`
	Resource           ResourceRef        `json:"resource"`
	ResourceID         string             `json:"resource_id,omitempty"`
	RelatedResourceIDs []string           `json:"related_resource_ids,omitempty"`
}

type AuthorizationAdapter interface {
	Authorize(ctx context.Context, req AuthorizationRequest) error
}

type authorizedAction struct {
	session sessionctx.Context
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

func (h *Host) authorizeManagement(ctx context.Context, action ManagementAction, resourceID string, relatedResourceIDs ...string) (authorizedAction, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return authorizedAction{}, err
	}
	resource := action.Resource()
	if !action.Valid() || !resource.Valid() || isNilInterfaceValue(h.adapters.Authorization) {
		return authorizedAction{}, ActionDeniedError{Action: action, Resource: resource, ResourceID: resourceID}
	}
	req := AuthorizationRequest{
		Session:            session,
		Action:             action,
		Resource:           resource,
		ResourceID:         resourceID,
		RelatedResourceIDs: append([]string(nil), relatedResourceIDs...),
	}
	if err := h.adapters.Authorization.Authorize(ctx, req); err != nil {
		return authorizedAction{}, ActionDeniedError{Action: action, Resource: resource, ResourceID: resourceID}
	}
	return authorizedAction{session: session}, nil
}
