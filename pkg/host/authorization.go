package host

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	ManagementActionRevokeSessionScope         ManagementAction = "session.revoke_scope"
	ManagementActionFinalizeSessionScope       ManagementAction = "session.finalize_scope"
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
		ManagementActionDisposeSurface:
		return ResourceSurface
	case ManagementActionRevokeSessionScope, ManagementActionFinalizeSessionScope:
		return ResourceSessionScope
	case ManagementActionReadSurfaceStream, ManagementActionAcknowledgeSurfaceStream:
		return ResourceStream
	case ManagementActionCancelSurfaceOperation:
		return ResourceOperation
	case ManagementActionRejectSurfaceConfirmation:
		return ResourceConfirmation
	case ManagementActionCallPluginMethod, ManagementActionPrepareMethodConfirmation:
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
		return ResourceConnector
	case ManagementActionMintStorageHandleGrant:
		return ResourceStore
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

// ResourceRef identifies one closed host-neutral resource family.
type ResourceRef string

const (
	ResourcePlugin            ResourceRef = "plugin"
	ResourcePlatform          ResourceRef = "platform"
	ResourceSurface           ResourceRef = "surface"
	ResourceSurfaceDefinition ResourceRef = "surface_definition"
	ResourceSurfaceAsset      ResourceRef = "surface_asset"
	ResourceAssetSession      ResourceRef = "asset_session"
	ResourceBridgeChannel     ResourceRef = "bridge_channel"
	ResourceStream            ResourceRef = "stream"
	ResourceConfirmation      ResourceRef = "confirmation"
	ResourceMethod            ResourceRef = "method"
	ResourceIntent            ResourceRef = "intent"
	ResourcePermission        ResourceRef = "permission"
	ResourceSecurityPolicy    ResourceRef = "security_policy"
	ResourceDiagnostic        ResourceRef = "diagnostic"
	ResourceOperation         ResourceRef = "operation"
	ResourceRuntime           ResourceRef = "runtime"
	ResourceConnector         ResourceRef = "connector"
	ResourceStore             ResourceRef = "store"
	ResourceRetainedData      ResourceRef = "retained_data"
	ResourcePluginData        ResourceRef = "plugin_data"
	ResourceDataExport        ResourceRef = "data_export"
	ResourceSettings          ResourceRef = "settings"
	ResourceSecret            ResourceRef = "secret"
	ResourceSessionScope      ResourceRef = "session_scope"
)

func (resource ResourceRef) Valid() bool {
	switch resource {
	case ResourcePlugin, ResourcePlatform, ResourceSurface,
		ResourceSurfaceDefinition, ResourceSurfaceAsset,
		ResourceAssetSession, ResourceBridgeChannel, ResourceStream,
		ResourceConfirmation, ResourceMethod, ResourceIntent, ResourcePermission,
		ResourceSecurityPolicy, ResourceDiagnostic, ResourceOperation,
		ResourceRuntime, ResourceConnector, ResourceStore,
		ResourceRetainedData, ResourcePluginData, ResourceDataExport,
		ResourceSettings, ResourceSecret, ResourceSessionScope:
		return true
	default:
		return false
	}
}

// AuthorizationTarget is one canonical resource presented to an embedding
// product's authorization policy. ResourceScope is always derived by Host from
// the authenticated session and is never accepted from wire or plugin input.
type AuthorizationTarget struct {
	Kind       ResourceRef               `json:"kind"`
	ID         string                    `json:"id,omitempty"`
	Collection bool                      `json:"collection,omitempty"`
	Scope      *sessionctx.ResourceScope `json:"-"`
}

type AuthorizationRequest struct {
	// Session is derived from the authenticated context by Host and is never
	// accepted from a command, HTTP payload, or plugin IPC request.
	Session        sessionctx.Context    `json:"-"`
	Action         ManagementAction      `json:"action"`
	Target         AuthorizationTarget   `json:"target"`
	RelatedTargets []AuthorizationTarget `json:"related_targets,omitempty"`
}

type AuthorizationAdapter interface {
	// Authorize returns ErrActionDenied only for an explicit policy denial.
	// Any other error is treated as an operational adapter failure.
	Authorize(ctx context.Context, req AuthorizationRequest) error
}

type authorizedAction struct {
	session sessionctx.Context
}

type sessionReservationContextKey struct{}

type sessionReservationContext struct {
	host  *Host
	scope sessionctx.SessionScope
}

func (h *Host) reserveAuthorizedAction(ctx context.Context, authorization authorizedAction) (context.Context, func(), error) {
	scope, err := authorization.session.SessionScope()
	if err != nil {
		return ctx, nil, err
	}
	if held, ok := ctx.Value(sessionReservationContextKey{}).(sessionReservationContext); ok && held.host == h && held.scope == scope {
		return ctx, func() {}, nil
	}
	reservation, err := h.sessionScopes.Reserve(ctx, scope)
	if err != nil {
		return ctx, nil, err
	}
	reserved := context.WithValue(ctx, sessionReservationContextKey{}, sessionReservationContext{host: h, scope: scope})
	return reserved, reservation.Release, nil
}

type authorizationTargetSpec struct {
	kind       ResourceRef
	id         string
	collection bool
	scopeKind  sessionctx.ScopeKind
}

func authorizationTarget(kind ResourceRef, id string) authorizationTargetSpec {
	return authorizationTargetSpec{kind: kind, id: id}
}

func scopedAuthorizationTarget(kind ResourceRef, id string, scopeKind sessionctx.ScopeKind) authorizationTargetSpec {
	return authorizationTargetSpec{kind: kind, id: id, scopeKind: scopeKind}
}

func authorizationCollectionTarget(kind ResourceRef) authorizationTargetSpec {
	return authorizationTargetSpec{kind: kind, collection: true}
}

func scopedAuthorizationCollectionTarget(kind ResourceRef, scopeKind sessionctx.ScopeKind) authorizationTargetSpec {
	return authorizationTargetSpec{kind: kind, collection: true, scopeKind: scopeKind}
}

func authorizationTargetOrCollection(kind ResourceRef, id string) authorizationTargetSpec {
	if strings.TrimSpace(id) == "" {
		return authorizationCollectionTarget(kind)
	}
	return authorizationTarget(kind, id)
}

func scopedAuthorizationTargetOrCollection(kind ResourceRef, id string, scopeKind sessionctx.ScopeKind) authorizationTargetSpec {
	if strings.TrimSpace(id) == "" {
		return scopedAuthorizationCollectionTarget(kind, scopeKind)
	}
	return scopedAuthorizationTarget(kind, id, scopeKind)
}

func relatedAuthorizationTargets(specs ...authorizationTargetSpec) []authorizationTargetSpec {
	result := make([]authorizationTargetSpec, 0, len(specs))
	for _, spec := range specs {
		if strings.TrimSpace(spec.id) != "" {
			result = append(result, spec)
		}
	}
	return result
}

type ActionDeniedError struct {
	Action ManagementAction
	Target AuthorizationTarget
}

func (e ActionDeniedError) Error() string {
	return fmt.Sprintf("%s: %s on %s", ErrActionDenied, e.Action, e.Target.Kind)
}

func (e ActionDeniedError) Unwrap() error { return ErrActionDenied }

func (h *Host) authorizeManagement(ctx context.Context, action ManagementAction, target authorizationTargetSpec, related ...authorizationTargetSpec) (authorizedAction, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return authorizedAction{}, err
	}
	return h.authorizeManagementSession(ctx, session, action, target, related...)
}

func (h *Host) authorizeManagementSession(ctx context.Context, session sessionctx.Context, action ManagementAction, target authorizationTargetSpec, related ...authorizationTargetSpec) (authorizedAction, error) {
	authorization, err := h.authorizeManagementSessionWithoutFence(ctx, session, action, target, related...)
	if err != nil {
		return authorizedAction{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return authorizedAction{}, err
	}
	if held, ok := ctx.Value(sessionReservationContextKey{}).(sessionReservationContext); ok && held.host == h && held.scope == scope {
		return authorization, nil
	}
	reservation, err := h.sessionScopes.Reserve(ctx, scope)
	if err != nil {
		return authorizedAction{}, err
	}
	reservation.Release()
	return authorization, nil
}

func (h *Host) authorizeManagementSessionWithoutFence(ctx context.Context, session sessionctx.Context, action ManagementAction, target authorizationTargetSpec, related ...authorizationTargetSpec) (authorizedAction, error) {
	resource := action.Resource()
	if !action.Valid() || !resource.Valid() || isNilInterfaceValue(h.adapters.Authorization) {
		return authorizedAction{}, ActionDeniedError{Action: action, Target: AuthorizationTarget{Kind: resource}}
	}
	canonicalTarget, err := canonicalAuthorizationTarget(session, target)
	if err != nil || canonicalTarget.Kind != resource ||
		(canonicalTarget.Collection && !action.allowsCollectionTarget()) ||
		(!canonicalTarget.Collection && canonicalTarget.ID == "") {
		return authorizedAction{}, ActionDeniedError{Action: action, Target: canonicalTarget}
	}
	relatedTargets := make([]AuthorizationTarget, len(related))
	for i := range related {
		relatedTargets[i], err = canonicalAuthorizationTarget(session, related[i])
		if err != nil || relatedTargets[i].ID == "" {
			return authorizedAction{}, ActionDeniedError{Action: action, Target: canonicalTarget}
		}
	}
	req := AuthorizationRequest{
		Session:        session,
		Action:         action,
		Target:         canonicalTarget,
		RelatedTargets: relatedTargets,
	}
	if err := h.adapters.Authorization.Authorize(ctx, req); err != nil {
		if errors.Is(err, ErrActionDenied) {
			return authorizedAction{}, ActionDeniedError{Action: action, Target: canonicalTarget}
		}
		return authorizedAction{}, fmt.Errorf("%w: authorization", ErrAdapterFailure)
	}
	return authorizedAction{session: session}, nil
}

func canonicalAuthorizationTarget(session sessionctx.Context, spec authorizationTargetSpec) (AuthorizationTarget, error) {
	target := AuthorizationTarget{Kind: spec.kind, ID: strings.TrimSpace(spec.id), Collection: spec.collection}
	if !target.Kind.Valid() {
		return target, errors.New("authorization target kind is invalid")
	}
	if target.Collection && target.ID != "" {
		return target, errors.New("authorization collection target must not include an ID")
	}
	if spec.scopeKind != "" {
		scope, err := session.ResourceScope(spec.scopeKind)
		if err != nil {
			return target, err
		}
		target.Scope = &scope
	}
	return target, nil
}

func (action ManagementAction) allowsCollectionTarget() bool {
	switch action {
	case ManagementActionRevokeSessionScope,
		ManagementActionListIntents,
		ManagementActionListPlugins,
		ManagementActionRefreshEnabledPlugins,
		ManagementActionListPermissionGrants,
		ManagementActionListSecurityPolicies,
		ManagementActionListDiagnosticEvents,
		ManagementActionListOperations,
		ManagementActionListRetainedData,
		ManagementActionCleanupExpiredRetainedData:
		return true
	default:
		return false
	}
}
