package host

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type recordingAuthorizationAdapter struct {
	err      error
	requests []AuthorizationRequest
}

func (a *recordingAuthorizationAdapter) Authorize(_ context.Context, req AuthorizationRequest) error {
	req.RelatedResourceIDs = append([]string(nil), req.RelatedResourceIDs...)
	a.requests = append(a.requests, req)
	return a.err
}

func TestManagementActionAndResourceContractsAreClosed(t *testing.T) {
	if ManagementAction("plugin.unknown").Valid() || ManagementAction("plugin.unknown").Resource().Valid() {
		t.Fatal("unknown management action must be invalid")
	}
	if ResourceRef("unknown").Valid() {
		t.Fatal("unknown resource ref must be invalid")
	}
	seen := make(map[ManagementAction]struct{})
	for _, action := range []ManagementAction{
		ManagementActionOpenSurface,
		ManagementActionPrepareSurface,
		ManagementActionMintBridgeToken,
		ManagementActionReadSurfaceAsset,
		ManagementActionReadSurfaceStream,
		ManagementActionAcknowledgeSurfaceStream,
		ManagementActionCancelSurfaceOperation,
		ManagementActionRejectSurfaceConfirmation,
		ManagementActionDisposeSurface,
		ManagementActionRevokeSurfaceScope,
		ManagementActionCallPluginMethod,
		ManagementActionPrepareMethodConfirmation,
		ManagementActionListIntents,
		ManagementActionInvokeIntent,
		ManagementActionImportLocalPackage,
		ManagementActionInstallReleaseRef,
		ManagementActionUpdateLocalPackage,
		ManagementActionUpdateReleaseRef,
		ManagementActionDowngradePlugin,
		ManagementActionListPlugins,
		ManagementActionListFeatures,
		ManagementActionGetCompatibility,
		ManagementActionRefreshEnabledPlugins,
		ManagementActionGrantPermission,
		ManagementActionRevokePermission,
		ManagementActionListPermissionGrants,
		ManagementActionPutSecurityPolicy,
		ManagementActionGetSecurityPolicy,
		ManagementActionListSecurityPolicies,
		ManagementActionDeleteSecurityPolicy,
		ManagementActionListDiagnosticEvents,
		ManagementActionListOperations,
		ManagementActionGetOperation,
		ManagementActionCancelOperation,
		ManagementActionStartRuntime,
		ManagementActionStopRuntime,
		ManagementActionGetRuntimeHealth,
		ManagementActionMintConnectionGrant,
		ManagementActionMintNetworkHandleGrant,
		ManagementActionMintStorageHandleGrant,
		ManagementActionEnablePlugin,
		ManagementActionDisablePlugin,
		ManagementActionUninstallPlugin,
		ManagementActionListRetainedData,
		ManagementActionDeleteRetainedData,
		ManagementActionBindRetainedData,
		ManagementActionCleanupExpiredRetainedData,
		ManagementActionExportPluginData,
		ManagementActionDeleteExportedPluginData,
		ManagementActionImportPluginData,
		ManagementActionGetSettingsSchema,
		ManagementActionGetPluginSettings,
		ManagementActionPatchPluginSettings,
		ManagementActionBindSecretRef,
		ManagementActionTestSecretRef,
		ManagementActionDeleteSecretRef,
	} {
		if !action.Valid() || !action.Resource().Valid() {
			t.Fatalf("action %q has invalid resource %q", action, action.Resource())
		}
		if _, exists := seen[action]; exists {
			t.Fatalf("management action %q is duplicated", action)
		}
		seen[action] = struct{}{}
	}
}

func TestDirectManagementAPIsFailClosedBeforeBusinessValidation(t *testing.T) {
	adapterFailure := errors.New("private authorization backend detail")
	authorization := &recordingAuthorizationAdapter{err: adapterFailure}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		authorization:  authorization,
	})
	ctx := hostTestContext()
	wantSession, err := requireUserSession(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		action ManagementAction
		call   func() error
	}{
		{"open surface", ManagementActionOpenSurface, func() error { _, err := h.OpenSurface(ctx, OpenSurfaceRequest{}); return err }},
		{"prepare surface", ManagementActionPrepareSurface, func() error { _, err := h.PrepareSurface(ctx, PrepareSurfaceRequest{}); return err }},
		{"mint bridge token", ManagementActionMintBridgeToken, func() error { _, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{}); return err }},
		{"read surface asset", ManagementActionReadSurfaceAsset, func() error { _, err := h.ReadSurfaceAsset(ctx, ReadSurfaceAssetRequest{}); return err }},
		{"read surface stream", ManagementActionReadSurfaceStream, func() error { _, err := h.ReadStream(ctx, ReadStreamRequest{}); return err }},
		{"acknowledge surface stream", ManagementActionAcknowledgeSurfaceStream, func() error { _, err := h.AcknowledgeStream(ctx, AcknowledgeStreamRequest{}); return err }},
		{"cancel surface operation", ManagementActionCancelSurfaceOperation, func() error { _, err := h.CancelSurfaceOperation(ctx, CancelSurfaceOperationRequest{}); return err }},
		{"reject surface confirmation", ManagementActionRejectSurfaceConfirmation, func() error { _, err := h.RejectMethodConfirmation(ctx, RejectMethodConfirmationRequest{}); return err }},
		{"dispose surface", ManagementActionDisposeSurface, func() error { return h.DisposeSurface(ctx, DisposeSurfaceRequest{}) }},
		{"revoke surface scope", ManagementActionRevokeSurfaceScope, func() error { _, err := h.RevokeSurfaceScope(ctx, RevokeSurfaceScopeRequest{}); return err }},
		{"call plugin method", ManagementActionCallPluginMethod, func() error { _, err := h.CallPluginMethod(ctx, CallMethodRequest{}); return err }},
		{"prepare method confirmation", ManagementActionPrepareMethodConfirmation, func() error {
			_, err := h.PrepareMethodConfirmation(ctx, PrepareMethodConfirmationRequest{})
			return err
		}},
		{"list intents", ManagementActionListIntents, func() error { _, err := h.ListIntents(ctx, ListIntentsRequest{}); return err }},
		{"invoke intent", ManagementActionInvokeIntent, func() error { _, err := h.InvokeIntent(ctx, InvokeIntentRequest{}); return err }},
		{"import local package", ManagementActionImportLocalPackage, func() error { _, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{}); return err }},
		{"install release ref", ManagementActionInstallReleaseRef, func() error { _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{}); return err }},
		{"update local package", ManagementActionUpdateLocalPackage, func() error { _, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{}); return err }},
		{"update release ref", ManagementActionUpdateReleaseRef, func() error { _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{}); return err }},
		{"downgrade", ManagementActionDowngradePlugin, func() error { _, err := h.DowngradePlugin(ctx, DowngradeRequest{}); return err }},
		{"list plugins", ManagementActionListPlugins, func() error { _, err := h.ListPlugins(ctx); return err }},
		{"list features", ManagementActionListFeatures, func() error { _, err := h.ListFeatures(ctx); return err }},
		{"get compatibility", ManagementActionGetCompatibility, func() error { _, err := h.GetCompatibility(ctx); return err }},
		{"refresh enabled", ManagementActionRefreshEnabledPlugins, func() error { _, err := h.RefreshEnabledPlugins(ctx); return err }},
		{"grant permission", ManagementActionGrantPermission, func() error { _, err := h.GrantPermission(ctx, GrantPermissionRequest{}); return err }},
		{"revoke permission", ManagementActionRevokePermission, func() error { _, err := h.RevokePermission(ctx, RevokePermissionRequest{}); return err }},
		{"list permission grants", ManagementActionListPermissionGrants, func() error { _, err := h.ListPermissionGrants(ctx, ListPermissionGrantsRequest{}); return err }},
		{"put security policy", ManagementActionPutSecurityPolicy, func() error { _, err := h.PutSecurityPolicy(ctx, PutSecurityPolicyRequest{}); return err }},
		{"get security policy", ManagementActionGetSecurityPolicy, func() error { _, err := h.GetSecurityPolicy(ctx, GetSecurityPolicyRequest{}); return err }},
		{"list security policies", ManagementActionListSecurityPolicies, func() error { _, err := h.ListSecurityPolicies(ctx); return err }},
		{"delete security policy", ManagementActionDeleteSecurityPolicy, func() error { _, err := h.DeleteSecurityPolicy(ctx, DeleteSecurityPolicyRequest{}); return err }},
		{"list diagnostics", ManagementActionListDiagnosticEvents, func() error { _, err := h.ListDiagnosticEvents(ctx, ListDiagnosticEventsRequest{}); return err }},
		{"list operations", ManagementActionListOperations, func() error { _, err := h.ListOperations(ctx, ListOperationsRequest{}); return err }},
		{"get operation", ManagementActionGetOperation, func() error { _, err := h.GetOperation(ctx, ""); return err }},
		{"cancel operation", ManagementActionCancelOperation, func() error { _, err := h.CancelOperation(ctx, CancelOperationRequest{}); return err }},
		{"start runtime", ManagementActionStartRuntime, func() error { _, err := h.StartRuntime(ctx, StartRuntimeRequest{}); return err }},
		{"stop runtime", ManagementActionStopRuntime, func() error { return h.StopRuntime(ctx) }},
		{"runtime health", ManagementActionGetRuntimeHealth, func() error { _, err := h.RuntimeHealth(ctx); return err }},
		{"mint connection grant", ManagementActionMintConnectionGrant, func() error { _, err := h.MintConnectionGrant(ctx, MintConnectionGrantRequest{}); return err }},
		{"mint network handle", ManagementActionMintNetworkHandleGrant, func() error { _, err := h.MintNetworkHandleGrant(ctx, MintConnectionGrantRequest{}); return err }},
		{"mint storage handle", ManagementActionMintStorageHandleGrant, func() error { _, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{}); return err }},
		{"enable plugin", ManagementActionEnablePlugin, func() error { _, err := h.EnablePlugin(ctx, EnableRequest{}); return err }},
		{"disable plugin", ManagementActionDisablePlugin, func() error { _, err := h.DisablePlugin(ctx, DisableRequest{}); return err }},
		{"uninstall plugin", ManagementActionUninstallPlugin, func() error { _, err := h.UninstallPlugin(ctx, UninstallRequest{}); return err }},
		{"list retained data", ManagementActionListRetainedData, func() error { _, err := h.ListRetainedData(ctx, ListRetainedDataRequest{}); return err }},
		{"delete retained data", ManagementActionDeleteRetainedData, func() error { _, err := h.DeleteRetainedData(ctx, DeleteRetainedDataRequest{}); return err }},
		{"bind retained data", ManagementActionBindRetainedData, func() error { _, err := h.BindRetainedData(ctx, BindRetainedDataRequest{}); return err }},
		{"cleanup retained data", ManagementActionCleanupExpiredRetainedData, func() error {
			_, err := h.CleanupExpiredRetainedData(ctx, CleanupExpiredRetainedDataRequest{})
			return err
		}},
		{"export data", ManagementActionExportPluginData, func() error { _, err := h.ExportPluginData(ctx, ExportDataRequest{}); return err }},
		{"delete export", ManagementActionDeleteExportedPluginData, func() error { return h.DeleteExportedPluginData(ctx, DeleteExportDataRequest{}) }},
		{"import data", ManagementActionImportPluginData, func() error { _, err := h.ImportPluginData(ctx, ImportDataRequest{}); return err }},
		{"get settings schema", ManagementActionGetSettingsSchema, func() error { _, err := h.GetSettingsSchema(ctx, GetSettingsRequest{}); return err }},
		{"get settings", ManagementActionGetPluginSettings, func() error { _, err := h.GetPluginSettings(ctx, GetSettingsRequest{}); return err }},
		{"patch settings", ManagementActionPatchPluginSettings, func() error { _, err := h.PatchPluginSettings(ctx, PatchSettingsRequest{}); return err }},
		{"bind secret", ManagementActionBindSecretRef, func() error { return h.BindSecretRef(ctx, SecretBindRequest{}) }},
		{"test secret", ManagementActionTestSecretRef, func() error { return h.TestSecretRef(ctx, SecretTestRequest{}) }},
		{"delete secret", ManagementActionDeleteSecretRef, func() error { return h.DeleteSecretRef(ctx, SecretDeleteRequest{}) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorization.requests = nil
			err := tt.call()
			if !errors.Is(err, ErrActionDenied) {
				t.Fatalf("error = %v, want %v", err, ErrActionDenied)
			}
			if errors.Is(err, adapterFailure) || err.Error() == adapterFailure.Error() {
				t.Fatalf("authorization adapter error leaked: %v", err)
			}
			if len(authorization.requests) != 1 {
				t.Fatalf("authorization requests = %d, want 1", len(authorization.requests))
			}
			got := authorization.requests[0]
			if got.Action != tt.action || got.Resource != tt.action.Resource() || got.Session != wantSession {
				t.Fatalf("authorization request = %#v, want action %q resource %q", got, tt.action, tt.action.Resource())
			}
		})
	}
}

func TestAuthorizeManagementRejectsUnknownActionAndInvalidOwner(t *testing.T) {
	authorization := &recordingAuthorizationAdapter{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization})

	if _, err := h.authorizeManagement(hostTestContext(), ManagementAction("plugin.unknown"), "plugin_1"); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("unknown action error = %v, want %v", err, ErrActionDenied)
	}
	if len(authorization.requests) != 0 {
		t.Fatalf("unknown action reached adapter with requests %#v", authorization.requests)
	}

	if _, err := h.authorizeManagement(context.Background(), ManagementActionListPlugins, "plugin_1"); !errors.Is(err, sessionctx.ErrSessionRequired) {
		t.Fatalf("invalid owner error = %v, want %v", err, sessionctx.ErrSessionRequired)
	}
	if len(authorization.requests) != 0 {
		t.Fatalf("invalid owner reached adapter with requests %#v", authorization.requests)
	}
}

func TestAuthorizeManagementDerivesOwnerAndResourceFromHostCall(t *testing.T) {
	authorization := &recordingAuthorizationAdapter{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization})
	ctx := hostTestContext()
	wantSession, err := requireUserSession(ctx)
	if err != nil {
		t.Fatal(err)
	}

	result, err := h.authorizeManagement(ctx, ManagementActionCancelSurfaceOperation, "operation_1", "surface_1", "channel_1")
	if err != nil {
		t.Fatal(err)
	}
	if result.session != wantSession {
		t.Fatalf("authorized session = %#v, want %#v", result.session, wantSession)
	}
	if len(authorization.requests) != 1 {
		t.Fatalf("authorization requests = %d, want 1", len(authorization.requests))
	}
	got := authorization.requests[0]
	if got.Session != wantSession || got.Action != ManagementActionCancelSurfaceOperation || got.Resource != ResourceOperation || got.ResourceID != "operation_1" {
		t.Fatalf("authorization request = %#v", got)
	}
	if len(got.RelatedResourceIDs) != 2 || got.RelatedResourceIDs[0] != "surface_1" || got.RelatedResourceIDs[1] != "channel_1" {
		t.Fatalf("related resource IDs = %#v", got.RelatedResourceIDs)
	}
}

func TestDirectHostAPIsProjectClosedAuthorizationResources(t *testing.T) {
	authorization := &recordingAuthorizationAdapter{err: errors.New("deny")}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization})
	ctx := hostTestContext()
	tests := []struct {
		name       string
		action     ManagementAction
		resource   ResourceRef
		resourceID string
		related    []string
		call       func() error
	}{
		{
			name: "prepare surface", action: ManagementActionPrepareSurface, resource: ResourceSurface,
			resourceID: "surface_1", call: func() error {
				_, err := h.PrepareSurface(ctx, PrepareSurfaceRequest{SurfaceInstanceID: "surface_1"})
				return err
			},
		},
		{
			name: "read surface asset", action: ManagementActionReadSurfaceAsset, resource: ResourceSurface,
			resourceID: "surface_1", related: []string{"asset_session_1", "binding_1"}, call: func() error {
				_, err := h.ReadSurfaceAsset(ctx, ReadSurfaceAssetRequest{SurfaceInstanceID: "surface_1", AssetSessionID: "asset_session_1", BindingID: "binding_1"})
				return err
			},
		},
		{
			name: "call plugin method", action: ManagementActionCallPluginMethod, resource: ResourceMethod,
			resourceID: "plugin_1", related: []string{"surface_1", "method_1"}, call: func() error {
				_, err := h.CallPluginMethod(ctx, CallMethodRequest{PluginInstanceID: "plugin_1", SurfaceInstanceID: "surface_1", Method: "method_1"})
				return err
			},
		},
		{
			name: "read stream", action: ManagementActionReadSurfaceStream, resource: ResourceStream,
			resourceID: "stream_1", related: []string{"surface_1", "read_1"}, call: func() error {
				_, err := h.ReadStream(ctx, ReadStreamRequest{StreamID: "stream_1", SurfaceInstanceID: "surface_1", ReadID: "read_1"})
				return err
			},
		},
		{
			name: "cancel surface operation", action: ManagementActionCancelSurfaceOperation, resource: ResourceOperation,
			resourceID: "operation_1", related: []string{"surface_1", "channel_1"}, call: func() error {
				_, err := h.CancelSurfaceOperation(ctx, CancelSurfaceOperationRequest{OperationID: "operation_1", SurfaceInstanceID: "surface_1", BridgeChannelID: "channel_1"})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorization.requests = nil
			if err := tt.call(); !errors.Is(err, ErrActionDenied) {
				t.Fatalf("error = %v, want %v", err, ErrActionDenied)
			}
			if len(authorization.requests) != 1 {
				t.Fatalf("authorization requests = %d, want 1", len(authorization.requests))
			}
			got := authorization.requests[0]
			if got.Action != tt.action || got.Resource != tt.resource || got.ResourceID != tt.resourceID {
				t.Fatalf("authorization request = %#v", got)
			}
			if len(got.RelatedResourceIDs) != len(tt.related) {
				t.Fatalf("related resource IDs = %#v, want %#v", got.RelatedResourceIDs, tt.related)
			}
			for i := range tt.related {
				if got.RelatedResourceIDs[i] != tt.related[i] {
					t.Fatalf("related resource IDs = %#v, want %#v", got.RelatedResourceIDs, tt.related)
				}
			}
		})
	}
}

func TestOpenRejectsTypedNilAuthorizationAdapter(t *testing.T) {
	config := func() Config {
		h, _, _ := newTestHost(t, true, true)
		return Config{Core: CoreAdapters{
			Policy:               h.adapters.Policy,
			Authorization:        h.adapters.Authorization,
			PackageTrustVerifier: h.adapters.PackageTrustVerifier,
			Registry:             h.adapters.Registry,
			Audit:                h.adapters.Audit,
			SecurityAudit:        h.adapters.SecurityAudit,
			Diagnostics:          h.adapters.Diagnostics,
			SurfaceCatalog:       h.adapters.SurfaceCatalog,
			SurfaceTokens:        h.adapters.SurfaceTokens,
			PluginData:           h.adapters.PluginData,
			Assets:               h.adapters.Assets,
			InstallStages:        h.adapters.InstallStages,
			Operations:           h.adapters.Operations,
			ConfirmationIntents:  h.adapters.ConfirmationIntents,
			Streams:              h.adapters.Streams,
		}}
	}()
	var typedNil *recordingAuthorizationAdapter
	config.Core.Authorization = typedNil

	_, err := Open(hostTestContext(), config)
	var configErr *HostConfigError
	if !errors.As(err, &configErr) || !errors.Is(err, ErrHostConfig) || configErr.Module != "core" || configErr.Adapter != "authorization" {
		t.Fatalf("Open(typed nil authorization) error = %#v, want HostConfigError", err)
	}
}
