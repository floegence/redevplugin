package host

import (
	"context"
	"errors"
	"testing"
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
		ManagementActionListIntents,
		ManagementActionInvokeIntent,
		ManagementActionImportLocalPackage,
		ManagementActionInstallReleaseRef,
		ManagementActionUpdateLocalPackage,
		ManagementActionUpdateReleaseRef,
		ManagementActionDowngradePlugin,
		ManagementActionListPlugins,
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

	tests := []struct {
		name   string
		action ManagementAction
		call   func() error
	}{
		{"open surface", ManagementActionOpenSurface, func() error { _, err := h.OpenSurface(ctx, OpenSurfaceRequest{}); return err }},
		{"list intents", ManagementActionListIntents, func() error { _, err := h.ListIntents(ctx, ListIntentsRequest{}); return err }},
		{"invoke intent", ManagementActionInvokeIntent, func() error { _, err := h.InvokeIntent(ctx, InvokeIntentRequest{}); return err }},
		{"import local package", ManagementActionImportLocalPackage, func() error { _, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{}); return err }},
		{"install release ref", ManagementActionInstallReleaseRef, func() error { _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{}); return err }},
		{"update local package", ManagementActionUpdateLocalPackage, func() error { _, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{}); return err }},
		{"update release ref", ManagementActionUpdateReleaseRef, func() error { _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{}); return err }},
		{"downgrade", ManagementActionDowngradePlugin, func() error { _, err := h.DowngradePlugin(ctx, DowngradeRequest{}); return err }},
		{"list plugins", ManagementActionListPlugins, func() error { _, err := h.ListPlugins(ctx); return err }},
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
			if got.Action != tt.action || got.Resource != tt.action.Resource() || !got.Session.Valid() {
				t.Fatalf("authorization request = %#v, want action %q resource %q", got, tt.action, tt.action.Resource())
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
