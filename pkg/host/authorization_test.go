package host

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
)

type recordingAuthorizationAdapter struct {
	err      error
	requests []AuthorizationRequest
}

type authorizationProbeRegistry struct {
	registry.Store
	getCalls  int
	listCalls int
}

func (r *authorizationProbeRegistry) GetPlugin(ctx context.Context, pluginInstanceID string) (registry.PluginRecord, error) {
	r.getCalls++
	return r.Store.GetPlugin(ctx, pluginInstanceID)
}

func (r *authorizationProbeRegistry) ListPlugins(ctx context.Context) ([]registry.PluginRecord, error) {
	r.listCalls++
	return r.Store.ListPlugins(ctx)
}

func authorizationTargetsEqual(left, right AuthorizationTarget) bool {
	if left.Kind != right.Kind || left.ID != right.ID || left.Collection != right.Collection {
		return false
	}
	if left.Scope == nil || right.Scope == nil {
		return left.Scope == nil && right.Scope == nil
	}
	return *left.Scope == *right.Scope
}

func (a *recordingAuthorizationAdapter) Authorize(_ context.Context, req AuthorizationRequest) error {
	req.RelatedTargets = append([]AuthorizationTarget(nil), req.RelatedTargets...)
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
		ManagementActionRevokeSessionScope,
		ManagementActionFinalizeSessionScope,
		ManagementActionCallPluginMethod,
		ManagementActionPrepareMethodConfirmation,
		ManagementActionListIntents,
		ManagementActionInvokeIntent,
		ManagementActionImportLocalPackage,
		ManagementActionInstallReleaseRef,
		ManagementActionInspectExternalPackage,
		ManagementActionCommitExternalPackage,
		ManagementActionQueryExternalPackageCommit,
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
		ManagementActionGetPermissionRequirements,
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

func TestDirectManagementAPIsSanitizeAuthorizationAdapterFailuresBeforeBusinessValidation(t *testing.T) {
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
		{"revoke session scope", ManagementActionRevokeSessionScope, func() error { _, err := h.RevokeSessionScope(ctx, RevokeSessionScopeRequest{}); return err }},
		{"finalize session scope", ManagementActionFinalizeSessionScope, func() error { return h.FinalizeSessionScope(ctx, FinalizeSessionScopeRequest{}) }},
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
		{"list features", ManagementActionListFeatures, func() error { _, err := h.Features(ctx); return err }},
		{"get compatibility", ManagementActionGetCompatibility, func() error { _, err := h.GetCompatibility(ctx); return err }},
		{"refresh enabled", ManagementActionRefreshEnabledPlugins, func() error { _, err := h.RefreshEnabledPlugins(ctx); return err }},
		{"grant permission", ManagementActionGrantPermission, func() error { _, err := h.GrantPermission(ctx, GrantPermissionRequest{}); return err }},
		{"revoke permission", ManagementActionRevokePermission, func() error { _, err := h.RevokePermission(ctx, RevokePermissionRequest{}); return err }},
		{"list permission grants", ManagementActionListPermissionGrants, func() error { _, err := h.ListPermissionGrants(ctx, ListPermissionGrantsRequest{}); return err }},
		{"get permission requirements", ManagementActionGetPermissionRequirements, func() error {
			_, err := h.GetPermissionRequirements(ctx, GetPermissionRequirementsRequest{})
			return err
		}},
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
			if err == nil {
				t.Fatal("direct Host API unexpectedly succeeded")
			}
			if len(authorization.requests) == 1 && !errors.Is(err, ErrAdapterFailure) {
				t.Fatalf("authorized call error = %v, want %v", err, ErrAdapterFailure)
			}
			if errors.Is(err, adapterFailure) || err.Error() == adapterFailure.Error() {
				t.Fatalf("authorization adapter error leaked: %v", err)
			}
			if len(authorization.requests) > 1 {
				t.Fatalf("authorization requests = %d, want at most 1", len(authorization.requests))
			}
			if len(authorization.requests) == 1 {
				got := authorization.requests[0]
				if got.Action != tt.action || got.Target.Kind != tt.action.Resource() || got.Session != wantSession {
					t.Fatalf("authorization request = %#v, want action %q resource %q", got, tt.action, tt.action.Resource())
				}
			}
		})
	}
}

func TestAuthorizeManagementRejectsUnknownActionAndInvalidOwner(t *testing.T) {
	authorization := &recordingAuthorizationAdapter{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization})

	if _, err := h.authorizeManagement(hostTestContext(), ManagementAction("plugin.unknown"), authorizationTarget(ResourcePlugin, "plugin_1")); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("unknown action error = %v, want %v", err, ErrActionDenied)
	}
	if len(authorization.requests) != 0 {
		t.Fatalf("unknown action reached adapter with requests %#v", authorization.requests)
	}

	if _, err := h.authorizeManagement(context.Background(), ManagementActionListPlugins, authorizationTarget(ResourcePlugin, "plugin_1")); !errors.Is(err, sessionctx.ErrSessionRequired) {
		t.Fatalf("invalid owner error = %v, want %v", err, sessionctx.ErrSessionRequired)
	}
	if len(authorization.requests) != 0 {
		t.Fatalf("invalid owner reached adapter with requests %#v", authorization.requests)
	}
}

func TestAuthorizationRunsBeforeSessionFenceAndFencedActionsAreRejected(t *testing.T) {
	authorization := &recordingAuthorizationAdapter{err: ErrActionDenied}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization})
	ctx := hostTestContext()
	session, err := requireUserSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Features(ctx); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("Features(denied) error = %v, want ErrActionDenied", err)
	}
	if _, err := h.sessionScopes.Snapshot(ctx, scope); !errors.Is(err, sessionscope.ErrScopeNotFound) {
		t.Fatalf("denied authorization created a session gate: %v", err)
	}
	identity, err := h.adapters.SessionLifecycle.PrepareSessionScopeClose(ctx, PrepareSessionScopeCloseRequest{Session: session})
	if err != nil {
		t.Fatal(err)
	}
	teardown, _, err := h.sessionScopes.BeginTeardown(ctx, scope, identity, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer teardown.Release()
	authorization.err = nil
	if _, err := h.Features(ctx); !errors.Is(err, sessionscope.ErrSessionRevoked) {
		t.Fatalf("Features(fenced) error = %v, want ErrSessionRevoked", err)
	}
	if len(authorization.requests) != 2 {
		t.Fatalf("authorization request count = %d, want 2", len(authorization.requests))
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

	result, err := h.authorizeManagement(ctx, ManagementActionCancelSurfaceOperation,
		authorizationTarget(ResourceOperation, "operation_1"),
		authorizationTarget(ResourceSurface, "surface_1"),
		authorizationTarget(ResourceBridgeChannel, "channel_1"),
	)
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
	if got.Session != wantSession || got.Action != ManagementActionCancelSurfaceOperation || !authorizationTargetsEqual(got.Target, AuthorizationTarget{Kind: ResourceOperation, ID: "operation_1"}) {
		t.Fatalf("authorization request = %#v", got)
	}
	if len(got.RelatedTargets) != 2 || !authorizationTargetsEqual(got.RelatedTargets[0], AuthorizationTarget{Kind: ResourceSurface, ID: "surface_1"}) || !authorizationTargetsEqual(got.RelatedTargets[1], AuthorizationTarget{Kind: ResourceBridgeChannel, ID: "channel_1"}) {
		t.Fatalf("related targets = %#v", got.RelatedTargets)
	}
}

func TestDirectHostAPIsProjectClosedAuthorizationResources(t *testing.T) {
	authorization := &recordingAuthorizationAdapter{err: ErrActionDenied}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization})
	ctx := hostTestContext()
	tests := []struct {
		name    string
		action  ManagementAction
		target  AuthorizationTarget
		related []AuthorizationTarget
		call    func() error
	}{
		{
			name: "prepare surface", action: ManagementActionPrepareSurface,
			target: AuthorizationTarget{Kind: ResourceSurface, ID: "surface_1"}, call: func() error {
				_, err := h.PrepareSurface(ctx, PrepareSurfaceRequest{SurfaceInstanceID: "surface_1"})
				return err
			},
		},
		{
			name: "read surface asset", action: ManagementActionReadSurfaceAsset,
			target: AuthorizationTarget{Kind: ResourceSurface, ID: "surface_1"}, related: []AuthorizationTarget{{Kind: ResourceAssetSession, ID: "asset_session_1"}, {Kind: ResourceSurfaceAsset, ID: "binding_1"}}, call: func() error {
				_, err := h.ReadSurfaceAsset(ctx, ReadSurfaceAssetRequest{SurfaceInstanceID: "surface_1", AssetSessionID: "asset_session_1", BindingID: "binding_1"})
				return err
			},
		},
		{
			name: "call plugin method", action: ManagementActionCallPluginMethod,
			target: AuthorizationTarget{Kind: ResourceMethod, ID: "method_1"}, related: []AuthorizationTarget{{Kind: ResourcePlugin, ID: "plugin_1"}, {Kind: ResourceSurface, ID: "surface_1"}, {Kind: ResourceBridgeChannel, ID: "channel_1"}}, call: func() error {
				_, err := h.CallPluginMethod(ctx, CallMethodRequest{PluginInstanceID: "plugin_1", SurfaceInstanceID: "surface_1", BridgeChannelID: "channel_1", Method: "method_1"})
				return err
			},
		},
		{
			name: "read stream", action: ManagementActionReadSurfaceStream,
			target: AuthorizationTarget{Kind: ResourceStream, ID: "stream_1"}, related: []AuthorizationTarget{{Kind: ResourceSurface, ID: "surface_1"}}, call: func() error {
				_, err := h.ReadStream(ctx, ReadStreamRequest{StreamID: "stream_1", SurfaceInstanceID: "surface_1", ReadID: "read_1"})
				return err
			},
		},
		{
			name: "cancel surface operation", action: ManagementActionCancelSurfaceOperation,
			target: AuthorizationTarget{Kind: ResourceOperation, ID: "operation_1"}, related: []AuthorizationTarget{{Kind: ResourceSurface, ID: "surface_1"}, {Kind: ResourceBridgeChannel, ID: "channel_1"}}, call: func() error {
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
			if got.Action != tt.action || !authorizationTargetsEqual(got.Target, tt.target) {
				t.Fatalf("authorization request = %#v", got)
			}
			if len(got.RelatedTargets) != len(tt.related) {
				t.Fatalf("related targets = %#v, want %#v", got.RelatedTargets, tt.related)
			}
			for i := range tt.related {
				if !authorizationTargetsEqual(got.RelatedTargets[i], tt.related[i]) {
					t.Fatalf("related targets = %#v, want %#v", got.RelatedTargets, tt.related)
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

func TestAuthorizationCanonicalizesTargetsBeforeAdapterDispatch(t *testing.T) {
	authorization := &recordingAuthorizationAdapter{err: ErrActionDenied}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization, developerMode: true, localGenerated: true})
	reader := &readAtProbe{reader: bytes.NewReader(buildFixturePackage(t))}

	_, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: "  plugini_canonical  ",
		PackageReader:    reader,
		PackageSize:      1,
	})
	if !errors.Is(err, ErrActionDenied) {
		t.Fatalf("ImportLocalPackage() error = %v, want ErrActionDenied", err)
	}
	if reader.calls != 0 {
		t.Fatalf("authorization denial read package %d times", reader.calls)
	}
	if len(authorization.requests) != 1 {
		t.Fatalf("authorization requests = %#v", authorization.requests)
	}
	request := authorization.requests[0]
	wantScope := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"}
	if !authorizationTargetsEqual(request.Target, AuthorizationTarget{Kind: ResourcePlugin, ID: "plugini_canonical", Scope: &wantScope}) {
		t.Fatalf("canonical target = %#v", request.Target)
	}
}

func TestInstallEntryPointsRejectMissingPluginInstanceIDBeforeExternalInput(t *testing.T) {
	authorization := &recordingAuthorizationAdapter{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		authorization:  authorization,
		developerMode:  true,
		localGenerated: true,
	})
	reader := &readAtProbe{reader: bytes.NewReader(buildFixturePackage(t))}

	if _, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PackageReader: reader,
		PackageSize:   int64(reader.reader.Len()),
	}); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("ImportLocalPackage() error = %v, want ErrActionDenied", err)
	}
	if reader.calls != 0 {
		t.Fatalf("missing plugin_instance_id read package %d times", reader.calls)
	}

	if _, err := h.InstallReleaseRef(hostTestContext(), InstallReleaseRefRequest{}); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrActionDenied", err)
	}
	if len(authorization.requests) != 0 {
		t.Fatalf("invalid install target reached authorization adapter: %#v", authorization.requests)
	}
}

func TestAuthorizationAdapterOperationalFailureIsSanitized(t *testing.T) {
	const sensitive = "authorization database unavailable at /private/policy.db"
	authorization := &recordingAuthorizationAdapter{err: errors.New(sensitive)}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization})

	_, err := h.ListPlugins(hostTestContext())
	if !errors.Is(err, ErrAdapterFailure) || errors.Is(err, ErrActionDenied) {
		t.Fatalf("ListPlugins() error = %v, want sanitized ErrAdapterFailure", err)
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("authorization adapter detail leaked: %v", err)
	}
}

func TestReleaseUpdateAndIntentAuthorizationPrecedeDiscovery(t *testing.T) {
	t.Run("release update", func(t *testing.T) {
		authorization := &recordingAuthorizationAdapter{err: ErrActionDenied}
		artifactResolver := &recordingReleaseArtifactResolver{}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			authorization: authorization,
		})
		registryProbe := &authorizationProbeRegistry{Store: h.adapters.Registry}
		h.adapters.Registry = registryProbe

		_, err := h.UpdateReleaseRef(hostTestContext(), UpdateReleaseRefRequest{
			PluginInstanceID: "  plugini_update_auth  ",
		})
		if !errors.Is(err, ErrActionDenied) {
			t.Fatalf("UpdateReleaseRef() error = %v, want ErrActionDenied", err)
		}
		if registryProbe.getCalls != 0 || registryProbe.listCalls != 0 || artifactResolver.calls != 0 {
			t.Fatalf("authorization denial reached discovery: registry get=%d list=%d artifact=%d", registryProbe.getCalls, registryProbe.listCalls, artifactResolver.calls)
		}
		wantScope := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"}
		if len(authorization.requests) != 1 || !authorizationTargetsEqual(authorization.requests[0].Target, AuthorizationTarget{Kind: ResourcePlugin, ID: "plugini_update_auth", Scope: &wantScope}) {
			t.Fatalf("authorization requests = %#v", authorization.requests)
		}
	})

	t.Run("intent invoke", func(t *testing.T) {
		authorization := &recordingAuthorizationAdapter{err: ErrActionDenied}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{authorization: authorization})
		registryProbe := &authorizationProbeRegistry{Store: h.adapters.Registry}
		h.adapters.Registry = registryProbe

		_, err := h.InvokeIntent(hostTestContext(), InvokeIntentRequest{
			PluginInstanceID: "  plugini_intent_auth  ",
			IntentID:         "  example.open  ",
		})
		if !errors.Is(err, ErrActionDenied) {
			t.Fatalf("InvokeIntent() error = %v, want ErrActionDenied", err)
		}
		if registryProbe.getCalls != 0 || registryProbe.listCalls != 0 {
			t.Fatalf("authorization denial reached registry: get=%d list=%d", registryProbe.getCalls, registryProbe.listCalls)
		}
		wantScope := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"}
		if len(authorization.requests) != 1 || !authorizationTargetsEqual(authorization.requests[0].Target, AuthorizationTarget{Kind: ResourceIntent, ID: "example.open", Scope: &wantScope}) {
			t.Fatalf("authorization requests = %#v", authorization.requests)
		}
		if len(authorization.requests[0].RelatedTargets) != 1 || !authorizationTargetsEqual(authorization.requests[0].RelatedTargets[0], AuthorizationTarget{Kind: ResourcePlugin, ID: "plugini_intent_auth", Scope: &wantScope}) {
			t.Fatalf("related targets = %#v", authorization.requests[0].RelatedTargets)
		}
	})
}

func TestScopedDirectActionsDeriveResourceScopeBeforeAuthorization(t *testing.T) {
	tests := []struct {
		name        string
		packageData func(*testing.T) []byte
		calls       func(*Host, registry.PluginRecord) []error
		wantKinds   []ResourceRef
		wantScopes  []sessionctx.ScopeKind
	}{
		{
			name: "settings", packageData: buildSettingsFixturePackage,
			calls: func(h *Host, record registry.PluginRecord) []error {
				_, userErr := h.GetPluginSettings(hostTestContext(), GetSettingsRequest{PluginInstanceID: record.PluginInstanceID, Scope: sessionctx.ScopeUser})
				_, envErr := h.GetPluginSettings(hostTestContext(), GetSettingsRequest{PluginInstanceID: record.PluginInstanceID, Scope: sessionctx.ScopeEnvironment})
				return []error{userErr, envErr}
			},
			wantKinds: []ResourceRef{ResourceSettings, ResourceSettings}, wantScopes: []sessionctx.ScopeKind{sessionctx.ScopeUser, sessionctx.ScopeEnvironment},
		},
		{
			name: "secret", packageData: buildSettingsFixturePackage,
			calls: func(h *Host, record registry.PluginRecord) []error {
				return []error{h.BindSecretRef(hostTestContext(), SecretBindRequest{PluginInstanceID: record.PluginInstanceID, SecretRef: " api_token ", Scope: " user "})}
			},
			wantKinds: []ResourceRef{ResourceSecret}, wantScopes: []sessionctx.ScopeKind{sessionctx.ScopeUser},
		},
		{
			name: "storage", packageData: buildStorageFixturePackage,
			calls: func(h *Host, record registry.PluginRecord) []error {
				_, userErr := h.MintStorageHandleGrant(hostTestContext(), MintStorageHandleGrantRequest{PluginInstanceID: record.PluginInstanceID, StoreID: "cache", RuntimeGenerationID: "runtime_gen"})
				_, envErr := h.MintStorageHandleGrant(hostTestContext(), MintStorageHandleGrantRequest{PluginInstanceID: record.PluginInstanceID, StoreID: "db", RuntimeGenerationID: "runtime_gen"})
				return []error{userErr, envErr}
			},
			wantKinds: []ResourceRef{ResourceStore, ResourceStore}, wantScopes: []sessionctx.ScopeKind{sessionctx.ScopeUser, sessionctx.ScopeEnvironment},
		},
		{
			name: "connector", packageData: buildNetworkFixturePackage,
			calls: func(h *Host, record registry.PluginRecord) []error {
				_, userErr := h.MintConnectionGrant(hostTestContext(), MintConnectionGrantRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "api", Transport: "http", Destination: "https://api.example.com"})
				_, envErr := h.MintConnectionGrant(hostTestContext(), MintConnectionGrantRequest{PluginInstanceID: record.PluginInstanceID, ConnectorID: "mysql", Transport: "tcp", Destination: "db.example.com:3306"})
				return []error{userErr, envErr}
			},
			wantKinds: []ResourceRef{ResourceConnector, ResourceConnector}, wantScopes: []sessionctx.ScopeKind{sessionctx.ScopeUser, sessionctx.ScopeEnvironment},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
			record, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), test.packageData(t))
			if err != nil {
				t.Fatal(err)
			}
			authorization := &recordingAuthorizationAdapter{err: ErrActionDenied}
			h.adapters.Authorization = authorization
			errs := test.calls(h, record)
			if len(errs) != len(test.wantKinds) || len(authorization.requests) != len(test.wantKinds) {
				t.Fatalf("errors=%d requests=%#v", len(errs), authorization.requests)
			}
			for i := range errs {
				if !errors.Is(errs[i], ErrActionDenied) {
					t.Fatalf("call %d error = %v, want ErrActionDenied", i, errs[i])
				}
				target := authorization.requests[i].Target
				if target.Scope == nil || target.Kind != test.wantKinds[i] || target.Scope.Kind != test.wantScopes[i] || target.Scope.OwnerEnvHash != "env_hash" {
					t.Fatalf("call %d target = %#v", i, target)
				}
				if test.wantScopes[i] == sessionctx.ScopeUser && target.Scope.OwnerUserHash != "user_hash" {
					t.Fatalf("call %d user target = %#v", i, target)
				}
				if test.wantScopes[i] == sessionctx.ScopeEnvironment && target.Scope.OwnerUserHash != "" {
					t.Fatalf("call %d environment target = %#v", i, target)
				}
			}
		})
	}
}

func TestDeleteExportAuthorizationBindsBundleAndPluginOwnership(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	authorization := &recordingAuthorizationAdapter{err: ErrActionDenied}
	h.adapters.Authorization = authorization

	err := h.DeleteExportedPluginData(hostTestContext(), DeleteExportDataRequest{
		PluginInstanceID: "  plugini_export_owner  ",
		BundleRef:        "  export_bundle_1  ",
	})
	if !errors.Is(err, ErrActionDenied) {
		t.Fatalf("DeleteExportedPluginData() error = %v, want ErrActionDenied", err)
	}
	if len(authorization.requests) != 1 {
		t.Fatalf("authorization requests = %#v", authorization.requests)
	}
	request := authorization.requests[0]
	wantUserScope := sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"}
	if !authorizationTargetsEqual(request.Target, AuthorizationTarget{Kind: ResourceDataExport, ID: "export_bundle_1", Scope: &wantUserScope}) {
		t.Fatalf("export target = %#v", request.Target)
	}
	wantEnvironmentScope := sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"}
	wantRelated := []AuthorizationTarget{{Kind: ResourcePlugin, ID: "plugini_export_owner", Scope: &wantEnvironmentScope}}
	if len(request.RelatedTargets) != 1 || !authorizationTargetsEqual(request.RelatedTargets[0], wantRelated[0]) {
		t.Fatalf("related targets = %#v, want %#v", request.RelatedTargets, wantRelated)
	}
}
