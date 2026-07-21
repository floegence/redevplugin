package host

import (
	"reflect"
	"strings"
	"testing"
)

func TestPublicRequestDTOsDeclareClosedJSONFieldNames(t *testing.T) {
	requests := []any{
		ListDiagnosticEventsRequest{}, PackageTrustVerificationRequest{}, HostRequirementSelectionRequest{},
		CapabilityContractResolveRequest{}, ReleaseArtifactResolveRequest{}, StartRuntimeRequest{},
		ImportLocalPackageRequest{}, UpdateLocalPackageRequest{}, InstallReleaseRefRequest{}, UpdateReleaseRefRequest{},
		DowngradeRequest{}, EnableRequest{}, DisableRequest{}, UninstallRequest{}, ListRetainedDataRequest{},
		DeleteRetainedDataRequest{}, BindRetainedDataRequest{}, CleanupExpiredRetainedDataRequest{}, ExportDataRequest{},
		ImportDataRequest{}, DeleteExportDataRequest{}, GrantPermissionRequest{}, RevokePermissionRequest{},
		ListPermissionGrantsRequest{}, PutSecurityPolicyRequest{}, GetSecurityPolicyRequest{}, DeleteSecurityPolicyRequest{},
		GetSettingsRequest{}, PatchSettingsRequest{}, OpenSurfaceRequest{}, PrepareSurfaceRequest{},
		ReadSurfaceAssetRequest{}, DisposeSurfaceRequest{}, RevokeSessionScopeRequest{}, FinalizeSessionScopeRequest{}, MintBridgeTokenRequest{},
		CallMethodRequest{}, ListIntentsRequest{}, InvokeIntentRequest{}, PrepareMethodConfirmationRequest{},
		RejectMethodConfirmationRequest{}, ListOperationsRequest{}, CancelOperationRequest{}, CancelSurfaceOperationRequest{},
		ReadStreamRequest{}, AcknowledgeStreamRequest{}, MintConnectionGrantRequest{}, MintStorageHandleGrantRequest{},
		AuthorizationRequest{}, AuthorizationTarget{},
	}
	internalFields := map[string]struct{}{
		"Now": {}, "WaitTimeout": {}, "PackageReader": {}, "PackageSize": {}, "TTL": {},
		"Session":       {},
		"ResourceScope": {},
	}
	for _, request := range requests {
		typeOf := reflect.TypeOf(request)
		t.Run(typeOf.Name(), func(t *testing.T) {
			for index := range typeOf.NumField() {
				field := typeOf.Field(index)
				if !field.IsExported() {
					continue
				}
				tag, ok := field.Tag.Lookup("json")
				if !ok || strings.TrimSpace(tag) == "" {
					t.Fatalf("exported field %s must declare an explicit json tag", field.Name)
				}
				jsonName := strings.Split(tag, ",")[0]
				if _, internal := internalFields[field.Name]; internal && jsonName != "-" {
					t.Fatalf("internal field %s json tag = %q, want -", field.Name, tag)
				}
			}
		})
	}
}
