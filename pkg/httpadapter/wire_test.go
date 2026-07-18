package httpadapter

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestPublicWireProjectionsExcludeInternalIdentity(t *testing.T) {
	now := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	plugin := mustPublicPluginRecord(t, registry.PluginRecord{
		OwnerEnvHash:     "owner_env_private",
		PluginInstanceID: "plugin_instance_public",
		PluginID:         "plugin.public",
		Version:          "1.2.3",
		InstalledAt:      now,
		UpdatedAt:        now,
	})
	permission := publicPermissionMutation(host.PermissionMutationResult{
		Permission: permissions.Record{
			PluginInstanceID: "plugin_instance_public",
			PermissionID:     "network.http",
			Effect:           permissions.EffectGrant,
			GrantedBy:        "owner_user_grant_private",
			GrantedAt:        now,
			RevokedBy:        "owner_user_revoke_private",
		},
		Revisions: registry.AuthorizationRevisions{PolicyRevision: 2, ManagementRevision: 3, RevokeEpoch: 4},
	})
	publicOperation := mustPublicOperationRecord(t, operation.Record{
		OperationID: "operation_public",
		ExecutionBinding: capability.ExecutionBinding{
			InvocationID:         "invocation_public",
			PluginInstanceID:     "plugin_instance_public",
			BridgeChannelID:      "bridge_channel_private",
			OwnerSessionHash:     "owner_session_private",
			OwnerUserHash:        "owner_user_private",
			OwnerEnvHash:         "owner_env_operation_private",
			SessionChannelIDHash: "session_channel_private",
		},
	})
	runtimeHealth := publicRuntimeHealth(runtimeclient.ManagerHealth{
		Shards: []runtimeclient.ShardHealth{{
			RuntimeShardID: "runtime_shard_public",
			Health: runtimeclient.Health{
				RuntimeInstanceID:   "runtime_instance_public",
				RuntimeGenerationID: "runtime_generation_public",
				IPCChannelID:        "ipc_channel_private",
				ConnectionNonce:     "connection_nonce_private",
			},
		}},
	})

	raw, err := json.Marshal([]any{plugin, permission, publicOperation, runtimeHealth})
	if err != nil {
		t.Fatalf("Marshal(public wire projections) error = %v", err)
	}
	encoded := string(raw)
	for _, forbidden := range []string{
		"owner_env_private", "owner_user_grant_private", "owner_user_revoke_private",
		"bridge_channel_private", "owner_session_private", "owner_user_private",
		"owner_env_operation_private", "session_channel_private", "ipc_channel_private",
		"connection_nonce_private",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("public wire projections exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestPublicWireMappersPreservePublishedFields(t *testing.T) {
	now := time.Date(2026, 7, 18, 11, 0, 0, 0, time.UTC)
	record := registry.PluginRecord{
		OwnerEnvHash:      "owner_env_private",
		PluginInstanceID:  "plugin_instance_1",
		PublisherID:       "publisher.example",
		PluginID:          "plugin.example",
		Version:           "1.2.3",
		ActiveFingerprint: "fingerprint_1",
		PackageHash:       "package_hash_1",
		ManifestHash:      "manifest_hash_1",
		EntriesHash:       "entries_hash_1",
		TrustState:        registry.TrustVerified,
		TrustAssessment: registry.TrustAssessment{
			TrustState: registry.TrustVerified,
			VerifiedSignature: &registry.VerifiedSignature{
				Algorithm: "ed25519",
				KeyID:     "key_1",
			},
		},
		EnableState:        registry.EnableEnabled,
		PolicyRevision:     2,
		ManagementRevision: 3,
		RevokeEpoch:        4,
		VersionHistory: []registry.PluginVersion{{
			Version:           "1.0.0",
			ActiveFingerprint: "fingerprint_0",
			ActivatedAt:       now.Add(-time.Hour),
		}},
		InstalledAt: now,
		UpdatedAt:   now,
	}
	plugin := mustPublicPluginRecord(t, record)
	if plugin.PluginInstanceID != record.PluginInstanceID || plugin.PublisherID != record.PublisherID ||
		plugin.PluginID != record.PluginID || plugin.Version != record.Version || plugin.ActiveFingerprint != record.ActiveFingerprint ||
		plugin.PolicyRevision != record.PolicyRevision || plugin.ManagementRevision != record.ManagementRevision ||
		plugin.RevokeEpoch != record.RevokeEpoch || plugin.TrustAssessment.VerifiedSignature == nil ||
		plugin.TrustAssessment.VerifiedSignature.KeyID != "key_1" || len(plugin.VersionHistory) != 1 ||
		plugin.VersionHistory[0].ActiveFingerprint != "fingerprint_0" {
		t.Fatalf("public plugin mapper lost published fields: %#v", plugin)
	}

	schema := mustPublicSettingsSchema(t, host.SettingsSchemaResult{
		PluginInstanceID: "plugin_instance_1",
		Scope:            sessionctx.ScopeUser,
		SchemaVersion:    5,
		Fields: []manifest.SettingFieldSpec{{
			Key: "region", Type: "string", Label: "Region", Scope: "user", Default: "us-east",
			Options: []string{"us-east", "eu-west"}, Validation: map[string]any{"min_length": 2.0},
		}},
		ValuesRevision: 7,
	})
	if schema.PluginInstanceID != "plugin_instance_1" || schema.Scope != string(sessionctx.ScopeUser) ||
		schema.SchemaVersion != 5 || schema.ValuesRevision != 7 || len(schema.Fields) != 1 ||
		schema.Fields[0].Default != "us-east" || len(schema.Fields[0].Options) != 2 {
		t.Fatalf("public settings schema mapper lost published fields: %#v", schema)
	}

	snapshot := mustPublicSettingsSnapshot(t, host.SettingsResult{
		PluginInstanceID: "plugin_instance_1",
		Scope:            sessionctx.ScopeUser,
		SchemaVersion:    5,
		ValuesRevision:   8,
		Values:           map[string]any{"region": "eu-west"},
		SecretMetadata: []host.SettingsSecretMetadata{{
			Key: "token", SecretRef: "api_token", Scope: "user", Bound: true, UpdatedAt: &now,
		}},
	})
	if snapshot.Values["region"] != "eu-west" || len(snapshot.SecretMetadata) != 1 ||
		snapshot.SecretMetadata[0].SecretRef != "api_token" || snapshot.SecretMetadata[0].UpdatedAt == nil ||
		!snapshot.SecretMetadata[0].UpdatedAt.Equal(now) {
		t.Fatalf("public settings snapshot mapper lost published fields: %#v", snapshot)
	}
}

func TestPublicWireMappersOwnNestedCollections(t *testing.T) {
	defaultSize := &manifest.WidgetSizeSpec{Width: 640, Height: 480}
	record := registry.PluginRecord{
		SourcePolicySnapshot: map[string]any{"nested": map[string]any{"value": "original"}},
		TrustAssessment: registry.TrustAssessment{
			ReasonCodes: []string{"verified"},
			Metadata:    map[string]string{"trust": "original"},
		},
		CapabilityContracts: []capabilitycontract.Pin{{ContractID: "contract.original"}},
		Manifest: manifest.Manifest{
			Surfaces: []manifest.SurfaceSpec{{SurfaceID: "surface.original", DefaultSize: defaultSize}},
			Methods: []manifest.MethodSpec{{
				Method: "method.original",
				RequestSchema: map[string]any{
					"properties": map[string]any{"name": map[string]any{"type": "string"}},
				},
			}},
			NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{{
				ConnectorID: "connector.original", Destinations: []string{"example.com"},
				Auth: map[string]any{"headers": map[string]any{"authorization": "declared"}},
			}}},
		},
		PackageEntries: []pluginpkg.Entry{{Path: "ui/original.js"}},
		VersionHistory: []registry.PluginVersion{{
			SourcePolicySnapshot: map[string]any{"history": map[string]any{"value": "original"}},
			Metadata:             map[string]string{"history": "original"},
		}},
		Metadata: map[string]string{"record": "original"},
	}
	publicRecord := mustPublicPluginRecord(t, record)

	record.SourcePolicySnapshot["nested"].(map[string]any)["value"] = "mutated"
	record.TrustAssessment.ReasonCodes[0] = "mutated"
	record.TrustAssessment.Metadata["trust"] = "mutated"
	record.CapabilityContracts[0].ContractID = "contract.mutated"
	record.Manifest.Surfaces[0].SurfaceID = "surface.mutated"
	record.Manifest.Surfaces[0].DefaultSize.Width = 1
	record.Manifest.Methods[0].RequestSchema["properties"].(map[string]any)["name"].(map[string]any)["type"] = "number"
	record.Manifest.NetworkAccess.Connectors[0].Destinations[0] = "mutated.example"
	record.Manifest.NetworkAccess.Connectors[0].Auth["headers"].(map[string]any)["authorization"] = "mutated"
	record.PackageEntries[0].Path = "ui/mutated.js"
	record.VersionHistory[0].SourcePolicySnapshot["history"].(map[string]any)["value"] = "mutated"
	record.VersionHistory[0].Metadata["history"] = "mutated"
	record.Metadata["record"] = "mutated"

	if publicRecord.SourcePolicySnapshot["nested"].(map[string]any)["value"] != "original" ||
		publicRecord.TrustAssessment.ReasonCodes[0] != "verified" || publicRecord.TrustAssessment.Metadata["trust"] != "original" ||
		publicRecord.CapabilityContracts[0].ContractID != "contract.original" || publicRecord.Manifest.Surfaces[0].SurfaceID != "surface.original" ||
		publicRecord.Manifest.Surfaces[0].DefaultSize.Width != 640 ||
		publicRecord.Manifest.Methods[0].RequestSchema["properties"].(map[string]any)["name"].(map[string]any)["type"] != "string" ||
		publicRecord.Manifest.NetworkAccess.Connectors[0].Destinations[0] != "example.com" ||
		publicRecord.Manifest.NetworkAccess.Connectors[0].Auth["headers"].(map[string]any)["authorization"] != "declared" ||
		publicRecord.PackageEntries[0].Path != "ui/original.js" ||
		publicRecord.VersionHistory[0].SourcePolicySnapshot["history"].(map[string]any)["value"] != "original" ||
		publicRecord.VersionHistory[0].Metadata["history"] != "original" || publicRecord.Metadata["record"] != "original" {
		t.Fatalf("public plugin projection shares nested domain state: %#v", publicRecord)
	}

	data := map[string]any{"items": []any{map[string]any{"value": "original"}}}
	call := mustPublicCallMethod(t, host.CallMethodResult{Data: data})
	data["items"].([]any)[0].(map[string]any)["value"] = "mutated"
	if call.Data.(map[string]any)["items"].([]any)[0].(map[string]any)["value"] != "original" {
		t.Fatalf("public call response shares adapter data: %#v", call.Data)
	}

	binding := capability.ExecutionBinding{
		Permissions: capability.PermissionEvidence{Required: []string{"read"}, Granted: []string{"read"}},
		Target:      capability.TargetDescriptor{Fields: map[string]any{"resource": map[string]any{"id": "original"}}},
	}
	publicOperation := mustPublicOperationRecord(t, operation.Record{ExecutionBinding: binding})
	binding.Permissions.Required[0] = "mutated"
	binding.Target.Fields["resource"].(map[string]any)["id"] = "mutated"
	if publicOperation.Permissions.Required[0] != "read" || publicOperation.Target.Fields["resource"].(map[string]any)["id"] != "original" {
		t.Fatalf("public operation projection shares execution state: %#v", publicOperation)
	}

	eventData := []byte("original")
	publicStream := publicSurfaceStream(host.ReadStreamResult{Events: []stream.Event{{Data: eventData}}})
	eventData[0] = 'X'
	if string(publicStream.Events[0].Data) != "original" {
		t.Fatalf("public stream projection shares event bytes: %q", publicStream.Events[0].Data)
	}
}

func TestPublicWireClonePreservesCanonicalNumbersAndNulls(t *testing.T) {
	data := map[string]any{
		"number": json.Number("42.5"),
		"object": map[string]any(nil),
		"array":  []any(nil),
	}
	call := mustPublicCallMethod(t, host.CallMethodResult{Data: data})
	operationRecord := mustPublicOperationRecord(t, operation.Record{ExecutionBinding: capability.ExecutionBinding{
		Target: capability.TargetDescriptor{Fields: data},
	}})

	for name, value := range map[string]map[string]any{
		"rpc":       call.Data.(map[string]any),
		"operation": operationRecord.Target.Fields,
	} {
		t.Run(name, func(t *testing.T) {
			if value["number"] != json.Number("42.5") {
				t.Fatalf("number representation changed: %#v", value["number"])
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(raw); got != `{"array":null,"number":42.5,"object":null}` {
				t.Fatalf("wire projection = %s", got)
			}
		})
	}
}

func TestHTTPWireDTOJSONTagsAreSnakeCase(t *testing.T) {
	types := []any{
		successResponse{}, mutationSuccessResponse{}, errorBody{}, mutationErrorBody{}, errorDetails{},
		packageHashSetRequest{}, releaseRefRequest{}, trustHashSetResponse{}, verifiedSignatureResponse{},
		trustAssessmentResponse{}, localImportProvenanceResponse{}, runtimeRequirementResponse{}, pluginVersionResponse{},
		capabilityPinResponse{}, packageEntryResponse{}, manifestPublisherResponse{}, manifestPluginResponse{},
		manifestWidgetSizeResponse{}, manifestSurfaceResponse{}, manifestCapabilityBindingResponse{}, manifestMethodRouteResponse{},
		manifestConfirmationResponse{}, manifestCancelPolicyResponse{}, manifestStorageAccessResponse{}, manifestNetworkAccessResponse{},
		manifestMethodBrokerAccessResponse{}, manifestMethodResponse{}, manifestWorkerResponse{}, manifestStoreResponse{},
		manifestStorageResponse{}, manifestConnectorResponse{}, manifestNetworkResponse{}, manifestSettingFieldResponse{},
		manifestSettingsResponse{}, manifestIntentResponse{}, manifestResponse{}, opaqueSurfaceStyleResponse{},
		opaqueSurfaceWorkerResponse{}, opaqueSurfaceAssetResponse{}, opaqueSurfaceDocumentResponse{},
		pluginRecordResponse{}, permissionResponse{}, authorizationRevisionsResponse{}, permissionMutationResponse{},
		settingsFieldResponse{}, settingsSchemaResponse{}, settingsSecretMetadataResponse{}, settingsSnapshotResponse{},
		runtimeTargetResponse{}, runtimeDescriptorResponse{}, runtimeLimitsResponse{}, runtimeModuleCacheResponse{},
		runtimeShardHealthResponse{}, runtimeHealthResponse{}, runtimeRefreshErrorResponse{}, runtimeRefreshEntryResponse{},
		runtimeRefreshResponse{}, surfacePreparationResponse{}, bridgeTokenResponse{}, callMethodResponse{},
		confirmationPreparationResponse{}, confirmationRejectionResponse{}, intentResponse{}, intentListResponse{},
		pluginDataBindingResponse{}, retainedDataListResponse{}, retainedDataCleanupResponse{}, diagnosticEventResponse{},
		diagnosticListResponse{}, surfaceAssetResponse{}, streamEventResponse{}, surfaceStreamResponse{},
		pluginCatalogResponse{}, permissionListResponse{}, dataExportResponse{}, acknowledgementResponse{},
		surfaceDisposeResponse{}, runtimeStopResponse{}, deleteResponse{}, secretBindResponse{}, secretTestResponse{},
		surfaceScopeRevokeResponse{}, securityPolicyDeleteResponse{}, securityPolicyListResponse{},
		compatibilityMatrixResponse{}, compatibilityContractResponse{}, compatibilityResponse{}, surfaceBootstrapResponse{},
		securityPolicyResponse{}, operationPermissionEvidenceResponse{}, operationConfirmationEvidenceResponse{},
		operationRevisionEvidenceResponse{}, operationQuotaResponse{}, operationTargetResponse{}, operationResponse{}, operationListResponse{},
	}
	validName := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	for _, value := range types {
		typeOf := reflect.TypeOf(value)
		t.Run(typeOf.Name(), func(t *testing.T) {
			for index := range typeOf.NumField() {
				field := typeOf.Field(index)
				tag, ok := field.Tag.Lookup("json")
				if !ok || strings.TrimSpace(tag) == "" {
					t.Fatalf("field %s must declare an explicit json tag", field.Name)
				}
				name := strings.Split(tag, ",")[0]
				if !validName.MatchString(name) {
					t.Fatalf("field %s json name = %q, want snake_case", field.Name, name)
				}
			}
		})
	}
}

func TestPublicAggregateProjectionsMatchPublishedFieldSets(t *testing.T) {
	pairs := []struct {
		name       string
		domainType any
		wireType   any
	}{
		{name: "capability pin", domainType: capabilitycontract.Pin{}, wireType: capabilityPinResponse{}},
		{name: "package entry", domainType: pluginpkg.Entry{}, wireType: packageEntryResponse{}},
		{name: "manifest", domainType: manifest.Manifest{}, wireType: manifestResponse{}},
		{name: "manifest publisher", domainType: manifest.Publisher{}, wireType: manifestPublisherResponse{}},
		{name: "manifest plugin", domainType: manifest.Plugin{}, wireType: manifestPluginResponse{}},
		{name: "manifest surface", domainType: manifest.SurfaceSpec{}, wireType: manifestSurfaceResponse{}},
		{name: "manifest widget size", domainType: manifest.WidgetSizeSpec{}, wireType: manifestWidgetSizeResponse{}},
		{name: "manifest capability binding", domainType: manifest.CapabilityBinding{}, wireType: manifestCapabilityBindingResponse{}},
		{name: "manifest method", domainType: manifest.MethodSpec{}, wireType: manifestMethodResponse{}},
		{name: "manifest method route", domainType: manifest.MethodRouteSpec{}, wireType: manifestMethodRouteResponse{}},
		{name: "manifest confirmation", domainType: manifest.ConfirmationSpec{}, wireType: manifestConfirmationResponse{}},
		{name: "manifest cancel policy", domainType: manifest.CancelPolicySpec{}, wireType: manifestCancelPolicyResponse{}},
		{name: "manifest broker access", domainType: manifest.MethodBrokerAccessSpec{}, wireType: manifestMethodBrokerAccessResponse{}},
		{name: "manifest storage access", domainType: manifest.StorageBrokerAccessSpec{}, wireType: manifestStorageAccessResponse{}},
		{name: "manifest network access", domainType: manifest.NetworkBrokerAccessSpec{}, wireType: manifestNetworkAccessResponse{}},
		{name: "manifest worker", domainType: manifest.WorkerSpec{}, wireType: manifestWorkerResponse{}},
		{name: "manifest storage", domainType: manifest.StorageSpec{}, wireType: manifestStorageResponse{}},
		{name: "manifest store", domainType: manifest.StoreSpec{}, wireType: manifestStoreResponse{}},
		{name: "manifest network", domainType: manifest.NetworkAccessSpec{}, wireType: manifestNetworkResponse{}},
		{name: "manifest connector", domainType: manifest.NetworkConnectorSpec{}, wireType: manifestConnectorResponse{}},
		{name: "manifest settings", domainType: manifest.SettingsSpec{}, wireType: manifestSettingsResponse{}},
		{name: "manifest setting field", domainType: manifest.SettingFieldSpec{}, wireType: manifestSettingFieldResponse{}},
		{name: "manifest intent", domainType: manifest.IntentSpec{}, wireType: manifestIntentResponse{}},
		{name: "opaque surface document", domainType: pluginpkg.OpaqueSurfaceDocument{}, wireType: opaqueSurfaceDocumentResponse{}},
		{name: "opaque surface style", domainType: pluginpkg.OpaqueSurfaceStyle{}, wireType: opaqueSurfaceStyleResponse{}},
		{name: "opaque surface worker", domainType: pluginpkg.OpaqueSurfaceWorker{}, wireType: opaqueSurfaceWorkerResponse{}},
		{name: "opaque surface asset", domainType: pluginpkg.OpaqueSurfaceAsset{}, wireType: opaqueSurfaceAssetResponse{}},
		{name: "compatibility matrix", domainType: version.Matrix{}, wireType: compatibilityMatrixResponse{}},
		{name: "compatibility contract", domainType: version.ContractArtifact{}, wireType: compatibilityContractResponse{}},
		{name: "compatibility manifest", domainType: version.CompatibilityManifest{}, wireType: compatibilityResponse{}},
	}
	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			assertSameJSONFieldSet(t, reflect.TypeOf(pair.domainType), reflect.TypeOf(pair.wireType))
		})
	}
}

func TestPublicPlatformMappersOwnAndPreserveValues(t *testing.T) {
	features := []host.Feature{host.FeatureRelease, host.FeatureRuntime}
	publicFeatureSet := publicFeatures(features)
	features[0] = host.FeatureSecrets
	if !reflect.DeepEqual(publicFeatureSet, []string{string(host.FeatureRelease), string(host.FeatureRuntime)}) {
		t.Fatalf("publicFeatures() = %#v", publicFeatureSet)
	}

	source := version.CompatibilityManifest{
		SchemaVersion: "compatibility-test",
		Contracts: []version.ContractArtifact{{
			ID: "contract-id", Path: "contract-path", Version: "contract-version", SHA256: "contract-sha256",
		}},
	}
	matrix := reflect.ValueOf(&source.Matrix).Elem()
	for index := range matrix.NumField() {
		matrix.Field(index).SetString(matrix.Type().Field(index).Name)
	}
	response := publicCompatibility(source)
	publicMatrix := reflect.ValueOf(response.Matrix)
	for index := range matrix.NumField() {
		field := matrix.Type().Field(index)
		mapped := publicMatrix.FieldByName(field.Name)
		if !mapped.IsValid() || mapped.String() != matrix.Field(index).String() {
			t.Fatalf("publicCompatibility() lost matrix field %s: %#v", field.Name, response.Matrix)
		}
	}
	source.Contracts[0].ID = "mutated"
	if response.SchemaVersion != "compatibility-test" || len(response.Contracts) != 1 || response.Contracts[0].ID != "contract-id" {
		t.Fatalf("publicCompatibility() lost or shared published values: %#v", response)
	}
}

func TestReleaseRefWireRequestRejectsNestedUnknownFields(t *testing.T) {
	raw := []byte(`{
		"release_ref": {
			"source_id": "source_1",
			"release_metadata_ref": "release_1",
			"release_metadata_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"publisher_id": "publisher.example",
			"plugin_id": "plugin.example",
			"version": "1.2.3",
			"expected_hashes": {
				"package_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				"entries_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				"owner_env_hash": "attacker_controlled"
			}
		}
	}`)
	var request installReleaseRefRequest
	if err := decodeStrictJSON(raw, &request); err == nil || !strings.Contains(err.Error(), "owner_env_hash") {
		t.Fatalf("decodeStrictJSON() error = %v, want nested unknown field rejection", err)
	}
}

func TestPublicWireCloneRejectsNonCanonicalValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "int", value: int(1)},
		{name: "uint64", value: uint64(1)},
		{name: "nan", value: math.NaN()},
		{name: "positive infinity", value: math.Inf(1)},
		{name: "negative infinity", value: math.Inf(-1)},
		{name: "unsafe positive magnitude", value: float64(1 << 53)},
		{name: "unsafe negative magnitude", value: -float64(1 << 53)},
		{name: "bytes", value: []byte("not canonical JSON")},
		{name: "channel", value: make(chan int)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := publicCallMethod(host.CallMethodResult{Data: test.value})
			if err == nil {
				t.Fatal("publicCallMethod() accepted a non-canonical value")
			}
			var projectionErr *wireProjectionError
			if !errors.As(err, &projectionErr) {
				t.Fatalf("publicCallMethod() error = %T %v, want wireProjectionError", err, err)
			}
		})
	}
}

func TestDomainClockFieldsAreExcludedFromJSON(t *testing.T) {
	requests := []any{
		permissions.GrantRequest{}, permissions.RevokeRequest{}, permissions.CheckRequest{},
		registry.AuthorizeRequest{}, registry.PutOptions{},
		operation.RegisterRequest{}, operation.CancelRequest{}, operation.FinishRequest{}, operation.PluginTransitionRequest{},
		stream.RegisterRequest{}, stream.AppendRequest{}, stream.CloseRequest{}, stream.PluginTransitionRequest{},
		installstage.CreateRequest{}, installstage.MarkPreparedRequest{}, installstage.MarkCommittedRequest{}, installstage.MarkFailedRequest{},
		security.PutConfirmationIntentRequest{}, security.ConsumeConfirmationIntentRequest{},
		security.RejectConfirmationIntentRequest{}, security.RevokePluginConfirmationIntentsRequest{}, security.PutPolicyRequest{},
		connectivity.GrantRequest{}, connectivity.HTTPRequest{}, connectivity.TCPRoundTripRequest{},
		connectivity.UDPRoundTripRequest{}, connectivity.WebSocketRoundTripRequest{},
		runtimeclient.RuntimeLeaseReplayConsumeRequest{}, runtimeclient.RuntimeLeaseVerificationRequest{},
		plugindata.CommitEnableRequest{}, plugindata.ImportRequest{}, plugindata.BindRetainedRequest{}, plugindata.CommitUninstallRequest{},
	}
	for _, request := range requests {
		typeOf := reflect.TypeOf(request)
		t.Run(typeOf.PkgPath()+"."+typeOf.Name(), func(t *testing.T) {
			field, ok := typeOf.FieldByName("Now")
			if !ok {
				t.Fatal("request has no Now field")
			}
			if field.Tag.Get("json") != "-" {
				t.Fatalf("Now json tag = %q, want -", field.Tag.Get("json"))
			}
		})
	}
}

func mustPublicPluginRecord(t testing.TB, record registry.PluginRecord) pluginRecordResponse {
	t.Helper()
	response, err := publicPluginRecord(record)
	if err != nil {
		t.Fatalf("publicPluginRecord() error = %v", err)
	}
	return response
}

func mustPublicSettingsSchema(t testing.TB, result host.SettingsSchemaResult) settingsSchemaResponse {
	t.Helper()
	response, err := publicSettingsSchema(result)
	if err != nil {
		t.Fatalf("publicSettingsSchema() error = %v", err)
	}
	return response
}

func mustPublicSettingsSnapshot(t testing.TB, result host.SettingsResult) settingsSnapshotResponse {
	t.Helper()
	response, err := publicSettingsSnapshot(result)
	if err != nil {
		t.Fatalf("publicSettingsSnapshot() error = %v", err)
	}
	return response
}

func mustPublicCallMethod(t testing.TB, result host.CallMethodResult) callMethodResponse {
	t.Helper()
	response, err := publicCallMethod(result)
	if err != nil {
		t.Fatalf("publicCallMethod() error = %v", err)
	}
	return response
}

func mustPublicOperationRecord(t testing.TB, record operation.Record) operationResponse {
	t.Helper()
	response, err := publicOperationRecord(record)
	if err != nil {
		t.Fatalf("publicOperationRecord() error = %v", err)
	}
	return response
}

func assertSameJSONFieldSet(t testing.TB, domainType, wireType reflect.Type) {
	t.Helper()
	domainFields := jsonFieldSet(domainType)
	wireFields := jsonFieldSet(wireType)
	if !reflect.DeepEqual(domainFields, wireFields) {
		t.Fatalf("JSON fields differ: domain=%v wire=%v", domainFields, wireFields)
	}
}

func jsonFieldSet(typeOf reflect.Type) []string {
	fields := make([]string, 0, typeOf.NumField())
	for index := range typeOf.NumField() {
		name := strings.Split(typeOf.Field(index).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	slices.Sort(fields)
	return fields
}
