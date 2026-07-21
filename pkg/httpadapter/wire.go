package httpadapter

import (
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/registry"
)

// HTTP wire DTOs are deliberately separate from Host and persistence DTOs.
// Adding an internal field to a domain record must never add it to the public API.

type packageHashSetRequest struct {
	PackageSHA256  string `json:"package_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	EntriesSHA256  string `json:"entries_sha256"`
}

type releaseRefRequest struct {
	SourceID              string                `json:"source_id"`
	Channel               string                `json:"channel"`
	ReleaseMetadataRef    string                `json:"release_metadata_ref"`
	ReleaseMetadataSHA256 string                `json:"release_metadata_sha256"`
	PublisherID           string                `json:"publisher_id"`
	PluginID              string                `json:"plugin_id"`
	Version               string                `json:"version"`
	ExpectedHashes        packageHashSetRequest `json:"expected_hashes"`
}

func (request releaseRefRequest) domain() host.PluginReleaseRef {
	return host.PluginReleaseRef{
		SourceID:              request.SourceID,
		Channel:               request.Channel,
		ReleaseMetadataRef:    request.ReleaseMetadataRef,
		ReleaseMetadataSHA256: request.ReleaseMetadataSHA256,
		PublisherID:           request.PublisherID,
		PluginID:              request.PluginID,
		Version:               request.Version,
		ExpectedHashes: host.PackageHashSet{
			PackageSHA256:  request.ExpectedHashes.PackageSHA256,
			ManifestSHA256: request.ExpectedHashes.ManifestSHA256,
			EntriesSHA256:  request.ExpectedHashes.EntriesSHA256,
		},
	}
}

type trustHashSetResponse struct {
	PackageSHA256  string `json:"package_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	EntriesSHA256  string `json:"entries_sha256"`
}

type verifiedSignatureResponse struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
}

type trustAssessmentResponse struct {
	TrustState           string                     `json:"trust_state"`
	ReasonCodes          []string                   `json:"reason_codes,omitempty"`
	VerifiedHashes       trustHashSetResponse       `json:"verified_hashes"`
	VerifiedSignature    *verifiedSignatureResponse `json:"verified_signature,omitempty"`
	TrustAssessmentEpoch string                     `json:"trust_assessment_epoch,omitempty"`
	PolicyEpoch          string                     `json:"policy_epoch,omitempty"`
	RevocationEpoch      string                     `json:"revocation_epoch,omitempty"`
	Metadata             map[string]string          `json:"metadata,omitempty"`
}

type localImportProvenanceResponse struct {
	ImportID       string `json:"import_id"`
	Distribution   string `json:"distribution"`
	PolicyEpoch    string `json:"policy_epoch"`
	UnsignedPolicy string `json:"unsigned_policy"`
	AssessedAt     string `json:"assessed_at"`
}

type runtimeRequirementResponse struct {
	MinVersion       string   `json:"min_version"`
	SupportedTargets []string `json:"supported_targets,omitempty"`
}

type releaseTrustBindingResponse struct {
	SourceID              string `json:"source_id"`
	Channel               string `json:"channel"`
	ReleaseMetadataRef    string `json:"release_metadata_ref"`
	ReleaseMetadataSHA256 string `json:"release_metadata_sha256"`
	PublisherID           string `json:"publisher_id"`
	PluginID              string `json:"plugin_id"`
	Version               string `json:"version"`
	VerifiedStateSHA256   string `json:"verified_state_sha256"`
	RootEpoch             string `json:"root_epoch"`
	PolicyEpoch           string `json:"policy_epoch"`
	RevocationEpoch       string `json:"revocation_epoch"`
}

type pluginVersionResponse struct {
	Version               string                         `json:"version"`
	ActiveFingerprint     string                         `json:"active_fingerprint"`
	PackageHash           string                         `json:"package_hash"`
	ManifestHash          string                         `json:"manifest_hash"`
	EntriesHash           string                         `json:"entries_hash"`
	TrustState            string                         `json:"trust_state"`
	TrustAssessment       trustAssessmentResponse        `json:"trust_assessment"`
	ReleaseTrustBinding   *releaseTrustBindingResponse   `json:"release_trust_binding,omitempty"`
	LocalImportProvenance *localImportProvenanceResponse `json:"local_import_provenance,omitempty"`
	CapabilityContracts   []capabilityPinResponse        `json:"capability_contracts,omitempty"`
	Manifest              manifestResponse               `json:"manifest"`
	PackageEntries        []packageEntryResponse         `json:"package_entries"`
	RuntimeRequirement    *runtimeRequirementResponse    `json:"runtime_requirement,omitempty"`
	ActivatedAt           time.Time                      `json:"activated_at"`
	Metadata              map[string]string              `json:"metadata,omitempty"`
}

type pluginRecordResponse struct {
	PluginInstanceID      string                         `json:"plugin_instance_id"`
	PublisherID           string                         `json:"publisher_id"`
	PluginID              string                         `json:"plugin_id"`
	Version               string                         `json:"version"`
	ActiveFingerprint     string                         `json:"active_fingerprint"`
	PackageHash           string                         `json:"package_hash"`
	ManifestHash          string                         `json:"manifest_hash"`
	EntriesHash           string                         `json:"entries_hash"`
	TrustState            string                         `json:"trust_state"`
	TrustAssessment       trustAssessmentResponse        `json:"trust_assessment"`
	ReleaseTrustBinding   *releaseTrustBindingResponse   `json:"release_trust_binding,omitempty"`
	LocalImportProvenance *localImportProvenanceResponse `json:"local_import_provenance,omitempty"`
	CapabilityContracts   []capabilityPinResponse        `json:"capability_contracts,omitempty"`
	EnableState           string                         `json:"enable_state"`
	DisabledReason        string                         `json:"disabled_reason,omitempty"`
	PolicyRevision        uint64                         `json:"policy_revision"`
	ManagementRevision    uint64                         `json:"management_revision"`
	RevokeEpoch           uint64                         `json:"revoke_epoch"`
	Manifest              manifestResponse               `json:"manifest"`
	PackageEntries        []packageEntryResponse         `json:"package_entries"`
	RuntimeRequirement    *runtimeRequirementResponse    `json:"runtime_requirement,omitempty"`
	VersionHistory        []pluginVersionResponse        `json:"version_history,omitempty"`
	InstalledAt           time.Time                      `json:"installed_at"`
	EnabledAt             *time.Time                     `json:"enabled_at,omitempty"`
	UpdatedAt             time.Time                      `json:"updated_at"`
	DeletedAt             *time.Time                     `json:"deleted_at,omitempty"`
	Metadata              map[string]string              `json:"metadata,omitempty"`
}

func publicPluginRecord(record registry.PluginRecord) (pluginRecordResponse, error) {
	versions := make([]pluginVersionResponse, len(record.VersionHistory))
	for index, version := range record.VersionHistory {
		mapped, err := publicPluginVersion(version)
		if err != nil {
			return pluginRecordResponse{}, err
		}
		versions[index] = mapped
	}
	publicManifest, err := publicManifest(record.Manifest)
	if err != nil {
		return pluginRecordResponse{}, err
	}
	return pluginRecordResponse{
		PluginInstanceID: record.PluginInstanceID, PublisherID: record.PublisherID, PluginID: record.PluginID,
		Version: record.Version, ActiveFingerprint: record.ActiveFingerprint, PackageHash: record.PackageHash,
		ManifestHash: record.ManifestHash, EntriesHash: record.EntriesHash, TrustState: string(record.TrustState),
		TrustAssessment: publicTrustAssessment(record.TrustAssessment), ReleaseTrustBinding: publicReleaseTrustBinding(record.ReleaseTrustBinding),
		LocalImportProvenance: publicLocalImportProvenance(record.LocalImportProvenance),
		CapabilityContracts:   publicCapabilityPins(record.CapabilityContracts), EnableState: string(record.EnableState), DisabledReason: record.DisabledReason,
		PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch,
		Manifest: publicManifest, PackageEntries: publicPackageEntries(record.PackageEntries), RuntimeRequirement: publicRuntimeRequirement(record.RuntimeRequirement),
		VersionHistory: versions, InstalledAt: record.InstalledAt, EnabledAt: cloneWireTime(record.EnabledAt), UpdatedAt: record.UpdatedAt,
		DeletedAt: cloneWireTime(record.DeletedAt), Metadata: cloneWireStringMap(record.Metadata),
	}, nil
}

func publicPluginRecords(records []registry.PluginRecord) ([]pluginRecordResponse, error) {
	responses := make([]pluginRecordResponse, len(records))
	for index, record := range records {
		mapped, err := publicPluginRecord(record)
		if err != nil {
			return nil, err
		}
		responses[index] = mapped
	}
	return responses, nil
}

func publicPluginVersion(version registry.PluginVersion) (pluginVersionResponse, error) {
	publicManifest, err := publicManifest(version.Manifest)
	if err != nil {
		return pluginVersionResponse{}, err
	}
	return pluginVersionResponse{
		Version: version.Version, ActiveFingerprint: version.ActiveFingerprint, PackageHash: version.PackageHash,
		ManifestHash: version.ManifestHash, EntriesHash: version.EntriesHash, TrustState: string(version.TrustState),
		TrustAssessment: publicTrustAssessment(version.TrustAssessment), ReleaseTrustBinding: publicReleaseTrustBinding(version.ReleaseTrustBinding),
		LocalImportProvenance: publicLocalImportProvenance(version.LocalImportProvenance),
		CapabilityContracts:   publicCapabilityPins(version.CapabilityContracts), Manifest: publicManifest,
		PackageEntries: publicPackageEntries(version.PackageEntries), RuntimeRequirement: publicRuntimeRequirement(version.RuntimeRequirement),
		ActivatedAt: version.ActivatedAt, Metadata: cloneWireStringMap(version.Metadata),
	}, nil
}

func publicReleaseTrustBinding(value *registry.ReleaseTrustBinding) *releaseTrustBindingResponse {
	if value == nil {
		return nil
	}
	return &releaseTrustBindingResponse{
		SourceID: value.SourceID, Channel: value.Channel,
		ReleaseMetadataRef: value.ReleaseMetadataRef, ReleaseMetadataSHA256: value.ReleaseMetadataSHA256,
		PublisherID: value.PublisherID, PluginID: value.PluginID, Version: value.Version,
		VerifiedStateSHA256: value.VerifiedStateSHA256, RootEpoch: value.RootEpoch,
		PolicyEpoch: value.PolicyEpoch, RevocationEpoch: value.RevocationEpoch,
	}
}

func publicTrustAssessment(assessment registry.TrustAssessment) trustAssessmentResponse {
	response := trustAssessmentResponse{
		TrustState: string(assessment.TrustState), ReasonCodes: append([]string(nil), assessment.ReasonCodes...),
		VerifiedHashes: trustHashSetResponse{
			PackageSHA256:  assessment.VerifiedHashes.PackageSHA256,
			ManifestSHA256: assessment.VerifiedHashes.ManifestSHA256,
			EntriesSHA256:  assessment.VerifiedHashes.EntriesSHA256,
		},
		TrustAssessmentEpoch: assessment.TrustAssessmentEpoch, PolicyEpoch: assessment.PolicyEpoch,
		RevocationEpoch: assessment.RevocationEpoch, Metadata: cloneWireStringMap(assessment.Metadata),
	}
	if assessment.VerifiedSignature != nil {
		response.VerifiedSignature = &verifiedSignatureResponse{
			Algorithm: assessment.VerifiedSignature.Algorithm,
			KeyID:     assessment.VerifiedSignature.KeyID,
		}
	}
	return response
}

func publicLocalImportProvenance(value *registry.LocalImportProvenance) *localImportProvenanceResponse {
	if value == nil {
		return nil
	}
	return &localImportProvenanceResponse{
		ImportID: value.ImportID, Distribution: value.Distribution, PolicyEpoch: value.PolicyEpoch,
		UnsignedPolicy: value.UnsignedPolicy, AssessedAt: value.AssessedAt,
	}
}

func publicRuntimeRequirement(value *registry.RuntimeRequirement) *runtimeRequirementResponse {
	if value == nil {
		return nil
	}
	targets := make([]string, len(value.SupportedTargets))
	for index, target := range value.SupportedTargets {
		targets[index] = target.String()
	}
	return &runtimeRequirementResponse{MinVersion: value.MinVersion, SupportedTargets: targets}
}

type permissionResponse struct {
	PluginInstanceID string     `json:"plugin_instance_id"`
	PermissionID     string     `json:"permission_id"`
	Effect           string     `json:"effect"`
	GrantedAt        time.Time  `json:"granted_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedReason    string     `json:"revoked_reason,omitempty"`
}

type authorizationRevisionsResponse struct {
	PolicyRevision     uint64 `json:"policy_revision"`
	ManagementRevision uint64 `json:"management_revision"`
	RevokeEpoch        uint64 `json:"revoke_epoch"`
}

type permissionMutationResponse struct {
	Permission permissionResponse             `json:"permission"`
	Revisions  authorizationRevisionsResponse `json:"revisions"`
}

func publicPermission(record permissions.Record) permissionResponse {
	return permissionResponse{
		PluginInstanceID: record.PluginInstanceID, PermissionID: record.PermissionID, Effect: string(record.Effect),
		GrantedAt: record.GrantedAt, ExpiresAt: cloneWireTime(record.ExpiresAt), RevokedAt: cloneWireTime(record.RevokedAt),
		RevokedReason: record.RevokedReason,
	}
}

func publicPermissions(records []permissions.Record) []permissionResponse {
	responses := make([]permissionResponse, len(records))
	for index, record := range records {
		responses[index] = publicPermission(record)
	}
	return responses
}

func publicPermissionMutation(result host.PermissionMutationResult) permissionMutationResponse {
	return permissionMutationResponse{
		Permission: publicPermission(result.Permission),
		Revisions: authorizationRevisionsResponse{
			PolicyRevision:     result.Revisions.PolicyRevision,
			ManagementRevision: result.Revisions.ManagementRevision,
			RevokeEpoch:        result.Revisions.RevokeEpoch,
		},
	}
}

type settingsFieldResponse struct {
	Key        string         `json:"key"`
	Type       string         `json:"type"`
	Label      string         `json:"label"`
	Scope      string         `json:"scope"`
	Default    any            `json:"default,omitempty"`
	SecretRef  string         `json:"secret_ref,omitempty"`
	Options    []string       `json:"options,omitempty"`
	Validation map[string]any `json:"validation,omitempty"`
}

type settingsSchemaResponse struct {
	PluginInstanceID string                  `json:"plugin_instance_id"`
	Scope            string                  `json:"scope"`
	SchemaVersion    int                     `json:"schema_version"`
	Fields           []settingsFieldResponse `json:"fields"`
	ValuesRevision   uint64                  `json:"values_revision"`
}

type settingsSecretMetadataResponse struct {
	Key            string     `json:"key"`
	SecretRef      string     `json:"secret_ref"`
	Scope          string     `json:"scope"`
	Bound          bool       `json:"bound"`
	LastTestStatus string     `json:"last_test_status,omitempty"`
	BoundAt        *time.Time `json:"bound_at,omitempty"`
	TestedAt       *time.Time `json:"tested_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

type settingsSnapshotResponse struct {
	PluginInstanceID string                           `json:"plugin_instance_id"`
	Scope            string                           `json:"scope"`
	SchemaVersion    int                              `json:"schema_version"`
	ValuesRevision   uint64                           `json:"values_revision"`
	Values           map[string]any                   `json:"values"`
	SecretMetadata   []settingsSecretMetadataResponse `json:"secret_metadata"`
}

func publicSettingsSchema(result host.SettingsSchemaResult) (settingsSchemaResponse, error) {
	fields := make([]settingsFieldResponse, len(result.Fields))
	for index, field := range result.Fields {
		defaultValue, err := cloneWireJSONValue(field.Default)
		if err != nil {
			return settingsSchemaResponse{}, err
		}
		validation, err := cloneWireJSONMap(field.Validation)
		if err != nil {
			return settingsSchemaResponse{}, err
		}
		fields[index] = settingsFieldResponse{
			Key: field.Key, Type: field.Type, Label: field.Label, Scope: field.Scope, Default: defaultValue,
			SecretRef: field.SecretRef, Options: append([]string(nil), field.Options...), Validation: validation,
		}
	}
	return settingsSchemaResponse{
		PluginInstanceID: result.PluginInstanceID, Scope: string(result.Scope), SchemaVersion: result.SchemaVersion,
		Fields: fields, ValuesRevision: result.ValuesRevision,
	}, nil
}

func publicSettingsSnapshot(result host.SettingsResult) (settingsSnapshotResponse, error) {
	metadata := make([]settingsSecretMetadataResponse, len(result.SecretMetadata))
	for index, item := range result.SecretMetadata {
		metadata[index] = settingsSecretMetadataResponse{
			Key: item.Key, SecretRef: item.SecretRef, Scope: item.Scope, Bound: item.Bound,
			LastTestStatus: item.LastTestStatus, BoundAt: cloneWireTime(item.BoundAt), TestedAt: cloneWireTime(item.TestedAt),
			UpdatedAt: cloneWireTime(item.UpdatedAt),
		}
	}
	values, err := cloneWireJSONMap(result.Values)
	if err != nil {
		return settingsSnapshotResponse{}, err
	}
	return settingsSnapshotResponse{
		PluginInstanceID: result.PluginInstanceID, Scope: string(result.Scope), SchemaVersion: result.SchemaVersion,
		ValuesRevision: result.ValuesRevision, Values: values, SecretMetadata: metadata,
	}, nil
}

type runtimeDescriptorResponse struct {
	SchemaVersion     string `json:"schema_version"`
	PlatformVersion   string `json:"platform_version"`
	Target            string `json:"target"`
	RustIPCVersion    string `json:"rust_ipc_version"`
	WASMABIVersion    string `json:"wasm_abi_version"`
	ContractSetSHA256 string `json:"contract_set_sha256"`
	BinarySHA256      string `json:"binary_sha256"`
}

type runtimeLimitsResponse struct {
	WorkerCount            int   `json:"worker_count"`
	QueueCapacity          int   `json:"queue_capacity"`
	PerPluginConcurrency   int   `json:"per_plugin_concurrency"`
	ModuleCacheEntries     int   `json:"module_cache_entries"`
	ModuleCacheSourceBytes int64 `json:"module_cache_source_bytes"`
}

type runtimeModuleCacheResponse struct {
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	Compiles    uint64 `json:"compiles"`
	Entries     int    `json:"entries"`
	SourceBytes int64  `json:"source_bytes"`
}

type runtimeShardHealthResponse struct {
	RuntimeShardID      string                     `json:"runtime_shard_id"`
	RuntimeInstanceID   string                     `json:"runtime_instance_id"`
	RuntimeGenerationID string                     `json:"runtime_generation_id"`
	Descriptor          runtimeDescriptorResponse  `json:"descriptor"`
	Ready               bool                       `json:"ready"`
	ActiveInvocations   int                        `json:"active_invocations"`
	QueuedInvocations   int                        `json:"queued_invocations"`
	Limits              runtimeLimitsResponse      `json:"limits"`
	ModuleCache         runtimeModuleCacheResponse `json:"module_cache"`
}

type runtimeHealthResponse struct {
	Ready      bool                         `json:"ready"`
	Descriptor runtimeDescriptorResponse    `json:"descriptor"`
	Shards     []runtimeShardHealthResponse `json:"shards"`
}

func publicRuntimeHealth(health host.RuntimeHealth) runtimeHealthResponse {
	shards := make([]runtimeShardHealthResponse, len(health.Shards))
	for index, shard := range health.Shards {
		shards[index] = runtimeShardHealthResponse{
			RuntimeShardID: shard.RuntimeShardID, RuntimeInstanceID: shard.RuntimeInstanceID,
			RuntimeGenerationID: shard.RuntimeGenerationID, Descriptor: publicRuntimeDescriptor(shard.Descriptor),
			Ready: shard.Ready, ActiveInvocations: shard.ActiveInvocations, QueuedInvocations: shard.QueuedInvocations,
			Limits: publicRuntimeLimits(shard.Limits), ModuleCache: publicRuntimeModuleCache(shard.ModuleCache),
		}
	}
	return runtimeHealthResponse{Ready: health.Ready, Descriptor: publicRuntimeDescriptor(health.Descriptor), Shards: shards}
}

func publicRuntimeDescriptor(descriptor host.RuntimeDescriptor) runtimeDescriptorResponse {
	target := descriptor.Target().String()
	return runtimeDescriptorResponse{
		SchemaVersion: "runtime-descriptor-v2", PlatformVersion: descriptor.PlatformVersion().String(), Target: target,
		RustIPCVersion: descriptor.RustIPCVersion().String(), WASMABIVersion: descriptor.WASMABIVersion().String(),
		ContractSetSHA256: descriptor.ContractSetSHA256().String(), BinarySHA256: descriptor.BinarySHA256().String(),
	}
}

func publicRuntimeLimits(limits host.RuntimeLimits) runtimeLimitsResponse {
	return runtimeLimitsResponse{
		WorkerCount: limits.WorkerCount, QueueCapacity: limits.QueueCapacity,
		PerPluginConcurrency: limits.PerPluginConcurrency, ModuleCacheEntries: limits.ModuleCacheEntries,
		ModuleCacheSourceBytes: limits.ModuleCacheSourceBytes,
	}
}

func publicRuntimeModuleCache(metrics host.RuntimeModuleCacheMetrics) runtimeModuleCacheResponse {
	return runtimeModuleCacheResponse{
		Hits: metrics.Hits, Misses: metrics.Misses, Compiles: metrics.Compiles,
		Entries: metrics.Entries, SourceBytes: metrics.SourceBytes,
	}
}

type runtimeRefreshErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type runtimeRefreshEntryResponse struct {
	PluginInstanceID string                       `json:"plugin_instance_id"`
	Status           string                       `json:"status"`
	Error            *runtimeRefreshErrorResponse `json:"error,omitempty"`
}

type runtimeRefreshResponse struct {
	Results []runtimeRefreshEntryResponse `json:"results"`
}

func publicRuntimeRefresh(results []host.RefreshEnabledPluginResult) runtimeRefreshResponse {
	responses := make([]runtimeRefreshEntryResponse, len(results))
	for index, result := range results {
		responses[index] = runtimeRefreshEntryResponse{PluginInstanceID: result.PluginInstanceID, Status: string(result.Status)}
		if result.Error != nil {
			responses[index].Error = &runtimeRefreshErrorResponse{Code: string(result.Error.Code), Message: result.Error.Message}
		}
	}
	return runtimeRefreshResponse{Results: responses}
}

type surfacePreparationResponse struct {
	AssetSession       string                        `json:"asset_session"`
	AssetSessionID     string                        `json:"asset_session_id"`
	AssetSessionNonce  string                        `json:"asset_session_nonce"`
	EntryPath          string                        `json:"entry_path"`
	EntrySHA256        string                        `json:"entry_sha256"`
	ManagementRevision uint64                        `json:"management_revision"`
	RevokeEpoch        uint64                        `json:"revoke_epoch"`
	IssuedAt           time.Time                     `json:"issued_at"`
	ExpiresAt          time.Time                     `json:"expires_at"`
	Document           opaqueSurfaceDocumentResponse `json:"document"`
}

func publicSurfacePreparation(result host.PrepareSurfaceResult) surfacePreparationResponse {
	return surfacePreparationResponse{
		AssetSession: result.AssetSession, AssetSessionID: result.AssetSessionID,
		AssetSessionNonce: result.AssetSessionNonce, EntryPath: result.EntryPath, EntrySHA256: result.EntrySHA256,
		ManagementRevision: result.ManagementRevision, RevokeEpoch: result.RevokeEpoch,
		IssuedAt: result.IssuedAt, ExpiresAt: result.ExpiresAt, Document: publicOpaqueSurfaceDocument(result.Document),
	}
}

type bridgeTokenResponse struct {
	GatewayToken   string    `json:"plugin_gateway_token"`
	GatewayTokenID string    `json:"plugin_gateway_token_id"`
	AssetSession   string    `json:"asset_session"`
	AssetSessionID string    `json:"asset_session_id"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func publicBridgeToken(result bridge.GatewayTokenResult) bridgeTokenResponse {
	return bridgeTokenResponse{
		GatewayToken: result.GatewayToken, GatewayTokenID: result.GatewayTokenID,
		AssetSession: result.AssetSession, AssetSessionID: result.AssetSessionID,
		IssuedAt: result.IssuedAt, ExpiresAt: result.ExpiresAt,
	}
}

type callMethodResponse struct {
	Data                 any        `json:"data"`
	OperationID          string     `json:"operation_id,omitempty"`
	StreamID             string     `json:"stream_id,omitempty"`
	StreamTicket         string     `json:"stream_ticket,omitempty"`
	StreamTicketID       string     `json:"stream_ticket_id,omitempty"`
	StreamExpiresAt      *time.Time `json:"stream_expires_at,omitempty"`
	ConfirmationRequired bool       `json:"confirmation_required,omitempty"`
	ConfirmationTokenID  string     `json:"confirmation_token_id,omitempty"`
	RequestHash          string     `json:"request_hash,omitempty"`
	PlanHash             string     `json:"plan_hash,omitempty"`
}

func publicCallMethod(result host.CallMethodResult) (callMethodResponse, error) {
	data, err := cloneWireJSONValue(result.Data)
	if err != nil {
		return callMethodResponse{}, err
	}
	return callMethodResponse{
		Data: data, OperationID: result.OperationID, StreamID: result.StreamID,
		StreamTicket: result.StreamTicket, StreamTicketID: result.StreamTicketID,
		StreamExpiresAt: cloneWireTime(result.StreamExpiresAt), ConfirmationRequired: result.ConfirmationRequired,
		ConfirmationTokenID: result.ConfirmationTokenID, RequestHash: result.RequestHash, PlanHash: result.PlanHash,
	}, nil
}

type confirmationPreparationResponse struct {
	ConfirmationID      string    `json:"confirmation_id"`
	ConfirmationTokenID string    `json:"confirmation_token_id"`
	RequestHash         string    `json:"request_hash"`
	PlanHash            string    `json:"plan_hash"`
	Plan                any       `json:"plan,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
}

func publicConfirmationPreparation(result host.PrepareMethodConfirmationResult) (confirmationPreparationResponse, error) {
	plan, err := cloneWireJSONValue(result.Plan)
	if err != nil {
		return confirmationPreparationResponse{}, err
	}
	return confirmationPreparationResponse{
		ConfirmationID: result.ConfirmationID, ConfirmationTokenID: result.ConfirmationTokenID,
		RequestHash: result.RequestHash, PlanHash: result.PlanHash, Plan: plan, ExpiresAt: result.ExpiresAt,
	}, nil
}

type confirmationRejectionResponse struct {
	Rejected bool `json:"rejected"`
}

type intentResponse struct {
	PluginID          string         `json:"plugin_id"`
	PluginInstanceID  string         `json:"plugin_instance_id"`
	PublisherID       string         `json:"publisher_id"`
	DisplayName       string         `json:"display_name"`
	Version           string         `json:"version"`
	ActiveFingerprint string         `json:"active_fingerprint"`
	IntentID          string         `json:"intent_id"`
	Method            string         `json:"method"`
	Effect            string         `json:"effect"`
	Execution         string         `json:"execution"`
	PayloadSchema     map[string]any `json:"payload_schema,omitempty"`
}

type intentListResponse struct {
	Intents []intentResponse `json:"intents"`
}

func publicIntent(record host.IntentRecord) (intentResponse, error) {
	payloadSchema, err := cloneWireJSONMap(record.PayloadSchema)
	if err != nil {
		return intentResponse{}, err
	}
	return intentResponse{
		PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, PublisherID: record.PublisherID,
		DisplayName: record.DisplayName, Version: record.Version, ActiveFingerprint: record.ActiveFingerprint,
		IntentID: record.IntentID, Method: record.Method, Effect: string(record.Effect), Execution: string(record.Execution),
		PayloadSchema: payloadSchema,
	}, nil
}

func publicIntents(records []host.IntentRecord) (intentListResponse, error) {
	responses := make([]intentResponse, len(records))
	for index, record := range records {
		mapped, err := publicIntent(record)
		if err != nil {
			return intentListResponse{}, err
		}
		responses[index] = mapped
	}
	return intentListResponse{Intents: responses}, nil
}

type pluginDataBindingResponse struct {
	PluginInstanceID string     `json:"plugin_instance_id"`
	GenerationID     string     `json:"generation_id"`
	State            string     `json:"state"`
	Revision         uint64     `json:"revision"`
	ShapeHash        string     `json:"shape_hash"`
	RetainedAt       *time.Time `json:"retained_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

type retainedDataListResponse struct {
	RetainedData []pluginDataBindingResponse `json:"retained_data"`
}

type retainedDataCleanupResponse struct {
	Deleted []pluginDataBindingResponse `json:"deleted"`
}

func publicPluginDataBinding(binding plugindata.Binding) pluginDataBindingResponse {
	return pluginDataBindingResponse{
		PluginInstanceID: binding.PluginInstanceID, GenerationID: binding.GenerationID, State: string(binding.State),
		Revision: binding.Revision, ShapeHash: binding.ShapeHash,
		RetainedAt: cloneWireTime(binding.RetainedAt), ExpiresAt: cloneWireTime(binding.ExpiresAt),
	}
}

func publicPluginDataBindings(bindings []plugindata.Binding) []pluginDataBindingResponse {
	responses := make([]pluginDataBindingResponse, len(bindings))
	for index, binding := range bindings {
		responses[index] = publicPluginDataBinding(binding)
	}
	return responses
}

func publicRetainedData(bindings []plugindata.Binding) retainedDataListResponse {
	return retainedDataListResponse{RetainedData: publicPluginDataBindings(bindings)}
}

func publicRetainedDataCleanup(result host.RetainedDataCleanupResult) retainedDataCleanupResponse {
	return retainedDataCleanupResponse{Deleted: publicPluginDataBindings(result.Deleted)}
}

type diagnosticEventResponse struct {
	EventID           string                     `json:"event_id,omitempty"`
	Type              string                     `json:"type"`
	Severity          string                     `json:"severity"`
	Message           string                     `json:"message"`
	PluginID          string                     `json:"plugin_id,omitempty"`
	PluginInstanceID  string                     `json:"plugin_instance_id,omitempty"`
	SurfaceID         string                     `json:"surface_id,omitempty"`
	SurfaceInstanceID string                     `json:"surface_instance_id,omitempty"`
	ActiveFingerprint string                     `json:"active_fingerprint,omitempty"`
	RequestID         string                     `json:"request_id,omitempty"`
	CorrelationID     string                     `json:"correlation_id,omitempty"`
	MutationOutcome   string                     `json:"mutation_outcome,omitempty"`
	OccurredAt        time.Time                  `json:"occurred_at,omitempty"`
	Details           *diagnosticDetailsResponse `json:"details,omitempty"`
}

type diagnosticDetailsResponse struct {
	OperationsDeleted         int64                                   `json:"operations_deleted,omitempty"`
	StreamsDeleted            int64                                   `json:"streams_deleted,omitempty"`
	InvocationID              string                                  `json:"invocation_id,omitempty"`
	Method                    string                                  `json:"method,omitempty"`
	FailureCode               string                                  `json:"failure_code,omitempty"`
	RuntimeProcessFailureCode observability.RuntimeProcessFailureCode `json:"runtime_process_failure_code,omitempty"`
	OperationID               string                                  `json:"operation_id,omitempty"`
	StreamID                  string                                  `json:"stream_id,omitempty"`
	RuntimeInstanceID         string                                  `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID       string                                  `json:"runtime_generation_id,omitempty"`
	RuntimeVersion            string                                  `json:"runtime_version,omitempty"`
	RustIPCVersion            string                                  `json:"rust_ipc_version,omitempty"`
	WASMABIVersion            string                                  `json:"wasm_abi_version,omitempty"`
	ContractSetSHA256         string                                  `json:"contract_set_sha256,omitempty"`
	RuntimeTargetOS           string                                  `json:"runtime_target_os,omitempty"`
	RuntimeTargetArch         string                                  `json:"runtime_target_arch,omitempty"`
	RuntimeBinarySHA256       string                                  `json:"runtime_binary_sha256,omitempty"`
	OS                        string                                  `json:"os,omitempty"`
	Arch                      string                                  `json:"arch,omitempty"`
	Stream                    string                                  `json:"stream,omitempty"`
	PackageHash               string                                  `json:"package_hash,omitempty"`
	Artifact                  string                                  `json:"artifact,omitempty"`
	PluginInstanceID          string                                  `json:"plugin_instance_id,omitempty"`
	StoreID                   string                                  `json:"store_id,omitempty"`
	Operation                 string                                  `json:"operation,omitempty"`
	Hostcall                  string                                  `json:"hostcall,omitempty"`
	Code                      string                                  `json:"code,omitempty"`
	ConnectorID               string                                  `json:"connector_id,omitempty"`
	Transport                 string                                  `json:"transport,omitempty"`
	RevokeEpoch               uint64                                  `json:"revoke_epoch,omitempty"`
	StageID                   string                                  `json:"stage_id,omitempty"`
	Reason                    string                                  `json:"reason,omitempty"`
	SurfaceInstanceID         string                                  `json:"surface_instance_id,omitempty"`
}

type diagnosticListResponse struct {
	DiagnosticEvents []diagnosticEventResponse `json:"diagnostic_events"`
}

func publicDiagnostics(events []host.DiagnosticEvent) diagnosticListResponse {
	responses := make([]diagnosticEventResponse, len(events))
	for index, event := range events {
		responses[index] = diagnosticEventResponse{
			EventID: event.EventID, Type: event.Type, Severity: string(event.Severity), Message: event.Message,
			PluginID: event.PluginID, PluginInstanceID: event.PluginInstanceID, SurfaceID: event.SurfaceID,
			SurfaceInstanceID: event.SurfaceInstanceID, ActiveFingerprint: event.ActiveFingerprint,
			RequestID: event.RequestID, CorrelationID: event.CorrelationID,
			MutationOutcome: string(event.MutationOutcome), OccurredAt: event.OccurredAt,
			Details: publicDiagnosticDetails(event.Details),
		}
	}
	return diagnosticListResponse{DiagnosticEvents: responses}
}

func publicDiagnosticDetails(details host.DiagnosticDetails) *diagnosticDetailsResponse {
	if details == (host.DiagnosticDetails{}) {
		return nil
	}
	return &diagnosticDetailsResponse{
		OperationsDeleted: details.OperationsDeleted, StreamsDeleted: details.StreamsDeleted,
		InvocationID: details.InvocationID, Method: details.Method, FailureCode: details.FailureCode,
		RuntimeProcessFailureCode: details.RuntimeProcessFailureCode,
		OperationID:               details.OperationID, StreamID: details.StreamID, RuntimeInstanceID: details.RuntimeInstanceID,
		RuntimeGenerationID: details.RuntimeGenerationID, RuntimeVersion: details.RuntimeVersion,
		RustIPCVersion: details.RustIPCVersion, WASMABIVersion: details.WASMABIVersion,
		ContractSetSHA256: details.ContractSetSHA256,
		RuntimeTargetOS:   details.RuntimeTargetOS, RuntimeTargetArch: details.RuntimeTargetArch,
		RuntimeBinarySHA256: details.RuntimeBinarySHA256, OS: details.OS, Arch: details.Arch,
		Stream: details.Stream, PackageHash: details.PackageHash, Artifact: details.Artifact,
		PluginInstanceID: details.PluginInstanceID, StoreID: details.StoreID, Operation: details.Operation,
		Hostcall: details.Hostcall, Code: details.Code, ConnectorID: details.ConnectorID,
		Transport: details.Transport, RevokeEpoch: details.RevokeEpoch, StageID: details.StageID,
		Reason: details.Reason, SurfaceInstanceID: details.SurfaceInstanceID,
	}
}

type surfaceAssetResponse struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	ContentType   string `json:"content_type"`
	ContentBase64 string `json:"content_base64"`
}

type streamEventResponse struct {
	StreamID string    `json:"stream_id"`
	Sequence uint64    `json:"sequence"`
	Kind     string    `json:"kind"`
	Data     []byte    `json:"data,omitempty"`
	Error    string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
}

type surfaceStreamResponse struct {
	DeliveryID     string                `json:"delivery_id,omitempty"`
	ReadID         string                `json:"read_id"`
	Events         []streamEventResponse `json:"events"`
	Done           bool                  `json:"done"`
	TerminalStatus string                `json:"terminal_status,omitempty"`
}

func publicSurfaceStream(result host.ReadStreamResult) surfaceStreamResponse {
	events := make([]streamEventResponse, len(result.Events))
	for index, event := range result.Events {
		events[index] = streamEventResponse{
			StreamID: event.StreamID, Sequence: event.Sequence, Kind: event.Kind,
			Data: append([]byte(nil), event.Data...), Error: event.Error, At: event.At,
		}
	}
	return surfaceStreamResponse{
		DeliveryID: result.DeliveryID, ReadID: result.ReadID, Events: events,
		Done: result.Done, TerminalStatus: string(result.TerminalStatus),
	}
}

type pluginCatalogResponse struct {
	Plugins []pluginRecordResponse `json:"plugins"`
}

type permissionListResponse struct {
	Permissions []permissionResponse `json:"permissions"`
}

type dataExportResponse struct {
	BundleRef string `json:"bundle_ref"`
}

type acknowledgementResponse struct {
	Acknowledged bool `json:"acknowledged"`
}

type surfaceDisposeResponse struct {
	Disposed bool `json:"disposed"`
}

type sessionScopeRevokeCountsResponse struct {
	Surfaces              uint64 `json:"surfaces"`
	AssetTickets          uint64 `json:"asset_tickets"`
	AssetSessions         uint64 `json:"asset_sessions"`
	PluginGatewayTokens   uint64 `json:"plugin_gateway_tokens"`
	ConfirmationTokens    uint64 `json:"confirmation_tokens"`
	StreamTickets         uint64 `json:"stream_tickets"`
	HandleGrants          uint64 `json:"handle_grants"`
	Confirmations         uint64 `json:"confirmations"`
	Operations            uint64 `json:"operations"`
	Streams               uint64 `json:"streams"`
	RuntimeExecutions     uint64 `json:"runtime_executions"`
	ActiveNetworkRequests uint64 `json:"active_network_requests"`
	Sockets               uint64 `json:"sockets"`
	NetworkStreams        uint64 `json:"network_streams"`
	StorageHostcalls      uint64 `json:"storage_hostcalls"`
}

type sessionScopeRevokeResponse struct {
	State    string                           `json:"state"`
	Fenced   bool                             `json:"fenced"`
	Complete bool                             `json:"complete"`
	Counts   sessionScopeRevokeCountsResponse `json:"counts"`
}

func (response sessionScopeRevokeResponse) validIncomplete() bool {
	return response.State == "incomplete" && response.Fenced && !response.Complete
}

func publicSessionScopeRevocation(result host.RevokeSessionScopeResult) sessionScopeRevokeResponse {
	return sessionScopeRevokeResponse{
		State: string(result.State), Fenced: result.Fenced, Complete: result.Complete,
		Counts: sessionScopeRevokeCountsResponse{
			Surfaces: result.Counts.Surfaces, AssetTickets: result.Counts.AssetTickets,
			AssetSessions: result.Counts.AssetSessions, PluginGatewayTokens: result.Counts.PluginGatewayTokens,
			ConfirmationTokens: result.Counts.ConfirmationTokens, StreamTickets: result.Counts.StreamTickets,
			HandleGrants: result.Counts.HandleGrants, Confirmations: result.Counts.Confirmations,
			Operations: result.Counts.Operations, Streams: result.Counts.Streams,
			RuntimeExecutions:     result.Counts.RuntimeExecutions,
			ActiveNetworkRequests: result.Counts.ActiveNetworkRequests, Sockets: result.Counts.Sockets,
			NetworkStreams: result.Counts.NetworkStreams, StorageHostcalls: result.Counts.StorageHostcalls,
		},
	}
}

type runtimeStopResponse struct {
	Stopped bool `json:"stopped"`
}

type deleteResponse struct {
	Deleted bool `json:"deleted"`
}

type secretBindResponse struct {
	Bound bool `json:"bound"`
}

type secretTestResponse struct {
	Tested bool `json:"tested"`
}

type securityPolicyDeleteResponse struct {
	PluginInstanceID   string `json:"plugin_instance_id"`
	Deleted            bool   `json:"deleted"`
	PolicyRevision     uint64 `json:"policy_revision"`
	ManagementRevision uint64 `json:"management_revision"`
	RevokeEpoch        uint64 `json:"revoke_epoch"`
}

type securityPolicyListResponse struct {
	SecurityPolicies []securityPolicyResponse `json:"security_policies"`
}
