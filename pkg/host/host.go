package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

type AuditSink = observability.AuditSink

type DiagnosticsSink = observability.DiagnosticsSink

type DiagnosticLister = observability.DiagnosticLister

type AuditEvent = observability.AuditEvent

type DiagnosticEvent struct {
	EventID           string                           `json:"event_id,omitempty"`
	Type              string                           `json:"type"`
	Severity          observability.DiagnosticSeverity `json:"severity"`
	Message           string                           `json:"message"`
	PluginID          string                           `json:"plugin_id,omitempty"`
	PluginInstanceID  string                           `json:"plugin_instance_id,omitempty"`
	SurfaceID         string                           `json:"surface_id,omitempty"`
	SurfaceInstanceID string                           `json:"surface_instance_id,omitempty"`
	ActiveFingerprint string                           `json:"active_fingerprint,omitempty"`
	RequestID         string                           `json:"request_id,omitempty"`
	OccurredAt        time.Time                        `json:"occurred_at,omitempty"`
	Details           map[string]any                   `json:"details,omitempty"`
}

type ListDiagnosticEventsRequest struct {
	PluginID          string                           `json:"plugin_id,omitempty"`
	PluginInstanceID  string                           `json:"plugin_instance_id,omitempty"`
	SurfaceInstanceID string                           `json:"surface_instance_id,omitempty"`
	Type              string                           `json:"type,omitempty"`
	Severity          observability.DiagnosticSeverity `json:"severity,omitempty"`
	Limit             int                              `json:"limit,omitempty"`
}

var (
	ErrStreamTicketRequired          = errors.New("stream ticket is required")
	ErrPluginDataNotDeclared         = errors.New("plugin does not declare exportable data")
	ErrPluginStorageNotDeclared      = errors.New("target plugin does not declare storage")
	ErrPluginSettingsNotDeclared     = errors.New("target plugin does not declare settings")
	ErrPluginDataContractChanged     = errors.New("plugin data contract changed")
	ErrOperationCancelDispatchFailed = errors.New("operation cancel dispatch failed")
	ErrMethodRequestContract         = errors.New("plugin method request contract validation failed")
	ErrMethodResponseContract        = errors.New("plugin method response contract validation failed")
	ErrMethodAdapterPanic            = errors.New("plugin method adapter panicked")
	ErrConfirmationInvalid           = errors.New("plugin confirmation is invalid")
	ErrConfirmationRejected          = errors.New("plugin confirmation was rejected")
	ErrManagementRevisionMismatch    = errors.New("management revision mismatch")
	ErrPluginAlreadyInstalled        = errors.New("plugin instance is already installed")
	ErrPluginTrustUnavailable        = errors.New("plugin trust is unavailable")
	ErrPluginTrustDenied             = errors.New("plugin trust does not allow execution")
	ErrPluginUIProtocolUnsupported   = errors.New("plugin UI protocol is unsupported")
	ErrPluginRuntimeNotConfigured    = errors.New("plugin runtime is not configured")
	ErrPluginRuntimeIncompatible     = errors.New("plugin runtime is incompatible")
	ErrSecurityEventPersistence      = errors.New("plugin security event persistence failed")
	ErrHostClosed                    = errors.New("plugin host is closed")
	ErrFeatureNotConfigured          = errors.New("plugin feature is not configured")
	ErrReleaseModuleRequired         = errors.New("release module is required")
	ErrRuntimeModuleRequired         = errors.New("runtime module is required")
	ErrCapabilityModuleRequired      = errors.New("capability module is required")
	ErrConnectivityModuleRequired    = errors.New("connectivity module is required")
	ErrSecretsModuleRequired         = errors.New("secrets module is required")
	ErrCoreActionModuleRequired      = errors.New("core action module is required")
)

// Feature identifies an optional host integration module. The values are part
// of the host contract and must remain a closed, sorted set.
type Feature string

const (
	FeatureRelease      Feature = "release"
	FeatureRuntime      Feature = "runtime"
	FeatureCapability   Feature = "capability"
	FeatureConnectivity Feature = "connectivity"
	FeatureSecrets      Feature = "secrets"
	FeatureCoreAction   Feature = "core_action"
)

// FeatureNotConfiguredError identifies an optional module that was not
// installed in the host configuration.
type FeatureNotConfiguredError struct {
	Features []Feature
}

func (e FeatureNotConfiguredError) Error() string {
	values := make([]string, len(e.Features))
	for index, feature := range e.Features {
		values[index] = string(feature)
	}
	return fmt.Sprintf("%s: %s", ErrFeatureNotConfigured, strings.Join(values, ", "))
}

func (e FeatureNotConfiguredError) Unwrap() error { return ErrFeatureNotConfigured }

func (e FeatureNotConfiguredError) MissingFeatures() []Feature {
	return append([]Feature(nil), e.Features...)
}

type PolicyAdapter interface {
	EvaluateLocalPolicy(ctx context.Context, session sessionctx.Context, plugin PluginRef, method manifest.MethodSpec) (PolicyDecision, error)
	DeveloperModeEnabled(ctx context.Context, session sessionctx.Context) (bool, error)
	LocalGeneratedPluginsEnabled(ctx context.Context, session sessionctx.Context) (bool, error)
}

// PackageTrustVerifier is the install/update trust decision boundary. Runnable
// trust states must come from this verifier or the release/local import
// provenance handled by Host core.
type PackageTrustVerifier interface {
	VerifyPackageTrust(ctx context.Context, req PackageTrustVerificationRequest) (PackageTrustVerificationResult, error)
}

type PackageTrustAction string

const (
	PackageTrustActionInstall PackageTrustAction = "install"
	PackageTrustActionUpdate  PackageTrustAction = "update"
)

const (
	installStageTTL            = 30 * time.Minute
	hostRuntimeShutdownTimeout = 5 * time.Second
)

type PackageTrustVerificationRequest struct {
	Action               PackageTrustAction     `json:"action"`
	Package              pluginpkg.Package      `json:"package"`
	LocalImport          bool                   `json:"local_import,omitempty"`
	ReleaseRef           *PluginReleaseRef      `json:"release_ref,omitempty"`
	Release              *PluginPackageRelease  `json:"release,omitempty"`
	SourcePolicySnapshot *SourcePolicySnapshot  `json:"source_policy_snapshot,omitempty"`
	CurrentRecord        *registry.PluginRecord `json:"current_record,omitempty"`
	PluginInstanceID     string                 `json:"plugin_instance_id,omitempty"`
	Now                  time.Time              `json:"now,omitempty"`
}

type PackageTrustVerificationResult = registry.TrustAssessment

type ReleaseMetadataVerificationRequest struct {
	Action                   PackageTrustAction     `json:"action"`
	ReleaseRef               PluginReleaseRef       `json:"release_ref"`
	Release                  PluginPackageRelease   `json:"release"`
	SourcePolicySnapshot     SourcePolicySnapshot   `json:"source_policy_snapshot"`
	ReleaseMetadataBytes     []byte                 `json:"-"`
	ReleaseMetadataSignature []byte                 `json:"-"`
	CurrentRecord            *registry.PluginRecord `json:"current_record,omitempty"`
	PluginInstanceID         string                 `json:"plugin_instance_id,omitempty"`
	Now                      time.Time              `json:"now,omitempty"`
}

type ReleaseMetadataVerificationResult struct {
	Metadata map[string]string `json:"metadata,omitempty"`
}

type SourceRevocationEvidenceVerificationRequest struct {
	ReleaseRef                  PluginReleaseRef               `json:"release_ref"`
	SourcePolicySnapshot        SourcePolicySnapshot           `json:"source_policy_snapshot"`
	RevocationEvidence          SourcePolicyRevocationEvidence `json:"revocation_evidence"`
	RevocationMetadata          SourceRevocationMetadata       `json:"revocation_metadata"`
	RevocationMetadataBytes     []byte                         `json:"-"`
	RevocationMetadataSignature []byte                         `json:"-"`
	Now                         time.Time                      `json:"now,omitempty"`
}

type SourceRevocationEvidenceVerificationResult struct {
	Metadata map[string]string `json:"metadata,omitempty"`
}

type PolicyDecision string

const (
	PolicyAllow PolicyDecision = "allow"
	PolicyDeny  PolicyDecision = "deny"
)

type SecretStoreAdapter interface {
	secrets.Store
	secrets.Lister
	secrets.PluginDeleter
}

type SecretBindRequest = secrets.BindRequest
type SecretDeleteRequest = secrets.DeleteRequest
type SecretTestRequest = secrets.TestRequest

type ReleaseMetadataVerifier interface {
	VerifyReleaseMetadata(ctx context.Context, req ReleaseMetadataVerificationRequest) (ReleaseMetadataVerificationResult, error)
}

type SourceRevocationEvidenceVerifier interface {
	VerifySourceRevocationEvidence(ctx context.Context, req SourceRevocationEvidenceVerificationRequest) (SourceRevocationEvidenceVerificationResult, error)
}

type ReleaseSourcePolicyResolver interface {
	ResolveReleaseSourcePolicy(ctx context.Context, req ReleaseSourcePolicyRequest) (SourcePolicySnapshot, error)
}

type ReleaseArtifactResolver interface {
	ResolveReleaseArtifact(ctx context.Context, req ReleaseArtifactResolveRequest) (ResolvedPackageArtifact, error)
}

type PackageDistribution string

const (
	PackageDistributionRegistryRef     PackageDistribution = "registry_ref"
	PackageDistributionHostArtifactRef PackageDistribution = "host_artifact_ref"
	PackageDistributionLocalImport     PackageDistribution = "local_import"
)

type PackageSourceType string

const (
	PackageSourceRegistry     PackageSourceType = "registry"
	PackageSourceHostArtifact PackageSourceType = "host_artifact"
)

type PackageSourceClass string

const (
	PackageSourceClassOfficial  PackageSourceClass = "official"
	PackageSourceClassCurated   PackageSourceClass = "curated"
	PackageSourceClassCommunity PackageSourceClass = "community"
	PackageSourceClassPrivate   PackageSourceClass = "private"
)

type PackageInstallPolicy string

const (
	PackageInstallAllow          PackageInstallPolicy = "allow"
	PackageInstallReviewRequired PackageInstallPolicy = "review_required"
	PackageInstallBlock          PackageInstallPolicy = "block"
)

type PackageUnsignedPolicy string

const (
	PackageUnsignedDevOnly        PackageUnsignedPolicy = "dev_only"
	PackageUnsignedReviewRequired PackageUnsignedPolicy = "review_required"
	PackageUnsignedBlock          PackageUnsignedPolicy = "block"
)

type PackageDowngradePolicy string

const (
	PackageDowngradeBlock          PackageDowngradePolicy = "block"
	PackageDowngradeReviewRequired PackageDowngradePolicy = "review_required"
)

type PackageHashSet struct {
	PackageSHA256  string `json:"package_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	EntriesSHA256  string `json:"entries_sha256"`
}

type PluginReleaseRef struct {
	SourceID              string         `json:"source_id"`
	ReleaseMetadataRef    string         `json:"release_metadata_ref"`
	ReleaseMetadataSHA256 string         `json:"release_metadata_sha256"`
	PublisherID           string         `json:"publisher_id"`
	PluginID              string         `json:"plugin_id"`
	Version               string         `json:"version"`
	ExpectedHashes        PackageHashSet `json:"expected_hashes"`
}

type PackageDistributionRef struct {
	Distribution PackageDistribution `json:"distribution"`
	ArtifactRef  string              `json:"artifact_ref,omitempty"`
	ImportID     string              `json:"import_id,omitempty"`
}

type SourcePolicySnapshot struct {
	SchemaVersion        string                          `json:"schema_version"`
	SourceID             string                          `json:"source_id"`
	SourceType           PackageSourceType               `json:"source_type"`
	SourceClass          PackageSourceClass              `json:"source_class,omitempty"`
	AllowedPublishers    []string                        `json:"allowed_publishers,omitempty"`
	AllowedArtifactHosts []string                        `json:"allowed_artifact_hosts,omitempty"`
	TrustedKeyIDs        []string                        `json:"trusted_key_ids,omitempty"`
	TrustedKeys          []SourcePolicyTrustedKey        `json:"trusted_keys,omitempty"`
	RevocationEvidence   *SourcePolicyRevocationEvidence `json:"revocation_evidence,omitempty"`
	RequireSignature     bool                            `json:"require_signature,omitempty"`
	InstallPolicy        PackageInstallPolicy            `json:"install_policy,omitempty"`
	UnsignedPolicy       PackageUnsignedPolicy           `json:"unsigned_policy,omitempty"`
	DowngradePolicy      PackageDowngradePolicy          `json:"downgrade_policy,omitempty"`
	PolicyEpoch          string                          `json:"policy_epoch,omitempty"`
	KeyRotationEpoch     string                          `json:"key_rotation_epoch,omitempty"`
	RevocationEpoch      string                          `json:"revocation_epoch,omitempty"`
	AssessedAt           string                          `json:"assessed_at,omitempty"`
	Metadata             map[string]string               `json:"metadata,omitempty"`
}

type SourcePolicyTrustedKey struct {
	Algorithm                   string   `json:"algorithm"`
	KeyID                       string   `json:"key_id"`
	PublicKeySHA256             string   `json:"public_key_sha256"`
	Usage                       []string `json:"usage"`
	AllowedCapabilityPublishers []string `json:"allowed_capability_publishers,omitempty"`
	ValidFrom                   string   `json:"valid_from,omitempty"`
	ValidUntil                  string   `json:"valid_until,omitempty"`
	RevocationEpoch             string   `json:"revocation_epoch,omitempty"`
}

type SourcePolicyRevocationEvidence struct {
	MetadataRef      string `json:"metadata_ref"`
	MetadataSHA256   string `json:"metadata_sha256"`
	SignatureRef     string `json:"signature_ref"`
	SignatureKeyID   string `json:"signature_key_id"`
	VerifiedAt       string `json:"verified_at"`
	ExpiresAt        string `json:"expires_at"`
	HighestSeenEpoch string `json:"highest_seen_epoch"`
	MetadataBytes    []byte `json:"-"`
	SignatureBytes   []byte `json:"-"`
}

type SourceRevocationMetadata struct {
	SchemaVersion    string   `json:"schema_version"`
	SourceID         string   `json:"source_id"`
	HighestSeenEpoch string   `json:"highest_seen_epoch"`
	GeneratedAt      string   `json:"generated_at"`
	ExpiresAt        string   `json:"expires_at"`
	RevokedKeyIDs    []string `json:"revoked_key_ids,omitempty"`
}

type PackageReleaseSignature struct {
	Algorithm          string `json:"algorithm"`
	KeyID              string `json:"key_id"`
	SignatureBundleRef string `json:"signature_bundle_ref"`
	SourcePolicyEpoch  string `json:"source_policy_epoch"`
	RevocationEpoch    string `json:"revocation_epoch"`
}

type ReleaseMetadataSignature struct {
	Algorithm         string `json:"algorithm"`
	KeyID             string `json:"key_id"`
	SignatureRef      string `json:"signature_ref"`
	SourcePolicyEpoch string `json:"source_policy_epoch"`
	RevocationEpoch   string `json:"revocation_epoch"`
}

type PluginPackageRelease struct {
	SourceID                 string                    `json:"source_id"`
	PublisherID              string                    `json:"publisher_id"`
	PluginID                 string                    `json:"plugin_id"`
	Version                  string                    `json:"version"`
	DistributionRef          PackageDistributionRef    `json:"distribution_ref"`
	ReleaseMetadataSHA256    string                    `json:"release_metadata_sha256"`
	ReleaseMetadataSignature *ReleaseMetadataSignature `json:"release_metadata_signature,omitempty"`
	Hashes                   PackageHashSet            `json:"hashes"`
	PackageSignature         *PackageReleaseSignature  `json:"package_signature,omitempty"`
	Compatibility            *ReleaseCompatibility     `json:"compatibility,omitempty"`
	HostRequirements         []HostRequirement         `json:"host_requirements,omitempty"`
	ReleaseEvidence          *ReleaseEvidence          `json:"release_evidence,omitempty"`
	Metadata                 map[string]string         `json:"metadata,omitempty"`
}

type ReleaseCompatibility struct {
	MinReDevPluginVersion string   `json:"min_redevplugin_version,omitempty"`
	MinRuntimeVersion     string   `json:"min_runtime_version,omitempty"`
	UIProtocolVersion     string   `json:"ui_protocol_version,omitempty"`
	SupportedTargets      []string `json:"supported_targets,omitempty"`
}

type HostRequirement struct {
	HostID                      string                      `json:"host_id"`
	MinHostVersion              string                      `json:"min_host_version,omitempty"`
	RequiredCapabilityContracts []HostCapabilityRequirement `json:"required_capability_contracts,omitempty"`
}

type HostCapabilityRequirement struct {
	CapabilityID      string                    `json:"capability_id"`
	CapabilityVersion string                    `json:"capability_version"`
	Contract          HostCapabilityContractRef `json:"contract"`
}

type HostCapabilityContractRef = capabilitycontract.Pin

type HostRequirementSelectionRequest struct {
	SourceID      string            `json:"source_id"`
	PublisherID   string            `json:"publisher_id"`
	PluginID      string            `json:"plugin_id"`
	PluginVersion string            `json:"plugin_version"`
	Requirements  []HostRequirement `json:"requirements"`
}

type HostRequirementSelection struct {
	HostID string `json:"host_id"`
}

type HostRequirementPolicy interface {
	SelectHostRequirement(ctx context.Context, req HostRequirementSelectionRequest) (HostRequirementSelection, error)
}

type CapabilityContractResolveRequest struct {
	SourceID             string                 `json:"source_id"`
	PluginPublisherID    string                 `json:"plugin_publisher_id"`
	Pin                  capabilitycontract.Pin `json:"pin"`
	SourcePolicySnapshot SourcePolicySnapshot   `json:"source_policy_snapshot"`
}

type CapabilityArtifactFetchHop struct {
	URL        string `json:"url"`
	ResolvedIP string `json:"resolved_ip"`
}

type ResolvedCapabilityContractFile struct {
	Reader     io.ReadCloser                `json:"-"`
	Size       int64                        `json:"size"`
	MediaType  string                       `json:"media_type"`
	FetchChain []CapabilityArtifactFetchHop `json:"fetch_chain"`
}

type CapabilityContractArtifactSet interface {
	OpenCapabilityContractArtifact(ctx context.Context, ref string) (ResolvedCapabilityContractFile, error)
}

type ResolvedCapabilityContractArtifact struct {
	Artifacts CapabilityContractArtifactSet `json:"-"`
}

type CapabilityContractArtifactResolver interface {
	ResolveCapabilityContract(ctx context.Context, req CapabilityContractResolveRequest) (ResolvedCapabilityContractArtifact, error)
}

type CapabilityContractKeyRequest struct {
	SourceID             string               `json:"source_id"`
	PublisherID          string               `json:"publisher_id"`
	KeyID                string               `json:"key_id"`
	SourcePolicySnapshot SourcePolicySnapshot `json:"source_policy_snapshot"`
}

type CapabilityContractKeyResolver interface {
	ResolveCapabilityContractKey(ctx context.Context, req CapabilityContractKeyRequest) ([]byte, error)
}

type ReleaseEvidence struct {
	NoticesSHA256    string `json:"notices_sha256,omitempty"`
	ProvenanceSHA256 string `json:"provenance_sha256,omitempty"`
	GeneratedAt      string `json:"generated_at,omitempty"`
}

type signedReleaseMetadata struct {
	SchemaVersion            string                    `json:"schema_version"`
	SourceID                 string                    `json:"source_id"`
	ReleaseMetadataRef       string                    `json:"release_metadata_ref"`
	PublisherID              string                    `json:"publisher_id"`
	PluginID                 string                    `json:"plugin_id"`
	Version                  string                    `json:"version"`
	DistributionRef          PackageDistributionRef    `json:"distribution_ref"`
	Hashes                   PackageHashSet            `json:"hashes"`
	ReleaseMetadataSignature *ReleaseMetadataSignature `json:"release_metadata_signature,omitempty"`
	PackageSignature         *PackageReleaseSignature  `json:"package_signature,omitempty"`
	Compatibility            *ReleaseCompatibility     `json:"compatibility,omitempty"`
	HostRequirements         []HostRequirement         `json:"host_requirements,omitempty"`
	ReleaseEvidence          *ReleaseEvidence          `json:"release_evidence,omitempty"`
	Metadata                 map[string]string         `json:"metadata,omitempty"`
}

type ReleaseSourcePolicyRequest struct {
	Action           PackageTrustAction     `json:"action"`
	ReleaseRef       PluginReleaseRef       `json:"release_ref"`
	CurrentRecord    *registry.PluginRecord `json:"current_record,omitempty"`
	PluginInstanceID string                 `json:"plugin_instance_id,omitempty"`
	Now              time.Time              `json:"now,omitempty"`
}

type ReleaseArtifactResolveRequest struct {
	Action               PackageTrustAction     `json:"action"`
	ReleaseRef           PluginReleaseRef       `json:"release_ref"`
	SourcePolicySnapshot SourcePolicySnapshot   `json:"source_policy_snapshot"`
	CurrentRecord        *registry.PluginRecord `json:"current_record,omitempty"`
	PluginInstanceID     string                 `json:"plugin_instance_id,omitempty"`
	Now                  time.Time              `json:"now,omitempty"`
}

type ResolvedPackageArtifact struct {
	ReleaseMetadataBytes     []byte      `json:"-"`
	ReleaseMetadataSignature []byte      `json:"-"`
	Reader                   io.ReaderAt `json:"-"`
	Size                     int64       `json:"size"`
	ArtifactSHA256           string      `json:"artifact_sha256"`
}

type CoreActionAdapter interface {
	ResolveCoreActionTarget(ctx context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error)
	InvokeCoreAction(ctx context.Context, req capability.Invocation) (capability.Result, error)
}

type RuntimeTarget struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type StartRuntimeRequest struct {
	Target RuntimeTarget `json:"target,omitempty"`
}

type SurfaceCatalogSink interface {
	PublishSurfaces(ctx context.Context, snapshot SurfaceSnapshot) error
}

type SurfaceSnapshot struct {
	PluginInstanceID  string                 `json:"plugin_instance_id"`
	ActiveFingerprint string                 `json:"active_fingerprint"`
	Surfaces          []manifest.SurfaceSpec `json:"surfaces"`
}

type PluginRef struct {
	PluginID          string `json:"plugin_id"`
	PluginInstanceID  string `json:"plugin_instance_id"`
	Version           string `json:"version"`
	ActiveFingerprint string `json:"active_fingerprint"`
}

// CoreAdapters contains the dependencies required by every Host instance.
// Optional capabilities are intentionally kept out of this structure so a
// host can expose only the integrations it actually provides. Package trust is
// core because every package mutation crosses the same trust boundary.
type CoreAdapters struct {
	Policy               PolicyAdapter
	PackageTrustVerifier PackageTrustVerifier
	Registry             registry.Store
	Audit                AuditSink
	SecurityAudit        observability.SecurityAuditJournal
	Diagnostics          DiagnosticsSink
	SurfaceCatalog       SurfaceCatalogSink
	SurfaceTokens        *bridge.SurfaceTokenService
	PluginData           PluginData
	Assets               pluginpkg.AssetStore
	InstallStages        installstage.Store
	Operations           operation.Store
	ConfirmationIntents  security.ConfirmationIntentStore
	Streams              stream.Store
}

type ReleaseModule struct {
	ReleaseMetadataVerifier     ReleaseMetadataVerifier
	RevocationVerifier          SourceRevocationEvidenceVerifier
	ReleaseSourcePolicy         ReleaseSourcePolicyResolver
	ReleaseArtifactResolver     ReleaseArtifactResolver
	HostRequirements            HostRequirementPolicy
	CapabilityContractArtifacts CapabilityContractArtifactResolver
	CapabilityContractKeys      CapabilityContractKeyResolver
}

type RuntimeModule struct {
	Manager runtimeclient.Manager
}

type CapabilityModule struct {
	Registry *capability.Registry
}

type ConnectivityModule struct {
	Broker          connectivity.Broker
	NetworkExecutor connectivity.NetworkExecutor
}

type SecretsModule struct {
	Store SecretStoreAdapter
}

type CoreActionModule struct {
	Adapter CoreActionAdapter
}

type Config struct {
	Core         CoreAdapters
	Release      *ReleaseModule
	Runtime      *RuntimeModule
	Capability   *CapabilityModule
	Connectivity *ConnectivityModule
	Secrets      *SecretsModule
	CoreAction   *CoreActionModule
}

type normalizedAdapters struct {
	Policy                      PolicyAdapter
	PackageTrustVerifier        PackageTrustVerifier
	ReleaseMetadataVerifier     ReleaseMetadataVerifier
	RevocationVerifier          SourceRevocationEvidenceVerifier
	ReleaseSourcePolicy         ReleaseSourcePolicyResolver
	ReleaseArtifactResolver     ReleaseArtifactResolver
	HostRequirements            HostRequirementPolicy
	CapabilityContractArtifacts CapabilityContractArtifactResolver
	CapabilityContractKeys      CapabilityContractKeyResolver
	Registry                    registry.Store
	Audit                       AuditSink
	SecurityAudit               observability.SecurityAuditJournal
	Diagnostics                 DiagnosticsSink
	Secrets                     SecretStoreAdapter
	RuntimeManager              runtimeclient.Manager
	SurfaceCatalog              SurfaceCatalogSink
	Assets                      pluginpkg.AssetStore
	InstallStages               installstage.Store
	Capabilities                *capability.Registry
	CoreActions                 CoreActionAdapter
	SurfaceTokens               *bridge.SurfaceTokenService
	PluginData                  PluginData
	Connectivity                connectivity.Broker
	NetworkExecutor             connectivity.NetworkExecutor
	Operations                  operation.Store
	ConfirmationIntents         security.ConfirmationIntentStore
	Streams                     stream.Store
}

type PluginData interface {
	plugindata.Store
	storage.FilesBroker
	storage.KVBroker
	storage.SQLiteBroker
	storage.Inspector
	Close() error
}

type Host struct {
	adapters            normalizedAdapters
	features            map[Feature]struct{}
	securityJournal     observability.SecurityAuditJournal
	securityExporter    *observability.SecurityAuditExporter
	securityExportMu    sync.Mutex
	surfaceTokens       *bridge.SurfaceTokenService
	surfaceDocuments    *surfaceDocumentCache
	methodSchemas       *methodSchemaCache
	surfaceGenerationID string
	lifecycleLocks      *pluginLifecycleLockRegistry
	executions          *executionLeaseRegistry
	streamReads         *streamReadLockRegistry
	detachedCancelJobs  sync.Map
	lifecycleCtx        context.Context
	lifecycleCancel     context.CancelFunc
	lifecycleMu         sync.RWMutex
	lifecycleWG         sync.WaitGroup
	securityAuditWG     sync.WaitGroup
	closed              bool
	closeOnce           sync.Once
	closeErr            error
}

type ImportLocalPackageRequest struct {
	PackageReader    io.ReaderAt
	PackageSize      int64
	PluginInstanceID string
	Now              time.Time
}

type UpdateLocalPackageRequest struct {
	PluginInstanceID           string
	ExpectedManagementRevision uint64
	PackageReader              io.ReaderAt
	PackageSize                int64
	Now                        time.Time
}

type InstallReleaseRefRequest struct {
	ReleaseRef       PluginReleaseRef
	PluginInstanceID string
	Now              time.Time
}

type UpdateReleaseRefRequest struct {
	PluginInstanceID           string
	ExpectedManagementRevision uint64
	ReleaseRef                 PluginReleaseRef
	Now                        time.Time
}

type packageTrustInput struct {
	LocalImport          bool
	ReleaseRef           *PluginReleaseRef
	Release              *PluginPackageRelease
	SourcePolicySnapshot *SourcePolicySnapshot
}

type DowngradeRequest struct {
	PluginInstanceID           string
	ExpectedManagementRevision uint64
	Version                    string
	PackageHash                string
	Now                        time.Time
}

type EnableRequest struct {
	PluginInstanceID           string
	ExpectedManagementRevision uint64
	Now                        time.Time
}

type DisableRequest struct {
	PluginInstanceID           string
	ExpectedManagementRevision uint64
	Reason                     string
	Now                        time.Time
}

type UninstallRequest struct {
	PluginInstanceID           string
	ExpectedManagementRevision uint64
	DeleteData                 bool
	Now                        time.Time
}

type ListRetainedDataRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type DeleteRetainedDataRequest struct {
	PluginInstanceID        string `json:"plugin_instance_id"`
	ExpectedBindingRevision uint64 `json:"expected_binding_revision"`
}

type BindRetainedDataRequest struct {
	SourcePluginInstanceID           string    `json:"source_plugin_instance_id"`
	ExpectedSourceBindingRevision    uint64    `json:"expected_source_binding_revision"`
	TargetPluginInstanceID           string    `json:"target_plugin_instance_id"`
	TargetExpectedManagementRevision uint64    `json:"target_expected_management_revision"`
	Now                              time.Time `json:"now,omitempty"`
}

type CleanupExpiredRetainedDataRequest struct {
	Now time.Time `json:"now,omitempty"`
}

type RetainedDataCleanupResult struct {
	Deleted []plugindata.Binding `json:"deleted,omitempty"`
}

type ExportDataRequest struct {
	PluginInstanceID string
}

type ImportDataRequest struct {
	PluginInstanceID           string
	BundleRef                  string
	ExpectedManagementRevision uint64
	Now                        time.Time
}

type ExportDataResult struct {
	BundleRef   string `json:"bundle_ref"`
	ContentHash string `json:"content_hash"`
	SizeBytes   int64  `json:"size_bytes"`
}

type DeleteExportDataRequest struct {
	BundleRef string `json:"bundle_ref"`
}

type GrantPermissionRequest struct {
	PluginInstanceID           string    `json:"plugin_instance_id"`
	PermissionID               string    `json:"permission_id"`
	ExpectedPolicyRevision     uint64    `json:"expected_policy_revision"`
	ExpectedManagementRevision uint64    `json:"expected_management_revision"`
	ExpectedRevokeEpoch        uint64    `json:"expected_revoke_epoch"`
	Now                        time.Time `json:"now,omitempty"`
	ExpiresAt                  time.Time `json:"expires_at,omitempty"`
}

type RevokePermissionRequest struct {
	PluginInstanceID           string    `json:"plugin_instance_id"`
	PermissionID               string    `json:"permission_id"`
	ExpectedPolicyRevision     uint64    `json:"expected_policy_revision"`
	ExpectedManagementRevision uint64    `json:"expected_management_revision"`
	ExpectedRevokeEpoch        uint64    `json:"expected_revoke_epoch"`
	Reason                     string    `json:"reason,omitempty"`
	Now                        time.Time `json:"now,omitempty"`
}

type ListPermissionGrantsRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	ActiveOnly       bool   `json:"active_only,omitempty"`
}

type PutSecurityPolicyRequest struct {
	PluginInstanceID           string    `json:"plugin_instance_id"`
	ExpectedPolicyRevision     uint64    `json:"expected_policy_revision"`
	ExpectedManagementRevision uint64    `json:"expected_management_revision"`
	ExpectedRevokeEpoch        uint64    `json:"expected_revoke_epoch"`
	AllowedPermissions         []string  `json:"allowed_permissions,omitempty"`
	DeniedMethods              []string  `json:"denied_methods,omitempty"`
	Now                        time.Time `json:"now,omitempty"`
}

type GetSecurityPolicyRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
}

type DeleteSecurityPolicyRequest struct {
	PluginInstanceID           string    `json:"plugin_instance_id"`
	ExpectedPolicyRevision     uint64    `json:"expected_policy_revision"`
	ExpectedManagementRevision uint64    `json:"expected_management_revision"`
	ExpectedRevokeEpoch        uint64    `json:"expected_revoke_epoch"`
	Now                        time.Time `json:"now,omitempty"`
}

type SecurityPolicyResult struct {
	Policy    security.PolicyRecord           `json:"policy"`
	Revisions registry.AuthorizationRevisions `json:"revisions"`
}

type GetSettingsRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
}

type PatchSettingsRequest struct {
	PluginInstanceID       string         `json:"plugin_instance_id"`
	ExpectedValuesRevision uint64         `json:"expected_values_revision"`
	Set                    map[string]any `json:"set"`
	Remove                 []string       `json:"remove,omitempty"`
}

type SettingsSchemaResult struct {
	PluginInstanceID string                      `json:"plugin_instance_id"`
	SchemaVersion    int                         `json:"schema_version"`
	Fields           []manifest.SettingFieldSpec `json:"fields"`
	ValuesRevision   uint64                      `json:"values_revision"`
}

type SettingsResult struct {
	PluginInstanceID string                   `json:"plugin_instance_id"`
	SchemaVersion    int                      `json:"schema_version"`
	ValuesRevision   uint64                   `json:"values_revision"`
	Values           map[string]any           `json:"values"`
	SecretMetadata   []SettingsSecretMetadata `json:"secret_metadata"`
}

type SettingsSecretMetadata struct {
	Key            string     `json:"key"`
	SecretRef      string     `json:"secret_ref"`
	Scope          string     `json:"scope"`
	Bound          bool       `json:"bound"`
	LastTestStatus string     `json:"last_test_status,omitempty"`
	BoundAt        *time.Time `json:"bound_at,omitempty"`
	TestedAt       *time.Time `json:"tested_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

type PermissionMutationResult struct {
	Permission permissions.Record              `json:"permission"`
	Revisions  registry.AuthorizationRevisions `json:"revisions"`
}

type OpenSurfaceRequest struct {
	PluginInstanceID           string
	ExpectedManagementRevision uint64
	SurfaceID                  string
	SurfaceInstanceID          string
	Now                        time.Time
}

type ExchangeAssetTicketRequest struct {
	SurfaceInstanceID string
	AssetTicket       string
	Now               time.Time
}

type ReadSurfaceAssetRequest struct {
	AssetSession   string
	AssetSessionID string
	BindingID      string
	Now            time.Time
}

type DisposeSurfaceRequest struct {
	SurfaceInstanceID string
	BridgeNonce       string
	Now               time.Time
}

type RevokeSurfaceScopeRequest struct {
	Now time.Time
}

type ReadSurfaceAssetResult struct {
	Entry   pluginpkg.Entry
	Content []byte
	Session bridge.SurfaceSession
}

type PrepareSurfaceResult struct {
	bridge.AssetSessionResult
	Document pluginpkg.OpaqueSurfaceDocument `json:"document"`
}

type MintBridgeTokenRequest struct {
	Handshake                 bridge.Handshake
	BridgeChannelID           string
	HandshakeTranscriptSHA256 string
	PreviousGatewayToken      string
	Now                       time.Time
}

type CallMethodRequest struct {
	PluginInstanceID       string         `json:"plugin_instance_id"`
	SurfaceInstanceID      string         `json:"surface_instance_id"`
	BridgeChannelID        string         `json:"bridge_channel_id"`
	GatewayToken           string         `json:"plugin_gateway_token"`
	ConfirmationID         string         `json:"confirmation_id,omitempty"`
	Method                 string         `json:"method"`
	Params                 map[string]any `json:"params,omitempty"`
	Now                    time.Time      `json:"now,omitempty"`
	session                sessionctx.Context
	executionAuthorization methodExecutionAuthorization
	streamTicketMinter     methodStreamTicketMinter
}

type methodStreamTicketMinter func(operationID string, streamID string) (bridge.StreamTicketResult, error)

type CallMethodResult struct {
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

type IntentRecord struct {
	PluginID          string                       `json:"plugin_id"`
	PluginInstanceID  string                       `json:"plugin_instance_id"`
	PublisherID       string                       `json:"publisher_id"`
	DisplayName       string                       `json:"display_name"`
	Version           string                       `json:"version"`
	ActiveFingerprint string                       `json:"active_fingerprint"`
	IntentID          string                       `json:"intent_id"`
	Method            string                       `json:"method"`
	Effect            manifest.MethodEffect        `json:"effect"`
	Execution         manifest.MethodExecutionMode `json:"execution"`
	PayloadSchema     map[string]any               `json:"payload_schema,omitempty"`
}

type ListIntentsRequest struct {
	IntentID         string `json:"intent_id,omitempty"`
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type InvokeIntentRequest struct {
	PluginInstanceID string         `json:"plugin_instance_id,omitempty"`
	IntentID         string         `json:"intent_id"`
	Params           map[string]any `json:"params,omitempty"`
	Now              time.Time      `json:"now,omitempty"`
	session          sessionctx.Context
}

type workerInvocationPayload struct {
	PluginID             string                          `json:"plugin_id"`
	PluginInstanceID     string                          `json:"plugin_instance_id"`
	ActiveFingerprint    string                          `json:"active_fingerprint"`
	RuntimeInstanceID    string                          `json:"runtime_instance_id"`
	RuntimeGenerationID  string                          `json:"runtime_generation_id"`
	PackageHash          string                          `json:"package_hash"`
	WorkerID             string                          `json:"worker_id"`
	WorkerMode           string                          `json:"worker_mode"`
	WorkerScope          string                          `json:"worker_scope"`
	Artifact             string                          `json:"artifact"`
	ArtifactSHA256       string                          `json:"artifact_sha256"`
	ABI                  string                          `json:"abi"`
	Method               string                          `json:"method"`
	Effect               string                          `json:"effect"`
	Execution            string                          `json:"execution"`
	SurfaceInstanceID    string                          `json:"surface_instance_id,omitempty"`
	OwnerSessionHash     string                          `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string                          `json:"owner_user_hash,omitempty"`
	OwnerEnvHash         string                          `json:"owner_env_hash,omitempty"`
	SessionChannelIDHash string                          `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string                          `json:"bridge_channel_id,omitempty"`
	OperationID          string                          `json:"operation_id,omitempty"`
	StreamID             string                          `json:"stream_id,omitempty"`
	AuditCorrelationID   string                          `json:"audit_correlation_id"`
	ParamsSHA256         string                          `json:"params_sha256"`
	Params               map[string]any                  `json:"params"`
	StorageHandleGrants  map[string]string               `json:"storage_handle_grants,omitempty"`
	BrokerAccess         manifest.MethodBrokerAccessSpec `json:"broker_access"`
	BrokerAccessSHA256   string                          `json:"broker_access_sha256"`
}

type PrepareMethodConfirmationRequest struct {
	PluginInstanceID  string         `json:"plugin_instance_id"`
	SurfaceInstanceID string         `json:"surface_instance_id"`
	BridgeChannelID   string         `json:"bridge_channel_id"`
	GatewayToken      string         `json:"plugin_gateway_token"`
	Method            string         `json:"method"`
	Params            map[string]any `json:"params,omitempty"`
	Now               time.Time      `json:"now,omitempty"`
}

type PrepareMethodConfirmationResult struct {
	ConfirmationID      string    `json:"confirmation_id"`
	ConfirmationTokenID string    `json:"confirmation_token_id"`
	RequestHash         string    `json:"request_hash"`
	PlanHash            string    `json:"plan_hash"`
	Plan                any       `json:"plan,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type RejectMethodConfirmationRequest struct {
	PluginInstanceID  string
	SurfaceInstanceID string
	BridgeChannelID   string
	GatewayToken      string
	ConfirmationID    string
	Now               time.Time
}

type RejectMethodConfirmationResult struct {
	Rejected bool `json:"rejected"`
}

func normalizeConfig(config Config) (normalizedAdapters, map[Feature]struct{}, error) {
	adapters := normalizedAdapters{}
	core := config.Core
	adapters.Policy = core.Policy
	adapters.PackageTrustVerifier = core.PackageTrustVerifier
	adapters.Registry = core.Registry
	adapters.Audit = core.Audit
	adapters.SecurityAudit = core.SecurityAudit
	adapters.Diagnostics = core.Diagnostics
	adapters.SurfaceCatalog = core.SurfaceCatalog
	adapters.SurfaceTokens = core.SurfaceTokens
	adapters.PluginData = core.PluginData
	adapters.Assets = core.Assets
	adapters.InstallStages = core.InstallStages
	adapters.Operations = core.Operations
	adapters.ConfirmationIntents = core.ConfirmationIntents
	adapters.Streams = core.Streams

	features := make(map[Feature]struct{}, 6)
	if module := config.Release; module != nil {
		adapters.ReleaseMetadataVerifier = module.ReleaseMetadataVerifier
		adapters.RevocationVerifier = module.RevocationVerifier
		adapters.ReleaseSourcePolicy = module.ReleaseSourcePolicy
		adapters.ReleaseArtifactResolver = module.ReleaseArtifactResolver
		adapters.HostRequirements = module.HostRequirements
		adapters.CapabilityContractArtifacts = module.CapabilityContractArtifacts
		adapters.CapabilityContractKeys = module.CapabilityContractKeys
		features[FeatureRelease] = struct{}{}
	}
	if module := config.Runtime; module != nil {
		adapters.RuntimeManager = module.Manager
		features[FeatureRuntime] = struct{}{}
	}
	if module := config.Capability; module != nil {
		adapters.Capabilities = module.Registry
		features[FeatureCapability] = struct{}{}
	}
	if module := config.Connectivity; module != nil {
		adapters.Connectivity = module.Broker
		adapters.NetworkExecutor = module.NetworkExecutor
		features[FeatureConnectivity] = struct{}{}
	}
	if module := config.Secrets; module != nil {
		adapters.Secrets = module.Store
		features[FeatureSecrets] = struct{}{}
	}
	if module := config.CoreAction; module != nil {
		adapters.CoreActions = module.Adapter
		features[FeatureCoreAction] = struct{}{}
	}
	return adapters, features, validateConfig(adapters, config)
}

func validateConfig(adapters normalizedAdapters, config Config) error {
	checks := []struct {
		name string
		ok   bool
	}{
		{"policy adapter", adapters.Policy != nil},
		{"package trust verifier", adapters.PackageTrustVerifier != nil},
		{"registry store", adapters.Registry != nil},
		{"audit sink", adapters.Audit != nil},
		{"security audit journal", adapters.SecurityAudit != nil},
		{"diagnostics sink", adapters.Diagnostics != nil},
		{"surface token service", adapters.SurfaceTokens != nil},
		{"plugin data store", adapters.PluginData != nil},
		{"asset store", adapters.Assets != nil},
		{"install stage store", adapters.InstallStages != nil},
		{"operation store", adapters.Operations != nil},
		{"confirmation intent store", adapters.ConfirmationIntents != nil},
		{"stream store", adapters.Streams != nil},
	}
	for _, check := range checks {
		if !check.ok {
			return fmt.Errorf("core adapter %s is required", check.name)
		}
	}
	if module := config.Release; module != nil {
		if module.ReleaseMetadataVerifier == nil || module.RevocationVerifier == nil ||
			module.ReleaseSourcePolicy == nil || module.ReleaseArtifactResolver == nil || module.HostRequirements == nil ||
			module.CapabilityContractArtifacts == nil || module.CapabilityContractKeys == nil {
			return ErrReleaseModuleRequired
		}
	}
	if module := config.Runtime; module != nil && module.Manager == nil {
		return ErrRuntimeModuleRequired
	}
	if module := config.Capability; module != nil && module.Registry == nil {
		return ErrCapabilityModuleRequired
	}
	if module := config.Connectivity; module != nil && (module.Broker == nil || module.NetworkExecutor == nil) {
		return ErrConnectivityModuleRequired
	}
	if module := config.Secrets; module != nil && module.Store == nil {
		return ErrSecretsModuleRequired
	}
	if module := config.CoreAction; module != nil && module.Adapter == nil {
		return ErrCoreActionModuleRequired
	}
	return nil
}

var (
	ErrSecretStoreRequired              = errors.New("secret store adapter is required")
	ErrInvalidSecretRef                 = secrets.ErrInvalidSecretRef
	ErrPackageTrustVerifierRequired     = errors.New("package trust verifier is required for requested trust state")
	ErrPackageTrustVerificationInvalid  = errors.New("package trust verifier returned invalid trust state")
	ErrReleaseMetadataVerifierRequired  = errors.New("release metadata verifier is required")
	ErrSourceRevocationVerifierRequired = errors.New("source revocation evidence verifier is required")
	ErrReleaseSourcePolicyRequired      = errors.New("release source policy resolver is required")
	ErrReleaseArtifactResolverRequired  = errors.New("release artifact resolver is required")
	ErrReleaseRefVerificationFailed     = errors.New("release ref verification failed")
	ErrReleaseRefPolicyDenied           = errors.New("release ref source policy denied")
)

const (
	maxReleaseMetadataBytes     int64 = 1 << 20
	maxReleaseMetadataSignature int64 = 64 << 10
	maxReleasePackageBytes      int64 = 256 << 20
)

type ListOperationsRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	Cursor           string `json:"cursor,omitempty"`
	Limit            int    `json:"limit,omitempty"`
}

type ListOperationsResult struct {
	Operations []operation.Record `json:"operations"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type CancelOperationRequest struct {
	OperationID string `json:"operation_id"`
	Reason      string `json:"reason,omitempty"`
	Now         time.Time
}

type CancelSurfaceOperationRequest struct {
	OperationID       string
	SurfaceInstanceID string
	BridgeChannelID   string
	Reason            string
	Now               time.Time
}

type ReadStreamRequest struct {
	StreamID          string        `json:"stream_id"`
	StreamTicket      string        `json:"stream_ticket,omitempty"`
	ReadID            string        `json:"read_id"`
	SurfaceInstanceID string        `json:"surface_instance_id,omitempty"`
	MaxEvents         int           `json:"max_events,omitempty"`
	MaxBytes          int64         `json:"max_bytes,omitempty"`
	WaitTimeout       time.Duration `json:"-"`
	Now               time.Time
}

type ReadStreamResult struct {
	Record         stream.Record  `json:"record"`
	DeliveryID     string         `json:"delivery_id,omitempty"`
	ReadID         string         `json:"read_id"`
	Events         []stream.Event `json:"events,omitempty"`
	Done           bool           `json:"done"`
	TerminalStatus stream.Status  `json:"terminal_status,omitempty"`
}

type AcknowledgeStreamRequest struct {
	StreamID          string    `json:"stream_id"`
	StreamTicket      string    `json:"stream_ticket"`
	DeliveryID        string    `json:"delivery_id"`
	SurfaceInstanceID string    `json:"surface_instance_id"`
	Now               time.Time `json:"-"`
}

type MintConnectionGrantRequest struct {
	PluginInstanceID    string                 `json:"plugin_instance_id"`
	ConnectorID         string                 `json:"connector_id"`
	Transport           connectivity.Transport `json:"transport"`
	Destination         string                 `json:"destination"`
	RuntimeInstanceID   string                 `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string                 `json:"runtime_generation_id,omitempty"`
	RuntimeShardID      string                 `json:"runtime_shard_id,omitempty"`
	Now                 time.Time              `json:"now,omitempty"`
	TTL                 time.Duration          `json:"ttl,omitempty"`
}

type NetworkHandleGrantResult struct {
	ConnectionGrant connectivity.ConnectionGrant `json:"connection_grant"`
	HandleGrant     bridge.HandleGrantResult     `json:"handle_grant"`
}

type MintStorageHandleGrantRequest struct {
	PluginInstanceID    string        `json:"plugin_instance_id"`
	StoreID             string        `json:"store_id"`
	RuntimeInstanceID   string        `json:"runtime_instance_id,omitempty"`
	RuntimeGenerationID string        `json:"runtime_generation_id"`
	RuntimeShardID      string        `json:"runtime_shard_id,omitempty"`
	Now                 time.Time     `json:"now,omitempty"`
	TTL                 time.Duration `json:"ttl,omitempty"`
}

type StorageHandleGrantResult struct {
	Namespace   storage.Namespace        `json:"namespace"`
	HandleGrant bridge.HandleGrantResult `json:"handle_grant"`
}

type ManagementRevisionMismatchError struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	Expected         uint64 `json:"expected_management_revision"`
	Actual           uint64 `json:"actual_management_revision"`
}

func (e *ManagementRevisionMismatchError) Error() string {
	return fmt.Sprintf(
		"%s: plugin %q is at management revision %d, request expected %d",
		ErrManagementRevisionMismatch,
		e.PluginInstanceID,
		e.Actual,
		e.Expected,
	)
}

func (e *ManagementRevisionMismatchError) Unwrap() error {
	return ErrManagementRevisionMismatch
}

func Open(ctx context.Context, config Config) (*Host, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	adapters, features, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	surfaceGenerationID, err := newHostSurfaceGenerationID()
	if err != nil {
		return nil, err
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	host := &Host{
		adapters:            adapters,
		features:            features,
		securityJournal:     adapters.SecurityAudit,
		surfaceTokens:       adapters.SurfaceTokens,
		surfaceDocuments:    newSurfaceDocumentCache(defaultSurfaceDocumentCacheEntries, defaultSurfaceDocumentCacheBytes),
		methodSchemas:       newMethodSchemaCache(defaultMethodSchemaCacheEntries),
		surfaceGenerationID: surfaceGenerationID,
		lifecycleLocks:      newPluginLifecycleLockRegistry(),
		executions:          newExecutionLeaseRegistry(),
		streamReads:         newStreamReadLockRegistry(),
		lifecycleCtx:        lifecycleCtx,
		lifecycleCancel:     lifecycleCancel,
	}
	if host.securityJournal != nil {
		if err := host.securityJournal.ReconcilePendingSecurityAudits(ctx); err != nil {
			lifecycleCancel()
			return nil, fmt.Errorf("reconcile security audit journal: %w", err)
		}
		if adapters.Audit != nil {
			host.securityExporter = observability.NewSecurityAuditExporter(host.securityJournal, adapters.Audit)
			if err := host.securityExporter.Export(ctx); err != nil {
				lifecycleCancel()
				return nil, fmt.Errorf("export reconciled security audits: %w", err)
			}
		}
	}
	if err := host.reconcileDurableExecutionStates(ctx); err != nil {
		lifecycleCancel()
		return nil, fmt.Errorf("reconcile durable operation and stream state: %w", err)
	}
	maintenanceNow := time.Now().UTC()
	if err := host.pruneTerminalExecutionRecords(ctx, maintenanceNow); err != nil {
		lifecycleCancel()
		return nil, fmt.Errorf("prune terminal operation and stream state: %w", err)
	}
	if host.executions.beginTerminalMaintenance(maintenanceNow) {
		host.executions.finishTerminalMaintenance()
	}
	if host.adapters.RuntimeManager != nil {
		if err := host.adapters.RuntimeManager.BindHostServices(runtimeclient.RuntimeHostServices{
			StreamSink: hostRuntimeStreamSink{executions: host.executions},
		}); err != nil {
			lifecycleCancel()
			return nil, fmt.Errorf("bind runtime manager host services: %w", err)
		}
	}
	host.startSecurityAuditExporter()
	return host, nil
}

func (h *Host) Close() error {
	if h == nil {
		return nil
	}
	h.closeOnce.Do(func() {
		h.lifecycleMu.Lock()
		h.closed = true
		if h.executions != nil {
			h.executions.cancelAll(ErrHostClosed)
		}
		if h.lifecycleCancel != nil {
			h.lifecycleCancel()
		}
		h.lifecycleMu.Unlock()
		if h.executions != nil {
			h.executions.finishAll()
		}
		h.lifecycleWG.Wait()
		h.securityAuditWG.Wait()
		var runtimeCloseErr error
		if h.adapters.RuntimeManager != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), hostRuntimeShutdownTimeout)
			runtimeCloseErr = h.adapters.RuntimeManager.Stop(shutdownCtx)
			cancel()
		}
		var pluginDataCloseErr error
		if h.adapters.PluginData != nil {
			pluginDataCloseErr = h.adapters.PluginData.Close()
		}
		var assetStoreCloseErr error
		if h.adapters.Assets != nil {
			assetStoreCloseErr = h.adapters.Assets.Close()
		}
		h.closeErr = errors.Join(runtimeCloseErr, pluginDataCloseErr, assetStoreCloseErr)
	})
	return h.closeErr
}

// Features returns the configured optional modules in canonical order.
func (h *Host) Features() []string {
	if h == nil || len(h.features) == 0 {
		return []string{}
	}
	ordered := []Feature{FeatureRelease, FeatureRuntime, FeatureCapability, FeatureConnectivity, FeatureSecrets, FeatureCoreAction}
	result := make([]string, 0, len(h.features))
	for _, feature := range ordered {
		if _, ok := h.features[feature]; ok {
			result = append(result, string(feature))
		}
	}
	return result
}

func (h *Host) requireFeature(feature Feature) error {
	return h.requireFeatures([]Feature{feature})
}

func (h *Host) requireFeatures(required []Feature) error {
	missing := make([]Feature, 0, len(required))
	for _, candidate := range []Feature{FeatureRelease, FeatureRuntime, FeatureCapability, FeatureConnectivity, FeatureSecrets, FeatureCoreAction} {
		if slices.Contains(required, candidate) && !h.featureConfigured(candidate) {
			missing = append(missing, candidate)
		}
	}
	if len(missing) > 0 {
		return FeatureNotConfiguredError{Features: missing}
	}
	return nil
}

func (h *Host) featureConfigured(feature Feature) bool {
	if h == nil {
		return false
	}
	if _, ok := h.features[feature]; !ok {
		return false
	}
	switch feature {
	case FeatureRelease:
		return h.adapters.ReleaseMetadataVerifier != nil && h.adapters.RevocationVerifier != nil &&
			h.adapters.ReleaseSourcePolicy != nil && h.adapters.ReleaseArtifactResolver != nil &&
			h.adapters.HostRequirements != nil && h.adapters.CapabilityContractArtifacts != nil &&
			h.adapters.CapabilityContractKeys != nil
	case FeatureRuntime:
		return h.adapters.RuntimeManager != nil
	case FeatureCapability:
		return h.adapters.Capabilities != nil
	case FeatureConnectivity:
		return h.adapters.Connectivity != nil && h.adapters.NetworkExecutor != nil
	case FeatureSecrets:
		return h.adapters.Secrets != nil
	case FeatureCoreAction:
		return h.adapters.CoreActions != nil
	default:
		return false
	}
}

// ensureOpen registers an admitted lifecycle call before Close can publish the closed state.
func (h *Host) ensureOpen() (func(), error) {
	if h == nil {
		return nil, ErrHostClosed
	}
	h.lifecycleMu.RLock()
	if h.closed {
		h.lifecycleMu.RUnlock()
		return nil, ErrHostClosed
	}
	h.lifecycleWG.Add(1)
	h.lifecycleMu.RUnlock()
	return h.lifecycleWG.Done, nil
}

func (h *Host) startLifecycleJob(run func(context.Context)) bool {
	if h == nil || run == nil {
		return false
	}
	h.lifecycleMu.RLock()
	if h.closed {
		h.lifecycleMu.RUnlock()
		return false
	}
	h.lifecycleWG.Add(1)
	ctx := h.lifecycleCtx
	h.lifecycleMu.RUnlock()
	go func() {
		defer h.lifecycleWG.Done()
		run(ctx)
	}()
	return true
}

func (h *Host) Capabilities() *capability.Registry {
	return h.adapters.Capabilities
}

func requireManagementRevision(record registry.PluginRecord, expected uint64) error {
	if expected == 0 {
		return &ManagementRevisionMismatchError{PluginInstanceID: record.PluginInstanceID, Actual: record.ManagementRevision}
	}
	if record.ManagementRevision != expected {
		return &ManagementRevisionMismatchError{
			PluginInstanceID: record.PluginInstanceID,
			Expected:         expected,
			Actual:           record.ManagementRevision,
		}
	}
	return nil
}

func managementMutationError(record registry.PluginRecord, err error) error {
	var conflict *registry.ManagementRevisionConflictError
	if errors.As(err, &conflict) {
		return &ManagementRevisionMismatchError{PluginInstanceID: conflict.PluginInstanceID, Expected: conflict.Expected, Actual: conflict.Actual}
	}
	return err
}

func requireUserSession(ctx context.Context) (sessionctx.Context, error) {
	return sessionctx.Require(ctx)
}

func (h *Host) OpenSurface(ctx context.Context, req OpenSurfaceRequest) (result bridge.SurfaceBootstrap, retErr error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireRead(ctx, req.PluginInstanceID)
	if err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	defer releaseLifecycle()
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	if err := requireManagementRevision(record, req.ExpectedManagementRevision); err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	if record.Manifest.Plugin.UIProtocolVersion != version.PluginUIProtocolVersion {
		return bridge.SurfaceBootstrap{}, fmt.Errorf("%w: installed %s, required %s", ErrPluginUIProtocolUnsupported, record.Manifest.Plugin.UIProtocolVersion, version.PluginUIProtocolVersion)
	}
	if record.EnableState != registry.EnableEnabled {
		return bridge.SurfaceBootstrap{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	surface, ok := manifestSurfaceByID(record.Manifest, req.SurfaceID)
	if !ok {
		return bridge.SurfaceBootstrap{}, fmt.Errorf("surface %q is not declared", req.SurfaceID)
	}
	entry, ok := packageEntryByPath(record.PackageEntries, surface.Entry)
	if !ok || strings.TrimSpace(entry.SHA256) == "" {
		return bridge.SurfaceBootstrap{}, fmt.Errorf("surface %q entry metadata is unavailable", req.SurfaceID)
	}
	if req.SurfaceInstanceID == "" {
		req.SurfaceInstanceID, err = newSurfaceInstanceID()
		if err != nil {
			return bridge.SurfaceBootstrap{}, err
		}
	}
	runtimeGenerationID := h.surfaceGenerationID
	if pluginHasWorkers(record.Manifest) {
		binding, err := h.bindCompatibleWorkerRuntime(ctx, record)
		if err != nil {
			return bridge.SurfaceBootstrap{}, err
		}
		runtimeGenerationID = binding.RuntimeGenerationID
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.surface.opened", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	bootstrap, err := h.surfaceTokens.OpenSurface(bridge.OpenSurfaceRequest{
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		PluginVersion:        record.Version,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		ActiveFingerprint:    record.ActiveFingerprint,
		EntryPath:            surface.Entry,
		EntrySHA256:          entry.SHA256,
		RouteRole:            bridge.RouteRoleTrustedParent,
		RuntimeGenerationID:  runtimeGenerationID,
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
		Revision: bridge.RevisionBinding{
			PolicyRevision:     record.PolicyRevision,
			ManagementRevision: record.ManagementRevision,
			RevokeEpoch:        record.RevokeEpoch,
		},
		Now: req.Now,
	})
	if err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	return bootstrap, nil
}

func (h *Host) ExchangeAssetTicket(ctx context.Context, req ExchangeAssetTicketRequest) (bridge.AssetSessionResult, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return bridge.AssetSessionResult{}, err
	}
	result, err := h.surfaceTokens.ExchangeAssetTicket(bridge.ExchangeAssetTicketRequest{
		SurfaceInstanceID:    req.SurfaceInstanceID,
		AssetTicket:          req.AssetTicket,
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
		Now:                  req.Now,
	})
	if err != nil {
		return bridge.AssetSessionResult{}, err
	}
	return result, nil
}

func (h *Host) PrepareSurface(ctx context.Context, req ExchangeAssetTicketRequest) (result PrepareSurfaceResult, err error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return PrepareSurfaceResult{}, err
	}
	assetSession, err := h.ExchangeAssetTicket(ctx, req)
	if err != nil {
		return PrepareSurfaceResult{}, err
	}
	defer func() {
		if err != nil {
			_ = h.surfaceTokens.DisposeAssetSession(bridge.ValidateAssetSessionRequest{
				AssetSession:         assetSession.AssetSession,
				AssetSessionID:       assetSession.AssetSessionID,
				OwnerSessionHash:     session.OwnerSessionHash,
				OwnerUserHash:        session.OwnerUserHash,
				OwnerEnvHash:         session.OwnerEnvHash,
				SessionChannelIDHash: session.SessionChannelIDHash,
				Now:                  req.Now,
			})
		}
	}()
	assetRequest := ReadSurfaceAssetRequest{
		AssetSession:   assetSession.AssetSession,
		AssetSessionID: assetSession.AssetSessionID,
		Now:            req.Now,
	}
	validation, record, err := h.validateSurfaceAssetSession(ctx, assetRequest)
	if err != nil {
		return PrepareSurfaceResult{}, err
	}
	markPrepared := func() error {
		return h.surfaceTokens.MarkSurfacePrepared(bridge.MarkSurfacePreparedRequest{
			SurfaceInstanceID:    validation.Session.SurfaceInstanceID,
			AssetSessionID:       assetSession.AssetSessionID,
			BridgeNonce:          validation.Session.BridgeNonce,
			OwnerSessionHash:     session.OwnerSessionHash,
			OwnerUserHash:        session.OwnerUserHash,
			OwnerEnvHash:         session.OwnerEnvHash,
			SessionChannelIDHash: session.SessionChannelIDHash,
			Now:                  req.Now,
		})
	}
	entry, err := h.readValidatedSurfaceAsset(ctx, validation, record, assetSession.EntryPath, assetSession.EntrySHA256)
	if err != nil {
		return PrepareSurfaceResult{}, err
	}
	if document, ok := h.surfaceDocuments.Get(entry.Session.ActiveFingerprint, assetSession.EntryPath, assetSession.EntrySHA256); ok {
		if err := markPrepared(); err != nil {
			return PrepareSurfaceResult{}, err
		}
		return PrepareSurfaceResult{AssetSessionResult: assetSession, Document: document}, nil
	}
	readAssets := map[string]pluginpkg.Asset{
		assetSession.EntryPath: {Entry: entry.Entry, Content: entry.Content},
	}
	document, err := pluginpkg.BuildOpaqueSurfaceDocument(assetSession.EntryPath, func(assetPath string) (pluginpkg.Asset, error) {
		if asset, ok := readAssets[assetPath]; ok {
			return asset, nil
		}
		result, readErr := h.readValidatedSurfaceAsset(ctx, validation, record, assetPath, "")
		if readErr != nil {
			return pluginpkg.Asset{}, readErr
		}
		return pluginpkg.Asset{Entry: result.Entry, Content: result.Content}, nil
	})
	if err != nil {
		return PrepareSurfaceResult{}, err
	}
	if document.EntrySHA256 != assetSession.EntrySHA256 {
		return PrepareSurfaceResult{}, bridge.ErrTokenAudience
	}
	h.surfaceDocuments.Put(entry.Session.ActiveFingerprint, assetSession.EntryPath, assetSession.EntrySHA256, document)
	if err := markPrepared(); err != nil {
		return PrepareSurfaceResult{}, err
	}
	return PrepareSurfaceResult{AssetSessionResult: assetSession, Document: document}, nil
}

func (h *Host) ReadSurfaceAsset(ctx context.Context, req ReadSurfaceAssetRequest) (ReadSurfaceAssetResult, error) {
	validation, record, err := h.validateSurfaceAssetSession(ctx, req)
	if err != nil {
		return ReadSurfaceAssetResult{}, err
	}
	document, ok := h.surfaceDocuments.Get(
		validation.Session.ActiveFingerprint,
		validation.Session.EntryPath,
		validation.Session.EntrySHA256,
	)
	if !ok {
		return ReadSurfaceAssetResult{}, bridge.ErrTokenAudience
	}
	var binding *pluginpkg.OpaqueSurfaceAsset
	for i := range document.Assets {
		if document.Assets[i].BindingID == req.BindingID {
			binding = &document.Assets[i]
			break
		}
	}
	if binding == nil {
		return ReadSurfaceAssetResult{}, bridge.ErrTokenAudience
	}
	return h.readValidatedSurfaceAsset(ctx, validation, record, binding.Path, binding.SHA256)
}

func (h *Host) validateSurfaceAssetSession(ctx context.Context, req ReadSurfaceAssetRequest) (bridge.AssetSessionValidation, registry.PluginRecord, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return bridge.AssetSessionValidation{}, registry.PluginRecord{}, err
	}
	if h.adapters.Assets == nil {
		return bridge.AssetSessionValidation{}, registry.PluginRecord{}, errors.New("package asset store is required")
	}
	validation, err := h.surfaceTokens.ValidateAssetSession(bridge.ValidateAssetSessionRequest{
		AssetSession:         req.AssetSession,
		AssetSessionID:       req.AssetSessionID,
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
		Now:                  req.Now,
	})
	if err != nil {
		return bridge.AssetSessionValidation{}, registry.PluginRecord{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, validation.Session.PluginInstanceID)
	if err != nil {
		return bridge.AssetSessionValidation{}, registry.PluginRecord{}, err
	}
	if record.ActiveFingerprint != validation.Session.ActiveFingerprint {
		return bridge.AssetSessionValidation{}, registry.PluginRecord{}, bridge.ErrTokenRevoked
	}
	if record.EnableState != registry.EnableEnabled {
		return bridge.AssetSessionValidation{}, registry.PluginRecord{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return bridge.AssetSessionValidation{}, registry.PluginRecord{}, err
	}
	return validation, record, nil
}

func (h *Host) readValidatedSurfaceAsset(ctx context.Context, validation bridge.AssetSessionValidation, record registry.PluginRecord, assetPath string, expectedSHA256 string) (ReadSurfaceAssetResult, error) {
	expectedEntry, ok := packageEntryByPath(record.PackageEntries, assetPath)
	if !ok || strings.TrimSpace(expectedEntry.SHA256) == "" || expectedEntry.Size < 0 {
		return ReadSurfaceAssetResult{}, bridge.ErrTokenAudience
	}
	if expectedSHA256 != "" && expectedEntry.SHA256 != expectedSHA256 {
		return ReadSurfaceAssetResult{}, bridge.ErrTokenAudience
	}
	asset, err := h.adapters.Assets.ReadAsset(ctx, record.PackageHash, assetPath)
	if err != nil {
		return ReadSurfaceAssetResult{}, err
	}
	actualSHA256 := sha256.Sum256(asset.Content)
	if asset.Entry.Path != expectedEntry.Path ||
		asset.Entry.SHA256 != expectedEntry.SHA256 ||
		asset.Entry.Size != expectedEntry.Size ||
		asset.Entry.ContentType != expectedEntry.ContentType ||
		int64(len(asset.Content)) != expectedEntry.Size ||
		"sha256:"+hex.EncodeToString(actualSHA256[:]) != expectedEntry.SHA256 {
		return ReadSurfaceAssetResult{}, bridge.ErrTokenAudience
	}
	return ReadSurfaceAssetResult{
		Entry:   asset.Entry,
		Content: asset.Content,
		Session: validation.Session,
	}, nil
}

func (h *Host) DisposeSurface(ctx context.Context, req DisposeSurfaceRequest) error {
	session, err := requireUserSession(ctx)
	if err != nil {
		return err
	}
	return h.surfaceTokens.DisposeBoundSurface(bridge.DisposeSurfaceRequest{
		SurfaceInstanceID:    req.SurfaceInstanceID,
		BridgeNonce:          req.BridgeNonce,
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
		Now:                  req.Now,
	})
}

func (h *Host) RevokeSurfaceScope(ctx context.Context, req RevokeSurfaceScopeRequest) (result int, retErr error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return 0, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.surface_scope.revoked"})
	if err != nil {
		return 0, err
	}
	var auditDetails map[string]any
	defer func() { retErr = auditMutation.completeWithDetails(context.WithoutCancel(ctx), retErr, auditDetails) }()
	revoked, err := h.surfaceTokens.RevokeSurfaceScope(bridge.RevokeSurfaceScopeRequest{
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
		Now:                  req.Now,
	})
	if err != nil {
		return 0, err
	}
	auditDetails = map[string]any{
		"surface_count":  revoked,
		"channel_scoped": session.SessionChannelIDHash != "",
	}
	return revoked, nil
}

func (h *Host) MintBridgeToken(ctx context.Context, req MintBridgeTokenRequest) (result bridge.GatewayTokenResult, retErr error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return bridge.GatewayTokenResult{}, err
	}
	validation, err := h.surfaceTokens.ValidateBridgeHandshake(bridge.MintGatewayTokenRequest{
		Handshake:                 req.Handshake,
		BridgeChannelID:           req.BridgeChannelID,
		HandshakeTranscriptSHA256: req.HandshakeTranscriptSHA256,
		PreviousGatewayToken:      req.PreviousGatewayToken,
		Now:                       req.Now,
	})
	if err != nil {
		return bridge.GatewayTokenResult{}, err
	}
	if validation.Session.OwnerSessionHash != session.OwnerSessionHash ||
		validation.Session.OwnerUserHash != session.OwnerUserHash ||
		validation.Session.OwnerEnvHash != session.OwnerEnvHash ||
		validation.Session.SessionChannelIDHash != session.SessionChannelIDHash {
		return bridge.GatewayTokenResult{}, bridge.ErrTokenAudience
	}
	if err := h.requireSurfaceRuntimeGeneration(ctx, validation.Session.PluginInstanceID, validation.Session.SurfaceInstanceID, validation.Session.RuntimeGenerationID, req.Now); err != nil {
		return bridge.GatewayTokenResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, validation.Session.PluginInstanceID)
	if err != nil {
		return bridge.GatewayTokenResult{}, err
	}
	if record.PluginID != validation.Session.PluginID || record.ActiveFingerprint != validation.Session.ActiveFingerprint {
		return bridge.GatewayTokenResult{}, bridge.ErrHandshakeMismatch
	}
	if record.EnableState != registry.EnableEnabled {
		return bridge.GatewayTokenResult{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return bridge.GatewayTokenResult{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.bridge_token.minted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return bridge.GatewayTokenResult{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	result, err = h.surfaceTokens.MintGatewayToken(bridge.MintGatewayTokenRequest{
		Handshake:                 req.Handshake,
		BridgeChannelID:           req.BridgeChannelID,
		HandshakeTranscriptSHA256: req.HandshakeTranscriptSHA256,
		PreviousGatewayToken:      req.PreviousGatewayToken,
		Now:                       req.Now,
	})
	if err != nil {
		return bridge.GatewayTokenResult{}, err
	}
	return result, nil
}

func (h *Host) CallPluginMethod(ctx context.Context, req CallMethodRequest) (result CallMethodResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	var resolvedCall *resolvedMethodCall
	defer func() {
		resultErr = finalizeRPCError(ctx, resultErr)
		if resultErr != nil && resolvedCall != nil {
			reportErr := h.reportMethodRejectionSafely(ctx, resolvedCall.record, resolvedCall.method.Method, req.SurfaceInstanceID, resultErr)
			resultErr = mergeRPCFailures(ctx, resultErr, reportErr)
		}
	}()
	session, err := requireUserSession(ctx)
	if err != nil {
		return CallMethodResult{}, err
	}
	req.session = session
	frozenParams, err := deepCloneParams(req.Params)
	if err != nil {
		return CallMethodResult{}, err
	}
	req.Params = frozenParams
	call, err := h.resolveMethodCall(ctx, req)
	if err != nil {
		return CallMethodResult{}, err
	}
	resolvedCall = &call
	if methodRequiresConfirmation(call.method) {
		if err := h.validateMethodRequest(call.record, call.method, req.Params); err != nil {
			return CallMethodResult{}, err
		}
		requestHash, err := methodRequestHash(call.method, req.Params)
		if err != nil {
			return CallMethodResult{}, err
		}
		if req.ConfirmationID == "" {
			return CallMethodResult{
				ConfirmationRequired: true,
				RequestHash:          requestHash,
			}, ErrConfirmationRequired
		}
		confirmationAudit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.confirmation.consumed", PluginID: call.record.PluginID, PluginInstanceID: call.record.PluginInstanceID})
		if err != nil {
			return CallMethodResult{}, err
		}
		intent, consumeErr := h.consumeConfirmationIntent(ctx, req.ConfirmationID, req.Now)
		if err := confirmationAudit.complete(context.WithoutCancel(ctx), consumeErr); err != nil {
			if consumeErr != nil && !errors.Is(err, ErrSecurityEventPersistence) {
				return CallMethodResult{}, fmt.Errorf("%w: %v", ErrConfirmationInvalid, err)
			}
			return CallMethodResult{}, err
		}
		if intent.PluginInstanceID != call.record.PluginInstanceID ||
			intent.SurfaceInstanceID != req.SurfaceInstanceID ||
			intent.BridgeChannelID != req.BridgeChannelID ||
			intent.Method != call.method.Method ||
			intent.RequestHash != requestHash ||
			intent.Scope.ActiveFingerprint != call.record.ActiveFingerprint ||
			intent.Scope.OwnerSessionHash != req.session.OwnerSessionHash ||
			intent.Scope.OwnerUserHash != req.session.OwnerUserHash ||
			intent.Scope.OwnerEnvHash != req.session.OwnerEnvHash ||
			intent.Scope.SessionChannelIDHash != req.session.SessionChannelIDHash ||
			intent.Scope.PolicyRevision != call.record.PolicyRevision ||
			intent.Scope.ManagementRevision != call.record.ManagementRevision ||
			intent.Scope.RevokeEpoch != call.record.RevokeEpoch {
			return CallMethodResult{}, ErrConfirmationInvalid
		}
		target, targetHash, err := h.resolveMethodConfirmationTarget(ctx, call.record, call.method, req)
		if err != nil {
			return CallMethodResult{}, err
		}
		if targetHash != intent.Scope.TargetDescriptorSHA256 {
			return CallMethodResult{}, ErrConfirmationInvalid
		}
		_, currentPlanHash, err := h.prepareConfirmationPlan(ctx, call, req, requestHash)
		if err != nil {
			return CallMethodResult{}, err
		}
		if currentPlanHash != intent.PlanHash {
			return CallMethodResult{}, ErrConfirmationInvalid
		}
		confirmationAudience := call.audience
		confirmationAudience.ConfirmationID = intent.ConfirmationID
		confirmationAudience.Method = call.method.Method
		confirmationAudience.RequestHash = requestHash
		confirmationAudience.PlanHash = intent.PlanHash
		confirmationAudience.TargetDescriptorSHA256 = targetHash
		if _, err := h.surfaceTokens.ValidateConfirmationTokenID(bridge.ValidateConfirmationTokenIDRequest{
			ConfirmationTokenID: intent.ConfirmationTokenID,
			Audience:            confirmationAudience,
			Revision:            call.revision,
			Now:                 req.Now,
		}); err != nil {
			return CallMethodResult{}, fmt.Errorf("%w: %v", ErrConfirmationInvalid, err)
		}
		req.executionAuthorization = methodExecutionAuthorization{
			confirmation: capability.ConfirmationEvidence{
				Required:       true,
				Confirmed:      true,
				ConfirmationID: intent.ConfirmationID,
				RequestSHA256:  intent.RequestHash,
				PlanSHA256:     intent.PlanHash,
				TargetSHA256:   targetHash,
			},
			target:     target,
			targetHash: targetHash,
		}
	}
	req.streamTicketMinter = h.newMethodStreamTicketMinter(call.audience, call.revision, call.method.Method, req.Now)
	result, err = h.dispatchMethod(ctx, call.record, call.method, req)
	if err != nil {
		return CallMethodResult{}, err
	}
	if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.method.called", PluginID: call.record.PluginID, PluginInstanceID: call.record.PluginInstanceID}); err != nil {
		return result, mutation.Unknown(err)
	}
	return result, nil
}

func (h *Host) PrepareMethodConfirmation(ctx context.Context, req PrepareMethodConfirmationRequest) (response PrepareMethodConfirmationResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	defer func() {
		resultErr = finalizeRPCError(ctx, resultErr)
	}()
	session, err := requireUserSession(ctx)
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	frozenParams, err := deepCloneParams(req.Params)
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	req.Params = frozenParams
	callRequest := CallMethodRequest{
		PluginInstanceID:  req.PluginInstanceID,
		SurfaceInstanceID: req.SurfaceInstanceID,
		BridgeChannelID:   req.BridgeChannelID,
		GatewayToken:      req.GatewayToken,
		Method:            req.Method,
		Params:            req.Params,
		Now:               req.Now,
		session:           session,
	}
	call, err := h.resolveMethodCall(ctx, callRequest)
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	if !methodRequiresConfirmation(call.method) {
		return PrepareMethodConfirmationResult{}, errors.New("method does not require confirmation")
	}
	if err := h.validateMethodRequest(call.record, call.method, req.Params); err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	requestHash, err := methodRequestHash(call.method, req.Params)
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	_, targetHash, err := h.resolveMethodConfirmationTarget(ctx, call.record, call.method, callRequest)
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	plan, planHash, err := h.prepareConfirmationPlan(ctx, call, callRequest, requestHash)
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	confirmationID, err := newConfirmationID()
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.confirmation.issued", PluginID: call.record.PluginID, PluginInstanceID: call.record.PluginInstanceID})
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	defer func() { resultErr = auditMutation.complete(context.WithoutCancel(ctx), resultErr) }()
	result, err := h.surfaceTokens.MintConfirmationToken(bridge.MintConfirmationTokenRequest{
		PluginID:               call.audience.PluginID,
		PluginInstanceID:       call.audience.PluginInstanceID,
		PluginVersion:          call.audience.PluginVersion,
		ActiveFingerprint:      call.audience.ActiveFingerprint,
		SurfaceID:              call.audience.SurfaceID,
		SurfaceInstanceID:      call.audience.SurfaceInstanceID,
		EntryPath:              call.audience.EntryPath,
		EntrySHA256:            call.audience.EntrySHA256,
		AssetSessionNonce:      call.audience.AssetSessionNonce,
		RouteRole:              call.audience.RouteRole,
		ConfirmationID:         confirmationID,
		OwnerSessionHash:       call.audience.OwnerSessionHash,
		OwnerUserHash:          call.audience.OwnerUserHash,
		OwnerEnvHash:           call.audience.OwnerEnvHash,
		SessionChannelIDHash:   call.audience.SessionChannelIDHash,
		BridgeChannelID:        call.audience.BridgeChannelID,
		RuntimeGenerationID:    call.audience.RuntimeGenerationID,
		Method:                 call.method.Method,
		RequestHash:            requestHash,
		PlanHash:               planHash,
		TargetDescriptorSHA256: targetHash,
		Revision:               call.revision,
		Now:                    req.Now,
	})
	if err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	if _, err := h.storeConfirmationIntent(ctx, security.PutConfirmationIntentRequest{
		ConfirmationID:      confirmationID,
		ConfirmationTokenID: result.ConfirmationTokenID,
		PluginID:            call.record.PluginID,
		PluginInstanceID:    call.record.PluginInstanceID,
		SurfaceInstanceID:   req.SurfaceInstanceID,
		BridgeChannelID:     req.BridgeChannelID,
		Method:              call.method.Method,
		RequestHash:         result.RequestHash,
		PlanHash:            result.PlanHash,
		Scope: security.ConfirmationScope{
			ActiveFingerprint:      call.record.ActiveFingerprint,
			OwnerSessionHash:       session.OwnerSessionHash,
			OwnerUserHash:          session.OwnerUserHash,
			OwnerEnvHash:           session.OwnerEnvHash,
			SessionChannelIDHash:   session.SessionChannelIDHash,
			PolicyRevision:         call.record.PolicyRevision,
			ManagementRevision:     call.record.ManagementRevision,
			RevokeEpoch:            call.record.RevokeEpoch,
			TargetDescriptorSHA256: targetHash,
		},
		IssuedAt:  result.IssuedAt,
		ExpiresAt: result.ExpiresAt,
		Now:       req.Now,
	}); err != nil {
		return PrepareMethodConfirmationResult{}, err
	}
	return PrepareMethodConfirmationResult{
		ConfirmationID:      confirmationID,
		ConfirmationTokenID: result.ConfirmationTokenID,
		RequestHash:         result.RequestHash,
		PlanHash:            result.PlanHash,
		Plan:                plan,
		ExpiresAt:           result.ExpiresAt,
	}, nil
}

func (h *Host) RejectMethodConfirmation(ctx context.Context, req RejectMethodConfirmationRequest) (response RejectMethodConfirmationResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	defer func() {
		resultErr = finalizeRPCError(ctx, resultErr)
	}()
	session, err := requireUserSession(ctx)
	if err != nil {
		return RejectMethodConfirmationResult{}, err
	}
	if strings.TrimSpace(req.PluginInstanceID) == "" || strings.TrimSpace(req.SurfaceInstanceID) == "" ||
		strings.TrimSpace(req.BridgeChannelID) == "" || strings.TrimSpace(req.GatewayToken) == "" ||
		strings.TrimSpace(req.ConfirmationID) == "" {
		return RejectMethodConfirmationResult{}, ErrConfirmationInvalid
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return RejectMethodConfirmationResult{}, err
	}
	revision := bridge.RevisionBinding{
		PolicyRevision:     record.PolicyRevision,
		ManagementRevision: record.ManagementRevision,
		RevokeEpoch:        record.RevokeEpoch,
	}
	if _, err := h.surfaceTokens.ValidateSurfaceGatewayToken(bridge.ValidateSurfaceGatewayTokenRequest{
		GatewayToken:         req.GatewayToken,
		PluginInstanceID:     record.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Revision:             revision,
		Now:                  req.Now,
	}); err != nil {
		return RejectMethodConfirmationResult{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.confirmation.rejected", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return RejectMethodConfirmationResult{}, err
	}
	defer func() { resultErr = auditMutation.complete(context.WithoutCancel(ctx), resultErr) }()
	intent, err := h.adapters.ConfirmationIntents.RejectConfirmationIntent(ctx, security.RejectConfirmationIntentRequest{
		ConfirmationID:       req.ConfirmationID,
		PluginInstanceID:     record.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		BridgeChannelID:      req.BridgeChannelID,
		ActiveFingerprint:    record.ActiveFingerprint,
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
		PolicyRevision:       record.PolicyRevision,
		ManagementRevision:   record.ManagementRevision,
		RevokeEpoch:          record.RevokeEpoch,
		Now:                  req.Now,
	})
	err = finalizeRPCError(ctx, err)
	if errors.Is(err, security.ErrInvalidConfirmationIntent) ||
		errors.Is(err, security.ErrConfirmationIntentNotFound) ||
		errors.Is(err, security.ErrConfirmationIntentExpired) ||
		errors.Is(err, security.ErrConfirmationIntentScopeMismatch) {
		return RejectMethodConfirmationResult{}, ErrConfirmationInvalid
	}
	if err != nil {
		return RejectMethodConfirmationResult{}, err
	}
	if reportErr := h.reportMethodRejection(ctx, record, intent.Method, req.SurfaceInstanceID, ErrConfirmationRejected); reportErr != nil {
		return RejectMethodConfirmationResult{Rejected: true}, mutation.Unknown(reportErr)
	}
	return RejectMethodConfirmationResult{Rejected: true}, nil
}

func (h *Host) ListIntents(ctx context.Context, req ListIntentsRequest) ([]IntentRecord, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return nil, err
	}
	records, err := h.adapters.Registry.ListPlugins(ctx)
	if err != nil {
		return nil, err
	}
	var intents []IntentRecord
	for _, record := range records {
		if req.PluginInstanceID != "" && record.PluginInstanceID != req.PluginInstanceID {
			continue
		}
		if record.EnableState != registry.EnableEnabled {
			continue
		}
		if err := h.canRun(ctx, record); err != nil {
			continue
		}
		for _, intent := range record.Manifest.Intents {
			if req.IntentID != "" && intent.IntentID != req.IntentID {
				continue
			}
			method, ok := manifestMethod(record.Manifest, intent.Method)
			if !ok {
				continue
			}
			method, err = h.effectiveMethod(record, method)
			if err != nil {
				continue
			}
			intents = append(intents, IntentRecord{
				PluginID:          record.PluginID,
				PluginInstanceID:  record.PluginInstanceID,
				PublisherID:       record.PublisherID,
				DisplayName:       record.Manifest.Plugin.DisplayName,
				Version:           record.Version,
				ActiveFingerprint: record.ActiveFingerprint,
				IntentID:          intent.IntentID,
				Method:            intent.Method,
				Effect:            method.Effect,
				Execution:         method.Execution,
				PayloadSchema:     cloneParams(intent.PayloadSchema),
			})
		}
	}
	sort.Slice(intents, func(i, j int) bool {
		if intents[i].IntentID == intents[j].IntentID {
			if intents[i].PluginID == intents[j].PluginID {
				return intents[i].PluginInstanceID < intents[j].PluginInstanceID
			}
			return intents[i].PluginID < intents[j].PluginID
		}
		return intents[i].IntentID < intents[j].IntentID
	})
	return intents, nil
}

func (h *Host) InvokeIntent(ctx context.Context, req InvokeIntentRequest) (response CallMethodResult, resultErr error) {
	ctx = withRPCErrorScope(ctx)
	defer func() {
		resultErr = finalizeRPCError(ctx, resultErr)
	}()
	session, err := requireUserSession(ctx)
	if err != nil {
		return CallMethodResult{}, err
	}
	req.session = session
	resolved, err := h.resolveIntent(ctx, req)
	if err != nil {
		return CallMethodResult{}, err
	}
	if methodRequiresConfirmation(resolved.method) {
		if err := h.validateMethodRequest(resolved.record, resolved.method, req.Params); err != nil {
			return CallMethodResult{}, err
		}
		requestHash, hashErr := methodRequestHash(resolved.method, req.Params)
		if hashErr != nil {
			return CallMethodResult{}, hashErr
		}
		return CallMethodResult{
			ConfirmationRequired: true,
			RequestHash:          requestHash,
		}, ErrConfirmationRequired
	}
	callReq := CallMethodRequest{
		PluginInstanceID: resolved.record.PluginInstanceID,
		Method:           resolved.method.Method,
		Params:           cloneParams(req.Params),
		Now:              req.Now,
		session:          session,
	}
	callReq.streamTicketMinter = h.newMethodStreamTicketMinter(bridge.Audience{
		PluginID:             resolved.record.PluginID,
		PluginInstanceID:     resolved.record.PluginInstanceID,
		PluginVersion:        resolved.record.Version,
		ActiveFingerprint:    resolved.record.ActiveFingerprint,
		RouteRole:            bridge.RouteRoleTrustedIntent,
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
	}, resolved.revision, resolved.method.Method, req.Now)
	result, err := h.dispatchMethod(ctx, resolved.record, resolved.method, callReq)
	if err != nil {
		return CallMethodResult{}, err
	}
	if err := h.recordSecurityEvent(ctx, AuditEvent{
		Type:             "plugin.intent.invoked",
		PluginID:         resolved.record.PluginID,
		PluginInstanceID: resolved.record.PluginInstanceID,
		Details: map[string]any{
			"intent_id": req.IntentID,
			"method":    resolved.method.Method,
		},
	}); err != nil {
		return result, mutation.Unknown(err)
	}
	return result, nil
}

type resolvedMethodCall struct {
	record   registry.PluginRecord
	method   manifest.MethodSpec
	audience bridge.Audience
	revision bridge.RevisionBinding
}

type resolvedIntentCall struct {
	record   registry.PluginRecord
	intent   manifest.IntentSpec
	method   manifest.MethodSpec
	revision bridge.RevisionBinding
}

var ErrConfirmationRequired = errors.New("plugin method confirmation required")

const maxPendingConfirmationIntentsPerPlugin = security.DefaultMaxPendingConfirmationIntentsPerPlugin
const runtimeCapabilityRevokeTimeout = 2 * time.Second

func (h *Host) resolveMethodCall(ctx context.Context, req CallMethodRequest) (result resolvedMethodCall, resultErr error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return resolvedMethodCall{}, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = finalizeRPCError(ctx, resultErr)
			resultErr = mergeRPCFailures(ctx, resultErr, h.reportMethodRejectionSafely(ctx, record, req.Method, req.SurfaceInstanceID, resultErr))
		}
	}()
	if record.EnableState != registry.EnableEnabled {
		return resolvedMethodCall{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return resolvedMethodCall{}, err
	}
	method, ok := manifestMethod(record.Manifest, req.Method)
	if !ok {
		return resolvedMethodCall{}, fmt.Errorf("method %q is not declared", req.Method)
	}
	method, err = h.effectiveMethod(record, method)
	if err != nil {
		return resolvedMethodCall{}, err
	}
	revision := bridge.RevisionBinding{
		PolicyRevision:     record.PolicyRevision,
		ManagementRevision: record.ManagementRevision,
		RevokeEpoch:        record.RevokeEpoch,
	}
	token, err := h.surfaceTokens.ValidateSurfaceGatewayToken(bridge.ValidateSurfaceGatewayTokenRequest{
		GatewayToken:         req.GatewayToken,
		PluginInstanceID:     record.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.session.OwnerSessionHash,
		OwnerUserHash:        req.session.OwnerUserHash,
		OwnerEnvHash:         req.session.OwnerEnvHash,
		SessionChannelIDHash: req.session.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Revision:             revision,
		Now:                  req.Now,
	})
	if err != nil {
		return resolvedMethodCall{}, err
	}
	audience := token.Audience
	if err := h.requireSurfaceRuntimeGeneration(ctx, audience.PluginInstanceID, audience.SurfaceInstanceID, audience.RuntimeGenerationID, req.Now); err != nil {
		return resolvedMethodCall{}, err
	}
	decision, err := h.adapters.Policy.EvaluateLocalPolicy(ctx, req.session, pluginRefFromRecord(record), method)
	if err != nil {
		return resolvedMethodCall{}, err
	}
	if decision != PolicyAllow {
		return resolvedMethodCall{}, fmt.Errorf("%w: local policy denied plugin method", security.ErrPolicyDenied)
	}
	requiredPermissions, err := h.requiredPermissionsForMethod(record, method)
	if err != nil {
		return resolvedMethodCall{}, err
	}
	authorization, err := h.adapters.Registry.Authorize(ctx, registry.AuthorizeRequest{
		PluginInstanceID: record.PluginInstanceID,
		Method:           method.Method,
		PermissionIDs:    requiredPermissions,
		Now:              req.Now,
		Expected:         registry.AuthorizationRevisionsFromRecord(record),
	})
	if err != nil {
		return resolvedMethodCall{}, err
	}
	if err := authorizationDecisionError(authorization, method.Method); err != nil {
		return resolvedMethodCall{}, err
	}
	return resolvedMethodCall{record: record, method: method, audience: audience, revision: revision}, nil
}

func (h *Host) resolveIntent(ctx context.Context, req InvokeIntentRequest) (resolvedIntentCall, error) {
	intentID := strings.TrimSpace(req.IntentID)
	if intentID == "" {
		return resolvedIntentCall{}, fmt.Errorf("%w: intent_id is required", ErrMethodRequestContract)
	}
	var candidates []registry.PluginRecord
	if strings.TrimSpace(req.PluginInstanceID) != "" {
		record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
		if err != nil {
			return resolvedIntentCall{}, err
		}
		candidates = []registry.PluginRecord{record}
	} else {
		records, err := h.adapters.Registry.ListPlugins(ctx)
		if err != nil {
			return resolvedIntentCall{}, err
		}
		candidates = records
	}

	var matches []resolvedIntentCall
	for _, record := range candidates {
		if record.EnableState != registry.EnableEnabled {
			continue
		}
		if err := h.canRun(ctx, record); err != nil {
			continue
		}
		intent, ok := manifestIntent(record.Manifest, intentID)
		if !ok {
			continue
		}
		method, ok := manifestMethod(record.Manifest, intent.Method)
		if !ok {
			continue
		}
		effective, effectiveErr := h.effectiveMethod(record, method)
		if effectiveErr != nil {
			continue
		}
		method = effective
		revision := bridge.RevisionBinding{
			PolicyRevision:     record.PolicyRevision,
			ManagementRevision: record.ManagementRevision,
			RevokeEpoch:        record.RevokeEpoch,
		}
		matches = append(matches, resolvedIntentCall{
			record:   record,
			intent:   intent,
			method:   method,
			revision: revision,
		})
	}
	if len(matches) == 0 {
		return resolvedIntentCall{}, fmt.Errorf("%w: intent is not available", ErrMethodRequestContract)
	}
	if len(matches) > 1 && strings.TrimSpace(req.PluginInstanceID) == "" {
		return resolvedIntentCall{}, fmt.Errorf("%w: intent is ambiguous; plugin_instance_id is required", ErrMethodRequestContract)
	}
	resolved := matches[0]
	decision, err := h.adapters.Policy.EvaluateLocalPolicy(ctx, req.session, pluginRefFromRecord(resolved.record), resolved.method)
	if err != nil {
		return resolvedIntentCall{}, err
	}
	if decision != PolicyAllow {
		return resolvedIntentCall{}, errors.New("plugin intent denied by local policy")
	}
	requiredPermissions, err := h.requiredPermissionsForMethod(resolved.record, resolved.method)
	if err != nil {
		return resolvedIntentCall{}, err
	}
	authorization, err := h.adapters.Registry.Authorize(ctx, registry.AuthorizeRequest{
		PluginInstanceID: resolved.record.PluginInstanceID,
		Method:           resolved.method.Method,
		PermissionIDs:    requiredPermissions,
		Now:              req.Now,
		Expected:         registry.AuthorizationRevisionsFromRecord(resolved.record),
	})
	if err != nil {
		return resolvedIntentCall{}, err
	}
	if err := authorizationDecisionError(authorization, resolved.method.Method); err != nil {
		return resolvedIntentCall{}, err
	}
	return resolved, nil
}

func (h *Host) ImportLocalPackage(ctx context.Context, req ImportLocalPackageRequest) (registry.PluginRecord, error) {
	if err := h.enforceUnsignedLocalPluginPolicy(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	if req.PackageReader == nil {
		return registry.PluginRecord{}, errors.New("package reader is required")
	}
	pkg, err := pluginpkg.Read(ctx, req.PackageReader, req.PackageSize, pluginpkg.DefaultReadLimits())
	if err != nil {
		return registry.PluginRecord{}, err
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		pluginInstanceID = defaultPluginInstanceID(pkg)
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, pluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer releaseLifecycle()
	return h.installResolvedPackage(ctx, pkg, pluginInstanceID, packageTrustInput{LocalImport: true}, req.Now, localImportMetadata(req.Now))
}

func (h *Host) InstallReleaseRef(ctx context.Context, req InstallReleaseRefRequest) (registry.PluginRecord, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	pkg, release, sourcePolicy, metadata, err := h.resolveReleasePackage(ctx, PackageTrustActionInstall, req.ReleaseRef, nil, req.PluginInstanceID, req.Now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		pluginInstanceID = defaultPluginInstanceID(pkg)
	}
	unlockLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, pluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer unlockLifecycle()
	releaseRef := req.ReleaseRef
	return h.installResolvedPackage(ctx, pkg, pluginInstanceID, packageTrustInput{
		ReleaseRef:           &releaseRef,
		Release:              &release,
		SourcePolicySnapshot: &sourcePolicy,
	}, req.Now, metadata)
}

func (h *Host) installResolvedPackage(ctx context.Context, pkg pluginpkg.Package, pluginInstanceID string, trustInput packageTrustInput, now time.Time, baseMetadata map[string]string) (result registry.PluginRecord, retErr error) {
	if strings.TrimSpace(pluginInstanceID) == "" {
		pluginInstanceID = defaultPluginInstanceID(pkg)
	}
	if err := h.preflightPackageFeatures(pkg.Manifest, trustInput); err != nil {
		return registry.PluginRecord{}, err
	}
	if existing, err := h.adapters.Registry.GetPlugin(ctx, pluginInstanceID); err == nil {
		return registry.PluginRecord{}, fmt.Errorf("%w: plugin %q is at management revision %d", ErrPluginAlreadyInstalled, pluginInstanceID, existing.ManagementRevision)
	} else if !errors.Is(err, registry.ErrNotFound) {
		return registry.PluginRecord{}, err
	}
	runtimeRequirement, err := runtimeRequirementForPackage(pkg.Manifest, trustInput)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.preflightWorkerRuntime(ctx, registry.PluginRecord{Manifest: pkg.Manifest, RuntimeRequirement: runtimeRequirement}); err != nil {
		return registry.PluginRecord{}, err
	}
	if trustInput.SourcePolicySnapshot != nil {
		if err := h.recordSourceSecurityFloor(ctx, *trustInput.SourcePolicySnapshot, now); err != nil {
			return registry.PluginRecord{}, err
		}
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.installed", PluginID: pkg.Manifest.PluginID(), PluginInstanceID: pluginInstanceID})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	stage, err := h.createInstallStage(ctx, installstage.ActionInstall, pkg, pluginInstanceID, trustInput.stageRequestedTrust(), now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	trustAssessment, err := h.resolvePackageTrust(ctx, PackageTrustActionInstall, pkg, trustInput, nil, pluginInstanceID, now)
	if err != nil {
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "trust_failed", err, now)
	}
	capabilityPins, err := h.resolvePackageCapabilityPins(ctx, pkg.Manifest, trustInput)
	if err != nil {
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "capability_contract_failed", err, now)
	}
	metadata := cloneStringMap(trustAssessment.Metadata)
	metadata = mergeStringMap(baseMetadata, metadata)
	if _, err := h.adapters.InstallStages.MarkPrepared(ctx, installstage.MarkPreparedRequest{
		StageID:       stage.StageID,
		ResolvedTrust: string(trustAssessment.TrustState),
		ValidationSummary: map[string]string{
			"trust": "resolved",
		},
		Now: now,
	}); err != nil {
		return registry.PluginRecord{}, err
	}
	record := packageRecord(pkg, trustAssessment, pluginInstanceID, metadata, capabilityPins)
	record.RuntimeRequirement = runtimeRequirement
	if trustInput.LocalImport {
		record.LocalImportProvenance = localImportProvenance(now)
	}
	if trustInput.SourcePolicySnapshot != nil {
		if err := attachSourcePolicySnapshot(&record, *trustInput.SourcePolicySnapshot); err != nil {
			return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "source_policy_snapshot_failed", err, now)
		}
	}
	record.EnableState = registry.EnableDisabled
	if err := h.adapters.Assets.PutPackage(ctx, pkg); err != nil {
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "asset_store_failed", err, now)
	}
	previous, hadPrevious, err := h.getExistingInstallRecord(ctx, record.PluginInstanceID)
	if err != nil {
		_ = h.adapters.Assets.DeletePackage(ctx, pkg.PackageHash)
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "registry_lookup_failed", err, now)
	}
	stored, err := h.adapters.Registry.PutPlugin(ctx, record, registry.PutOptions{Now: now})
	if err != nil {
		_ = h.adapters.Assets.DeletePackage(ctx, pkg.PackageHash)
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "registry_failed", err, now)
	}
	if _, err := h.adapters.InstallStages.MarkCommitted(ctx, installstage.MarkCommittedRequest{StageID: stage.StageID, Now: now}); err != nil {
		_ = h.rollbackInstallRecord(ctx, previous, hadPrevious, stored.PluginInstanceID, pkg.PackageHash, now)
		h.reportLifecycleDiagnostic(ctx, stored, "plugin.install_stage.commit_failed", err, map[string]any{"stage_id": stage.StageID})
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	return stored, nil
}

func (h *Host) UpdateLocalPackage(ctx context.Context, req UpdateLocalPackageRequest) (registry.PluginRecord, error) {
	if err := h.enforceUnsignedLocalPluginPolicy(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	if req.PackageReader == nil {
		return registry.PluginRecord{}, errors.New("package reader is required")
	}
	pkg, err := pluginpkg.Read(ctx, req.PackageReader, req.PackageSize, pluginpkg.DefaultReadLimits())
	if err != nil {
		return registry.PluginRecord{}, err
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer releaseLifecycle()
	current, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := requireManagementRevision(current, req.ExpectedManagementRevision); err != nil {
		return registry.PluginRecord{}, err
	}
	return h.updateResolvedPackage(ctx, current, pkg, packageTrustInput{LocalImport: true}, req.Now, localImportMetadata(req.Now))
}

func (h *Host) UpdateReleaseRef(ctx context.Context, req UpdateReleaseRefRequest) (registry.PluginRecord, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := requireManagementRevision(current, req.ExpectedManagementRevision); err != nil {
		return registry.PluginRecord{}, err
	}
	pkg, release, sourcePolicy, metadata, err := h.resolveReleasePackage(ctx, PackageTrustActionUpdate, req.ReleaseRef, &current, current.PluginInstanceID, req.Now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	unlockLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer unlockLifecycle()
	current, err = h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := requireManagementRevision(current, req.ExpectedManagementRevision); err != nil {
		return registry.PluginRecord{}, err
	}
	releaseRef := req.ReleaseRef
	return h.updateResolvedPackage(ctx, current, pkg, packageTrustInput{
		ReleaseRef:           &releaseRef,
		Release:              &release,
		SourcePolicySnapshot: &sourcePolicy,
	}, req.Now, metadata)
}

func (h *Host) updateResolvedPackage(ctx context.Context, current registry.PluginRecord, pkg pluginpkg.Package, trustInput packageTrustInput, now time.Time, baseMetadata map[string]string) (result registry.PluginRecord, retErr error) {
	if err := h.preflightPackageFeatures(pkg.Manifest, trustInput); err != nil {
		return registry.PluginRecord{}, err
	}
	runtimeRequirement, err := runtimeRequirementForPackage(pkg.Manifest, trustInput)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.preflightWorkerRuntime(ctx, registry.PluginRecord{Manifest: pkg.Manifest, RuntimeRequirement: runtimeRequirement}); err != nil {
		return registry.PluginRecord{}, err
	}
	if trustInput.SourcePolicySnapshot != nil {
		if err := h.recordSourceSecurityFloor(ctx, *trustInput.SourcePolicySnapshot, now); err != nil {
			return registry.PluginRecord{}, err
		}
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.updated", PluginID: current.PluginID, PluginInstanceID: current.PluginInstanceID})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	stage, err := h.createInstallStage(ctx, installstage.ActionUpdate, pkg, current.PluginInstanceID, trustInput.stageRequestedTrust(), now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	trustAssessment, err := h.resolvePackageTrust(ctx, PackageTrustActionUpdate, pkg, trustInput, &current, current.PluginInstanceID, now)
	if err != nil {
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "trust_failed", err, now)
	}
	capabilityPins, err := h.resolvePackageCapabilityPins(ctx, pkg.Manifest, trustInput)
	if err != nil {
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "capability_contract_failed", err, now)
	}
	metadata := cloneStringMap(trustAssessment.Metadata)
	metadata = mergeStringMap(baseMetadata, metadata)
	next := packageRecord(pkg, trustAssessment, current.PluginInstanceID, metadata, capabilityPins)
	next.RuntimeRequirement = runtimeRequirement
	if trustInput.LocalImport {
		next.LocalImportProvenance = localImportProvenance(now)
	}
	if trustInput.SourcePolicySnapshot != nil {
		if err := attachSourcePolicySnapshot(&next, *trustInput.SourcePolicySnapshot); err != nil {
			return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "source_policy_snapshot_failed", err, now)
		}
	}
	if err := validateSamePluginIdentity(current, next); err != nil {
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "identity_mismatch", err, now)
	}
	if err := requireStablePluginDataShape(current.Manifest, next.Manifest); err != nil {
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "data_contract_changed", err, now)
	}
	if _, err := h.adapters.InstallStages.MarkPrepared(ctx, installstage.MarkPreparedRequest{
		StageID:       stage.StageID,
		ResolvedTrust: string(trustAssessment.TrustState),
		ValidationSummary: map[string]string{
			"trust":   "resolved",
			"version": "switch_prepared",
		},
		Now: now,
	}); err != nil {
		return registry.PluginRecord{}, err
	}
	next.VersionHistory = current.VersionHistory
	next = prepareVersionSwitchRecord(current, next, versionSnapshot(current, now), now)
	if next.EnableState == registry.EnableEnabled {
		if err := h.validateEnabledRuntimeState(ctx, next); err != nil {
			return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "runtime_validation_failed", err, now)
		}
		if err := h.prepareEnabledRuntimeState(ctx, next); err != nil {
			return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "runtime_prepare_failed", err, now)
		}
	}
	if err := h.adapters.Assets.PutPackage(ctx, pkg); err != nil {
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "asset_store_failed", err, now)
	}
	stored, err := h.adapters.Registry.PutPlugin(ctx, next, registry.PutOptions{Now: now})
	if err != nil {
		_ = h.adapters.Assets.DeletePackage(ctx, pkg.PackageHash)
		return registry.PluginRecord{}, h.markInstallStageFailed(ctx, stage.StageID, "registry_failed", err, now)
	}
	if err := h.publishEnabledSurfaces(ctx, stored); err != nil {
		_ = h.rollbackVersionSwitch(ctx, current, pkg.PackageHash, now)
		return registry.PluginRecord{}, mutation.Unknown(h.markInstallStageFailed(ctx, stage.StageID, "runtime_refresh_failed", err, now))
	}
	if err := h.revokePluginRuntimeCapabilities(ctx, stored, now); err != nil {
		_ = h.rollbackVersionSwitch(ctx, current, pkg.PackageHash, now)
		h.reportLifecycleDiagnostic(ctx, stored, "plugin.runtime_capabilities.revoke_failed", err, map[string]any{"stage_id": stage.StageID})
		return registry.PluginRecord{}, mutation.Unknown(h.markInstallStageFailed(ctx, stage.StageID, "runtime_revoke_failed", err, now))
	}
	if _, err := h.adapters.InstallStages.MarkCommitted(ctx, installstage.MarkCommittedRequest{StageID: stage.StageID, Now: now}); err != nil {
		_ = h.rollbackVersionSwitch(ctx, current, pkg.PackageHash, now)
		h.reportLifecycleDiagnostic(ctx, stored, "plugin.install_stage.commit_failed", err, map[string]any{"stage_id": stage.StageID})
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	return stored, nil
}

func (h *Host) resolveReleasePackage(ctx context.Context, action PackageTrustAction, ref PluginReleaseRef, current *registry.PluginRecord, pluginInstanceID string, now time.Time) (pluginpkg.Package, PluginPackageRelease, SourcePolicySnapshot, map[string]string, error) {
	if err := h.requireFeature(FeatureRelease); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if h.adapters.ReleaseSourcePolicy == nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, ErrReleaseSourcePolicyRequired
	}
	if h.adapters.ReleaseArtifactResolver == nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, ErrReleaseArtifactResolverRequired
	}
	if err := validateReleaseRef(ref); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	sourcePolicy, err := h.adapters.ReleaseSourcePolicy.ResolveReleaseSourcePolicy(ctx, ReleaseSourcePolicyRequest{
		Action:           action,
		ReleaseRef:       ref,
		CurrentRecord:    current,
		PluginInstanceID: pluginInstanceID,
		Now:              now,
	})
	if err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	revocationVerification, err := h.validateSourcePolicySnapshot(ctx, ref, sourcePolicy, now)
	if err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := enforceReleaseSourcePolicy(action, current, ref, sourcePolicy); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := h.validateSourceSecurityFloor(ctx, sourcePolicy); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	resolved, err := h.adapters.ReleaseArtifactResolver.ResolveReleaseArtifact(ctx, ReleaseArtifactResolveRequest{
		Action:               action,
		ReleaseRef:           ref,
		SourcePolicySnapshot: sourcePolicy,
		CurrentRecord:        current,
		PluginInstanceID:     pluginInstanceID,
		Now:                  now,
	})
	if err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if resolved.Reader == nil || resolved.Size <= 0 || resolved.Size > maxReleasePackageBytes {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, fmt.Errorf("%w: package artifact size is invalid", ErrReleaseRefVerificationFailed)
	}
	if len(resolved.ReleaseMetadataBytes) == 0 || int64(len(resolved.ReleaseMetadataBytes)) > maxReleaseMetadataBytes {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, fmt.Errorf("%w: release metadata exceeds size limit", ErrReleaseRefVerificationFailed)
	}
	if len(resolved.ReleaseMetadataSignature) == 0 || int64(len(resolved.ReleaseMetadataSignature)) > maxReleaseMetadataSignature {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, fmt.Errorf("%w: release metadata signature exceeds size limit", ErrReleaseRefVerificationFailed)
	}
	expectedArtifactSHA := strings.TrimPrefix(strings.TrimSpace(resolved.ArtifactSHA256), "sha256:")
	if !isLowerHexSHA256(expectedArtifactSHA) {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, fmt.Errorf("%w: package artifact sha256 is required", ErrReleaseRefVerificationFailed)
	}
	hasher := sha256.New()
	if _, err := io.CopyN(hasher, io.NewSectionReader(resolved.Reader, 0, resolved.Size), resolved.Size); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, fmt.Errorf("%w: package artifact read failed: %v", ErrReleaseRefVerificationFailed, err)
	}
	if actual := hex.EncodeToString(hasher.Sum(nil)); actual != expectedArtifactSHA {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, fmt.Errorf("%w: package artifact sha256 mismatch", ErrReleaseRefVerificationFailed)
	}
	release, err := parseSignedReleaseMetadata(ref, resolved.ReleaseMetadataBytes)
	if err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := validateResolvedRelease(ref, release); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	releaseMetadataVerification, err := h.verifyReleaseMetadata(ctx, action, ref, release, sourcePolicy, resolved.ReleaseMetadataBytes, resolved.ReleaseMetadataSignature, current, pluginInstanceID, now)
	if err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	pkg, err := pluginpkg.Read(ctx, resolved.Reader, resolved.Size, pluginpkg.DefaultReadLimits())
	if err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := validateReleasePackage(ref, pkg); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := validateReleaseCompatibility(pkg, release); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := validateReleaseSignature(pkg, release, sourcePolicy, now); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	distribution := release.DistributionRef.Distribution
	metadata := map[string]string{
		"source_id":               ref.SourceID,
		"source.type":             string(sourceTypeOrDefault(sourcePolicy.SourceType, distribution)),
		"source.distribution":     string(distribution),
		"release.artifact_ref":    release.DistributionRef.ArtifactRef,
		"release.metadata_sha256": ref.ReleaseMetadataSHA256,
	}
	if sourcePolicy.SourceClass != "" {
		metadata["source.class"] = string(sourcePolicy.SourceClass)
	}
	if sourcePolicy.RequireSignature {
		metadata["source.require_signature"] = "true"
	}
	if sourcePolicy.InstallPolicy != "" {
		metadata["source.install_policy"] = string(sourcePolicy.InstallPolicy)
	}
	if sourcePolicy.UnsignedPolicy != "" {
		metadata["source.unsigned_policy"] = string(sourcePolicy.UnsignedPolicy)
	}
	if sourcePolicy.DowngradePolicy != "" {
		metadata["source.downgrade_policy"] = string(sourcePolicy.DowngradePolicy)
	}
	if sourcePolicy.PolicyEpoch != "" {
		metadata["source.policy_epoch"] = sourcePolicy.PolicyEpoch
	}
	if sourcePolicy.KeyRotationEpoch != "" {
		metadata["source.key_rotation_epoch"] = sourcePolicy.KeyRotationEpoch
	}
	if sourcePolicy.RevocationEpoch != "" {
		metadata["source.revocation_epoch"] = sourcePolicy.RevocationEpoch
	}
	if sourcePolicy.AssessedAt != "" {
		metadata["source.assessed_at"] = sourcePolicy.AssessedAt
	}
	if release.ReleaseMetadataSignature != nil {
		metadata["release.metadata_signature_algorithm"] = release.ReleaseMetadataSignature.Algorithm
		metadata["release.metadata_signature_key_id"] = release.ReleaseMetadataSignature.KeyID
		metadata["release.metadata_signature_ref"] = release.ReleaseMetadataSignature.SignatureRef
	}
	if release.PackageSignature != nil {
		metadata["release.package_signature_algorithm"] = release.PackageSignature.Algorithm
		metadata["release.package_signature_key_id"] = release.PackageSignature.KeyID
		metadata["release.package_signature_bundle_ref"] = release.PackageSignature.SignatureBundleRef
	}
	metadata["release.metadata_ref"] = ref.ReleaseMetadataRef
	if err := mergePrefixedMetadata(metadata, "release.", release.Metadata); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := mergePrefixedMetadata(metadata, "source.", sourcePolicy.Metadata); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := mergePrefixedMetadata(metadata, "source.revocation_verifier.", revocationVerification); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	if err := mergePrefixedMetadata(metadata, "release.metadata_verifier.", releaseMetadataVerification); err != nil {
		return pluginpkg.Package{}, PluginPackageRelease{}, SourcePolicySnapshot{}, nil, err
	}
	return pkg, release, sourcePolicy, metadata, nil
}

func parseSignedReleaseMetadata(ref PluginReleaseRef, metadataBytes []byte) (PluginPackageRelease, error) {
	if len(metadataBytes) == 0 {
		return PluginPackageRelease{}, fmt.Errorf("%w: release metadata bytes are required", ErrReleaseRefVerificationFailed)
	}
	var envelope signedReleaseMetadata
	decoder := json.NewDecoder(bytes.NewReader(metadataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return PluginPackageRelease{}, fmt.Errorf("%w: release metadata is invalid: %v", ErrReleaseRefVerificationFailed, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PluginPackageRelease{}, fmt.Errorf("%w: release metadata must contain exactly one JSON document", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(envelope.SchemaVersion) != "redevplugin.release_metadata.v5" {
		return PluginPackageRelease{}, fmt.Errorf("%w: release metadata schema_version is invalid", ErrReleaseRefVerificationFailed)
	}
	if envelope.ReleaseMetadataRef != ref.ReleaseMetadataRef {
		return PluginPackageRelease{}, fmt.Errorf("%w: release metadata ref does not match release ref", ErrReleaseRefVerificationFailed)
	}
	return PluginPackageRelease{
		SourceID:                 envelope.SourceID,
		PublisherID:              envelope.PublisherID,
		PluginID:                 envelope.PluginID,
		Version:                  envelope.Version,
		DistributionRef:          envelope.DistributionRef,
		ReleaseMetadataSHA256:    ref.ReleaseMetadataSHA256,
		ReleaseMetadataSignature: envelope.ReleaseMetadataSignature,
		Hashes:                   envelope.Hashes,
		PackageSignature:         envelope.PackageSignature,
		Compatibility:            envelope.Compatibility,
		HostRequirements:         append([]HostRequirement(nil), envelope.HostRequirements...),
		ReleaseEvidence:          envelope.ReleaseEvidence,
		Metadata:                 cloneStringMap(envelope.Metadata),
	}, nil
}

func (h *Host) verifyReleaseMetadata(ctx context.Context, action PackageTrustAction, ref PluginReleaseRef, release PluginPackageRelease, snapshot SourcePolicySnapshot, metadataBytes []byte, signature []byte, current *registry.PluginRecord, pluginInstanceID string, now time.Time) (map[string]string, error) {
	if release.ReleaseMetadataSignature == nil {
		return nil, fmt.Errorf("%w: release metadata signature is required", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(release.ReleaseMetadataSignature.Algorithm) == "" {
		return nil, fmt.Errorf("%w: release metadata signature algorithm is required", ErrReleaseRefVerificationFailed)
	}
	if release.ReleaseMetadataSignature.Algorithm != pluginpkg.PackageSignatureAlgorithmEd25519 {
		return nil, fmt.Errorf("%w: release metadata signature algorithm is unsupported", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(release.ReleaseMetadataSignature.KeyID) == "" {
		return nil, fmt.Errorf("%w: release metadata signature key_id is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := requireTrustedSourceKey(snapshot, release.ReleaseMetadataSignature.KeyID, "release_metadata", now); err != nil {
		return nil, fmt.Errorf("%w: release metadata signature key_id is not trusted by source policy: %v", ErrReleaseRefVerificationFailed, err)
	}
	if err := validateRegistryRelativeArtifactRef(release.ReleaseMetadataSignature.SignatureRef, "release.release_metadata_signature.signature_ref", true); err != nil {
		return nil, err
	}
	if err := validateReleaseSignatureEpochBinding("release metadata signature", release.ReleaseMetadataSignature.SourcePolicyEpoch, release.ReleaseMetadataSignature.RevocationEpoch, snapshot); err != nil {
		return nil, err
	}
	if h.adapters.ReleaseMetadataVerifier == nil {
		return nil, ErrReleaseMetadataVerifierRequired
	}
	if len(metadataBytes) == 0 {
		return nil, fmt.Errorf("%w: release metadata bytes are required", ErrReleaseRefVerificationFailed)
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("%w: release metadata signature bytes are required", ErrReleaseRefVerificationFailed)
	}
	sum := sha256.Sum256(metadataBytes)
	if !hashEqual(hex.EncodeToString(sum[:]), ref.ReleaseMetadataSHA256) {
		return nil, fmt.Errorf("%w: release metadata bytes do not match release ref hash", ErrReleaseRefVerificationFailed)
	}
	result, err := h.adapters.ReleaseMetadataVerifier.VerifyReleaseMetadata(ctx, ReleaseMetadataVerificationRequest{
		Action:                   action,
		ReleaseRef:               ref,
		Release:                  release,
		SourcePolicySnapshot:     snapshot,
		ReleaseMetadataBytes:     append([]byte(nil), metadataBytes...),
		ReleaseMetadataSignature: append([]byte(nil), signature...),
		CurrentRecord:            current,
		PluginInstanceID:         pluginInstanceID,
		Now:                      now,
	})
	if err != nil {
		return nil, err
	}
	return cloneStringMap(result.Metadata), nil
}

func validateReleaseRef(ref PluginReleaseRef) error {
	if strings.TrimSpace(ref.SourceID) == "" {
		return fmt.Errorf("%w: source_id is required", ErrReleaseRefVerificationFailed)
	}
	if err := validateRegistryRelativeArtifactRef(ref.ReleaseMetadataRef, "release_ref.release_metadata_ref", true); err != nil {
		return err
	}
	if err := validateSHA256Hex(ref.ReleaseMetadataSHA256); err != nil {
		return fmt.Errorf("%w: release_ref.release_metadata_sha256 %v", ErrReleaseRefVerificationFailed, err)
	}
	if strings.TrimSpace(ref.PublisherID) == "" {
		return fmt.Errorf("%w: publisher_id is required", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(ref.PluginID) == "" {
		return fmt.Errorf("%w: plugin_id is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := version.ParseSemVer(ref.Version); err != nil {
		return fmt.Errorf("%w: version is invalid: %v", ErrReleaseRefVerificationFailed, err)
	}
	return validateHashSet("release_ref.expected_hashes", ref.ExpectedHashes)
}

func validateResolvedRelease(ref PluginReleaseRef, release PluginPackageRelease) error {
	if release.SourceID != ref.SourceID || release.PublisherID != ref.PublisherID || release.PluginID != ref.PluginID || release.Version != ref.Version {
		return fmt.Errorf("%w: resolved release identity does not match release ref", ErrReleaseRefVerificationFailed)
	}
	if !hashEqual(release.ReleaseMetadataSHA256, ref.ReleaseMetadataSHA256) {
		return fmt.Errorf("%w: resolved release metadata hash does not match release ref", ErrReleaseRefVerificationFailed)
	}
	if err := validateHashSet("release.hashes", release.Hashes); err != nil {
		return err
	}
	if !hashSetsEqual(release.Hashes, ref.ExpectedHashes) {
		return fmt.Errorf("%w: resolved release hashes do not match release ref", ErrReleaseRefVerificationFailed)
	}
	if err := validateReleaseDistributionRef(release.DistributionRef); err != nil {
		return err
	}
	return validateReleaseHostRequirements(release.HostRequirements)
}

func (h *Host) validateSourcePolicySnapshot(ctx context.Context, ref PluginReleaseRef, snapshot SourcePolicySnapshot, now time.Time) (map[string]string, error) {
	if err := validateSourcePolicySnapshotStructure(ref, snapshot, now); err != nil {
		return nil, err
	}
	return h.verifySourceRevocationEvidence(ctx, ref, snapshot, now)
}

func validateSourcePolicySnapshotStructure(ref PluginReleaseRef, snapshot SourcePolicySnapshot, now time.Time) error {
	if snapshot.SchemaVersion != "redevplugin.source_policy.v1" {
		return fmt.Errorf("%w: source policy schema_version is invalid", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(snapshot.SourceID) == "" {
		return fmt.Errorf("%w: source policy source_id is required", ErrReleaseRefVerificationFailed)
	}
	if snapshot.SourceID != ref.SourceID {
		return fmt.Errorf("%w: source policy source_id does not match release ref", ErrReleaseRefVerificationFailed)
	}
	switch snapshot.SourceType {
	case PackageSourceRegistry, PackageSourceHostArtifact:
	default:
		return fmt.Errorf("%w: source policy source_type is invalid", ErrReleaseRefVerificationFailed)
	}
	switch snapshot.SourceClass {
	case PackageSourceClassOfficial, PackageSourceClassCurated, PackageSourceClassCommunity, PackageSourceClassPrivate:
	default:
		return fmt.Errorf("%w: source policy source_class is invalid", ErrReleaseRefVerificationFailed)
	}
	switch snapshot.InstallPolicy {
	case PackageInstallAllow, PackageInstallReviewRequired, PackageInstallBlock:
	default:
		return fmt.Errorf("%w: source policy install_policy is invalid", ErrReleaseRefVerificationFailed)
	}
	if !snapshot.RequireSignature {
		return fmt.Errorf("%w: release-ref source policy require_signature must be true", ErrReleaseRefVerificationFailed)
	}
	if snapshot.UnsignedPolicy != PackageUnsignedBlock {
		return fmt.Errorf("%w: source policy unsigned_policy is invalid", ErrReleaseRefVerificationFailed)
	}
	switch snapshot.DowngradePolicy {
	case PackageDowngradeBlock, PackageDowngradeReviewRequired:
	default:
		return fmt.Errorf("%w: source policy downgrade_policy is invalid", ErrReleaseRefVerificationFailed)
	}
	for _, publisher := range snapshot.AllowedPublishers {
		if strings.TrimSpace(publisher) == "" {
			return fmt.Errorf("%w: source policy allowed_publishers contains an empty publisher", ErrReleaseRefVerificationFailed)
		}
	}
	seenArtifactHosts := map[string]struct{}{}
	for _, artifactHost := range snapshot.AllowedArtifactHosts {
		normalized := strings.ToLower(strings.TrimSpace(artifactHost))
		if normalized == "" || strings.ContainsAny(normalized, "/:@?#") || strings.HasPrefix(normalized, ".") || strings.HasSuffix(normalized, ".") {
			return fmt.Errorf("%w: source policy allowed_artifact_hosts contains an invalid host", ErrReleaseRefVerificationFailed)
		}
		if _, duplicate := seenArtifactHosts[normalized]; duplicate {
			return fmt.Errorf("%w: source policy allowed_artifact_hosts contains a duplicate host", ErrReleaseRefVerificationFailed)
		}
		seenArtifactHosts[normalized] = struct{}{}
	}
	if len(snapshot.TrustedKeyIDs) == 0 {
		return fmt.Errorf("%w: source policy trusted_key_ids are required", ErrReleaseRefVerificationFailed)
	}
	for _, keyID := range snapshot.TrustedKeyIDs {
		if strings.TrimSpace(keyID) == "" {
			return fmt.Errorf("%w: source policy trusted_key_ids contains an empty key id", ErrReleaseRefVerificationFailed)
		}
	}
	if len(snapshot.AllowedPublishers) == 0 {
		return fmt.Errorf("%w: source policy allowed_publishers are required", ErrReleaseRefVerificationFailed)
	}
	if !stringSliceContains(snapshot.AllowedPublishers, ref.PublisherID) {
		return fmt.Errorf("%w: source policy does not allow publisher", ErrReleaseRefVerificationFailed)
	}
	if len(snapshot.TrustedKeys) == 0 {
		return fmt.Errorf("%w: source policy trusted_keys are required", ErrReleaseRefVerificationFailed)
	}
	if err := validateTrustedSourceKeys(snapshot, now); err != nil {
		return err
	}
	if err := validateRevocationEvidence(snapshot, now); err != nil {
		return err
	}
	for _, value := range []struct {
		name  string
		value string
	}{
		{name: "policy_epoch", value: snapshot.PolicyEpoch},
		{name: "key_rotation_epoch", value: snapshot.KeyRotationEpoch},
		{name: "revocation_epoch", value: snapshot.RevocationEpoch},
	} {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%w: source policy %s is required", ErrReleaseRefVerificationFailed, value.name)
		}
		if _, err := parseSourcePolicyEpoch(value.value); err != nil {
			return fmt.Errorf("%w: source policy %s must be a decimal monotonic epoch", ErrReleaseRefVerificationFailed, value.name)
		}
	}
	if strings.TrimSpace(snapshot.AssessedAt) == "" {
		return fmt.Errorf("%w: source policy assessed_at is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := time.Parse(time.RFC3339, snapshot.AssessedAt); err != nil {
		return fmt.Errorf("%w: source policy assessed_at is invalid", ErrReleaseRefVerificationFailed)
	}
	return nil
}

func (h *Host) verifySourceRevocationEvidence(ctx context.Context, ref PluginReleaseRef, snapshot SourcePolicySnapshot, now time.Time) (map[string]string, error) {
	if snapshot.RevocationEvidence == nil {
		return nil, fmt.Errorf("%w: source policy revocation_evidence is required", ErrReleaseRefVerificationFailed)
	}
	evidence := *snapshot.RevocationEvidence
	metadata, err := parseSourceRevocationMetadata(ref, evidence.MetadataBytes)
	if err != nil {
		return nil, err
	}
	if metadata.SourceID != snapshot.SourceID {
		return nil, fmt.Errorf("%w: source revocation metadata source_id does not match source policy", ErrReleaseRefVerificationFailed)
	}
	if metadata.HighestSeenEpoch != snapshot.RevocationEpoch || metadata.HighestSeenEpoch != evidence.HighestSeenEpoch {
		return nil, fmt.Errorf("%w: source revocation metadata highest_seen_epoch does not match source policy", ErrReleaseRefVerificationFailed)
	}
	if stringSliceContains(metadata.RevokedKeyIDs, evidence.SignatureKeyID) {
		return nil, fmt.Errorf("%w: source revocation evidence signature key is revoked", ErrReleaseRefVerificationFailed)
	}
	if metadata.ExpiresAt != evidence.ExpiresAt {
		return nil, fmt.Errorf("%w: source revocation metadata expires_at does not match source policy evidence", ErrReleaseRefVerificationFailed)
	}
	if len(evidence.SignatureBytes) == 0 {
		return nil, fmt.Errorf("%w: source revocation evidence signature bytes are required", ErrReleaseRefVerificationFailed)
	}
	verifier := h.adapters.RevocationVerifier
	if verifier == nil {
		if combined, ok := h.adapters.ReleaseMetadataVerifier.(SourceRevocationEvidenceVerifier); ok {
			verifier = combined
		}
	}
	if verifier == nil {
		return nil, ErrSourceRevocationVerifierRequired
	}
	result, err := verifier.VerifySourceRevocationEvidence(ctx, SourceRevocationEvidenceVerificationRequest{
		ReleaseRef:                  ref,
		SourcePolicySnapshot:        snapshot,
		RevocationEvidence:          evidence,
		RevocationMetadata:          metadata,
		RevocationMetadataBytes:     append([]byte(nil), evidence.MetadataBytes...),
		RevocationMetadataSignature: append([]byte(nil), evidence.SignatureBytes...),
		Now:                         now,
	})
	if err != nil {
		return nil, err
	}
	return cloneStringMap(result.Metadata), nil
}

func parseSourceRevocationMetadata(ref PluginReleaseRef, metadataBytes []byte) (SourceRevocationMetadata, error) {
	if len(metadataBytes) == 0 {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata bytes are required", ErrReleaseRefVerificationFailed)
	}
	var metadata SourceRevocationMetadata
	decoder := json.NewDecoder(bytes.NewReader(metadataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata is invalid: %v", ErrReleaseRefVerificationFailed, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata must contain exactly one JSON document", ErrReleaseRefVerificationFailed)
	}
	if metadata.SchemaVersion != "redevplugin.source_revocations.v1" {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata schema_version is invalid", ErrReleaseRefVerificationFailed)
	}
	if metadata.SourceID != ref.SourceID {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata source_id does not match release ref", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(metadata.HighestSeenEpoch) == "" {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata highest_seen_epoch is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := parseSourcePolicyEpoch(metadata.HighestSeenEpoch); err != nil {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata highest_seen_epoch must be a decimal monotonic epoch", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(metadata.GeneratedAt) == "" {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata generated_at is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := time.Parse(time.RFC3339, metadata.GeneratedAt); err != nil {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata generated_at is invalid", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(metadata.ExpiresAt) == "" {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata expires_at is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := time.Parse(time.RFC3339, metadata.ExpiresAt); err != nil {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata expires_at is invalid", ErrReleaseRefVerificationFailed)
	}
	for _, keyID := range metadata.RevokedKeyIDs {
		if strings.TrimSpace(keyID) == "" {
			return SourceRevocationMetadata{}, fmt.Errorf("%w: source revocation metadata revoked_key_ids contains an empty key id", ErrReleaseRefVerificationFailed)
		}
	}
	return metadata, nil
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func sourcePolicyRevocationMetadata(snapshot SourcePolicySnapshot) (SourceRevocationMetadata, error) {
	if snapshot.RevocationEvidence == nil {
		return SourceRevocationMetadata{}, fmt.Errorf("%w: source policy revocation_evidence is required", ErrReleaseRefVerificationFailed)
	}
	return parseSourceRevocationMetadata(PluginReleaseRef{SourceID: snapshot.SourceID}, snapshot.RevocationEvidence.MetadataBytes)
}

func validateTrustedSourceKeys(snapshot SourcePolicySnapshot, now time.Time) error {
	seen := map[string]bool{}
	trustedIDSet := map[string]bool{}
	for _, keyID := range snapshot.TrustedKeyIDs {
		trustedIDSet[keyID] = true
	}
	for _, key := range snapshot.TrustedKeys {
		if strings.TrimSpace(key.KeyID) == "" {
			return fmt.Errorf("%w: source policy trusted_keys contains an empty key_id", ErrReleaseRefVerificationFailed)
		}
		if seen[key.KeyID] {
			return fmt.Errorf("%w: source policy trusted_keys contains duplicate key_id", ErrReleaseRefVerificationFailed)
		}
		seen[key.KeyID] = true
		if len(trustedIDSet) > 0 && !trustedIDSet[key.KeyID] {
			return fmt.Errorf("%w: source policy trusted_key_ids does not include trusted_keys entry", ErrReleaseRefVerificationFailed)
		}
		if strings.TrimSpace(key.Algorithm) == "" {
			return fmt.Errorf("%w: source policy trusted key algorithm is required", ErrReleaseRefVerificationFailed)
		}
		if key.Algorithm != pluginpkg.PackageSignatureAlgorithmEd25519 {
			return fmt.Errorf("%w: source policy trusted key algorithm is unsupported", ErrReleaseRefVerificationFailed)
		}
		if err := validateSHA256Hex(key.PublicKeySHA256); err != nil {
			return fmt.Errorf("%w: source policy trusted key public_key_sha256 %v", ErrReleaseRefVerificationFailed, err)
		}
		if len(key.Usage) == 0 {
			return fmt.Errorf("%w: source policy trusted key usage is required", ErrReleaseRefVerificationFailed)
		}
		for _, usage := range key.Usage {
			switch usage {
			case "release_metadata", "package_signature", "revocation_metadata", "host_capability_contract":
			default:
				return fmt.Errorf("%w: source policy trusted key usage %q is invalid", ErrReleaseRefVerificationFailed, usage)
			}
		}
		if stringSliceContains(key.Usage, "host_capability_contract") {
			if len(key.AllowedCapabilityPublishers) == 0 {
				return fmt.Errorf("%w: source policy host capability signing key requires allowed_capability_publishers", ErrReleaseRefVerificationFailed)
			}
			seenPublishers := map[string]struct{}{}
			for _, publisher := range key.AllowedCapabilityPublishers {
				publisher = strings.TrimSpace(publisher)
				if publisher == "" {
					return fmt.Errorf("%w: source policy allowed_capability_publishers contains an empty publisher", ErrReleaseRefVerificationFailed)
				}
				if _, duplicate := seenPublishers[publisher]; duplicate {
					return fmt.Errorf("%w: source policy allowed_capability_publishers contains a duplicate publisher", ErrReleaseRefVerificationFailed)
				}
				seenPublishers[publisher] = struct{}{}
			}
		}
		if strings.TrimSpace(key.RevocationEpoch) == "" {
			return fmt.Errorf("%w: source policy trusted key revocation_epoch is required", ErrReleaseRefVerificationFailed)
		}
		if key.RevocationEpoch != snapshot.RevocationEpoch {
			return fmt.Errorf("%w: source policy trusted key revocation_epoch does not match source policy", ErrReleaseRefVerificationFailed)
		}
		if err := validateSourceKeyValidity(key, now); err != nil {
			return err
		}
	}
	for _, keyID := range snapshot.TrustedKeyIDs {
		if !seen[keyID] {
			return fmt.Errorf("%w: source policy trusted_key_ids contains key absent from trusted_keys", ErrReleaseRefVerificationFailed)
		}
	}
	return nil
}

func validateSourceKeyValidity(key SourcePolicyTrustedKey, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(key.ValidFrom) != "" {
		validFrom, err := time.Parse(time.RFC3339, key.ValidFrom)
		if err != nil {
			return fmt.Errorf("%w: source policy trusted key valid_from is invalid", ErrReleaseRefVerificationFailed)
		}
		if now.Before(validFrom) {
			return fmt.Errorf("%w: source policy trusted key is not valid yet", ErrReleaseRefVerificationFailed)
		}
	}
	if strings.TrimSpace(key.ValidUntil) == "" {
		return fmt.Errorf("%w: source policy trusted key valid_until is required", ErrReleaseRefVerificationFailed)
	}
	validUntil, err := time.Parse(time.RFC3339, key.ValidUntil)
	if err != nil {
		return fmt.Errorf("%w: source policy trusted key valid_until is invalid", ErrReleaseRefVerificationFailed)
	}
	if !now.Before(validUntil) {
		return fmt.Errorf("%w: source policy trusted key is expired", ErrReleaseRefVerificationFailed)
	}
	return nil
}

func validateRevocationEvidence(snapshot SourcePolicySnapshot, now time.Time) error {
	evidence := snapshot.RevocationEvidence
	if evidence == nil {
		return fmt.Errorf("%w: source policy revocation_evidence is required", ErrReleaseRefVerificationFailed)
	}
	if err := validateRegistryRelativeArtifactRef(evidence.MetadataRef, "source_policy.revocation_evidence.metadata_ref", true); err != nil {
		return err
	}
	if err := validateSHA256Hex(evidence.MetadataSHA256); err != nil {
		return fmt.Errorf("%w: source policy revocation_evidence.metadata_sha256 %v", ErrReleaseRefVerificationFailed, err)
	}
	if len(evidence.MetadataBytes) == 0 {
		return fmt.Errorf("%w: source policy revocation_evidence metadata bytes are required", ErrReleaseRefVerificationFailed)
	}
	metadataSum := sha256.Sum256(evidence.MetadataBytes)
	if !hashEqual(hex.EncodeToString(metadataSum[:]), evidence.MetadataSHA256) {
		return fmt.Errorf("%w: source policy revocation_evidence metadata bytes do not match metadata_sha256", ErrReleaseRefVerificationFailed)
	}
	if err := validateRegistryRelativeArtifactRef(evidence.SignatureRef, "source_policy.revocation_evidence.signature_ref", true); err != nil {
		return err
	}
	if len(evidence.SignatureBytes) == 0 {
		return fmt.Errorf("%w: source policy revocation_evidence signature bytes are required", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(evidence.SignatureKeyID) == "" {
		return fmt.Errorf("%w: source policy revocation_evidence.signature_key_id is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := requireTrustedSourceKey(snapshot, evidence.SignatureKeyID, "revocation_metadata", now); err != nil {
		return fmt.Errorf("%w: source policy revocation evidence signature key is invalid: %v", ErrReleaseRefVerificationFailed, err)
	}
	if strings.TrimSpace(evidence.HighestSeenEpoch) == "" {
		return fmt.Errorf("%w: source policy revocation_evidence.highest_seen_epoch is required", ErrReleaseRefVerificationFailed)
	}
	if evidence.HighestSeenEpoch != snapshot.RevocationEpoch {
		return fmt.Errorf("%w: source policy revocation evidence highest_seen_epoch does not match revocation_epoch", ErrReleaseRefVerificationFailed)
	}
	for _, value := range []struct {
		name  string
		value string
	}{
		{name: "verified_at", value: evidence.VerifiedAt},
		{name: "expires_at", value: evidence.ExpiresAt},
	} {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%w: source policy revocation_evidence.%s is required", ErrReleaseRefVerificationFailed, value.name)
		}
		if _, err := time.Parse(time.RFC3339, value.value); err != nil {
			return fmt.Errorf("%w: source policy revocation_evidence.%s is invalid", ErrReleaseRefVerificationFailed, value.name)
		}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt, _ := time.Parse(time.RFC3339, evidence.ExpiresAt)
	if !now.Before(expiresAt) {
		return fmt.Errorf("%w: source policy revocation_evidence is expired", ErrReleaseRefVerificationFailed)
	}
	return nil
}

func requireTrustedSourceKey(snapshot SourcePolicySnapshot, keyID string, usage string, now time.Time) (SourcePolicyTrustedKey, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return SourcePolicyTrustedKey{}, errors.New("key_id is required")
	}
	for _, key := range snapshot.TrustedKeys {
		if key.KeyID != keyID {
			continue
		}
		if err := validateSourceKeyValidity(key, now); err != nil {
			return SourcePolicyTrustedKey{}, err
		}
		if !stringSliceContains(key.Usage, usage) {
			return SourcePolicyTrustedKey{}, fmt.Errorf("key %q is not allowed for %s", keyID, usage)
		}
		metadata, err := sourcePolicyRevocationMetadata(snapshot)
		if err != nil {
			return SourcePolicyTrustedKey{}, err
		}
		if stringSliceContains(metadata.RevokedKeyIDs, keyID) {
			return SourcePolicyTrustedKey{}, fmt.Errorf("key %q is revoked by source revocation metadata", keyID)
		}
		return key, nil
	}
	return SourcePolicyTrustedKey{}, fmt.Errorf("key %q is not trusted", keyID)
}

func validateReleaseDistributionRef(distributionRef PackageDistributionRef) error {
	distribution := distributionRef.Distribution
	if strings.TrimSpace(string(distribution)) == "" {
		return fmt.Errorf("%w: distribution_ref.distribution is required", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(distributionRef.ImportID) != "" {
		return fmt.Errorf("%w: distribution_ref.import_id is not allowed in release metadata", ErrReleaseRefVerificationFailed)
	}
	switch distribution {
	case PackageDistributionRegistryRef:
		if err := validateRegistryRelativeArtifactRef(distributionRef.ArtifactRef, "distribution_ref.artifact_ref", true); err != nil {
			return err
		}
		return nil
	case PackageDistributionHostArtifactRef:
		if err := validateRegistryRelativeArtifactRef(distributionRef.ArtifactRef, "distribution_ref.artifact_ref", true); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("%w: distribution_ref.distribution is invalid", ErrReleaseRefVerificationFailed)
	}
}

func validateReleaseHostRequirements(requirements []HostRequirement) error {
	seenHosts := make(map[string]struct{}, len(requirements))
	for hostIndex, requirement := range requirements {
		prefix := fmt.Sprintf("host_requirements[%d]", hostIndex)
		hostID := strings.TrimSpace(requirement.HostID)
		if hostID == "" {
			return fmt.Errorf("%w: %s.host_id is required", ErrReleaseRefVerificationFailed, prefix)
		}
		if _, exists := seenHosts[hostID]; exists {
			return fmt.Errorf("%w: %s.host_id is duplicated", ErrReleaseRefVerificationFailed, prefix)
		}
		seenHosts[hostID] = struct{}{}
		if requirement.MinHostVersion != "" {
			if _, err := version.ParseSemVer(requirement.MinHostVersion); err != nil {
				return fmt.Errorf("%w: %s.min_host_version is invalid: %v", ErrReleaseRefVerificationFailed, prefix, err)
			}
		}
		seenContracts := make(map[string]struct{}, len(requirement.RequiredCapabilityContracts))
		for contractIndex, contract := range requirement.RequiredCapabilityContracts {
			contractPrefix := fmt.Sprintf("%s.required_capability_contracts[%d]", prefix, contractIndex)
			if strings.TrimSpace(contract.CapabilityID) == "" {
				return fmt.Errorf("%w: %s.capability_id is required", ErrReleaseRefVerificationFailed, contractPrefix)
			}
			if _, err := version.ParseSemVer(contract.CapabilityVersion); err != nil {
				return fmt.Errorf("%w: %s.capability_version is invalid: %v", ErrReleaseRefVerificationFailed, contractPrefix, err)
			}
			contractRef := contract.Contract
			if strings.TrimSpace(contractRef.PublisherID) == "" {
				return fmt.Errorf("%w: %s.contract.publisher_id is required", ErrReleaseRefVerificationFailed, contractPrefix)
			}
			if strings.TrimSpace(contractRef.ContractID) == "" {
				return fmt.Errorf("%w: %s.contract_id is required", ErrReleaseRefVerificationFailed, contractPrefix)
			}
			if _, err := version.ParseSemVer(contractRef.ContractVersion); err != nil {
				return fmt.Errorf("%w: %s.contract_version is invalid: %v", ErrReleaseRefVerificationFailed, contractPrefix, err)
			}
			contractKey := contract.CapabilityID + "\x00" + contract.CapabilityVersion + "\x00" + contractRef.ContractID + "\x00" + contractRef.ContractVersion
			if _, exists := seenContracts[contractKey]; exists {
				return fmt.Errorf("%w: %s contains a duplicate capability contract", ErrReleaseRefVerificationFailed, contractPrefix)
			}
			seenContracts[contractKey] = struct{}{}
			if err := validateRegistryRelativeArtifactRef(contractRef.ArtifactRef, contractPrefix+".contract.artifact_ref", true); err != nil {
				return err
			}
			if err := validateRegistryRelativeArtifactRef(contractRef.ManifestRef, contractPrefix+".contract.manifest_ref", true); err != nil {
				return err
			}
			if err := validateRegistryRelativeArtifactRef(contractRef.SignatureRef, contractPrefix+".contract.signature_ref", true); err != nil {
				return err
			}
			if err := validateRegistryRelativeArtifactRef(contractRef.CompatibilityRef, contractPrefix+".contract.compatibility_ref", true); err != nil {
				return err
			}
			if err := validateRegistryRelativeArtifactRef(contractRef.GeneratedClientRef, contractPrefix+".contract.generated_client_ref", true); err != nil {
				return err
			}
			if err := validateRegistryRelativeArtifactRef(contractRef.NoticesRef, contractPrefix+".contract.notices_ref", true); err != nil {
				return err
			}
			if strings.TrimSpace(contractRef.SignatureKeyID) == "" {
				return fmt.Errorf("%w: %s.contract.signature_key_id is required", ErrReleaseRefVerificationFailed, contractPrefix)
			}
			if strings.TrimSpace(contractRef.SignaturePolicyEpoch) == "" || strings.TrimSpace(contractRef.SignatureRevocationEpoch) == "" {
				return fmt.Errorf("%w: %s.contract signature epochs are required", ErrReleaseRefVerificationFailed, contractPrefix)
			}
			for _, field := range []struct {
				name  string
				value string
			}{
				{name: "artifact_sha256", value: contractRef.ArtifactSHA256},
				{name: "manifest_sha256", value: contractRef.ManifestSHA256},
				{name: "signature_sha256", value: contractRef.SignatureSHA256},
				{name: "compatibility_sha256", value: contractRef.CompatibilitySHA256},
				{name: "generated_client_sha256", value: contractRef.GeneratedClientSHA256},
				{name: "notices_sha256", value: contractRef.NoticesSHA256},
			} {
				if err := validateSHA256Hex(field.value); err != nil {
					return fmt.Errorf("%w: %s.contract.%s %v", ErrReleaseRefVerificationFailed, contractPrefix, field.name, err)
				}
			}
		}
	}
	return nil
}

func validateReleasePackage(ref PluginReleaseRef, pkg pluginpkg.Package) error {
	if pkg.Manifest.Publisher.PublisherID != ref.PublisherID || pkg.Manifest.PluginID() != ref.PluginID || pkg.Manifest.Version() != ref.Version {
		return fmt.Errorf("%w: package identity does not match release ref", ErrReleaseRefVerificationFailed)
	}
	if !hashEqual(pkg.PackageHash, ref.ExpectedHashes.PackageSHA256) || !hashEqual(pkg.ManifestHash, ref.ExpectedHashes.ManifestSHA256) || !hashEqual(pkg.EntriesHash, ref.ExpectedHashes.EntriesSHA256) {
		return fmt.Errorf("%w: package hashes do not match release ref", ErrReleaseRefVerificationFailed)
	}
	return nil
}

func validateReleaseCompatibility(pkg pluginpkg.Package, release PluginPackageRelease) error {
	if release.Compatibility == nil {
		return fmt.Errorf("%w: release compatibility is required", ErrReleaseRefVerificationFailed)
	}
	compatibility := release.Compatibility
	minimumReDevPluginVersion, err := version.ParseSemVer(compatibility.MinReDevPluginVersion)
	if err != nil {
		return fmt.Errorf("%w: release compatibility min_redevplugin_version is invalid: %v", ErrReleaseRefVerificationFailed, err)
	}
	if _, err := version.ParseSemVer(compatibility.MinRuntimeVersion); err != nil {
		return fmt.Errorf("%w: release compatibility min_runtime_version is invalid: %v", ErrReleaseRefVerificationFailed, err)
	}
	if strings.TrimSpace(compatibility.UIProtocolVersion) == "" {
		return fmt.Errorf("%w: release compatibility ui_protocol_version is required", ErrReleaseRefVerificationFailed)
	}
	if compatibility.MinRuntimeVersion != pkg.Manifest.Plugin.MinRuntimeVersion {
		return fmt.Errorf("%w: release compatibility min_runtime_version does not match package manifest", ErrReleaseRefVerificationFailed)
	}
	if compatibility.UIProtocolVersion != pkg.Manifest.Plugin.UIProtocolVersion {
		return fmt.Errorf("%w: release compatibility ui_protocol_version does not match package manifest", ErrReleaseRefVerificationFailed)
	}
	currentReDevPluginVersion, err := version.ParseSemVer(version.CurrentCompatibilityVersion())
	if err != nil {
		return fmt.Errorf("%w: current redevplugin version is invalid: %v", ErrReleaseRefVerificationFailed, err)
	}
	if currentReDevPluginVersion.Compare(minimumReDevPluginVersion) < 0 {
		return fmt.Errorf("%w: release requires newer redevplugin go version", ErrReleaseRefVerificationFailed)
	}
	seenTargets := make(map[string]struct{}, len(compatibility.SupportedTargets))
	for _, value := range compatibility.SupportedTargets {
		target, err := parseRuntimeTarget(value)
		if err != nil || runtimeTargetString(target) != value {
			return fmt.Errorf("%w: release compatibility supported target %q is invalid", ErrReleaseRefVerificationFailed, value)
		}
		if _, exists := seenTargets[value]; exists {
			return fmt.Errorf("%w: release compatibility supported target %q is duplicated", ErrReleaseRefVerificationFailed, value)
		}
		seenTargets[value] = struct{}{}
	}
	return nil
}

func enforceReleaseSourcePolicy(action PackageTrustAction, current *registry.PluginRecord, ref PluginReleaseRef, snapshot SourcePolicySnapshot) error {
	nextVersion, err := version.ParseSemVer(ref.Version)
	if err != nil {
		return fmt.Errorf("%w: release version is invalid: %v", ErrReleaseRefVerificationFailed, err)
	}
	if snapshot.InstallPolicy == PackageInstallBlock || snapshot.InstallPolicy == PackageInstallReviewRequired {
		return fmt.Errorf("%w: source policy install_policy is %s", ErrReleaseRefPolicyDenied, snapshot.InstallPolicy)
	}
	if action == PackageTrustActionUpdate && current != nil {
		currentVersion, err := version.ParseSemVer(current.Version)
		if err != nil {
			return fmt.Errorf("%w: installed plugin version is invalid: %v", ErrReleaseRefVerificationFailed, err)
		}
		if nextVersion.Compare(currentVersion) < 0 &&
			(snapshot.DowngradePolicy == PackageDowngradeBlock || snapshot.DowngradePolicy == PackageDowngradeReviewRequired) {
			return fmt.Errorf("%w: source policy downgrade_policy is %s", ErrReleaseRefPolicyDenied, snapshot.DowngradePolicy)
		}
	}
	return nil
}

func validateReleaseSignature(pkg pluginpkg.Package, release PluginPackageRelease, snapshot SourcePolicySnapshot, now time.Time) error {
	if release.ReleaseMetadataSignature == nil {
		return fmt.Errorf("%w: release metadata signature is required", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(release.ReleaseMetadataSignature.Algorithm) == "" {
		return fmt.Errorf("%w: release metadata signature algorithm is required", ErrReleaseRefVerificationFailed)
	}
	if release.ReleaseMetadataSignature.Algorithm != pluginpkg.PackageSignatureAlgorithmEd25519 {
		return fmt.Errorf("%w: release metadata signature algorithm is unsupported", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(release.ReleaseMetadataSignature.KeyID) == "" {
		return fmt.Errorf("%w: release metadata signature key_id is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := requireTrustedSourceKey(snapshot, release.ReleaseMetadataSignature.KeyID, "release_metadata", now); err != nil {
		return fmt.Errorf("%w: release metadata signature key_id is not trusted by source policy: %v", ErrReleaseRefVerificationFailed, err)
	}
	if err := validateRegistryRelativeArtifactRef(release.ReleaseMetadataSignature.SignatureRef, "release.release_metadata_signature.signature_ref", true); err != nil {
		return err
	}
	if err := validateReleaseSignatureEpochBinding("release metadata signature", release.ReleaseMetadataSignature.SourcePolicyEpoch, release.ReleaseMetadataSignature.RevocationEpoch, snapshot); err != nil {
		return err
	}
	if release.PackageSignature == nil {
		return fmt.Errorf("%w: package signature metadata is required", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(release.PackageSignature.Algorithm) == "" {
		return fmt.Errorf("%w: package signature algorithm is required", ErrReleaseRefVerificationFailed)
	}
	if release.PackageSignature.Algorithm != pluginpkg.PackageSignatureAlgorithmEd25519 {
		return fmt.Errorf("%w: package signature algorithm is unsupported", ErrReleaseRefVerificationFailed)
	}
	if strings.TrimSpace(release.PackageSignature.KeyID) == "" {
		return fmt.Errorf("%w: package signature key_id is required", ErrReleaseRefVerificationFailed)
	}
	if _, err := requireTrustedSourceKey(snapshot, release.PackageSignature.KeyID, "package_signature", now); err != nil {
		return fmt.Errorf("%w: package signature key_id is not trusted by source policy: %v", ErrReleaseRefVerificationFailed, err)
	}
	if err := validateRegistryRelativeArtifactRef(release.PackageSignature.SignatureBundleRef, "release.package_signature.signature_bundle_ref", true); err != nil {
		return err
	}
	if err := validateReleaseSignatureEpochBinding("package signature", release.PackageSignature.SourcePolicyEpoch, release.PackageSignature.RevocationEpoch, snapshot); err != nil {
		return err
	}
	if pkg.PackageSignature == nil {
		return fmt.Errorf("%w: package signature is required", ErrReleaseRefVerificationFailed)
	}
	if pkg.PackageSignature.Algorithm != release.PackageSignature.Algorithm || pkg.PackageSignature.KeyID != release.PackageSignature.KeyID {
		return fmt.Errorf("%w: package signature does not match release package signature metadata", ErrReleaseRefVerificationFailed)
	}
	return nil
}

func validateReleaseSignatureEpochBinding(label string, sourcePolicyEpoch string, revocationEpoch string, snapshot SourcePolicySnapshot) error {
	if strings.TrimSpace(sourcePolicyEpoch) == "" {
		return fmt.Errorf("%w: %s source_policy_epoch is required", ErrReleaseRefVerificationFailed, label)
	}
	if _, err := parseSourcePolicyEpoch(sourcePolicyEpoch); err != nil {
		return fmt.Errorf("%w: %s source_policy_epoch must be a decimal monotonic epoch", ErrReleaseRefVerificationFailed, label)
	}
	if sourcePolicyEpoch != snapshot.PolicyEpoch {
		return fmt.Errorf("%w: %s source_policy_epoch does not match source policy", ErrReleaseRefVerificationFailed, label)
	}
	if strings.TrimSpace(revocationEpoch) == "" {
		return fmt.Errorf("%w: %s revocation_epoch is required", ErrReleaseRefVerificationFailed, label)
	}
	if _, err := parseSourcePolicyEpoch(revocationEpoch); err != nil {
		return fmt.Errorf("%w: %s revocation_epoch must be a decimal monotonic epoch", ErrReleaseRefVerificationFailed, label)
	}
	if revocationEpoch != snapshot.RevocationEpoch {
		return fmt.Errorf("%w: %s revocation_epoch does not match source policy", ErrReleaseRefVerificationFailed, label)
	}
	return nil
}

func validateHashSet(label string, hashes PackageHashSet) error {
	for name, value := range map[string]string{
		"package_sha256":  hashes.PackageSHA256,
		"manifest_sha256": hashes.ManifestSHA256,
		"entries_sha256":  hashes.EntriesSHA256,
	} {
		if err := validateSHA256Hex(value); err != nil {
			return fmt.Errorf("%w: %s.%s %v", ErrReleaseRefVerificationFailed, label, name, err)
		}
	}
	return nil
}

func validateSHA256Hex(value string) error {
	if strings.TrimSpace(value) != value {
		return errors.New("must not contain surrounding whitespace")
	}
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) != 64 {
		return errors.New("must be a sha256 hex digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("must be a valid sha256 hex digest")
	}
	return nil
}

func isLowerHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func hashSetsEqual(left PackageHashSet, right PackageHashSet) bool {
	return hashEqual(left.PackageSHA256, right.PackageSHA256) &&
		hashEqual(left.ManifestSHA256, right.ManifestSHA256) &&
		hashEqual(left.EntriesSHA256, right.EntriesSHA256)
}

func hashEqual(left string, right string) bool {
	return normalizeSHA256(left) == normalizeSHA256(right)
}

func normalizeSHA256(value string) string {
	value = strings.TrimPrefix(value, "sha256:")
	if value == "" {
		return ""
	}
	return "sha256:" + value
}

func mergePrefixedMetadata(base map[string]string, prefix string, values map[string]string) error {
	for key, value := range values {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("%w: metadata key is required", ErrReleaseRefVerificationFailed)
		}
		metadataKey := prefix + key
		if _, exists := base[metadataKey]; exists {
			return fmt.Errorf("%w: metadata key %q is reserved", ErrReleaseRefVerificationFailed, metadataKey)
		}
		base[metadataKey] = value
	}
	return nil
}

func validateRegistryRelativeArtifactRef(value string, field string, required bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return fmt.Errorf("%w: %s is required", ErrReleaseRefVerificationFailed, field)
		}
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return fmt.Errorf("%w: %s must be a registry-relative artifact ref", ErrReleaseRefVerificationFailed, field)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(value, "?") || strings.Contains(value, "#") {
		return fmt.Errorf("%w: %s must not contain query or fragment", ErrReleaseRefVerificationFailed, field)
	}
	if strings.Contains(value, "\\") || strings.Contains(value, "%") || strings.HasPrefix(value, "/") {
		return fmt.Errorf("%w: %s must be a normalized relative path", ErrReleaseRefVerificationFailed, field)
	}
	clean := path.Clean(value)
	if clean == "." || clean != value || strings.HasPrefix(clean, "../") || clean == ".." {
		return fmt.Errorf("%w: %s must not contain path traversal", ErrReleaseRefVerificationFailed, field)
	}
	for _, segment := range strings.Split(clean, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%w: %s must not contain empty or relative path segments", ErrReleaseRefVerificationFailed, field)
		}
	}
	return nil
}

func sourceTypeOrDefault(sourceType PackageSourceType, distribution PackageDistribution) PackageSourceType {
	if sourceType != "" {
		return sourceType
	}
	switch distribution {
	case PackageDistributionHostArtifactRef:
		return PackageSourceHostArtifact
	default:
		return PackageSourceRegistry
	}
}

func localImportMetadata(now time.Time) map[string]string {
	assessedAt := lifecycleNow(now).Format(time.RFC3339)
	return map[string]string{
		"source_id":                    "local_import",
		"local_import.import_id":       "local_import",
		"local_import.distribution":    string(PackageDistributionLocalImport),
		"local_import.policy_epoch":    "local_import",
		"local_import.unsigned_policy": string(PackageUnsignedDevOnly),
		"local_import.assessed_at":     assessedAt,
	}
}

func localImportProvenance(now time.Time) *registry.LocalImportProvenance {
	return &registry.LocalImportProvenance{
		ImportID:       "local_import",
		Distribution:   string(PackageDistributionLocalImport),
		PolicyEpoch:    "local_import",
		UnsignedPolicy: string(PackageUnsignedDevOnly),
		AssessedAt:     lifecycleNow(now).Format(time.RFC3339),
	}
}

func attachSourcePolicySnapshot(record *registry.PluginRecord, snapshot SourcePolicySnapshot) error {
	hash, projected, err := sourcePolicySnapshotProjection(snapshot)
	if err != nil {
		return err
	}
	record.SourcePolicySnapshotHash = hash
	record.SourcePolicySnapshot = projected
	if record.Metadata == nil {
		record.Metadata = map[string]string{}
	}
	record.Metadata["source_policy_snapshot_sha256"] = hash
	return nil
}

func sourcePolicySnapshotProjection(snapshot SourcePolicySnapshot) (string, map[string]any, error) {
	projectedRaw, err := json.Marshal(snapshot)
	if err != nil {
		return "", nil, err
	}
	securitySnapshot := snapshot
	securitySnapshot.AssessedAt = ""
	if snapshot.RevocationEvidence != nil {
		revocationEvidence := *snapshot.RevocationEvidence
		revocationEvidence.VerifiedAt = ""
		securitySnapshot.RevocationEvidence = &revocationEvidence
	}
	securityRaw, err := json.Marshal(securitySnapshot)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(securityRaw)
	projected := map[string]any{}
	if err := json.Unmarshal(projectedRaw, &projected); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(sum[:]), projected, nil
}

func parseSourcePolicyEpoch(value string) (uint64, error) {
	if value == "" {
		return 0, errors.New("epoch is required")
	}
	if strings.TrimSpace(value) != value {
		return 0, errors.New("epoch must be canonical decimal")
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, errors.New("epoch must be canonical decimal")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("epoch must be canonical decimal")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func compareSourcePolicyEpoch(left string, right string) (int, error) {
	leftValue, err := parseSourcePolicyEpoch(left)
	if err != nil {
		return 0, err
	}
	rightValue, err := parseSourcePolicyEpoch(right)
	if err != nil {
		return 0, err
	}
	switch {
	case leftValue < rightValue:
		return -1, nil
	case leftValue > rightValue:
		return 1, nil
	default:
		return 0, nil
	}
}

func (h *Host) recordSourceSecurityFloor(ctx context.Context, snapshot SourcePolicySnapshot, now time.Time) error {
	hash, _, err := sourcePolicySnapshotProjection(snapshot)
	if err != nil {
		return err
	}
	if snapshot.RevocationEvidence == nil {
		return fmt.Errorf("%w: source policy revocation_evidence is required", ErrReleaseRefVerificationFailed)
	}
	floor := registry.SourceSecurityFloor{
		SourceID:                 snapshot.SourceID,
		PolicyEpoch:              snapshot.PolicyEpoch,
		KeyRotationEpoch:         snapshot.KeyRotationEpoch,
		RevocationEpoch:          snapshot.RevocationEpoch,
		SourcePolicySnapshotHash: hash,
		RevocationMetadataSHA256: snapshot.RevocationEvidence.MetadataSHA256,
	}
	if _, err := h.adapters.Registry.PutSourceSecurityFloor(ctx, floor, registry.PutOptions{Now: now}); err != nil {
		projected := finalizeRPCError(ctx, err)
		if errors.Is(projected, registry.ErrSourceSecurityFloorRollback) {
			return ErrReleaseRefPolicyDenied
		}
		return projected
	}
	return nil
}

func (h *Host) validateSourceSecurityFloor(ctx context.Context, snapshot SourcePolicySnapshot) error {
	if snapshot.RevocationEvidence == nil {
		return fmt.Errorf("%w: source policy revocation_evidence is required", ErrReleaseRefVerificationFailed)
	}
	hash, _, err := sourcePolicySnapshotProjection(snapshot)
	if err != nil {
		return err
	}
	candidate := registry.SourceSecurityFloor{
		SourceID:                 snapshot.SourceID,
		PolicyEpoch:              snapshot.PolicyEpoch,
		KeyRotationEpoch:         snapshot.KeyRotationEpoch,
		RevocationEpoch:          snapshot.RevocationEpoch,
		SourcePolicySnapshotHash: hash,
		RevocationMetadataSHA256: snapshot.RevocationEvidence.MetadataSHA256,
	}
	existing, err := h.adapters.Registry.GetSourceSecurityFloor(ctx, snapshot.SourceID)
	if errors.Is(err, registry.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := registry.ValidateSourceSecurityFloorTransition(existing, candidate); err != nil {
		if errors.Is(err, registry.ErrSourceSecurityFloorRollback) {
			return ErrReleaseRefPolicyDenied
		}
		return err
	}
	return nil
}

func (h *Host) createInstallStage(ctx context.Context, action installstage.Action, pkg pluginpkg.Package, pluginInstanceID string, requestedTrust string, now time.Time) (installstage.Record, error) {
	if h.adapters.InstallStages == nil {
		return installstage.Record{}, errors.New("install stage store is required")
	}
	stageID, err := installstage.NewStageID()
	if err != nil {
		return installstage.Record{}, err
	}
	stageNow := lifecycleNow(now)
	return h.adapters.InstallStages.Create(ctx, installstage.CreateRequest{
		StageID:          stageID,
		Action:           action,
		PluginInstanceID: pluginInstanceID,
		PublisherID:      pkg.Manifest.Publisher.PublisherID,
		PluginID:         pkg.Manifest.PluginID(),
		Version:          pkg.Manifest.Version(),
		PackageHash:      pkg.PackageHash,
		ManifestHash:     pkg.ManifestHash,
		EntriesHash:      pkg.EntriesHash,
		RequestedTrust:   requestedTrust,
		ValidationSummary: map[string]string{
			"package_read": "ok",
		},
		ExpiresAt: stageNow.Add(installStageTTL),
		Now:       stageNow,
	})
}

func (h *Host) markInstallStageFailed(ctx context.Context, stageID string, code string, cause error, now time.Time) error {
	if cause == nil {
		cause = errors.New("install stage failed")
	}
	if h.adapters.InstallStages == nil {
		return cause
	}
	if _, err := h.adapters.InstallStages.MarkFailed(ctx, installstage.MarkFailedRequest{
		StageID:      stageID,
		ErrorCode:    code,
		ErrorMessage: cause.Error(),
		Now:          lifecycleNow(now),
	}); err != nil {
		return fmt.Errorf("%w; failed to update install stage: %v", cause, err)
	}
	return cause
}

func requireStablePluginDataShape(current manifest.Manifest, next manifest.Manifest) error {
	currentShape, err := plugindata.ShapeFromManifest(current)
	if err != nil {
		return err
	}
	nextShape, err := plugindata.ShapeFromManifest(next)
	if err != nil {
		return err
	}
	currentHash, err := plugindata.HashShape(currentShape)
	if err != nil {
		return err
	}
	nextHash, err := plugindata.HashShape(nextShape)
	if err != nil {
		return err
	}
	if currentHash != nextHash {
		return fmt.Errorf("%w: use a new plugin identity for a different data shape", ErrPluginDataContractChanged)
	}
	return nil
}

func (h *Host) DowngradePlugin(ctx context.Context, req DowngradeRequest) (result registry.PluginRecord, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer releaseLifecycle()
	current, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := requireManagementRevision(current, req.ExpectedManagementRevision); err != nil {
		return registry.PluginRecord{}, err
	}
	snapshot, remaining, err := selectVersionSnapshot(current.VersionHistory, req.Version, req.PackageHash)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	next := recordFromVersionSnapshot(current, snapshot)
	if err := requireStablePluginDataShape(current.Manifest, next.Manifest); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.preflightPackageFeatures(next.Manifest, packageTrustInput{}); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.preflightWorkerRuntime(ctx, next); err != nil {
		return registry.PluginRecord{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.downgraded", PluginID: current.PluginID, PluginInstanceID: current.PluginInstanceID})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	next.VersionHistory = remaining
	next = prepareVersionSwitchRecord(current, next, versionSnapshot(current, req.Now), req.Now)
	if next.EnableState == registry.EnableEnabled {
		if err := h.validateEnabledRuntimeState(ctx, next); err != nil {
			return registry.PluginRecord{}, err
		}
	}
	stored, err := h.adapters.Registry.PutPlugin(ctx, next, registry.PutOptions{Now: req.Now})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.revokePluginRuntimeCapabilities(ctx, stored, req.Now); err != nil {
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	if err := h.refreshEnabledRuntimeState(ctx, stored); err != nil {
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	return stored, nil
}

func (input packageTrustInput) stageRequestedTrust() string {
	return ""
}

func (h *Host) resolvePackageTrust(ctx context.Context, action PackageTrustAction, pkg pluginpkg.Package, input packageTrustInput, current *registry.PluginRecord, instanceID string, now time.Time) (registry.TrustAssessment, error) {
	if h.adapters.PackageTrustVerifier == nil {
		if input.LocalImport {
			return defaultTrustAssessment(pkg, registry.TrustUnsignedLocal, input), nil
		}
		if err := h.requireFeature(FeatureRelease); err != nil {
			return registry.TrustAssessment{}, err
		}
		if input.SourcePolicySnapshot != nil {
			return registry.TrustAssessment{}, ErrPackageTrustVerifierRequired
		}
		return defaultTrustAssessment(pkg, registry.TrustUntrusted, input), nil
	}
	result, err := h.adapters.PackageTrustVerifier.VerifyPackageTrust(ctx, PackageTrustVerificationRequest{
		Action:               action,
		Package:              pkg,
		LocalImport:          input.LocalImport,
		ReleaseRef:           input.ReleaseRef,
		Release:              input.Release,
		SourcePolicySnapshot: input.SourcePolicySnapshot,
		CurrentRecord:        current,
		PluginInstanceID:     instanceID,
		Now:                  now,
	})
	if err != nil {
		return registry.TrustAssessment{}, err
	}
	if !knownTrustState(result.TrustState) {
		return registry.TrustAssessment{}, fmt.Errorf("%w: %q", ErrPackageTrustVerificationInvalid, result.TrustState)
	}
	if input.SourcePolicySnapshot != nil && result.TrustState != registry.TrustVerified {
		return registry.TrustAssessment{}, fmt.Errorf("%w: release-ref trust_state must be verified, got %q", ErrPackageTrustVerificationInvalid, result.TrustState)
	}
	return normalizeTrustAssessmentForPackage(pkg, result, input), nil
}

func knownTrustState(state registry.TrustState) bool {
	switch state {
	case registry.TrustVerified, registry.TrustUnsignedLocal, registry.TrustUntrusted, registry.TrustNeedsReview, registry.TrustUnavailable, registry.TrustBlockedSecurity:
		return true
	default:
		return false
	}
}

func defaultTrustAssessment(pkg pluginpkg.Package, trust registry.TrustState, input packageTrustInput) registry.TrustAssessment {
	return normalizeTrustAssessmentForPackage(pkg, registry.TrustAssessment{
		TrustState:  trust,
		ReasonCodes: []string{"host_default"},
	}, input)
}

func normalizeTrustAssessmentForPackage(pkg pluginpkg.Package, assessment registry.TrustAssessment, input packageTrustInput) registry.TrustAssessment {
	if assessment.VerifiedHashes.PackageSHA256 == "" {
		assessment.VerifiedHashes.PackageSHA256 = pkg.PackageHash
	}
	if assessment.VerifiedHashes.ManifestSHA256 == "" {
		assessment.VerifiedHashes.ManifestSHA256 = pkg.ManifestHash
	}
	if assessment.VerifiedHashes.EntriesSHA256 == "" {
		assessment.VerifiedHashes.EntriesSHA256 = pkg.EntriesHash
	}
	if input.SourcePolicySnapshot != nil {
		if assessment.PolicyEpoch == "" {
			assessment.PolicyEpoch = input.SourcePolicySnapshot.PolicyEpoch
		}
		if assessment.RevocationEpoch == "" {
			assessment.RevocationEpoch = input.SourcePolicySnapshot.RevocationEpoch
		}
	}
	if assessment.TrustAssessmentEpoch == "" {
		parts := []string{
			string(assessment.TrustState),
			assessment.PolicyEpoch,
			assessment.RevocationEpoch,
			assessment.VerifiedHashes.PackageSHA256,
			assessment.VerifiedHashes.ManifestSHA256,
			assessment.VerifiedHashes.EntriesSHA256,
		}
		sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
		assessment.TrustAssessmentEpoch = hex.EncodeToString(sum[:])
	}
	assessment.Metadata = cloneStringMap(assessment.Metadata)
	return assessment
}

func packageRecord(pkg pluginpkg.Package, trust registry.TrustAssessment, instanceID string, metadata map[string]string, capabilityPins []capabilitycontract.Pin) registry.PluginRecord {
	if instanceID == "" {
		instanceID = defaultPluginInstanceID(pkg)
	}
	trust = normalizeTrustAssessmentForPackage(pkg, trust, packageTrustInput{})
	metadata = cloneStringMap(metadata)
	metadata = mergeStringMap(trust.Metadata, metadata)
	return registry.PluginRecord{
		PluginInstanceID:    instanceID,
		PublisherID:         pkg.Manifest.Publisher.PublisherID,
		PluginID:            pkg.Manifest.PluginID(),
		Version:             pkg.Manifest.Version(),
		ActiveFingerprint:   activeFingerprintForPackage(pkg, instanceID, trust, capabilityPins),
		PackageHash:         pkg.PackageHash,
		ManifestHash:        pkg.ManifestHash,
		EntriesHash:         pkg.EntriesHash,
		TrustState:          trust.TrustState,
		TrustAssessment:     trust,
		EnableState:         registry.EnableDisabled,
		Manifest:            pkg.Manifest,
		PackageEntries:      pkg.Entries,
		CapabilityContracts: append([]capabilitycontract.Pin(nil), capabilityPins...),
		Metadata:            cloneStringMap(metadata),
	}
}

func activeFingerprintForPackage(pkg pluginpkg.Package, instanceID string, trust registry.TrustAssessment, capabilityPins []capabilitycontract.Pin) string {
	declaredCapabilityHash := declaredCapabilityContractHash(pkg.Manifest)
	resolvedCapabilityHash := resolvedCapabilityContractHash(capabilityPins)
	parts := []string{
		"redevplugin.active_fingerprint.v1",
		instanceID,
		pkg.Manifest.Publisher.PublisherID,
		pkg.Manifest.PluginID(),
		pkg.Manifest.Version(),
		pkg.PackageHash,
		pkg.ManifestHash,
		pkg.EntriesHash,
		declaredCapabilityHash,
		resolvedCapabilityHash,
		trust.TrustAssessmentEpoch,
		trust.PolicyEpoch,
		trust.RevocationEpoch,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func resolvedCapabilityContractHash(pins []capabilitycontract.Pin) string {
	values := make([]string, 0, len(pins))
	for _, pin := range pins {
		raw, err := json.Marshal(pin)
		if err != nil {
			continue
		}
		values = append(values, string(raw))
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}

func declaredCapabilityContractHash(m manifest.Manifest) string {
	values := make([]string, 0, len(m.CapabilityBindings))
	for _, capabilitySpec := range m.CapabilityBindings {
		raw, err := json.Marshal(capabilitySpec.Contract)
		if err != nil {
			continue
		}
		values = append(values, capabilitySpec.BindingID+"\x00"+string(raw))
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}

func validateSamePluginIdentity(current registry.PluginRecord, next registry.PluginRecord) error {
	if current.PublisherID != next.PublisherID || current.PluginID != next.PluginID {
		return fmt.Errorf("package identity mismatch: got %s/%s, want %s/%s", next.PublisherID, next.PluginID, current.PublisherID, current.PluginID)
	}
	return nil
}

func prepareVersionSwitchRecord(current registry.PluginRecord, next registry.PluginRecord, previous registry.PluginVersion, now time.Time) registry.PluginRecord {
	next.PluginInstanceID = current.PluginInstanceID
	next.EnableState = current.EnableState
	next.DisabledReason = current.DisabledReason
	next.PolicyRevision = current.PolicyRevision
	next.ManagementRevision = current.ManagementRevision
	next.RevokeEpoch = current.RevokeEpoch
	next.InstalledAt = current.InstalledAt
	next.EnabledAt = cloneTimePtr(current.EnabledAt)
	if current.EnableState == registry.EnableDisabledIncompatible && next.Manifest.Plugin.UIProtocolVersion == version.PluginUIProtocolVersion {
		next.EnableState = registry.EnableDisabled
		next.DisabledReason = "updated to the current UI protocol; explicit enable is required"
		next.EnabledAt = nil
	}
	next.DeletedAt = cloneTimePtr(current.DeletedAt)
	next.Metadata = mergeStringMap(current.Metadata, next.Metadata)
	if previous.PackageHash != "" && previous.PackageHash != next.PackageHash {
		next.VersionHistory = appendVersionSnapshot(next.VersionHistory, previous)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	next.UpdatedAt = now
	return next
}

func versionSnapshot(record registry.PluginRecord, now time.Time) registry.PluginVersion {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return registry.PluginVersion{
		Version:                  record.Version,
		ActiveFingerprint:        record.ActiveFingerprint,
		PackageHash:              record.PackageHash,
		ManifestHash:             record.ManifestHash,
		EntriesHash:              record.EntriesHash,
		TrustState:               record.TrustState,
		TrustAssessment:          record.TrustAssessment,
		SourcePolicySnapshotHash: record.SourcePolicySnapshotHash,
		SourcePolicySnapshot:     cloneAnyMap(record.SourcePolicySnapshot),
		LocalImportProvenance:    cloneLocalImportProvenance(record.LocalImportProvenance),
		CapabilityContracts:      append([]capabilitycontract.Pin(nil), record.CapabilityContracts...),
		Manifest:                 record.Manifest,
		PackageEntries:           cloneEntries(record.PackageEntries),
		RuntimeRequirement:       cloneRuntimeRequirement(record.RuntimeRequirement),
		ActivatedAt:              now,
		Metadata:                 cloneStringMap(record.Metadata),
	}
}

func recordFromVersionSnapshot(current registry.PluginRecord, snapshot registry.PluginVersion) registry.PluginRecord {
	next := current
	next.Version = snapshot.Version
	next.ActiveFingerprint = snapshot.ActiveFingerprint
	next.PackageHash = snapshot.PackageHash
	next.ManifestHash = snapshot.ManifestHash
	next.EntriesHash = snapshot.EntriesHash
	next.TrustState = snapshot.TrustState
	next.TrustAssessment = snapshot.TrustAssessment
	next.SourcePolicySnapshotHash = snapshot.SourcePolicySnapshotHash
	next.SourcePolicySnapshot = cloneAnyMap(snapshot.SourcePolicySnapshot)
	next.LocalImportProvenance = cloneLocalImportProvenance(snapshot.LocalImportProvenance)
	next.CapabilityContracts = append([]capabilitycontract.Pin(nil), snapshot.CapabilityContracts...)
	next.Manifest = snapshot.Manifest
	next.PackageEntries = cloneEntries(snapshot.PackageEntries)
	next.RuntimeRequirement = cloneRuntimeRequirement(snapshot.RuntimeRequirement)
	next.Metadata = cloneStringMap(snapshot.Metadata)
	return next
}

func cloneLocalImportProvenance(provenance *registry.LocalImportProvenance) *registry.LocalImportProvenance {
	if provenance == nil {
		return nil
	}
	clone := *provenance
	return &clone
}

func cloneRuntimeRequirement(requirement *registry.RuntimeRequirement) *registry.RuntimeRequirement {
	if requirement == nil {
		return nil
	}
	return &registry.RuntimeRequirement{
		MinVersion:       requirement.MinVersion,
		SupportedTargets: append([]string(nil), requirement.SupportedTargets...),
	}
}

func (h *Host) preflightPackageFeatures(pluginManifest manifest.Manifest, input packageTrustInput) error {
	return h.requireFeatures(requiredPackageFeatures(pluginManifest, input))
}

func requiredPackageFeatures(pluginManifest manifest.Manifest, input packageTrustInput) []Feature {
	required := make([]Feature, 0, 6)
	if input.ReleaseRef != nil || input.Release != nil {
		required = append(required, FeatureRelease)
	}
	if len(pluginManifest.Workers) > 0 {
		required = append(required, FeatureRuntime)
	}
	if len(pluginManifest.CapabilityBindings) > 0 || releaseRequiresCapabilities(input.Release) {
		required = append(required, FeatureCapability)
	}
	if manifestRequiresConnectivity(pluginManifest) {
		required = append(required, FeatureConnectivity)
	}
	if manifestRequiresSecrets(pluginManifest) {
		required = append(required, FeatureSecrets)
	}
	for _, method := range pluginManifest.Methods {
		if method.Route.Kind == manifest.MethodRouteCoreAction {
			required = append(required, FeatureCoreAction)
			break
		}
	}
	return required
}

func releaseRequiresCapabilities(release *PluginPackageRelease) bool {
	if release == nil {
		return false
	}
	for _, requirement := range release.HostRequirements {
		if len(requirement.RequiredCapabilityContracts) > 0 {
			return true
		}
	}
	return false
}

func manifestRequiresConnectivity(pluginManifest manifest.Manifest) bool {
	if pluginManifest.NetworkAccess != nil && len(pluginManifest.NetworkAccess.Connectors) > 0 {
		return true
	}
	for _, method := range pluginManifest.Methods {
		if method.BrokerAccess != nil && len(method.BrokerAccess.Network) > 0 {
			return true
		}
	}
	return false
}

func manifestRequiresSecrets(pluginManifest manifest.Manifest) bool {
	if pluginManifest.Settings != nil {
		for _, field := range pluginManifest.Settings.Fields {
			if strings.TrimSpace(field.SecretRef) != "" {
				return true
			}
		}
	}
	if pluginManifest.NetworkAccess != nil {
		for _, connector := range pluginManifest.NetworkAccess.Connectors {
			if mapContainsSecretRef(connector.Auth) || mapContainsSecretRef(connector.TLS) {
				return true
			}
		}
	}
	return false
}

func mapContainsSecretRef(values map[string]any) bool {
	for key, value := range values {
		if strings.EqualFold(key, "secret_ref") {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				return true
			}
		}
		switch nested := value.(type) {
		case map[string]any:
			if mapContainsSecretRef(nested) {
				return true
			}
		case []any:
			for _, item := range nested {
				if object, ok := item.(map[string]any); ok && mapContainsSecretRef(object) {
					return true
				}
			}
		}
	}
	return false
}

func runtimeRequirementForPackage(pluginManifest manifest.Manifest, input packageTrustInput) (*registry.RuntimeRequirement, error) {
	if !pluginHasWorkers(pluginManifest) {
		return nil, nil
	}
	minimumVersion, err := version.ParseSemVer(pluginManifest.Plugin.MinRuntimeVersion)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid minimum runtime version: %v", ErrPluginRuntimeIncompatible, err)
	}
	requirement := &registry.RuntimeRequirement{MinVersion: minimumVersion.String()}
	if input.Release != nil && input.Release.Compatibility != nil {
		requirement.SupportedTargets = append([]string(nil), input.Release.Compatibility.SupportedTargets...)
	}
	seenTargets := make(map[string]struct{}, len(requirement.SupportedTargets))
	for _, value := range requirement.SupportedTargets {
		target, err := parseRuntimeTarget(value)
		if err != nil {
			return nil, fmt.Errorf("%w: supported target %q: %v", ErrPluginRuntimeIncompatible, value, err)
		}
		canonical := runtimeTargetString(target)
		if canonical != value {
			return nil, fmt.Errorf("%w: supported target %q is not canonical", ErrPluginRuntimeIncompatible, value)
		}
		if _, exists := seenTargets[canonical]; exists {
			return nil, fmt.Errorf("%w: supported target %q is duplicated", ErrPluginRuntimeIncompatible, value)
		}
		seenTargets[canonical] = struct{}{}
	}
	sort.Strings(requirement.SupportedTargets)
	return requirement, nil
}

func pluginHasWorkers(pluginManifest manifest.Manifest) bool {
	return len(pluginManifest.Workers) > 0
}

func parseRuntimeTarget(value string) (runtimeclient.Target, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return runtimeclient.Target{}, runtimeclient.ErrRuntimeTargetUnsupported
	}
	target := runtimeclient.Target{OS: parts[0], Arch: parts[1]}
	if err := runtimeclient.ValidateTarget(target); err != nil {
		return runtimeclient.Target{}, err
	}
	return target, nil
}

func runtimeTargetString(target runtimeclient.Target) string {
	return target.OS + "/" + target.Arch
}

func currentRuntimeTarget() runtimeclient.Target {
	return runtimeclient.Target{OS: runtime.GOOS, Arch: runtime.GOARCH}
}

func validateWorkerRuntimeDescriptor(record registry.PluginRecord, descriptor runtimeclient.RuntimeDescriptor, expectedTarget runtimeclient.Target) error {
	if !pluginHasWorkers(record.Manifest) {
		return nil
	}
	if record.RuntimeRequirement == nil {
		return fmt.Errorf("%w: worker runtime requirement is missing", ErrPluginRuntimeIncompatible)
	}
	minimumVersion, err := version.ParseSemVer(record.RuntimeRequirement.MinVersion)
	if err != nil {
		return fmt.Errorf("%w: invalid minimum runtime version: %v", ErrPluginRuntimeIncompatible, err)
	}
	if err := descriptor.CompatibleWithPlatform(); err != nil {
		return fmt.Errorf("%w: %v", ErrPluginRuntimeIncompatible, err)
	}
	if descriptor.Target() != expectedTarget {
		return fmt.Errorf(
			"%w: runtime target %s does not match expected %s",
			ErrPluginRuntimeIncompatible,
			runtimeTargetString(descriptor.Target()),
			runtimeTargetString(expectedTarget),
		)
	}
	if descriptor.Version().Compare(minimumVersion) < 0 {
		return fmt.Errorf(
			"%w: runtime %s is below required %s",
			ErrPluginRuntimeIncompatible,
			descriptor.Version().String(),
			minimumVersion.String(),
		)
	}
	if len(record.RuntimeRequirement.SupportedTargets) > 0 {
		actualTarget := runtimeTargetString(descriptor.Target())
		supported := false
		for _, target := range record.RuntimeRequirement.SupportedTargets {
			if target == actualTarget {
				supported = true
				break
			}
		}
		if !supported {
			return fmt.Errorf("%w: runtime target %s is unsupported by the package", ErrPluginRuntimeIncompatible, actualTarget)
		}
	}
	for _, worker := range record.Manifest.Workers {
		if worker.ABI != descriptor.WASMABIVersion() {
			return fmt.Errorf(
				"%w: worker %q ABI %s does not match runtime %s",
				ErrPluginRuntimeIncompatible,
				worker.WorkerID,
				worker.ABI,
				descriptor.WASMABIVersion(),
			)
		}
	}
	return nil
}

func (h *Host) preflightWorkerRuntime(ctx context.Context, record registry.PluginRecord) error {
	if !pluginHasWorkers(record.Manifest) {
		return nil
	}
	if h.adapters.RuntimeManager == nil {
		return ErrPluginRuntimeNotConfigured
	}
	descriptor, err := h.adapters.RuntimeManager.Preflight(ctx, currentRuntimeTarget())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPluginRuntimeIncompatible, err)
	}
	return validateWorkerRuntimeDescriptor(record, descriptor, currentRuntimeTarget())
}

func (h *Host) bindCompatibleWorkerRuntime(ctx context.Context, record registry.PluginRecord) (runtimeclient.RuntimeBinding, error) {
	if !pluginHasWorkers(record.Manifest) {
		return runtimeclient.RuntimeBinding{}, fmt.Errorf("%w: plugin has no workers", ErrPluginRuntimeIncompatible)
	}
	if h.adapters.RuntimeManager == nil {
		if err := h.requireFeature(FeatureRuntime); err != nil {
			return runtimeclient.RuntimeBinding{}, err
		}
		return runtimeclient.RuntimeBinding{}, ErrPluginRuntimeNotConfigured
	}
	health, err := h.adapters.RuntimeManager.Health(ctx)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if err := validateRuntimeManagerHealth(health, health.Descriptor); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if err := validateWorkerRuntimeDescriptor(record, health.Descriptor, currentRuntimeTarget()); err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	binding, err := h.adapters.RuntimeManager.BindPlugin(ctx, record.PluginInstanceID)
	if err != nil {
		return runtimeclient.RuntimeBinding{}, err
	}
	if binding.Descriptor != health.Descriptor {
		return runtimeclient.RuntimeBinding{}, fmt.Errorf("%w: runtime binding descriptor changed", ErrPluginRuntimeIncompatible)
	}
	if strings.TrimSpace(binding.RuntimeGenerationID) == "" {
		return runtimeclient.RuntimeBinding{}, fmt.Errorf("%w: runtime binding generation is missing", ErrPluginRuntimeIncompatible)
	}
	return binding, nil
}

func validateRuntimeManagerHealth(health runtimeclient.ManagerHealth, expected runtimeclient.RuntimeDescriptor) error {
	if len(health.Shards) == 0 {
		return runtimeclient.ErrRuntimeNotReady
	}
	if err := expected.CompatibleWithPlatform(); err != nil {
		return fmt.Errorf("%w: %v", ErrPluginRuntimeIncompatible, err)
	}
	if health.Descriptor != expected {
		return fmt.Errorf("%w: manager descriptor mismatch", ErrPluginRuntimeIncompatible)
	}
	for _, shard := range health.Shards {
		if shard.Descriptor != expected {
			return fmt.Errorf("%w: runtime shard %q descriptor mismatch", ErrPluginRuntimeIncompatible, shard.RuntimeShardID)
		}
	}
	if !health.Ready {
		return runtimeclient.ErrRuntimeNotReady
	}
	for _, shard := range health.Shards {
		if !shard.Ready {
			return runtimeclient.ErrRuntimeNotReady
		}
	}
	return nil
}

func selectVersionSnapshot(history []registry.PluginVersion, requestedVersion string, packageHash string) (registry.PluginVersion, []registry.PluginVersion, error) {
	packageHash = strings.TrimSpace(packageHash)
	if requestedVersion == "" && packageHash == "" {
		return registry.PluginVersion{}, nil, errors.New("version or package_hash is required")
	}
	if requestedVersion != "" {
		if _, err := version.ParseSemVer(requestedVersion); err != nil {
			return registry.PluginVersion{}, nil, fmt.Errorf("version is invalid: %w", err)
		}
	}
	for i, snapshot := range history {
		if (requestedVersion == "" || snapshot.Version == requestedVersion) && (packageHash == "" || snapshot.PackageHash == packageHash) {
			remaining := make([]registry.PluginVersion, 0, len(history)-1)
			remaining = append(remaining, history[:i]...)
			remaining = append(remaining, history[i+1:]...)
			return snapshot, remaining, nil
		}
	}
	return registry.PluginVersion{}, nil, registry.ErrNotFound
}

func appendVersionSnapshot(history []registry.PluginVersion, snapshot registry.PluginVersion) []registry.PluginVersion {
	next := make([]registry.PluginVersion, 0, len(history)+1)
	for _, existing := range history {
		if existing.PackageHash == snapshot.PackageHash {
			continue
		}
		next = append(next, existing)
	}
	next = append(next, snapshot)
	return next
}

func (h *Host) validateEnabledRuntimeState(ctx context.Context, record registry.PluginRecord) error {
	if err := h.canRun(ctx, record); err != nil {
		return err
	}
	if _, _, err := compileConnectivityPolicy(record); err != nil {
		return err
	}
	return nil
}

func (h *Host) refreshEnabledRuntimeState(ctx context.Context, record registry.PluginRecord) error {
	if record.EnableState != registry.EnableEnabled {
		return nil
	}
	if pluginHasWorkers(record.Manifest) {
		if _, err := h.bindCompatibleWorkerRuntime(ctx, record); err != nil {
			return err
		}
	}
	if err := h.prepareEnabledRuntimeState(ctx, record); err != nil {
		return err
	}
	return h.publishEnabledSurfaces(ctx, record)
}

func (h *Host) prepareEnabledRuntimeState(ctx context.Context, record registry.PluginRecord) error {
	connectivityPolicy, hasConnectivityPolicy, err := compileConnectivityPolicy(record)
	if err != nil {
		return err
	}
	if err := h.installConnectivityPolicy(ctx, record, connectivityPolicy, hasConnectivityPolicy); err != nil {
		if h.adapters.Connectivity != nil {
			_ = h.adapters.Connectivity.RemovePolicy(ctx, record.PluginInstanceID)
		}
		return err
	}
	return nil
}

func (h *Host) publishEnabledSurfaces(ctx context.Context, record registry.PluginRecord) error {
	if record.EnableState != registry.EnableEnabled {
		return nil
	}
	if h.adapters.SurfaceCatalog != nil {
		if err := h.adapters.SurfaceCatalog.PublishSurfaces(ctx, SurfaceSnapshot{
			PluginInstanceID:  record.PluginInstanceID,
			ActiveFingerprint: record.ActiveFingerprint,
			Surfaces:          record.Manifest.Surfaces,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (h *Host) rollbackVersionSwitch(ctx context.Context, current registry.PluginRecord, packageHash string, now time.Time) error {
	if _, err := h.adapters.Registry.PutPlugin(ctx, current, registry.PutOptions{Now: now}); err != nil {
		return err
	}
	if packageHash != "" && packageHash != current.PackageHash {
		_ = h.adapters.Assets.DeletePackage(ctx, packageHash)
	}
	return h.publishEnabledSurfaces(ctx, current)
}

func (h *Host) getExistingInstallRecord(ctx context.Context, pluginInstanceID string) (registry.PluginRecord, bool, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, pluginInstanceID)
	if errors.Is(err, registry.ErrNotFound) {
		return registry.PluginRecord{}, false, nil
	}
	if err != nil {
		return registry.PluginRecord{}, false, err
	}
	return record, true, nil
}

func (h *Host) rollbackInstallRecord(ctx context.Context, previous registry.PluginRecord, hadPrevious bool, pluginInstanceID string, packageHash string, now time.Time) error {
	if hadPrevious {
		if _, err := h.adapters.Registry.PutPlugin(ctx, previous, registry.PutOptions{Now: now}); err != nil {
			return err
		}
	} else if err := h.adapters.Registry.AbortInstall(ctx, pluginInstanceID); err != nil && !errors.Is(err, registry.ErrNotFound) {
		return err
	}
	if packageHash != "" && (!hadPrevious || packageHash != previous.PackageHash) {
		_ = h.adapters.Assets.DeletePackage(ctx, packageHash)
	}
	return nil
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil
	}
	return cloned
}

func mergeStringMap(base map[string]string, overlay map[string]string) map[string]string {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	merged := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range overlay {
		merged[key] = value
	}
	return merged
}

func cloneEntries(entries []pluginpkg.Entry) []pluginpkg.Entry {
	if entries == nil {
		return nil
	}
	return append([]pluginpkg.Entry(nil), entries...)
}

func (h *Host) ListPlugins(ctx context.Context) ([]registry.PluginRecord, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return nil, err
	}
	return h.adapters.Registry.ListPlugins(ctx)
}

type RefreshEnabledPluginStatus string

const (
	RefreshEnabledPluginStatusRefreshed RefreshEnabledPluginStatus = "refreshed"
	RefreshEnabledPluginStatusFailed    RefreshEnabledPluginStatus = "failed"
	refreshEnabledPluginFailureMessage                             = "Plugin runtime state could not be refreshed"
)

type RefreshEnabledPluginResult struct {
	PluginInstanceID string                           `json:"plugin_instance_id"`
	Status           RefreshEnabledPluginStatus       `json:"status"`
	Error            *RefreshEnabledPluginPublicError `json:"error,omitempty"`
}

type RefreshEnabledPluginPublicError struct {
	Code    security.ErrorCode `json:"code"`
	Message string             `json:"message"`
}

func refreshedPluginResult(pluginInstanceID string) RefreshEnabledPluginResult {
	return RefreshEnabledPluginResult{
		PluginInstanceID: strings.TrimSpace(pluginInstanceID),
		Status:           RefreshEnabledPluginStatusRefreshed,
	}
}

func failedPluginRefreshResult(pluginInstanceID string) RefreshEnabledPluginResult {
	return RefreshEnabledPluginResult{
		PluginInstanceID: strings.TrimSpace(pluginInstanceID),
		Status:           RefreshEnabledPluginStatusFailed,
		Error: &RefreshEnabledPluginPublicError{
			Code:    security.ErrRuntimeUnavailable,
			Message: refreshEnabledPluginFailureMessage,
		},
	}
}

func (result RefreshEnabledPluginResult) validate() error {
	if strings.TrimSpace(result.PluginInstanceID) == "" {
		return errors.New("runtime refresh result requires plugin_instance_id")
	}
	switch result.Status {
	case RefreshEnabledPluginStatusRefreshed:
		if result.Error != nil {
			return errors.New("refreshed runtime result must not include an error")
		}
	case RefreshEnabledPluginStatusFailed:
		if result.Error == nil || result.Error.Code != security.ErrRuntimeUnavailable || result.Error.Message != refreshEnabledPluginFailureMessage {
			return errors.New("failed runtime refresh result requires the stable runtime error")
		}
	default:
		return fmt.Errorf("unsupported runtime refresh status %q", result.Status)
	}
	return nil
}

func (result RefreshEnabledPluginResult) MarshalJSON() ([]byte, error) {
	if err := result.validate(); err != nil {
		return nil, err
	}
	type wireResult RefreshEnabledPluginResult
	return json.Marshal(wireResult(result))
}

func (h *Host) RefreshEnabledPlugins(ctx context.Context) ([]RefreshEnabledPluginResult, error) {
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return nil, err
	}
	defer releaseOpen()
	records, err := h.adapters.Registry.ListPlugins(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]RefreshEnabledPluginResult, 0, len(records))
	for _, record := range records {
		if record.EnableState != registry.EnableEnabled {
			continue
		}
		if err := h.refreshEnabledRuntimeState(ctx, record); err != nil {
			h.reportLifecycleDiagnostic(ctx, record, "plugin.runtime_state.refresh_failed", err, nil)
			results = append(results, failedPluginRefreshResult(record.PluginInstanceID))
			continue
		}
		results = append(results, refreshedPluginResult(record.PluginInstanceID))
		if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.runtime_state.refreshed", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID}); err != nil {
			return results, mutation.Unknown(err)
		}
	}
	return results, nil
}

func (h *Host) GrantPermission(ctx context.Context, req GrantPermissionRequest) (result PermissionMutationResult, retErr error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return PermissionMutationResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return PermissionMutationResult{}, err
	}
	if record.SourcePolicySnapshotHash != "" {
		now := req.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		if err := h.verifyCurrentSourcePolicy(ctx, record, now); err != nil {
			if cleanupErr := h.disablePluginForSourcePolicyFailure(ctx, record, now); cleanupErr != nil {
				return PermissionMutationResult{}, errors.Join(err, cleanupErr)
			}
			return PermissionMutationResult{}, err
		}
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.permission.granted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return PermissionMutationResult{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	snapshot, err := h.adapters.Registry.GrantPermission(ctx, permissions.GrantRequest{
		PluginInstanceID: record.PluginInstanceID,
		PermissionID:     req.PermissionID,
		GrantedBy:        session.OwnerUserHash,
		Now:              req.Now,
		ExpiresAt:        req.ExpiresAt,
	}, authorizationRevisions(req.ExpectedPolicyRevision, req.ExpectedManagementRevision, req.ExpectedRevokeEpoch))
	if err != nil {
		return PermissionMutationResult{}, err
	}
	if err := h.refreshConnectivityPolicy(ctx, snapshot.Plugin); err != nil {
		return PermissionMutationResult{}, mutation.Unknown(err)
	}
	permission, err := permissionGrantFromSnapshot(snapshot, req.PermissionID)
	if err != nil {
		return PermissionMutationResult{}, err
	}
	return PermissionMutationResult{Permission: permission, Revisions: registry.AuthorizationRevisionsFromRecord(snapshot.Plugin)}, nil
}

func (h *Host) RevokePermission(ctx context.Context, req RevokePermissionRequest) (result PermissionMutationResult, retErr error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return PermissionMutationResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return PermissionMutationResult{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.permission.revoked", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return PermissionMutationResult{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	snapshot, err := h.adapters.Registry.RevokePermission(ctx, permissions.RevokeRequest{
		PluginInstanceID: record.PluginInstanceID,
		PermissionID:     req.PermissionID,
		RevokedBy:        session.OwnerUserHash,
		Reason:           req.Reason,
		Now:              req.Now,
	}, authorizationRevisions(req.ExpectedPolicyRevision, req.ExpectedManagementRevision, req.ExpectedRevokeEpoch))
	if err != nil {
		return PermissionMutationResult{}, err
	}
	if err := errors.Join(
		h.refreshConnectivityPolicy(ctx, snapshot.Plugin),
		h.revokePluginRuntimeCapabilities(ctx, snapshot.Plugin, req.Now),
	); err != nil {
		return PermissionMutationResult{}, mutation.Unknown(err)
	}
	permission, err := permissionGrantFromSnapshot(snapshot, req.PermissionID)
	if err != nil {
		return PermissionMutationResult{}, err
	}
	return PermissionMutationResult{Permission: permission, Revisions: registry.AuthorizationRevisionsFromRecord(snapshot.Plugin)}, nil
}

func (h *Host) ListPermissionGrants(ctx context.Context, req ListPermissionGrantsRequest) ([]permissions.Record, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return nil, err
	}
	var snapshots []registry.AuthorizationSnapshot
	if strings.TrimSpace(req.PluginInstanceID) != "" {
		snapshot, err := h.adapters.Registry.GetAuthorization(ctx, req.PluginInstanceID)
		if err != nil {
			return nil, err
		}
		snapshots = []registry.AuthorizationSnapshot{snapshot}
	} else {
		var err error
		snapshots, err = h.adapters.Registry.ListAuthorization(ctx)
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	records := make([]permissions.Record, 0)
	for _, snapshot := range snapshots {
		for _, record := range snapshot.Grants {
			if !req.ActiveOnly || activePermissionGrant(record, now) {
				records = append(records, record)
			}
		}
	}
	return records, nil
}

func (h *Host) PutSecurityPolicy(ctx context.Context, req PutSecurityPolicyRequest) (result SecurityPolicyResult, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return SecurityPolicyResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return SecurityPolicyResult{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.security_policy.updated", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return SecurityPolicyResult{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	snapshot, err := h.adapters.Registry.PutSecurityPolicy(ctx, security.PutPolicyRequest{
		PluginInstanceID:   record.PluginInstanceID,
		AllowedPermissions: req.AllowedPermissions,
		DeniedMethods:      req.DeniedMethods,
		Now:                req.Now,
	}, authorizationRevisions(req.ExpectedPolicyRevision, req.ExpectedManagementRevision, req.ExpectedRevokeEpoch))
	if err != nil {
		return SecurityPolicyResult{}, err
	}
	if err := errors.Join(
		h.refreshConnectivityPolicy(ctx, snapshot.Plugin),
		h.revokePluginRuntimeCapabilities(ctx, snapshot.Plugin, req.Now),
	); err != nil {
		return SecurityPolicyResult{}, mutation.Unknown(err)
	}
	if snapshot.Policy == nil {
		return SecurityPolicyResult{}, mutation.Unknown(errors.New("committed security policy is missing from authorization snapshot"))
	}
	return securityPolicyResult(snapshot), nil
}

func (h *Host) GetSecurityPolicy(ctx context.Context, req GetSecurityPolicyRequest) (SecurityPolicyResult, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return SecurityPolicyResult{}, err
	}
	snapshot, err := h.adapters.Registry.GetAuthorization(ctx, req.PluginInstanceID)
	if err != nil {
		return SecurityPolicyResult{}, err
	}
	if snapshot.Policy == nil {
		return SecurityPolicyResult{}, security.ErrPolicyNotFound
	}
	return securityPolicyResult(snapshot), nil
}

func (h *Host) ListSecurityPolicies(ctx context.Context) ([]SecurityPolicyResult, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return nil, err
	}
	snapshots, err := h.adapters.Registry.ListAuthorization(ctx)
	if err != nil {
		return nil, err
	}
	policies := make([]SecurityPolicyResult, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.Policy != nil {
			policies = append(policies, securityPolicyResult(snapshot))
		}
	}
	return policies, nil
}

func securityPolicyResult(snapshot registry.AuthorizationSnapshot) SecurityPolicyResult {
	return SecurityPolicyResult{
		Policy:    *snapshot.Policy,
		Revisions: registry.AuthorizationRevisionsFromRecord(snapshot.Plugin),
	}
}

func (h *Host) DeleteSecurityPolicy(ctx context.Context, req DeleteSecurityPolicyRequest) (result registry.AuthorizationRevisions, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return registry.AuthorizationRevisions{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.AuthorizationRevisions{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.security_policy.deleted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return registry.AuthorizationRevisions{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	snapshot, err := h.adapters.Registry.DeleteSecurityPolicy(
		ctx,
		record.PluginInstanceID,
		req.Now,
		authorizationRevisions(req.ExpectedPolicyRevision, req.ExpectedManagementRevision, req.ExpectedRevokeEpoch),
	)
	if err != nil {
		return registry.AuthorizationRevisions{}, err
	}
	if err := errors.Join(
		h.refreshConnectivityPolicy(ctx, snapshot.Plugin),
		h.revokePluginRuntimeCapabilities(ctx, snapshot.Plugin, req.Now),
	); err != nil {
		return registry.AuthorizationRevisions{}, mutation.Unknown(err)
	}
	return registry.AuthorizationRevisionsFromRecord(snapshot.Plugin), nil
}

func authorizationRevisions(policyRevision, managementRevision, revokeEpoch uint64) registry.AuthorizationRevisions {
	return registry.AuthorizationRevisions{
		PolicyRevision:     policyRevision,
		ManagementRevision: managementRevision,
		RevokeEpoch:        revokeEpoch,
	}
}

func permissionGrantFromSnapshot(snapshot registry.AuthorizationSnapshot, permissionID string) (permissions.Record, error) {
	permissionID = strings.TrimSpace(permissionID)
	for _, grant := range snapshot.Grants {
		if grant.PermissionID == permissionID {
			return grant, nil
		}
	}
	return permissions.Record{}, mutation.Unknown(errors.New("committed permission grant is missing from authorization snapshot"))
}

func activePermissionGrant(record permissions.Record, now time.Time) bool {
	return record.Effect == permissions.EffectGrant && record.RevokedAt == nil &&
		(record.ExpiresAt == nil || record.ExpiresAt.After(now))
}

func (h *Host) ListDiagnosticEvents(ctx context.Context, req ListDiagnosticEventsRequest) ([]DiagnosticEvent, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return nil, err
	}
	lister, ok := h.adapters.Diagnostics.(DiagnosticLister)
	if !ok {
		return nil, errors.New("diagnostic event lister is unavailable")
	}
	if req.Severity != "" && !req.Severity.Valid() {
		return nil, observability.ErrInvalidDiagnosticSeverity
	}
	events, err := lister.ListPluginDiagnostics(ctx, observability.ListDiagnosticRequest{
		PluginID:             req.PluginID,
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     session.OwnerSessionHash,
		OwnerUserHash:        session.OwnerUserHash,
		OwnerEnvHash:         session.OwnerEnvHash,
		SessionChannelIDHash: session.SessionChannelIDHash,
		Type:                 req.Type,
		Severity:             req.Severity,
		Limit:                req.Limit,
	})
	if err != nil {
		return nil, err
	}
	pluginID := strings.TrimSpace(req.PluginID)
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	surfaceInstanceID := strings.TrimSpace(req.SurfaceInstanceID)
	eventType := strings.TrimSpace(req.Type)
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	filtered := make([]DiagnosticEvent, 0, len(events))
	for _, event := range events {
		if event.OwnerSessionHash != session.OwnerSessionHash ||
			event.OwnerUserHash != session.OwnerUserHash ||
			event.OwnerEnvHash != session.OwnerEnvHash ||
			event.SessionChannelIDHash != session.SessionChannelIDHash {
			continue
		}
		if pluginID != "" && event.PluginID != pluginID ||
			pluginInstanceID != "" && event.PluginInstanceID != pluginInstanceID ||
			surfaceInstanceID != "" && event.SurfaceInstanceID != surfaceInstanceID ||
			eventType != "" && event.Type != eventType ||
			req.Severity != "" && event.Severity != req.Severity ||
			!event.Severity.Valid() {
			continue
		}
		filtered = append(filtered, DiagnosticEvent{
			EventID:           event.EventID,
			Type:              event.Type,
			Severity:          event.Severity,
			Message:           event.Message,
			PluginID:          event.PluginID,
			PluginInstanceID:  event.PluginInstanceID,
			SurfaceID:         event.SurfaceID,
			SurfaceInstanceID: event.SurfaceInstanceID,
			ActiveFingerprint: event.ActiveFingerprint,
			RequestID:         event.RequestID,
			OccurredAt:        event.OccurredAt,
			Details:           cloneAnyMap(event.Details),
		})
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].OccurredAt.Equal(filtered[j].OccurredAt) {
			return filtered[i].EventID > filtered[j].EventID
		}
		return filtered[i].OccurredAt.After(filtered[j].OccurredAt)
	})
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered, nil
}

func (h *Host) ListOperations(ctx context.Context, req ListOperationsRequest) (ListOperationsResult, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return ListOperationsResult{}, err
	}
	cursor, err := operation.DecodeCursor(req.Cursor)
	if err != nil {
		return ListOperationsResult{}, err
	}
	page, err := h.adapters.Operations.List(ctx, operation.ListRequest{
		PluginInstanceID: req.PluginInstanceID,
		Cursor:           cursor,
		Limit:            req.Limit,
		Owner:            operationOwnerScope(session),
	})
	if err != nil {
		return ListOperationsResult{}, err
	}
	nextCursor, err := operation.EncodeCursor(page.NextCursor)
	if err != nil {
		return ListOperationsResult{}, err
	}
	return ListOperationsResult{Operations: page.Records, NextCursor: nextCursor}, nil
}

func (h *Host) StartRuntime(ctx context.Context, req StartRuntimeRequest) (result runtimeclient.ManagerHealth, retErr error) {
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	defer releaseOpen()
	if err := h.requireFeature(FeatureRuntime); err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	if h.adapters.RuntimeManager == nil {
		return runtimeclient.ManagerHealth{}, ErrPluginRuntimeNotConfigured
	}
	target := runtimeclient.Target{OS: req.Target.OS, Arch: req.Target.Arch}
	if err := runtimeclient.ValidateTarget(target); err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	descriptor, err := h.adapters.RuntimeManager.Preflight(ctx, target)
	if err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	records, err := h.adapters.Registry.ListPlugins(ctx)
	if err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	for _, record := range records {
		if record.EnableState != registry.EnableEnabled || !pluginHasWorkers(record.Manifest) {
			continue
		}
		if err := validateWorkerRuntimeDescriptor(record, descriptor, target); err != nil {
			return runtimeclient.ManagerHealth{}, fmt.Errorf("plugin %q: %w", record.PluginInstanceID, err)
		}
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.runtime.started"})
	if err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	health, err := h.adapters.RuntimeManager.Start(ctx, target)
	if err != nil {
		if errors.Is(err, runtimeclient.ErrManagerLifecycleOutcomeUnknown) {
			return runtimeclient.ManagerHealth{}, mutation.Unknown(err)
		}
		return runtimeclient.ManagerHealth{}, err
	}
	if err := validateRuntimeManagerHealth(health, descriptor); err != nil {
		return runtimeclient.ManagerHealth{}, fmt.Errorf("%w: started runtime health: %v", ErrPluginRuntimeIncompatible, err)
	}
	return health, nil
}

func (h *Host) StopRuntime(ctx context.Context) (retErr error) {
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return err
	}
	defer releaseOpen()
	if err := h.requireFeature(FeatureRuntime); err != nil {
		return err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.runtime.stopped"})
	if err != nil {
		return err
	}
	var auditDetails map[string]any
	defer func() { retErr = auditMutation.completeWithDetails(context.WithoutCancel(ctx), retErr, auditDetails) }()
	var stopErr error
	if h.adapters.RuntimeManager != nil {
		stopErr = h.adapters.RuntimeManager.Stop(ctx)
	}
	revokedSurfaces := h.surfaceTokens.RevokeSurfacesExceptGeneration(h.surfaceGenerationID, time.Time{})
	auditDetails = map[string]any{"revoked_surface_count": revokedSurfaces}
	if stopErr != nil {
		h.diagnostic(ctx, observability.DiagnosticEvent{
			Type:            "plugin.runtime.stop_failed",
			Severity:        "warning",
			Message:         "plugin runtime stop failed",
			InternalDetails: map[string]any{"error": stopErr.Error()},
		})
	}
	if stopErr != nil {
		return mutation.Unknown(stopErr)
	}
	return nil
}

func (h *Host) RuntimeHealth(ctx context.Context) (runtimeclient.ManagerHealth, error) {
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	defer releaseOpen()
	if err := h.requireFeature(FeatureRuntime); err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	if h.adapters.RuntimeManager == nil {
		return runtimeclient.ManagerHealth{}, ErrPluginRuntimeNotConfigured
	}
	health, err := h.adapters.RuntimeManager.Health(ctx)
	if err != nil || !health.Ready {
		return health, err
	}
	if err := validateRuntimeManagerHealth(health, health.Descriptor); err != nil {
		return runtimeclient.ManagerHealth{}, err
	}
	return health, nil
}

func (h *Host) requireSurfaceRuntimeGeneration(ctx context.Context, pluginInstanceID, surfaceInstanceID, boundGenerationID string, now time.Time) error {
	record, err := h.adapters.Registry.GetPlugin(ctx, pluginInstanceID)
	if err != nil {
		return err
	}
	currentGenerationID := h.surfaceGenerationID
	if pluginHasWorkers(record.Manifest) {
		binding, err := h.bindCompatibleWorkerRuntime(ctx, record)
		if err != nil {
			return err
		}
		currentGenerationID = binding.RuntimeGenerationID
	}
	if strings.TrimSpace(boundGenerationID) == currentGenerationID {
		return nil
	}
	h.surfaceTokens.DisposeSurface(surfaceInstanceID, now)
	return bridge.ErrTokenRevoked
}

func (h *Host) GetOperation(ctx context.Context, operationID string) (operation.Record, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return operation.Record{}, err
	}
	record, err := h.adapters.Operations.Get(ctx, operationID)
	if err != nil {
		return operation.Record{}, err
	}
	if !operationOwnedBySession(record, session) {
		return operation.Record{}, operation.ErrNotFound
	}
	return record, nil
}

func (h *Host) CancelOperation(ctx context.Context, req CancelOperationRequest) (result operation.Record, retErr error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return operation.Record{}, err
	}
	current, err := h.adapters.Operations.Get(ctx, req.OperationID)
	if err != nil {
		return operation.Record{}, err
	}
	if !operationOwnedBySession(current, session) {
		return operation.Record{}, operation.ErrNotFound
	}
	if operationTerminal(current.Status) {
		return current, nil
	}
	if !current.Cancelable {
		return operation.Record{}, operation.ErrNotCancelable
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.operation.cancel_requested", PluginID: current.PluginID, PluginInstanceID: current.PluginInstanceID})
	if err != nil {
		return operation.Record{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	record, err := h.adapters.Operations.RequestCancel(ctx, operation.CancelRequest{
		OperationID: req.OperationID,
		Reason:      req.Reason,
		Now:         req.Now,
	})
	if err != nil {
		return operation.Record{}, err
	}
	if err := h.dispatchOperationCancellation(ctx, record, req.Reason, req.Now, errors.New("operation cancellation requested")); err != nil {
		return record, mutation.Unknown(err)
	}
	return record, nil
}

func operationOwnerScope(session sessionctx.Context) operation.OwnerScope {
	return operation.OwnerScope{
		OwnerSessionHash:     strings.TrimSpace(session.OwnerSessionHash),
		OwnerUserHash:        strings.TrimSpace(session.OwnerUserHash),
		OwnerEnvHash:         strings.TrimSpace(session.OwnerEnvHash),
		SessionChannelIDHash: strings.TrimSpace(session.SessionChannelIDHash),
	}
}

func operationOwnedBySession(record operation.Record, session sessionctx.Context) bool {
	return operationOwnerScope(session) == (operation.OwnerScope{
		OwnerSessionHash:     record.OwnerSessionHash,
		OwnerUserHash:        record.OwnerUserHash,
		OwnerEnvHash:         record.OwnerEnvHash,
		SessionChannelIDHash: record.SessionChannelIDHash,
	})
}

func (h *Host) dispatchOperationCancellation(ctx context.Context, record operation.Record, reason string, now time.Time, cause error) error {
	matched, dispatchErr := h.executions.cancelOperation(ctx, capability.OperationCancellation{
		Execution:   capability.ExecutionContext{ExecutionBinding: record.ExecutionBinding},
		OperationID: record.OperationID,
		Reason:      reason,
		RequestedAt: lifecycleNow(now),
	}, cause)
	if dispatchErr != nil {
		return fmt.Errorf("%w: %w", ErrOperationCancelDispatchFailed, dispatchErr)
	}
	if !matched {
		h.armDetachedOperationCancelAckTimeout(record)
	}
	return nil
}

func (h *Host) CancelSurfaceOperation(ctx context.Context, req CancelSurfaceOperationRequest) (operation.Record, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return operation.Record{}, err
	}
	record, err := h.adapters.Operations.Get(ctx, req.OperationID)
	if err != nil {
		return operation.Record{}, err
	}
	if record.SurfaceInstanceID != req.SurfaceInstanceID ||
		record.OwnerSessionHash != session.OwnerSessionHash ||
		record.OwnerUserHash != session.OwnerUserHash ||
		record.OwnerEnvHash != session.OwnerEnvHash ||
		record.SessionChannelIDHash != session.SessionChannelIDHash ||
		record.BridgeChannelID != req.BridgeChannelID {
		return operation.Record{}, bridge.ErrTokenAudience
	}
	return h.CancelOperation(ctx, CancelOperationRequest{OperationID: req.OperationID, Reason: req.Reason, Now: req.Now})
}

func (h *Host) armDetachedOperationCancelAckTimeout(record operation.Record) {
	if record.CancelAckTimeoutMS <= 0 {
		return
	}
	if _, loaded := h.detachedCancelJobs.LoadOrStore(record.OperationID, struct{}{}); loaded {
		return
	}
	timeout := time.Duration(record.CancelAckTimeoutMS) * time.Millisecond
	started := h.startLifecycleJob(func(ctx context.Context) {
		defer h.detachedCancelJobs.Delete(record.OperationID)
		if !waitForCancellationReconcile(ctx, timeout) {
			return
		}
		current, err := h.adapters.Operations.Get(ctx, record.OperationID)
		if errors.Is(err, operation.ErrNotFound) || (err == nil && current.Status != operation.StatusCancelRequested) {
			return
		}
		if err != nil {
			return
		}
		if current.StreamID != "" {
			closed, closeErr := h.adapters.Streams.Close(ctx, stream.CloseRequest{
				StreamID: current.StreamID, Status: stream.StatusCanceled, Reason: "cancellation acknowledgement timed out",
			})
			if closeErr != nil {
				return
			}
			status, ok := operationStatusForStreamStatus(closed.Status)
			if !ok {
				return
			}
			current.Status = status
			current.Reason = closed.Reason
		} else {
			current.Status = operation.StatusCanceled
			current.Reason = "cancellation acknowledgement timed out"
		}
		finished, err := h.adapters.Operations.Finish(ctx, operation.FinishRequest{
			OperationID: current.OperationID, Status: current.Status, Reason: current.Reason,
		})
		if err == nil {
			if auditErr := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operation.finished", PluginID: finished.PluginID, PluginInstanceID: finished.PluginInstanceID, Details: map[string]any{"operation_id": finished.OperationID, "status": finished.Status}}); auditErr != nil {
				h.diagnostic(ctx, observability.DiagnosticEvent{Type: "plugin.security_event.persistence_failed", Severity: observability.DiagnosticSeverityWarning, Message: "security event persistence failed", InternalDetails: map[string]any{"error": auditErr.Error()}})
			}
		}
	})
	if !started {
		h.detachedCancelJobs.Delete(record.OperationID)
	}
}

func (h *Host) ReadStream(ctx context.Context, req ReadStreamRequest) (ReadStreamResult, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return ReadStreamResult{}, err
	}
	if strings.TrimSpace(req.StreamTicket) == "" {
		return ReadStreamResult{}, ErrStreamTicketRequired
	}
	if strings.TrimSpace(req.ReadID) == "" {
		return ReadStreamResult{}, stream.ErrInvalidStream
	}
	release, err := h.streamReads.acquire(ctx, req.StreamID)
	if err != nil {
		return ReadStreamResult{}, err
	}
	defer release()

	now := lifecycleNow(req.Now)
	record, _, validation, err := h.resolveStreamReadAuthorization(ctx, req, session, now)
	if err != nil {
		return ReadStreamResult{}, err
	}
	if _, err := h.surfaceTokens.InspectBoundStreamTicket(validation); err != nil {
		return ReadStreamResult{}, err
	}
	if record.Status == stream.StatusOpen && req.WaitTimeout > 0 {
		_, delivery, deliverErr := h.adapters.Streams.Deliver(ctx, stream.DeliverRequest{
			StreamID: req.StreamID, ReadID: req.ReadID, MaxEvents: req.MaxEvents, MaxBytes: req.MaxBytes,
		})
		if deliverErr != nil {
			return ReadStreamResult{}, deliverErr
		}
		if delivery.DeliveryID == "" {
			waitCtx, cancel := context.WithTimeout(ctx, req.WaitTimeout)
			err = h.adapters.Streams.Wait(waitCtx, req.StreamID)
			cancel()
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				return ReadStreamResult{}, err
			}
		}
	}

	releaseLifecycle, err := h.lifecycleLocks.acquireRead(ctx, record.PluginInstanceID)
	if err != nil {
		return ReadStreamResult{}, err
	}
	defer releaseLifecycle()
	now = lifecycleNow(req.Now)
	record, _, validation, err = h.resolveStreamReadAuthorization(ctx, req, session, now)
	if err != nil {
		return ReadStreamResult{}, err
	}
	if _, err := h.surfaceTokens.InspectBoundStreamTicket(validation); err != nil {
		return ReadStreamResult{}, err
	}
	record, delivery, err := h.adapters.Streams.Deliver(ctx, stream.DeliverRequest{
		StreamID: req.StreamID, ReadID: req.ReadID, MaxEvents: req.MaxEvents, MaxBytes: req.MaxBytes,
	})
	if err != nil {
		return ReadStreamResult{}, err
	}
	return readStreamResult(record, delivery), nil
}

func readStreamResult(record stream.Record, delivery stream.Delivery) ReadStreamResult {
	return ReadStreamResult{
		Record: record, DeliveryID: delivery.DeliveryID, ReadID: delivery.ReadID,
		Events: delivery.Events, Done: delivery.Done, TerminalStatus: delivery.TerminalStatus,
	}
}

func (h *Host) AcknowledgeStream(ctx context.Context, req AcknowledgeStreamRequest) (stream.Record, error) {
	session, err := requireUserSession(ctx)
	if err != nil {
		return stream.Record{}, err
	}
	if strings.TrimSpace(req.StreamTicket) == "" {
		return stream.Record{}, ErrStreamTicketRequired
	}
	if strings.TrimSpace(req.DeliveryID) == "" {
		return stream.Record{}, stream.ErrDeliveryInvalid
	}
	release, err := h.streamReads.acquire(ctx, req.StreamID)
	if err != nil {
		return stream.Record{}, err
	}
	defer release()
	readReq := ReadStreamRequest{
		StreamID: req.StreamID, StreamTicket: req.StreamTicket,
		SurfaceInstanceID: req.SurfaceInstanceID, Now: req.Now,
	}
	streamRecord, _, _, err := h.resolveStreamReadAuthorization(ctx, readReq, session, lifecycleNow(req.Now))
	if err != nil {
		return stream.Record{}, err
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireRead(ctx, streamRecord.PluginInstanceID)
	if err != nil {
		return stream.Record{}, err
	}
	defer releaseLifecycle()
	_, _, validation, err := h.resolveStreamReadAuthorization(ctx, readReq, session, lifecycleNow(req.Now))
	if err != nil {
		return stream.Record{}, err
	}
	if _, err := h.surfaceTokens.InspectBoundStreamTicket(validation); err != nil {
		return stream.Record{}, err
	}
	record, err := h.adapters.Streams.Acknowledge(ctx, stream.AcknowledgeRequest{StreamID: req.StreamID, DeliveryID: req.DeliveryID})
	if err == nil && record.Status != stream.StatusOpen {
		h.maintainTerminalExecutionRecords(ctx, time.Now().UTC())
	}
	return record, err
}

func (h *Host) resolveStreamReadAuthorization(ctx context.Context, req ReadStreamRequest, session sessionctx.Context, now time.Time) (stream.Record, registry.PluginRecord, bridge.ValidateBoundStreamTicketRequest, error) {
	record, err := h.adapters.Streams.Get(ctx, req.StreamID)
	if err != nil {
		return stream.Record{}, registry.PluginRecord{}, bridge.ValidateBoundStreamTicketRequest{}, err
	}
	if record.SurfaceInstanceID != req.SurfaceInstanceID ||
		record.OwnerSessionHash != session.OwnerSessionHash ||
		record.OwnerUserHash != session.OwnerUserHash ||
		record.OwnerEnvHash != session.OwnerEnvHash ||
		record.SessionChannelIDHash != session.SessionChannelIDHash {
		return stream.Record{}, registry.PluginRecord{}, bridge.ValidateBoundStreamTicketRequest{}, bridge.ErrTokenAudience
	}
	plugin, err := h.adapters.Registry.GetPlugin(ctx, record.PluginInstanceID)
	if err != nil {
		return stream.Record{}, registry.PluginRecord{}, bridge.ValidateBoundStreamTicketRequest{}, err
	}
	return record, plugin, bridge.ValidateBoundStreamTicketRequest{
		StreamTicket:         req.StreamTicket,
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		PluginVersion:        plugin.Version,
		ActiveFingerprint:    plugin.ActiveFingerprint,
		SurfaceInstanceID:    record.SurfaceInstanceID,
		OwnerSessionHash:     record.OwnerSessionHash,
		OwnerUserHash:        record.OwnerUserHash,
		OwnerEnvHash:         record.OwnerEnvHash,
		SessionChannelIDHash: record.SessionChannelIDHash,
		BridgeChannelID:      record.BridgeChannelID,
		StreamID:             record.StreamID,
		OperationID:          record.OperationID,
		StreamDirection:      string(record.Direction),
		Method:               record.Method,
		Revision: bridge.RevisionBinding{
			PolicyRevision:     plugin.PolicyRevision,
			ManagementRevision: plugin.ManagementRevision,
			RevokeEpoch:        plugin.RevokeEpoch,
		},
		Now: now,
	}, nil
}

func (h *Host) MintConnectionGrant(ctx context.Context, req MintConnectionGrantRequest) (result connectivity.ConnectionGrant, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return connectivity.ConnectionGrant{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.connectivity.grant_minted", PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return connectivity.ConnectionGrant{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	_, grant, err := h.mintConnectionGrant(ctx, req)
	if err != nil {
		return connectivity.ConnectionGrant{}, err
	}
	return grant, nil
}

func (h *Host) mintConnectionGrant(ctx context.Context, req MintConnectionGrantRequest) (registry.PluginRecord, connectivity.ConnectionGrant, error) {
	if err := h.requireFeature(FeatureConnectivity); err != nil {
		return registry.PluginRecord{}, connectivity.ConnectionGrant{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, connectivity.ConnectionGrant{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		return registry.PluginRecord{}, connectivity.ConnectionGrant{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return registry.PluginRecord{}, connectivity.ConnectionGrant{}, err
	}
	grant, err := h.adapters.Connectivity.MintConnectionGrant(ctx, connectivity.GrantRequest{
		PluginInstanceID:    record.PluginInstanceID,
		ActiveFingerprint:   record.ActiveFingerprint,
		PolicyRevision:      record.PolicyRevision,
		ManagementRevision:  record.ManagementRevision,
		RevokeEpoch:         record.RevokeEpoch,
		ConnectorID:         req.ConnectorID,
		Transport:           req.Transport,
		Destination:         req.Destination,
		RuntimeGenerationID: req.RuntimeGenerationID,
		Now:                 req.Now,
		TTL:                 req.TTL,
	})
	if err != nil {
		return registry.PluginRecord{}, connectivity.ConnectionGrant{}, err
	}
	return record, grant, nil
}

func (h *Host) MintNetworkHandleGrant(ctx context.Context, req MintConnectionGrantRequest) (result NetworkHandleGrantResult, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return NetworkHandleGrantResult{}, err
	}
	if strings.TrimSpace(req.RuntimeGenerationID) == "" {
		return NetworkHandleGrantResult{}, bridge.ErrMissingTokenAudience
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.connectivity.handle_grant_minted", PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return NetworkHandleGrantResult{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	_, grant, err := h.mintConnectionGrant(ctx, req)
	if err != nil {
		return NetworkHandleGrantResult{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = bridge.DefaultHandleGrantTTL
	}
	expiresAt := now.Add(ttl)
	if grant.ExpiresAt.Before(expiresAt) {
		expiresAt = grant.ExpiresAt
	}
	handleGrant, err := h.surfaceTokens.MintHandleGrant(bridge.MintHandleGrantRequest{
		PluginInstanceID:    grant.PluginInstanceID,
		ActiveFingerprint:   grant.ActiveFingerprint,
		RuntimeInstanceID:   req.RuntimeInstanceID,
		RuntimeGenerationID: req.RuntimeGenerationID,
		RuntimeShardID:      req.RuntimeShardID,
		HandleID:            grant.GrantID,
		Method:              "network." + string(grant.Transport),
		Revision: bridge.RevisionBinding{
			PolicyRevision:     grant.PolicyRevision,
			ManagementRevision: grant.ManagementRevision,
			RevokeEpoch:        grant.RevokeEpoch,
		},
		Limits:    bridge.Limits{MaxTotalBytes: 0},
		Now:       now,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return NetworkHandleGrantResult{}, err
	}
	return NetworkHandleGrantResult{ConnectionGrant: grant, HandleGrant: handleGrant}, nil
}

func (h *Host) MintStorageHandleGrant(ctx context.Context, req MintStorageHandleGrantRequest) (result StorageHandleGrantResult, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return StorageHandleGrantResult{}, err
	}
	if strings.TrimSpace(req.RuntimeGenerationID) == "" || strings.TrimSpace(req.StoreID) == "" {
		return StorageHandleGrantResult{}, bridge.ErrMissingTokenAudience
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.storage.handle_grant_minted", PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return StorageHandleGrantResult{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return StorageHandleGrantResult{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		return StorageHandleGrantResult{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return StorageHandleGrantResult{}, err
	}
	namespace, ok, err := storageNamespaceByStoreID(record, req.StoreID)
	if err != nil {
		return StorageHandleGrantResult{}, err
	}
	if !ok {
		return StorageHandleGrantResult{}, storage.ErrNamespaceNotFound
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = bridge.DefaultHandleGrantTTL
	}
	handleGrant, err := h.surfaceTokens.MintHandleGrant(bridge.MintHandleGrantRequest{
		PluginInstanceID:    record.PluginInstanceID,
		ActiveFingerprint:   record.ActiveFingerprint,
		RuntimeInstanceID:   req.RuntimeInstanceID,
		RuntimeGenerationID: req.RuntimeGenerationID,
		RuntimeShardID:      req.RuntimeShardID,
		HandleID:            "storage:" + namespace.StoreID,
		Method:              "storage." + string(namespace.Kind),
		Revision: bridge.RevisionBinding{
			PolicyRevision:     record.PolicyRevision,
			ManagementRevision: record.ManagementRevision,
			RevokeEpoch:        record.RevokeEpoch,
		},
		Limits:    bridge.Limits{MaxTotalBytes: namespace.QuotaBytes},
		Now:       now,
		ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		return StorageHandleGrantResult{}, err
	}
	return StorageHandleGrantResult{Namespace: namespace, HandleGrant: handleGrant}, nil
}

func (h *Host) EnablePlugin(ctx context.Context, req EnableRequest) (result registry.PluginRecord, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer releaseLifecycle()
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := requireManagementRevision(record, req.ExpectedManagementRevision); err != nil {
		return registry.PluginRecord{}, err
	}
	if record.Manifest.Plugin.UIProtocolVersion != version.PluginUIProtocolVersion {
		return registry.PluginRecord{}, fmt.Errorf("%w: installed %s, required %s", ErrPluginUIProtocolUnsupported, record.Manifest.Plugin.UIProtocolVersion, version.PluginUIProtocolVersion)
	}
	if err := h.canRun(ctx, record); err != nil {
		return registry.PluginRecord{}, err
	}
	if _, _, err := compileConnectivityPolicy(record); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.preflightWorkerRuntime(ctx, record); err != nil {
		return registry.PluginRecord{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.enabled", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	shape, err := plugindata.ShapeFromManifest(record.Manifest)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	initialSettings, err := settings.DefaultValues(shape.Settings.Fields)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if _, err := h.adapters.PluginData.CommitEnable(ctx, plugindata.CommitEnableRequest{
		PluginInstanceID:           record.PluginInstanceID,
		Shape:                      shape,
		InitialSettings:            initialSettings,
		ExpectedManagementRevision: record.ManagementRevision,
		Now:                        req.Now,
	}); err != nil {
		return registry.PluginRecord{}, managementMutationError(record, err)
	}
	enabled, err := h.adapters.Registry.GetPlugin(ctx, record.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	connectivityPolicy, hasConnectivityPolicy, err := compileConnectivityPolicy(enabled)
	if err != nil {
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	if err := h.installConnectivityPolicy(ctx, enabled, connectivityPolicy, hasConnectivityPolicy); err != nil {
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	if h.adapters.SurfaceCatalog != nil {
		if err := h.adapters.SurfaceCatalog.PublishSurfaces(ctx, SurfaceSnapshot{
			PluginInstanceID:  enabled.PluginInstanceID,
			ActiveFingerprint: enabled.ActiveFingerprint,
			Surfaces:          enabled.Manifest.Surfaces,
		}); err != nil {
			return registry.PluginRecord{}, mutation.Unknown(err)
		}
	}
	return enabled, nil
}

func (h *Host) DisablePlugin(ctx context.Context, req DisableRequest) (result registry.PluginRecord, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer releaseLifecycle()
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := requireManagementRevision(record, req.ExpectedManagementRevision); err != nil {
		return registry.PluginRecord{}, err
	}
	reason := req.Reason
	if reason == "" {
		reason = "disabled"
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.disabled", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	disabled, err := h.adapters.Registry.SetEnableState(ctx, req.PluginInstanceID, registry.EnableDisabled, reason, req.Now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	operations, err := h.adapters.Operations.MarkPluginDisabled(ctx, operation.PluginTransitionRequest{
		PluginInstanceID: disabled.PluginInstanceID,
		Reason:           reason,
		Now:              req.Now,
	})
	if err != nil {
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	if h.adapters.SurfaceCatalog != nil {
		if err := h.adapters.SurfaceCatalog.PublishSurfaces(ctx, SurfaceSnapshot{
			PluginInstanceID:  disabled.PluginInstanceID,
			ActiveFingerprint: disabled.ActiveFingerprint,
			Surfaces:          nil,
		}); err != nil {
			return registry.PluginRecord{}, mutation.Unknown(err)
		}
	}
	if len(operations) > 0 {
		if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operations.disabled_transitioned", PluginID: disabled.PluginID, PluginInstanceID: disabled.PluginInstanceID}); err != nil {
			return registry.PluginRecord{}, mutation.Unknown(err)
		}
	}
	streams, err := h.adapters.Streams.MarkPluginTransition(ctx, stream.PluginTransitionRequest{
		PluginInstanceID: disabled.PluginInstanceID,
		Status:           stream.StatusOrphanedDisabled,
		Reason:           reason,
		Now:              req.Now,
	})
	if err != nil {
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	if streams.Changed > 0 {
		if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.streams.disabled_transitioned", PluginID: disabled.PluginID, PluginInstanceID: disabled.PluginInstanceID}); err != nil {
			return registry.PluginRecord{}, mutation.Unknown(err)
		}
	}
	var revokeErr error
	if err := h.revokePluginRuntimeCapabilities(ctx, disabled, req.Now); err != nil {
		revokeErr = err
	}
	if h.adapters.Connectivity != nil {
		revokeErr = errors.Join(revokeErr, h.adapters.Connectivity.RemovePolicy(ctx, disabled.PluginInstanceID))
	}
	if revokeErr != nil {
		return registry.PluginRecord{}, mutation.Unknown(revokeErr)
	}
	return disabled, nil
}

func (h *Host) UninstallPlugin(ctx context.Context, req UninstallRequest) (result registry.PluginRecord, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer releaseLifecycle()
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := requireManagementRevision(record, req.ExpectedManagementRevision); err != nil {
		return registry.PluginRecord{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.uninstalled", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, Details: map[string]any{"delete_data": req.DeleteData}})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	operations, err := h.adapters.Operations.MarkPluginUninstalled(ctx, operation.PluginTransitionRequest{
		PluginInstanceID: record.PluginInstanceID,
		Reason:           "uninstalled",
		Now:              req.Now,
	})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	for _, operationRecord := range operations {
		if operationRecord.Status == operation.StatusCancelRequested {
			if err := h.dispatchOperationCancellation(ctx, operationRecord, operationRecord.Reason, req.Now, errors.New("plugin uninstall cancellation requested")); err != nil {
				return registry.PluginRecord{}, mutation.Unknown(err)
			}
		}
	}
	if req.DeleteData && operationsBlockDelete(operations) {
		if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operations.delete_blocked", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID}); err != nil {
			return registry.PluginRecord{}, mutation.Unknown(errors.Join(operation.ErrDeleteBlocked, err))
		}
		return registry.PluginRecord{}, mutation.Unknown(operation.ErrDeleteBlocked)
	}
	commit, err := h.adapters.PluginData.CommitUninstall(ctx, plugindata.CommitUninstallRequest{
		PluginInstanceID:           record.PluginInstanceID,
		DeleteData:                 req.DeleteData,
		ExpectedManagementRevision: record.ManagementRevision,
		Now:                        req.Now,
	})
	if err != nil {
		return registry.PluginRecord{}, managementMutationError(record, err)
	}
	record.EnableState = registry.EnableDisabled
	record.DisabledReason = "uninstalled"
	record.ManagementRevision = commit.ManagementRevision
	record.RevokeEpoch = commit.RevokeEpoch
	record.EnabledAt = nil
	record.UpdatedAt = commit.DeletedAt
	record.DeletedAt = &commit.DeletedAt

	var derivedErr error
	if err := h.adapters.Connectivity.RemovePolicy(ctx, record.PluginInstanceID); err != nil {
		derivedErr = errors.Join(derivedErr, err)
	}
	if h.adapters.SurfaceCatalog != nil {
		if err := h.adapters.SurfaceCatalog.PublishSurfaces(ctx, SurfaceSnapshot{PluginInstanceID: record.PluginInstanceID, ActiveFingerprint: record.ActiveFingerprint}); err != nil {
			derivedErr = errors.Join(derivedErr, err)
		}
	}
	streams, err := h.adapters.Streams.MarkPluginTransition(ctx, stream.PluginTransitionRequest{
		PluginInstanceID: record.PluginInstanceID,
		Status:           stream.StatusOrphanedRemoved,
		Reason:           "uninstalled",
		Now:              req.Now,
	})
	if err != nil {
		derivedErr = errors.Join(derivedErr, err)
	}
	if err := h.revokePluginRuntimeCapabilities(ctx, record, req.Now); err != nil {
		derivedErr = errors.Join(derivedErr, err)
	}
	if err := h.deleteSecretBindingsIfNeeded(ctx, record, req.DeleteData); err != nil {
		derivedErr = errors.Join(derivedErr, err)
	}
	if len(operations) > 0 {
		if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.operations.uninstalled_transitioned", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID}); err != nil {
			derivedErr = errors.Join(derivedErr, err)
		}
	}
	if streams.Changed > 0 {
		if err := h.recordSecurityEvent(ctx, AuditEvent{Type: "plugin.streams.uninstalled_transitioned", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID}); err != nil {
			derivedErr = errors.Join(derivedErr, err)
		}
	}
	if derivedErr != nil {
		return registry.PluginRecord{}, mutation.Unknown(derivedErr)
	}
	return record, nil
}

func (h *Host) ListRetainedData(ctx context.Context, req ListRetainedDataRequest) ([]plugindata.Binding, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return nil, err
	}
	return h.adapters.PluginData.ListRetained(ctx, plugindata.RetainedFilter{PluginInstanceID: req.PluginInstanceID})
}

func (h *Host) DeleteRetainedData(ctx context.Context, req DeleteRetainedDataRequest) (result plugindata.Binding, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return plugindata.Binding{}, err
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, req.PluginInstanceID)
	if err != nil {
		return plugindata.Binding{}, err
	}
	defer releaseLifecycle()
	records, err := h.adapters.PluginData.ListRetained(ctx, plugindata.RetainedFilter{PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return plugindata.Binding{}, err
	}
	if len(records) != 1 {
		return plugindata.Binding{}, plugindata.ErrBindingNotFound
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.retained_data.deleted", PluginInstanceID: req.PluginInstanceID})
	if err != nil {
		return plugindata.Binding{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	if err := h.adapters.PluginData.DeleteRetained(ctx, plugindata.DeleteRetainedRequest{PluginInstanceID: req.PluginInstanceID, ExpectedBindingRevision: req.ExpectedBindingRevision}); err != nil {
		return plugindata.Binding{}, err
	}
	return records[0], nil
}

func (h *Host) BindRetainedData(ctx context.Context, req BindRetainedDataRequest) (result plugindata.Binding, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return plugindata.Binding{}, err
	}
	targetPluginInstanceID := strings.TrimSpace(req.TargetPluginInstanceID)
	if strings.TrimSpace(req.SourcePluginInstanceID) == "" || targetPluginInstanceID == "" || req.ExpectedSourceBindingRevision == 0 || req.TargetExpectedManagementRevision == 0 {
		return plugindata.Binding{}, plugindata.ErrInvalidArgument
	}
	releaseLifecycle, err := h.lifecycleLocks.acquireWriteMany(ctx, req.SourcePluginInstanceID, targetPluginInstanceID)
	if err != nil {
		return plugindata.Binding{}, err
	}
	defer releaseLifecycle()
	target, err := h.adapters.Registry.GetPlugin(ctx, targetPluginInstanceID)
	if err != nil {
		return plugindata.Binding{}, err
	}
	if err := requireManagementRevision(target, req.TargetExpectedManagementRevision); err != nil {
		return plugindata.Binding{}, err
	}
	if err := h.canRun(ctx, target); err != nil {
		return plugindata.Binding{}, err
	}
	shape, err := plugindata.ShapeFromManifest(target.Manifest)
	if err != nil {
		return plugindata.Binding{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.retained_data.bound", PluginID: target.PluginID, PluginInstanceID: target.PluginInstanceID, Details: map[string]any{"source_plugin_instance_id": req.SourcePluginInstanceID}})
	if err != nil {
		return plugindata.Binding{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	dataset, err := h.adapters.PluginData.BindRetained(ctx, plugindata.BindRetainedRequest{
		SourcePluginInstanceID:           req.SourcePluginInstanceID,
		ExpectedSourceBindingRevision:    req.ExpectedSourceBindingRevision,
		TargetPluginInstanceID:           target.PluginInstanceID,
		TargetExpectedManagementRevision: target.ManagementRevision,
		ExpectedShape:                    shape,
		Now:                              req.Now,
	})
	if err != nil {
		return plugindata.Binding{}, managementMutationError(target, err)
	}
	return dataset.Binding, nil
}

func (h *Host) CleanupExpiredRetainedData(ctx context.Context, req CleanupExpiredRetainedDataRequest) (RetainedDataCleanupResult, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return RetainedDataCleanupResult{}, err
	}
	result, err := h.adapters.PluginData.CleanupExpired(ctx, lifecycleNow(req.Now))
	if err != nil {
		return RetainedDataCleanupResult{}, err
	}
	return RetainedDataCleanupResult{Deleted: result.Deleted}, nil
}

func (h *Host) ExportPluginData(ctx context.Context, req ExportDataRequest) (result ExportDataResult, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return ExportDataResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return ExportDataResult{}, err
	}
	if record.Manifest.Settings == nil && (record.Manifest.Storage == nil || len(record.Manifest.Storage.Stores) == 0) {
		return ExportDataResult{}, ErrPluginDataNotDeclared
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.data.exported", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return ExportDataResult{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	exported, err := h.adapters.PluginData.Export(ctx, plugindata.ExportRequest{PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return ExportDataResult{}, err
	}
	return ExportDataResult{BundleRef: exported.ObjectID, ContentHash: exported.ContentHash, SizeBytes: exported.SizeBytes}, nil
}

func (h *Host) DeleteExportedPluginData(ctx context.Context, req DeleteExportDataRequest) error {
	if _, err := requireUserSession(ctx); err != nil {
		return err
	}
	return h.adapters.PluginData.DeleteExport(ctx, strings.TrimSpace(req.BundleRef))
}

func (h *Host) GetSettingsSchema(ctx context.Context, req GetSettingsRequest) (SettingsSchemaResult, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return SettingsSchemaResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return SettingsSchemaResult{}, err
	}
	if record.Manifest.Settings == nil {
		return SettingsSchemaResult{}, ErrPluginSettingsNotDeclared
	}
	snapshot, err := h.adapters.PluginData.GetSettings(ctx, record.PluginInstanceID)
	if err != nil {
		return SettingsSchemaResult{}, err
	}
	return SettingsSchemaResult{
		PluginInstanceID: record.PluginInstanceID,
		SchemaVersion:    record.Manifest.Settings.SchemaVersion,
		Fields:           cloneSettingFields(record.Manifest.Settings.Fields),
		ValuesRevision:   snapshot.Revision,
	}, nil
}

func (h *Host) GetPluginSettings(ctx context.Context, req GetSettingsRequest) (SettingsResult, error) {
	if _, err := requireUserSession(ctx); err != nil {
		return SettingsResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return SettingsResult{}, err
	}
	if record.Manifest.Settings == nil {
		return SettingsResult{}, ErrPluginSettingsNotDeclared
	}
	snapshot, err := h.adapters.PluginData.GetSettings(ctx, record.PluginInstanceID)
	if err != nil {
		return SettingsResult{}, err
	}
	secretMetadata, err := h.settingsSecretMetadata(ctx, record)
	if err != nil {
		return SettingsResult{}, err
	}
	return pluginSettingsResult(record, snapshot, secretMetadata)
}

func (h *Host) PatchPluginSettings(ctx context.Context, req PatchSettingsRequest) (result SettingsResult, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return SettingsResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return SettingsResult{}, err
	}
	if record.Manifest.Settings == nil {
		return SettingsResult{}, ErrPluginSettingsNotDeclared
	}
	set := make(map[string]json.RawMessage, len(req.Set))
	for key, value := range req.Set {
		raw, err := json.Marshal(value)
		if err != nil {
			return SettingsResult{}, fmt.Errorf("encode setting %q: %w", key, err)
		}
		set[key] = raw
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.settings.updated", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return SettingsResult{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	snapshot, err := h.adapters.PluginData.PatchSettings(ctx, plugindata.PatchSettingsRequest{
		PluginInstanceID:       record.PluginInstanceID,
		ExpectedValuesRevision: req.ExpectedValuesRevision,
		Set:                    set,
		Remove:                 append([]string(nil), req.Remove...),
	})
	if err != nil {
		return SettingsResult{}, err
	}
	secretMetadata, err := h.settingsSecretMetadata(ctx, record)
	if err != nil {
		return SettingsResult{}, mutation.Unknown(err)
	}
	return pluginSettingsResult(record, snapshot, secretMetadata)
}

func (h *Host) ImportPluginData(ctx context.Context, req ImportDataRequest) (result registry.PluginRecord, retErr error) {
	if _, err := requireUserSession(ctx); err != nil {
		return registry.PluginRecord{}, err
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	releaseLifecycle, err := h.lifecycleLocks.acquireWrite(ctx, pluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer releaseLifecycle()
	record, err := h.adapters.Registry.GetPlugin(ctx, pluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := requireManagementRevision(record, req.ExpectedManagementRevision); err != nil {
		return registry.PluginRecord{}, err
	}
	shape, err := plugindata.ShapeFromManifest(record.Manifest)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.data.imported", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	if _, err := h.adapters.PluginData.Import(ctx, plugindata.ImportRequest{
		PluginInstanceID:           record.PluginInstanceID,
		ObjectID:                   strings.TrimSpace(req.BundleRef),
		ExpectedShape:              shape,
		ExpectedManagementRevision: record.ManagementRevision,
		Now:                        req.Now,
	}); err != nil {
		return registry.PluginRecord{}, managementMutationError(record, err)
	}
	updated, err := h.adapters.Registry.GetPlugin(ctx, record.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, mutation.Unknown(err)
	}
	return updated, nil
}

func (h *Host) BindSecretRef(ctx context.Context, req SecretBindRequest) (retErr error) {
	if err := h.requireFeature(FeatureSecrets); err != nil {
		return err
	}
	if _, err := requireUserSession(ctx); err != nil {
		return err
	}
	record, normalized, err := h.resolveSecretRequest(ctx, req)
	if err != nil {
		return err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.secret.bound", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	if err := h.adapters.Secrets.BindSecretRef(ctx, normalized); err != nil {
		h.reportSecretAdapterFailure(ctx, record, "bind", err)
		return mutation.Unknown(err)
	}
	return nil
}

func (h *Host) TestSecretRef(ctx context.Context, req SecretTestRequest) (retErr error) {
	if err := h.requireFeature(FeatureSecrets); err != nil {
		return err
	}
	if _, err := requireUserSession(ctx); err != nil {
		return err
	}
	record, normalized, err := h.resolveSecretRequest(ctx, SecretBindRequest(req))
	if err != nil {
		return err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.secret.tested", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	if err := h.adapters.Secrets.TestSecretRef(ctx, SecretTestRequest(normalized)); err != nil {
		h.reportSecretAdapterFailure(ctx, record, "test", err)
		return mutation.Unknown(err)
	}
	return nil
}

func (h *Host) DeleteSecretRef(ctx context.Context, req SecretDeleteRequest) (retErr error) {
	if err := h.requireFeature(FeatureSecrets); err != nil {
		return err
	}
	if _, err := requireUserSession(ctx); err != nil {
		return err
	}
	record, normalized, err := h.resolveSecretRequest(ctx, SecretBindRequest(req))
	if err != nil {
		return err
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.secret.deleted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	if err := h.adapters.Secrets.DeleteSecretRef(ctx, SecretDeleteRequest(normalized)); err != nil {
		h.reportSecretAdapterFailure(ctx, record, "delete", err)
		return mutation.Unknown(err)
	}
	return nil
}

func (h *Host) reportSecretAdapterFailure(ctx context.Context, record registry.PluginRecord, operation string, err error) {
	if err == nil {
		return
	}
	h.diagnostic(ctx, observability.DiagnosticEvent{
		Type:              "plugin.secret.adapter_failed",
		Severity:          "warning",
		Message:           "secret adapter operation failed",
		PluginID:          record.PluginID,
		PluginInstanceID:  record.PluginInstanceID,
		ActiveFingerprint: record.ActiveFingerprint,
		Details: map[string]any{
			"operation": operation,
		},
		InternalDetails: map[string]any{"error": err.Error()},
	})
}

type runtimeArtifactProvider struct {
	assets pluginpkg.AssetStore
}

func (p runtimeArtifactProvider) ReadArtifact(ctx context.Context, req runtimeclient.ArtifactRequest) (runtimeclient.ArtifactResult, error) {
	if p.assets == nil {
		return runtimeclient.ArtifactResult{}, errors.New("package asset store is required")
	}
	asset, err := p.assets.ReadAsset(ctx, req.PackageHash, req.Artifact)
	if err != nil {
		return runtimeclient.ArtifactResult{}, err
	}
	if strings.TrimSpace(asset.Entry.SHA256) == "" {
		return runtimeclient.ArtifactResult{}, fmt.Errorf("artifact %q is missing sha256", req.Artifact)
	}
	if asset.Entry.SHA256 != req.ArtifactSHA256 {
		return runtimeclient.ArtifactResult{}, fmt.Errorf("artifact %q sha256 mismatch", req.Artifact)
	}
	return runtimeclient.ArtifactResult{Content: asset.Content, SHA256: asset.Entry.SHA256}, nil
}

type runtimeHandleGrantValidator struct {
	tokens *bridge.SurfaceTokenService
}

func (v runtimeHandleGrantValidator) ValidateHandleGrant(_ context.Context, req runtimeclient.HandleGrantValidationRequest) (runtimeclient.HandleGrantValidationResult, error) {
	if v.tokens == nil {
		return runtimeclient.HandleGrantValidationResult{}, errors.New("surface token service is required")
	}
	record, err := v.tokens.ValidateHandleGrant(bridge.ValidateHandleGrantRequest{
		HandleGrantToken: req.HandleGrantToken,
		Audience: bridge.Audience{
			PluginInstanceID:    req.PluginInstanceID,
			ActiveFingerprint:   req.ActiveFingerprint,
			RuntimeInstanceID:   req.RuntimeInstanceID,
			RuntimeGenerationID: req.RuntimeGenerationID,
			RuntimeShardID:      req.RuntimeShardID,
			HandleID:            req.HandleID,
			Method:              req.Method,
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision:     req.PolicyRevision,
			ManagementRevision: req.ManagementRevision,
			RevokeEpoch:        req.RevokeEpoch,
		},
	})
	if err != nil {
		return runtimeclient.HandleGrantValidationResult{}, err
	}
	return runtimeclient.HandleGrantValidationResult{
		HandleGrantID:       record.TokenID,
		HandleID:            record.Audience.HandleID,
		Method:              record.Audience.Method,
		RuntimeGenerationID: record.Audience.RuntimeGenerationID,
		MaxBytesPerSecond:   record.Limits.MaxBytesPerSecond,
		MaxTotalBytes:       record.Limits.MaxTotalBytes,
	}, nil
}

func (h *Host) newMethodStreamTicketMinter(audience bridge.Audience, revision bridge.RevisionBinding, method string, now time.Time) methodStreamTicketMinter {
	return func(operationID string, streamID string) (bridge.StreamTicketResult, error) {
		return h.surfaceTokens.MintStreamTicket(bridge.MintStreamTicketRequest{
			PluginID:             audience.PluginID,
			PluginInstanceID:     audience.PluginInstanceID,
			PluginVersion:        audience.PluginVersion,
			ActiveFingerprint:    audience.ActiveFingerprint,
			SurfaceID:            audience.SurfaceID,
			SurfaceInstanceID:    audience.SurfaceInstanceID,
			EntryPath:            audience.EntryPath,
			EntrySHA256:          audience.EntrySHA256,
			AssetSessionNonce:    audience.AssetSessionNonce,
			RouteRole:            audience.RouteRole,
			OwnerSessionHash:     audience.OwnerSessionHash,
			OwnerUserHash:        audience.OwnerUserHash,
			OwnerEnvHash:         audience.OwnerEnvHash,
			SessionChannelIDHash: audience.SessionChannelIDHash,
			BridgeChannelID:      audience.BridgeChannelID,
			RuntimeGenerationID:  audience.RuntimeGenerationID,
			StreamID:             streamID,
			OperationID:          operationID,
			StreamDirection:      "read",
			Method:               method,
			Revision:             revision,
			Now:                  now,
		})
	}
}

func (h *Host) mintMethodStreamTicket(req CallMethodRequest, operationID string, streamID string) (*bridge.StreamTicketResult, error) {
	if strings.TrimSpace(streamID) == "" {
		return nil, nil
	}
	if req.streamTicketMinter == nil {
		return nil, errors.New("stream ticket minter is required for subscription methods")
	}
	result, err := req.streamTicketMinter(operationID, streamID)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (h *Host) revokeMethodStreamTicket(ticket *bridge.StreamTicketResult) {
	if ticket == nil {
		return
	}
	h.surfaceTokens.RevokeStreamTicketID(ticket.StreamTicketID, time.Now().UTC())
}

func (h *Host) dispatchMethod(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (response CallMethodResult, responseErr error) {
	if err := h.validateMethodRequest(record, method, req.Params); err != nil {
		return CallMethodResult{}, err
	}

	var (
		result       capability.Result
		operationID  string
		streamID     string
		streamTicket *bridge.StreamTicketResult
		finish       executionFinish
		dispatched   bool
		err          error
	)
	defer func() {
		if recovered := recover(); recovered != nil {
			panicErr := fmt.Errorf("%w: adapter panic", ErrMethodAdapterPanic)
			h.revokeMethodStreamTicket(streamTicket)
			if finish != nil {
				panicErr = errors.Join(panicErr, finish(false, panicErr))
			}
			if dispatched {
				panicErr = methodErrorAfterDispatch(ctx, method, panicErr)
			}
			response = CallMethodResult{}
			responseErr = panicErr
		}
	}()
	switch method.Route.Kind {
	case manifest.MethodRouteCapability:
		resolved, resolveErr := h.resolveCapabilityMethod(record, method)
		if resolveErr != nil {
			return CallMethodResult{}, resolveErr
		}
		invocation, executionCtx, closeExecution, prepareErr := h.prepareCapabilityExecution(ctx, record, method, req, req.executionAuthorization, resolved)
		if prepareErr != nil {
			return CallMethodResult{}, prepareErr
		}
		finish = closeExecution
		if invocation.Execution.Operation != nil {
			operationID = invocation.Execution.Operation.ID()
		}
		if invocation.Execution.Stream != nil {
			streamID = invocation.Execution.Stream.ID()
		}
		streamTicket, err = h.mintMethodStreamTicket(req, operationID, streamID)
		if err != nil {
			break
		}
		dispatched = true
		result, err = resolved.registration.Adapter.Invoke(executionCtx, invocation)
		if err != nil {
			err = normalizeCapabilityBusinessError(resolved.contract.Contract, err)
		}
	case manifest.MethodRouteWorker:
		workerDispatch, workerErr := h.invokeWorker(ctx, record, method, req)
		result = workerDispatch.result
		operationID = workerDispatch.operationID
		streamID = workerDispatch.streamID
		streamTicket = workerDispatch.streamTicket
		finish = workerDispatch.finish
		dispatched = workerDispatch.dispatched
		err = workerErr
	case manifest.MethodRouteCoreAction:
		var invocation capability.Invocation
		var executionCtx context.Context
		invocation, executionCtx, finish, err = h.prepareCoreActionExecution(ctx, record, method, req)
		if err == nil {
			if invocation.Execution.Operation != nil {
				operationID = invocation.Execution.Operation.ID()
			}
			if invocation.Execution.Stream != nil {
				streamID = invocation.Execution.Stream.ID()
			}
			streamTicket, err = h.mintMethodStreamTicket(req, operationID, streamID)
			if err == nil {
				dispatched = true
				result, err = h.adapters.CoreActions.InvokeCoreAction(executionCtx, invocation)
			}
		}
	default:
		return CallMethodResult{}, fmt.Errorf("method route kind %q is invalid", method.Route.Kind)
	}
	err = finalizeRPCError(ctx, err)
	if err != nil {
		h.revokeMethodStreamTicket(streamTicket)
		if finish != nil {
			err = errors.Join(err, finish(false, err))
		}
		if dispatched {
			err = methodErrorAfterDispatch(ctx, method, err)
		}
		return CallMethodResult{}, err
	}
	visibleData, err := capability.PrepareResponseData(result.Data)
	if err != nil {
		h.revokeMethodStreamTicket(streamTicket)
		if finish != nil {
			err = errors.Join(err, finish(false, err))
		}
		return CallMethodResult{}, methodErrorAfterDispatch(ctx, method, fmt.Errorf("%w: method %q: %v", ErrMethodResponseContract, method.Method, err))
	}
	if err := h.validateMethodResponse(record, method, visibleData); err != nil {
		h.revokeMethodStreamTicket(streamTicket)
		if finish != nil {
			err = errors.Join(err, finish(false, err))
		}
		return CallMethodResult{}, methodErrorAfterDispatch(ctx, method, err)
	}
	if finish != nil {
		if err := finish(true, nil); err != nil {
			h.revokeMethodStreamTicket(streamTicket)
			return CallMethodResult{}, methodErrorAfterDispatch(ctx, method, err)
		}
	}
	response = CallMethodResult{Data: visibleData, OperationID: operationID, StreamID: streamID}
	if streamTicket != nil {
		response.StreamTicket = streamTicket.StreamTicket
		response.StreamTicketID = streamTicket.StreamTicketID
		expiresAt := streamTicket.ExpiresAt
		response.StreamExpiresAt = &expiresAt
	}
	return response, nil
}

func methodErrorAfterDispatch(ctx context.Context, method manifest.MethodSpec, err error) error {
	err = finalizeRPCError(ctx, err)
	if err == nil || method.Effect == manifest.MethodEffectRead {
		return err
	}
	if _, _, explicit, ok := closedRPCFailure(err); ok && explicit {
		return err
	}
	failure, _, _, ok := closedRPCFailure(err)
	if !ok {
		return &mutation.Error{Outcome: mutation.OutcomeUnknown, Err: newRPCFailure(rpcErrorScopeFromContext(ctx), []error{ErrMethodResponseContract}, nil, nil)}
	}
	return &mutation.Error{Outcome: mutation.OutcomeUnknown, Err: failure}
}

func normalizeCapabilityBusinessError(contract capabilitycontract.Contract, err error) error {
	businessError, outcome, explicitOutcome, ok := directCapabilityBusinessError(err)
	if !ok {
		return err
	}
	if businessError == nil {
		return methodResponseContractError("invalid capability business error")
	}
	for _, published := range contract.Errors {
		if published.Code != businessError.Code {
			continue
		}
		if published.DetailsSchema == nil {
			if len(businessError.Details) != 0 {
				return fmt.Errorf("%w: undeclared business error details for %s", ErrMethodResponseContract, businessError.Code)
			}
			digest, digestErr := capabilitycontract.DetailSchemaSHA256(nil)
			if digestErr != nil {
				return fmt.Errorf("%w: business error %s detail schema digest: %v", ErrMethodResponseContract, businessError.Code, digestErr)
			}
			return &validatedCapabilityErrorCandidate{businessError: capability.BusinessError{
				CapabilityID: contract.CapabilityID, CapabilityVersion: contract.CapabilityVersion, DetailSchemaSHA256: digest,
				Code: published.Code, Message: published.Message,
			}, outcome: outcome, explicit: explicitOutcome}
		}
		normalized, normalizeErr := capability.PrepareResponseData(businessError.Details)
		if normalizeErr != nil {
			return fmt.Errorf("%w: business error %s details: %v", ErrMethodResponseContract, businessError.Code, normalizeErr)
		}
		details, ok := normalized.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: business error %s details must be an object", ErrMethodResponseContract, businessError.Code)
		}
		if validateErr := capabilitycontract.ValidateValue(published.DetailsSchema, details); validateErr != nil {
			return fmt.Errorf("%w: business error %s details: %v", ErrMethodResponseContract, businessError.Code, validateErr)
		}
		digest, digestErr := capabilitycontract.DetailSchemaSHA256(published.DetailsSchema)
		if digestErr != nil {
			return fmt.Errorf("%w: business error %s detail schema digest: %v", ErrMethodResponseContract, businessError.Code, digestErr)
		}
		return &validatedCapabilityErrorCandidate{businessError: capability.BusinessError{
			CapabilityID: contract.CapabilityID, CapabilityVersion: contract.CapabilityVersion, DetailSchemaSHA256: digest,
			Code: published.Code, Message: published.Message, Details: details,
		}, outcome: outcome, explicit: explicitOutcome}
	}
	return fmt.Errorf("%w: undeclared business error code %q", ErrMethodResponseContract, businessError.Code)
}

func (h *Host) validateMethodRequest(record registry.PluginRecord, method manifest.MethodSpec, params map[string]any) error {
	compiled, err := h.methodSchemas.get(record, method)
	if err != nil {
		return fmt.Errorf("%w: method %q: %v", ErrMethodRequestContract, method.Method, err)
	}
	if err := compiled.ValidateRequest(params); err != nil {
		return fmt.Errorf("%w: method %q: %v", ErrMethodRequestContract, method.Method, err)
	}
	return nil
}

func (h *Host) validateMethodResponse(record registry.PluginRecord, method manifest.MethodSpec, data any) error {
	compiled, err := h.methodSchemas.get(record, method)
	if err != nil {
		return fmt.Errorf("%w: method %q: %v", ErrMethodResponseContract, method.Method, err)
	}
	if err := compiled.ValidateResponse(data); err != nil {
		return fmt.Errorf("%w: method %q: %v", ErrMethodResponseContract, method.Method, err)
	}
	return nil
}

func (h *Host) prepareCoreActionExecution(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (capability.Invocation, context.Context, executionFinish, error) {
	if h.adapters.CoreActions == nil {
		if err := h.requireFeature(FeatureCoreAction); err != nil {
			return capability.Invocation{}, nil, nil, err
		}
		return capability.Invocation{}, nil, nil, errors.New("core action adapter is required")
	}
	actionID := strings.TrimSpace(method.Route.ActionID)
	if actionID == "" {
		return capability.Invocation{}, nil, nil, errors.New("core action_id is required")
	}
	arguments, err := deepCloneParams(req.Params)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	target, err := h.adapters.CoreActions.ResolveCoreActionTarget(ctx, capability.TargetResolutionRequest{
		Identity: capability.PluginIdentity{
			PublisherID:       record.PublisherID,
			PluginID:          record.PluginID,
			PluginInstanceID:  record.PluginInstanceID,
			PluginVersion:     record.Version,
			ActiveFingerprint: record.ActiveFingerprint,
		},
		Surface: capability.SurfaceScope{
			SurfaceInstanceID:    req.SurfaceInstanceID,
			OwnerSessionHash:     req.session.OwnerSessionHash,
			OwnerUserHash:        req.session.OwnerUserHash,
			OwnerEnvHash:         req.session.OwnerEnvHash,
			SessionChannelIDHash: req.session.SessionChannelIDHash,
			BridgeChannelID:      req.BridgeChannelID,
		},
		CapabilityID: "core_action",
		Method:       method.Method,
		TargetMethod: actionID,
		TargetInput:  arguments,
	})
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	if strings.TrimSpace(target.Kind) == "" || target.Fields == nil {
		return capability.Invocation{}, nil, nil, errors.New("core action adapter returned an invalid target descriptor")
	}
	targetHash, err := canonicalDescriptorHash(target)
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	if req.executionAuthorization.targetHash != "" && targetHash != req.executionAuthorization.targetHash {
		return capability.Invocation{}, nil, nil, bridge.ErrTokenAudience
	}
	invocationID, err := newCapabilityID("invoke")
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	auditID, err := newCapabilityID("audit")
	if err != nil {
		return capability.Invocation{}, nil, nil, err
	}
	binding := capability.ExecutionBinding{
		InvocationID:           invocationID,
		AuditCorrelationID:     auditID,
		PublisherID:            record.PublisherID,
		PluginID:               record.PluginID,
		PluginInstanceID:       record.PluginInstanceID,
		PluginVersion:          record.Version,
		ActiveFingerprint:      record.ActiveFingerprint,
		SurfaceInstanceID:      req.SurfaceInstanceID,
		OwnerSessionHash:       req.session.OwnerSessionHash,
		OwnerUserHash:          req.session.OwnerUserHash,
		OwnerEnvHash:           req.session.OwnerEnvHash,
		SessionChannelIDHash:   req.session.SessionChannelIDHash,
		BridgeChannelID:        req.BridgeChannelID,
		RouteKind:              capability.RouteCoreAction,
		CapabilityID:           "redevplugin.core_action",
		CapabilityVersion:      "1",
		BindingID:              actionID,
		Method:                 method.Method,
		TargetMethod:           actionID,
		Effect:                 capability.Effect(method.Effect),
		Execution:              string(method.Execution),
		Permissions:            capability.PermissionEvidence{Required: []string{}, Granted: []string{}},
		Confirmation:           req.executionAuthorization.confirmation,
		Revision:               capability.RevisionEvidence{PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch},
		Target:                 target,
		TargetDescriptorSHA256: targetHash,
	}
	return h.startMethodExecution(ctx, record, method, binding, arguments, lifecycleNow(req.Now), nil, operationCancelDispatchFor(h.adapters.CoreActions), false)
}

type workerMethodDispatch struct {
	result       capability.Result
	operationID  string
	streamID     string
	streamTicket *bridge.StreamTicketResult
	finish       executionFinish
	dispatched   bool
}

func (h *Host) invokeWorker(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (dispatch workerMethodDispatch, responseErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			responseErr = fmt.Errorf("%w: adapter panic", ErrMethodAdapterPanic)
		}
	}()
	worker, ok := manifestWorker(record.Manifest, method.Route.WorkerID)
	if !ok {
		return workerMethodDispatch{}, fmt.Errorf("worker %q is not declared", method.Route.WorkerID)
	}
	runtimeBinding, err := h.bindCompatibleWorkerRuntime(ctx, record)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	revision := bridge.RevisionBinding{
		PolicyRevision:     record.PolicyRevision,
		ManagementRevision: record.ManagementRevision,
		RevokeEpoch:        record.RevokeEpoch,
	}
	if h.adapters.Assets == nil {
		return workerMethodDispatch{}, errors.New("package asset store is required for worker methods")
	}
	workerEntry, ok := packageEntryByPath(record.PackageEntries, worker.Artifact)
	if !ok || strings.TrimSpace(workerEntry.SHA256) == "" {
		return workerMethodDispatch{}, fmt.Errorf("worker artifact %q metadata is unavailable", worker.Artifact)
	}
	targetDescriptorHashes, err := runtimeLeaseTargetDescriptorHashes(record, method, worker, workerEntry.SHA256)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	params, err := deepCloneParams(req.Params)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	target := capability.TargetDescriptor{
		Kind: "worker",
		Fields: map[string]any{
			"worker_id":             worker.WorkerID,
			"artifact_sha256":       workerEntry.SHA256,
			"runtime_generation_id": runtimeBinding.RuntimeGenerationID,
			"arguments":             params,
		},
	}
	targetHash, err := canonicalDescriptorHash(target)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	if req.executionAuthorization.targetHash != "" && targetHash != req.executionAuthorization.targetHash {
		return workerMethodDispatch{}, bridge.ErrTokenAudience
	}
	targetDescriptorHashes = append(targetDescriptorHashes, targetHash)
	sort.Strings(targetDescriptorHashes)
	invocationID, err := newCapabilityID("invoke")
	if err != nil {
		return workerMethodDispatch{}, err
	}
	auditID, err := newCapabilityID("audit")
	if err != nil {
		return workerMethodDispatch{}, err
	}
	binding := capability.ExecutionBinding{
		InvocationID:           invocationID,
		AuditCorrelationID:     auditID,
		PublisherID:            record.PublisherID,
		PluginID:               record.PluginID,
		PluginInstanceID:       record.PluginInstanceID,
		PluginVersion:          record.Version,
		ActiveFingerprint:      record.ActiveFingerprint,
		SurfaceInstanceID:      req.SurfaceInstanceID,
		OwnerSessionHash:       req.session.OwnerSessionHash,
		OwnerUserHash:          req.session.OwnerUserHash,
		OwnerEnvHash:           req.session.OwnerEnvHash,
		SessionChannelIDHash:   req.session.SessionChannelIDHash,
		BridgeChannelID:        req.BridgeChannelID,
		RouteKind:              capability.RouteWorker,
		CapabilityID:           "redevplugin.worker",
		CapabilityVersion:      "1",
		BindingID:              worker.WorkerID,
		Method:                 method.Method,
		TargetMethod:           method.Method,
		Effect:                 capability.Effect(method.Effect),
		Execution:              string(method.Execution),
		Permissions:            capability.PermissionEvidence{Required: []string{}, Granted: []string{}},
		Confirmation:           req.executionAuthorization.confirmation,
		Revision:               capability.RevisionEvidence{PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch},
		Target:                 target,
		TargetDescriptorSHA256: targetHash,
	}
	invocation, executionCtx, finish, err := h.startMethodExecution(ctx, record, method, binding, params, now, nil, operationCancelDispatchFor(h.adapters.RuntimeManager), true)
	if err != nil {
		return workerMethodDispatch{}, err
	}
	dispatch = workerMethodDispatch{finish: finish}
	if invocation.Execution.Operation != nil {
		dispatch.operationID = invocation.Execution.Operation.ID()
	}
	if invocation.Execution.Stream != nil {
		dispatch.streamID = invocation.Execution.Stream.ID()
	}
	dispatch.streamTicket, err = h.mintMethodStreamTicket(req, dispatch.operationID, dispatch.streamID)
	if err != nil {
		return dispatch, err
	}
	payload := workerInvocationPayload{
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		ActiveFingerprint:    record.ActiveFingerprint,
		RuntimeInstanceID:    runtimeBinding.RuntimeInstanceID,
		RuntimeGenerationID:  runtimeBinding.RuntimeGenerationID,
		PackageHash:          record.PackageHash,
		WorkerID:             worker.WorkerID,
		WorkerMode:           string(worker.Mode),
		WorkerScope:          worker.Scope,
		Artifact:             worker.Artifact,
		ArtifactSHA256:       workerEntry.SHA256,
		ABI:                  worker.ABI,
		Method:               method.Method,
		Effect:               string(method.Effect),
		Execution:            string(method.Execution),
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.session.OwnerSessionHash,
		OwnerUserHash:        req.session.OwnerUserHash,
		OwnerEnvHash:         req.session.OwnerEnvHash,
		SessionChannelIDHash: req.session.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		OperationID:          dispatch.operationID,
		StreamID:             dispatch.streamID,
		AuditCorrelationID:   binding.AuditCorrelationID,
		Params:               params,
		BrokerAccess:         normalizedWorkerBrokerAccess(method.BrokerAccess),
	}
	payload.BrokerAccessSHA256, err = workerBrokerAccessHash(payload.BrokerAccess)
	if err != nil {
		return dispatch, err
	}
	payload.StorageHandleGrants, err = h.mintWorkerStorageHandleGrants(ctx, record, method, runtimeBinding, now)
	if err != nil {
		return dispatch, err
	}
	paramsBytes, err := marshalWorkerCanonicalJSON(payload.Params)
	if err != nil {
		return dispatch, err
	}
	paramsSum := sha256.Sum256(paramsBytes)
	payload.ParamsSHA256 = "sha256:" + hex.EncodeToString(paramsSum[:])
	invocationTargetHash, err := workerInvocationTargetHash(payload)
	if err != nil {
		return dispatch, err
	}
	targetDescriptorHashes = append(targetDescriptorHashes, invocationTargetHash)
	sort.Strings(targetDescriptorHashes)
	leaseAudit, err := h.beginSecurityMutation(ctx, AuditEvent{
		Type:              "plugin.runtime.lease.issued",
		PluginID:          record.PluginID,
		PluginInstanceID:  record.PluginInstanceID,
		SurfaceInstanceID: req.SurfaceInstanceID,
		Actor:             "host",
	})
	if err != nil {
		return dispatch, err
	}
	lease, leaseErr := h.surfaceTokens.MintRuntimeExecutionLease(bridge.MintRuntimeExecutionLeaseRequest{
		PluginInstanceID:       record.PluginInstanceID,
		PluginID:               record.PluginID,
		PluginVersion:          record.Version,
		ActiveFingerprint:      record.ActiveFingerprint,
		SurfaceInstanceID:      req.SurfaceInstanceID,
		OwnerSessionHash:       req.session.OwnerSessionHash,
		OwnerUserHash:          req.session.OwnerUserHash,
		OwnerEnvHash:           req.session.OwnerEnvHash,
		SessionChannelIDHash:   req.session.SessionChannelIDHash,
		BridgeChannelID:        req.BridgeChannelID,
		RuntimeInstanceID:      runtimeBinding.RuntimeInstanceID,
		RuntimeGenerationID:    runtimeBinding.RuntimeGenerationID,
		RuntimeShardID:         runtimeBinding.RuntimeShardID,
		IPCChannelID:           runtimeBinding.IPCChannelID,
		ConnectionNonce:        runtimeBinding.ConnectionNonce,
		Method:                 method.Method,
		Effect:                 string(method.Effect),
		Execution:              string(method.Execution),
		OperationID:            dispatch.operationID,
		StreamID:               dispatch.streamID,
		AuditCorrelationID:     binding.AuditCorrelationID,
		TargetDescriptorHashes: targetDescriptorHashes,
		Limits: bridge.RuntimeExecutionLeaseLimits{
			MemoryBytes: worker.MemoryLimitBytes,
		},
		Revision: revision,
		Now:      now,
	})
	var leaseAuditDetails map[string]any
	if leaseErr == nil {
		leaseAuditDetails = map[string]any{
			"lease_id":                 lease.LeaseID,
			"token_id":                 lease.TokenID,
			"method":                   lease.Method,
			"effect":                   lease.Effect,
			"execution":                lease.Execution,
			"runtime_instance_id":      lease.RuntimeInstanceID,
			"runtime_generation_id":    lease.RuntimeGenerationID,
			"ipc_channel_id":           lease.IPCChannelID,
			"policy_revision":          lease.PolicyRevision,
			"management_revision":      lease.ManagementRevision,
			"revoke_epoch":             lease.RevokeEpoch,
			"target_descriptor_hashes": append([]string(nil), lease.TargetDescriptorHashes...),
			"expires_at_unix_ms":       lease.ExpiresAtUnixMillis,
		}
	}
	if err := leaseAudit.completeWithDetails(context.WithoutCancel(ctx), leaseErr, leaseAuditDetails); err != nil {
		return dispatch, err
	}
	if leaseErr != nil {
		return dispatch, leaseErr
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return dispatch, err
	}
	dispatch.dispatched = true
	rawResult, err := h.adapters.RuntimeManager.InvokeWorker(executionCtx, runtimeBinding, runtimeclient.Lease{
		LeaseID:                lease.LeaseID,
		TokenID:                lease.TokenID,
		LeaseNonce:             lease.LeaseNonce,
		PluginID:               lease.PluginID,
		PluginVersion:          lease.PluginVersion,
		ActiveFingerprint:      lease.ActiveFingerprint,
		SurfaceInstanceID:      lease.SurfaceInstanceID,
		OwnerSessionHash:       lease.OwnerSessionHash,
		OwnerUserHash:          lease.OwnerUserHash,
		OwnerEnvHash:           lease.OwnerEnvHash,
		SessionChannelIDHash:   lease.SessionChannelIDHash,
		BridgeChannelID:        lease.BridgeChannelID,
		RuntimeGenerationID:    lease.RuntimeGenerationID,
		PluginInstanceID:       lease.PluginInstanceID,
		Method:                 lease.Method,
		Effect:                 lease.Effect,
		Execution:              lease.Execution,
		OperationID:            lease.OperationID,
		StreamID:               lease.StreamID,
		AuditCorrelationID:     lease.AuditCorrelationID,
		TargetDescriptorHashes: append([]string(nil), lease.TargetDescriptorHashes...),
		Limits: runtimeclient.LeaseLimits{
			TimeoutMillis:           lease.Limits.TimeoutMillis,
			MemoryBytes:             lease.Limits.MemoryBytes,
			MaxPayloadBytes:         lease.Limits.MaxPayloadBytes,
			MaxStreamBytesPerSecond: lease.Limits.MaxStreamBytesPerSecond,
		},
		PolicyRevision:      lease.PolicyRevision,
		ManagementRevision:  lease.ManagementRevision,
		RevokeEpoch:         lease.RevokeEpoch,
		RuntimeShardID:      lease.RuntimeShardID,
		RuntimeInstanceID:   lease.RuntimeInstanceID,
		IPCChannelID:        lease.IPCChannelID,
		ConnectionNonce:     lease.ConnectionNonce,
		IssuedAtUnixMillis:  lease.IssuedAtUnixMillis,
		ExpiresAtUnixMillis: lease.ExpiresAtUnixMillis,
	}, method.Method, rawPayload)
	if err != nil {
		return dispatch, validateWorkerErrorCandidate(err)
	}
	if len(rawResult) > 0 {
		if err := json.Unmarshal(rawResult, &dispatch.result); err != nil {
			return dispatch, fmt.Errorf("decode worker result: %w", err)
		}
	}
	return dispatch, nil
}

func (h *Host) mintWorkerStorageHandleGrants(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, binding runtimeclient.RuntimeBinding, now time.Time) (map[string]string, error) {
	if method.BrokerAccess == nil || len(method.BrokerAccess.Storage) == 0 {
		return nil, nil
	}
	grants := make(map[string]string, len(method.BrokerAccess.Storage))
	for _, access := range method.BrokerAccess.Storage {
		result, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
			PluginInstanceID:    record.PluginInstanceID,
			StoreID:             access.StoreID,
			RuntimeInstanceID:   binding.RuntimeInstanceID,
			RuntimeGenerationID: binding.RuntimeGenerationID,
			RuntimeShardID:      binding.RuntimeShardID,
			Now:                 now,
		})
		if err != nil {
			return nil, err
		}
		grants[access.StoreID] = result.HandleGrant.HandleGrantToken
	}
	return grants, nil
}

func normalizedWorkerBrokerAccess(access *manifest.MethodBrokerAccessSpec) manifest.MethodBrokerAccessSpec {
	if access == nil {
		return manifest.MethodBrokerAccessSpec{}
	}
	normalized := manifest.MethodBrokerAccessSpec{
		Storage: make([]manifest.StorageBrokerAccessSpec, len(access.Storage)),
		Network: make([]manifest.NetworkBrokerAccessSpec, len(access.Network)),
	}
	for i, item := range access.Storage {
		normalized.Storage[i] = manifest.StorageBrokerAccessSpec{
			StoreID:    item.StoreID,
			Operations: append([]string(nil), item.Operations...),
		}
		sort.Strings(normalized.Storage[i].Operations)
	}
	for i, item := range access.Network {
		normalized.Network[i] = manifest.NetworkBrokerAccessSpec{
			ConnectorID: item.ConnectorID,
			Transport:   item.Transport,
			Operations:  append([]string(nil), item.Operations...),
			HTTPMethods: append([]string(nil), item.HTTPMethods...),
		}
		sort.Strings(normalized.Network[i].Operations)
		sort.Strings(normalized.Network[i].HTTPMethods)
	}
	sort.Slice(normalized.Storage, func(i, j int) bool { return normalized.Storage[i].StoreID < normalized.Storage[j].StoreID })
	sort.Slice(normalized.Network, func(i, j int) bool { return normalized.Network[i].ConnectorID < normalized.Network[j].ConnectorID })
	return normalized
}

func workerBrokerAccessHash(access manifest.MethodBrokerAccessSpec) (string, error) {
	raw, err := marshalWorkerCanonicalJSON(access)
	if err != nil {
		return "", fmt.Errorf("marshal worker broker access: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func marshalWorkerCanonicalJSON(value any) ([]byte, error) {
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'}), nil
}

func workerInvocationTargetHash(payload workerInvocationPayload) (string, error) {
	fields := []string{
		"redevplugin.worker_invocation_target.v1",
		payload.PluginID,
		payload.PluginInstanceID,
		payload.ActiveFingerprint,
		payload.RuntimeInstanceID,
		payload.RuntimeGenerationID,
		payload.PackageHash,
		payload.WorkerID,
		payload.WorkerMode,
		payload.WorkerScope,
		payload.Artifact,
		payload.ArtifactSHA256,
		payload.ABI,
		payload.Method,
		payload.Effect,
		payload.Execution,
		payload.SurfaceInstanceID,
		payload.OwnerSessionHash,
		payload.OwnerUserHash,
		payload.OwnerEnvHash,
		payload.SessionChannelIDHash,
		payload.BridgeChannelID,
		payload.OperationID,
		payload.StreamID,
		payload.AuditCorrelationID,
		payload.ParamsSHA256,
		payload.BrokerAccessSHA256,
	}
	var canonical bytes.Buffer
	for _, field := range fields {
		if uint64(len(field)) > uint64(^uint32(0)) {
			return "", errors.New("worker invocation target field exceeds uint32 length")
		}
		if err := binary.Write(&canonical, binary.BigEndian, uint32(len(field))); err != nil {
			return "", err
		}
		if _, err := canonical.WriteString(field); err != nil {
			return "", err
		}
	}
	sum := sha256.Sum256(canonical.Bytes())
	return "invocation:sha256:" + hex.EncodeToString(sum[:]), nil
}

func (h *Host) resolveSecretRequest(ctx context.Context, req SecretBindRequest) (registry.PluginRecord, SecretBindRequest, error) {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	req.SecretRef = strings.TrimSpace(req.SecretRef)
	req.Scope = strings.TrimSpace(req.Scope)
	if req.PluginInstanceID == "" {
		return registry.PluginRecord{}, SecretBindRequest{}, fmt.Errorf("%w: plugin_instance_id is required", ErrInvalidSecretRef)
	}
	if req.SecretRef == "" {
		return registry.PluginRecord{}, SecretBindRequest{}, fmt.Errorf("%w: secret_ref is required", ErrInvalidSecretRef)
	}
	if req.Scope != "user" && req.Scope != "environment" {
		return registry.PluginRecord{}, SecretBindRequest{}, fmt.Errorf("%w: scope must be user or environment", ErrInvalidSecretRef)
	}
	if h.adapters.Secrets == nil {
		if err := h.requireFeature(FeatureSecrets); err != nil {
			return registry.PluginRecord{}, SecretBindRequest{}, err
		}
		return registry.PluginRecord{}, SecretBindRequest{}, ErrSecretStoreRequired
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, SecretBindRequest{}, err
	}
	if !secretRefDeclared(record.Manifest, req.SecretRef) {
		return registry.PluginRecord{}, SecretBindRequest{}, fmt.Errorf("%w: secret_ref %q is not declared", ErrInvalidSecretRef, req.SecretRef)
	}
	return record, req, nil
}

func operationsBlockDelete(records []operation.Record) bool {
	for _, record := range records {
		if record.Status == operation.StatusCancelRequested && record.UninstallBehavior == operation.UninstallBehaviorCancelThenBlockDelete {
			return true
		}
	}
	return false
}

func cancelPolicyDisableBehavior(policy *manifest.CancelPolicySpec) string {
	if policy == nil {
		return operation.DisableBehaviorCancel
	}
	return policy.DisableBehavior
}

func cancelPolicyUninstallBehavior(policy *manifest.CancelPolicySpec) string {
	if policy == nil {
		return operation.UninstallBehaviorCancelThenBlockDelete
	}
	return policy.UninstallBehavior
}

func pluginRefFromRecord(record registry.PluginRecord) PluginRef {
	return PluginRef{
		PluginID:          record.PluginID,
		PluginInstanceID:  record.PluginInstanceID,
		Version:           record.Version,
		ActiveFingerprint: record.ActiveFingerprint,
	}
}

func manifestMethod(m manifest.Manifest, methodName string) (manifest.MethodSpec, bool) {
	for _, method := range m.Methods {
		if method.Method == methodName {
			return method, true
		}
	}
	return manifest.MethodSpec{}, false
}

func manifestIntent(m manifest.Manifest, intentID string) (manifest.IntentSpec, bool) {
	for _, intent := range m.Intents {
		if intent.IntentID == intentID {
			return intent, true
		}
	}
	return manifest.IntentSpec{}, false
}

func (h *Host) requiredPermissionsForMethod(record registry.PluginRecord, method manifest.MethodSpec) ([]string, error) {
	if method.Route.Kind != manifest.MethodRouteCapability {
		return nil, nil
	}
	resolved, err := h.resolveCapabilityMethod(record, method)
	if err != nil {
		return nil, err
	}
	return normalizeStringSet(resolved.method.RequiredPermissions), nil
}

func authorizationDecisionError(decision registry.AuthorizationDecision, method string) error {
	if !decision.PolicyEvaluation.Allowed {
		switch decision.PolicyEvaluation.Reason {
		case security.PolicyDenyReasonMethodDenied:
			return fmt.Errorf("%w: method %q is denied", security.ErrPolicyDenied, decision.PolicyEvaluation.DeniedMethod)
		case security.PolicyDenyReasonPermissionNotAllowed:
			return fmt.Errorf("%w: permissions not allowed: %s", security.ErrPolicyDenied, strings.Join(decision.PolicyEvaluation.MissingPermissions, ", "))
		default:
			return fmt.Errorf("%w: method %q", security.ErrPolicyDenied, method)
		}
	}
	if len(decision.MissingPermissions) > 0 {
		return fmt.Errorf("%w: %s", permissions.ErrPermissionDenied, strings.Join(decision.MissingPermissions, ", "))
	}
	return nil
}

func manifestWorker(m manifest.Manifest, workerID string) (manifest.WorkerSpec, bool) {
	for _, worker := range m.Workers {
		if worker.WorkerID == workerID {
			return worker, true
		}
	}
	return manifest.WorkerSpec{}, false
}

func runtimeLeaseTargetDescriptorHashes(record registry.PluginRecord, method manifest.MethodSpec, worker manifest.WorkerSpec, artifactSHA256 string) ([]string, error) {
	methodHash, err := runtimeLeaseDescriptorHash("method", method)
	if err != nil {
		return nil, err
	}
	workerHash, err := runtimeLeaseDescriptorHash("worker", struct {
		Worker         manifest.WorkerSpec `json:"worker"`
		ArtifactSHA256 string              `json:"artifact_sha256"`
	}{
		Worker:         worker,
		ArtifactSHA256: strings.TrimSpace(artifactSHA256),
	})
	if err != nil {
		return nil, err
	}
	hashes := []string{
		"package:" + strings.TrimSpace(record.PackageHash),
		"manifest:" + strings.TrimSpace(record.ManifestHash),
		methodHash,
		workerHash,
	}
	if artifactSHA256 = strings.TrimSpace(artifactSHA256); artifactSHA256 != "" {
		hashes = append(hashes, "artifact:"+artifactSHA256)
	}
	out := make([]string, 0, len(hashes))
	seen := map[string]struct{}{}
	for _, hash := range hashes {
		hash = strings.TrimSpace(hash)
		if hash == "" {
			continue
		}
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		out = append(out, hash)
	}
	return out, nil
}

func runtimeLeaseDescriptorHash(prefix string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal runtime lease %s descriptor: %w", prefix, err)
	}
	sum := sha256.Sum256(raw)
	return prefix + ":sha256:" + hex.EncodeToString(sum[:]), nil
}

func normalizeStringSet(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func cloneParams(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	cloned := make(map[string]any, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

func methodRequiresConfirmation(method manifest.MethodSpec) bool {
	if method.Dangerous {
		return true
	}
	if method.Confirmation == nil {
		return false
	}
	switch method.Confirmation.Mode {
	case manifest.ConfirmationRequired, manifest.ConfirmationRiskBased:
		return true
	default:
		return false
	}
}

func (h *Host) resolveMethodConfirmationTarget(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (capability.TargetDescriptor, string, error) {
	switch method.Route.Kind {
	case manifest.MethodRouteCapability:
		resolved, err := h.resolveCapabilityMethod(record, method)
		if err != nil {
			return capability.TargetDescriptor{}, "", err
		}
		return h.resolveCapabilityTarget(ctx, record, method, req, resolved)
	case manifest.MethodRouteCoreAction:
		if h.adapters.CoreActions == nil {
			if err := h.requireFeature(FeatureCoreAction); err != nil {
				return capability.TargetDescriptor{}, "", err
			}
			return capability.TargetDescriptor{}, "", errors.New("core action adapter is required")
		}
		arguments, err := deepCloneParams(req.Params)
		if err != nil {
			return capability.TargetDescriptor{}, "", err
		}
		target, err := h.adapters.CoreActions.ResolveCoreActionTarget(ctx, capability.TargetResolutionRequest{
			Identity: capability.PluginIdentity{
				PublisherID: record.PublisherID, PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID,
				PluginVersion: record.Version, ActiveFingerprint: record.ActiveFingerprint,
			},
			Surface: capability.SurfaceScope{
				SurfaceInstanceID: req.SurfaceInstanceID, OwnerSessionHash: req.session.OwnerSessionHash, OwnerUserHash: req.session.OwnerUserHash, OwnerEnvHash: req.session.OwnerEnvHash,
				SessionChannelIDHash: req.session.SessionChannelIDHash, BridgeChannelID: req.BridgeChannelID,
			},
			CapabilityID: "redevplugin.core_action", BindingID: method.Route.ActionID,
			Method: method.Method, TargetMethod: method.Route.ActionID, TargetInput: arguments,
		})
		if err != nil {
			return capability.TargetDescriptor{}, "", err
		}
		if strings.TrimSpace(target.Kind) == "" || target.Fields == nil {
			return capability.TargetDescriptor{}, "", errors.New("core action adapter returned an invalid target descriptor")
		}
		hash, err := canonicalDescriptorHash(target)
		return target, hash, err
	case manifest.MethodRouteWorker:
		worker, ok := manifestWorker(record.Manifest, method.Route.WorkerID)
		if !ok {
			return capability.TargetDescriptor{}, "", fmt.Errorf("worker %q is not declared", method.Route.WorkerID)
		}
		runtimeBinding, err := h.bindCompatibleWorkerRuntime(ctx, record)
		if err != nil {
			return capability.TargetDescriptor{}, "", err
		}
		workerEntry, ok := packageEntryByPath(record.PackageEntries, worker.Artifact)
		if !ok || strings.TrimSpace(workerEntry.SHA256) == "" {
			return capability.TargetDescriptor{}, "", fmt.Errorf("worker artifact %q metadata is unavailable", worker.Artifact)
		}
		arguments, err := deepCloneParams(req.Params)
		if err != nil {
			return capability.TargetDescriptor{}, "", err
		}
		target := capability.TargetDescriptor{Kind: "worker", Fields: map[string]any{
			"worker_id": worker.WorkerID, "artifact_sha256": workerEntry.SHA256,
			"runtime_generation_id": runtimeBinding.RuntimeGenerationID, "arguments": arguments,
		}}
		hash, err := canonicalDescriptorHash(target)
		return target, hash, err
	default:
		return capability.TargetDescriptor{}, "", fmt.Errorf("method route kind %q is invalid", method.Route.Kind)
	}
}

func methodRequestHash(method manifest.MethodSpec, params map[string]any) (string, error) {
	payload := struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params,omitempty"`
	}{
		Method: method.Method,
		Params: params,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (h *Host) prepareConfirmationPlan(ctx context.Context, call resolvedMethodCall, req CallMethodRequest, requestHash string) (any, string, error) {
	var plan any
	preflightMethodName := confirmationPreflightMethod(call.method)
	if preflightMethodName != "" {
		preflight, err := h.resolveConfirmationPreflightMethod(call.record, call.method, preflightMethodName)
		if err != nil {
			return nil, "", err
		}
		preflightReq := req
		preflightReq.Method = preflight.Method
		preflightReq.ConfirmationID = ""
		result, err := h.dispatchMethod(ctx, call.record, preflight, preflightReq)
		if err != nil {
			return nil, "", fmt.Errorf("confirmation preflight method %q failed: %w", preflight.Method, err)
		}
		plan = result.Data
		normalizedPlan, err := capability.NormalizeRiskPlanData(plan)
		if err != nil {
			return nil, "", fmt.Errorf("confirmation preflight method %q returned invalid risk plan: %w", preflight.Method, err)
		}
		plan = normalizedPlan
	}
	planHash, err := methodPlanHash(call.method, requestHash, plan)
	if err != nil {
		return nil, "", err
	}
	if preflightMethodName != "" {
		if err := h.recordSecurityEvent(ctx, AuditEvent{
			Type:             "plugin.confirmation.preflighted",
			PluginID:         call.record.PluginID,
			PluginInstanceID: call.record.PluginInstanceID,
			Details: map[string]any{
				"method":           call.method.Method,
				"preflight_method": preflightMethodName,
				"plan_hash":        planHash,
			},
		}); err != nil {
			return nil, "", mutation.Unknown(err)
		}
	}
	return plan, planHash, nil
}

func (h *Host) resolveConfirmationPreflightMethod(record registry.PluginRecord, method manifest.MethodSpec, preflightMethodName string) (manifest.MethodSpec, error) {
	if method.Route.Kind == manifest.MethodRouteCapability {
		preflight := manifest.MethodSpec{
			Method: preflightMethodName,
			Route: manifest.MethodRouteSpec{
				Kind:         manifest.MethodRouteCapability,
				BindingID:    method.Route.BindingID,
				TargetMethod: preflightMethodName,
			},
		}
		effective, err := h.effectiveMethod(record, preflight)
		if err != nil {
			return manifest.MethodSpec{}, fmt.Errorf("resolve signed confirmation preflight method %q: %w", preflightMethodName, err)
		}
		if !effective.PreflightOnly || effective.Route.BindingID != method.Route.BindingID {
			return manifest.MethodSpec{}, fmt.Errorf("confirmation preflight method %q is not a signed preflight on the same capability binding", preflightMethodName)
		}
		return effective, nil
	}
	preflight, ok := manifestMethod(record.Manifest, preflightMethodName)
	if !ok {
		return manifest.MethodSpec{}, fmt.Errorf("confirmation preflight method %q is not declared", preflightMethodName)
	}
	return preflight, nil
}

func confirmationPreflightMethod(method manifest.MethodSpec) string {
	if method.Confirmation == nil || method.Confirmation.PreflightMethod == nil {
		return ""
	}
	return strings.TrimSpace(*method.Confirmation.PreflightMethod)
}

func methodPlanHash(method manifest.MethodSpec, requestHash string, plan any) (string, error) {
	confirmationMode := ""
	planHashRequired := false
	var requestHashFields []string
	preflightMethod := ""
	if method.Confirmation != nil {
		confirmationMode = string(method.Confirmation.Mode)
		planHashRequired = method.Confirmation.PlanHashRequired
		requestHashFields = append([]string(nil), method.Confirmation.RequestHashFields...)
		preflightMethod = confirmationPreflightMethod(method)
	}
	payload := struct {
		Method            string   `json:"method"`
		RequestHash       string   `json:"request_hash"`
		ConfirmationMode  string   `json:"confirmation_mode,omitempty"`
		PreflightMethod   string   `json:"preflight_method,omitempty"`
		RequestHashFields []string `json:"request_hash_fields,omitempty"`
		PlanHashRequired  bool     `json:"plan_hash_required,omitempty"`
		Plan              any      `json:"plan,omitempty"`
	}{
		Method:            method.Method,
		RequestHash:       requestHash,
		ConfirmationMode:  confirmationMode,
		PreflightMethod:   preflightMethod,
		RequestHashFields: requestHashFields,
		PlanHashRequired:  planHashRequired,
		Plan:              plan,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func newConfirmationID() (string, error) {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "confirmation_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (h *Host) storeConfirmationIntent(ctx context.Context, req security.PutConfirmationIntentRequest) (security.ConfirmationIntentRecord, error) {
	req.MaxPendingPerPlugin = maxPendingConfirmationIntentsPerPlugin
	return h.adapters.ConfirmationIntents.PutConfirmationIntent(ctx, req)
}

func (h *Host) deleteConfirmationIntentsForPlugin(ctx context.Context, pluginInstanceID string, now time.Time) (int, error) {
	return h.adapters.ConfirmationIntents.RevokePluginConfirmationIntents(ctx, security.RevokePluginConfirmationIntentsRequest{
		PluginInstanceID: pluginInstanceID,
		Now:              now,
	})
}

func (h *Host) consumeConfirmationIntent(ctx context.Context, confirmationID string, now time.Time) (security.ConfirmationIntentRecord, error) {
	if strings.TrimSpace(confirmationID) == "" {
		return security.ConfirmationIntentRecord{}, bridge.ErrMissingTokenAudience
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	intent, err := h.adapters.ConfirmationIntents.ConsumeConfirmationIntent(ctx, security.ConsumeConfirmationIntentRequest{
		ConfirmationID: confirmationID,
		Now:            now,
	})
	err = finalizeRPCError(ctx, err)
	if errors.Is(err, security.ErrConfirmationIntentNotFound) {
		return security.ConfirmationIntentRecord{}, bridge.ErrTokenInvalid
	}
	if errors.Is(err, security.ErrConfirmationIntentExpired) {
		return security.ConfirmationIntentRecord{}, bridge.ErrTokenExpired
	}
	if err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	return intent, nil
}

func (h *Host) revokePluginRuntimeCapabilities(ctx context.Context, record registry.PluginRecord, now time.Time) (retErr error) {
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.runtime_capabilities.revoked", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return err
	}
	var auditDetails map[string]any
	defer func() { retErr = auditMutation.completeWithDetails(context.WithoutCancel(ctx), retErr, auditDetails) }()
	revokedExecutionLeases := h.executions.cancelPlugin(record.PluginInstanceID, capability.ErrExecutionRevoked)
	var resultErr error
	revokedTokens := 0
	if h.surfaceTokens != nil {
		var err error
		revokedTokens, err = h.surfaceTokens.RevokePlugin(record.PluginInstanceID, record.RevokeEpoch, now)
		if err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}
	revokedConfirmations, err := h.deleteConfirmationIntentsForPlugin(ctx, record.PluginInstanceID, now)
	if err != nil {
		resultErr = errors.Join(resultErr, err)
	}
	runtimeRevoked := false
	var runtimeRevokeResult runtimeclient.RevokeResult
	var runtimeErr error
	if h.adapters.RuntimeManager != nil && pluginHasWorkers(record.Manifest) {
		revokeCtx := ctx
		cancel := func() {}
		if _, ok := ctx.Deadline(); !ok {
			revokeCtx, cancel = context.WithTimeout(ctx, runtimeCapabilityRevokeTimeout)
		}
		defer cancel()
		result, err := h.adapters.RuntimeManager.Revoke(revokeCtx, record.PluginInstanceID, record.RevokeEpoch)
		if err != nil {
			h.diagnostic(ctx, observability.DiagnosticEvent{
				Type:              "plugin.runtime_capabilities.revoke_failed",
				Severity:          "warning",
				Message:           "plugin runtime capability revocation failed",
				PluginID:          record.PluginID,
				PluginInstanceID:  record.PluginInstanceID,
				ActiveFingerprint: record.ActiveFingerprint,
				Details: map[string]any{
					"revoke_epoch": record.RevokeEpoch,
				},
				InternalDetails: map[string]any{"error": err.Error()},
			})
		} else {
			runtimeRevokeResult = result
			runtimeRevoked = true
		}
		runtimeErr = err
	}
	reconcileCtx := ctx
	reconcileCancel := func() {}
	if _, ok := reconcileCtx.Deadline(); !ok {
		reconcileCtx, reconcileCancel = context.WithTimeout(ctx, 2*time.Second)
	}
	reconcileRevokedExecutions(reconcileCtx, revokedExecutionLeases, capability.ErrExecutionRevoked)
	reconcileCancel()
	revokedExecutions := len(revokedExecutionLeases)
	if runtimeRevoked || revokedTokens > 0 || revokedConfirmations > 0 || revokedExecutions > 0 {
		auditDetails = map[string]any{
			"token_count":        revokedTokens,
			"confirmation_count": revokedConfirmations,
			"revoke_epoch":       record.RevokeEpoch,
			"runtime_revoked":    runtimeRevoked,
			"execution_count":    revokedExecutions,
		}
		if runtimeRevoked {
			auditDetails["closed_socket_count"] = runtimeRevokeResult.ClosedSocketCount
			auditDetails["closed_stream_count"] = runtimeRevokeResult.ClosedStreamCount
			auditDetails["closed_storage_handle_count"] = runtimeRevokeResult.ClosedStorageHandleCount
			auditDetails["runtime_stopped"] = runtimeRevokeResult.RuntimeStopped
		}
	}
	return errors.Join(resultErr, runtimeErr)
}

func (h *Host) diagnostic(ctx context.Context, event observability.DiagnosticEvent) {
	_ = h.appendDiagnostic(ctx, event)
}

func (h *Host) appendDiagnostic(ctx context.Context, event observability.DiagnosticEvent) error {
	if h.adapters.Diagnostics == nil {
		return nil
	}
	if session, ok := sessionctx.FromContext(ctx); ok {
		event.OwnerSessionHash = session.OwnerSessionHash
		event.OwnerUserHash = session.OwnerUserHash
		event.OwnerEnvHash = session.OwnerEnvHash
		event.SessionChannelIDHash = session.SessionChannelIDHash
	}
	return h.adapters.Diagnostics.AppendPluginDiagnostic(ctx, event)
}

func (h *Host) ReportHTTPAdapterFailure(ctx context.Context, operation string, code security.ErrorCode, err error) {
	if err == nil {
		return
	}
	h.diagnostic(ctx, observability.DiagnosticEvent{
		Type:     "plugin.http.operation_failed",
		Severity: "warning",
		Message:  "plugin HTTP operation failed",
		Details: map[string]any{
			"operation": strings.TrimSpace(operation),
			"code":      string(code),
		},
		InternalDetails: map[string]any{"error": err.Error()},
	})
}

func (h *Host) canRun(ctx context.Context, record registry.PluginRecord) error {
	if !registry.RunnableTrustState(record.TrustState) {
		if record.TrustState == registry.TrustUnavailable {
			return fmt.Errorf("%w: trust_state %q", ErrPluginTrustUnavailable, record.TrustState)
		}
		return fmt.Errorf("%w: trust_state %q", ErrPluginTrustDenied, record.TrustState)
	}
	if record.SourcePolicySnapshotHash != "" {
		now := time.Now().UTC()
		if err := h.verifyCurrentSourcePolicy(ctx, record, now); err != nil {
			if cleanupErr := h.disablePluginForSourcePolicyFailure(ctx, record, now); cleanupErr != nil {
				return errors.Join(err, cleanupErr)
			}
			return err
		}
	}
	if record.TrustState == registry.TrustUnsignedLocal {
		if err := h.enforceUnsignedLocalPluginPolicy(ctx); err != nil {
			now := time.Now().UTC()
			if cleanupErr := h.disablePluginForPolicyFailure(ctx, record, "developer mode or local generated plugins disabled", now); cleanupErr != nil {
				return errors.Join(err, cleanupErr)
			}
			return err
		}
	}
	return nil
}

func (h *Host) enforceUnsignedLocalPluginPolicy(ctx context.Context) error {
	session, err := requireUserSession(ctx)
	if err != nil {
		return err
	}
	developerMode, err := h.adapters.Policy.DeveloperModeEnabled(ctx, session)
	if err != nil {
		return err
	}
	localGenerated, err := h.adapters.Policy.LocalGeneratedPluginsEnabled(ctx, session)
	if err != nil {
		return err
	}
	if !developerMode || !localGenerated {
		return fmt.Errorf("%w: unsigned local plugins require developer mode and local generated plugins", security.ErrPolicyDenied)
	}
	return nil
}

func (h *Host) disablePluginForSourcePolicyFailure(ctx context.Context, record registry.PluginRecord, now time.Time) error {
	return h.disablePluginForPolicyFailure(ctx, record, "source policy verification failed", now)
}

func (h *Host) disablePluginForPolicyFailure(ctx context.Context, record registry.PluginRecord, reason string, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	disabled, err := h.adapters.Registry.SetEnableState(ctx, record.PluginInstanceID, registry.EnableDisabledByPolicy, reason, now)
	if err != nil {
		return err
	}
	return h.revokePluginRuntimeCapabilities(ctx, disabled, now)
}

func (h *Host) verifyCurrentSourcePolicy(ctx context.Context, record registry.PluginRecord, now time.Time) error {
	if record.SourcePolicySnapshotHash == "" {
		return nil
	}
	ref, err := releaseRefFromRecord(record)
	if err != nil {
		return err
	}
	if h.adapters.ReleaseSourcePolicy == nil {
		return ErrReleaseSourcePolicyRequired
	}
	snapshot, err := h.adapters.ReleaseSourcePolicy.ResolveReleaseSourcePolicy(ctx, ReleaseSourcePolicyRequest{
		Action:           PackageTrustActionUpdate,
		ReleaseRef:       ref,
		CurrentRecord:    &record,
		PluginInstanceID: record.PluginInstanceID,
		Now:              now,
	})
	if err != nil {
		return err
	}
	if _, err := h.validateSourcePolicySnapshot(ctx, ref, snapshot, now); err != nil {
		return err
	}
	if err := h.recordSourceSecurityFloor(ctx, snapshot, now); err != nil {
		return err
	}
	if err := verifyInstalledRecordAgainstCurrentSourcePolicy(record, snapshot, now); err != nil {
		return err
	}
	return nil
}

func verifyInstalledRecordAgainstCurrentSourcePolicy(record registry.PluginRecord, snapshot SourcePolicySnapshot, now time.Time) error {
	for _, item := range []struct {
		name      string
		current   string
		installed string
	}{
		{name: "policy_epoch", current: snapshot.PolicyEpoch, installed: record.TrustAssessment.PolicyEpoch},
		{name: "revocation_epoch", current: snapshot.RevocationEpoch, installed: record.TrustAssessment.RevocationEpoch},
		{name: "key_rotation_epoch", current: snapshot.KeyRotationEpoch, installed: record.Metadata["source.key_rotation_epoch"]},
	} {
		if strings.TrimSpace(item.installed) == "" {
			return fmt.Errorf("%w: installed source %s is missing", ErrReleaseRefVerificationFailed, item.name)
		}
		cmp, err := compareSourcePolicyEpoch(item.current, item.installed)
		if err != nil {
			return fmt.Errorf("%w: installed source %s is invalid: %v", ErrReleaseRefVerificationFailed, item.name, err)
		}
		if cmp < 0 {
			return fmt.Errorf("%w: current source policy %s rolled back from %s to %s", ErrReleaseRefPolicyDenied, item.name, item.installed, item.current)
		}
		if cmp > 0 {
			return fmt.Errorf("%w: current source policy %s advanced from %s to %s and requires trust reassessment", ErrReleaseRefPolicyDenied, item.name, item.installed, item.current)
		}
	}
	if keyID := strings.TrimSpace(record.Metadata["release.metadata_signature_key_id"]); keyID != "" {
		if _, err := requireTrustedSourceKey(snapshot, keyID, "release_metadata", now); err != nil {
			return fmt.Errorf("%w: installed release metadata key is no longer trusted: %v", ErrReleaseRefPolicyDenied, err)
		}
	}
	if keyID := strings.TrimSpace(record.Metadata["release.package_signature_key_id"]); keyID != "" {
		if _, err := requireTrustedSourceKey(snapshot, keyID, "package_signature", now); err != nil {
			return fmt.Errorf("%w: installed package signature key is no longer trusted: %v", ErrReleaseRefPolicyDenied, err)
		}
	}
	return nil
}

func releaseRefFromRecord(record registry.PluginRecord) (PluginReleaseRef, error) {
	sourceID := strings.TrimSpace(record.Metadata["source_id"])
	metadataRef := strings.TrimSpace(record.Metadata["release.metadata_ref"])
	metadataSHA := strings.TrimSpace(record.Metadata["release.metadata_sha256"])
	if sourceID == "" || metadataRef == "" || metadataSHA == "" {
		return PluginReleaseRef{}, fmt.Errorf("%w: installed release source metadata is incomplete", ErrReleaseRefVerificationFailed)
	}
	return PluginReleaseRef{
		SourceID:              sourceID,
		ReleaseMetadataRef:    metadataRef,
		ReleaseMetadataSHA256: metadataSHA,
		PublisherID:           record.PublisherID,
		PluginID:              record.PluginID,
		Version:               record.Version,
		ExpectedHashes: PackageHashSet{
			PackageSHA256:  record.PackageHash,
			ManifestSHA256: record.ManifestHash,
			EntriesSHA256:  record.EntriesHash,
		},
	}, nil
}

func compileConnectivityPolicy(record registry.PluginRecord) (connectivity.PolicySet, bool, error) {
	if record.Manifest.NetworkAccess == nil || len(record.Manifest.NetworkAccess.Connectors) == 0 {
		return connectivity.PolicySet{}, false, nil
	}
	policy, err := connectivity.CompilePolicy(connectivity.CompileRequest{
		PluginInstanceID:   record.PluginInstanceID,
		PluginID:           record.PluginID,
		ActiveFingerprint:  record.ActiveFingerprint,
		PolicyRevision:     record.PolicyRevision,
		ManagementRevision: record.ManagementRevision,
		RevokeEpoch:        record.RevokeEpoch,
		Manifest:           record.Manifest,
	})
	if err != nil {
		return connectivity.PolicySet{}, false, err
	}
	return policy, true, nil
}

func (h *Host) installConnectivityPolicy(ctx context.Context, record registry.PluginRecord, policy connectivity.PolicySet, hasPolicy bool) (retErr error) {
	if !hasPolicy {
		return nil
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.connectivity.policy_installed", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	if h.adapters.Connectivity != nil {
		if err := h.adapters.Connectivity.InstallPolicy(ctx, policy); err != nil {
			return err
		}
	}
	return nil
}

func (h *Host) refreshConnectivityPolicy(ctx context.Context, record registry.PluginRecord) error {
	if h.adapters.Connectivity == nil {
		return nil
	}
	if record.EnableState != registry.EnableEnabled {
		return h.adapters.Connectivity.RemovePolicy(ctx, record.PluginInstanceID)
	}
	policy, hasPolicy, err := compileConnectivityPolicy(record)
	if err != nil {
		_ = h.adapters.Connectivity.RemovePolicy(ctx, record.PluginInstanceID)
		return err
	}
	if !hasPolicy {
		return h.adapters.Connectivity.RemovePolicy(ctx, record.PluginInstanceID)
	}
	if err := h.installConnectivityPolicy(ctx, record, policy, true); err != nil {
		_ = h.adapters.Connectivity.RemovePolicy(ctx, record.PluginInstanceID)
		return err
	}
	return nil
}

func (h *Host) deleteSecretBindingsIfNeeded(ctx context.Context, record registry.PluginRecord, deleteData bool) (retErr error) {
	if !deleteData {
		return nil
	}
	auditMutation, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.secrets.deleted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return err
	}
	defer func() { retErr = auditMutation.complete(context.WithoutCancel(ctx), retErr) }()
	if err := h.adapters.Secrets.DeletePlugin(ctx, record.PluginInstanceID); err != nil {
		return err
	}
	return nil
}

func (h *Host) reportLifecycleDiagnostic(ctx context.Context, record registry.PluginRecord, eventType string, err error, details map[string]any) {
	if err == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	h.diagnostic(ctx, observability.DiagnosticEvent{
		Type:              eventType,
		Severity:          "warning",
		Message:           "plugin lifecycle operation failed",
		PluginID:          record.PluginID,
		PluginInstanceID:  record.PluginInstanceID,
		ActiveFingerprint: record.ActiveFingerprint,
		Details:           details,
		InternalDetails:   map[string]any{"error": err.Error()},
	})
}

func (h *Host) reportMethodRejection(ctx context.Context, record registry.PluginRecord, method string, surfaceInstanceID string, err error) error {
	if err == nil {
		return nil
	}
	err = finalizeRPCError(ctx, err)
	reason := methodRejectionReason(err)
	var persistenceErr error
	if auditErr := h.recordSecurityEvent(ctx, AuditEvent{
		Type:              "plugin.method.rejected",
		PluginID:          record.PluginID,
		PluginInstanceID:  record.PluginInstanceID,
		SurfaceInstanceID: surfaceInstanceID,
		Details: map[string]any{
			"method": method,
			"reason": reason,
		},
	}); auditErr != nil {
		persistenceErr = errors.Join(persistenceErr, auditErr)
	}
	if h.adapters.Diagnostics != nil {
		if diagnosticErr := h.appendDiagnostic(ctx, observability.DiagnosticEvent{
			Type:              "plugin.method.rejected",
			Severity:          "warning",
			Message:           "plugin method was rejected",
			PluginID:          record.PluginID,
			PluginInstanceID:  record.PluginInstanceID,
			SurfaceInstanceID: surfaceInstanceID,
			ActiveFingerprint: record.ActiveFingerprint,
			Details: map[string]any{
				"method":              method,
				"reason":              reason,
				"surface_instance_id": surfaceInstanceID,
			},
		}); diagnosticErr != nil {
			persistenceErr = errors.Join(persistenceErr, fmt.Errorf("%w: diagnostic append failed", ErrSecurityEventPersistence))
		}
	}
	return persistenceErr
}

func (h *Host) reportMethodRejectionSafely(ctx context.Context, record registry.PluginRecord, method string, surfaceInstanceID string, err error) (reportErr error) {
	defer func() {
		if recover() != nil {
			reportErr = fmt.Errorf("%w: rejection reporting panicked", ErrSecurityEventPersistence)
		}
	}()
	return h.reportMethodRejection(ctx, record, method, surfaceInstanceID, err)
}

func methodRejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrMethodRequestContract):
		return "request_contract"
	case errors.Is(err, ErrMethodResponseContract):
		return "response_contract"
	case errors.Is(err, permissions.ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, security.ErrPolicyDenied):
		return "policy_denied"
	case errors.Is(err, ErrConfirmationRequired):
		return "confirmation_required"
	case errors.Is(err, ErrConfirmationInvalid):
		return "confirmation_invalid"
	case errors.Is(err, ErrConfirmationRejected):
		return "confirmation_rejected"
	case errors.Is(err, capability.ErrQuotaExceeded):
		return "quota_exceeded"
	case errors.Is(err, capability.ErrExecutionRevoked):
		return "execution_revoked"
	case errors.Is(err, bridge.ErrTokenAudience):
		return "remote_mismatch"
	case errors.Is(err, bridge.ErrTokenRevoked):
		return "lease_revoked"
	case errors.Is(err, bridge.ErrTokenInvalid), errors.Is(err, bridge.ErrTokenExpired), errors.Is(err, bridge.ErrTokenReplay), errors.Is(err, bridge.ErrTokenKind):
		return "token_invalid"
	case errors.Is(err, ErrPluginTrustUnavailable), errors.Is(err, ErrReleaseRefVerificationFailed):
		return "trust_unavailable"
	case errors.Is(err, ErrPluginTrustDenied):
		return "trust_denied"
	case isCapabilityBusinessError(err):
		return "business_error"
	case errors.Is(err, ErrMethodAdapterPanic):
		return "adapter_panic"
	default:
		return "unavailable"
	}
}

func isCapabilityBusinessError(err error) bool {
	_, ok := AsValidatedCapabilityBusinessError(err)
	return ok
}

func storageNamespacesFromManifest(record registry.PluginRecord) ([]storage.Namespace, error) {
	if record.Manifest.Storage == nil || len(record.Manifest.Storage.Stores) == 0 {
		return nil, nil
	}
	namespaces := make([]storage.Namespace, 0, len(record.Manifest.Storage.Stores))
	for _, store := range record.Manifest.Storage.Stores {
		namespaces = append(namespaces, storage.Namespace{
			PluginInstanceID: record.PluginInstanceID,
			StoreID:          store.StoreID,
			Kind:             storage.StoreKind(store.Kind),
			Scope:            store.Scope,
			QuotaBytes:       store.QuotaBytes,
			QuotaFiles:       storageQuotaFilesFromManifest(store.QuotaFiles),
			SchemaVersion:    store.SchemaVersion,
		})
	}
	return namespaces, nil
}

func storageQuotaFilesFromManifest(quotaFiles *int64) int64 {
	if quotaFiles == nil {
		return manifest.DefaultStoreQuotaFiles
	}
	return *quotaFiles
}

func storageNamespaceByStoreID(record registry.PluginRecord, storeID string) (storage.Namespace, bool, error) {
	namespaces, err := storageNamespacesFromManifest(record)
	if err != nil {
		return storage.Namespace{}, false, err
	}
	storeID = strings.TrimSpace(storeID)
	for _, ns := range namespaces {
		if ns.StoreID == storeID {
			return ns, true, nil
		}
	}
	return storage.Namespace{}, false, nil
}

func (h *Host) settingsSecretMetadata(ctx context.Context, record registry.PluginRecord) ([]SettingsSecretMetadata, error) {
	records, err := h.adapters.Secrets.List(ctx, secrets.ListRequest{PluginInstanceID: record.PluginInstanceID})
	if err != nil {
		return nil, err
	}
	recordByRef := make(map[string]secrets.Record, len(records))
	for _, item := range records {
		recordByRef[item.Scope+"\x00"+item.SecretRef] = item
	}
	metadata := make([]SettingsSecretMetadata, 0)
	for _, field := range record.Manifest.Settings.Fields {
		if field.Type != settings.FieldSecret {
			continue
		}
		secretRef := strings.TrimSpace(field.SecretRef)
		scope := strings.TrimSpace(field.Scope)
		lookupKey := scope + "\x00" + secretRef
		item := SettingsSecretMetadata{Key: field.Key, SecretRef: secretRef, Scope: scope}
		if stored, exists := recordByRef[lookupKey]; exists {
			item.Bound = stored.Bound
			item.LastTestStatus = stored.LastTestStatus
			item.BoundAt = stored.BoundAt
			item.TestedAt = stored.TestedAt
			updatedAt := stored.UpdatedAt
			item.UpdatedAt = &updatedAt
		}
		metadata = append(metadata, item)
	}
	return metadata, nil
}

func pluginSettingsResult(record registry.PluginRecord, snapshot plugindata.Settings, secretMetadata []SettingsSecretMetadata) (SettingsResult, error) {
	values, err := settings.DecodeValues(snapshot.Values)
	if err != nil {
		return SettingsResult{}, err
	}
	return SettingsResult{
		PluginInstanceID: record.PluginInstanceID,
		SchemaVersion:    record.Manifest.Settings.SchemaVersion,
		ValuesRevision:   snapshot.Revision,
		Values:           values,
		SecretMetadata:   secretMetadata,
	}, nil
}

func cloneSettingFields(fields []manifest.SettingFieldSpec) []manifest.SettingFieldSpec {
	cloned := make([]manifest.SettingFieldSpec, len(fields))
	copy(cloned, fields)
	return cloned
}

func secretRefDeclared(m manifest.Manifest, secretRef string) bool {
	if m.Settings != nil && settingsSecretRefDeclared(m.Settings.Fields, secretRef) {
		return true
	}
	if m.NetworkAccess != nil {
		for _, connector := range m.NetworkAccess.Connectors {
			if secretRefInMap(connector.Auth, secretRef) || secretRefInMap(connector.TLS, secretRef) {
				return true
			}
		}
	}
	return false
}

func settingsSecretRefDeclared(fields []manifest.SettingFieldSpec, secretRef string) bool {
	secretRef = strings.TrimSpace(secretRef)
	for _, field := range fields {
		if field.Type == settings.FieldSecret && strings.TrimSpace(field.SecretRef) == secretRef {
			return true
		}
	}
	return false
}

func secretRefInMap(values map[string]any, secretRef string) bool {
	for key, value := range values {
		if strings.EqualFold(key, "secret_ref") {
			if text, ok := value.(string); ok && strings.TrimSpace(text) == secretRef {
				return true
			}
		}
		if nested, ok := value.(map[string]any); ok && secretRefInMap(nested, secretRef) {
			return true
		}
	}
	return false
}

func defaultPluginInstanceID(pkg pluginpkg.Package) string {
	sum := sha256.Sum256([]byte(pkg.Manifest.Publisher.PublisherID + "\x00" + pkg.Manifest.PluginID() + "\x00" + pkg.PackageHash))
	return "plugini_" + hex.EncodeToString(sum[:16])
}

func lifecycleNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}

func newSurfaceInstanceID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "surface_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func newHostSurfaceGenerationID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "host_surface_gen_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func manifestSurfaceByID(m manifest.Manifest, surfaceID string) (manifest.SurfaceSpec, bool) {
	for _, surface := range m.Surfaces {
		if surface.SurfaceID == surfaceID {
			return surface, true
		}
	}
	return manifest.SurfaceSpec{}, false
}

func packageEntryByPath(entries []pluginpkg.Entry, entryPath string) (pluginpkg.Entry, bool) {
	for _, entry := range entries {
		if entry.Path == entryPath {
			return entry, true
		}
	}
	return pluginpkg.Entry{}, false
}

func ImportLocalPackageBytes(ctx context.Context, h *Host, data []byte) (registry.PluginRecord, error) {
	return h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
		PackageReader: bytes.NewReader(data),
		PackageSize:   int64(len(data)),
	})
}
