package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/browsersite"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/cleanup"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
)

type AuditSink = observability.AuditSink

type DiagnosticsSink = observability.DiagnosticsSink

type AuditLister = observability.AuditLister

type DiagnosticLister = observability.DiagnosticLister

type AuditEvent = observability.AuditEvent

type DiagnosticEvent = observability.DiagnosticEvent

type ListAuditEventsRequest = observability.ListAuditRequest

type ListDiagnosticEventsRequest = observability.ListDiagnosticRequest

var ErrStreamTicketRequired = errors.New("stream ticket is required")

type PolicyAdapter interface {
	EvaluateLocalPolicy(ctx context.Context, session sessionctx.Context, plugin PluginRef, method manifest.MethodSpec) (PolicyDecision, error)
	DeveloperModeEnabled(ctx context.Context, session sessionctx.Context) (bool, error)
	LocalGeneratedPluginsEnabled(ctx context.Context, session sessionctx.Context) (bool, error)
}

// PackageTrustVerifier is the install/update trust decision boundary. The Host
// library treats requested trust_state values as requests only; runnable
// verified/bundled states must come from this verifier or installation fails.
type PackageTrustVerifier interface {
	VerifyPackageTrust(ctx context.Context, req PackageTrustVerificationRequest) (PackageTrustVerificationResult, error)
}

type PackageTrustAction string

const (
	PackageTrustActionInstall PackageTrustAction = "install"
	PackageTrustActionUpdate  PackageTrustAction = "update"
)

type PackageTrustVerificationRequest struct {
	Action              PackageTrustAction     `json:"action"`
	Package             pluginpkg.Package      `json:"package"`
	RequestedTrustState registry.TrustState    `json:"requested_trust_state"`
	CurrentRecord       *registry.PluginRecord `json:"current_record,omitempty"`
	PluginInstanceID    string                 `json:"plugin_instance_id,omitempty"`
	Now                 time.Time              `json:"now,omitempty"`
}

type PackageTrustVerificationResult struct {
	TrustState registry.TrustState `json:"trust_state"`
	Metadata   map[string]string   `json:"metadata,omitempty"`
}

type PolicyDecision string

const (
	PolicyAllow PolicyDecision = "allow"
	PolicyDeny  PolicyDecision = "deny"
)

type SecretStoreAdapter interface {
	BindSecretRef(ctx context.Context, req SecretBindRequest) error
	DeleteSecretRef(ctx context.Context, req SecretDeleteRequest) error
	TestSecretRef(ctx context.Context, req SecretTestRequest) error
}

type SecretBindRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	SecretRef        string `json:"secret_ref"`
	Scope            string `json:"scope"`
}

type SecretDeleteRequest = SecretBindRequest
type SecretTestRequest = SecretBindRequest

type RuntimeArtifactResolver interface {
	RuntimePath(ctx context.Context, target RuntimeTarget) (string, error)
}

type CoreActionAdapter interface {
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

type Adapters struct {
	SessionResolver         sessionctx.Resolver
	Policy                  PolicyAdapter
	PackageTrustVerifier    PackageTrustVerifier
	Registry                registry.Store
	Audit                   AuditSink
	Diagnostics             DiagnosticsSink
	Secrets                 SecretStoreAdapter
	RuntimeArtifactResolver RuntimeArtifactResolver
	RuntimeSupervisor       runtimeclient.Supervisor
	SurfaceCatalog          SurfaceCatalogSink
	Assets                  pluginpkg.AssetStore
	Capabilities            *capability.Registry
	CoreActions             CoreActionAdapter
	SurfaceTokens           *bridge.SurfaceTokenService
	Storage                 storage.Broker
	Connectivity            connectivity.Broker
	NetworkExecutor         connectivity.NetworkExecutor
	Operations              operation.Store
	Permissions             permissions.Store
	Cleanup                 cleanup.Orchestrator
	BrowserSite             browsersite.Store
	Settings                settings.Store
	Streams                 stream.Store
}

type Host struct {
	adapters      Adapters
	surfaceTokens *bridge.SurfaceTokenService
	runtimeMu     sync.Mutex
}

type InstallRequest struct {
	PackageReader    io.ReaderAt
	PackageSize      int64
	TrustState       registry.TrustState
	PluginInstanceID string
	Now              time.Time
}

type UpdateRequest struct {
	PluginInstanceID string
	PackageReader    io.ReaderAt
	PackageSize      int64
	TrustState       registry.TrustState
	Now              time.Time
}

type DowngradeRequest struct {
	PluginInstanceID string
	Version          string
	PackageHash      string
	Now              time.Time
}

type EnableRequest struct {
	PluginInstanceID string
	Now              time.Time
}

type DisableRequest struct {
	PluginInstanceID string
	Reason           string
	Now              time.Time
}

type UninstallRequest struct {
	PluginInstanceID string
	DeleteData       bool
	Now              time.Time
}

type ExportDataRequest struct {
	PluginInstanceID string
	IncludeSecrets   bool
}

type ImportDataRequest struct {
	PluginInstanceID string
	ArchiveRef       string
	DeleteExisting   bool
}

type ExportDataResult struct {
	ArchiveRef string `json:"archive_ref"`
}

type GrantPermissionRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionID     string    `json:"permission_id"`
	GrantedBy        string    `json:"granted_by,omitempty"`
	Now              time.Time `json:"now,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type RevokePermissionRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionID     string    `json:"permission_id"`
	RevokedBy        string    `json:"revoked_by,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	Now              time.Time `json:"now,omitempty"`
}

type ListPermissionGrantsRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
	ActiveOnly       bool   `json:"active_only,omitempty"`
}

type GetSettingsRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
}

type PatchSettingsRequest struct {
	PluginInstanceID string         `json:"plugin_instance_id"`
	Values           map[string]any `json:"values"`
	Now              time.Time      `json:"now,omitempty"`
}

type SettingsSchemaResult struct {
	PluginInstanceID string                      `json:"plugin_instance_id"`
	SchemaVersion    int                         `json:"schema_version"`
	Migration        manifest.MigrationSpec      `json:"migration"`
	Fields           []manifest.SettingFieldSpec `json:"fields"`
	SettingsRevision uint64                      `json:"settings_revision"`
}

type SettingsResult struct {
	PluginInstanceID string         `json:"plugin_instance_id"`
	SchemaVersion    int            `json:"schema_version"`
	SettingsRevision uint64         `json:"settings_revision"`
	Values           map[string]any `json:"values"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type OpenSurfaceRequest struct {
	PluginInstanceID     string
	SurfaceID            string
	SurfaceInstanceID    string
	OwnerSessionHash     string
	OwnerUserHash        string
	SessionChannelIDHash string
	SandboxOrigin        string
	Now                  time.Time
}

type ExchangeAssetTicketRequest struct {
	SurfaceInstanceID string
	AssetTicket       string
	Now               time.Time
}

type ReadSurfaceAssetRequest struct {
	AssetSession string
	AssetPath    string
	Now          time.Time
}

type ReadSurfaceAssetResult struct {
	Entry   pluginpkg.Entry
	Content []byte
	Session bridge.SurfaceSession
}

type CSPViolationReport struct {
	PluginID           string         `json:"plugin_id,omitempty"`
	PluginInstanceID   string         `json:"plugin_instance_id,omitempty"`
	SurfaceID          string         `json:"surface_id,omitempty"`
	SurfaceInstanceID  string         `json:"surface_instance_id,omitempty"`
	ActiveFingerprint  string         `json:"active_fingerprint,omitempty"`
	BlockedURI         string         `json:"blocked_uri,omitempty"`
	DocumentURI        string         `json:"document_uri,omitempty"`
	EffectiveDirective string         `json:"effective_directive,omitempty"`
	ViolatedDirective  string         `json:"violated_directive,omitempty"`
	OriginalPolicy     string         `json:"original_policy,omitempty"`
	Disposition        string         `json:"disposition,omitempty"`
	LineNumber         int            `json:"line_number,omitempty"`
	ColumnNumber       int            `json:"column_number,omitempty"`
	SourceFile         string         `json:"source_file,omitempty"`
	Sample             string         `json:"sample,omitempty"`
	Raw                map[string]any `json:"raw,omitempty"`
}

type MintBridgeTokenRequest struct {
	Handshake       bridge.Handshake
	BridgeChannelID string
	Now             time.Time
}

type CallMethodRequest struct {
	PluginInstanceID     string         `json:"plugin_instance_id"`
	SurfaceInstanceID    string         `json:"surface_instance_id"`
	SessionChannelIDHash string         `json:"session_channel_id_hash,omitempty"`
	OwnerSessionHash     string         `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string         `json:"owner_user_hash,omitempty"`
	BridgeChannelID      string         `json:"bridge_channel_id"`
	GatewayToken         string         `json:"plugin_gateway_token"`
	ConfirmationToken    string         `json:"confirmation_token,omitempty"`
	Method               string         `json:"method"`
	Params               map[string]any `json:"params,omitempty"`
	Now                  time.Time      `json:"now,omitempty"`
}

type CallMethodResult struct {
	Data                 any    `json:"data,omitempty"`
	OperationID          string `json:"operation_id,omitempty"`
	StreamID             string `json:"stream_id,omitempty"`
	StreamTicket         string `json:"stream_ticket,omitempty"`
	StreamTicketID       string `json:"stream_ticket_id,omitempty"`
	ConfirmationRequired bool   `json:"confirmation_required,omitempty"`
	ConfirmationTokenID  string `json:"confirmation_token_id,omitempty"`
	RequestHash          string `json:"request_hash,omitempty"`
}

type IntentRecord struct {
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

type ListIntentsRequest struct {
	IntentID         string `json:"intent_id,omitempty"`
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type InvokeIntentRequest struct {
	PluginInstanceID     string         `json:"plugin_instance_id,omitempty"`
	IntentID             string         `json:"intent_id"`
	Params               map[string]any `json:"params,omitempty"`
	OwnerSessionHash     string         `json:"owner_session_hash,omitempty"`
	OwnerUserHash        string         `json:"owner_user_hash,omitempty"`
	SessionChannelIDHash string         `json:"session_channel_id_hash,omitempty"`
	Now                  time.Time      `json:"now,omitempty"`
}

type WorkerInvocationPayload struct {
	PluginID             string         `json:"plugin_id"`
	PluginInstanceID     string         `json:"plugin_instance_id"`
	ActiveFingerprint    string         `json:"active_fingerprint"`
	RuntimeInstanceID    string         `json:"runtime_instance_id"`
	RuntimeGenerationID  string         `json:"runtime_generation_id"`
	PackageHash          string         `json:"package_hash"`
	WorkerID             string         `json:"worker_id"`
	WorkerMode           string         `json:"worker_mode"`
	WorkerScope          string         `json:"worker_scope"`
	Artifact             string         `json:"artifact"`
	ArtifactSHA256       string         `json:"artifact_sha256"`
	ABI                  string         `json:"abi"`
	Method               string         `json:"method"`
	Export               string         `json:"export"`
	Effect               string         `json:"effect"`
	Execution            string         `json:"execution"`
	SurfaceInstanceID    string         `json:"surface_instance_id,omitempty"`
	SessionChannelIDHash string         `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string         `json:"bridge_channel_id,omitempty"`
	Params               map[string]any `json:"params"`
}

type ConfirmMethodRequest = CallMethodRequest

type ConfirmMethodResult struct {
	ConfirmationToken   string    `json:"confirmation_token"`
	ConfirmationTokenID string    `json:"confirmation_token_id"`
	RequestHash         string    `json:"request_hash"`
	ExpiresAt           time.Time `json:"expires_at"`
}

var (
	ErrSecretStoreRequired             = errors.New("secret store adapter is required")
	ErrInvalidSecretRef                = errors.New("secret_ref is invalid")
	ErrPackageTrustVerifierRequired    = errors.New("package trust verifier is required for requested trust state")
	ErrPackageTrustVerificationInvalid = errors.New("package trust verifier returned invalid trust state")
)

type ListOperationsRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type CancelOperationRequest struct {
	OperationID string `json:"operation_id"`
	Reason      string `json:"reason,omitempty"`
	Now         time.Time
}

type FinishOperationRequest struct {
	OperationID string           `json:"operation_id"`
	Status      operation.Status `json:"status"`
	Reason      string           `json:"reason,omitempty"`
	Now         time.Time
}

type AppendStreamEventRequest struct {
	StreamID string    `json:"stream_id"`
	Kind     string    `json:"kind,omitempty"`
	Data     []byte    `json:"data,omitempty"`
	Error    string    `json:"error,omitempty"`
	Now      time.Time `json:"now,omitempty"`
}

type ReadStreamRequest struct {
	StreamID     string `json:"stream_id"`
	StreamTicket string `json:"stream_ticket,omitempty"`
	MaxEvents    int    `json:"max_events,omitempty"`
	MaxBytes     int64  `json:"max_bytes,omitempty"`
}

type ReadStreamResult struct {
	Record stream.Record  `json:"record"`
	Events []stream.Event `json:"events,omitempty"`
}

type CloseStreamRequest struct {
	StreamID string        `json:"stream_id"`
	Status   stream.Status `json:"status,omitempty"`
	Reason   string        `json:"reason,omitempty"`
	Now      time.Time     `json:"now,omitempty"`
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

func New(adapters Adapters) (*Host, error) {
	if adapters.SessionResolver == nil {
		return nil, errors.New("session resolver is required")
	}
	if adapters.Policy == nil {
		return nil, errors.New("policy adapter is required")
	}
	if adapters.Registry == nil {
		adapters.Registry = registry.NewMemoryStore()
	}
	if adapters.Audit == nil || adapters.Diagnostics == nil {
		store := observability.NewMemoryStore()
		if adapters.Audit == nil {
			adapters.Audit = store
		}
		if adapters.Diagnostics == nil {
			adapters.Diagnostics = store
		}
	}
	if adapters.Capabilities == nil {
		adapters.Capabilities = capability.NewRegistry()
	}
	if adapters.SurfaceTokens == nil {
		adapters.SurfaceTokens = bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{})
	}
	if adapters.Connectivity == nil {
		adapters.Connectivity = connectivity.NewMemoryBroker()
	}
	if adapters.NetworkExecutor == nil {
		adapters.NetworkExecutor = connectivity.NewExecutor(connectivity.ExecutorOptions{})
	}
	if adapters.Operations == nil {
		adapters.Operations = operation.NewMemoryStore()
	}
	if adapters.Permissions == nil {
		adapters.Permissions = permissions.NewMemoryStore()
	}
	if adapters.Cleanup == nil {
		adapters.Cleanup = cleanup.NewMemoryOrchestrator()
	}
	if adapters.BrowserSite == nil {
		adapters.BrowserSite = browsersite.NewMemoryStore()
	}
	if adapters.Settings == nil {
		adapters.Settings = settings.NewMemoryStore()
	}
	if adapters.Streams == nil {
		adapters.Streams = stream.NewMemoryStore()
	}
	if adapters.Assets == nil {
		adapters.Assets = pluginpkg.NewMemoryAssetStore()
	}
	return &Host{adapters: adapters, surfaceTokens: adapters.SurfaceTokens}, nil
}

func (h *Host) Capabilities() *capability.Registry {
	return h.adapters.Capabilities
}

func (h *Host) OpenSurface(ctx context.Context, req OpenSurfaceRequest) (bridge.SurfaceBootstrap, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		return bridge.SurfaceBootstrap{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	if !manifestHasSurface(record.Manifest, req.SurfaceID) {
		return bridge.SurfaceBootstrap{}, fmt.Errorf("surface %q is not declared", req.SurfaceID)
	}
	if req.SurfaceInstanceID == "" {
		req.SurfaceInstanceID = defaultSurfaceInstanceID(record, req.SurfaceID, req.OwnerSessionHash)
	}
	bootstrap, err := h.surfaceTokens.OpenSurface(bridge.OpenSurfaceRequest{
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		SurfaceID:            req.SurfaceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		ActiveFingerprint:    record.ActiveFingerprint,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
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
	if err := h.registerBrowserOrigin(ctx, record, req, bootstrap); err != nil {
		return bridge.SurfaceBootstrap{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.surface.opened", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return bootstrap, nil
}

func (h *Host) registerBrowserOrigin(ctx context.Context, record registry.PluginRecord, req OpenSurfaceRequest, bootstrap bridge.SurfaceBootstrap) error {
	if h.adapters.BrowserSite == nil || strings.TrimSpace(req.SandboxOrigin) == "" {
		return nil
	}
	origin, err := h.adapters.BrowserSite.RegisterOrigin(ctx, browsersite.RegisterRequest{
		PluginInstanceID:  record.PluginInstanceID,
		PluginID:          record.PluginID,
		ActiveFingerprint: record.ActiveFingerprint,
		SurfaceID:         req.SurfaceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		Origin:            req.SandboxOrigin,
		OwnerSessionHash:  req.OwnerSessionHash,
		OwnerUserHash:     req.OwnerUserHash,
		Now:               req.Now,
	})
	if err != nil {
		return err
	}
	h.audit(ctx, AuditEvent{
		Type:             "plugin.browser_origin.registered",
		PluginID:         record.PluginID,
		PluginInstanceID: record.PluginInstanceID,
		SurfaceID:        req.SurfaceID,
		Details: map[string]any{
			"origin":              origin.Origin,
			"surface_instance_id": origin.SurfaceInstanceID,
			"origin_state":        string(origin.State),
		},
	})
	return nil
}

func (h *Host) ExchangeAssetTicket(ctx context.Context, req ExchangeAssetTicketRequest) (bridge.AssetSessionResult, error) {
	result, err := h.surfaceTokens.ExchangeAssetTicket(bridge.ExchangeAssetTicketRequest{
		SurfaceInstanceID: req.SurfaceInstanceID,
		AssetTicket:       req.AssetTicket,
		Now:               req.Now,
	})
	if err != nil {
		return bridge.AssetSessionResult{}, err
	}
	return result, nil
}

func (h *Host) ReadSurfaceAsset(ctx context.Context, req ReadSurfaceAssetRequest) (ReadSurfaceAssetResult, error) {
	if h.adapters.Assets == nil {
		return ReadSurfaceAssetResult{}, errors.New("package asset store is required")
	}
	validation, err := h.surfaceTokens.ValidateAssetSession(bridge.ValidateAssetSessionRequest{
		AssetSession: req.AssetSession,
		Now:          req.Now,
	})
	if err != nil {
		return ReadSurfaceAssetResult{}, err
	}
	record, err := h.adapters.Registry.GetPlugin(ctx, validation.Session.PluginInstanceID)
	if err != nil {
		return ReadSurfaceAssetResult{}, err
	}
	if record.ActiveFingerprint != validation.Session.ActiveFingerprint {
		return ReadSurfaceAssetResult{}, bridge.ErrTokenRevoked
	}
	if record.EnableState != registry.EnableEnabled {
		return ReadSurfaceAssetResult{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return ReadSurfaceAssetResult{}, err
	}
	asset, err := h.adapters.Assets.ReadAsset(ctx, record.PackageHash, req.AssetPath)
	if err != nil {
		return ReadSurfaceAssetResult{}, err
	}
	return ReadSurfaceAssetResult{
		Entry:   asset.Entry,
		Content: asset.Content,
		Session: validation.Session,
	}, nil
}

func (h *Host) MintBridgeToken(ctx context.Context, req MintBridgeTokenRequest) (bridge.GatewayTokenResult, error) {
	result, err := h.surfaceTokens.MintGatewayToken(bridge.MintGatewayTokenRequest{
		Handshake:       req.Handshake,
		BridgeChannelID: req.BridgeChannelID,
		Now:             req.Now,
	})
	if err != nil {
		return bridge.GatewayTokenResult{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.bridge_token.minted", PluginID: req.Handshake.PluginID})
	return result, nil
}

func (h *Host) CallPluginMethod(ctx context.Context, req CallMethodRequest) (CallMethodResult, error) {
	call, err := h.resolveMethodCall(ctx, req)
	if err != nil {
		return CallMethodResult{}, err
	}
	if methodRequiresConfirmation(call.method) {
		requestHash, err := methodRequestHash(call.method, req.Params)
		if err != nil {
			return CallMethodResult{}, err
		}
		if req.ConfirmationToken == "" {
			return CallMethodResult{
				ConfirmationRequired: true,
				RequestHash:          requestHash,
			}, ErrConfirmationRequired
		}
		confirmationAudience := call.audience
		confirmationAudience.Method = call.method.Method
		confirmationAudience.RequestHash = requestHash
		if _, err := h.surfaceTokens.ValidateConfirmationToken(bridge.ValidateConfirmationTokenRequest{
			ConfirmationToken: req.ConfirmationToken,
			Audience:          confirmationAudience,
			Revision:          call.revision,
			Now:               req.Now,
		}); err != nil {
			return CallMethodResult{}, err
		}
	}
	result, err := h.dispatchMethod(ctx, call.record, call.method, req)
	if err != nil {
		return CallMethodResult{}, err
	}
	if result.StreamID != "" {
		streamTicket, err := h.surfaceTokens.MintStreamTicket(bridge.MintStreamTicketRequest{
			PluginInstanceID:     call.record.PluginInstanceID,
			ActiveFingerprint:    call.record.ActiveFingerprint,
			SurfaceInstanceID:    req.SurfaceInstanceID,
			OwnerSessionHash:     req.OwnerSessionHash,
			OwnerUserHash:        req.OwnerUserHash,
			SessionChannelIDHash: req.SessionChannelIDHash,
			BridgeChannelID:      req.BridgeChannelID,
			StreamID:             result.StreamID,
			StreamDirection:      "read",
			Method:               call.method.Method,
			Revision:             call.revision,
			Now:                  req.Now,
		})
		if err != nil {
			return CallMethodResult{}, err
		}
		result.StreamTicket = streamTicket.StreamTicket
		result.StreamTicketID = streamTicket.StreamTicketID
	}
	h.audit(ctx, AuditEvent{Type: "plugin.method.called", PluginID: call.record.PluginID, PluginInstanceID: call.record.PluginInstanceID})
	return result, nil
}

func (h *Host) PrepareMethodConfirmation(ctx context.Context, req ConfirmMethodRequest) (ConfirmMethodResult, error) {
	call, err := h.resolveMethodCall(ctx, CallMethodRequest{
		PluginInstanceID:     req.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: req.SessionChannelIDHash,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		BridgeChannelID:      req.BridgeChannelID,
		GatewayToken:         req.GatewayToken,
		Method:               req.Method,
		Params:               req.Params,
		Now:                  req.Now,
	})
	if err != nil {
		return ConfirmMethodResult{}, err
	}
	if !methodRequiresConfirmation(call.method) {
		return ConfirmMethodResult{}, errors.New("method does not require confirmation")
	}
	requestHash, err := methodRequestHash(call.method, req.Params)
	if err != nil {
		return ConfirmMethodResult{}, err
	}
	result, err := h.surfaceTokens.MintConfirmationToken(bridge.MintConfirmationTokenRequest{
		PluginInstanceID:     call.record.PluginInstanceID,
		ActiveFingerprint:    call.record.ActiveFingerprint,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Method:               call.method.Method,
		RequestHash:          requestHash,
		Revision:             call.revision,
		Now:                  req.Now,
	})
	if err != nil {
		return ConfirmMethodResult{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.confirmation.issued", PluginID: call.record.PluginID, PluginInstanceID: call.record.PluginInstanceID})
	return ConfirmMethodResult{
		ConfirmationToken:   result.ConfirmationToken,
		ConfirmationTokenID: result.ConfirmationTokenID,
		RequestHash:         result.RequestHash,
		ExpiresAt:           result.ExpiresAt,
	}, nil
}

func (h *Host) ListIntents(ctx context.Context, req ListIntentsRequest) ([]IntentRecord, error) {
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
			intents = append(intents, IntentRecord{
				PluginID:          record.PluginID,
				PluginInstanceID:  record.PluginInstanceID,
				PublisherID:       record.PublisherID,
				DisplayName:       record.Manifest.Plugin.DisplayName,
				Version:           record.Version,
				ActiveFingerprint: record.ActiveFingerprint,
				IntentID:          intent.IntentID,
				Method:            intent.Method,
				Effect:            string(method.Effect),
				Execution:         string(method.Execution),
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

func (h *Host) InvokeIntent(ctx context.Context, req InvokeIntentRequest) (CallMethodResult, error) {
	resolved, err := h.resolveIntent(ctx, req)
	if err != nil {
		return CallMethodResult{}, err
	}
	if methodRequiresConfirmation(resolved.method) {
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
		PluginInstanceID:     resolved.record.PluginInstanceID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		Method:               resolved.method.Method,
		Params:               cloneParams(req.Params),
		Now:                  req.Now,
	}
	result, err := h.dispatchMethod(ctx, resolved.record, resolved.method, callReq)
	if err != nil {
		return CallMethodResult{}, err
	}
	if result.StreamID != "" {
		streamTicket, err := h.surfaceTokens.MintStreamTicket(bridge.MintStreamTicketRequest{
			PluginInstanceID:     resolved.record.PluginInstanceID,
			ActiveFingerprint:    resolved.record.ActiveFingerprint,
			OwnerSessionHash:     req.OwnerSessionHash,
			OwnerUserHash:        req.OwnerUserHash,
			SessionChannelIDHash: req.SessionChannelIDHash,
			StreamID:             result.StreamID,
			StreamDirection:      "read",
			Method:               resolved.method.Method,
			Revision:             resolved.revision,
			Now:                  req.Now,
		})
		if err != nil {
			return CallMethodResult{}, err
		}
		result.StreamTicket = streamTicket.StreamTicket
		result.StreamTicketID = streamTicket.StreamTicketID
	}
	h.audit(ctx, AuditEvent{
		Type:             "plugin.intent.invoked",
		PluginID:         resolved.record.PluginID,
		PluginInstanceID: resolved.record.PluginInstanceID,
		Details: map[string]any{
			"intent_id": req.IntentID,
			"method":    resolved.method.Method,
		},
	})
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

func (h *Host) resolveMethodCall(ctx context.Context, req CallMethodRequest) (resolvedMethodCall, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return resolvedMethodCall{}, err
	}
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
	audience := bridge.Audience{
		PluginInstanceID:     record.PluginInstanceID,
		ActiveFingerprint:    record.ActiveFingerprint,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
	}
	revision := bridge.RevisionBinding{
		PolicyRevision:     record.PolicyRevision,
		ManagementRevision: record.ManagementRevision,
		RevokeEpoch:        record.RevokeEpoch,
	}
	if _, err := h.surfaceTokens.ValidateGatewayToken(req.GatewayToken, audience, revision, req.Now); err != nil {
		return resolvedMethodCall{}, err
	}
	session := sessionctx.Context{
		SessionChannelIDHash: req.SessionChannelIDHash,
		OwnerUserHash:        req.OwnerUserHash,
	}
	decision, err := h.adapters.Policy.EvaluateLocalPolicy(ctx, session, pluginRefFromRecord(record), method)
	if err != nil {
		return resolvedMethodCall{}, err
	}
	if decision != PolicyAllow {
		return resolvedMethodCall{}, errors.New("plugin method denied by local policy")
	}
	requiredPermissions := requiredPermissionsForMethod(record.Manifest, method)
	granted, missing, err := h.adapters.Permissions.IsGranted(ctx, permissions.CheckRequest{
		PluginInstanceID: record.PluginInstanceID,
		PermissionIDs:    requiredPermissions,
		Now:              req.Now,
	})
	if err != nil {
		return resolvedMethodCall{}, err
	}
	if !granted {
		return resolvedMethodCall{}, fmt.Errorf("%w: %s", permissions.ErrPermissionDenied, strings.Join(missing, ", "))
	}
	return resolvedMethodCall{record: record, method: method, audience: audience, revision: revision}, nil
}

func (h *Host) resolveIntent(ctx context.Context, req InvokeIntentRequest) (resolvedIntentCall, error) {
	intentID := strings.TrimSpace(req.IntentID)
	if intentID == "" {
		return resolvedIntentCall{}, errors.New("intent_id is required")
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
		return resolvedIntentCall{}, fmt.Errorf("intent %q is not available", intentID)
	}
	if len(matches) > 1 && strings.TrimSpace(req.PluginInstanceID) == "" {
		return resolvedIntentCall{}, fmt.Errorf("intent %q is ambiguous; plugin_instance_id is required", intentID)
	}
	resolved := matches[0]
	session := sessionctx.Context{
		SessionChannelIDHash: req.SessionChannelIDHash,
		OwnerUserHash:        req.OwnerUserHash,
	}
	decision, err := h.adapters.Policy.EvaluateLocalPolicy(ctx, session, pluginRefFromRecord(resolved.record), resolved.method)
	if err != nil {
		return resolvedIntentCall{}, err
	}
	if decision != PolicyAllow {
		return resolvedIntentCall{}, errors.New("plugin intent denied by local policy")
	}
	requiredPermissions := requiredPermissionsForMethod(resolved.record.Manifest, resolved.method)
	granted, missing, err := h.adapters.Permissions.IsGranted(ctx, permissions.CheckRequest{
		PluginInstanceID: resolved.record.PluginInstanceID,
		PermissionIDs:    requiredPermissions,
		Now:              req.Now,
	})
	if err != nil {
		return resolvedIntentCall{}, err
	}
	if !granted {
		return resolvedIntentCall{}, fmt.Errorf("%w: %s", permissions.ErrPermissionDenied, strings.Join(missing, ", "))
	}
	return resolved, nil
}

func (h *Host) InstallPackage(ctx context.Context, req InstallRequest) (registry.PluginRecord, error) {
	if req.PackageReader == nil {
		return registry.PluginRecord{}, errors.New("package reader is required")
	}
	pkg, err := pluginpkg.Read(ctx, req.PackageReader, req.PackageSize, pluginpkg.DefaultReadOptions())
	if err != nil {
		return registry.PluginRecord{}, err
	}
	trust, metadata, err := h.resolvePackageTrust(ctx, PackageTrustActionInstall, pkg, req.TrustState, nil, req.PluginInstanceID, req.Now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	record := packageRecord(pkg, trust, req.PluginInstanceID, metadata)
	record.EnableState = registry.EnableDisabled
	record.RetainedDataState = registry.RetainedDataNone
	if err := h.adapters.Assets.PutPackage(ctx, pkg); err != nil {
		return registry.PluginRecord{}, err
	}
	stored, err := h.adapters.Registry.PutPlugin(ctx, record, registry.PutOptions{Now: req.Now})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.installed", PluginID: stored.PluginID, PluginInstanceID: stored.PluginInstanceID})
	return stored, nil
}

func (h *Host) UpdatePlugin(ctx context.Context, req UpdateRequest) (registry.PluginRecord, error) {
	current, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if req.PackageReader == nil {
		return registry.PluginRecord{}, errors.New("package reader is required")
	}
	pkg, err := pluginpkg.Read(ctx, req.PackageReader, req.PackageSize, pluginpkg.DefaultReadOptions())
	if err != nil {
		return registry.PluginRecord{}, err
	}
	requestedTrust := req.TrustState
	if requestedTrust == "" {
		requestedTrust = current.TrustState
	}
	trust, metadata, err := h.resolvePackageTrust(ctx, PackageTrustActionUpdate, pkg, requestedTrust, &current, current.PluginInstanceID, req.Now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	next := packageRecord(pkg, trust, current.PluginInstanceID, metadata)
	if err := validateSamePluginIdentity(current, next); err != nil {
		return registry.PluginRecord{}, err
	}
	next.VersionHistory = current.VersionHistory
	next = prepareVersionSwitchRecord(current, next, versionSnapshot(current, req.Now), req.Now)
	if next.EnableState == registry.EnableEnabled {
		if err := h.validateEnabledRuntimeState(ctx, next); err != nil {
			return registry.PluginRecord{}, err
		}
	}
	if err := h.adapters.Assets.PutPackage(ctx, pkg); err != nil {
		return registry.PluginRecord{}, err
	}
	stored, err := h.adapters.Registry.PutPlugin(ctx, next, registry.PutOptions{Now: req.Now})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.refreshEnabledRuntimeState(ctx, stored); err != nil {
		return registry.PluginRecord{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.updated", PluginID: stored.PluginID, PluginInstanceID: stored.PluginInstanceID})
	return stored, nil
}

func (h *Host) DowngradePlugin(ctx context.Context, req DowngradeRequest) (registry.PluginRecord, error) {
	current, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	snapshot, remaining, err := selectVersionSnapshot(current.VersionHistory, req.Version, req.PackageHash)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	next := recordFromVersionSnapshot(current, snapshot)
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
	if err := h.refreshEnabledRuntimeState(ctx, stored); err != nil {
		return registry.PluginRecord{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.downgraded", PluginID: stored.PluginID, PluginInstanceID: stored.PluginInstanceID})
	return stored, nil
}

func (h *Host) resolvePackageTrust(ctx context.Context, action PackageTrustAction, pkg pluginpkg.Package, requested registry.TrustState, current *registry.PluginRecord, instanceID string, now time.Time) (registry.TrustState, map[string]string, error) {
	if requested == "" {
		requested = registry.TrustUntrusted
	}
	if !knownTrustState(requested) {
		return "", nil, fmt.Errorf("%w: %q", ErrPackageTrustVerificationInvalid, requested)
	}
	if h.adapters.PackageTrustVerifier == nil {
		if trustStateRequiresVerifier(requested) {
			return "", nil, ErrPackageTrustVerifierRequired
		}
		return requested, nil, nil
	}
	result, err := h.adapters.PackageTrustVerifier.VerifyPackageTrust(ctx, PackageTrustVerificationRequest{
		Action:              action,
		Package:             pkg,
		RequestedTrustState: requested,
		CurrentRecord:       current,
		PluginInstanceID:    instanceID,
		Now:                 now,
	})
	if err != nil {
		return "", nil, err
	}
	if !knownTrustState(result.TrustState) {
		return "", nil, fmt.Errorf("%w: %q", ErrPackageTrustVerificationInvalid, result.TrustState)
	}
	return result.TrustState, cloneStringMap(result.Metadata), nil
}

func knownTrustState(state registry.TrustState) bool {
	switch state {
	case registry.TrustBundled, registry.TrustVerified, registry.TrustUnsignedLocal, registry.TrustUntrusted, registry.TrustNeedsReview, registry.TrustBlockedSecurity:
		return true
	default:
		return false
	}
}

func trustStateRequiresVerifier(state registry.TrustState) bool {
	switch state {
	case registry.TrustBundled, registry.TrustVerified:
		return true
	default:
		return false
	}
}

func packageRecord(pkg pluginpkg.Package, trust registry.TrustState, instanceID string, metadata map[string]string) registry.PluginRecord {
	if instanceID == "" {
		instanceID = defaultPluginInstanceID(pkg)
	}
	return registry.PluginRecord{
		PluginInstanceID:  instanceID,
		PublisherID:       pkg.Manifest.Publisher.PublisherID,
		PluginID:          pkg.Manifest.PluginID(),
		Version:           pkg.Manifest.Version(),
		ActiveFingerprint: pkg.PackageHash,
		PackageHash:       pkg.PackageHash,
		ManifestHash:      pkg.ManifestHash,
		EntriesHash:       pkg.EntriesHash,
		TrustState:        trust,
		EnableState:       registry.EnableDisabled,
		Manifest:          pkg.Manifest,
		PackageEntries:    pkg.Entries,
		RetainedDataState: registry.RetainedDataNone,
		Metadata:          cloneStringMap(metadata),
	}
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
	next.RetainedDataState = current.RetainedDataState
	next.PolicyRevision = current.PolicyRevision
	next.ManagementRevision = current.ManagementRevision
	next.RevokeEpoch = current.RevokeEpoch
	next.InstalledAt = current.InstalledAt
	next.EnabledAt = cloneTimePtr(current.EnabledAt)
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
		Version:           record.Version,
		ActiveFingerprint: record.ActiveFingerprint,
		PackageHash:       record.PackageHash,
		ManifestHash:      record.ManifestHash,
		EntriesHash:       record.EntriesHash,
		TrustState:        record.TrustState,
		Manifest:          record.Manifest,
		PackageEntries:    cloneEntries(record.PackageEntries),
		ActivatedAt:       now,
		Metadata:          cloneStringMap(record.Metadata),
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
	next.Manifest = snapshot.Manifest
	next.PackageEntries = cloneEntries(snapshot.PackageEntries)
	next.Metadata = cloneStringMap(snapshot.Metadata)
	return next
}

func selectVersionSnapshot(history []registry.PluginVersion, version string, packageHash string) (registry.PluginVersion, []registry.PluginVersion, error) {
	version = strings.TrimSpace(version)
	packageHash = strings.TrimSpace(packageHash)
	if version == "" && packageHash == "" {
		return registry.PluginVersion{}, nil, errors.New("version or package_hash is required")
	}
	for i, snapshot := range history {
		if (version == "" || snapshot.Version == version) && (packageHash == "" || snapshot.PackageHash == packageHash) {
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
	if record.Manifest.Storage != nil && len(record.Manifest.Storage.Stores) > 0 && h.adapters.Storage == nil {
		return errors.New("storage broker is required for plugins that declare storage")
	}
	if record.Manifest.Settings != nil && h.adapters.Settings == nil {
		return errors.New("settings store is required for plugins that declare settings")
	}
	return nil
}

func (h *Host) refreshEnabledRuntimeState(ctx context.Context, record registry.PluginRecord) error {
	if record.EnableState != registry.EnableEnabled {
		return nil
	}
	if err := h.ensureStorageNamespaces(ctx, record); err != nil {
		return err
	}
	if _, err := h.ensureSettings(ctx, record, time.Time{}, true); err != nil {
		return err
	}
	connectivityPolicy, hasConnectivityPolicy, err := compileConnectivityPolicy(record)
	if err != nil {
		return err
	}
	if err := h.installConnectivityPolicy(ctx, record, connectivityPolicy, hasConnectivityPolicy); err != nil {
		_, _ = h.adapters.Registry.SetEnableState(ctx, record.PluginInstanceID, registry.EnableDisabledByPolicy, "connectivity policy installation failed", time.Now().UTC())
		if h.adapters.Connectivity != nil {
			_ = h.adapters.Connectivity.RemovePolicy(ctx, record.PluginInstanceID)
		}
		return err
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
	return h.adapters.Registry.ListPlugins(ctx)
}

func (h *Host) GrantPermission(ctx context.Context, req GrantPermissionRequest) (permissions.Record, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return permissions.Record{}, err
	}
	grant, err := h.adapters.Permissions.Grant(ctx, permissions.GrantRequest{
		PluginInstanceID: record.PluginInstanceID,
		PermissionID:     req.PermissionID,
		GrantedBy:        req.GrantedBy,
		Now:              req.Now,
		ExpiresAt:        req.ExpiresAt,
	})
	if err != nil {
		return permissions.Record{}, err
	}
	if _, err := h.adapters.Registry.BumpPolicyRevision(ctx, record.PluginInstanceID, false, req.Now); err != nil {
		return permissions.Record{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.permission.granted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return grant, nil
}

func (h *Host) RevokePermission(ctx context.Context, req RevokePermissionRequest) (permissions.Record, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return permissions.Record{}, err
	}
	grant, err := h.adapters.Permissions.Revoke(ctx, permissions.RevokeRequest{
		PluginInstanceID: record.PluginInstanceID,
		PermissionID:     req.PermissionID,
		RevokedBy:        req.RevokedBy,
		Reason:           req.Reason,
		Now:              req.Now,
	})
	if err != nil {
		return permissions.Record{}, err
	}
	if _, err := h.adapters.Registry.BumpPolicyRevision(ctx, record.PluginInstanceID, true, req.Now); err != nil {
		return permissions.Record{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.permission.revoked", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return grant, nil
}

func (h *Host) ListPermissionGrants(ctx context.Context, req ListPermissionGrantsRequest) ([]permissions.Record, error) {
	if req.PluginInstanceID != "" {
		if _, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID); err != nil {
			return nil, err
		}
	}
	return h.adapters.Permissions.List(ctx, permissions.ListRequest{
		PluginInstanceID: req.PluginInstanceID,
		ActiveOnly:       req.ActiveOnly,
	})
}

func (h *Host) ListAuditEvents(ctx context.Context, req ListAuditEventsRequest) ([]AuditEvent, error) {
	lister, ok := h.adapters.Audit.(AuditLister)
	if !ok {
		return nil, errors.New("audit event lister is unavailable")
	}
	return lister.ListPluginAudit(ctx, observability.ListAuditRequest(req))
}

func (h *Host) ListDiagnosticEvents(ctx context.Context, req ListDiagnosticEventsRequest) ([]DiagnosticEvent, error) {
	lister, ok := h.adapters.Diagnostics.(DiagnosticLister)
	if !ok {
		return nil, errors.New("diagnostic event lister is unavailable")
	}
	return lister.ListPluginDiagnostics(ctx, observability.ListDiagnosticRequest(req))
}

func (h *Host) ListOperations(ctx context.Context, req ListOperationsRequest) ([]operation.Record, error) {
	return h.adapters.Operations.List(ctx, operation.ListRequest{PluginInstanceID: req.PluginInstanceID})
}

func (h *Host) StartRuntime(ctx context.Context, req StartRuntimeRequest) (runtimeclient.Health, error) {
	if h.adapters.RuntimeSupervisor == nil {
		h.runtimeMu.Lock()
		defer h.runtimeMu.Unlock()
		if h.adapters.RuntimeSupervisor == nil && h.adapters.RuntimeArtifactResolver == nil {
			return runtimeclient.Health{}, errors.New("runtime artifact resolver is required")
		}
		if h.adapters.RuntimeSupervisor == nil {
			target := normalizeRuntimeTarget(req.Target)
			runtimePath, err := h.adapters.RuntimeArtifactResolver.RuntimePath(ctx, target)
			if err != nil {
				return runtimeclient.Health{}, err
			}
			supervisor, err := runtimeclient.NewProcessSupervisor(h.processSupervisorOptions(runtimePath))
			if err != nil {
				return runtimeclient.Health{}, err
			}
			h.adapters.RuntimeSupervisor = supervisor
		}
	}
	target := normalizeRuntimeTarget(req.Target)
	if err := h.adapters.RuntimeSupervisor.Start(ctx, runtimeclient.Target{OS: target.OS, Arch: target.Arch}); err != nil {
		return runtimeclient.Health{}, err
	}
	health, err := h.adapters.RuntimeSupervisor.Health(ctx)
	if err != nil {
		return runtimeclient.Health{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.runtime.started"})
	return health, nil
}

func (h *Host) processSupervisorOptions(runtimePath string) runtimeclient.ProcessSupervisorOptions {
	return runtimeclient.ProcessSupervisorOptions{
		RuntimePath:     runtimePath,
		Diagnostics:     h.adapters.Diagnostics,
		Artifacts:       runtimeArtifactProvider{assets: h.adapters.Assets},
		HandleGrants:    runtimeHandleGrantValidator{tokens: h.surfaceTokens},
		StorageFiles:    storageFilesBroker(h.adapters.Storage),
		Connectivity:    h.adapters.Connectivity,
		NetworkExecutor: h.adapters.NetworkExecutor,
	}
}

func (h *Host) StopRuntime(ctx context.Context) error {
	if h.adapters.RuntimeSupervisor == nil {
		return nil
	}
	if err := h.adapters.RuntimeSupervisor.Stop(ctx); err != nil {
		return err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.runtime.stopped"})
	return nil
}

func (h *Host) RuntimeHealth(ctx context.Context) (runtimeclient.Health, error) {
	if h.adapters.RuntimeSupervisor == nil {
		return runtimeclient.Health{}, nil
	}
	return h.adapters.RuntimeSupervisor.Health(ctx)
}

func (h *Host) GetOperation(ctx context.Context, operationID string) (operation.Record, error) {
	return h.adapters.Operations.Get(ctx, operationID)
}

func (h *Host) CancelOperation(ctx context.Context, req CancelOperationRequest) (operation.Record, error) {
	record, err := h.adapters.Operations.RequestCancel(ctx, operation.CancelRequest{
		OperationID: req.OperationID,
		Reason:      req.Reason,
		Now:         req.Now,
	})
	if err != nil {
		return operation.Record{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.operation.cancel_requested", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return record, nil
}

func (h *Host) FinishOperation(ctx context.Context, req FinishOperationRequest) (operation.Record, error) {
	record, err := h.adapters.Operations.Finish(ctx, operation.FinishRequest{
		OperationID: req.OperationID,
		Status:      req.Status,
		Reason:      req.Reason,
		Now:         req.Now,
	})
	if err != nil {
		return operation.Record{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.operation.finished", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return record, nil
}

func (h *Host) AppendStreamEvent(ctx context.Context, req AppendStreamEventRequest) (stream.Event, error) {
	event, err := h.adapters.Streams.Append(ctx, stream.AppendRequest{
		StreamID: req.StreamID,
		Kind:     req.Kind,
		Data:     req.Data,
		Error:    req.Error,
		Now:      req.Now,
	})
	if err != nil {
		return stream.Event{}, err
	}
	return event, nil
}

func (h *Host) ReadStream(ctx context.Context, req ReadStreamRequest) (ReadStreamResult, error) {
	if strings.TrimSpace(req.StreamTicket) == "" {
		return ReadStreamResult{}, ErrStreamTicketRequired
	}
	record, err := h.adapters.Streams.Get(ctx, req.StreamID)
	if err != nil {
		return ReadStreamResult{}, err
	}
	plugin, err := h.adapters.Registry.GetPlugin(ctx, record.PluginInstanceID)
	if err != nil {
		return ReadStreamResult{}, err
	}
	if _, err := h.surfaceTokens.ValidateStreamTicket(bridge.ValidateStreamTicketRequest{
		StreamTicket: req.StreamTicket,
		Audience: bridge.Audience{
			PluginInstanceID:     record.PluginInstanceID,
			ActiveFingerprint:    plugin.ActiveFingerprint,
			SurfaceInstanceID:    record.SurfaceInstanceID,
			OwnerSessionHash:     record.OwnerSessionHash,
			OwnerUserHash:        record.OwnerUserHash,
			SessionChannelIDHash: record.SessionChannelIDHash,
			BridgeChannelID:      record.BridgeChannelID,
			StreamID:             record.StreamID,
			StreamDirection:      string(record.Direction),
			Method:               record.Method,
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision:     plugin.PolicyRevision,
			ManagementRevision: plugin.ManagementRevision,
			RevokeEpoch:        plugin.RevokeEpoch,
		},
		Now: time.Time{},
	}); err != nil {
		return ReadStreamResult{}, err
	}
	record, events, err := h.adapters.Streams.Read(ctx, stream.ReadRequest{
		StreamID:  req.StreamID,
		MaxEvents: req.MaxEvents,
		MaxBytes:  req.MaxBytes,
	})
	if err != nil {
		return ReadStreamResult{}, err
	}
	return ReadStreamResult{Record: record, Events: events}, nil
}

func (h *Host) CloseStream(ctx context.Context, req CloseStreamRequest) (stream.Record, error) {
	record, err := h.adapters.Streams.Close(ctx, stream.CloseRequest{
		StreamID: req.StreamID,
		Status:   req.Status,
		Reason:   req.Reason,
		Now:      req.Now,
	})
	if err != nil {
		return stream.Record{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.stream.closed", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return record, nil
}

func (h *Host) MintConnectionGrant(ctx context.Context, req MintConnectionGrantRequest) (connectivity.ConnectionGrant, error) {
	_, grant, err := h.mintConnectionGrant(ctx, req)
	if err != nil {
		return connectivity.ConnectionGrant{}, err
	}
	return grant, nil
}

func (h *Host) mintConnectionGrant(ctx context.Context, req MintConnectionGrantRequest) (registry.PluginRecord, connectivity.ConnectionGrant, error) {
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
	h.audit(ctx, AuditEvent{Type: "plugin.connectivity.grant_minted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return record, grant, nil
}

func (h *Host) MintNetworkHandleGrant(ctx context.Context, req MintConnectionGrantRequest) (NetworkHandleGrantResult, error) {
	if strings.TrimSpace(req.RuntimeGenerationID) == "" {
		return NetworkHandleGrantResult{}, bridge.ErrMissingTokenAudience
	}
	record, grant, err := h.mintConnectionGrant(ctx, req)
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
	h.audit(ctx, AuditEvent{Type: "plugin.connectivity.handle_grant_minted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return NetworkHandleGrantResult{ConnectionGrant: grant, HandleGrant: handleGrant}, nil
}

func (h *Host) MintStorageHandleGrant(ctx context.Context, req MintStorageHandleGrantRequest) (StorageHandleGrantResult, error) {
	if strings.TrimSpace(req.RuntimeGenerationID) == "" || strings.TrimSpace(req.StoreID) == "" {
		return StorageHandleGrantResult{}, bridge.ErrMissingTokenAudience
	}
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
	h.audit(ctx, AuditEvent{Type: "plugin.storage.handle_grant_minted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return StorageHandleGrantResult{Namespace: namespace, HandleGrant: handleGrant}, nil
}

func (h *Host) EnablePlugin(ctx context.Context, req EnableRequest) (registry.PluginRecord, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.canRun(ctx, record); err != nil {
		return registry.PluginRecord{}, err
	}
	if _, _, err := compileConnectivityPolicy(record); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.ensureStorageNamespaces(ctx, record); err != nil {
		return registry.PluginRecord{}, err
	}
	if _, err := h.ensureSettings(ctx, record, req.Now, true); err != nil {
		return registry.PluginRecord{}, err
	}
	enabled, err := h.adapters.Registry.SetEnableState(ctx, req.PluginInstanceID, registry.EnableEnabled, "", req.Now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	connectivityPolicy, hasConnectivityPolicy, err := compileConnectivityPolicy(enabled)
	if err != nil {
		_, _ = h.adapters.Registry.SetEnableState(ctx, req.PluginInstanceID, registry.EnableDisabledByPolicy, "connectivity policy compilation failed", req.Now)
		return registry.PluginRecord{}, err
	}
	if err := h.installConnectivityPolicy(ctx, enabled, connectivityPolicy, hasConnectivityPolicy); err != nil {
		_, _ = h.adapters.Registry.SetEnableState(ctx, req.PluginInstanceID, registry.EnableDisabledByPolicy, "connectivity policy installation failed", req.Now)
		if h.adapters.Connectivity != nil {
			_ = h.adapters.Connectivity.RemovePolicy(ctx, enabled.PluginInstanceID)
		}
		return registry.PluginRecord{}, err
	}
	if h.adapters.SurfaceCatalog != nil {
		if err := h.adapters.SurfaceCatalog.PublishSurfaces(ctx, SurfaceSnapshot{
			PluginInstanceID:  enabled.PluginInstanceID,
			ActiveFingerprint: enabled.ActiveFingerprint,
			Surfaces:          enabled.Manifest.Surfaces,
		}); err != nil {
			return registry.PluginRecord{}, err
		}
	}
	h.audit(ctx, AuditEvent{Type: "plugin.enabled", PluginID: enabled.PluginID, PluginInstanceID: enabled.PluginInstanceID})
	return enabled, nil
}

func (h *Host) DisablePlugin(ctx context.Context, req DisableRequest) (registry.PluginRecord, error) {
	reason := req.Reason
	if reason == "" {
		reason = "disabled"
	}
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
		return registry.PluginRecord{}, err
	}
	if h.adapters.SurfaceCatalog != nil {
		if err := h.adapters.SurfaceCatalog.PublishSurfaces(ctx, SurfaceSnapshot{
			PluginInstanceID:  disabled.PluginInstanceID,
			ActiveFingerprint: disabled.ActiveFingerprint,
			Surfaces:          nil,
		}); err != nil {
			return registry.PluginRecord{}, err
		}
	}
	h.audit(ctx, AuditEvent{Type: "plugin.disabled", PluginID: disabled.PluginID, PluginInstanceID: disabled.PluginInstanceID})
	if len(operations) > 0 {
		h.audit(ctx, AuditEvent{Type: "plugin.operations.disabled_transitioned", PluginID: disabled.PluginID, PluginInstanceID: disabled.PluginInstanceID})
	}
	streams, err := h.adapters.Streams.MarkPluginTransition(ctx, stream.PluginTransitionRequest{
		PluginInstanceID: disabled.PluginInstanceID,
		Status:           stream.StatusOrphanedDisabled,
		Now:              req.Now,
	})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if len(streams) > 0 {
		h.audit(ctx, AuditEvent{Type: "plugin.streams.disabled_transitioned", PluginID: disabled.PluginID, PluginInstanceID: disabled.PluginInstanceID})
	}
	if h.adapters.Connectivity != nil {
		_ = h.adapters.Connectivity.RemovePolicy(ctx, disabled.PluginInstanceID)
	}
	return disabled, nil
}

func (h *Host) UninstallPlugin(ctx context.Context, req UninstallRequest) (registry.PluginRecord, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	operations, err := h.adapters.Operations.MarkPluginUninstalled(ctx, operation.PluginTransitionRequest{
		PluginInstanceID: record.PluginInstanceID,
		Reason:           "uninstalled",
		Now:              req.Now,
	})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if req.DeleteData && operationsBlockDelete(operations) {
		h.audit(ctx, AuditEvent{Type: "plugin.operations.delete_blocked", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
		return registry.PluginRecord{}, operation.ErrDeleteBlocked
	}
	cleanupPlan, err := h.adapters.Cleanup.PlanUninstall(ctx, record.PluginInstanceID, req.DeleteData)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.adapters.Cleanup.Execute(ctx, cleanupPlan); err != nil {
		return registry.PluginRecord{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.cleanup.executed", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if err := h.deleteOrRetainStorage(ctx, record, req.DeleteData); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.deleteOrRetainSettings(ctx, record, req.DeleteData, req.Now); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.deleteOrRetainBrowserSiteData(ctx, record, req.DeleteData, req.Now); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.adapters.Permissions.DeletePluginGrants(ctx, record.PluginInstanceID); err != nil {
		return registry.PluginRecord{}, err
	}
	if h.adapters.Connectivity != nil {
		_ = h.adapters.Connectivity.RemovePolicy(ctx, record.PluginInstanceID)
	}
	retained := registry.RetainedDataRetained
	if req.DeleteData {
		retained = registry.RetainedDataDeleted
	}
	record, err = h.adapters.Registry.MarkUninstalled(ctx, req.PluginInstanceID, retained, req.Now)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if h.adapters.SurfaceCatalog != nil {
		if err := h.adapters.SurfaceCatalog.PublishSurfaces(ctx, SurfaceSnapshot{
			PluginInstanceID:  record.PluginInstanceID,
			ActiveFingerprint: record.ActiveFingerprint,
			Surfaces:          nil,
		}); err != nil {
			return registry.PluginRecord{}, err
		}
	}
	h.audit(ctx, AuditEvent{Type: "plugin.uninstalled", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	if len(operations) > 0 {
		h.audit(ctx, AuditEvent{Type: "plugin.operations.uninstalled_transitioned", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	}
	streams, err := h.adapters.Streams.MarkPluginTransition(ctx, stream.PluginTransitionRequest{
		PluginInstanceID: record.PluginInstanceID,
		Status:           stream.StatusOrphanedRemoved,
		Now:              req.Now,
	})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if len(streams) > 0 {
		h.audit(ctx, AuditEvent{Type: "plugin.streams.uninstalled_transitioned", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	}
	return record, nil
}

func (h *Host) ExportPluginData(ctx context.Context, req ExportDataRequest) (ExportDataResult, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return ExportDataResult{}, err
	}
	if h.adapters.Storage == nil {
		return ExportDataResult{}, errors.New("storage broker is required")
	}
	archiveRef, err := h.adapters.Storage.ExportData(ctx, storage.ExportRequest{
		PluginInstanceID: record.PluginInstanceID,
		IncludeSecrets:   req.IncludeSecrets,
	})
	if err != nil {
		return ExportDataResult{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.data.exported", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return ExportDataResult{ArchiveRef: archiveRef}, nil
}

func (h *Host) GetSettingsSchema(ctx context.Context, req GetSettingsRequest) (SettingsSchemaResult, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return SettingsSchemaResult{}, err
	}
	if record.Manifest.Settings == nil {
		return SettingsSchemaResult{}, settings.ErrNotDeclared
	}
	snapshot, err := h.ensureSettings(ctx, record, time.Time{}, false)
	if err != nil {
		return SettingsSchemaResult{}, err
	}
	return SettingsSchemaResult{
		PluginInstanceID: record.PluginInstanceID,
		SchemaVersion:    record.Manifest.Settings.SchemaVersion,
		Migration:        record.Manifest.Settings.Migration,
		Fields:           cloneSettingFields(record.Manifest.Settings.Fields),
		SettingsRevision: snapshot.SettingsRevision,
	}, nil
}

func (h *Host) GetPluginSettings(ctx context.Context, req GetSettingsRequest) (SettingsResult, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return SettingsResult{}, err
	}
	if record.Manifest.Settings == nil {
		return SettingsResult{}, settings.ErrNotDeclared
	}
	snapshot, err := h.ensureSettings(ctx, record, time.Time{}, false)
	if err != nil {
		return SettingsResult{}, err
	}
	return settingsResult(snapshot), nil
}

func (h *Host) PatchPluginSettings(ctx context.Context, req PatchSettingsRequest) (SettingsResult, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return SettingsResult{}, err
	}
	if record.Manifest.Settings == nil {
		return SettingsResult{}, settings.ErrNotDeclared
	}
	if _, err := h.ensureSettings(ctx, record, req.Now, false); err != nil {
		return SettingsResult{}, err
	}
	snapshot, err := h.adapters.Settings.Patch(ctx, settings.PatchRequest{
		PluginInstanceID: record.PluginInstanceID,
		Values:           cloneParams(req.Values),
		Now:              req.Now,
	})
	if err != nil {
		return SettingsResult{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.settings.updated", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return settingsResult(snapshot), nil
}

func (h *Host) ImportPluginData(ctx context.Context, req ImportDataRequest) error {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return err
	}
	if h.adapters.Storage == nil {
		return errors.New("storage broker is required")
	}
	namespaces, err := storageNamespacesFromManifest(record)
	if err != nil {
		return err
	}
	if len(namespaces) == 0 {
		return errors.New("target plugin does not declare storage")
	}
	for _, ns := range namespaces {
		if err := h.adapters.Storage.EnsureNamespace(ctx, ns); err != nil {
			return fmt.Errorf("ensure storage namespace %q: %w", ns.StoreID, err)
		}
	}
	if err := h.adapters.Storage.ImportData(ctx, storage.ImportRequest{
		PluginInstanceID: record.PluginInstanceID,
		ArchiveRef:       req.ArchiveRef,
		DeleteExisting:   req.DeleteExisting,
		TargetNamespaces: namespaces,
	}); err != nil {
		return err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.data.imported", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) BindSecretRef(ctx context.Context, req SecretBindRequest) error {
	record, normalized, err := h.resolveSecretRequest(ctx, req)
	if err != nil {
		return err
	}
	if err := h.adapters.Secrets.BindSecretRef(ctx, normalized); err != nil {
		return err
	}
	if err := h.markSettingsSecret(ctx, record, normalized.SecretRef, true, "", time.Time{}); err != nil {
		return err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.secret.bound", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) TestSecretRef(ctx context.Context, req SecretTestRequest) error {
	record, normalized, err := h.resolveSecretRequest(ctx, SecretBindRequest(req))
	if err != nil {
		return err
	}
	if err := h.adapters.Secrets.TestSecretRef(ctx, SecretTestRequest(normalized)); err != nil {
		return err
	}
	if err := h.markSettingsSecret(ctx, record, normalized.SecretRef, true, "passed", time.Time{}); err != nil {
		return err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.secret.tested", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) DeleteSecretRef(ctx context.Context, req SecretDeleteRequest) error {
	record, normalized, err := h.resolveSecretRequest(ctx, SecretBindRequest(req))
	if err != nil {
		return err
	}
	if err := h.adapters.Secrets.DeleteSecretRef(ctx, SecretDeleteRequest(normalized)); err != nil {
		return err
	}
	if err := h.markSettingsSecret(ctx, record, normalized.SecretRef, false, "", time.Time{}); err != nil {
		return err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.secret.deleted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) ReportCSPViolation(ctx context.Context, report CSPViolationReport) error {
	if h.adapters.Diagnostics == nil {
		return nil
	}
	message := report.EffectiveDirective
	if message == "" {
		message = report.ViolatedDirective
	}
	if message == "" {
		message = "content security policy violation"
	}
	details := map[string]any{}
	addStringDetail(details, "blocked_uri", report.BlockedURI)
	addStringDetail(details, "document_uri", report.DocumentURI)
	addStringDetail(details, "effective_directive", report.EffectiveDirective)
	addStringDetail(details, "violated_directive", report.ViolatedDirective)
	addStringDetail(details, "original_policy", report.OriginalPolicy)
	addStringDetail(details, "disposition", report.Disposition)
	addStringDetail(details, "source_file", report.SourceFile)
	addStringDetail(details, "sample", report.Sample)
	if report.LineNumber > 0 {
		details["line_number"] = report.LineNumber
	}
	if report.ColumnNumber > 0 {
		details["column_number"] = report.ColumnNumber
	}
	if len(report.Raw) > 0 {
		details["raw"] = report.Raw
	}
	return h.adapters.Diagnostics.AppendPluginDiagnostic(ctx, DiagnosticEvent{
		Type:              "plugin.csp.violation",
		Severity:          "warning",
		Message:           message,
		PluginID:          report.PluginID,
		PluginInstanceID:  report.PluginInstanceID,
		SurfaceID:         report.SurfaceID,
		SurfaceInstanceID: report.SurfaceInstanceID,
		ActiveFingerprint: report.ActiveFingerprint,
		Details:           details,
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

func storageFilesBroker(broker storage.Broker) storage.FilesBroker {
	files, ok := broker.(storage.FilesBroker)
	if !ok {
		return nil
	}
	return files
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

func (h *Host) dispatchMethod(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (CallMethodResult, error) {
	switch method.Route.Kind {
	case manifest.MethodRouteCapability:
		binding, ok := manifestCapabilityBinding(record.Manifest, method.Route.BindingID)
		if !ok {
			return CallMethodResult{}, fmt.Errorf("capability binding %q is not declared", method.Route.BindingID)
		}
		adapter, ok := h.adapters.Capabilities.Adapter(binding.CapabilityID)
		if !ok {
			return CallMethodResult{}, fmt.Errorf("capability %q is unavailable", binding.CapabilityID)
		}
		result, err := adapter.InvokeCapability(ctx, capability.Invocation{
			CapabilityID:         binding.CapabilityID,
			BindingID:            binding.BindingID,
			Method:               method.Method,
			TargetMethod:         method.Route.TargetMethod,
			Effect:               capability.Effect(method.Effect),
			PluginID:             record.PluginID,
			PluginInstanceID:     record.PluginInstanceID,
			SurfaceInstanceID:    req.SurfaceInstanceID,
			SessionChannelIDHash: req.SessionChannelIDHash,
			BridgeChannelID:      req.BridgeChannelID,
			Arguments:            cloneParams(req.Params),
		})
		if err != nil {
			return CallMethodResult{}, err
		}
		if err := validateExecutionResult(method, result); err != nil {
			return CallMethodResult{}, err
		}
		if err := h.registerOperationIfNeeded(ctx, record, method, req, result.OperationID); err != nil {
			return CallMethodResult{}, err
		}
		if err := h.registerStreamIfNeeded(ctx, record, method, req, result.StreamID); err != nil {
			return CallMethodResult{}, err
		}
		return CallMethodResult{Data: result.Data, OperationID: result.OperationID, StreamID: result.StreamID}, nil
	case manifest.MethodRouteWorker:
		result, err := h.invokeWorker(ctx, record, method, req)
		if err != nil {
			return CallMethodResult{}, err
		}
		if err := validateExecutionResult(method, result); err != nil {
			return CallMethodResult{}, err
		}
		if err := h.registerOperationIfNeeded(ctx, record, method, req, result.OperationID); err != nil {
			return CallMethodResult{}, err
		}
		if err := h.registerStreamIfNeeded(ctx, record, method, req, result.StreamID); err != nil {
			return CallMethodResult{}, err
		}
		return CallMethodResult{Data: result.Data, OperationID: result.OperationID, StreamID: result.StreamID}, nil
	case manifest.MethodRouteCoreAction:
		result, err := h.invokeCoreAction(ctx, record, method, req)
		if err != nil {
			return CallMethodResult{}, err
		}
		if err := validateExecutionResult(method, result); err != nil {
			return CallMethodResult{}, err
		}
		if err := h.registerOperationIfNeeded(ctx, record, method, req, result.OperationID); err != nil {
			return CallMethodResult{}, err
		}
		if err := h.registerStreamIfNeeded(ctx, record, method, req, result.StreamID); err != nil {
			return CallMethodResult{}, err
		}
		return CallMethodResult{Data: result.Data, OperationID: result.OperationID, StreamID: result.StreamID}, nil
	default:
		return CallMethodResult{}, fmt.Errorf("method route kind %q is invalid", method.Route.Kind)
	}
}

func (h *Host) invokeCoreAction(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (capability.Result, error) {
	if h.adapters.CoreActions == nil {
		return capability.Result{}, errors.New("core action adapter is required")
	}
	actionID := strings.TrimSpace(method.Route.ActionID)
	if actionID == "" {
		return capability.Result{}, errors.New("core action_id is required")
	}
	return h.adapters.CoreActions.InvokeCoreAction(ctx, capability.Invocation{
		CapabilityID:         "core_action",
		Method:               method.Method,
		TargetMethod:         actionID,
		Effect:               capability.Effect(method.Effect),
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Arguments:            cloneParams(req.Params),
	})
}

func (h *Host) invokeWorker(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest) (capability.Result, error) {
	if h.adapters.RuntimeSupervisor == nil {
		return capability.Result{}, errors.New("runtime supervisor is required for worker methods")
	}
	worker, ok := manifestWorker(record.Manifest, method.Route.WorkerID)
	if !ok {
		return capability.Result{}, fmt.Errorf("worker %q is not declared", method.Route.WorkerID)
	}
	health, err := h.adapters.RuntimeSupervisor.Health(ctx)
	if err != nil {
		return capability.Result{}, err
	}
	if !health.Ready {
		return capability.Result{}, errors.New("runtime supervisor is not ready")
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
	lease, err := h.surfaceTokens.MintRuntimeExecutionLease(bridge.MintRuntimeExecutionLeaseRequest{
		PluginInstanceID:    record.PluginInstanceID,
		ActiveFingerprint:   record.ActiveFingerprint,
		RuntimeInstanceID:   health.RuntimeInstanceID,
		RuntimeGenerationID: health.RuntimeGenerationID,
		Method:              method.Method,
		Revision:            revision,
		Now:                 now,
	})
	if err != nil {
		return capability.Result{}, err
	}
	params := cloneParams(req.Params)
	if params == nil {
		params = map[string]any{}
	}
	if h.adapters.Assets == nil {
		return capability.Result{}, errors.New("package asset store is required for worker methods")
	}
	workerAsset, err := h.adapters.Assets.ReadAsset(ctx, record.PackageHash, worker.Artifact)
	if err != nil {
		return capability.Result{}, fmt.Errorf("read worker artifact %q: %w", worker.Artifact, err)
	}
	if strings.TrimSpace(workerAsset.Entry.SHA256) == "" {
		return capability.Result{}, fmt.Errorf("worker artifact %q is missing sha256", worker.Artifact)
	}
	payload := WorkerInvocationPayload{
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		ActiveFingerprint:    record.ActiveFingerprint,
		RuntimeInstanceID:    health.RuntimeInstanceID,
		RuntimeGenerationID:  health.RuntimeGenerationID,
		PackageHash:          record.PackageHash,
		WorkerID:             worker.WorkerID,
		WorkerMode:           string(worker.Mode),
		WorkerScope:          worker.Scope,
		Artifact:             worker.Artifact,
		ArtifactSHA256:       workerAsset.Entry.SHA256,
		ABI:                  worker.ABI,
		Method:               method.Method,
		Export:               method.Route.Export,
		Effect:               string(method.Effect),
		Execution:            string(method.Execution),
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Params:               params,
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return capability.Result{}, err
	}
	rawResult, err := h.adapters.RuntimeSupervisor.InvokeWorker(ctx, runtimeclient.Lease{
		LeaseID:             lease.LeaseID,
		LeaseToken:          lease.LeaseToken,
		RuntimeGenerationID: lease.RuntimeGenerationID,
		PluginInstanceID:    record.PluginInstanceID,
		PolicyRevision:      record.PolicyRevision,
		ManagementRevision:  record.ManagementRevision,
		RevokeEpoch:         record.RevokeEpoch,
		ExpiresAt:           lease.ExpiresAt,
	}, method.Method, rawPayload)
	if err != nil {
		return capability.Result{}, err
	}
	var result capability.Result
	if len(rawResult) > 0 {
		if err := json.Unmarshal(rawResult, &result); err != nil {
			return capability.Result{}, fmt.Errorf("decode worker result: %w", err)
		}
	}
	return result, nil
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

func (h *Host) registerOperationIfNeeded(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest, operationID string) error {
	if operationID == "" {
		return nil
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:          operationID,
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		Method:               method.Method,
		Effect:               string(method.Effect),
		Execution:            string(method.Execution),
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		DisableBehavior:      cancelPolicyDisableBehavior(method.CancelPolicy),
		UninstallBehavior:    cancelPolicyUninstallBehavior(method.CancelPolicy),
		Now:                  req.Now,
	}); err != nil {
		return err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.operation.started", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) registerStreamIfNeeded(ctx context.Context, record registry.PluginRecord, method manifest.MethodSpec, req CallMethodRequest, streamID string) error {
	if streamID == "" {
		return nil
	}
	if _, err := h.adapters.Streams.Register(ctx, stream.RegisterRequest{
		StreamID:             streamID,
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		Method:               method.Method,
		Effect:               string(method.Effect),
		Execution:            string(method.Execution),
		SurfaceInstanceID:    req.SurfaceInstanceID,
		OwnerSessionHash:     req.OwnerSessionHash,
		OwnerUserHash:        req.OwnerUserHash,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Direction:            stream.DirectionRead,
		Now:                  req.Now,
	}); err != nil {
		return err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.stream.started", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func validateExecutionResult(method manifest.MethodSpec, result capability.Result) error {
	switch method.Execution {
	case manifest.MethodExecutionSync:
		if result.OperationID != "" || result.StreamID != "" {
			return fmt.Errorf("sync method %q returned async handles", method.Method)
		}
	case manifest.MethodExecutionOperation:
		if result.OperationID == "" {
			return fmt.Errorf("operation method %q did not return operation_id", method.Method)
		}
	case manifest.MethodExecutionSubscription:
		if result.StreamID == "" && result.OperationID == "" {
			return fmt.Errorf("subscription method %q did not return stream_id or operation_id", method.Method)
		}
	}
	return nil
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

func manifestCapabilityBinding(m manifest.Manifest, bindingID string) (manifest.CapabilityBinding, bool) {
	for _, binding := range m.CapabilityBindings {
		if binding.BindingID == bindingID {
			return binding, true
		}
	}
	return manifest.CapabilityBinding{}, false
}

func requiredPermissionsForMethod(m manifest.Manifest, method manifest.MethodSpec) []string {
	if method.Route.Kind != manifest.MethodRouteCapability {
		return nil
	}
	binding, ok := manifestCapabilityBinding(m, method.Route.BindingID)
	if !ok {
		return nil
	}
	return normalizeStringSet(binding.RequiredPermissions)
}

func manifestWorker(m manifest.Manifest, workerID string) (manifest.WorkerSpec, bool) {
	for _, worker := range m.Workers {
		if worker.WorkerID == workerID {
			return worker, true
		}
	}
	return manifest.WorkerSpec{}, false
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

func addStringDetail(details map[string]any, key string, value string) {
	if value != "" {
		details[key] = value
	}
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

func (h *Host) canRun(ctx context.Context, record registry.PluginRecord) error {
	if !registry.RunnableTrustState(record.TrustState) {
		return fmt.Errorf("plugin trust_state %q is not runnable", record.TrustState)
	}
	if record.TrustState == registry.TrustUnsignedLocal {
		developerMode, err := h.adapters.Policy.DeveloperModeEnabled(ctx, sessionctx.Context{})
		if err != nil {
			return err
		}
		localGenerated, err := h.adapters.Policy.LocalGeneratedPluginsEnabled(ctx, sessionctx.Context{})
		if err != nil {
			return err
		}
		if !developerMode || !localGenerated {
			_, _ = h.adapters.Registry.SetEnableState(ctx, record.PluginInstanceID, registry.EnableDisabledByPolicy, "developer mode or local generated plugins disabled", time.Now().UTC())
			return errors.New("unsigned local plugins require developer mode and local generated plugins")
		}
	}
	return nil
}

func (h *Host) ensureStorageNamespaces(ctx context.Context, record registry.PluginRecord) error {
	if record.Manifest.Storage == nil || len(record.Manifest.Storage.Stores) == 0 {
		return nil
	}
	if h.adapters.Storage == nil {
		return errors.New("storage broker is required for plugins that declare storage")
	}
	namespaces, err := storageNamespacesFromManifest(record)
	if err != nil {
		return err
	}
	for _, ns := range namespaces {
		if err := h.adapters.Storage.EnsureNamespace(ctx, ns); err != nil {
			return fmt.Errorf("ensure storage namespace %q: %w", ns.StoreID, err)
		}
	}
	h.audit(ctx, AuditEvent{Type: "plugin.storage.ensured", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) ensureSettings(ctx context.Context, record registry.PluginRecord, now time.Time, audit bool) (settings.Snapshot, error) {
	if record.Manifest.Settings == nil {
		return settings.Snapshot{}, nil
	}
	if h.adapters.Settings == nil {
		return settings.Snapshot{}, errors.New("settings store is required for plugins that declare settings")
	}
	snapshot, err := h.adapters.Settings.Ensure(ctx, settings.EnsureRequest{
		PluginInstanceID: record.PluginInstanceID,
		Spec:             record.Manifest.Settings,
		Now:              now,
	})
	if err != nil {
		return settings.Snapshot{}, err
	}
	if audit {
		h.audit(ctx, AuditEvent{Type: "plugin.settings.ensured", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	}
	return snapshot, nil
}

func (h *Host) markSettingsSecret(ctx context.Context, record registry.PluginRecord, secretRef string, set bool, lastTestStatus string, now time.Time) error {
	if record.Manifest.Settings == nil || h.adapters.Settings == nil || !settingsSecretRefDeclared(record.Manifest.Settings.Fields, secretRef) {
		return nil
	}
	if _, err := h.ensureSettings(ctx, record, now, false); err != nil {
		return err
	}
	_, err := h.adapters.Settings.MarkSecret(ctx, settings.MarkSecretRequest{
		PluginInstanceID: record.PluginInstanceID,
		SecretRef:        secretRef,
		Set:              set,
		LastTestStatus:   lastTestStatus,
		Now:              now,
	})
	return err
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

func (h *Host) installConnectivityPolicy(ctx context.Context, record registry.PluginRecord, policy connectivity.PolicySet, hasPolicy bool) error {
	if !hasPolicy {
		return nil
	}
	if h.adapters.Connectivity != nil {
		if err := h.adapters.Connectivity.InstallPolicy(ctx, policy); err != nil {
			return err
		}
	}
	h.audit(ctx, AuditEvent{Type: "plugin.connectivity.policy_installed", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) deleteOrRetainStorage(ctx context.Context, record registry.PluginRecord, deleteData bool) error {
	if record.Manifest.Storage == nil || len(record.Manifest.Storage.Stores) == 0 {
		return nil
	}
	if h.adapters.Storage == nil {
		return errors.New("storage broker is required for plugins that declare storage")
	}
	if err := h.adapters.Storage.DeleteNamespace(ctx, record.PluginInstanceID, deleteData); err != nil {
		return err
	}
	eventType := "plugin.storage.retained"
	if deleteData {
		eventType = "plugin.storage.deleted"
	}
	h.audit(ctx, AuditEvent{Type: eventType, PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) deleteOrRetainSettings(ctx context.Context, record registry.PluginRecord, deleteData bool, now time.Time) error {
	if record.Manifest.Settings == nil {
		return nil
	}
	if h.adapters.Settings == nil {
		return errors.New("settings store is required for plugins that declare settings")
	}
	if err := h.adapters.Settings.Delete(ctx, settings.DeleteRequest{
		PluginInstanceID: record.PluginInstanceID,
		DeleteData:       deleteData,
		Now:              now,
	}); err != nil {
		return err
	}
	eventType := "plugin.settings.retained"
	if deleteData {
		eventType = "plugin.settings.deleted"
	}
	h.audit(ctx, AuditEvent{Type: eventType, PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return nil
}

func (h *Host) deleteOrRetainBrowserSiteData(ctx context.Context, record registry.PluginRecord, deleteData bool, now time.Time) error {
	if h.adapters.BrowserSite == nil {
		return nil
	}
	reason := "uninstall_keep_data"
	if deleteData {
		reason = "uninstall_delete_data"
	}
	result, err := h.adapters.BrowserSite.CleanupPluginOrigins(ctx, browsersite.CleanupRequest{
		PluginInstanceID: record.PluginInstanceID,
		DeleteData:       deleteData,
		Reason:           reason,
		Now:              now,
	})
	if err != nil {
		if h.adapters.Diagnostics != nil {
			_ = h.adapters.Diagnostics.AppendPluginDiagnostic(ctx, DiagnosticEvent{
				Type:              "plugin.browser_site.cleanup_failed",
				Severity:          "warning",
				Message:           err.Error(),
				PluginID:          record.PluginID,
				PluginInstanceID:  record.PluginInstanceID,
				ActiveFingerprint: record.ActiveFingerprint,
				Details: map[string]any{
					"origin_count": len(result.Records),
					"delete_data":  deleteData,
				},
			})
		}
		return err
	}
	if len(result.Records) == 0 {
		return nil
	}
	eventType := "plugin.browser_site.retained"
	if deleteData {
		eventType = "plugin.browser_site.deleted"
	}
	h.audit(ctx, AuditEvent{
		Type:             eventType,
		PluginID:         record.PluginID,
		PluginInstanceID: record.PluginInstanceID,
		Details: map[string]any{
			"origin_count": len(result.Records),
		},
	})
	return nil
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
			SchemaVersion:    store.SchemaVersion,
		})
	}
	return namespaces, nil
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

func settingsResult(snapshot settings.Snapshot) SettingsResult {
	return SettingsResult{
		PluginInstanceID: snapshot.PluginInstanceID,
		SchemaVersion:    snapshot.SchemaVersion,
		SettingsRevision: snapshot.SettingsRevision,
		Values:           cloneParams(snapshot.Values),
		UpdatedAt:        snapshot.UpdatedAt,
	}
}

func normalizeRuntimeTarget(target RuntimeTarget) RuntimeTarget {
	target.OS = strings.TrimSpace(target.OS)
	target.Arch = strings.TrimSpace(target.Arch)
	if target.OS == "" {
		target.OS = runtime.GOOS
	}
	if target.Arch == "" {
		target.Arch = runtime.GOARCH
	}
	return target
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

func (h *Host) audit(ctx context.Context, event AuditEvent) {
	if h.adapters.Audit != nil {
		_ = h.adapters.Audit.AppendPluginAudit(ctx, event)
	}
}

func defaultPluginInstanceID(pkg pluginpkg.Package) string {
	sum := sha256.Sum256([]byte(pkg.Manifest.Publisher.PublisherID + "\x00" + pkg.Manifest.PluginID() + "\x00" + pkg.PackageHash))
	return "plugini_" + hex.EncodeToString(sum[:16])
}

func defaultSurfaceInstanceID(record registry.PluginRecord, surfaceID string, ownerSessionHash string) string {
	sum := sha256.Sum256([]byte(record.PluginInstanceID + "\x00" + record.ActiveFingerprint + "\x00" + surfaceID + "\x00" + ownerSessionHash))
	return "surface_" + hex.EncodeToString(sum[:16])
}

func manifestHasSurface(m manifest.Manifest, surfaceID string) bool {
	for _, surface := range m.Surfaces {
		if surface.SurfaceID == surfaceID {
			return true
		}
	}
	return false
}

func InstallPackageBytes(ctx context.Context, h *Host, data []byte, trust registry.TrustState) (registry.PluginRecord, error) {
	return h.InstallPackage(ctx, InstallRequest{
		PackageReader: bytes.NewReader(data),
		PackageSize:   int64(len(data)),
		TrustState:    trust,
	})
}
