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
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/storage"
)

type AuditSink interface {
	AppendPluginAudit(ctx context.Context, event AuditEvent) error
}

type DiagnosticsSink interface {
	AppendPluginDiagnostic(ctx context.Context, event DiagnosticEvent) error
}

type AuditEvent struct {
	Type             string `json:"type"`
	PluginID         string `json:"plugin_id"`
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type DiagnosticEvent struct {
	Type              string         `json:"type"`
	Severity          string         `json:"severity"`
	Message           string         `json:"message"`
	PluginID          string         `json:"plugin_id,omitempty"`
	PluginInstanceID  string         `json:"plugin_instance_id,omitempty"`
	SurfaceID         string         `json:"surface_id,omitempty"`
	SurfaceInstanceID string         `json:"surface_instance_id,omitempty"`
	ActiveFingerprint string         `json:"active_fingerprint,omitempty"`
	RequestID         string         `json:"request_id,omitempty"`
	Details           map[string]any `json:"details,omitempty"`
}

type PolicyAdapter interface {
	EvaluateLocalPolicy(ctx context.Context, session sessionctx.Context, plugin PluginRef, method manifest.MethodSpec) (PolicyDecision, error)
	DeveloperModeEnabled(ctx context.Context, session sessionctx.Context) (bool, error)
	LocalGeneratedPluginsEnabled(ctx context.Context, session sessionctx.Context) (bool, error)
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

type RuntimeTarget struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
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
	Registry                registry.Store
	Audit                   AuditSink
	Diagnostics             DiagnosticsSink
	Secrets                 SecretStoreAdapter
	RuntimeArtifactResolver RuntimeArtifactResolver
	RuntimeSupervisor       runtimeclient.Supervisor
	SurfaceCatalog          SurfaceCatalogSink
	Assets                  pluginpkg.AssetStore
	Capabilities            *capability.Registry
	SurfaceTokens           *bridge.SurfaceTokenService
	Storage                 storage.Broker
	Connectivity            connectivity.Broker
	Operations              operation.Store
}

type Host struct {
	adapters      Adapters
	surfaceTokens *bridge.SurfaceTokenService
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

type OpenSurfaceRequest struct {
	PluginInstanceID     string
	SurfaceID            string
	SurfaceInstanceID    string
	OwnerSessionHash     string
	OwnerUserHash        string
	SessionChannelIDHash string
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
	ConfirmationRequired bool   `json:"confirmation_required,omitempty"`
	ConfirmationTokenID  string `json:"confirmation_token_id,omitempty"`
	RequestHash          string `json:"request_hash,omitempty"`
}

type WorkerInvocationPayload struct {
	PluginID             string         `json:"plugin_id"`
	PluginInstanceID     string         `json:"plugin_instance_id"`
	ActiveFingerprint    string         `json:"active_fingerprint"`
	WorkerID             string         `json:"worker_id"`
	WorkerMode           string         `json:"worker_mode"`
	WorkerScope          string         `json:"worker_scope"`
	Artifact             string         `json:"artifact"`
	ABI                  string         `json:"abi"`
	Method               string         `json:"method"`
	Export               string         `json:"export"`
	Effect               string         `json:"effect"`
	Execution            string         `json:"execution"`
	SurfaceInstanceID    string         `json:"surface_instance_id,omitempty"`
	SessionChannelIDHash string         `json:"session_channel_id_hash,omitempty"`
	BridgeChannelID      string         `json:"bridge_channel_id,omitempty"`
	Params               map[string]any `json:"params,omitempty"`
}

type ConfirmMethodRequest = CallMethodRequest

type ConfirmMethodResult struct {
	ConfirmationToken   string    `json:"confirmation_token"`
	ConfirmationTokenID string    `json:"confirmation_token_id"`
	RequestHash         string    `json:"request_hash"`
	ExpiresAt           time.Time `json:"expires_at"`
}

var (
	ErrSecretStoreRequired = errors.New("secret store adapter is required")
	ErrInvalidSecretRef    = errors.New("secret_ref is invalid")
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

type MintConnectionGrantRequest struct {
	PluginInstanceID    string                 `json:"plugin_instance_id"`
	ConnectorID         string                 `json:"connector_id"`
	Transport           connectivity.Transport `json:"transport"`
	Destination         string                 `json:"destination"`
	RuntimeGenerationID string                 `json:"runtime_generation_id,omitempty"`
	Now                 time.Time              `json:"now,omitempty"`
	TTL                 time.Duration          `json:"ttl,omitempty"`
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
	if adapters.Capabilities == nil {
		adapters.Capabilities = capability.NewRegistry()
	}
	if adapters.SurfaceTokens == nil {
		adapters.SurfaceTokens = bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{})
	}
	if adapters.Connectivity == nil {
		adapters.Connectivity = connectivity.NewMemoryBroker()
	}
	if adapters.Operations == nil {
		adapters.Operations = operation.NewMemoryStore()
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
	h.audit(ctx, AuditEvent{Type: "plugin.surface.opened", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return bootstrap, nil
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

type resolvedMethodCall struct {
	record   registry.PluginRecord
	method   manifest.MethodSpec
	audience bridge.Audience
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
	return resolvedMethodCall{record: record, method: method, audience: audience, revision: revision}, nil
}

func (h *Host) InstallPackage(ctx context.Context, req InstallRequest) (registry.PluginRecord, error) {
	if req.PackageReader == nil {
		return registry.PluginRecord{}, errors.New("package reader is required")
	}
	trust := req.TrustState
	if trust == "" {
		trust = registry.TrustUntrusted
	}
	pkg, record, err := h.readPackageRecord(ctx, req.PackageReader, req.PackageSize, trust, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
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
	trust := req.TrustState
	if trust == "" {
		trust = current.TrustState
	}
	pkg, next, err := h.readPackageRecord(ctx, req.PackageReader, req.PackageSize, trust, current.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
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

func (h *Host) readPackageRecord(ctx context.Context, reader io.ReaderAt, size int64, trust registry.TrustState, instanceID string) (pluginpkg.Package, registry.PluginRecord, error) {
	pkg, err := pluginpkg.Read(ctx, reader, size, pluginpkg.DefaultReadOptions())
	if err != nil {
		return pluginpkg.Package{}, registry.PluginRecord{}, err
	}
	if instanceID == "" {
		instanceID = defaultPluginInstanceID(pkg)
	}
	record := registry.PluginRecord{
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
	}
	return pkg, record, nil
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
	next.Metadata = cloneStringMap(current.Metadata)
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
	return nil
}

func (h *Host) refreshEnabledRuntimeState(ctx context.Context, record registry.PluginRecord) error {
	if record.EnableState != registry.EnableEnabled {
		return nil
	}
	if err := h.ensureStorageNamespaces(ctx, record); err != nil {
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

func cloneEntries(entries []pluginpkg.Entry) []pluginpkg.Entry {
	if entries == nil {
		return nil
	}
	return append([]pluginpkg.Entry(nil), entries...)
}

func (h *Host) ListPlugins(ctx context.Context) ([]registry.PluginRecord, error) {
	return h.adapters.Registry.ListPlugins(ctx)
}

func (h *Host) ListOperations(ctx context.Context, req ListOperationsRequest) ([]operation.Record, error) {
	return h.adapters.Operations.List(ctx, operation.ListRequest{PluginInstanceID: req.PluginInstanceID})
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

func (h *Host) MintConnectionGrant(ctx context.Context, req MintConnectionGrantRequest) (connectivity.ConnectionGrant, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return connectivity.ConnectionGrant{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		return connectivity.ConnectionGrant{}, errors.New("plugin is not enabled")
	}
	if err := h.canRun(ctx, record); err != nil {
		return connectivity.ConnectionGrant{}, err
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
		return connectivity.ConnectionGrant{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.connectivity.grant_minted", PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID})
	return grant, nil
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
	if err := h.deleteOrRetainStorage(ctx, record, req.DeleteData); err != nil {
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
		return CallMethodResult{Data: result.Data, OperationID: result.OperationID, StreamID: result.StreamID}, nil
	case manifest.MethodRouteCoreAction:
		return CallMethodResult{}, fmt.Errorf("method route kind %q is not implemented", method.Route.Kind)
	default:
		return CallMethodResult{}, fmt.Errorf("method route kind %q is invalid", method.Route.Kind)
	}
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
	payload := WorkerInvocationPayload{
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		ActiveFingerprint:    record.ActiveFingerprint,
		WorkerID:             worker.WorkerID,
		WorkerMode:           string(worker.Mode),
		WorkerScope:          worker.Scope,
		Artifact:             worker.Artifact,
		ABI:                  worker.ABI,
		Method:               method.Method,
		Export:               method.Route.Export,
		Effect:               string(method.Effect),
		Execution:            string(method.Execution),
		SurfaceInstanceID:    req.SurfaceInstanceID,
		SessionChannelIDHash: req.SessionChannelIDHash,
		BridgeChannelID:      req.BridgeChannelID,
		Params:               cloneParams(req.Params),
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

func manifestCapabilityBinding(m manifest.Manifest, bindingID string) (manifest.CapabilityBinding, bool) {
	for _, binding := range m.CapabilityBindings {
		if binding.BindingID == bindingID {
			return binding, true
		}
	}
	return manifest.CapabilityBinding{}, false
}

func manifestWorker(m manifest.Manifest, workerID string) (manifest.WorkerSpec, bool) {
	for _, worker := range m.Workers {
		if worker.WorkerID == workerID {
			return worker, true
		}
	}
	return manifest.WorkerSpec{}, false
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
