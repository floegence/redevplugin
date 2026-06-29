package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
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
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	PluginID  string `json:"plugin_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
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
	SurfaceCatalog          SurfaceCatalogSink
	Capabilities            *capability.Registry
	SurfaceTokens           *bridge.SurfaceTokenService
	Storage                 storage.Broker
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

type MintBridgeTokenRequest struct {
	Handshake       bridge.Handshake
	BridgeChannelID string
	Now             time.Time
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

func (h *Host) InstallPackage(ctx context.Context, req InstallRequest) (registry.PluginRecord, error) {
	if req.PackageReader == nil {
		return registry.PluginRecord{}, errors.New("package reader is required")
	}
	pkg, err := pluginpkg.Read(ctx, req.PackageReader, req.PackageSize, pluginpkg.DefaultReadOptions())
	if err != nil {
		return registry.PluginRecord{}, err
	}
	trust := req.TrustState
	if trust == "" {
		trust = registry.TrustUntrusted
	}
	instanceID := req.PluginInstanceID
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
	stored, err := h.adapters.Registry.PutPlugin(ctx, record, registry.PutOptions{Now: req.Now})
	if err != nil {
		return registry.PluginRecord{}, err
	}
	h.audit(ctx, AuditEvent{Type: "plugin.installed", PluginID: stored.PluginID, PluginInstanceID: stored.PluginInstanceID})
	return stored, nil
}

func (h *Host) EnablePlugin(ctx context.Context, req EnableRequest) (registry.PluginRecord, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.canRun(ctx, record); err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.ensureStorageNamespaces(ctx, record); err != nil {
		return registry.PluginRecord{}, err
	}
	enabled, err := h.adapters.Registry.SetEnableState(ctx, req.PluginInstanceID, registry.EnableEnabled, "", req.Now)
	if err != nil {
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
	return disabled, nil
}

func (h *Host) UninstallPlugin(ctx context.Context, req UninstallRequest) (registry.PluginRecord, error) {
	record, err := h.adapters.Registry.GetPlugin(ctx, req.PluginInstanceID)
	if err != nil {
		return registry.PluginRecord{}, err
	}
	if err := h.deleteOrRetainStorage(ctx, record, req.DeleteData); err != nil {
		return registry.PluginRecord{}, err
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
