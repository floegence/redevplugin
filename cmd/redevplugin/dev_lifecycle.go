package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/secrets"
)

const (
	devPackageFile       = "installed.redevplugin"
	devRegistryFile      = "registry.sqlite"
	devPluginDataDir     = "plugin-data"
	devSecretsFile       = "secrets.sqlite"
	devCapabilitiesDir   = "capability-artifacts"
	devCapabilityKeyFile = "host-capability.public.json"
)

var errDevStateNotInstalled = errors.New("dev plugin is not installed")

type devCapabilitySpec struct {
	ArtifactRoot  string
	PinFile       string
	PublicKeyFile string
}

type devLifecycleSummary struct {
	lifecycleSummary
	StateRoot      string `json:"state_root"`
	PluginDataRoot string `json:"plugin_data_root"`
}

type devOpenSurfaceSummary struct {
	OK                bool      `json:"ok"`
	Action            string    `json:"action"`
	StateRoot         string    `json:"state_root"`
	PluginInstanceID  string    `json:"plugin_instance_id"`
	PluginID          string    `json:"plugin_id"`
	Version           string    `json:"version"`
	SurfaceID         string    `json:"surface_id"`
	SurfaceInstanceID string    `json:"surface_instance_id"`
	ActiveFingerprint string    `json:"active_fingerprint"`
	BridgeNonce       string    `json:"bridge_nonce"`
	AssetTicketID     string    `json:"asset_ticket_id"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type devSecretSummary struct {
	OK               bool      `json:"ok"`
	Action           string    `json:"action"`
	StateRoot        string    `json:"state_root"`
	PluginInstanceID string    `json:"plugin_instance_id"`
	PluginID         string    `json:"plugin_id"`
	SecretRef        string    `json:"secret_ref"`
	Scope            string    `json:"scope"`
	Bound            bool      `json:"bound"`
	LastTestStatus   string    `json:"last_test_status,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type devPermissionSummary struct {
	OK               bool                 `json:"ok"`
	Action           string               `json:"action"`
	StateRoot        string               `json:"state_root"`
	PluginInstanceID string               `json:"plugin_instance_id"`
	PluginID         string               `json:"plugin_id"`
	Permission       permissions.Record   `json:"permission,omitempty"`
	Permissions      []permissions.Record `json:"permissions,omitempty"`
	ActiveOnly       bool                 `json:"active_only,omitempty"`
	UpdatedAt        time.Time            `json:"updated_at"`
}

type devDataSummary struct {
	OK               bool      `json:"ok"`
	Action           string    `json:"action"`
	StateRoot        string    `json:"state_root"`
	PluginInstanceID string    `json:"plugin_instance_id"`
	PluginID         string    `json:"plugin_id"`
	BundleRef        string    `json:"bundle_ref"`
	ContentHash      string    `json:"content_hash,omitempty"`
	SizeBytes        int64     `json:"size_bytes,omitempty"`
	Imported         bool      `json:"imported,omitempty"`
	Deleted          bool      `json:"deleted,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func parseDevCapabilityArgs(args []string) ([]devCapabilitySpec, error) {
	if len(args) == 0 {
		return nil, nil
	}
	if len(args)%4 != 0 {
		return nil, errors.New("each --capability requires artifact-root, pin.json, and public.json")
	}
	specs := make([]devCapabilitySpec, 0, len(args)/4)
	for index := 0; index < len(args); index += 4 {
		if args[index] != "--capability" {
			return nil, fmt.Errorf("unknown dev-install argument %q", args[index])
		}
		specs = append(specs, devCapabilitySpec{
			ArtifactRoot:  args[index+1],
			PinFile:       args[index+2],
			PublicKeyFile: args[index+3],
		})
	}
	return specs, nil
}

func devInstall(ctx context.Context, stateRoot string, packageFile string, capabilitySpecs []devCapabilitySpec) error {
	stateRoot, err := normalizeDevStateRoot(stateRoot)
	if err != nil {
		return err
	}
	precreatedEmptyRoot := false
	if info, err := os.Lstat(stateRoot); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("dev state already exists at %s", stateRoot)
		}
		entries, readErr := os.ReadDir(stateRoot)
		if readErr != nil {
			return readErr
		}
		if len(entries) != 0 {
			return fmt.Errorf("dev state already exists at %s", stateRoot)
		}
		precreatedEmptyRoot = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := os.ReadFile(packageFile)
	if err != nil {
		return err
	}
	pkg, err := pluginpkg.Read(ctx, bytes.NewReader(data), int64(len(data)), pluginpkg.DefaultReadLimits())
	if err != nil {
		return err
	}
	loadedCapabilities, err := loadDevCapabilitySpecs(capabilitySpecs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(stateRoot), 0o700); err != nil {
		return err
	}
	stagingRoot, err := os.MkdirTemp(filepath.Dir(stateRoot), "."+filepath.Base(stateRoot)+".install-")
	if err != nil {
		return err
	}
	if err := os.Chmod(stagingRoot, 0o700); err != nil {
		_ = os.RemoveAll(stagingRoot)
		return err
	}
	promoted := false
	defer func() {
		if !promoted {
			_ = os.RemoveAll(stagingRoot)
		}
	}()
	harness, err := newDevHarness(ctx, stagingRoot, loadedCapabilities, pluginpkg.NewMemoryAssetStore())
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = harness.Close()
		}
	}()
	record, err := harness.host.ImportLocalPackage(ctx, host.ImportLocalPackageRequest{
		PackageReader: bytes.NewReader(data),
		PackageSize:   int64(len(data)),
	})
	if err != nil {
		return err
	}
	if record.PluginID != pkg.Manifest.PluginID() {
		return fmt.Errorf("installed plugin identity mismatch")
	}
	packagePath := filepath.Join(stagingRoot, devPackageFile)
	if err := writeBytesFile(packagePath, data, 0o600); err != nil {
		return err
	}
	if err := persistDevCapabilities(stagingRoot, loadedCapabilities); err != nil {
		return err
	}
	if err := harness.Close(); err != nil {
		return err
	}
	closed = true
	if precreatedEmptyRoot {
		entries, err := os.ReadDir(stateRoot)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("dev state root changed during installation: %s", stateRoot)
		}
		if err := os.Remove(stateRoot); err != nil {
			return err
		}
	}
	if err := os.Rename(stagingRoot, stateRoot); err != nil {
		if precreatedEmptyRoot {
			_ = os.Mkdir(stateRoot, 0o700)
		}
		return err
	}
	promoted = true
	return writeDevLifecycle("dev-install", stateRoot, record)
}

func devEnable(ctx context.Context, stateRoot string) error {
	harness, record, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	record, err = harness.host.EnablePlugin(ctx, host.EnableRequest{
		PluginInstanceID:           record.PluginInstanceID,
		ExpectedManagementRevision: record.ManagementRevision,
	})
	if err != nil {
		return err
	}
	return writeDevLifecycle("dev-enable", harness.stateRoot, record)
}

func devOpen(ctx context.Context, stateRoot string, surfaceID string) error {
	harness, record, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	if record.EnableState != registry.EnableEnabled {
		return errors.New("dev plugin must be enabled before opening a surface")
	}
	surfaceID = strings.TrimSpace(surfaceID)
	if surfaceID == "" {
		return errors.New("surface_id is required")
	}
	bootstrap, err := harness.host.OpenSurface(ctx, host.OpenSurfaceRequest{
		PluginInstanceID:           record.PluginInstanceID,
		ExpectedManagementRevision: record.ManagementRevision,
		SurfaceID:                  surfaceID,
	})
	if err != nil {
		return err
	}
	return writeJSON(devOpenSurfaceSummary{
		OK:                true,
		Action:            "dev-open",
		StateRoot:         harness.stateRoot,
		PluginInstanceID:  record.PluginInstanceID,
		PluginID:          record.PluginID,
		Version:           record.Version,
		SurfaceID:         bootstrap.SurfaceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		ActiveFingerprint: bootstrap.ActiveFingerprint,
		BridgeNonce:       bootstrap.BridgeNonce,
		AssetTicketID:     bootstrap.AssetTicketID,
		IssuedAt:          bootstrap.IssuedAt,
		ExpiresAt:         bootstrap.ExpiresAt,
	})
}

func devDisable(ctx context.Context, stateRoot string) error {
	harness, record, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	record, err = harness.host.DisablePlugin(ctx, host.DisableRequest{
		PluginInstanceID:           record.PluginInstanceID,
		ExpectedManagementRevision: record.ManagementRevision,
		Reason:                     "dev-cli",
	})
	if err != nil {
		return err
	}
	return writeDevLifecycle("dev-disable", harness.stateRoot, record)
}

func devUninstall(ctx context.Context, stateRoot string) error {
	harness, record, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	record, err = harness.host.UninstallPlugin(ctx, host.UninstallRequest{
		PluginInstanceID:           record.PluginInstanceID,
		ExpectedManagementRevision: record.ManagementRevision,
		DeleteData:                 true,
	})
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(harness.stateRoot, devPackageFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeDevLifecycle("dev-uninstall", harness.stateRoot, record)
}

func devSecretBind(ctx context.Context, stateRoot string, secretRef string, scope string) error {
	harness, record, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	req := host.SecretBindRequest{
		PluginInstanceID: record.PluginInstanceID,
		SecretRef:        secretRef,
		Scope:            scope,
	}
	if err := harness.host.BindSecretRef(ctx, req); err != nil {
		return err
	}
	return writeCurrentDevSecret(ctx, harness, record, "dev-secret-bind", req)
}

func devSecretTest(ctx context.Context, stateRoot string, secretRef string, scope string) error {
	harness, record, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	req := host.SecretBindRequest{
		PluginInstanceID: record.PluginInstanceID,
		SecretRef:        secretRef,
		Scope:            scope,
	}
	if err := harness.host.TestSecretRef(ctx, host.SecretTestRequest(req)); err != nil {
		return err
	}
	return writeCurrentDevSecret(ctx, harness, record, "dev-secret-test", req)
}

func devSecretDelete(ctx context.Context, stateRoot string, secretRef string, scope string) error {
	harness, record, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	req := host.SecretBindRequest{
		PluginInstanceID: record.PluginInstanceID,
		SecretRef:        secretRef,
		Scope:            scope,
	}
	if err := harness.host.DeleteSecretRef(ctx, host.SecretDeleteRequest(req)); err != nil {
		return err
	}
	return writeCurrentDevSecret(ctx, harness, record, "dev-secret-delete", req)
}

func devPermissionGrant(ctx context.Context, stateRoot string, permissionID string) error {
	harness, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	record, err := harness.host.GrantPermission(ctx, host.GrantPermissionRequest{
		PluginInstanceID:           plugin.PluginInstanceID,
		PermissionID:               permissionID,
		ExpectedPolicyRevision:     plugin.PolicyRevision,
		ExpectedManagementRevision: plugin.ManagementRevision,
		ExpectedRevokeEpoch:        plugin.RevokeEpoch,
	})
	if err != nil {
		return err
	}
	plugin, err = harness.registryStore.GetPlugin(ctx, plugin.PluginInstanceID)
	if err != nil {
		return err
	}
	return writeDevPermission(harness, plugin, "dev-permission-grant", record.Permission)
}

func devPermissionRevoke(ctx context.Context, stateRoot string, permissionID string, reason string) error {
	harness, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	if strings.TrimSpace(reason) == "" {
		reason = "dev-cli"
	}
	record, err := harness.host.RevokePermission(ctx, host.RevokePermissionRequest{
		PluginInstanceID:           plugin.PluginInstanceID,
		PermissionID:               permissionID,
		ExpectedPolicyRevision:     plugin.PolicyRevision,
		ExpectedManagementRevision: plugin.ManagementRevision,
		ExpectedRevokeEpoch:        plugin.RevokeEpoch,
		Reason:                     reason,
	})
	if err != nil {
		return err
	}
	plugin, err = harness.registryStore.GetPlugin(ctx, plugin.PluginInstanceID)
	if err != nil {
		return err
	}
	return writeDevPermission(harness, plugin, "dev-permission-revoke", record.Permission)
}

func devPermissionList(ctx context.Context, stateRoot string, activeOnly bool) error {
	harness, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	records, err := harness.host.ListPermissionGrants(ctx, host.ListPermissionGrantsRequest{
		PluginInstanceID: plugin.PluginInstanceID,
		ActiveOnly:       activeOnly,
	})
	if err != nil {
		return err
	}
	return writeJSON(devPermissionSummary{
		OK:               true,
		Action:           "dev-permission-list",
		StateRoot:        harness.stateRoot,
		PluginInstanceID: plugin.PluginInstanceID,
		PluginID:         plugin.PluginID,
		Permissions:      records,
		ActiveOnly:       activeOnly,
		UpdatedAt:        time.Now().UTC(),
	})
}

func devExportData(ctx context.Context, stateRoot string) error {
	harness, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	result, err := harness.host.ExportPluginData(ctx, host.ExportDataRequest{
		PluginInstanceID: plugin.PluginInstanceID,
	})
	if err != nil {
		return err
	}
	return writeJSON(devDataSummary{
		OK:               true,
		Action:           "dev-export-data",
		StateRoot:        harness.stateRoot,
		PluginInstanceID: plugin.PluginInstanceID,
		PluginID:         plugin.PluginID,
		BundleRef:        result.BundleRef,
		ContentHash:      result.ContentHash,
		SizeBytes:        result.SizeBytes,
		UpdatedAt:        time.Now().UTC(),
	})
}

func devImportData(ctx context.Context, stateRoot string, bundleRef string) error {
	harness, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	bundleRef = strings.TrimSpace(bundleRef)
	if bundleRef == "" {
		return plugindata.ErrInvalidArgument
	}
	if _, err := harness.host.ImportPluginData(ctx, host.ImportDataRequest{
		PluginInstanceID:           plugin.PluginInstanceID,
		BundleRef:                  bundleRef,
		ExpectedManagementRevision: plugin.ManagementRevision,
	}); err != nil {
		return err
	}
	return writeJSON(devDataSummary{
		OK:               true,
		Action:           "dev-import-data",
		StateRoot:        harness.stateRoot,
		PluginInstanceID: plugin.PluginInstanceID,
		PluginID:         plugin.PluginID,
		BundleRef:        bundleRef,
		Imported:         true,
		UpdatedAt:        time.Now().UTC(),
	})
}

func devDeleteExport(ctx context.Context, stateRoot string, bundleRef string) error {
	harness, plugin, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	bundleRef = strings.TrimSpace(bundleRef)
	if bundleRef == "" {
		return plugindata.ErrInvalidArgument
	}
	if err := harness.host.DeleteExportedPluginData(ctx, host.DeleteExportDataRequest{BundleRef: bundleRef}); err != nil {
		return err
	}
	return writeJSON(devDataSummary{OK: true, Action: "dev-delete-export", StateRoot: harness.stateRoot, PluginInstanceID: plugin.PluginInstanceID, PluginID: plugin.PluginID, BundleRef: bundleRef, Deleted: true, UpdatedAt: time.Now().UTC()})
}

func devStatus(stateRoot string) error {
	harness, record, err := loadDevHarness(context.Background(), stateRoot)
	if err != nil {
		return err
	}
	defer harness.Close()
	return writeDevLifecycle("dev-status", harness.stateRoot, record)
}

func writeCurrentDevSecret(ctx context.Context, harness devHarness, plugin registry.PluginRecord, action string, req host.SecretBindRequest) error {
	record, err := devSecretRecordFor(ctx, harness.secretStore, req)
	if err != nil {
		return err
	}
	return writeDevSecret(action, harness.stateRoot, plugin, record)
}

func writeDevPermission(harness devHarness, plugin registry.PluginRecord, action string, record permissions.Record) error {
	return writeJSON(devPermissionSummary{
		OK:               true,
		Action:           action,
		StateRoot:        harness.stateRoot,
		PluginInstanceID: plugin.PluginInstanceID,
		PluginID:         plugin.PluginID,
		Permission:       record,
		UpdatedAt:        plugin.UpdatedAt,
	})
}

func writeDevLifecycle(action string, stateRoot string, record registry.PluginRecord) error {
	return writeJSON(devLifecycleSummary{
		lifecycleSummary: lifecycleSummary{
			OK:                 true,
			Action:             action,
			PluginInstanceID:   record.PluginInstanceID,
			PluginID:           record.PluginID,
			Version:            record.Version,
			TrustState:         record.TrustState,
			EnableState:        record.EnableState,
			PolicyRevision:     record.PolicyRevision,
			ManagementRevision: record.ManagementRevision,
			RevokeEpoch:        record.RevokeEpoch,
		},
		StateRoot:      stateRoot,
		PluginDataRoot: filepath.Join(stateRoot, devPluginDataDir),
	})
}

func writeDevSecret(action string, stateRoot string, plugin registry.PluginRecord, secret secrets.Record) error {
	return writeJSON(devSecretSummary{
		OK:               true,
		Action:           action,
		StateRoot:        stateRoot,
		PluginInstanceID: plugin.PluginInstanceID,
		PluginID:         plugin.PluginID,
		SecretRef:        secret.SecretRef,
		Scope:            secret.Scope,
		Bound:            secret.Bound,
		LastTestStatus:   secret.LastTestStatus,
		UpdatedAt:        secret.UpdatedAt,
	})
}

type devHarness struct {
	stateRoot     string
	host          *host.Host
	registryStore *registry.SQLiteStore
	pluginData    *plugindata.FileStore
	secretStore   *secrets.SQLiteStore
}

func (h devHarness) Close() error {
	if h.host == nil {
		return nil
	}
	return errors.Join(h.host.Close(), h.secretStore.Close(), h.registryStore.Close())
}

func loadDevHarness(ctx context.Context, stateRoot string) (devHarness, registry.PluginRecord, error) {
	stateRoot, err := normalizeDevStateRoot(stateRoot)
	if err != nil {
		return devHarness{}, registry.PluginRecord{}, err
	}
	packagePath := filepath.Join(stateRoot, devPackageFile)
	pkg, err := pluginpkg.ReadFile(ctx, packagePath, pluginpkg.DefaultReadLimits())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return devHarness{}, registry.PluginRecord{}, errDevStateNotInstalled
		}
		return devHarness{}, registry.PluginRecord{}, err
	}
	assets := pluginpkg.NewMemoryAssetStore()
	if err := assets.PutPackage(ctx, pkg); err != nil {
		return devHarness{}, registry.PluginRecord{}, err
	}
	loadedCapabilities, err := loadPersistedDevCapabilities(stateRoot)
	if err != nil {
		return devHarness{}, registry.PluginRecord{}, err
	}
	harness, err := newDevHarness(ctx, stateRoot, loadedCapabilities, assets)
	if err != nil {
		return devHarness{}, registry.PluginRecord{}, err
	}
	records, err := harness.registryStore.ListPlugins(ctx)
	if err != nil {
		_ = harness.Close()
		return devHarness{}, registry.PluginRecord{}, err
	}
	if len(records) != 1 || records[0].PluginID != pkg.Manifest.PluginID() {
		_ = harness.Close()
		return devHarness{}, registry.PluginRecord{}, errDevStateNotInstalled
	}
	return harness, records[0], nil
}

func newDevHarness(ctx context.Context, stateRoot string, loadedCapabilities []loadedHostCapabilityArtifact, assets pluginpkg.AssetStore) (devHarness, error) {
	registryStore, err := registry.NewSQLiteStore(ctx, filepath.Join(stateRoot, devRegistryFile))
	if err != nil {
		return devHarness{}, err
	}
	pluginData, err := plugindata.Open(ctx, filepath.Join(stateRoot, devPluginDataDir), registryStore)
	if err != nil {
		_ = registryStore.Close()
		return devHarness{}, err
	}
	secretStore, err := secrets.NewSQLiteStore(ctx, filepath.Join(stateRoot, devSecretsFile))
	if err != nil {
		_ = pluginData.Close()
		_ = registryStore.Close()
		return devHarness{}, err
	}
	capabilities, err := devCapabilityRegistry(loadedCapabilities)
	if err != nil {
		_ = secretStore.Close()
		_ = pluginData.Close()
		_ = registryStore.Close()
		return devHarness{}, err
	}
	adapters := newEphemeralCLIAdapters(registryStore, pluginData)
	adapters.Core.Registry = registryStore
	adapters.Core.Assets = assets
	adapters.Secrets = &host.SecretsModule{Store: secretStore}
	adapters.Capability = &host.CapabilityModule{Registry: capabilities}
	h, err := host.Open(cliContext(ctx), adapters)
	if err != nil {
		_ = secretStore.Close()
		_ = pluginData.Close()
		_ = registryStore.Close()
		return devHarness{}, err
	}
	return devHarness{
		stateRoot:     stateRoot,
		host:          h,
		registryStore: registryStore,
		pluginData:    pluginData,
		secretStore:   secretStore,
	}, nil
}

type devCapabilityAdapter struct{}

func (devCapabilityAdapter) ProjectTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	return capability.TargetDescriptor{Kind: "dev_reference_host", Fields: req.TargetInput}, nil
}

func (devCapabilityAdapter) Invoke(context.Context, capability.Invocation) (capability.Result, error) {
	return capability.Result{}, errors.New("dev reference host does not implement this capability")
}

func loadDevCapabilitySpecs(specs []devCapabilitySpec) ([]loadedHostCapabilityArtifact, error) {
	loaded := make([]loadedHostCapabilityArtifact, 0, len(specs))
	for _, spec := range specs {
		artifact, err := loadVerifiedHostCapability(spec.ArtifactRoot, spec.PinFile, spec.PublicKeyFile)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, artifact)
	}
	return loaded, nil
}

func devCapabilityRegistry(loaded []loadedHostCapabilityArtifact) (*capability.Registry, error) {
	capabilities := capability.NewRegistry()
	for _, artifact := range loaded {
		adapter := devCapabilityAdapter{}
		if err := capabilities.Register(capability.Registration{Contract: artifact.Verified, TargetProjector: adapter, Adapter: adapter}); err != nil {
			return nil, err
		}
	}
	return capabilities, nil
}

func persistDevCapabilities(stateRoot string, loaded []loadedHostCapabilityArtifact) error {
	for _, artifact := range loaded {
		contract := artifact.Verified.Contract
		rootRel := filepath.ToSlash(filepath.Join(devCapabilitiesDir, contract.ContractID, contract.ContractVersion))
		root, err := resolveDevCapabilityStatePath(stateRoot, rootRel)
		if err != nil {
			return err
		}
		if err := createEmptyDirectory(root); err != nil {
			return err
		}
		for ref, content := range artifact.Bundle.Files {
			if err := writeArtifactFile(root, ref, content); err != nil {
				return err
			}
		}
		pinRel := filepath.ToSlash(filepath.Join(rootRel, hostCapabilityPinFile))
		pinFile, err := resolveDevCapabilityStatePath(stateRoot, pinRel)
		if err != nil {
			return err
		}
		if err := writeJSONFile(pinFile, artifact.Bundle.Pin, 0o600); err != nil {
			return err
		}
		publicRel := filepath.ToSlash(filepath.Join(rootRel, devCapabilityKeyFile))
		publicFile, err := resolveDevCapabilityStatePath(stateRoot, publicRel)
		if err != nil {
			return err
		}
		if err := writeJSONFile(publicFile, artifact.PublicDoc, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func loadPersistedDevCapabilities(stateRoot string) ([]loadedHostCapabilityArtifact, error) {
	capabilitiesRoot := filepath.Join(stateRoot, devCapabilitiesDir)
	contracts, err := os.ReadDir(capabilitiesRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	loaded := []loadedHostCapabilityArtifact{}
	for _, contract := range contracts {
		if !contract.IsDir() {
			return nil, fmt.Errorf("unexpected capability artifact entry %q", contract.Name())
		}
		versionsRoot := filepath.Join(capabilitiesRoot, contract.Name())
		versions, err := os.ReadDir(versionsRoot)
		if err != nil {
			return nil, err
		}
		for _, versionEntry := range versions {
			if !versionEntry.IsDir() {
				return nil, fmt.Errorf("unexpected capability version entry %q", versionEntry.Name())
			}
			artifactRoot := filepath.Join(versionsRoot, versionEntry.Name())
			artifact, err := loadVerifiedHostCapability(
				artifactRoot,
				filepath.Join(artifactRoot, hostCapabilityPinFile),
				filepath.Join(artifactRoot, devCapabilityKeyFile),
			)
			if err != nil {
				return nil, err
			}
			loaded = append(loaded, artifact)
		}
	}
	return loaded, nil
}

func resolveDevCapabilityStatePath(stateRoot, relative string) (string, error) {
	relative = filepath.Clean(filepath.FromSlash(strings.TrimSpace(relative)))
	if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("dev capability path must stay inside the state root")
	}
	rootAbs, err := filepath.Abs(stateRoot)
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(rootAbs, relative)
	if !strings.HasPrefix(filepath.Clean(resolved), rootAbs+string(filepath.Separator)) {
		return "", errors.New("dev capability path escaped the state root")
	}
	return resolved, nil
}

func normalizeDevStateRoot(stateRoot string) (string, error) {
	stateRoot = strings.TrimSpace(stateRoot)
	if stateRoot == "" {
		return "", errors.New("state root is required")
	}
	abs, err := filepath.Abs(stateRoot)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func devSecretRecordFor(ctx context.Context, store secrets.Lister, req host.SecretBindRequest) (secrets.Record, error) {
	normalized, err := normalizeDevSecretRequest(req)
	if err != nil {
		return secrets.Record{}, err
	}
	records, err := store.List(ctx, secrets.ListRequest{
		PluginInstanceID: normalized.PluginInstanceID,
		Scope:            normalized.Scope,
	})
	if err != nil {
		return secrets.Record{}, err
	}
	for _, record := range records {
		if record.SecretRef == normalized.SecretRef {
			return record, nil
		}
	}
	return secrets.Record{}, errors.New("secret adapter did not return committed metadata")
}

func normalizeDevSecretRequest(req host.SecretBindRequest) (host.SecretBindRequest, error) {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	req.SecretRef = strings.TrimSpace(req.SecretRef)
	req.Scope = strings.TrimSpace(req.Scope)
	if req.PluginInstanceID == "" || req.SecretRef == "" || req.Scope == "" {
		return host.SecretBindRequest{}, host.ErrInvalidSecretRef
	}
	return req, nil
}

var _ host.SecretStoreAdapter = (*secrets.SQLiteStore)(nil)
