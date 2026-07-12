package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
)

const (
	devStateSchemaVersion = "redevplugin.dev_state.v2"
	devStateFile          = "redevplugin-dev-state.json"
	devPackageFile        = "installed.redevplugin"
	devStorageDir         = "storage"
)

var errDevStateNotInstalled = errors.New("dev plugin is not installed")

type devLifecycleState struct {
	SchemaVersion string                  `json:"schema_version"`
	PackageFile   string                  `json:"package_file,omitempty"`
	Record        registry.PluginRecord   `json:"record"`
	Settings      settings.MemoryState    `json:"settings,omitempty"`
	Secrets       secrets.MemoryState     `json:"secrets,omitempty"`
	Permissions   permissions.MemoryState `json:"permissions,omitempty"`
	UpdatedAt     time.Time               `json:"updated_at"`
}

type devLifecycleSummary struct {
	lifecycleSummary
	StateRoot       string `json:"state_root"`
	StorageRoot     string `json:"storage_root"`
	PackageRetained bool   `json:"package_retained"`
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
	OK                 bool      `json:"ok"`
	Action             string    `json:"action"`
	StateRoot          string    `json:"state_root"`
	PluginInstanceID   string    `json:"plugin_instance_id"`
	PluginID           string    `json:"plugin_id"`
	ArchiveRef         string    `json:"archive_ref,omitempty"`
	SettingsArchiveRef string    `json:"settings_archive_ref,omitempty"`
	IncludeSecrets     bool      `json:"include_secrets,omitempty"`
	DeleteExisting     bool      `json:"delete_existing,omitempty"`
	Imported           bool      `json:"imported,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func devInstall(ctx context.Context, stateRoot string, packageFile string) error {
	stateRoot, err := prepareDevStateRoot(stateRoot)
	if err != nil {
		return err
	}
	if stateExists(stateRoot) {
		return fmt.Errorf("dev state already exists at %s", stateRoot)
	}
	data, err := os.ReadFile(packageFile)
	if err != nil {
		return err
	}
	pkg, err := pluginpkg.Read(ctx, bytes.NewReader(data), int64(len(data)), pluginpkg.DefaultReadOptions())
	if err != nil {
		return err
	}
	h, err := newDevInstallHost(stateRoot)
	if err != nil {
		return err
	}
	record, err := h.ImportLocalPackage(ctx, host.ImportLocalPackageRequest{
		PackageReader: bytes.NewReader(data),
		PackageSize:   int64(len(data)),
	})
	if err != nil {
		return err
	}
	if record.PluginID != pkg.Manifest.PluginID() {
		return fmt.Errorf("installed plugin identity mismatch")
	}
	packagePath := filepath.Join(stateRoot, devPackageFile)
	if err := writeBytesFile(packagePath, data, 0o600); err != nil {
		return err
	}
	state := devLifecycleState{
		SchemaVersion: devStateSchemaVersion,
		PackageFile:   devPackageFile,
		Record:        record,
		UpdatedAt:     time.Now().UTC(),
	}
	if err := saveDevState(stateRoot, state); err != nil {
		return err
	}
	return writeDevLifecycle("dev-install", stateRoot, state)
}

func devEnable(ctx context.Context, stateRoot string) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	record, err := harness.host.EnablePlugin(ctx, host.EnableRequest{
		PluginInstanceID:   state.Record.PluginInstanceID,
		PluginStateVersion: state.Record.ManagementRevision,
	})
	if err != nil {
		return err
	}
	state.Record = record
	state.UpdatedAt = time.Now().UTC()
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeDevLifecycle("dev-enable", harness.stateRoot, state)
}

func devOpen(ctx context.Context, stateRoot string, surfaceID string) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	if state.Record.EnableState != registry.EnableEnabled {
		return errors.New("dev plugin must be enabled before opening a surface")
	}
	surfaceID = strings.TrimSpace(surfaceID)
	if surfaceID == "" {
		return errors.New("surface_id is required")
	}
	bootstrap, err := harness.host.OpenSurface(ctx, host.OpenSurfaceRequest{
		PluginInstanceID:     state.Record.PluginInstanceID,
		PluginStateVersion:   state.Record.ManagementRevision,
		SurfaceID:            surfaceID,
		OwnerSessionHash:     "dev_owner_session",
		OwnerUserHash:        "dev_owner_user",
		SessionChannelIDHash: "dev_session_channel",
	})
	if err != nil {
		return err
	}
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	state.UpdatedAt = time.Now().UTC()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeJSON(devOpenSurfaceSummary{
		OK:                true,
		Action:            "dev-open",
		StateRoot:         harness.stateRoot,
		PluginInstanceID:  state.Record.PluginInstanceID,
		PluginID:          state.Record.PluginID,
		Version:           state.Record.Version,
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
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	record, err := harness.host.DisablePlugin(ctx, host.DisableRequest{
		PluginInstanceID:   state.Record.PluginInstanceID,
		PluginStateVersion: state.Record.ManagementRevision,
		Reason:             "dev-cli",
	})
	if err != nil {
		return err
	}
	state.Record = record
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	state.UpdatedAt = time.Now().UTC()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeDevLifecycle("dev-disable", harness.stateRoot, state)
}

func devUninstall(ctx context.Context, stateRoot string, deleteData bool) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	pluginInstanceID := state.Record.PluginInstanceID
	record, err := harness.host.UninstallPlugin(ctx, host.UninstallRequest{
		PluginInstanceID:   pluginInstanceID,
		PluginStateVersion: state.Record.ManagementRevision,
		DeleteData:         deleteData,
	})
	if err != nil {
		return err
	}
	state.Record = record
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	state.PackageFile = ""
	state.UpdatedAt = time.Now().UTC()
	if err := os.Remove(filepath.Join(harness.stateRoot, devPackageFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeDevLifecycle("dev-uninstall", harness.stateRoot, state)
}

func devSecretBind(ctx context.Context, stateRoot string, secretRef string, scope string) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	req := host.SecretBindRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		SecretRef:        secretRef,
		Scope:            scope,
	}
	if err := harness.host.BindSecretRef(ctx, req); err != nil {
		return err
	}
	return saveAndWriteDevSecret(harness, state, "dev-secret-bind", req)
}

func devSecretTest(ctx context.Context, stateRoot string, secretRef string, scope string) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	req := host.SecretBindRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		SecretRef:        secretRef,
		Scope:            scope,
	}
	if err := harness.host.TestSecretRef(ctx, host.SecretTestRequest(req)); err != nil {
		return err
	}
	return saveAndWriteDevSecret(harness, state, "dev-secret-test", req)
}

func devSecretDelete(ctx context.Context, stateRoot string, secretRef string, scope string) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	req := host.SecretBindRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		SecretRef:        secretRef,
		Scope:            scope,
	}
	if err := harness.host.DeleteSecretRef(ctx, host.SecretDeleteRequest(req)); err != nil {
		return err
	}
	return saveAndWriteDevSecret(harness, state, "dev-secret-delete", req)
}

func devPermissionGrant(ctx context.Context, stateRoot string, permissionID string, grantedBy string) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	if strings.TrimSpace(grantedBy) == "" {
		grantedBy = "dev-cli"
	}
	record, err := harness.host.GrantPermission(ctx, host.GrantPermissionRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		PermissionID:     permissionID,
		GrantedBy:        grantedBy,
	})
	if err != nil {
		return err
	}
	state.Record = harness.registryStore.record()
	return saveAndWriteDevPermission(harness, state, "dev-permission-grant", record)
}

func devPermissionRevoke(ctx context.Context, stateRoot string, permissionID string, reason string) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	if strings.TrimSpace(reason) == "" {
		reason = "dev-cli"
	}
	record, err := harness.host.RevokePermission(ctx, host.RevokePermissionRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		PermissionID:     permissionID,
		RevokedBy:        "dev-cli",
		Reason:           reason,
	})
	if err != nil {
		return err
	}
	state.Record = harness.registryStore.record()
	return saveAndWriteDevPermission(harness, state, "dev-permission-revoke", record)
}

func devPermissionList(ctx context.Context, stateRoot string, activeOnly bool) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	records, err := harness.host.ListPermissionGrants(ctx, host.ListPermissionGrantsRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		ActiveOnly:       activeOnly,
	})
	if err != nil {
		return err
	}
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	state.UpdatedAt = time.Now().UTC()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeJSON(devPermissionSummary{
		OK:               true,
		Action:           "dev-permission-list",
		StateRoot:        harness.stateRoot,
		PluginInstanceID: state.Record.PluginInstanceID,
		PluginID:         state.Record.PluginID,
		Permissions:      records,
		ActiveOnly:       activeOnly,
		UpdatedAt:        state.UpdatedAt,
	})
}

func devExportData(ctx context.Context, stateRoot string, includeSecrets bool) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	result, err := harness.host.ExportPluginData(ctx, host.ExportDataRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		IncludeSecrets:   includeSecrets,
	})
	if err != nil {
		return err
	}
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	state.UpdatedAt = time.Now().UTC()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeJSON(devDataSummary{
		OK:                 true,
		Action:             "dev-export-data",
		StateRoot:          harness.stateRoot,
		PluginInstanceID:   state.Record.PluginInstanceID,
		PluginID:           state.Record.PluginID,
		ArchiveRef:         result.ArchiveRef,
		SettingsArchiveRef: result.SettingsArchiveRef,
		IncludeSecrets:     includeSecrets,
		UpdatedAt:          state.UpdatedAt,
	})
}

func devImportData(ctx context.Context, stateRoot string, archiveRef string, settingsArchiveRef string, deleteExisting bool) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	archiveRef = strings.TrimSpace(archiveRef)
	settingsArchiveRef = strings.TrimSpace(settingsArchiveRef)
	if err := harness.host.ImportPluginData(ctx, host.ImportDataRequest{
		PluginInstanceID:   state.Record.PluginInstanceID,
		ArchiveRef:         archiveRef,
		SettingsArchiveRef: settingsArchiveRef,
		DeleteExisting:     deleteExisting,
	}); err != nil {
		return err
	}
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	state.UpdatedAt = time.Now().UTC()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeJSON(devDataSummary{
		OK:                 true,
		Action:             "dev-import-data",
		StateRoot:          harness.stateRoot,
		PluginInstanceID:   state.Record.PluginInstanceID,
		PluginID:           state.Record.PluginID,
		ArchiveRef:         archiveRef,
		SettingsArchiveRef: settingsArchiveRef,
		DeleteExisting:     deleteExisting,
		Imported:           true,
		UpdatedAt:          state.UpdatedAt,
	})
}

func devStatus(stateRoot string) error {
	stateRoot, err := normalizeDevStateRoot(stateRoot)
	if err != nil {
		return err
	}
	state, err := loadDevState(stateRoot)
	if err != nil {
		return err
	}
	return writeDevLifecycle("dev-status", stateRoot, state)
}

func saveAndWriteDevSecret(harness devHarness, state devLifecycleState, action string, req host.SecretBindRequest) error {
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	state.UpdatedAt = time.Now().UTC()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeDevSecret(action, harness.stateRoot, state, devSecretRecordFor(harness.secretStore, req, state.UpdatedAt))
}

func saveAndWriteDevPermission(harness devHarness, state devLifecycleState, action string, record permissions.Record) error {
	state.Settings = harness.settingsStore.State()
	state.Secrets = harness.secretStore.State()
	state.Permissions = harness.permissionStore.State()
	state.UpdatedAt = time.Now().UTC()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeJSON(devPermissionSummary{
		OK:               true,
		Action:           action,
		StateRoot:        harness.stateRoot,
		PluginInstanceID: state.Record.PluginInstanceID,
		PluginID:         state.Record.PluginID,
		Permission:       record,
		UpdatedAt:        state.UpdatedAt,
	})
}

func writeDevLifecycle(action string, stateRoot string, state devLifecycleState) error {
	_, packageErr := os.Stat(filepath.Join(stateRoot, devPackageFile))
	return writeJSON(devLifecycleSummary{
		lifecycleSummary: lifecycleSummary{
			OK:                 true,
			Action:             action,
			PluginInstanceID:   state.Record.PluginInstanceID,
			PluginID:           state.Record.PluginID,
			Version:            state.Record.Version,
			TrustState:         state.Record.TrustState,
			EnableState:        state.Record.EnableState,
			RetainedDataState:  state.Record.RetainedDataState,
			PolicyRevision:     state.Record.PolicyRevision,
			ManagementRevision: state.Record.ManagementRevision,
			RevokeEpoch:        state.Record.RevokeEpoch,
		},
		StateRoot:       stateRoot,
		StorageRoot:     filepath.Join(stateRoot, devStorageDir),
		PackageRetained: packageErr == nil,
	})
}

func writeDevSecret(action string, stateRoot string, state devLifecycleState, secret secrets.Record) error {
	return writeJSON(devSecretSummary{
		OK:               true,
		Action:           action,
		StateRoot:        stateRoot,
		PluginInstanceID: state.Record.PluginInstanceID,
		PluginID:         state.Record.PluginID,
		SecretRef:        secret.SecretRef,
		Scope:            secret.Scope,
		Bound:            secret.Bound,
		LastTestStatus:   secret.LastTestStatus,
		UpdatedAt:        secret.UpdatedAt,
	})
}

type devHarness struct {
	stateRoot       string
	host            *host.Host
	registryStore   *devRegistryStore
	settingsStore   *settings.MemoryStore
	secretStore     *secrets.MemoryStore
	permissionStore *permissions.MemoryStore
}

func loadDevHarness(ctx context.Context, stateRoot string) (devHarness, devLifecycleState, error) {
	stateRoot, err := normalizeDevStateRoot(stateRoot)
	if err != nil {
		return devHarness{}, devLifecycleState{}, err
	}
	state, err := loadDevState(stateRoot)
	if err != nil {
		return devHarness{}, devLifecycleState{}, err
	}
	if state.Record.PluginInstanceID == "" || state.Record.DeletedAt != nil {
		return devHarness{}, devLifecycleState{}, errDevStateNotInstalled
	}
	if state.PackageFile == "" {
		return devHarness{}, devLifecycleState{}, errors.New("dev package copy is not available")
	}
	packagePath := filepath.Join(stateRoot, state.PackageFile)
	pkg, err := pluginpkg.ReadFile(ctx, packagePath, pluginpkg.DefaultReadOptions())
	if err != nil {
		return devHarness{}, devLifecycleState{}, err
	}
	assets := pluginpkg.NewMemoryAssetStore()
	if err := assets.PutPackage(ctx, pkg); err != nil {
		return devHarness{}, devLifecycleState{}, err
	}
	storageBroker, err := storage.NewFileBroker(filepath.Join(stateRoot, devStorageDir))
	if err != nil {
		return devHarness{}, devLifecycleState{}, err
	}
	settingsStore := settings.NewMemoryStoreFromState(state.Settings)
	secretStore := secrets.NewMemoryStoreFromState(state.Secrets)
	permissionStore := permissions.NewMemoryStoreFromState(state.Permissions)
	registryStore := newDevRegistryStore(state.Record)
	h, err := host.New(host.Adapters{
		SessionResolver: staticSessionResolver{},
		Policy:          staticPolicyAdapter{},
		Registry:        registryStore,
		Assets:          assets,
		Storage:         storageBroker,
		Settings:        settingsStore,
		Secrets:         secretStore,
		Permissions:     permissionStore,
	})
	if err != nil {
		return devHarness{}, devLifecycleState{}, err
	}
	return devHarness{
		stateRoot:       stateRoot,
		host:            h,
		registryStore:   registryStore,
		settingsStore:   settingsStore,
		secretStore:     secretStore,
		permissionStore: permissionStore,
	}, state, nil
}

func newDevInstallHost(stateRoot string) (*host.Host, error) {
	storageBroker, err := storage.NewFileBroker(filepath.Join(stateRoot, devStorageDir))
	if err != nil {
		return nil, err
	}
	h, err := host.New(host.Adapters{
		SessionResolver: staticSessionResolver{},
		Policy:          staticPolicyAdapter{},
		Storage:         storageBroker,
		Settings:        settings.NewMemoryStore(),
		Secrets:         secrets.NewMemoryStore(),
		Permissions:     permissions.NewMemoryStore(),
	})
	if err != nil {
		return nil, err
	}
	return h, nil
}

func prepareDevStateRoot(stateRoot string) (string, error) {
	normalized, err := normalizeDevStateRoot(stateRoot)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(normalized, 0o700); err != nil {
		return "", err
	}
	return normalized, nil
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

func stateExists(stateRoot string) bool {
	_, err := os.Stat(filepath.Join(stateRoot, devStateFile))
	return err == nil
}

func loadDevState(stateRoot string) (devLifecycleState, error) {
	raw, err := os.ReadFile(filepath.Join(stateRoot, devStateFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return devLifecycleState{}, errDevStateNotInstalled
		}
		return devLifecycleState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state devLifecycleState
	if err := decoder.Decode(&state); err != nil {
		return devLifecycleState{}, err
	}
	if state.SchemaVersion != devStateSchemaVersion {
		return devLifecycleState{}, fmt.Errorf("unsupported dev state schema_version %q", state.SchemaVersion)
	}
	return state, nil
}

func saveDevState(stateRoot string, state devLifecycleState) error {
	state.SchemaVersion = devStateSchemaVersion
	return writeJSONFile(filepath.Join(stateRoot, devStateFile), state, 0o600)
}

type devRegistryStore struct {
	mu           sync.Mutex
	records      map[string]registry.PluginRecord
	sourceFloors *registry.MemoryStore
}

func newDevRegistryStore(record registry.PluginRecord) *devRegistryStore {
	records := map[string]registry.PluginRecord{}
	if record.PluginInstanceID != "" {
		records[record.PluginInstanceID] = record
	}
	return &devRegistryStore{records: records, sourceFloors: registry.NewMemoryStore()}
}

func (s *devRegistryStore) PutPlugin(_ context.Context, record registry.PluginRecord, opts registry.PutOptions) (registry.PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if record.PluginInstanceID == "" {
		return registry.PluginRecord{}, errors.New("plugin_instance_id is required")
	}
	existing, exists := s.records[record.PluginInstanceID]
	if exists {
		record.InstalledAt = existing.InstalledAt
		record.PolicyRevision = existing.PolicyRevision
		record.ManagementRevision = existing.ManagementRevision + 1
		record.RevokeEpoch = existing.RevokeEpoch + 1
	} else {
		record.InstalledAt = now
		if record.PolicyRevision == 0 {
			record.PolicyRevision = 1
		}
		if record.ManagementRevision == 0 {
			record.ManagementRevision = 1
		}
	}
	if record.RetainedDataState == "" {
		record.RetainedDataState = registry.RetainedDataNone
	}
	record.UpdatedAt = now
	s.records[record.PluginInstanceID] = record
	return record, nil
}

func (s *devRegistryStore) GetPlugin(_ context.Context, pluginInstanceID string) (registry.PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	return record, nil
}

func (s *devRegistryStore) ListPlugins(_ context.Context) ([]registry.PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]registry.PluginRecord, 0, len(s.records))
	for _, record := range s.records {
		if record.DeletedAt == nil {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].PluginID == records[j].PluginID {
			return records[i].PluginInstanceID < records[j].PluginInstanceID
		}
		return records[i].PluginID < records[j].PluginID
	})
	return records, nil
}

func (s *devRegistryStore) SetEnableState(_ context.Context, pluginInstanceID string, state registry.EnableState, reason string, now time.Time) (registry.PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.EnableState = state
	record.DisabledReason = reason
	record.ManagementRevision++
	record.RevokeEpoch++
	record.UpdatedAt = now
	if state == registry.EnableEnabled {
		record.EnabledAt = &now
	} else {
		record.EnabledAt = nil
	}
	s.records[pluginInstanceID] = record
	return record, nil
}

func (s *devRegistryStore) BumpPolicyRevision(_ context.Context, pluginInstanceID string, revoke bool, now time.Time) (registry.PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.PolicyRevision++
	if revoke {
		record.RevokeEpoch++
	}
	record.UpdatedAt = now
	s.records[pluginInstanceID] = record
	return record, nil
}

func (s *devRegistryStore) MarkUninstalled(_ context.Context, pluginInstanceID string, retained registry.RetainedDataState, now time.Time) (registry.PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return registry.PluginRecord{}, registry.ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.EnableState = registry.EnableDisabled
	record.DisabledReason = "uninstalled"
	record.RetainedDataState = retained
	record.ManagementRevision++
	record.RevokeEpoch++
	record.UpdatedAt = now
	record.DeletedAt = &now
	record.EnabledAt = nil
	s.records[pluginInstanceID] = record
	return record, nil
}

func (s *devRegistryStore) DeletePlugin(_ context.Context, pluginInstanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[pluginInstanceID]; !ok {
		return registry.ErrNotFound
	}
	delete(s.records, pluginInstanceID)
	return nil
}

func (s *devRegistryStore) PutSourceSecurityFloor(ctx context.Context, floor registry.SourceSecurityFloor, opts registry.PutOptions) (registry.SourceSecurityFloor, error) {
	return s.sourceFloors.PutSourceSecurityFloor(ctx, floor, opts)
}

func (s *devRegistryStore) GetSourceSecurityFloor(ctx context.Context, sourceID string) (registry.SourceSecurityFloor, error) {
	return s.sourceFloors.GetSourceSecurityFloor(ctx, sourceID)
}

func (s *devRegistryStore) record() registry.PluginRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		return record
	}
	return registry.PluginRecord{}
}

func devSecretRecordFor(store *secrets.MemoryStore, req host.SecretBindRequest, fallback time.Time) secrets.Record {
	normalized, err := normalizeDevSecretRequest(req)
	if err != nil {
		return secrets.Record{UpdatedAt: fallback}
	}
	records, err := store.List(context.Background(), secrets.ListRequest{
		PluginInstanceID: normalized.PluginInstanceID,
		Scope:            normalized.Scope,
	})
	if err != nil {
		return secrets.Record{UpdatedAt: fallback}
	}
	for _, record := range records {
		if record.SecretRef == normalized.SecretRef {
			return record
		}
	}
	return secrets.Record{
		PluginInstanceID: normalized.PluginInstanceID,
		SecretRef:        normalized.SecretRef,
		Scope:            normalized.Scope,
		UpdatedAt:        fallback,
	}
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

var _ registry.Store = (*devRegistryStore)(nil)
var _ host.SecretStoreAdapter = (*secrets.MemoryStore)(nil)
