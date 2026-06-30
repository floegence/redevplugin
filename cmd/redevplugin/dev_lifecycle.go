package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/browsersite"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/storage"
)

const (
	devStateSchemaVersion = "redevplugin.dev_state.v1"
	devStateFile          = "redevplugin-dev-state.json"
	devPackageFile        = "installed.redeven-plugin"
	devStorageDir         = "storage"
	devDefaultSandbox     = "http://127.0.0.1:4174"
)

var errDevStateNotInstalled = errors.New("dev plugin is not installed")

type devLifecycleState struct {
	SchemaVersion  string                     `json:"schema_version"`
	PackageFile    string                     `json:"package_file,omitempty"`
	Record         registry.PluginRecord      `json:"record"`
	BrowserOrigins []browsersite.OriginRecord `json:"browser_origins,omitempty"`
	UpdatedAt      time.Time                  `json:"updated_at"`
}

type devLifecycleSummary struct {
	lifecycleSummary
	StateRoot          string `json:"state_root"`
	StorageRoot        string `json:"storage_root"`
	BrowserOriginCount int    `json:"browser_origin_count"`
	PackageRetained    bool   `json:"package_retained"`
}

type devOpenSurfaceSummary struct {
	OK                 bool      `json:"ok"`
	Action             string    `json:"action"`
	StateRoot          string    `json:"state_root"`
	PluginInstanceID   string    `json:"plugin_instance_id"`
	PluginID           string    `json:"plugin_id"`
	Version            string    `json:"version"`
	SurfaceID          string    `json:"surface_id"`
	SurfaceInstanceID  string    `json:"surface_instance_id"`
	ActiveFingerprint  string    `json:"active_fingerprint"`
	BridgeNonce        string    `json:"bridge_nonce"`
	AssetTicketID      string    `json:"asset_ticket_id"`
	SandboxOrigin      string    `json:"sandbox_origin"`
	BrowserOriginCount int       `json:"browser_origin_count"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
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
	h, _, err := newDevInstallHost(stateRoot)
	if err != nil {
		return err
	}
	record, err := h.InstallPackage(ctx, host.InstallRequest{
		PackageReader: bytes.NewReader(data),
		PackageSize:   int64(len(data)),
		TrustState:    registry.TrustUnsignedLocal,
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
	record, err := harness.host.EnablePlugin(ctx, host.EnableRequest{PluginInstanceID: state.Record.PluginInstanceID})
	if err != nil {
		return err
	}
	state.Record = record
	state.UpdatedAt = time.Now().UTC()
	state.BrowserOrigins = harness.browserSite.recordsList()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeDevLifecycle("dev-enable", harness.stateRoot, state)
}

func devOpen(ctx context.Context, stateRoot string, surfaceID string, sandboxOrigin string) error {
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
	sandboxOrigin = strings.TrimRight(strings.TrimSpace(sandboxOrigin), "/")
	if sandboxOrigin == "" {
		sandboxOrigin = devDefaultSandbox
	}
	if err := validateDevOrigin(sandboxOrigin); err != nil {
		return err
	}
	bootstrap, err := harness.host.OpenSurface(ctx, host.OpenSurfaceRequest{
		PluginInstanceID:     state.Record.PluginInstanceID,
		SurfaceID:            surfaceID,
		OwnerSessionHash:     "dev_owner_session",
		OwnerUserHash:        "dev_owner_user",
		SessionChannelIDHash: "dev_session_channel",
		SandboxOrigin:        sandboxOrigin,
	})
	if err != nil {
		return err
	}
	state.BrowserOrigins = harness.browserSite.recordsList()
	state.UpdatedAt = time.Now().UTC()
	if err := saveDevState(harness.stateRoot, state); err != nil {
		return err
	}
	return writeJSON(devOpenSurfaceSummary{
		OK:                 true,
		Action:             "dev-open",
		StateRoot:          harness.stateRoot,
		PluginInstanceID:   state.Record.PluginInstanceID,
		PluginID:           state.Record.PluginID,
		Version:            state.Record.Version,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetTicketID:      bootstrap.AssetTicketID,
		SandboxOrigin:      sandboxOrigin,
		BrowserOriginCount: len(state.BrowserOrigins),
		IssuedAt:           bootstrap.IssuedAt,
		ExpiresAt:          bootstrap.ExpiresAt,
	})
}

func devDisable(ctx context.Context, stateRoot string) error {
	harness, state, err := loadDevHarness(ctx, stateRoot)
	if err != nil {
		return err
	}
	record, err := harness.host.DisablePlugin(ctx, host.DisableRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		Reason:           "dev-cli",
	})
	if err != nil {
		return err
	}
	state.Record = record
	state.BrowserOrigins = harness.browserSite.recordsList()
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
	record, err := harness.host.UninstallPlugin(ctx, host.UninstallRequest{
		PluginInstanceID: state.Record.PluginInstanceID,
		DeleteData:       deleteData,
	})
	if err != nil {
		return err
	}
	state.Record = record
	state.BrowserOrigins = harness.browserSite.recordsList()
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
		StateRoot:          stateRoot,
		StorageRoot:        filepath.Join(stateRoot, devStorageDir),
		BrowserOriginCount: len(state.BrowserOrigins),
		PackageRetained:    packageErr == nil,
	})
}

type devHarness struct {
	stateRoot   string
	host        *host.Host
	browserSite *devBrowserSiteStore
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
	browserSite := newDevBrowserSiteStore(state.BrowserOrigins)
	h, err := host.New(host.Adapters{
		SessionResolver: staticSessionResolver{},
		Policy:          staticPolicyAdapter{},
		Registry:        newDevRegistryStore(state.Record),
		Assets:          assets,
		Storage:         storageBroker,
		BrowserSite:     browserSite,
	})
	if err != nil {
		return devHarness{}, devLifecycleState{}, err
	}
	return devHarness{stateRoot: stateRoot, host: h, browserSite: browserSite}, state, nil
}

func newDevInstallHost(stateRoot string) (*host.Host, *devBrowserSiteStore, error) {
	storageBroker, err := storage.NewFileBroker(filepath.Join(stateRoot, devStorageDir))
	if err != nil {
		return nil, nil, err
	}
	browserSite := newDevBrowserSiteStore(nil)
	h, err := host.New(host.Adapters{
		SessionResolver: staticSessionResolver{},
		Policy:          staticPolicyAdapter{},
		Storage:         storageBroker,
		BrowserSite:     browserSite,
	})
	if err != nil {
		return nil, nil, err
	}
	return h, browserSite, nil
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
	state.BrowserOrigins = cloneDevBrowserOrigins(state.BrowserOrigins)
	sort.Slice(state.BrowserOrigins, func(i, j int) bool {
		return state.BrowserOrigins[i].OriginKey < state.BrowserOrigins[j].OriginKey
	})
	return writeJSONFile(filepath.Join(stateRoot, devStateFile), state, 0o600)
}

func validateDevOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("sandbox origin must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("sandbox origin must be an origin without credentials, path, query, or fragment")
	}
	return nil
}

type devRegistryStore struct {
	mu      sync.Mutex
	records map[string]registry.PluginRecord
}

func newDevRegistryStore(record registry.PluginRecord) *devRegistryStore {
	records := map[string]registry.PluginRecord{}
	if record.PluginInstanceID != "" {
		records[record.PluginInstanceID] = record
	}
	return &devRegistryStore{records: records}
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

type devBrowserSiteStore struct {
	mu      sync.Mutex
	records map[string]browsersite.OriginRecord
}

func newDevBrowserSiteStore(records []browsersite.OriginRecord) *devBrowserSiteStore {
	store := &devBrowserSiteStore{records: map[string]browsersite.OriginRecord{}}
	for _, record := range records {
		if record.OriginKey == "" {
			record.OriginKey = devBrowserOriginKey(record.PluginInstanceID, record.ActiveFingerprint, record.OwnerSessionHash, record.Origin)
		}
		store.records[record.OriginKey] = record
	}
	return store
}

func (s *devBrowserSiteStore) RegisterOrigin(_ context.Context, req browsersite.RegisterRequest) (browsersite.OriginRecord, error) {
	if s == nil {
		return browsersite.OriginRecord{}, errors.New("browser site store is nil")
	}
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	req.PluginID = strings.TrimSpace(req.PluginID)
	req.ActiveFingerprint = strings.TrimSpace(req.ActiveFingerprint)
	req.SurfaceID = strings.TrimSpace(req.SurfaceID)
	req.SurfaceInstanceID = strings.TrimSpace(req.SurfaceInstanceID)
	req.OwnerSessionHash = strings.TrimSpace(req.OwnerSessionHash)
	req.OwnerUserHash = strings.TrimSpace(req.OwnerUserHash)
	req.Origin = strings.TrimRight(strings.TrimSpace(req.Origin), "/")
	if req.PluginInstanceID == "" || req.ActiveFingerprint == "" || req.Origin == "" {
		return browsersite.OriginRecord{}, fmt.Errorf("%w: plugin_instance_id, active_fingerprint, and origin are required", browsersite.ErrInvalidOrigin)
	}
	if err := validateDevOrigin(req.Origin); err != nil {
		return browsersite.OriginRecord{}, fmt.Errorf("%w: %v", browsersite.ErrInvalidOrigin, err)
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	key := devBrowserOriginKey(req.PluginInstanceID, req.ActiveFingerprint, req.OwnerSessionHash, req.Origin)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[key]; ok {
		existing.PluginID = req.PluginID
		existing.SurfaceID = req.SurfaceID
		existing.SurfaceInstanceID = req.SurfaceInstanceID
		existing.OwnerUserHash = req.OwnerUserHash
		existing.State = browsersite.StateActive
		existing.CleanupReason = ""
		existing.CleanupError = ""
		existing.UpdatedAt = now
		existing.LastSeenAt = now
		existing.CleanupRequestedAt = nil
		existing.CleanedAt = nil
		existing.RetainedAt = nil
		s.records[key] = existing
		return cloneDevBrowserOrigin(existing), nil
	}
	record := browsersite.OriginRecord{
		OriginKey:         key,
		PluginInstanceID:  req.PluginInstanceID,
		PluginID:          req.PluginID,
		ActiveFingerprint: req.ActiveFingerprint,
		SurfaceID:         req.SurfaceID,
		SurfaceInstanceID: req.SurfaceInstanceID,
		Origin:            req.Origin,
		OwnerSessionHash:  req.OwnerSessionHash,
		OwnerUserHash:     req.OwnerUserHash,
		State:             browsersite.StateActive,
		CreatedAt:         now,
		UpdatedAt:         now,
		LastSeenAt:        now,
	}
	s.records[key] = record
	return cloneDevBrowserOrigin(record), nil
}

func (s *devBrowserSiteStore) CleanupPluginOrigins(_ context.Context, req browsersite.CleanupRequest) (browsersite.CleanupResult, error) {
	if s == nil {
		return browsersite.CleanupResult{}, errors.New("browser site store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return browsersite.CleanupResult{}, fmt.Errorf("%w: plugin_instance_id is required", browsersite.ErrInvalidOrigin)
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		if req.DeleteData {
			reason = "delete_data"
		} else {
			reason = "retain_data"
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]browsersite.OriginRecord, 0)
	for key, record := range s.records {
		if record.PluginInstanceID != pluginInstanceID {
			continue
		}
		record.UpdatedAt = now
		record.CleanupReason = reason
		record.CleanupError = ""
		if req.DeleteData {
			record.State = browsersite.StateCleanupComplete
			record.CleanupRequestedAt = &now
			record.CleanedAt = &now
			record.RetainedAt = nil
		} else {
			record.State = browsersite.StateRetained
			record.CleanupRequestedAt = nil
			record.CleanedAt = nil
			record.RetainedAt = &now
		}
		s.records[key] = record
		records = append(records, cloneDevBrowserOrigin(record))
	}
	sortDevBrowserOrigins(records)
	return browsersite.CleanupResult{Records: records}, nil
}

func (s *devBrowserSiteStore) ListOrigins(_ context.Context, req browsersite.ListRequest) ([]browsersite.OriginRecord, error) {
	if s == nil {
		return nil, errors.New("browser site store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	state := browsersite.OriginState(strings.TrimSpace(req.State))
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]browsersite.OriginRecord, 0, len(s.records))
	for _, record := range s.records {
		if pluginInstanceID != "" && record.PluginInstanceID != pluginInstanceID {
			continue
		}
		if state != "" && record.State != state {
			continue
		}
		records = append(records, cloneDevBrowserOrigin(record))
	}
	sortDevBrowserOrigins(records)
	return records, nil
}

func (s *devBrowserSiteStore) recordsList() []browsersite.OriginRecord {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records := make([]browsersite.OriginRecord, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneDevBrowserOrigin(record))
	}
	sortDevBrowserOrigins(records)
	return records
}

func devBrowserOriginKey(pluginInstanceID string, activeFingerprint string, ownerSessionHash string, origin string) string {
	return pluginInstanceID + "\x00" + activeFingerprint + "\x00" + ownerSessionHash + "\x00" + origin
}

func cloneDevBrowserOrigins(records []browsersite.OriginRecord) []browsersite.OriginRecord {
	cloned := make([]browsersite.OriginRecord, len(records))
	for i, record := range records {
		cloned[i] = cloneDevBrowserOrigin(record)
	}
	return cloned
}

func cloneDevBrowserOrigin(record browsersite.OriginRecord) browsersite.OriginRecord {
	if record.CleanupRequestedAt != nil {
		value := *record.CleanupRequestedAt
		record.CleanupRequestedAt = &value
	}
	if record.CleanedAt != nil {
		value := *record.CleanedAt
		record.CleanedAt = &value
	}
	if record.RetainedAt != nil {
		value := *record.RetainedAt
		record.RetainedAt = &value
	}
	return record
}

func sortDevBrowserOrigins(records []browsersite.OriginRecord) {
	sort.Slice(records, func(i, j int) bool {
		return records[i].OriginKey < records[j].OriginKey
	})
}

var _ registry.Store = (*devRegistryStore)(nil)
var _ browsersite.Store = (*devBrowserSiteStore)(nil)
