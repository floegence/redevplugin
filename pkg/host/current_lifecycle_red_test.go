package host

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestInstallCommitInitializesPluginDataWithoutEnableCall(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := importCurrentLifecyclePackage(t, h, lifecycleManifestJSON("1.0.0", "Install Commit"))

	binding, found, err := h.controlStore.GetBinding(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || binding.State != plugindata.BindingActive {
		t.Fatalf("install binding = %#v, found=%v; want active binding", binding, found)
	}
	if installed.EnableState != registry.EnableEnabled {
		t.Fatalf("install state = %q, want enabled", installed.EnableState)
	}
}

func TestInstallCommitInitializesDefaultSettingsWithoutEnableCall(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := importCurrentLifecyclePackage(t, h, currentSettingsManifestJSON())

	settings, err := h.GetPluginSettings(hostTestContext(), GetSettingsRequest{
		PluginInstanceID: installed.PluginInstanceID,
		Scope:            sessionctx.ScopeUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	if settings.Values["default_engine"] != "docker" || settings.Values["show_stopped"] != true {
		t.Fatalf("default settings = %#v, want docker/true", settings.Values)
	}
}

func TestInstallCommitPublishesSurfaceWithoutEnableCall(t *testing.T) {
	h, surfaces, _ := newTestHost(t, true, true)
	installed := importCurrentLifecyclePackage(t, h, lifecycleManifestJSON("1.0.0", "Surface"))

	if len(surfaces.snapshots) != 1 || len(surfaces.snapshots[0].Surfaces) != 1 || surfaces.snapshots[0].PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("surface snapshots = %#v, want one installed snapshot", surfaces.snapshots)
	}
}

func TestInstallCommitInstallsConnectivityWithoutEnableCall(t *testing.T) {
	base := connectivity.NewMemoryBroker()
	broker := &installRecordingConnectivityBroker{Broker: base}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, connectivityBroker: broker,
	})
	importCurrentLifecyclePackage(t, h, currentNetworkManifestJSON())
	if broker.installs != 1 {
		t.Fatalf("connectivity policy installs = %d, want one during InstallCommit", broker.installs)
	}
}

func TestInstallCommitAdvancesManagementRevisionOnce(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := importCurrentLifecyclePackage(t, h, lifecycleManifestJSON("1.0.0", "Revision"))
	if installed.ManagementRevision != 1 {
		t.Fatalf("install management revision = %d, want one lifecycle commit", installed.ManagementRevision)
	}
	latest, err := h.getPluginRecord(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ManagementRevision != installed.ManagementRevision {
		t.Fatalf("persisted management revision = %d, returned=%d", latest.ManagementRevision, installed.ManagementRevision)
	}
}

func TestInstallCommitDefaultSettingsFailureLeavesNoRecordBindingOrAsset(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	settingsErr := errors.New("default settings initialization failed")
	h.adapters.PluginData = &failingInstallCommitPluginData{PluginData: h.adapters.PluginData, err: settingsErr}
	packageBytes := buildFixturePackage(t)
	pkg := readTestPackage(t, packageBytes)
	pluginInstanceID := nextTestPluginInstanceID(t)

	if _, err := ImportLocalPackageBytes(hostTestContext(), h, pluginInstanceID, packageBytes); !errors.Is(err, settingsErr) {
		t.Fatalf("ImportLocalPackageBytes() error = %v, want %v", err, settingsErr)
	}
	if _, err := h.getPluginRecord(hostTestContext(), pluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("plugin record after failed install error = %v, want not found", err)
	}
	if _, found, err := h.controlStore.GetBinding(hostTestContext(), pluginInstanceID); err != nil || found {
		t.Fatalf("binding after failed install: found=%v err=%v", found, err)
	}
	if _, err := h.adapters.Assets.ReadPackageMetadata(hostTestContext(), pkg.PackageHash); err == nil {
		t.Fatal("failed install retained package assets")
	}
}

func TestInstallDerivedSurfaceFailureIsCommittedAndRetryDoesNotAdvanceRevision(t *testing.T) {
	surfaceErr := errors.New("surface catalog unavailable")
	surfaces := &failingSurfaceSink{err: surfaceErr}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, surfaceCatalog: surfaces,
	})
	pluginInstanceID := nextTestPluginInstanceID(t)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, pluginInstanceID, buildFixturePackage(t))
	if !errors.Is(err, surfaceErr) || mutation.ForError(err) != mutation.OutcomeCommitted {
		t.Fatalf("install error = %v outcome=%q, want committed surface failure", err, mutation.ForError(err))
	}
	if installed.EnableState != registry.EnableEnabled || installed.ManagementRevision != 1 {
		t.Fatalf("committed install = %#v", installed)
	}
	surfaces.err = nil
	recovery, err := h.RetryPluginRecovery(hostTestContext(), pluginInstanceID)
	if err != nil || recovery.Status != PluginRecoveryReady {
		t.Fatalf("RetryPluginRecovery() = %#v, err=%v", recovery, err)
	}
	latest, err := h.getPluginRecord(hostTestContext(), pluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ManagementRevision != installed.ManagementRevision || latest.EnableState != registry.EnableEnabled {
		t.Fatalf("retry changed lifecycle: before=%#v after=%#v", installed, latest)
	}
}

func TestInstallDerivedConnectivityFailureIsCommittedAndRetryDoesNotAdvanceRevision(t *testing.T) {
	connectivityErr := errors.New("connectivity unavailable")
	broker := &installRecordingConnectivityBroker{Broker: connectivity.NewMemoryBroker(), installErr: connectivityErr}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, connectivityBroker: broker,
	})
	pluginInstanceID := nextTestPluginInstanceID(t)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, pluginInstanceID, buildCurrentLifecyclePackage(t, currentNetworkManifestJSON()))
	if !errors.Is(err, connectivityErr) || mutation.ForError(err) != mutation.OutcomeCommitted {
		t.Fatalf("install error = %v outcome=%q, want committed connectivity failure", err, mutation.ForError(err))
	}
	broker.installErr = nil
	recovery, err := h.RetryPluginRecovery(hostTestContext(), pluginInstanceID)
	if err != nil || recovery.Status != PluginRecoveryReady {
		t.Fatalf("RetryPluginRecovery() = %#v, err=%v", recovery, err)
	}
	latest, err := h.getPluginRecord(hostTestContext(), pluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ManagementRevision != installed.ManagementRevision || latest.EnableState != registry.EnableEnabled {
		t.Fatalf("retry changed lifecycle: before=%#v after=%#v", installed, latest)
	}
}

func TestOpenSurfaceMissingGrantReturnsPermissionRequiredAndKeepsEnabled(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildV9IOPermissionFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		SurfaceID:                  "io.view",
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("OpenSurface() error = %v, want permission denied", err)
	}
	latest, getErr := h.getPluginRecord(hostTestContext(), installed.PluginInstanceID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if latest.EnableState != registry.EnableEnabled {
		t.Fatalf("OpenSurface() changed enable state to %q", latest.EnableState)
	}
}

func TestPolicyFailureKeepsEnabledAndRevokesExistingSurface(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := importCurrentLifecyclePackage(t, h, lifecycleManifestJSON("1.0.0", "Policy"))
	opened, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		SurfaceID:                  "lifecycle.view",
		SurfaceInstanceID:          "surface_before_policy",
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.Policy = policyAdapter{developerMode: false, localGenerated: false}
	if _, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		SurfaceID:                  "lifecycle.view",
		SurfaceInstanceID:          "surface_after_policy",
		ExpectedManagementRevision: installed.ManagementRevision,
	}); !errors.Is(err, security.ErrPolicyDenied) {
		t.Fatalf("OpenSurface() policy error = %v, want policy denied", err)
	}
	latest, err := h.getPluginRecord(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.EnableState != registry.EnableEnabled {
		t.Fatalf("policy failure changed enable state to %q", latest.EnableState)
	}
	if _, err := h.PrepareSurface(hostTestContext(), PrepareSurfaceRequest{
		SurfaceInstanceID: opened.SurfaceInstanceID,
		AssetTicket:       opened.AssetTicket,
	}); err == nil {
		t.Fatal("PrepareSurface() reused a surface ticket after policy revocation")
	}
}

func TestOnlyExplicitDisableProducesDisabledByUser(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := importCurrentLifecyclePackage(t, h, lifecycleManifestJSON("1.0.0", "Disable"))
	if installed.EnableState != registry.EnableEnabled {
		t.Fatalf("initial enable state = %q", installed.EnableState)
	}
	disabled, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		Reason:                     "explicit test disable",
	})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.EnableState != registry.EnableDisabledByUser {
		t.Fatalf("explicit disable state = %q, want disabled_by_user", disabled.EnableState)
	}
}

func TestExplicitReenablePreservesPluginDataBinding(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := importCurrentLifecyclePackage(t, h, lifecycleManifestJSON("1.0.0", "Re-enable"))
	originalBinding, found, err := h.controlStore.GetBinding(hostTestContext(), installed.PluginInstanceID)
	if err != nil || !found {
		t.Fatalf("installed binding = %#v, found=%v err=%v", originalBinding, found, err)
	}
	disabled, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		Reason:                     "explicit re-enable test",
	})
	if err != nil {
		t.Fatal(err)
	}
	reenabled, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           disabled.PluginInstanceID,
		ExpectedManagementRevision: disabled.ManagementRevision,
	})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if reenabled.EnableState != registry.EnableEnabled || reenabled.ManagementRevision != disabled.ManagementRevision+1 {
		t.Fatalf("re-enabled plugin = %#v", reenabled)
	}
	currentBinding, found, err := h.controlStore.GetBinding(hostTestContext(), installed.PluginInstanceID)
	if err != nil || !found || currentBinding != originalBinding {
		t.Fatalf("re-enable changed binding: before=%#v after=%#v found=%v err=%v", originalBinding, currentBinding, found, err)
	}
}

type installRecordingConnectivityBroker struct {
	connectivity.Broker
	installs   int
	installErr error
}

type failingInstallCommitPluginData struct {
	PluginData
	err error
}

func (p *failingInstallCommitPluginData) InstallCommit(context.Context, plugindata.InstallCommitRequest, plugindata.InstallCatalogCommit) (plugindata.Dataset, error) {
	return plugindata.Dataset{}, p.err
}

func (b *installRecordingConnectivityBroker) InstallPolicy(ctx context.Context, policy connectivity.PolicySet) error {
	b.installs++
	if b.installErr != nil {
		return b.installErr
	}
	return b.Broker.InstallPolicy(ctx, policy)
}

func importCurrentLifecyclePackage(t *testing.T, h *Host, manifestJSON string) registry.PluginRecord {
	t.Helper()
	packageBytes := buildCurrentLifecyclePackage(t, manifestJSON)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	return installed
}

func buildCurrentLifecyclePackage(t *testing.T, manifestJSON string) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Current")
	var packageBytes bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &packageBytes, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return packageBytes.Bytes()
}

func currentSettingsManifestJSON() string {
	manifest := lifecycleManifestJSON("1.0.0", "Settings")
	return strings.Replace(manifest, `		"workers": [],`, `		"settings": {"schema_version": 1, "fields": [{"key": "default_engine", "type": "select", "scope": "user", "label": "Default engine", "default": "docker", "options": [{"value": "docker", "label": "Docker"}]}, {"key": "show_stopped", "type": "boolean", "scope": "user", "label": "Show stopped", "default": true}]},
		"workers": [],`, 1)
}

func currentNetworkManifestJSON() string {
	manifest := lifecycleManifestJSON("1.0.0", "Network")
	manifest = strings.Replace(manifest, `"permissions": [],`, `"permissions": ["network.client"],`, 1)
	manifest = strings.Replace(manifest, `"api": {"major": 1, "required_features": [], "optional_features": []},`, `"api": {"major": 1, "required_features": ["net.http.v1"], "optional_features": []},`, 1)
	return strings.Replace(manifest, `		"workers": [],`, `		"network_access": {"connectors": [{"connector_id": "api", "transport": "http", "scope": "user", "destinations": ["https://api.example.com"]}]},
		"workers": [],`, 1)
}
