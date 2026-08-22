package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/secrets"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func TestConfigExposesOnlyHostStateAndModules(t *testing.T) {
	configType := reflect.TypeOf(Config{})
	want := []string{
		"StateRoot",
		"Core",
		"Release",
		"Runtime",
		"Capability",
		"IO",
		"Connectivity",
		"Secrets",
		"CoreAction",
		"ExternalPackage",
	}
	if configType.NumField() != len(want) {
		t.Fatalf("Config has %d fields, want %d state and module fields", configType.NumField(), len(want))
	}
	for index, name := range want {
		if field := configType.Field(index); field.Name != name {
			t.Fatalf("Config field %d = %q, want %q", index, field.Name, name)
		}
	}
}

func TestCoreAdaptersDoNotExposePersistenceStores(t *testing.T) {
	typeOfCore := reflect.TypeOf(CoreAdapters{})
	for _, forbidden := range []string{
		"Registry",
		"InstallStages",
		"SurfaceTokens",
		"Operations",
		"ConfirmationIntents",
		"Streams",
		"SessionScopes",
	} {
		if _, ok := typeOfCore.FieldByName(forbidden); ok {
			t.Fatalf("CoreAdapters still exposes %s", forbidden)
		}
	}
}

func TestExternalPackageModuleKeepsInspectionStoragePrivateToHost(t *testing.T) {
	typeOfModule := reflect.TypeOf(ExternalPackageModule{})
	for _, forbidden := range []string{"StageStore", "PackageFetcher", "GitHubResolver"} {
		if _, ok := typeOfModule.FieldByName(forbidden); ok {
			t.Fatalf("ExternalPackageModule still exposes %s", forbidden)
		}
	}
}

func TestOpenOwnsInternalPlatformState(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "control-state")
	base := modularTestConfig(t)
	base.StateRoot = stateRoot
	base.Core = CoreAdapters{
		Policy:               base.Core.Policy,
		Authorization:        base.Core.Authorization,
		PackageTrustVerifier: base.Core.PackageTrustVerifier,
		Audit:                base.Core.Audit,
		SecurityAudit:        base.Core.SecurityAudit,
		Diagnostics:          base.Core.Diagnostics,
		SurfaceCatalog:       base.Core.SurfaceCatalog,
		Assets:               pluginpkg.NewMemoryAssetStore(),
	}

	h, err := Open(context.Background(), base)
	if err != nil {
		t.Fatalf("Open() without injected platform state owners: %v", err)
	}
	if h.surfaceTokens == nil || h.adapters.ConfirmationIntents == nil || h.sessionScopes == nil {
		t.Fatal("Open() did not construct every internal platform state owner")
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	base.Core.Assets = pluginpkg.NewMemoryAssetStore()
	reopened, err := Open(context.Background(), base)
	if err != nil {
		t.Fatalf("Open() after Host-owned stores were closed: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("reopened Close() error = %v", err)
	}
}

func TestOpenConfigRequiresCompleteCoreAdapters(t *testing.T) {
	_, err := Open(context.Background(), Config{Core: CoreAdapters{}})
	if err == nil {
		t.Fatal("Open() accepted an incomplete core adapter set")
	}
	if errors.Is(err, ErrFeatureNotConfigured) {
		t.Fatalf("core validation returned optional feature error: %v", err)
	}
	var configErr *HostConfigError
	if !errors.As(err, &configErr) || !errors.Is(err, ErrHostConfig) {
		t.Fatalf("Open() error = %v, want HostConfigError", err)
	}
}

func TestOpenConfigRejectsTypedNilAdapters(t *testing.T) {
	t.Run("core", func(t *testing.T) {
		config := modularTestConfig(t)
		var policy *policyAdapter
		config.Core.Policy = policy

		_, err := Open(context.Background(), config)
		var configErr *HostConfigError
		if !errors.As(err, &configErr) || !errors.Is(err, ErrHostConfig) {
			t.Fatalf("Open() error = %v, want HostConfigError", err)
		}
		if configErr.Module != "core" || configErr.Adapter != "policy" {
			t.Fatalf("HostConfigError = %#v", configErr)
		}
	})

	t.Run("optional module", func(t *testing.T) {
		config := modularTestConfig(t)
		var store *recordingSecretStore
		config.Secrets = &SecretsModule{Store: store}

		_, err := Open(context.Background(), config)
		var configErr *HostConfigError
		if !errors.As(err, &configErr) || !errors.Is(err, ErrHostConfig) || !errors.Is(err, ErrSecretsModuleRequired) {
			t.Fatalf("Open() error = %v, want HostConfigError and ErrSecretsModuleRequired", err)
		}
		if configErr.Module != string(FeatureSecrets) || configErr.Adapter != "store" {
			t.Fatalf("HostConfigError = %#v", configErr)
		}
	})

	t.Run("optional core adapter", func(t *testing.T) {
		config := modularTestConfig(t)
		var catalog *surfaceSink
		config.Core.SurfaceCatalog = catalog

		_, err := Open(context.Background(), config)
		var configErr *HostConfigError
		if !errors.As(err, &configErr) || !errors.Is(err, ErrHostConfig) {
			t.Fatalf("Open() error = %v, want HostConfigError", err)
		}
		if configErr.Module != "core" || configErr.Adapter != "surface catalog sink" {
			t.Fatalf("HostConfigError = %#v", configErr)
		}
	})

}

func TestOpenConfigRejectsIncompleteDeclaredModules(t *testing.T) {
	config := modularTestConfig(t)
	config.Runtime = &RuntimeModule{}
	_, err := Open(context.Background(), config)
	if err == nil {
		t.Fatal("Open() accepted incomplete runtime module")
	}
	if !errors.Is(err, ErrRuntimeModuleRequired) {
		t.Fatalf("Open() error = %v, want ErrRuntimeModuleRequired", err)
	}
}

func TestFeaturesReturnsClosedConfiguredSet(t *testing.T) {
	config := modularTestConfig(t)
	config.Runtime = &RuntimeModule{manager: newRecordingRuntimeManager()}
	config.Secrets = &SecretsModule{Store: secrets.NewMemoryStore()}
	h, err := Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	want := []Feature{FeatureRuntime, FeatureSecrets}
	got := h.configuredFeatures()
	if len(got) != len(want) {
		t.Fatalf("configuredFeatures() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("configuredFeatures() = %#v, want %#v", got, want)
		}
	}
}

func TestInstallPreflightReportsEveryMissingManifestFeatureBeforeSideEffects(t *testing.T) {
	h, assets := newModulePreflightTestHost(t)
	pkg := readTestPackage(t, buildV9IOPermissionFixturePackage(t))
	pkg.Manifest.CapabilityBindings = []manifest.CapabilityBinding{{Contract: capabilitycontract.Pin{ContractID: "test"}}}
	pkg.Manifest.Methods = append(pkg.Manifest.Methods, manifest.MethodSpec{Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCoreAction}})
	pkg.Manifest.Settings = &manifest.SettingsSpec{Fields: []manifest.SettingFieldSpec{{Type: "secret", SecretRef: "token"}}}
	disableModuleFeatures(h, FeatureRuntime, FeatureCapability, FeatureConnectivity, FeatureSecrets, FeatureCoreAction)

	_, err := h.installResolvedPackage(hostTestContext(), pkg, "plugini_module_preflight", packageTrustInput{LocalImport: true}, time.Time{}, nil)
	assertMissingFeatures(t, err, FeatureRuntime, FeatureCapability, FeatureConnectivity, FeatureSecrets, FeatureCoreAction)
	assertModulePreflightHasNoWrites(t, h, assets, 0)
}

func TestLocalInstallPreflightRejectsMissingConnectivityBeforeSideEffects(t *testing.T) {
	h, assets := newModulePreflightTestHost(t)
	disableModuleFeatures(h, FeatureConnectivity)

	_, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildV9IOPermissionFixturePackage(t))
	assertMissingFeatures(t, err, FeatureConnectivity)
	assertModulePreflightHasNoWrites(t, h, assets, 0)
}

func TestUpdatePreflightRejectsMissingConnectivityBeforeSideEffects(t *testing.T) {
	h, assets := newModulePreflightTestHost(t)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	assets.resetWrites()
	disableModuleFeatures(h, FeatureConnectivity)
	data := buildNetworkFixturePackage(t)

	_, err = h.UpdateLocalPackage(hostTestContext(), UpdateLocalPackageRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		PackageReader:              bytes.NewReader(data),
		PackageSize:                int64(len(data)),
	})
	assertMissingFeatures(t, err, FeatureConnectivity)
	assertModulePreflightHasNoWrites(t, h, assets, 1)
}

func TestDowngradePreflightRejectsMissingConnectivityBeforeRegistryMutation(t *testing.T) {
	h, assets := newModulePreflightTestHost(t)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	networkPackage := readTestPackage(t, buildNetworkFixturePackage(t))
	historic := installed
	historic.Version = "0.9.0"
	historic.Manifest.Plugin.Version = historic.Version
	historic.Manifest.NetworkAccess = networkPackage.Manifest.NetworkAccess
	canonicalManifest, err := manifest.MarshalCanonical(historic.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(canonicalManifest)
	historic.CanonicalManifest = string(canonicalManifest)
	historic.ManifestHash = "sha256:" + hex.EncodeToString(manifestSum[:])
	historic.PackageHash = "sha256:historic-network"
	// The fixture synthesizes a historical package without passing through
	// admission, so bind every security fact to the synthetic package exactly.
	historic.TrustAssessment.VerifiedHashes.PackageSHA256 = historic.PackageHash
	historic.TrustAssessment.VerifiedHashes.ManifestSHA256 = historic.ManifestHash
	historic.TrustAssessment.VerifiedHashes.EntriesSHA256 = historic.EntriesHash
	historic.SignatureAssessment.PackageSHA256 = historic.PackageHash
	historic.SignatureAssessment.ManifestSHA256 = historic.ManifestHash
	historic.SignatureAssessment.EntriesSHA256 = historic.EntriesHash
	historic.SignatureAssessment.AssessedHashes = historic.TrustAssessment.VerifiedHashes
	historic.PackageSourceProvenance.PackageSHA256 = historic.PackageHash
	historic.ExecutionApproval.PackageSHA256 = historic.PackageHash
	historic.SecurityCapabilitySummary = registry.SecurityCapabilitySummary{}
	installed.VersionHistory = []registry.PluginVersion{versionSnapshot(historic, time.Now().UTC())}
	installed, err = h.putPluginRecord(hostTestContext(), installed, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	assets.resetWrites()
	disableModuleFeatures(h, FeatureConnectivity)

	_, err = h.DowngradePlugin(hostTestContext(), DowngradeRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		Version:                    historic.Version,
		PackageHash:                historic.PackageHash,
	})
	assertMissingFeatures(t, err, FeatureConnectivity)
	assertModulePreflightHasNoWrites(t, h, assets, 1)
}

func TestReleaseInstallPreflightRejectsMissingRuntimeBeforeRegistryMutation(t *testing.T) {
	ctx := hostTestContext()
	fixture, err := releasetrustfixture.New(buildWorkerFixturePackage(t), releasetrustfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ref := PluginReleaseRef{
		SourceID:              fixture.Identity.SourceID,
		Channel:               fixture.Identity.Channel,
		ReleaseMetadataRef:    fixture.Identity.ReleaseMetadataRef,
		ReleaseMetadataSHA256: fixture.Identity.ReleaseMetadataSHA256,
		PublisherID:           fixture.Identity.PublisherID,
		PluginID:              fixture.Identity.PluginID,
		Version:               fixture.Identity.Version,
		ExpectedHashes: PackageHashSet{
			PackageSHA256:  fixture.Package.PackageHash,
			ManifestSHA256: fixture.Package.ManifestHash,
			EntriesSHA256:  fixture.Package.EntriesHash,
		},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		releaseTrust:   fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: ResolvedPackageArtifact{
			ReleaseMetadataBytes:     fixture.MetadataBytes,
			ReleaseMetadataSignature: fixture.MetadataSignature,
			Reader:                   bytes.NewReader(fixture.PackageBytes),
			Size:                     int64(len(fixture.PackageBytes)),
			ArtifactSHA256:           fixture.ReleaseArtifactSHA256,
		}},
	})
	assets := &modulePreflightAssetStore{AssetStore: h.adapters.Assets}
	h.adapters.Assets = assets
	assets.resetWrites()
	disableModuleFeatures(h, FeatureRuntime)

	pluginInstanceID := nextTestPluginInstanceID(t)
	digests := releaseMarketDigestsForTest(t, h, ctx, pluginInstanceID, ref)
	started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID: "request_missing_runtime", PluginInstanceID: pluginInstanceID,
		ReleaseRef: ref, ReleaseIdentityDigest: "sha256:" + strings.Repeat("a", 64), ManifestSHA256: ref.ExpectedHashes.ManifestSHA256,
		ContractSetSHA256: digests.contract, SummarySHA256: digests.summary,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
	if terminal.Execution.FailureCode != string(security.ErrRuntimeUnavailable) {
		t.Fatalf("runtime preflight failure = %#v", terminal)
	}
	assertModulePreflightHasNoWrites(t, h, assets, 0)
}

type modulePreflightAssetStore struct {
	pluginpkg.AssetStore
	putPackageCalls int
}

func (s *modulePreflightAssetStore) PutOwnedPackage(ctx context.Context, pkg *pluginpkg.Package) error {
	s.putPackageCalls++
	return s.AssetStore.PutOwnedPackage(ctx, pkg)
}

func (s *modulePreflightAssetStore) resetWrites() {
	s.putPackageCalls = 0
}

func newModulePreflightTestHost(t *testing.T) (*Host, *modulePreflightAssetStore) {
	t.Helper()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	assets := &modulePreflightAssetStore{AssetStore: h.adapters.Assets}
	h.adapters.Assets = assets
	return h, assets
}

func disableModuleFeatures(h *Host, features ...Feature) {
	for _, feature := range features {
		delete(h.features, feature)
		switch feature {
		case FeatureRelease:
			h.adapters.ReleaseTrust = nil
			h.adapters.ReleaseArtifactResolver = nil
		case FeatureRuntime:
			h.adapters.RuntimeManager = nil
		case FeatureCapability:
			h.adapters.Capabilities = nil
		case FeatureConnectivity:
			h.adapters.Connectivity = nil
			h.adapters.NetworkExecutor = nil
		case FeatureSecrets:
			h.adapters.Secrets = nil
		case FeatureCoreAction:
			h.adapters.CoreActions = nil
		}
	}
}

func assertMissingFeatures(t *testing.T, err error, want ...Feature) {
	t.Helper()
	var reporter interface{ MissingFeatures() []Feature }
	if !errors.As(err, &reporter) {
		t.Fatalf("error = %v, want missing feature reporter", err)
	}
	if got := reporter.MissingFeatures(); !reflect.DeepEqual(got, want) {
		t.Fatalf("missing features = %#v, want %#v", got, want)
	}
}

func assertModulePreflightHasNoWrites(t *testing.T, h *Host, assets *modulePreflightAssetStore, wantRecords int) {
	t.Helper()
	records, err := h.ListPlugins(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != wantRecords || assets.putPackageCalls != 0 {
		t.Fatalf("module preflight produced writes: records=%d assets=%d", len(records), assets.putPackageCalls)
	}
}

func modularTestConfig(t *testing.T) Config {
	legacy, _, _ := newTestHost(t, true, true)
	adapters := legacy.adapters
	return Config{StateRoot: filepath.Join(t.TempDir(), "control-state"), Core: CoreAdapters{
		Policy:               adapters.Policy,
		Authorization:        adapters.Authorization,
		PackageTrustVerifier: adapters.PackageTrustVerifier,
		Audit:                adapters.Audit,
		SecurityAudit:        adapters.SecurityAudit,
		Diagnostics:          adapters.Diagnostics,
		SurfaceCatalog:       adapters.SurfaceCatalog,
		Assets:               adapters.Assets,
		internalStateOwners: &internalStateOwnerOverrides{
			surfaceTokens:       adapters.SurfaceTokens,
			confirmationIntents: adapters.ConfirmationIntents,
			sessionScopes:       adapters.SessionScopes,
		},
	}}
}
