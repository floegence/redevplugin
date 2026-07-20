package host

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
)

func TestConfigExposesOnlyCoreAndOptionalModules(t *testing.T) {
	configType := reflect.TypeOf(Config{})
	want := []string{
		"Core",
		"Release",
		"Runtime",
		"Capability",
		"Connectivity",
		"Secrets",
		"CoreAction",
	}
	if configType.NumField() != len(want) {
		t.Fatalf("Config has %d fields, want %d module fields", configType.NumField(), len(want))
	}
	for index, name := range want {
		if field := configType.Field(index); field.Name != name {
			t.Fatalf("Config field %d = %q, want %q", index, field.Name, name)
		}
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

	t.Run("session lifecycle", func(t *testing.T) {
		config := modularTestConfig(t)
		var lifecycle *testSessionLifecycleAdapter
		config.Core.SessionLifecycle = lifecycle

		_, err := Open(context.Background(), config)
		var configErr *HostConfigError
		if !errors.As(err, &configErr) || !errors.Is(err, ErrHostConfig) {
			t.Fatalf("Open() error = %v, want HostConfigError", err)
		}
		if configErr.Module != "core" || configErr.Adapter != "session lifecycle adapter" {
			t.Fatalf("HostConfigError = %#v", configErr)
		}
	})

	t.Run("session coordinator", func(t *testing.T) {
		config := modularTestConfig(t)
		var coordinator *sessionscope.Coordinator
		config.Core.SessionScopes = coordinator

		_, err := Open(context.Background(), config)
		var configErr *HostConfigError
		if !errors.As(err, &configErr) || !errors.Is(err, ErrHostConfig) {
			t.Fatalf("Open() error = %v, want HostConfigError", err)
		}
		if configErr.Module != "core" || configErr.Adapter != "session scope coordinator" {
			t.Fatalf("HostConfigError = %#v", configErr)
		}
	})
}

func TestOpenConfigRequiresDurableFenceForDurableResources(t *testing.T) {
	config := modularTestConfig(t)
	memoryStore, err := sessionscope.NewMemoryStore(sessionscope.StoreOptions{})
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}
	config.Core.SessionScopes, err = sessionscope.NewCoordinator(memoryStore)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	_, err = Open(context.Background(), config)
	var configErr *HostConfigError
	if !errors.As(err, &configErr) || !errors.Is(err, ErrDurableSessionScopeRequired) {
		t.Fatalf("Open() error = %v, want durable HostConfigError", err)
	}
	if configErr.Module != "core" || configErr.Adapter != "session scope coordinator" {
		t.Fatalf("HostConfigError = %#v", configErr)
	}
}

func TestOpenReconcilesRetainedSessionScopesBeforeServing(t *testing.T) {
	config := modularTestConfig(t)
	session := sessionctx.Context{
		OwnerSessionHash: "startup_session", OwnerUserHash: "startup_user",
		OwnerEnvHash: "startup_env", SessionChannelIDHash: "startup_channel",
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sessionscope.GenerateClosedSessionProof()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sessionscope.NewTeardownIdentity("startup_reconcile", proof)
	if err != nil {
		t.Fatal(err)
	}
	teardown, _, err := config.Core.SessionScopes.BeginTeardown(context.Background(), scope, identity, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := teardown.MarkIncomplete(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	teardown.Release()
	lifecycle := &recordingSessionLifecycleAdapter{identity: identity}
	config.Core.SessionLifecycle = lifecycle

	h, err := Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if len(lifecycle.reconciled) != 1 || lifecycle.reconciled[0].SessionScope != scope || lifecycle.reconciled[0].Snapshot.State != sessionscope.StateIncomplete {
		t.Fatalf("reconciled retained session scopes = %#v", lifecycle.reconciled)
	}
}

func TestOpenRejectsRetainedSessionScopeReconciliationFailure(t *testing.T) {
	config := modularTestConfig(t)
	adapter := &recordingSessionLifecycleAdapter{reconcileErr: errors.New("retained identity unavailable")}
	config.Core.SessionLifecycle = adapter
	if _, err := Open(context.Background(), config); !errors.Is(err, ErrAdapterFailure) {
		t.Fatalf("Open() error = %v, want ErrAdapterFailure", err)
	}
	if adapter.reconcileCalls != 1 {
		t.Fatal("Open() did not invoke startup session reconciliation")
	}
}

type testSessionLifecycleAdapter struct{}

func (*testSessionLifecycleAdapter) ReconcileRetainedSessionScopes(_ context.Context, req ReconcileRetainedSessionScopesRequest) error {
	for _, retained := range req.Scopes {
		if !retained.SessionScope.Valid() || !retained.Snapshot.Fenced {
			return errors.New("retained session scope is invalid")
		}
	}
	return nil
}

func (*testSessionLifecycleAdapter) PrepareSessionScopeClose(_ context.Context, req PrepareSessionScopeCloseRequest) (sessionscope.TeardownIdentity, error) {
	if !req.Session.Valid() {
		return sessionscope.TeardownIdentity{}, sessionctx.ErrSessionRequired
	}
	proof, err := sessionscope.GenerateClosedSessionProof()
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	identity, err := sessionscope.NewTeardownIdentity("teardown_test", proof)
	if err != nil {
		return sessionscope.TeardownIdentity{}, err
	}
	return identity, nil
}

func (*testSessionLifecycleAdapter) CommitSessionScopeClose(_ context.Context, req CommitSessionScopeCloseRequest) error {
	if !req.Session.Valid() || !req.Identity.Valid() {
		return sessionctx.ErrSessionRequired
	}
	return nil
}

func (*testSessionLifecycleAdapter) ValidateClosedSessionScope(_ context.Context, req ValidateClosedSessionScopeRequest) error {
	if !req.Session.Valid() || !req.Identity.Valid() {
		return sessionctx.ErrSessionRequired
	}
	return nil
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
	config.Runtime = &RuntimeModule{Manager: newRecordingRuntimeManager()}
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
	h, registryStore, stages, assets := newModulePreflightTestHost(t)
	pkg := readTestPackage(t, buildWorkerNetworkFixturePackage(t))
	pkg.Manifest.CapabilityBindings = []manifest.CapabilityBinding{{Contract: capabilitycontract.Pin{ContractID: "test"}}}
	pkg.Manifest.Methods = append(pkg.Manifest.Methods, manifest.MethodSpec{Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCoreAction}})
	pkg.Manifest.Settings = &manifest.SettingsSpec{Fields: []manifest.SettingFieldSpec{{Type: "secret", SecretRef: "token"}}}
	disableModuleFeatures(h, FeatureRuntime, FeatureCapability, FeatureConnectivity, FeatureSecrets, FeatureCoreAction)

	_, err := h.installResolvedPackage(hostTestContext(), pkg, "plugini_module_preflight", packageTrustInput{LocalImport: true}, time.Time{}, nil)
	assertMissingFeatures(t, err, FeatureRuntime, FeatureCapability, FeatureConnectivity, FeatureSecrets, FeatureCoreAction)
	assertModulePreflightHasNoWrites(t, registryStore, stages, assets, 0)
}

func TestLocalInstallPreflightRejectsMissingConnectivityBeforeSideEffects(t *testing.T) {
	h, registryStore, stages, assets := newModulePreflightTestHost(t)
	disableModuleFeatures(h, FeatureConnectivity)

	_, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildNetworkFixturePackage(t))
	assertMissingFeatures(t, err, FeatureConnectivity)
	assertModulePreflightHasNoWrites(t, registryStore, stages, assets, 0)
}

func TestUpdatePreflightRejectsMissingConnectivityBeforeSideEffects(t *testing.T) {
	h, registryStore, stages, assets := newModulePreflightTestHost(t)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	stageCount := modulePreflightStageCount(t, stages)
	registryStore.resetWrites()
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
	assertModulePreflightHasNoWrites(t, registryStore, stages, assets, stageCount)
}

func TestDowngradePreflightRejectsMissingConnectivityBeforeRegistryMutation(t *testing.T) {
	h, registryStore, stages, assets := newModulePreflightTestHost(t)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	networkPackage := readTestPackage(t, buildNetworkFixturePackage(t))
	historic := installed
	historic.Version = "0.9.0"
	historic.Manifest.Plugin.Version = historic.Version
	historic.Manifest.NetworkAccess = networkPackage.Manifest.NetworkAccess
	historic.PackageHash = "sha256:historic-network"
	installed.VersionHistory = []registry.PluginVersion{versionSnapshot(historic, time.Now().UTC())}
	installed, err = registryStore.PutPlugin(hostTestContext(), installed, registry.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stageCount := modulePreflightStageCount(t, stages)
	registryStore.resetWrites()
	assets.resetWrites()
	disableModuleFeatures(h, FeatureConnectivity)

	_, err = h.DowngradePlugin(hostTestContext(), DowngradeRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		Version:                    historic.Version,
		PackageHash:                historic.PackageHash,
	})
	assertMissingFeatures(t, err, FeatureConnectivity)
	assertModulePreflightHasNoWrites(t, registryStore, stages, assets, stageCount)
}

func TestReleaseInstallPreflightDoesNotPersistSourceFloorForMissingRuntime(t *testing.T) {
	ctx := hostTestContext()
	packageBytes := buildSignedReleasePackageBytes(t, buildWorkerFixturePackage(t), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	registryStore := registry.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		registry:                registryStore,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes)},
	})
	disableModuleFeatures(h, FeatureRuntime)

	_, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: ref})
	assertMissingFeatures(t, err, FeatureRuntime)
	if _, floorErr := registryStore.GetSourceSecurityFloor(ctx, ref.SourceID); !errors.Is(floorErr, registry.ErrNotFound) {
		t.Fatalf("source security floor persisted before module preflight: %v", floorErr)
	}
}

type modulePreflightRegistry struct {
	registry.Store
	putPluginCalls int
}

func (s *modulePreflightRegistry) PutPlugin(ctx context.Context, record registry.PluginRecord, opts registry.PutOptions) (registry.PluginRecord, error) {
	s.putPluginCalls++
	return s.Store.PutPlugin(ctx, record, opts)
}

func (s *modulePreflightRegistry) resetWrites() {
	s.putPluginCalls = 0
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

func newModulePreflightTestHost(t *testing.T) (*Host, *modulePreflightRegistry, *installstage.MemoryStore, *modulePreflightAssetStore) {
	t.Helper()
	registryStore := &modulePreflightRegistry{Store: registry.NewMemoryStore()}
	stages := installstage.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{registry: registryStore, installStages: stages, developerMode: true, localGenerated: true})
	assets := &modulePreflightAssetStore{AssetStore: h.adapters.Assets}
	h.adapters.Assets = assets
	return h, registryStore, stages, assets
}

func disableModuleFeatures(h *Host, features ...Feature) {
	for _, feature := range features {
		delete(h.features, feature)
		switch feature {
		case FeatureRelease:
			h.adapters.ReleaseMetadataVerifier = nil
			h.adapters.RevocationVerifier = nil
			h.adapters.ReleaseSourcePolicy = nil
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

func assertModulePreflightHasNoWrites(t *testing.T, registryStore *modulePreflightRegistry, stages *installstage.MemoryStore, assets *modulePreflightAssetStore, wantStages int) {
	t.Helper()
	if registryStore.putPluginCalls != 0 || assets.putPackageCalls != 0 {
		t.Fatalf("module preflight produced writes: registry=%d assets=%d", registryStore.putPluginCalls, assets.putPackageCalls)
	}
	if got := modulePreflightStageCount(t, stages); got != wantStages {
		t.Fatalf("install stage count = %d, want %d", got, wantStages)
	}
}

func modulePreflightStageCount(t *testing.T, stages *installstage.MemoryStore) int {
	t.Helper()
	records, err := stages.List(hostTestContext(), installstage.ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return len(records)
}

func modularTestConfig(t *testing.T) Config {
	legacy, _, _ := newTestHost(t, true, true)
	adapters := legacy.adapters
	return Config{Core: CoreAdapters{
		Policy:               adapters.Policy,
		Authorization:        adapters.Authorization,
		PackageTrustVerifier: adapters.PackageTrustVerifier,
		Registry:             adapters.Registry,
		Audit:                adapters.Audit,
		SecurityAudit:        adapters.SecurityAudit,
		Diagnostics:          adapters.Diagnostics,
		SurfaceCatalog:       adapters.SurfaceCatalog,
		SurfaceTokens:        adapters.SurfaceTokens,
		PluginData:           adapters.PluginData,
		Assets:               adapters.Assets,
		InstallStages:        adapters.InstallStages,
		Operations:           adapters.Operations,
		ConfirmationIntents:  adapters.ConfirmationIntents,
		Streams:              adapters.Streams,
		SessionLifecycle:     adapters.SessionLifecycle,
		SessionScopes:        adapters.SessionScopes,
	}}
}
