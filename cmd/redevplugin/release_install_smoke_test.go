package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/remoterelease"
)

type smokeAssetFetcher struct {
	mu       sync.Mutex
	values   map[string][]byte
	requests []externalsource.ArtifactFetchRequest
}

func (fetcher *smokeAssetFetcher) FetchArtifact(ctx context.Context, request externalsource.ArtifactFetchRequest) (externalsource.ArtifactFetchResult, error) {
	fetcher.mu.Lock()
	value := append([]byte(nil), fetcher.values[request.URL]...)
	fetcher.requests = append(fetcher.requests, request)
	fetcher.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return externalsource.ArtifactFetchResult{}, err
	}
	if request.Progress != nil {
		request.Progress(int64(len(value)), int64(len(value)))
	}
	return externalsource.ArtifactFetchResult{Bytes: value, Source: request.URL, Final: request.URL}, nil
}

func (fetcher *smokeAssetFetcher) requestCount() int {
	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	return len(fetcher.requests)
}

type unusedHostRequirementPolicy struct{}

func (unusedHostRequirementPolicy) SelectHostRequirement(context.Context, host.HostRequirementSelectionRequest) (host.HostRequirementSelection, error) {
	return host.HostRequirementSelection{}, errors.New("unexpected host requirement selection")
}

type unusedCapabilityArtifactResolver struct{}

func (unusedCapabilityArtifactResolver) ResolveCapabilityContract(context.Context, host.CapabilityContractResolveRequest) (host.ResolvedCapabilityContractArtifact, error) {
	return host.ResolvedCapabilityContractArtifact{}, errors.New("unexpected capability artifact resolution")
}

func TestReleaseInstallOperationsReuseAssetCacheAndRecoverDiagnostics(t *testing.T) {
	ctx := cliContext(context.Background())
	root := t.TempDir()
	scaffoldRoot := filepath.Join(root, "plugin")
	packagePath := filepath.Join(root, "plugin.redevplugin")
	if _, err := captureCLIOutput(t, "scaffold", "com.example.install-smoke", "Install Smoke", scaffoldRoot); err != nil {
		t.Fatal(err)
	}
	makeScaffoldUIOnly(t, filepath.Join(scaffoldRoot, "dist", "manifest.json"))
	if _, err := captureCLIOutput(t, "package", filepath.Join(scaffoldRoot, "dist"), packagePath); err != nil {
		t.Fatal(err)
	}
	packageBytes, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := releasetrustfixture.New(packageBytes, releasetrustfixture.Options{
		AllowedArtifactHosts: []string{"artifacts.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	metadataURL := "https://artifacts.example.com/install-smoke/release.json"
	signatureURL := "https://artifacts.example.com/install-smoke/release.json.sig"
	packageURL := "https://artifacts.example.com/install-smoke/package.redevplugin"
	fetcher := &smokeAssetFetcher{values: map[string][]byte{
		metadataURL:  fixture.MetadataBytes,
		signatureURL: fixture.MetadataSignature,
		packageURL:   fixture.PackageBytes,
	}}
	assets := []remoterelease.Asset{
		smokeRemoteAsset(fixture.Identity.ReleaseMetadataRef, metadataURL, fixture.MetadataBytes),
		smokeRemoteAsset(fixture.Metadata.ReleaseMetadataSignature.SignatureRef, signatureURL, fixture.MetadataSignature),
		smokeRemoteAsset(fixture.Metadata.DistributionRef.ArtifactRef, packageURL, fixture.PackageBytes),
	}
	assetSet, err := remoterelease.NewAssetSet(remoterelease.AssetSetOptions{
		SourceID: fixture.Identity.SourceID, Channel: fixture.Identity.Channel,
		AllowedHosts: []string{"artifacts.example.com"}, Assets: assets, Fetcher: fetcher,
	})
	if err != nil {
		t.Fatal(err)
	}

	registryPath := filepath.Join(root, "registry.sqlite")
	pluginDataRoot := filepath.Join(root, "plugin-data")
	firstSessionRoot := filepath.Join(root, "first-host")
	if err := os.Mkdir(firstSessionRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := registry.NewSQLiteStore(ctx, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	pluginDataStore, err := plugindata.Open(ctx, pluginDataRoot, store)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	config, sessionScopeStore, err := newEphemeralCLIAdapters(ctx, firstSessionRoot, store, pluginDataStore)
	if err != nil {
		_ = pluginDataStore.Close()
		_ = store.Close()
		t.Fatal(err)
	}
	config.Release = &host.ReleaseModule{
		Trust: fixture.ServiceSet, ReleaseArtifactResolver: assetSet,
		HostRequirements: unusedHostRequirementPolicy{}, CapabilityContractArtifacts: unusedCapabilityArtifactResolver{},
	}
	installedHost, err := host.Open(ctx, config)
	if err != nil {
		_ = sessionScopeStore.Close()
		_ = pluginDataStore.Close()
		_ = store.Close()
		t.Fatal(err)
	}

	ref := smokeReleaseRef(fixture)
	first := runReleaseInstallSmokeOperation(t, installedHost, ctx, "request_install_smoke_first", "plugini_install_smoke_first", ref)
	if got := fetcher.requestCount(); got != 3 {
		t.Fatalf("first install network fetches = %d, want 3", got)
	}
	assertReleaseInstallSmokeEvidence(t, first, false, int64(len(fixture.PackageBytes)))

	second := runReleaseInstallSmokeOperation(t, installedHost, ctx, "request_install_smoke_second", "plugini_install_smoke_second", ref)
	if got := fetcher.requestCount(); got != 3 {
		t.Fatalf("second install network fetches = %d, want cache reuse with 3 total", got)
	}
	assertReleaseInstallSmokeEvidence(t, second, true, int64(len(fixture.PackageBytes)))

	if err := installedHost.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sessionScopeStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopenedStore, err := registry.NewSQLiteStore(ctx, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	reopenedPluginData, err := plugindata.Open(ctx, pluginDataRoot, reopenedStore)
	if err != nil {
		_ = reopenedStore.Close()
		t.Fatal(err)
	}
	secondSessionRoot := filepath.Join(root, "second-host")
	if err := os.Mkdir(secondSessionRoot, 0o700); err != nil {
		_ = reopenedPluginData.Close()
		_ = reopenedStore.Close()
		t.Fatal(err)
	}
	reopenedConfig, reopenedSessionScopes, err := newEphemeralCLIAdapters(ctx, secondSessionRoot, reopenedStore, reopenedPluginData)
	if err != nil {
		_ = reopenedPluginData.Close()
		_ = reopenedStore.Close()
		t.Fatal(err)
	}
	reopenedHost, err := host.Open(ctx, reopenedConfig)
	if err != nil {
		_ = reopenedSessionScopes.Close()
		_ = reopenedPluginData.Close()
		_ = reopenedStore.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopenedHost.Close()
		_ = reopenedSessionScopes.Close()
		_ = reopenedStore.Close()
	})

	for _, before := range []registry.ReleaseInstallOperation{first, second} {
		after, err := reopenedHost.GetReleaseInstallOperation(ctx, before.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Status != registry.ReleaseInstallSucceeded || after.Activation.Status != registry.ReleaseInstallActivationEnabled ||
			after.PluginRecord == nil || after.PluginRecord.EnableState != registry.EnableEnabled {
			t.Fatalf("reopened operation = %#v", after)
		}
		if !reflect.DeepEqual(after.PhaseDiagnostics, before.PhaseDiagnostics) {
			t.Fatalf("reopened diagnostics changed:\nbefore=%#v\nafter=%#v", before.PhaseDiagnostics, after.PhaseDiagnostics)
		}
	}
}

func runReleaseInstallSmokeOperation(t *testing.T, pluginHost *host.Host, ctx context.Context, requestID, pluginInstanceID string, ref host.PluginReleaseRef) registry.ReleaseInstallOperation {
	t.Helper()
	started, err := pluginHost.StartReleaseInstallOperation(ctx, host.StartReleaseInstallOperationRequest{
		RequestID: requestID, PluginInstanceID: pluginInstanceID, ReleaseRef: ref, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := pluginHost.GetReleaseInstallOperation(ctx, started.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Status == registry.ReleaseInstallSucceeded || operation.Status == registry.ReleaseInstallFailed {
			return operation
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("release install operation %q did not terminate", started.OperationID)
	return registry.ReleaseInstallOperation{}
}

func assertReleaseInstallSmokeEvidence(t *testing.T, operation registry.ReleaseInstallOperation, wantCacheHit bool, packageSize int64) {
	t.Helper()
	if operation.Status != registry.ReleaseInstallSucceeded || operation.Activation.Status != registry.ReleaseInstallActivationEnabled ||
		operation.PluginRecord == nil || operation.PluginRecord.EnableState != registry.EnableEnabled {
		t.Fatalf("terminal operation = %#v", operation)
	}
	wantPhases := []string{
		"queued", "fetch_trust_evidence", "fetch_release_evidence", "download_package", "verify_hashes",
		"verify_signatures_ledger", "fetch_capability_evidence", "commit", "enable", "complete",
	}
	gotPhases := make([]string, 0, len(operation.PhaseDiagnostics))
	var releaseEvidenceCacheHit bool
	var packageDownload *registry.ReleaseInstallPhaseDiagnostic
	for index := range operation.PhaseDiagnostics {
		diagnostic := &operation.PhaseDiagnostics[index]
		gotPhases = append(gotPhases, diagnostic.Phase)
		if diagnostic.CompletedAt == nil || diagnostic.DurationMS < 0 {
			t.Fatalf("incomplete phase diagnostic = %#v", diagnostic)
		}
		if diagnostic.Phase == "fetch_release_evidence" {
			releaseEvidenceCacheHit = diagnostic.CacheHit
		}
		if diagnostic.Phase == "download_package" {
			packageDownload = diagnostic
		}
		if (diagnostic.Phase == "verify_hashes" || diagnostic.Phase == "verify_signatures_ledger") && diagnostic.DurationMS >= 1000 {
			t.Fatalf("local verification exceeded one-second budget: %#v", diagnostic)
		}
	}
	if !reflect.DeepEqual(gotPhases, wantPhases) {
		t.Fatalf("phase history = %#v, want %#v", gotPhases, wantPhases)
	}
	if releaseEvidenceCacheHit != wantCacheHit {
		t.Fatalf("release evidence cache hit = %t, want %t", releaseEvidenceCacheHit, wantCacheHit)
	}
	if packageDownload == nil || packageDownload.CacheHit != wantCacheHit ||
		packageDownload.Progress.Kind != registry.ReleaseInstallProgressBytes ||
		packageDownload.Progress.Completed != packageSize || packageDownload.Progress.Total != packageSize {
		t.Fatalf("package download diagnostic = %#v, want bytes=%d cache_hit=%t", packageDownload, packageSize, wantCacheHit)
	}
}

func smokeRemoteAsset(locator, rawURL string, value []byte) remoterelease.Asset {
	digest := sha256.Sum256(value)
	return remoterelease.Asset{
		Locator: locator, URL: rawURL, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(value)),
	}
}

func smokeReleaseRef(fixture *releasetrustfixture.Fixture) host.PluginReleaseRef {
	return host.PluginReleaseRef{
		SourceID: fixture.Identity.SourceID, Channel: fixture.Identity.Channel,
		ReleaseMetadataRef: fixture.Identity.ReleaseMetadataRef, ReleaseMetadataSHA256: fixture.Identity.ReleaseMetadataSHA256,
		PublisherID: fixture.Identity.PublisherID, PluginID: fixture.Identity.PluginID, Version: fixture.Identity.Version,
		ExpectedHashes: host.PackageHashSet{
			PackageSHA256: fixture.Package.PackageHash, ManifestSHA256: fixture.Package.ManifestHash, EntriesSHA256: fixture.Package.EntriesHash,
		},
	}
}
