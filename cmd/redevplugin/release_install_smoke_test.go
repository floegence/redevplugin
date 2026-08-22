package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/remoterelease"
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

	stateRoot := filepath.Join(root, "host-state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	config, err := newEphemeralCLIAdapters(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	config.Release = &host.ReleaseModule{
		Trust: fixture.ServiceSet, ReleaseArtifactResolver: assetSet,
	}
	installedHost, err := host.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}

	ref := smokeReleaseRef(fixture)
	first := runReleaseInstallSmokeExecution(t, installedHost, fixture, ctx, "request_install_smoke_first", "plugini_install_smoke_first", ref)
	if got := fetcher.requestCount(); got != 3 {
		t.Fatalf("first install network fetches = %d, want 3", got)
	}
	assertReleaseInstallSmokeEvidence(t, installedHost, ctx, first)

	second := runReleaseInstallSmokeExecution(t, installedHost, fixture, ctx, "request_install_smoke_second", "plugini_install_smoke_second", ref)
	if got := fetcher.requestCount(); got != 3 {
		t.Fatalf("second install network fetches = %d, want cache reuse with 3 total", got)
	}
	assertReleaseInstallSmokeEvidence(t, installedHost, ctx, second)

	if err := installedHost.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedConfig, err := newEphemeralCLIAdapters(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	reopenedHost, err := host.Open(ctx, reopenedConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopenedHost.Close()
	})

	for _, before := range []execution.Execution{first, second} {
		after, err := reopenedHost.GetExecution(ctx, before.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Status != execution.StatusCompleted || after.Cursor != before.Cursor || after.TerminalAt == nil {
			t.Fatalf("reopened execution = %#v", after)
		}
		beforeEvents, err := installedExecutionEvents(ctx, reopenedHost, before.ID)
		if err != nil {
			t.Fatal(err)
		}
		if uint64(len(beforeEvents)) != after.Cursor {
			t.Fatalf("reopened event count = %d, cursor = %d", len(beforeEvents), after.Cursor)
		}
	}
	assertInstalledPluginsEnabled(t, reopenedHost, ctx, first.PluginInstanceID, second.PluginInstanceID)
}

func runReleaseInstallSmokeExecution(t *testing.T, pluginHost *host.Host, fixture *releasetrustfixture.Fixture, ctx context.Context, requestID, pluginInstanceID string, ref host.PluginReleaseRef) execution.Execution {
	t.Helper()
	required := make(map[string][]string, len(fixture.Package.Manifest.Methods))
	for _, method := range fixture.Package.Manifest.Methods {
		if method.Route.Kind == manifest.MethodRouteWorker {
			for _, permission := range fixture.Package.Manifest.Permissions {
				required[method.Method] = append(required[method.Method], string(permission))
			}
		}
	}
	summary, err := host.BuildExternalPackageSecuritySummary(fixture.Package.Manifest, nil, required)
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := host.CapabilityContractSetSHA256(summary)
	if err != nil {
		t.Fatal(err)
	}
	releaseIdentityDigest, err := registry.ReleaseInstallIdentitySHA256(registry.ReleaseInstallIdentity{
		SourceID: ref.SourceID, Channel: ref.Channel, ReleaseMetadataRef: ref.ReleaseMetadataRef, ReleaseMetadataSHA256: ref.ReleaseMetadataSHA256,
		PublisherID: ref.PublisherID, PluginID: ref.PluginID, Version: ref.Version, PackageSHA256: ref.ExpectedHashes.PackageSHA256,
		ManifestSHA256: ref.ExpectedHashes.ManifestSHA256, EntriesSHA256: ref.ExpectedHashes.EntriesSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	started, err := pluginHost.StartReleaseInstallExecution(ctx, host.StartReleaseInstallExecutionRequest{
		RequestID: requestID, PluginInstanceID: pluginInstanceID, ReleaseRef: ref,
		ReleaseIdentityDigest: releaseIdentityDigest, ManifestSHA256: ref.ExpectedHashes.ManifestSHA256,
		ContractSetSHA256: contractDigest, SummarySHA256: summary.SummarySHA256, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		current, err := pluginHost.GetExecution(ctx, started.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status == execution.StatusCompleted || current.Status == execution.StatusFailed {
			return current
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("release install execution %q did not terminate", started.ID)
	return execution.Execution{}
}

func assertReleaseInstallSmokeEvidence(t *testing.T, pluginHost *host.Host, ctx context.Context, current execution.Execution) {
	t.Helper()
	if current.Status != execution.StatusCompleted || current.TerminalAt == nil || current.FailureCode != "" {
		t.Fatalf("terminal execution = %#v", current)
	}
	events, err := installedExecutionEvents(ctx, pluginHost, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantPhases := []string{
		"download_package", "fetch_trust_evidence", "fetch_release_evidence", "download_package", "fetch_release_evidence", "download_package", "verify_hashes", "verify_signatures", "validate_install", "runtime_preflight",
		"fetch_capability_evidence", "commit", "complete",
	}
	gotPhases := make([]string, 0, len(events))
	for _, event := range events {
		phase, _ := event.Payload["phase"].(string)
		if phase == "" || (len(gotPhases) > 0 && gotPhases[len(gotPhases)-1] == phase) {
			continue
		}
		gotPhases = append(gotPhases, phase)
	}
	if !reflect.DeepEqual(gotPhases, wantPhases) {
		t.Fatalf("phase history = %#v, want %#v", gotPhases, wantPhases)
	}
	assertInstalledPluginsEnabled(t, pluginHost, ctx, current.PluginInstanceID)
}

func installedExecutionEvents(ctx context.Context, pluginHost *host.Host, executionID string) ([]execution.Event, error) {
	return pluginHost.EventsAfter(ctx, executionID, 0, 1000)
}

func assertInstalledPluginsEnabled(t *testing.T, pluginHost *host.Host, ctx context.Context, pluginInstanceIDs ...string) {
	t.Helper()
	inventory, err := pluginHost.ListPluginInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, pluginInstanceID := range pluginInstanceIDs {
		index := slices.IndexFunc(inventory, func(item host.PluginInventoryRecord) bool {
			return item.Plugin.PluginInstanceID == pluginInstanceID
		})
		if index < 0 || inventory[index].Plugin.EnableState != registry.EnableEnabled || !inventory[index].ActionState.CanOpen {
			t.Fatalf("installed plugin %q inventory = %#v", pluginInstanceID, inventory)
		}
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
