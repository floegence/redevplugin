package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v2/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/v2/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v2/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v2/pkg/registry"
	"github.com/floegence/redevplugin/v2/pkg/releasecontract"
)

func newHostReleaseTrustFixture(t *testing.T) *releasetrustfixture.Fixture {
	t.Helper()
	generatedAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	fixture, err := releasetrustfixture.New(buildHostReleasePackage(t), releasetrustfixture.Options{
		GeneratedAt: generatedAt,
		ExpiresAt:   generatedAt.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestRecoverEnabledRefreshesCurrentReleaseRevocationBeforeRuntime(t *testing.T) {
	testRecoverEnabledRefreshesCurrentRevocationBeforeRuntime(t, func(fixture *releasetrustfixture.Fixture, now time.Time) error {
		return fixture.RevokeRelease(now)
	})
}

func TestRecoverEnabledRefreshesCurrentSigningKeyRevocationBeforeRuntime(t *testing.T) {
	testRecoverEnabledRefreshesCurrentRevocationBeforeRuntime(t, func(fixture *releasetrustfixture.Fixture, now time.Time) error {
		return fixture.RevokeSigningKey(now)
	})
}

func testRecoverEnabledRefreshesCurrentRevocationBeforeRuntime(t *testing.T, revoke func(*releasetrustfixture.Fixture, time.Time) error) {
	t.Helper()
	fixture := newHostReleaseTrustFixture(t)
	stateRoot := filepath.Join(t.TempDir(), "control-state")
	resolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)}
	first, _, _ := newTestHostWithOptions(t, testHostOptions{
		stateRoot: stateRoot, releaseTrust: fixture.ServiceSet, releaseArtifactResolver: resolver,
	})
	installed, err := first.InstallReleaseRef(hostTestContext(), InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := first.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable state = %q", enabled.EnableState)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := revoke(fixture, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	runtimeManager := newRecordingRuntimeManager()
	restarted, _, _ := newTestHostWithOptions(t, testHostOptions{
		stateRoot: stateRoot, releaseTrust: fixture.ServiceSet, releaseArtifactResolver: resolver, runtimeManager: runtimeManager,
	})
	snapshot, err := restarted.RecoverEnabled(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Complete || len(snapshot.Results) != 1 || snapshot.Results[0].Status != PluginRecoveryFailed || snapshot.Results[0].Reason != string(refreshFailureReasonTrustRevoked) {
		t.Fatalf("recovery snapshot = %#v", snapshot)
	}
	stored, err := restarted.getPluginRecord(context.Background(), enabled.PluginInstanceID)
	if err == nil {
		t.Fatal("background context unexpectedly read owner-scoped plugin")
	}
	stored, err = restarted.getPluginRecord(hostTestContext(), enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("stored enable state = %q", stored.EnableState)
	}
	if runtimeManager.startCalls != 0 || runtimeManager.calls != 0 {
		t.Fatalf("runtime calls start=%d invoke=%d", runtimeManager.startCalls, runtimeManager.calls)
	}
}

func releaseTrustFixtureRef(fixture *releasetrustfixture.Fixture) PluginReleaseRef {
	return PluginReleaseRef{
		SourceID: fixture.Identity.SourceID, Channel: fixture.Identity.Channel,
		ReleaseMetadataRef: fixture.Identity.ReleaseMetadataRef, ReleaseMetadataSHA256: fixture.Identity.ReleaseMetadataSHA256,
		PublisherID: fixture.Identity.PublisherID, PluginID: fixture.Identity.PluginID, Version: fixture.Identity.Version,
		ExpectedHashes: PackageHashSet{
			PackageSHA256: fixture.Package.PackageHash, ManifestSHA256: fixture.Package.ManifestHash, EntriesSHA256: fixture.Package.EntriesHash,
		},
	}
}

func resolvedReleaseTrustFixture(fixture *releasetrustfixture.Fixture) ResolvedPackageArtifact {
	return ResolvedPackageArtifact{
		ReleaseMetadataBytes:     append([]byte(nil), fixture.MetadataBytes...),
		ReleaseMetadataSignature: append([]byte(nil), fixture.MetadataSignature...),
		Reader:                   bytes.NewReader(fixture.PackageBytes), Size: int64(len(fixture.PackageBytes)),
		ArtifactSHA256: fixture.ReleaseArtifactSHA256,
	}
}

func releaseCapabilityContractRef(pin capabilitycontract.Pin) releasecontract.HostCapabilityContractRef {
	return releasecontract.HostCapabilityContractRef{
		PublisherID: pin.PublisherID, ContractID: pin.ContractID, ContractVersion: pin.ContractVersion,
		ArtifactSHA256: pin.ArtifactSHA256,
	}
}

func buildHostReleasePackage(t *testing.T) []byte {
	t.Helper()
	return buildHostReleasePackageFromManifest(t, hostReleaseManifestJSON())
}

func buildHostReleasePackageFromManifest(t *testing.T, manifestJSON string) []byte {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "ui", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		"manifest.json":    []byte(manifestJSON),
		"ui/index.html":    []byte(`<!doctype html><title>Fixture</title><script type="text/redevplugin-worker" src="assets/app.js"></script>`),
		"ui/assets/app.js": []byte("void 0;"),
	} {
		if err := os.WriteFile(filepath.Join(directory, path), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), directory, &buffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func hostReleaseManifestJSON() string {
	document := map[string]any{
		"schema_version": "redevplugin.manifest.v8",
		"publisher":      map[string]any{"publisher_id": "fixture.publisher", "display_name": "Fixture"},
		"plugin": map[string]any{
			"plugin_id": "fixture.plugin", "display_name": "Fixture", "version": "1.0.0",
			"api_version": "plugin-v1", "min_runtime_version": "0.1.0", "ui_protocol_version": "plugin-ui-v7",
		},
		"presentation": map[string]any{
			"default_locale": "en-US", "summary": "Fixture release plugin.",
			"description": []string{"Fixture release plugin used by signed release tests."},
			"highlights":  []string{}, "keywords": []string{"fixture"}, "localizations": []any{},
		},
		"surfaces": []any{map[string]any{"surface_id": "fixture.view", "kind": "view", "label": "Fixture", "entry": "ui/index.html"}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
