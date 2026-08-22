package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
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
	ctx := hostTestContext()
	pluginInstanceID := nextTestPluginInstanceID(t)
	ref := releaseTrustFixtureRef(fixture)
	digests := releaseMarketDigestsForTest(t, first, ctx, pluginInstanceID, ref)
	started, err := first.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID: "request_current_revocation", PluginInstanceID: pluginInstanceID,
		ReleaseRef: ref, ReleaseIdentityDigest: releaseInstallIdentityDigestForTest(t, ref), ManifestSHA256: ref.ExpectedHashes.ManifestSHA256,
		ContractSetSHA256: digests.contract, SummarySHA256: digests.summary,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal := waitForReleaseInstallOperation(t, first, ctx, started.Execution.ID)
	if terminal.PluginRecord == nil {
		t.Fatalf("release install terminal = %#v", terminal)
	}
	installed := *terminal.PluginRecord
	if installed.EnableState != registry.EnableEnabled {
		t.Fatalf("install enable state = %q", installed.EnableState)
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
	stored, err := restarted.getPluginRecord(context.Background(), installed.PluginInstanceID)
	if err == nil {
		t.Fatal("background context unexpectedly read owner-scoped plugin")
	}
	stored, err = restarted.getPluginRecord(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.EnableState != registry.EnableEnabled {
		t.Fatalf("trust revocation changed enable state to %q", stored.EnableState)
	}
	if stored.RevokeEpoch <= installed.RevokeEpoch {
		t.Fatalf("trust revocation did not advance revoke epoch: before=%d after=%d", installed.RevokeEpoch, stored.RevokeEpoch)
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
		"schema_version": "redevplugin.manifest.v9",
		"publisher":      map[string]any{"publisher_id": "fixture.publisher", "display_name": "Fixture"},
		"plugin": map[string]any{
			"plugin_id": "fixture.plugin", "display_name": "Fixture", "version": "1.0.0",
		},
		"api":         map[string]any{"major": 1, "required_features": []any{}, "optional_features": []any{}},
		"permissions": []any{},
		"presentation": map[string]any{
			"locales": map[string]any{"default": "en-US"},
		},
		"surfaces": []any{map[string]any{"surface_id": "fixture.view", "kind": "view", "label": "Fixture", "entry": "ui/index.html"}},
		"workers":  []any{},
		"methods":  []any{},
		"storage":  map[string]any{"stores": []any{}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
