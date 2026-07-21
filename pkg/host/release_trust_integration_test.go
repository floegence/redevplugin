package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/releasecontract"
	"github.com/floegence/redevplugin/pkg/releasetrust"
	"github.com/floegence/redevplugin/pkg/stream"
)

type hostReleaseTrustNoopFence struct{}

func (hostReleaseTrustNoopFence) TeardownSourceTrust(context.Context, releasetrust.SourceFenceRequest) error {
	return nil
}

type releaseTrustConnectivityBroker struct {
	*connectivity.MemoryBroker
	removeCalls int
}

func (broker *releaseTrustConnectivityBroker) RemovePolicy(ctx context.Context, pluginInstanceID string) error {
	broker.removeCalls++
	return broker.MemoryBroker.RemovePolicy(ctx, pluginInstanceID)
}

func TestReleaseTrustInstallPersistsBindingAndEnables(t *testing.T) {
	fixture := newHostReleaseTrustFixture(t)
	resolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet, releaseArtifactResolver: resolver,
	})

	installed, err := h.InstallReleaseRef(hostTestContext(), InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if installed.ReleaseTrustBinding == nil {
		t.Fatal("release trust binding was not persisted")
	}
	binding := installed.ReleaseTrustBinding
	if binding.SourceID != fixture.Identity.SourceID || binding.Channel != fixture.Identity.Channel ||
		binding.ReleaseMetadataSHA256 != fixture.Identity.ReleaseMetadataSHA256 || binding.VerifiedStateSHA256 == "" ||
		binding.RootEpoch != "1" || binding.PolicyEpoch != "1" || binding.RevocationEpoch != "1" {
		t.Fatalf("release trust binding = %#v", binding)
	}
	persisted, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ReleaseTrustBinding == nil || *persisted.ReleaseTrustBinding != *binding {
		t.Fatalf("persisted release trust binding = %#v, want %#v", persisted.ReleaseTrustBinding, binding)
	}
	enabled, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable state = %q, want %q", enabled.EnableState, registry.EnableEnabled)
	}
	lease, ok := h.releaseLeases.get(enabled.PluginInstanceID, *enabled.ReleaseTrustBinding)
	if !ok {
		t.Fatal("enabled release is missing its activation lease")
	}
	if err := fixture.ServiceSet.ValidateActivationLease(lease); err != nil {
		t.Fatalf("ValidateActivationLease() error = %v", err)
	}
}

func TestReleaseTrustInstallRejectsTamperingBeforeRegistryMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ResolvedPackageArtifact)
	}{
		{
			name: "metadata",
			mutate: func(artifact *ResolvedPackageArtifact) {
				artifact.ReleaseMetadataBytes = append([]byte(nil), artifact.ReleaseMetadataBytes...)
				artifact.ReleaseMetadataBytes[len(artifact.ReleaseMetadataBytes)-1] ^= 1
			},
		},
		{
			name: "package",
			mutate: func(artifact *ResolvedPackageArtifact) {
				tampered := make([]byte, artifact.Size)
				if _, err := artifact.Reader.ReadAt(tampered, 0); err != nil {
					panic(err)
				}
				tampered[len(tampered)-1] ^= 1
				artifact.Reader = bytes.NewReader(tampered)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newHostReleaseTrustFixture(t)
			artifact := resolvedReleaseTrustFixture(fixture)
			tt.mutate(&artifact)
			resolver := &recordingReleaseArtifactResolver{artifact: artifact}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				releaseTrust: fixture.ServiceSet, releaseArtifactResolver: resolver,
			})
			pluginInstanceID := nextTestPluginInstanceID(t)
			if _, err := h.InstallReleaseRef(hostTestContext(), InstallReleaseRefRequest{
				PluginInstanceID: pluginInstanceID, ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
			}); err == nil {
				t.Fatal("InstallReleaseRef() error = nil, want tampering rejection")
			}
			if _, err := h.adapters.Registry.GetPlugin(hostTestContext(), pluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
				t.Fatalf("GetPlugin() after rejected install error = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestReleaseActivationLeaseIsSharedBySourceChannel(t *testing.T) {
	fixture := newHostReleaseTrustFixture(t)
	if err := fixture.ServiceSet.BindFenceCoordinator(hostReleaseTrustNoopFence{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := fixture.ServiceSet.PrepareRelease(hostTestContext(), fixture.Identity)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := fixture.ServiceSet.VerifyReleaseMetadata(
		hostTestContext(), prepared, fixture.MetadataBytes, fixture.MetadataSignature,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := fixture.ServiceSet.VerifyPackage(hostTestContext(), metadata, fixture.PackageSignature)
	if err != nil {
		t.Fatal(err)
	}
	binding := *releaseTrustBinding(verified)
	leases := newReleaseLeaseRegistry()
	for _, pluginInstanceID := range []string{"plugini_release_a", "plugini_release_b"} {
		if err := leases.ensure(
			pluginInstanceID, binding, fixture.ServiceSet.ValidateActivationLease, verified.AuthorizeActivation,
		); err != nil {
			t.Fatal(err)
		}
	}
	first, firstOK := leases.get("plugini_release_a", binding)
	second, secondOK := leases.get("plugini_release_b", binding)
	if !firstOK || !secondOK || first != second {
		t.Fatalf("source/channel leases were not shared: first=%#v second=%#v", first, second)
	}
	if _, err := verified.AuthorizeActivation(); err != nil {
		t.Fatal(err)
	}
	if err := leases.ensure(
		"plugini_release_a", binding, fixture.ServiceSet.ValidateActivationLease, verified.AuthorizeActivation,
	); err != nil {
		t.Fatal(err)
	}
	refreshedFirst, _ := leases.get("plugini_release_a", binding)
	refreshedSecond, _ := leases.get("plugini_release_b", binding)
	if refreshedFirst != refreshedSecond || refreshedFirst == first {
		t.Fatal("lease replacement did not update every plugin sharing the source/channel entry")
	}
}

func TestReleaseTrustInstallVerifiesCapabilityContractBundle(t *testing.T) {
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	contract.PublisherID = "fixture.capability"
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract: contract, PublisherID: contract.PublisherID,
		ArtifactBaseRef: "capabilities/fixture/echo/1.0.0", GeneratedAt: time.Date(2026, 7, 21, 1, 0, 0, 0, time.UTC),
		SourceCommit: "0123456789abcdef0123456789abcdef01234567", MinReDevPluginVersion: "0.1.0",
		SignatureKeyID: "fixture_signing_key", SignaturePolicyEpoch: "1", SignatureRevocationEpoch: "1",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := releasetrustfixture.New(buildHostReleasePackageWithCapability(t, bundle.Pin), releasetrustfixture.Options{
		HostRequirements: []releasecontract.ReleaseHostRequirement{{
			HostID: "test-host", MinHostVersion: "0.1.0",
			RequiredCapabilityContracts: []releasecontract.HostCapabilityRequirementRef{{
				CapabilityID: contract.CapabilityID, CapabilityVersion: contract.CapabilityVersion,
				Contract: releaseCapabilityContractRef(bundle.Pin),
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilityResolver := &recordingCapabilityContractArtifactResolver{result: ResolvedCapabilityContractArtifact{
		Artifacts: &memoryCapabilityContractArtifactSet{bundle: bundle},
	}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet, releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
		capabilityArtifacts: capabilityResolver,
	})
	installed, err := h.InstallReleaseRef(hostTestContext(), InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if capabilityResolver.calls != 1 || len(installed.CapabilityContracts) != 1 || installed.CapabilityContracts[0] != bundle.Pin {
		t.Fatalf("verified capability contracts = %#v, resolver calls = %d", installed.CapabilityContracts, capabilityResolver.calls)
	}
}

func TestFailedReleaseUpdateRestoresVerifiedReleaseAndLease(t *testing.T) {
	fixture := newHostReleaseTrustFixture(t)
	resolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet, releaseArtifactResolver: resolver,
	})
	ctx := hostTestContext()
	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldBinding := *enabled.ReleaseTrustBinding
	oldVerified, ok := h.verifiedReleases.get(enabled.PluginInstanceID, oldBinding)
	if !ok {
		t.Fatal("enabled release is missing verified package cache")
	}
	if _, err := oldVerified.AuthorizeActivation(); err != nil {
		t.Fatal(err)
	}

	h.adapters.SurfaceCatalog = &failingSurfaceSink{err: errors.New("publish failed")}
	if _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{
		PluginInstanceID: enabled.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision,
		ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	}); err == nil {
		t.Fatal("UpdateReleaseRef() error = nil, want publish failure")
	}

	stored, err := h.adapters.Registry.GetPlugin(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ReleaseTrustBinding == nil || *stored.ReleaseTrustBinding != oldBinding {
		t.Fatalf("release binding after rollback = %#v, want %#v", stored.ReleaseTrustBinding, oldBinding)
	}
	restored, ok := h.verifiedReleases.get(stored.PluginInstanceID, oldBinding)
	if !ok || !bytes.Equal(restored.ReleaseMetadata().CanonicalBytes(), oldVerified.ReleaseMetadata().CanonicalBytes()) {
		t.Fatal("failed release update did not restore the previous verified package")
	}
	lease, ok := h.releaseLeases.get(stored.PluginInstanceID, oldBinding)
	if !ok {
		t.Fatal("failed release update did not restore the previous lease association")
	}
	if err := fixture.ServiceSet.ValidateActivationLease(lease); err != nil {
		t.Fatalf("restored activation lease is invalid: %v", err)
	}
}

func TestReleaseTrustFenceTearsDownPluginActivity(t *testing.T) {
	fixture, err := releasetrustfixture.New(buildWorkerFixturePackage(t), releasetrustfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)}
	operations := operation.NewMemoryStore()
	streams := stream.NewMemoryStore()
	runtimeManager := newRecordingRuntimeManager()
	connectivityBroker := &releaseTrustConnectivityBroker{MemoryBroker: connectivity.NewMemoryBroker()}
	h, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet, releaseArtifactResolver: resolver,
		operations: operations, streams: streams, runtimeManager: runtimeManager, connectivityBroker: connectivityBroker,
	})
	ctx := hostTestContext()
	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, gateway := openSurfaceAndMintGateway(t, h, enabled.PluginInstanceID, "worker.view")
	binding := testExecutionBinding(enabled, "worker.echo", manifest.MethodExecutionOperation)
	if _, err := operations.Register(ctx, operation.RegisterRequest{
		OperationID: "operation_release_fence", ExecutionBinding: binding, DisableBehavior: operation.DisableBehaviorOrphan,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := streams.Register(ctx, stream.RegisterRequest{
		StreamID: "stream_release_fence", ExecutionBinding: binding,
	}); err != nil {
		t.Fatal(err)
	}
	lease, ok := h.releaseLeases.get(enabled.PluginInstanceID, *enabled.ReleaseTrustBinding)
	if !ok {
		t.Fatal("enabled release is missing activation lease")
	}
	verified, ok := h.verifiedReleases.get(enabled.PluginInstanceID, *enabled.ReleaseTrustBinding)
	if !ok {
		t.Fatal("enabled release is missing verified package")
	}
	if _, err := verified.AuthorizeActivation(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.ServiceSet.RefreshActivationLease(ctx, lease); !errors.Is(err, releasetrust.ErrActivationLeaseInvalid) {
		t.Fatalf("RefreshActivationLease() error = %v, want ErrActivationLeaseInvalid", err)
	}

	disabled, err := h.adapters.Registry.GetPlugin(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("enable state after source fence = %q, want %q", disabled.EnableState, registry.EnableDisabledByPolicy)
	}
	operationRecord, err := operations.Get(ctx, "operation_release_fence")
	if err != nil {
		t.Fatal(err)
	}
	if operationRecord.Status != operation.StatusOrphanedAfterDisable {
		t.Fatalf("operation status after source fence = %q", operationRecord.Status)
	}
	streamRecord, err := streams.Get(ctx, "stream_release_fence")
	if err != nil {
		t.Fatal(err)
	}
	if streamRecord.Status != stream.StatusOrphanedDisabled {
		t.Fatalf("stream status after source fence = %q", streamRecord.Status)
	}
	if len(surfaces.snapshots) == 0 || len(surfaces.snapshots[len(surfaces.snapshots)-1].Surfaces) != 0 {
		t.Fatalf("last surface snapshot after source fence = %#v", surfaces.snapshots)
	}
	if runtimeManager.revokeCalls != 1 || runtimeManager.lastRevokedPlugin != enabled.PluginInstanceID {
		t.Fatalf("runtime revoke calls = %d, plugin = %q", runtimeManager.revokeCalls, runtimeManager.lastRevokedPlugin)
	}
	if connectivityBroker.removeCalls != 1 {
		t.Fatalf("connectivity RemovePolicy calls = %d, want 1", connectivityBroker.removeCalls)
	}
	if _, err := h.surfaceTokens.ValidateSurfaceGatewayToken(bridge.ValidateSurfaceGatewayTokenRequest{
		GatewayToken: gateway.GatewayToken, PluginInstanceID: enabled.PluginInstanceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID, BridgeChannelID: "bridge_rpc",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
		Revision: bridge.RevisionBinding{
			PolicyRevision: enabled.PolicyRevision, ManagementRevision: enabled.ManagementRevision, RevokeEpoch: enabled.RevokeEpoch,
		},
		Now: time.Now().UTC(),
	}); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateSurfaceGatewayToken() after source fence error = %v, want ErrTokenRevoked", err)
	}
	if _, ok := h.releaseLeases.get(enabled.PluginInstanceID, *enabled.ReleaseTrustBinding); ok {
		t.Fatal("source fence retained activation lease association")
	}
	if _, ok := h.verifiedReleases.get(enabled.PluginInstanceID, *enabled.ReleaseTrustBinding); ok {
		t.Fatal("source fence retained verified package association")
	}
}

func newHostReleaseTrustFixture(t *testing.T) *releasetrustfixture.Fixture {
	t.Helper()
	fixture, err := releasetrustfixture.New(buildHostReleasePackage(t), releasetrustfixture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
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

func releaseCapabilityContractRef(pin capabilitycontract.Pin) releasecontract.HostCapabilityContractRef {
	return releasecontract.HostCapabilityContractRef{
		PublisherID: pin.PublisherID, ContractID: pin.ContractID, ContractVersion: pin.ContractVersion,
		ArtifactRef: pin.ArtifactRef, ArtifactSHA256: pin.ArtifactSHA256,
		ManifestRef: pin.ManifestRef, ManifestSHA256: pin.ManifestSHA256,
		SignatureRef: pin.SignatureRef, SignatureSHA256: pin.SignatureSHA256,
		SignatureKeyID: pin.SignatureKeyID, SignaturePolicyEpoch: pin.SignaturePolicyEpoch,
		SignatureRevocationEpoch: pin.SignatureRevocationEpoch,
		CompatibilityRef:         pin.CompatibilityRef, CompatibilitySHA256: pin.CompatibilitySHA256,
		GeneratedClientRef: pin.GeneratedClientRef, GeneratedClientSHA256: pin.GeneratedClientSHA256,
		NoticesRef: pin.NoticesRef, NoticesSHA256: pin.NoticesSHA256,
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

func buildHostReleasePackageWithCapability(t *testing.T, pin capabilitycontract.Pin) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(hostReleaseManifestJSON()), &document); err != nil {
		t.Fatal(err)
	}
	pinBytes, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	var pinDocument map[string]any
	if err := json.Unmarshal(pinBytes, &pinDocument); err != nil {
		t.Fatal(err)
	}
	document["capability_bindings"] = []any{map[string]any{"binding_id": "fixture.echo", "contract": pinDocument}}
	manifest, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return buildHostReleasePackageFromManifest(t, string(manifest))
}

func buildHostReleasePackageFromManifest(t *testing.T, manifest string) []byte {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "ui", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ui", "index.html"), []byte(`<!doctype html><title>Fixture</title><script type="text/redevplugin-worker" src="assets/app.js"></script>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ui", "assets", "app.js"), []byte("void 0;"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), directory, &buffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func hostReleaseManifestJSON() string {
	return `{
  "schema_version": "redevplugin.manifest.v5",
  "publisher": {"publisher_id": "fixture.publisher", "display_name": "Fixture"},
  "plugin": {
    "plugin_id": "fixture.plugin",
    "display_name": "Fixture",
    "version": "1.0.0",
    "api_version": "plugin-v1",
    "min_runtime_version": "0.1.0",
    "ui_protocol_version": "plugin-ui-v5"
  },
  "surfaces": [
    {"surface_id": "fixture.view", "kind": "view", "label": "Fixture", "entry": "ui/index.html"}
  ]
}`
}
