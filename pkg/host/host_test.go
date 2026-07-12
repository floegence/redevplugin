package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/browsersite"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/cleanup"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/retaineddata"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/settings"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
)

func TestLifecycleInstallEnableDisableUninstall(t *testing.T) {
	host, surfaces, audits := newTestHost(t, true, true)
	packageBytes := buildFixturePackage(t)

	installed, err := ImportLocalPackageBytes(context.Background(), host, packageBytes)
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	if installed.EnableState != registry.EnableDisabled {
		t.Fatalf("install EnableState = %s", installed.EnableState)
	}
	if installed.PolicyRevision == 0 || installed.ManagementRevision == 0 {
		t.Fatalf("revision fields not initialized: %#v", installed)
	}
	if installed.LocalImportProvenance == nil ||
		installed.LocalImportProvenance.Distribution != string(PackageDistributionLocalImport) ||
		installed.LocalImportProvenance.UnsignedPolicy != string(PackageUnsignedDevOnly) {
		t.Fatalf("local import provenance mismatch: %#v", installed.LocalImportProvenance)
	}

	enabled, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable EnableState = %s", enabled.EnableState)
	}
	if len(surfaces.snapshots) != 1 || len(surfaces.snapshots[0].Surfaces) != 1 {
		t.Fatalf("surface publish mismatch: %#v", surfaces.snapshots)
	}

	disabled, err := host.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test"})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if disabled.EnableState != registry.EnableDisabled {
		t.Fatalf("disable EnableState = %s", disabled.EnableState)
	}
	if len(surfaces.snapshots) != 2 || len(surfaces.snapshots[1].Surfaces) != 0 {
		t.Fatalf("disable did not clear surfaces: %#v", surfaces.snapshots)
	}

	uninstalled, err := host.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true})
	if err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	if uninstalled.RetainedDataState != registry.RetainedDataDeleted {
		t.Fatalf("RetainedDataState = %s", uninstalled.RetainedDataState)
	}
	if _, err := host.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID); err != registry.ErrNotFound {
		t.Fatalf("GetPlugin after uninstall error = %v", err)
	}
	for _, eventType := range []string{"plugin.installed", "plugin.enabled", "plugin.disabled", "plugin.cleanup.executed", "plugin.uninstalled"} {
		if !audits.hasEvent(eventType) {
			t.Fatalf("missing audit event %q: %#v", eventType, audits.events)
		}
	}
}

func TestUpdateAndDowngradeRefreshEnabledPluginAndRevokeOldTokens(t *testing.T) {
	ctx := context.Background()
	h, surfaces, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	v1 := buildVersionedRPCPackage(t, "1.0.0", "RPC")
	v2 := buildVersionedRPCPackage(t, "2.0.0", "RPC v2")
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	installed, err := ImportLocalPackageBytes(ctx, h, v1)
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "rpc.activity",
		SurfaceInstanceID:    "surface_update",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if _, err := h.ExchangeAssetTicket(ctx, ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("ExchangeAssetTicket() error = %v", err)
	}
	handshake := bridge.Handshake{
		PluginID:          bootstrap.PluginID,
		SurfaceID:         bootstrap.SurfaceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		ActiveFingerprint: bootstrap.ActiveFingerprint,
		BridgeNonce:       bootstrap.BridgeNonce,
		UIProtocolVersion: "plugin-ui-v1",
	}
	gateway, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_update",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_update"),
		Now:                       now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}

	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(v2),
		PackageSize:      int64(len(v2)),
		Now:              now.Add(4 * time.Second),
	})
	if err != nil {
		t.Fatalf("UpdateLocalPackage() error = %v", err)
	}
	if updated.Version != "2.0.0" || updated.EnableState != registry.EnableEnabled || len(updated.VersionHistory) != 1 || updated.VersionHistory[0].Version != "1.0.0" {
		t.Fatalf("updated record mismatch: %#v", updated)
	}
	if updated.LocalImportProvenance == nil || updated.VersionHistory[0].LocalImportProvenance == nil {
		t.Fatalf("local import provenance missing from update/version history: updated=%#v history=%#v", updated.LocalImportProvenance, updated.VersionHistory[0].LocalImportProvenance)
	}
	if updated.ManagementRevision <= installed.ManagementRevision || updated.RevokeEpoch <= installed.RevokeEpoch {
		t.Fatalf("update did not bump revision/revoke epoch: before=%#v after=%#v", installed, updated)
	}
	if len(surfaces.snapshots) < 2 || surfaces.snapshots[len(surfaces.snapshots)-1].ActiveFingerprint != updated.ActiveFingerprint {
		t.Fatalf("surface catalog was not refreshed: %#v", surfaces.snapshots)
	}
	if _, err := h.surfaceTokens.ValidateGatewayToken(gateway.GatewayToken, bridge.Audience{
		PluginInstanceID:     updated.PluginInstanceID,
		ActiveFingerprint:    bootstrap.ActiveFingerprint,
		SurfaceInstanceID:    "surface_update",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_update",
	}, bridge.RevisionBinding{
		PolicyRevision:     updated.PolicyRevision,
		ManagementRevision: updated.ManagementRevision,
		RevokeEpoch:        updated.RevokeEpoch,
	}, now.Add(5*time.Second)); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() old token error = %v, want ErrTokenRevoked", err)
	}

	downgraded, err := h.DowngradePlugin(ctx, DowngradeRequest{
		PluginInstanceID: updated.PluginInstanceID,
		Version:          "1.0.0",
		Now:              now.Add(6 * time.Second),
	})
	if err != nil {
		t.Fatalf("DowngradePlugin() error = %v", err)
	}
	if downgraded.Version != "1.0.0" || downgraded.ActiveFingerprint != installed.ActiveFingerprint || len(downgraded.VersionHistory) != 1 || downgraded.VersionHistory[0].Version != "2.0.0" {
		t.Fatalf("downgraded record mismatch: %#v", downgraded)
	}
	if !audits.hasEvent("plugin.updated") || !audits.hasEvent("plugin.downgraded") {
		t.Fatalf("missing update/downgrade audit events: %#v", audits.events)
	}
}

func TestUpdateRejectsDifferentPluginIdentity(t *testing.T) {
	ctx := context.Background()
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(ctx, h, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	other := buildStorageFixturePackage(t)
	if _, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(other),
		PackageSize:      int64(len(other)),
	}); err == nil {
		t.Fatal("UpdateLocalPackage() expected identity mismatch error")
	}
}

func TestUpdateAndDowngradeValidateMigrationPreflight(t *testing.T) {
	ctx := context.Background()
	h, _, _ := newTestHost(t, true, true)
	v1 := buildMigrationFixturePackage(t, migrationFixtureOptions{
		Version:            "1.0.0",
		SettingsSchema:     1,
		SettingsFrom:       1,
		SettingsTo:         1,
		SettingsReversible: true,
		StorageSchema:      1,
		StorageFrom:        1,
		StorageTo:          1,
		StorageReversible:  true,
	})
	v2 := buildMigrationFixturePackage(t, migrationFixtureOptions{
		Version:            "2.0.0",
		SettingsSchema:     2,
		SettingsFrom:       1,
		SettingsTo:         2,
		SettingsReversible: true,
		StorageSchema:      2,
		StorageFrom:        1,
		StorageTo:          2,
		StorageReversible:  true,
	})

	installed, err := ImportLocalPackageBytes(ctx, h, v1)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(v2),
		PackageSize:      int64(len(v2)),
	})
	if err != nil {
		t.Fatalf("UpdateLocalPackage() migration preflight error = %v", err)
	}
	if updated.Manifest.Settings.SchemaVersion != 2 || updated.Manifest.Storage.Stores[0].SchemaVersion != 2 {
		t.Fatalf("updated schemas mismatch: settings=%#v storage=%#v", updated.Manifest.Settings, updated.Manifest.Storage)
	}
	downgraded, err := h.DowngradePlugin(ctx, DowngradeRequest{
		PluginInstanceID: updated.PluginInstanceID,
		Version:          "1.0.0",
	})
	if err != nil {
		t.Fatalf("DowngradePlugin() reversible migration error = %v", err)
	}
	if downgraded.Version != "1.0.0" || downgraded.Manifest.Settings.SchemaVersion != 1 {
		t.Fatalf("downgraded record mismatch: %#v", downgraded)
	}
}

func TestUpdateRejectsMismatchedMigrationPreflight(t *testing.T) {
	ctx := context.Background()
	h, _, _ := newTestHost(t, true, true)
	v1 := buildMigrationFixturePackage(t, migrationFixtureOptions{
		Version:            "1.0.0",
		SettingsSchema:     1,
		SettingsFrom:       1,
		SettingsTo:         1,
		SettingsReversible: true,
		StorageSchema:      1,
		StorageFrom:        1,
		StorageTo:          1,
		StorageReversible:  true,
	})
	badV2 := buildMigrationFixturePackage(t, migrationFixtureOptions{
		Version:            "2.0.0",
		SettingsSchema:     2,
		SettingsFrom:       0,
		SettingsTo:         2,
		SettingsReversible: true,
		StorageSchema:      2,
		StorageFrom:        1,
		StorageTo:          2,
		StorageReversible:  true,
	})

	installed, err := ImportLocalPackageBytes(ctx, h, v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(badV2),
		PackageSize:      int64(len(badV2)),
	}); !errors.Is(err, ErrPluginMigrationPreflight) {
		t.Fatalf("UpdateLocalPackage() error = %v, want ErrPluginMigrationPreflight", err)
	}
}

func TestDowngradeRejectsIrreversibleMigrationPreflight(t *testing.T) {
	ctx := context.Background()
	h, _, _ := newTestHost(t, true, true)
	v1 := buildMigrationFixturePackage(t, migrationFixtureOptions{
		Version:            "1.0.0",
		SettingsSchema:     1,
		SettingsFrom:       1,
		SettingsTo:         1,
		SettingsReversible: true,
		StorageSchema:      1,
		StorageFrom:        1,
		StorageTo:          1,
		StorageReversible:  true,
	})
	irreversibleV2 := buildMigrationFixturePackage(t, migrationFixtureOptions{
		Version:            "2.0.0",
		SettingsSchema:     2,
		SettingsFrom:       1,
		SettingsTo:         2,
		SettingsReversible: false,
		StorageSchema:      2,
		StorageFrom:        1,
		StorageTo:          2,
		StorageReversible:  true,
	})

	installed, err := ImportLocalPackageBytes(ctx, h, v1)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(irreversibleV2),
		PackageSize:      int64(len(irreversibleV2)),
	})
	if err != nil {
		t.Fatalf("UpdateLocalPackage() irreversible forward migration error = %v", err)
	}
	if _, err := h.DowngradePlugin(ctx, DowngradeRequest{
		PluginInstanceID: updated.PluginInstanceID,
		Version:          "1.0.0",
	}); !errors.Is(err, ErrPluginMigrationPreflight) {
		t.Fatalf("DowngradePlugin() error = %v, want ErrPluginMigrationPreflight", err)
	}
}

func TestEnableRejectsUntrusted(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	pkg := readTestPackage(t, buildFixturePackage(t))
	installed, err := host.adapters.Registry.PutPlugin(context.Background(), packageRecord(pkg, registry.TrustAssessment{TrustState: registry.TrustUntrusted}, "", nil), registry.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err == nil {
		t.Fatal("EnablePlugin() expected untrusted error")
	}
}

func TestEnableUnsignedLocalRequiresPolicy(t *testing.T) {
	host, err := New(Adapters{
		SessionResolver: fakeSessionResolver{},
		Policy:          policyAdapter{developerMode: false, localGenerated: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := ImportLocalPackageBytes(context.Background(), host, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err == nil {
		t.Fatal("EnablePlugin() expected policy error")
	}
	record, err := host.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s", record.EnableState)
	}
}

func TestInstallReleaseRefRequiresPackageTrustVerifier(t *testing.T) {
	packageBytes := buildSignedReleasePackageBytes(t, buildFixturePackage(t), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, err := New(Adapters{
		SessionResolver:         fakeSessionResolver{},
		Policy:                  policyAdapter{developerMode: true, localGenerated: true},
		ReleaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		ReleaseArtifactResolver: resolver,
		ReleaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.InstallReleaseRef(context.Background(), InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrPackageTrustVerifierRequired) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrPackageTrustVerifierRequired", err)
	}
}

func TestInstallReleaseRefRejectsNonVerifiedTrustAssessment(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildFixturePackage(t), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		trustVerifier:           &recordingPackageTrustVerifier{trustState: registry.TrustUnsignedLocal},
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrPackageTrustVerificationInvalid) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrPackageTrustVerificationInvalid", err)
	}
}

func TestInstallUsesVerifierTrustDecisionAndMetadata(t *testing.T) {
	verifier := &recordingPackageTrustVerifier{
		trustState: registry.TrustNeedsReview,
		metadata:   map[string]string{"trust.source": "test-review"},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		trustVerifier:  verifier,
	})

	installed, err := ImportLocalPackageBytes(context.Background(), h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if installed.TrustState != registry.TrustNeedsReview {
		t.Fatalf("TrustState = %s, want needs_review", installed.TrustState)
	}
	if installed.Metadata["trust.source"] != "test-review" {
		t.Fatalf("Metadata = %#v", installed.Metadata)
	}
	if verifier.last.Action != PackageTrustActionInstall || !verifier.last.LocalImport || verifier.last.Package.PackageHash == "" {
		t.Fatalf("verifier request mismatch: %#v", verifier.last)
	}
}

func TestInstallReleaseRefResolvesArtifactAndInstallsVerifiedPackage(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	metadataVerifier := &recordingReleaseMetadataVerifier{}
	verifier := &recordingPackageTrustVerifier{trustState: registry.TrustVerified, metadata: map[string]string{"trust.key_id": "official"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		trustVerifier:           verifier,
		releaseMetadataVerifier: metadataVerifier,
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		ReleaseRef:       ref,
		PluginInstanceID: "plugini_release_ref",
	})
	if err != nil {
		t.Fatal(err)
	}
	if installed.PluginInstanceID != "plugini_release_ref" || installed.PackageHash != pkg.PackageHash || installed.ManifestHash != pkg.ManifestHash || installed.EntriesHash != pkg.EntriesHash {
		t.Fatalf("installed record mismatch: %#v", installed)
	}
	if installed.TrustState != registry.TrustVerified {
		t.Fatalf("TrustState = %s, want verified", installed.TrustState)
	}
	wantMetadataSignatureRef := "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/release.json.sig"
	wantPackageSignatureBundleRef := "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/plugin.sigbundle"
	if installed.Metadata["source_id"] != "official" ||
		installed.Metadata["source.type"] != string(PackageSourceRegistry) ||
		installed.Metadata["source.class"] != string(PackageSourceClassOfficial) ||
		installed.Metadata["source.distribution"] != string(PackageDistributionRegistryRef) ||
		installed.Metadata["source.install_policy"] != string(PackageInstallAllow) ||
		installed.Metadata["source.unsigned_policy"] != string(PackageUnsignedBlock) ||
		installed.Metadata["source.downgrade_policy"] != string(PackageDowngradeBlock) ||
		installed.Metadata["source.policy_epoch"] != "1" ||
		installed.Metadata["source.key_rotation_epoch"] != "1" ||
		installed.Metadata["source.revocation_epoch"] != "1" ||
		installed.Metadata["source.assessed_at"] != "2026-07-07T00:00:00Z" ||
		installed.Metadata["release.metadata_signature_algorithm"] != "ed25519" ||
		installed.Metadata["release.metadata_signature_key_id"] != "official" ||
		installed.Metadata["release.metadata_signature_ref"] != wantMetadataSignatureRef ||
		installed.Metadata["release.package_signature_algorithm"] != "ed25519" ||
		installed.Metadata["release.package_signature_key_id"] != "official" ||
		installed.Metadata["release.package_signature_bundle_ref"] != wantPackageSignatureBundleRef ||
		installed.Metadata["trust.key_id"] != "official" {
		t.Fatalf("metadata = %#v", installed.Metadata)
	}
	if resolver.last.Action != PackageTrustActionInstall || resolver.last.ReleaseRef.PluginID != pkg.Manifest.PluginID() {
		t.Fatalf("resolver request mismatch: %#v", resolver.last)
	}
	if resolver.last.SourcePolicySnapshot.SourceClass != PackageSourceClassOfficial || !resolver.last.SourcePolicySnapshot.RequireSignature {
		t.Fatalf("resolver source policy mismatch: %#v", resolver.last.SourcePolicySnapshot)
	}
	if verifier.last.Action != PackageTrustActionInstall || verifier.last.LocalImport || verifier.last.Package.PackageHash != pkg.PackageHash {
		t.Fatalf("verifier request mismatch: %#v", verifier.last)
	}
	if verifier.last.SourcePolicySnapshot == nil || verifier.last.SourcePolicySnapshot.SourceClass != PackageSourceClassOfficial || !verifier.last.SourcePolicySnapshot.RequireSignature {
		t.Fatalf("verifier source policy mismatch: %#v", verifier.last.SourcePolicySnapshot)
	}
	if verifier.last.ReleaseRef == nil || verifier.last.ReleaseRef.PluginID != pkg.Manifest.PluginID() {
		t.Fatalf("verifier release ref mismatch: %#v", verifier.last.ReleaseRef)
	}
	if metadataVerifier.calls != 1 || metadataVerifier.last.ReleaseRef.PluginID != pkg.Manifest.PluginID() || len(metadataVerifier.last.ReleaseMetadataBytes) == 0 || len(metadataVerifier.last.ReleaseMetadataSignature) == 0 {
		t.Fatalf("metadata verifier request mismatch: calls=%d request=%#v", metadataVerifier.calls, metadataVerifier.last)
	}
	floor, err := h.adapters.Registry.GetSourceSecurityFloor(ctx, ref.SourceID)
	if err != nil {
		t.Fatalf("GetSourceSecurityFloor() error = %v", err)
	}
	if floor.PolicyEpoch != "1" || floor.KeyRotationEpoch != "1" || floor.RevocationEpoch != "1" || floor.SourcePolicySnapshotHash != installed.SourcePolicySnapshotHash {
		t.Fatalf("source security floor mismatch: %#v installed snapshot=%s", floor, installed.SourcePolicySnapshotHash)
	}
}

func TestInstallReleaseRefRejectsSourceSecurityFloorRollbackBeforeArtifactResolution(t *testing.T) {
	ctx := context.Background()
	v1Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	v1Pkg := readTestPackage(t, v1Bytes)
	v1Ref := releaseRefForPackage(t, "official", v1Pkg)
	v1Policy := sourcePolicyForRelease(v1Ref)
	setSourcePolicyEpochs(&v1Policy, "2")
	v1Release := releaseForPackage(v1Ref, v1Pkg)
	setReleaseSignatureEpochs(&v1Release, "2")
	setReleaseRefMetadataHash(t, &v1Ref, v1Release)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: v1Policy},
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForRelease(t, v1Ref, v1Release, v1Bytes)},
	})
	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: v1Ref, PluginInstanceID: "plugini_floor_v1"}); err != nil {
		t.Fatalf("InstallReleaseRef(v1) error = %v", err)
	}

	v2Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2"), "official")
	v2Pkg := readTestPackage(t, v2Bytes)
	v2Ref := releaseRefForPackage(t, "official", v2Pkg)
	artifactResolver := &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v2Ref, v2Pkg, v2Bytes)}
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v2Ref)}
	h.adapters.ReleaseArtifactResolver = artifactResolver

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: v2Ref, PluginInstanceID: "plugini_floor_v2"}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("InstallReleaseRef(rollback) error = %v, want ErrReleaseRefPolicyDenied", err)
	}
	if artifactResolver.calls != 0 {
		t.Fatalf("artifact resolver calls = %d, want 0 before rollback rejection", artifactResolver.calls)
	}
}

func TestInstallReleaseRefRejectsSourceRevocationMetadataSubstitutionBeforeArtifactResolution(t *testing.T) {
	ctx := context.Background()
	v1Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	v1Pkg := readTestPackage(t, v1Bytes)
	v1Ref := releaseRefForPackage(t, "official", v1Pkg)
	v1Policy := sourcePolicyForRelease(v1Ref)
	setSourcePolicyRevokedKeys(&v1Policy, []string{"previously-revoked"})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: v1Policy},
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v1Ref, v1Pkg, v1Bytes)},
	})
	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: v1Ref, PluginInstanceID: "plugini_floor_revoke_v1"}); err != nil {
		t.Fatalf("InstallReleaseRef(v1) error = %v", err)
	}

	v2Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2"), "official")
	v2Pkg := readTestPackage(t, v2Bytes)
	v2Ref := releaseRefForPackage(t, "official", v2Pkg)
	artifactResolver := &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v2Ref, v2Pkg, v2Bytes)}
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v2Ref)}
	h.adapters.ReleaseArtifactResolver = artifactResolver

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: v2Ref, PluginInstanceID: "plugini_floor_revoke_v2"}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("InstallReleaseRef(substituted revocation metadata) error = %v, want ErrReleaseRefPolicyDenied", err)
	}
	if artifactResolver.calls != 0 {
		t.Fatalf("artifact resolver calls = %d, want 0 before substitution rejection", artifactResolver.calls)
	}
}

func TestOpenSurfaceRejectsCurrentSourceSecurityFloorRollback(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourcePolicy := sourcePolicyForRelease(ref)
	setSourcePolicyEpochs(&sourcePolicy, "2")
	release := releaseForPackage(ref, pkg)
	setReleaseSignatureEpochs(&release, "2")
	setReleaseRefMetadataHash(t, &ref, release)
	sourceResolver := &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     sourceResolver,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForRelease(t, ref, release, packageBytes)},
	})
	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref, PluginInstanceID: "plugini_floor_open"})
	if err != nil {
		t.Fatalf("InstallReleaseRef() error = %v", err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}

	sourceResolver.snapshot = sourcePolicyForRelease(ref)
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "lifecycle.activity",
		SurfaceInstanceID: "surface_floor_rollback",
	}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("OpenSurface() error = %v, want ErrReleaseRefPolicyDenied", err)
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState after source rollback = %s, want disabled_by_policy", current.EnableState)
	}
}

func TestInstallReleaseRefRejectsRevokedReleaseSignatureKey(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourcePolicy := sourcePolicyForRelease(ref)
	sourcePolicy.TrustedKeyIDs = []string{"official", "revoker"}
	sourcePolicy.TrustedKeys = append(sourcePolicy.TrustedKeys, SourcePolicyTrustedKey{
		Algorithm:       pluginpkg.PackageSignatureAlgorithmEd25519,
		KeyID:           "revoker",
		PublicKeySHA256: strings.Repeat("b", 64),
		Usage:           []string{"revocation_metadata"},
		ValidFrom:       "2026-01-01T00:00:00Z",
		ValidUntil:      "2027-01-01T00:00:00Z",
		RevocationEpoch: "1",
	})
	setSourcePolicyRevokedKeys(&sourcePolicy, []string{"official"})
	sourcePolicy.RevocationEvidence.SignatureKeyID = "revoker"
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes)},
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsDigestMismatchWithoutRegistryMutation(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	ref.ExpectedHashes.PackageSHA256 = strings.Repeat("0", 64)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
	records, err := h.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("records after failed install = %#v", records)
	}
}

func TestInstallReleaseRefRejectsReleaseMetadataHashMismatchWithoutRegistryMutation(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	ref.ReleaseMetadataSHA256 = strings.Repeat("b", 64)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
	records, err := h.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("records after failed install = %#v", records)
	}
}

func TestInstallReleaseRefRejectsPackageChangedAfterMetadataResolvedWithoutRegistryMutation(t *testing.T) {
	ctx := context.Background()
	metadataBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	metadataPkg := readTestPackage(t, metadataBytes)
	ref := releaseRefForPackage(t, "official", metadataPkg)
	assetBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.1.0", "Lifecycle replaced"), "official")
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, metadataPkg, assetBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
	records, err := h.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("records after failed install = %#v", records)
	}
}

func TestInstallReleaseRefRejectsUnavailableSourcePolicyBeforeArtifactResolution(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourceResolver := &recordingReleaseSourcePolicyResolver{err: errors.New("revocation metadata unavailable")}
	artifactResolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseSourcePolicy:     sourceResolver,
		releaseArtifactResolver: artifactResolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); err == nil || !strings.Contains(err.Error(), "revocation metadata unavailable") {
		t.Fatalf("InstallReleaseRef() error = %v, want source policy error", err)
	}
	if sourceResolver.calls != 1 {
		t.Fatalf("source resolver calls = %d, want 1", sourceResolver.calls)
	}
	if artifactResolver.calls != 0 {
		t.Fatalf("artifact resolver calls = %d, want 0", artifactResolver.calls)
	}
	records, err := h.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("records after failed install = %#v", records)
	}
}

func TestInstallReleaseRefRejectsUnsafeArtifactPath(t *testing.T) {
	for _, artifactRef := range []string{
		"https://127.0.0.1/plugin.redevplugin",
		"%2e%2e/plugin.redevplugin",
		"plugins/%2e%2e/plugin.redevplugin",
	} {
		t.Run(artifactRef, func(t *testing.T) {
			ctx := context.Background()
			packageBytes := buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle")
			pkg := readTestPackage(t, packageBytes)
			ref := releaseRefForPackage(t, "official", pkg)
			release := releaseForPackage(ref, pkg)
			release.DistributionRef.ArtifactRef = artifactRef
			setReleaseRefMetadataHash(t, &ref, release)
			resolver := &recordingReleaseArtifactResolver{
				artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
			}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode:           true,
				localGenerated:          true,
				releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
				releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
				releaseArtifactResolver: resolver,
			})

			if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
				t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
			}
		})
	}
}

func TestInstallReleaseRefRejectsOfficialSourceWithoutSignatureRequirement(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourcePolicy := sourcePolicyForRelease(ref)
	sourcePolicy.RequireSignature = false
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsInvalidSourcePolicyTrustEvidence(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)

	for _, tc := range []struct {
		name   string
		mutate func(*SourcePolicySnapshot)
	}{
		{name: "non canonical policy epoch", mutate: func(snapshot *SourcePolicySnapshot) {
			snapshot.PolicyEpoch = "01"
		}},
		{name: "missing trusted key ids", mutate: func(snapshot *SourcePolicySnapshot) {
			snapshot.TrustedKeyIDs = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourcePolicy := sourcePolicyForRelease(ref)
			tc.mutate(&sourcePolicy)
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode:           true,
				localGenerated:          true,
				releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
				releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
				releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes)},
			})

			if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
				t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
			}
		})
	}
}

func TestInstallReleaseRefRejectsCommunitySourceWithoutSignatureRequirement(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "community", pkg)
	sourcePolicy := sourcePolicyForRelease(ref)
	sourcePolicy.SourceClass = PackageSourceClassCommunity
	sourcePolicy.RequireSignature = false
	sourcePolicy.UnsignedPolicy = PackageUnsignedReviewRequired
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsPublisherOutsideSourcePolicy(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourcePolicy := sourcePolicyForRelease(ref)
	sourcePolicy.AllowedPublishers = []string{"com.example.other"}
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRequiresSourcePolicyResolver(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseSourcePolicyRequired) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseSourcePolicyRequired", err)
	}
}

func TestInstallReleaseRefRejectsLocalImportDistribution(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.DistributionRef = PackageDistributionRef{Distribution: PackageDistributionLocalImport, ImportID: "local_import_1"}
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsMissingReleaseDistribution(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.DistributionRef.Distribution = ""
	setReleaseRefMetadataHash(t, &ref, release)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsReleaseDistributionImportID(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.DistributionRef.ImportID = "local_import_1"
	setReleaseRefMetadataHash(t, &ref, release)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRequiresCompleteHostCapabilityContractPins(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	baseRef := releaseRefForPackage(t, "official", pkg)

	t.Run("accepts complete host capability contract pins", func(t *testing.T) {
		ref := baseRef
		release := releaseForPackage(ref, pkg)
		release.HostRequirements = []HostRequirement{{
			HostID:         "example-host",
			MinHostVersion: "1.2.3",
			RequiredCapabilityContracts: []HostCapabilityRequirement{{
				CapabilityID:      "example.capability.resources",
				CapabilityVersion: "1.0.0",
				Contract: HostCapabilityContractRef{
					ContractID:            "example.resources.v1",
					ContractVersion:       "1.0.0",
					ArtifactRef:           "capabilities/example/resources/v1/contract.json",
					ArtifactSHA256:        strings.Repeat("1", 64),
					ManifestSHA256:        strings.Repeat("2", 64),
					SignatureRef:          "capabilities/example/resources/v1/contract.json.sig",
					SignatureSHA256:       strings.Repeat("6", 64),
					SignatureKeyID:        "official",
					CompatibilitySHA256:   strings.Repeat("3", 64),
					GeneratedClientSHA256: strings.Repeat("4", 64),
					NoticesSHA256:         strings.Repeat("5", 64),
				},
			}},
		}}
		setReleaseRefMetadataHash(t, &ref, release)
		metadataVerifier := &recordingReleaseMetadataVerifier{}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			developerMode:           true,
			localGenerated:          true,
			releaseMetadataVerifier: metadataVerifier,
			releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForRelease(t, ref, release, packageBytes)},
		})

		if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); err != nil {
			t.Fatalf("InstallReleaseRef() error = %v", err)
		}
		got := metadataVerifier.last.Release.HostRequirements[0].RequiredCapabilityContracts[0].Contract
		if got.GeneratedClientSHA256 != strings.Repeat("4", 64) ||
			got.SignatureKeyID != "official" ||
			got.SignatureSHA256 != strings.Repeat("6", 64) {
			t.Fatalf("host capability contract pins were not preserved: %#v", got)
		}
	})

	t.Run("rejects incomplete host capability contract pins", func(t *testing.T) {
		ref := baseRef
		release := releaseForPackage(ref, pkg)
		release.HostRequirements = []HostRequirement{{
			HostID: "example-host",
			RequiredCapabilityContracts: []HostCapabilityRequirement{{
				CapabilityID:      "example.capability.resources",
				CapabilityVersion: "1.0.0",
				Contract: HostCapabilityContractRef{
					ContractID:      "example.resources.v1",
					ContractVersion: "1.0.0",
					ArtifactRef:     "capabilities/example/resources/v1/contract.json",
					ArtifactSHA256:  strings.Repeat("1", 64),
					ManifestSHA256:  strings.Repeat("2", 64),
					SignatureRef:    "capabilities/example/resources/v1/contract.json.sig",
					SignatureSHA256: strings.Repeat("6", 64),
					SignatureKeyID:  "official",
					// GeneratedClientSHA256 is intentionally omitted.
					CompatibilitySHA256: strings.Repeat("3", 64),
					NoticesSHA256:       strings.Repeat("5", 64),
				},
			}},
		}}
		setReleaseRefMetadataHash(t, &ref, release)
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			developerMode:           true,
			localGenerated:          true,
			releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
			releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForRelease(t, ref, release, packageBytes)},
		})

		if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
			t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
		}
	})

	t.Run("rejects missing host capability contract signature hash", func(t *testing.T) {
		ref := baseRef
		release := releaseForPackage(ref, pkg)
		release.HostRequirements = []HostRequirement{{
			HostID: "example-host",
			RequiredCapabilityContracts: []HostCapabilityRequirement{{
				CapabilityID:      "example.capability.resources",
				CapabilityVersion: "1.0.0",
				Contract: HostCapabilityContractRef{
					ContractID:            "example.resources.v1",
					ContractVersion:       "1.0.0",
					ArtifactRef:           "capabilities/example/resources/v1/contract.json",
					ArtifactSHA256:        strings.Repeat("1", 64),
					ManifestSHA256:        strings.Repeat("2", 64),
					SignatureRef:          "capabilities/example/resources/v1/contract.json.sig",
					SignatureKeyID:        "official",
					CompatibilitySHA256:   strings.Repeat("3", 64),
					GeneratedClientSHA256: strings.Repeat("4", 64),
					NoticesSHA256:         strings.Repeat("5", 64),
				},
			}},
		}}
		setReleaseRefMetadataHash(t, &ref, release)
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			developerMode:           true,
			localGenerated:          true,
			releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
			releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForRelease(t, ref, release, packageBytes)},
		})

		if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
			t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
		}
	})
}

func TestInstallReleaseRefRejectsMissingPackageSignature(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsMissingReleaseMetadataSignature(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.ReleaseMetadataSignature = nil
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsMissingReleaseMetadataSourcePolicyEpoch(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.ReleaseMetadataSignature.SourcePolicyEpoch = ""
	setReleaseRefMetadataHash(t, &ref, release)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsMissingPackageSignatureMetadata(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.PackageSignature = nil
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsPackageSignatureRevocationEpochMismatch(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.PackageSignature.RevocationEpoch = "2"
	setReleaseRefMetadataHash(t, &ref, release)
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsUntrustedReleaseMetadataSignatureKey(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.ReleaseMetadataSignature.KeyID = "other"
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsUntrustedReleasePackageSignatureKey(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.PackageSignature.KeyID = "other"
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsSourcePolicyInstallReviewRequired(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourcePolicy := sourcePolicyForRelease(ref)
	sourcePolicy.InstallPolicy = PackageInstallReviewRequired
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefPolicyDenied", err)
	}
}

func TestInstallReleaseRefRejectsCanonicalMetadataOverride(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.Metadata = map[string]string{"metadata_signature_key_id": "spoofed"}
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsTrailingReleaseMetadataJSON(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	artifact := resolvedArtifactForPackage(t, ref, pkg, packageBytes)
	artifact.ReleaseMetadataBytes = append(append([]byte(nil), artifact.ReleaseMetadataBytes...), []byte("\n{}")...)
	resolver := &recordingReleaseArtifactResolver{artifact: artifact}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsMissingReleaseCompatibility(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	release := releaseForPackage(ref, pkg)
	release.Compatibility = nil
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForRelease(t, ref, release, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestInstallReleaseRefRejectsExpiredRevocationEvidence(t *testing.T) {
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourcePolicy := sourcePolicyForRelease(ref)
	sourcePolicy.RevocationEvidence.ExpiresAt = "2026-07-06T00:00:00Z"
	resolver := &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
		releaseArtifactResolver: resolver,
	})

	if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		ReleaseRef:       ref,
		PluginInstanceID: "plugini_expired_revocation",
		Now:              time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC),
	}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("InstallReleaseRef() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestUpdateReleaseRefRejectsDowngradeWhenSourcePolicyBlocks(t *testing.T) {
	ctx := context.Background()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
	})
	current, err := ImportLocalPackageBytes(ctx, h, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "0.9.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourcePolicy := sourcePolicyForRelease(ref)
	sourcePolicy.DowngradePolicy = PackageDowngradeBlock
	h.adapters.ReleaseArtifactResolver = &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy}

	if _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{PluginInstanceID: current.PluginInstanceID, ReleaseRef: ref}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("UpdateReleaseRef() error = %v, want ErrReleaseRefPolicyDenied", err)
	}
}

func TestUpdateReleaseRefSwitchesEnabledPluginAndRevokesOldSurfaceToken(t *testing.T) {
	ctx := context.Background()
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
	}
	metadataVerifier := &recordingReleaseMetadataVerifier{}
	verifier := &recordingPackageTrustVerifier{trustState: registry.TrustVerified, metadata: map[string]string{"trust.key_id": "official-v1"}}
	h, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		trustVerifier:           verifier,
		releaseMetadataVerifier: metadataVerifier,
		runtimeSupervisor:       runtime,
	})
	v1Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	v1Pkg := readTestPackage(t, v1Bytes)
	v1Ref := releaseRefForPackage(t, "official", v1Pkg)
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v1Ref)}
	h.adapters.ReleaseArtifactResolver = &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v1Ref, v1Pkg, v1Bytes)}
	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: v1Ref, PluginInstanceID: "plugini_release_update"})
	if err != nil {
		t.Fatalf("InstallReleaseRef(v1) error = %v", err)
	}
	installedPackageHash := installed.PackageHash
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "lifecycle.activity")

	verifier.metadata = map[string]string{"trust.key_id": "official-v2"}
	v2Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2"), "official")
	v2Pkg := readTestPackage(t, v2Bytes)
	v2Ref := releaseRefForPackage(t, "official", v2Pkg)
	sourceResolver := &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v2Ref)}
	artifactResolver := &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v2Ref, v2Pkg, v2Bytes)}
	h.adapters.ReleaseSourcePolicy = sourceResolver
	h.adapters.ReleaseArtifactResolver = artifactResolver

	updated, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{PluginInstanceID: installed.PluginInstanceID, ReleaseRef: v2Ref})
	if err != nil {
		t.Fatalf("UpdateReleaseRef() error = %v", err)
	}
	if updated.Version != "2.0.0" || updated.EnableState != registry.EnableEnabled || len(updated.VersionHistory) != 1 || updated.VersionHistory[0].Version != "1.0.0" {
		t.Fatalf("updated record mismatch: %#v", updated)
	}
	if verifier.last.Action != PackageTrustActionUpdate || verifier.last.CurrentRecord == nil || verifier.last.CurrentRecord.PackageHash != installedPackageHash {
		t.Fatalf("package verifier update request mismatch: %#v", verifier.last)
	}
	if len(sourceResolver.requests) == 0 || sourceResolver.requests[0].Action != PackageTrustActionUpdate || sourceResolver.requests[0].CurrentRecord == nil || sourceResolver.requests[0].CurrentRecord.PackageHash != installedPackageHash {
		t.Fatalf("source policy update request mismatch: %#v", sourceResolver.requests)
	}
	if artifactResolver.last.Action != PackageTrustActionUpdate || artifactResolver.last.CurrentRecord == nil || artifactResolver.last.CurrentRecord.PackageHash != installedPackageHash {
		t.Fatalf("artifact resolver update request mismatch: %#v", artifactResolver.last)
	}
	if metadataVerifier.last.Action != PackageTrustActionUpdate || metadataVerifier.last.CurrentRecord == nil || metadataVerifier.last.CurrentRecord.PackageHash != installedPackageHash {
		t.Fatalf("metadata verifier update request mismatch: %#v", metadataVerifier.last)
	}
	if runtime.revokeCalls != 1 || runtime.lastRevokedPlugin != installed.PluginInstanceID || runtime.lastRevokeEpoch != updated.RevokeEpoch {
		t.Fatalf("runtime revoke mismatch: calls=%d plugin=%q epoch=%d updated=%#v", runtime.revokeCalls, runtime.lastRevokedPlugin, runtime.lastRevokeEpoch, updated)
	}
	if len(surfaces.snapshots) == 0 || surfaces.snapshots[len(surfaces.snapshots)-1].ActiveFingerprint != updated.ActiveFingerprint {
		t.Fatalf("surface catalog not refreshed to updated fingerprint: %#v", surfaces.snapshots)
	}
	if _, err := h.surfaceTokens.ValidateGatewayToken(gateway.GatewayToken, bridge.Audience{
		PluginInstanceID:     updated.PluginInstanceID,
		ActiveFingerprint:    bootstrap.ActiveFingerprint,
		SurfaceInstanceID:    "surface_rpc",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_rpc",
	}, bridge.RevisionBinding{
		PolicyRevision:     updated.PolicyRevision,
		ManagementRevision: updated.ManagementRevision,
		RevokeEpoch:        updated.RevokeEpoch,
	}, now.Add(time.Minute)); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken(old token) error = %v, want ErrTokenRevoked", err)
	}
}

func TestUpdateReleaseRefFailureRestoresCurrentRecord(t *testing.T) {
	ctx := context.Background()
	surfaces := &failingSurfaceSink{err: errors.New("surface catalog unavailable")}
	verifier := &recordingPackageTrustVerifier{trustState: registry.TrustVerified, metadata: map[string]string{"trust.key_id": "official-v1"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		trustVerifier:  verifier,
	})
	h.adapters.SurfaceCatalog = surfaces
	v1Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	v1Pkg := readTestPackage(t, v1Bytes)
	v1Ref := releaseRefForPackage(t, "official", v1Pkg)
	h.adapters.ReleaseMetadataVerifier = &recordingReleaseMetadataVerifier{}
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v1Ref)}
	h.adapters.ReleaseArtifactResolver = &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v1Ref, v1Pkg, v1Bytes)}
	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: v1Ref, PluginInstanceID: "plugini_release_update_fail"})
	if err != nil {
		t.Fatalf("InstallReleaseRef(v1) error = %v", err)
	}
	surfaces.err = nil
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}

	verifier.metadata = map[string]string{"trust.key_id": "official-v2"}
	v2Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2"), "official")
	v2Pkg := readTestPackage(t, v2Bytes)
	v2Ref := releaseRefForPackage(t, "official", v2Pkg)
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v2Ref)}
	h.adapters.ReleaseArtifactResolver = &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v2Ref, v2Pkg, v2Bytes)}
	surfaces.err = errors.New("surface catalog unavailable")

	if _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{PluginInstanceID: enabled.PluginInstanceID, ReleaseRef: v2Ref}); err == nil || !strings.Contains(err.Error(), "surface catalog unavailable") {
		t.Fatalf("UpdateReleaseRef() error = %v, want surface catalog failure", err)
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != enabled.Version || current.PackageHash != enabled.PackageHash || current.ActiveFingerprint != enabled.ActiveFingerprint || len(current.VersionHistory) != len(enabled.VersionHistory) {
		t.Fatalf("registry record was not restored after failed update: current=%#v enabled=%#v", current, enabled)
	}
	if current.Metadata["trust.key_id"] != "official-v1" {
		t.Fatalf("restored metadata mismatch: %#v", current.Metadata)
	}
}

func TestUpdateReleaseRefRuntimeRevokeFailureRestoresCurrentRecord(t *testing.T) {
	ctx := context.Background()
	runtime := &recordingRuntimeSupervisor{
		health:    runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		revokeErr: errors.New("runtime revoke unavailable"),
	}
	verifier := &recordingPackageTrustVerifier{trustState: registry.TrustVerified, metadata: map[string]string{"trust.key_id": "official-v1"}}
	h, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		trustVerifier:      verifier,
		runtimeSupervisor:  runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
		storageBroker:      storage.NewMemoryBroker(),
	})
	v1Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	v1Pkg := readTestPackage(t, v1Bytes)
	v1Ref := releaseRefForPackage(t, "official", v1Pkg)
	h.adapters.ReleaseMetadataVerifier = &recordingReleaseMetadataVerifier{}
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v1Ref)}
	h.adapters.ReleaseArtifactResolver = &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v1Ref, v1Pkg, v1Bytes)}
	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: v1Ref, PluginInstanceID: "plugini_release_update_revoke_fail"})
	if err != nil {
		t.Fatalf("InstallReleaseRef(v1) error = %v", err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}

	verifier.metadata = map[string]string{"trust.key_id": "official-v2"}
	v2Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2"), "official")
	v2Pkg := readTestPackage(t, v2Bytes)
	v2Ref := releaseRefForPackage(t, "official", v2Pkg)
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v2Ref)}
	h.adapters.ReleaseArtifactResolver = &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v2Ref, v2Pkg, v2Bytes)}

	if _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{PluginInstanceID: enabled.PluginInstanceID, ReleaseRef: v2Ref}); err == nil || !strings.Contains(err.Error(), "runtime revoke unavailable") {
		t.Fatalf("UpdateReleaseRef() error = %v, want runtime revoke failure", err)
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != enabled.Version || current.PackageHash != enabled.PackageHash || current.ActiveFingerprint != enabled.ActiveFingerprint || current.Metadata["trust.key_id"] != "official-v1" {
		t.Fatalf("registry record was not restored after runtime revoke failure: current=%#v enabled=%#v", current, enabled)
	}
	if runtime.revokeCalls != 1 || runtime.lastRevokeEpoch <= enabled.RevokeEpoch {
		t.Fatalf("runtime revoke call mismatch: calls=%d epoch=%d enabled=%#v", runtime.revokeCalls, runtime.lastRevokeEpoch, enabled)
	}
	if len(surfaces.snapshots) == 0 || surfaces.snapshots[len(surfaces.snapshots)-1].ActiveFingerprint != enabled.ActiveFingerprint {
		t.Fatalf("surface catalog was not restored after runtime revoke failure: %#v", surfaces.snapshots)
	}
}

func TestUpdateUsesVerifierCurrentRecordAndMetadata(t *testing.T) {
	ctx := context.Background()
	verifier := &recordingPackageTrustVerifier{trustState: registry.TrustVerified, metadata: map[string]string{"trust.key_id": "old"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		trustVerifier:  verifier,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	verifier.trustState = registry.TrustVerified
	verifier.metadata = map[string]string{"trust.key_id": "new"}
	nextBytes := buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2")

	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(nextBytes),
		PackageSize:      int64(len(nextBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if verifier.last.Action != PackageTrustActionUpdate || verifier.last.CurrentRecord == nil || verifier.last.CurrentRecord.PackageHash != installed.PackageHash {
		t.Fatalf("verifier update request mismatch: %#v", verifier.last)
	}
	if updated.Metadata["trust.key_id"] != "new" {
		t.Fatalf("updated metadata = %#v", updated.Metadata)
	}
	if len(updated.VersionHistory) != 1 || updated.VersionHistory[0].Metadata["trust.key_id"] != "old" {
		t.Fatalf("version history metadata mismatch: %#v", updated.VersionHistory)
	}
}

func TestInstallAndUpdateRecordLifecycleStages(t *testing.T) {
	ctx := context.Background()
	stages := installstage.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		installStages:  stages,
	})
	v1 := buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle")
	v2 := buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2")
	now := time.Date(2026, 7, 2, 20, 0, 0, 0, time.UTC)

	installed, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
		PackageReader: bytes.NewReader(v1),
		PackageSize:   int64(len(v1)),
		Now:           now,
	})
	if err != nil {
		t.Fatalf("ImportLocalPackage() error = %v", err)
	}
	stageRecords, err := stages.List(ctx, installstage.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(stageRecords) != 1 ||
		stageRecords[0].Action != installstage.ActionInstall ||
		stageRecords[0].Status != installstage.StatusCommitted ||
		stageRecords[0].ResolvedTrust != string(registry.TrustUnsignedLocal) ||
		stageRecords[0].PackageHash != installed.PackageHash {
		t.Fatalf("install stage mismatch: %#v", stageRecords)
	}

	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(v2),
		PackageSize:      int64(len(v2)),
		Now:              now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("UpdateLocalPackage() error = %v", err)
	}
	stageRecords, err = stages.List(ctx, installstage.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(stageRecords) != 2 ||
		stageRecords[1].Action != installstage.ActionUpdate ||
		stageRecords[1].Status != installstage.StatusCommitted ||
		stageRecords[1].ResolvedTrust != string(registry.TrustUnsignedLocal) ||
		stageRecords[1].PackageHash != updated.PackageHash {
		t.Fatalf("update stage mismatch: %#v", stageRecords)
	}
}

func TestActiveFingerprintIncludesPackageCapabilitiesAndTrustEpochs(t *testing.T) {
	pkg := readTestPackage(t, buildVersionedRPCPackage(t, "1.0.0", "RPC"))
	trust := registry.TrustAssessment{
		TrustState:           registry.TrustVerified,
		TrustAssessmentEpoch: "trust_epoch_1",
		PolicyEpoch:          "1",
		RevocationEpoch:      "1",
	}
	first := activeFingerprintForPackage(pkg, "plugini_fingerprint", trust)
	if first == "" || first != activeFingerprintForPackage(pkg, "plugini_fingerprint", trust) {
		t.Fatalf("active fingerprint should be stable, got %q", first)
	}
	metadataChanged := trust
	metadataChanged.Metadata = map[string]string{"ignored": "metadata"}
	if got := activeFingerprintForPackage(pkg, "plugini_fingerprint", metadataChanged); got != first {
		t.Fatalf("metadata-only trust change affected active fingerprint: got %q want %q", got, first)
	}
	for name, mutate := range map[string]func(pluginpkg.Package, registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment){
		"package_hash": func(pkg pluginpkg.Package, trust registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment) {
			pkg.PackageHash = strings.Repeat("a", 64)
			return pkg, trust
		},
		"capability_contract": func(pkg pluginpkg.Package, trust registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment) {
			pkg.Manifest.CapabilityBindings = append(pkg.Manifest.CapabilityBindings, manifest.CapabilityBinding{BindingID: "extra", CapabilityID: "example.capability.extra", MinCapabilityVersion: "1.0.0"})
			return pkg, trust
		},
		"trust_epoch": func(pkg pluginpkg.Package, trust registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment) {
			trust.TrustAssessmentEpoch = "trust_epoch_2"
			return pkg, trust
		},
		"policy_epoch": func(pkg pluginpkg.Package, trust registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment) {
			trust.PolicyEpoch = "2"
			return pkg, trust
		},
		"revocation_epoch": func(pkg pluginpkg.Package, trust registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment) {
			trust.RevocationEpoch = "2"
			return pkg, trust
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedPkg, changedTrust := mutate(pkg, trust)
			if got := activeFingerprintForPackage(changedPkg, "plugini_fingerprint", changedTrust); got == first {
				t.Fatalf("active fingerprint did not change for %s", name)
			}
		})
	}
}

func TestOpenSurfaceRejectsCurrentSourcePolicyEpochAdvance(t *testing.T) {
	ctx := context.Background()
	h, sourceResolver, installed, ref := installReleaseRefLifecyclePlugin(t, testHostOptions{})
	now := stableRecentTestNow()
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	nextPolicy := sourcePolicyForRelease(ref)
	setSourcePolicyEpochs(&nextPolicy, "2")
	sourceResolver.snapshot = nextPolicy

	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "lifecycle.activity",
		SurfaceInstanceID: "surface_source_policy_advance",
		OwnerSessionHash:  "session_hash",
		OwnerUserHash:     "user_hash",
		Now:               now.Add(time.Second),
	}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("OpenSurface() error = %v, want ErrReleaseRefPolicyDenied", err)
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s, want disabled_by_policy", current.EnableState)
	}
}

func TestGrantPermissionRejectsCurrentSourcePolicyEpochAdvanceWithoutGrant(t *testing.T) {
	ctx := context.Background()
	permissionStore := permissions.NewMemoryStore()
	h, sourceResolver, installed, ref := installReleaseRefLifecyclePlugin(t, testHostOptions{permissions: permissionStore})
	nextPolicy := sourcePolicyForRelease(ref)
	setSourcePolicyEpochs(&nextPolicy, "2")
	sourceResolver.snapshot = nextPolicy

	if _, err := h.GrantPermission(ctx, GrantPermissionRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PermissionID:     "read",
		GrantedBy:        "tester",
		Now:              stableRecentTestNow(),
	}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("GrantPermission() error = %v, want ErrReleaseRefPolicyDenied", err)
	}
	grants, err := permissionStore.List(ctx, permissions.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("permission grants after failed source policy replay = %#v, want none", grants)
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.PolicyRevision != installed.PolicyRevision {
		t.Fatalf("PolicyRevision = %d, want %d", current.PolicyRevision, installed.PolicyRevision)
	}
	if current.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s, want disabled_by_policy", current.EnableState)
	}
}

func TestMintBridgeTokenRejectsCurrentSourcePolicyEpochAdvance(t *testing.T) {
	ctx := context.Background()
	h, sourceResolver, installed, ref := installReleaseRefLifecyclePlugin(t, testHostOptions{})
	now := stableRecentTestNow()
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.activity",
		SurfaceInstanceID:    "surface_source_policy_bridge",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if _, err := h.ExchangeAssetTicket(ctx, ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("ExchangeAssetTicket() error = %v", err)
	}
	nextPolicy := sourcePolicyForRelease(ref)
	setSourcePolicyEpochs(&nextPolicy, "2")
	sourceResolver.snapshot = nextPolicy
	handshake := bridge.Handshake{
		PluginID:          bootstrap.PluginID,
		SurfaceID:         bootstrap.SurfaceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		ActiveFingerprint: bootstrap.ActiveFingerprint,
		BridgeNonce:       bootstrap.BridgeNonce,
		UIProtocolVersion: "plugin-ui-v1",
	}

	if _, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_source_policy",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_source_policy"),
		Now:                       now.Add(3 * time.Second),
	}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("MintBridgeToken() error = %v, want ErrReleaseRefPolicyDenied", err)
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s, want disabled_by_policy", current.EnableState)
	}
}

func TestCurrentSourcePolicyFailureRevokesStorageHandleAndRuntime(t *testing.T) {
	ctx := context.Background()
	storageBroker := storage.NewMemoryBroker()
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		revokeResult: runtimeclient.RevokeResult{
			ClosedStorageHandleCount: 1,
		},
	}
	packageBytes := buildSignedReleasePackageBytes(t, buildStorageFixturePackage(t), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourceResolver := &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		releaseMetadataVerifier: &recordingReleaseMetadataVerifier{},
		releaseSourcePolicy:     sourceResolver,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
		},
		storageBroker:     storageBroker,
		runtimeSupervisor: runtime,
	})
	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		ReleaseRef:       ref,
		PluginInstanceID: "plugini_release_ref_policy_storage",
		Now:              stableRecentTestNow(),
	})
	if err != nil {
		t.Fatalf("InstallReleaseRef() error = %v", err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: stableRecentTestNow()})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	now := stableRecentTestNow().Add(time.Minute)
	handle, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
		PluginInstanceID:    enabled.PluginInstanceID,
		StoreID:             "db",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_a",
		Now:                 now,
		TTL:                 time.Minute,
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant() error = %v", err)
	}
	nextPolicy := sourcePolicyForRelease(ref)
	setSourcePolicyEpochs(&nextPolicy, "2")
	sourceResolver.snapshot = nextPolicy

	if _, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
		PluginInstanceID:    enabled.PluginInstanceID,
		StoreID:             "db",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_2",
		RuntimeShardID:      "runtime_shard_a",
		Now:                 now.Add(time.Second),
	}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
		t.Fatalf("MintStorageHandleGrant() after source policy advance error = %v, want ErrReleaseRefPolicyDenied", err)
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s, want disabled_by_policy", current.EnableState)
	}
	if runtime.revokeCalls != 1 || runtime.lastRevokedPlugin != enabled.PluginInstanceID || runtime.lastRevokeEpoch != current.RevokeEpoch {
		t.Fatalf("runtime revoke mismatch: calls=%d plugin=%q epoch=%d current=%#v", runtime.revokeCalls, runtime.lastRevokedPlugin, runtime.lastRevokeEpoch, current)
	}
	if _, err := h.surfaceTokens.ValidateHandleGrant(bridge.ValidateHandleGrantRequest{
		HandleGrantToken: handle.HandleGrant.HandleGrantToken,
		Audience: bridge.Audience{
			PluginInstanceID:    enabled.PluginInstanceID,
			ActiveFingerprint:   enabled.ActiveFingerprint,
			RuntimeInstanceID:   "runtime_1",
			RuntimeGenerationID: "runtime_gen_1",
			RuntimeShardID:      "runtime_shard_a",
			HandleID:            "storage:db",
			Method:              "storage.sqlite",
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision:     enabled.PolicyRevision,
			ManagementRevision: enabled.ManagementRevision,
			RevokeEpoch:        enabled.RevokeEpoch,
		},
		Now: now.Add(2 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateHandleGrant() after source policy failure error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatalf("missing runtime capability revocation audit event: %#v", audits.events)
	}
}

func TestUnsignedLocalPolicyFailureRevokesStorageHandleAndRuntime(t *testing.T) {
	ctx := context.Background()
	storageBroker := storage.NewMemoryBroker()
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		revokeResult: runtimeclient.RevokeResult{
			ClosedStorageHandleCount: 1,
		},
	}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		storageBroker:     storageBroker,
		runtimeSupervisor: runtime,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: stableRecentTestNow()})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	now := stableRecentTestNow().Add(time.Minute)
	handle, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
		PluginInstanceID:    enabled.PluginInstanceID,
		StoreID:             "db",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_a",
		Now:                 now,
		TTL:                 time.Minute,
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant() error = %v", err)
	}
	h.adapters.Policy = policyAdapter{developerMode: false, localGenerated: false}

	if _, err := h.MintStorageHandleGrant(ctx, MintStorageHandleGrantRequest{
		PluginInstanceID:    enabled.PluginInstanceID,
		StoreID:             "db",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_2",
		RuntimeShardID:      "runtime_shard_a",
		Now:                 now.Add(time.Second),
	}); err == nil || !strings.Contains(err.Error(), "unsigned local plugins require developer mode") {
		t.Fatalf("MintStorageHandleGrant() after unsigned local policy failure error = %v, want policy failure", err)
	}
	current, err := h.adapters.Registry.GetPlugin(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s, want disabled_by_policy", current.EnableState)
	}
	if runtime.revokeCalls != 1 || runtime.lastRevokedPlugin != enabled.PluginInstanceID || runtime.lastRevokeEpoch != current.RevokeEpoch {
		t.Fatalf("runtime revoke mismatch: calls=%d plugin=%q epoch=%d current=%#v", runtime.revokeCalls, runtime.lastRevokedPlugin, runtime.lastRevokeEpoch, current)
	}
	if _, err := h.surfaceTokens.ValidateHandleGrant(bridge.ValidateHandleGrantRequest{
		HandleGrantToken: handle.HandleGrant.HandleGrantToken,
		Audience: bridge.Audience{
			PluginInstanceID:    enabled.PluginInstanceID,
			ActiveFingerprint:   enabled.ActiveFingerprint,
			RuntimeInstanceID:   "runtime_1",
			RuntimeGenerationID: "runtime_gen_1",
			RuntimeShardID:      "runtime_shard_a",
			HandleID:            "storage:db",
			Method:              "storage.sqlite",
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision:     enabled.PolicyRevision,
			ManagementRevision: enabled.ManagementRevision,
			RevokeEpoch:        enabled.RevokeEpoch,
		},
		Now: now.Add(2 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateHandleGrant() after unsigned local policy failure error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatalf("missing runtime capability revocation audit event: %#v", audits.events)
	}
}

func TestInstallTrustFailureMarksLifecycleStageFailed(t *testing.T) {
	ctx := context.Background()
	stages := installstage.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		installStages:  stages,
		trustVerifier:  &recordingPackageTrustVerifier{err: errors.New("signature revoked")},
	})
	packageBytes := buildFixturePackage(t)
	if _, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
		PackageReader: bytes.NewReader(packageBytes),
		PackageSize:   int64(len(packageBytes)),
	}); err == nil {
		t.Fatal("ImportLocalPackage() expected trust failure")
	}
	stageRecords, err := stages.List(ctx, installstage.ListRequest{Status: installstage.StatusFailed})
	if err != nil {
		t.Fatal(err)
	}
	if len(stageRecords) != 1 || stageRecords[0].ErrorCode != "trust_failed" || !strings.Contains(stageRecords[0].ErrorMessage, "signature revoked") {
		t.Fatalf("failed stage mismatch: %#v", stageRecords)
	}
	if _, err := h.adapters.Registry.GetPlugin(ctx, stageRecords[0].PluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("GetPlugin() after failed install error = %v, want ErrNotFound", err)
	}
}

func TestSurfaceBridgeLifecycle(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := ImportLocalPackageBytes(context.Background(), host, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatal(err)
	}

	bootstrap, err := host.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.activity",
		SurfaceInstanceID:    "surface_lifecycle",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if bootstrap.AssetTicket == "" || bootstrap.BridgeNonce == "" {
		t.Fatalf("bootstrap missing ticket/nonce: %#v", bootstrap)
	}

	if _, err := host.ExchangeAssetTicket(context.Background(), ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("ExchangeAssetTicket() error = %v", err)
	}

	handshake := bridge.Handshake{
		PluginID:          bootstrap.PluginID,
		SurfaceID:         bootstrap.SurfaceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		ActiveFingerprint: bootstrap.ActiveFingerprint,
		BridgeNonce:       bootstrap.BridgeNonce,
		UIProtocolVersion: "plugin-ui-v1",
	}
	gateway, err := host.MintBridgeToken(context.Background(), MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_channel",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_channel"),
		Now:                       now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}
	if gateway.GatewayToken == "" {
		t.Fatalf("gateway token is empty: %#v", gateway)
	}
}

func TestOpenSurfaceRegistersBrowserOrigin(t *testing.T) {
	browserSite := browsersite.NewMemoryStore()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		browserSite:    browserSite,
	})
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatal(err)
	}

	bootstrap, err := h.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.activity",
		SurfaceInstanceID:    "surface_lifecycle_browser",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		SandboxOrigin:        "https://plg-lifecycle.sandbox.redevplugin.local",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	origins, err := browserSite.ListOrigins(context.Background(), browsersite.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 1 {
		t.Fatalf("registered origins = %#v", origins)
	}
	origin := origins[0]
	if origin.State != browsersite.StateActive ||
		origin.PluginID != installed.PluginID ||
		origin.ActiveFingerprint != installed.ActiveFingerprint ||
		origin.SurfaceID != "lifecycle.activity" ||
		origin.SurfaceInstanceID != bootstrap.SurfaceInstanceID ||
		origin.OwnerSessionHash != "owner_session_hash" ||
		origin.OwnerUserHash != "owner_user_hash" ||
		origin.Origin != "https://plg-lifecycle.sandbox.redevplugin.local" {
		t.Fatalf("registered origin mismatch: %#v", origin)
	}
	if !audits.hasEvent("plugin.browser_origin.registered") {
		t.Fatalf("missing browser origin audit event: %#v", audits.events)
	}
}

func TestReadSurfaceAssetRequiresAssetSession(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.activity",
		SurfaceInstanceID:    "surface_asset",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession: "not-a-session",
		AssetPath:    "ui/index.html",
		Now:          now.Add(2 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenInvalid) {
		t.Fatalf("ReadSurfaceAsset() error = %v, want ErrTokenInvalid", err)
	}
	session, err := h.ExchangeAssetTicket(context.Background(), ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession:   session.AssetSession,
		AssetSessionID: session.AssetSessionID,
		AssetPath:      "ui/index.html",
		Now:            now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("ReadSurfaceAsset() error = %v", err)
	}
	if string(asset.Content) != "<!doctype html><title>Plugin</title>" || asset.Session.SurfaceInstanceID != bootstrap.SurfaceInstanceID {
		t.Fatalf("asset mismatch: session=%#v entry=%#v content=%q", asset.Session, asset.Entry, string(asset.Content))
	}
	if _, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession:   session.AssetSession,
		AssetSessionID: "asset_session_other",
		AssetPath:      "ui/index.html",
		Now:            now.Add(3 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("ReadSurfaceAsset(wrong session id) error = %v, want ErrTokenAudience", err)
	}
}

func TestOpenSurfaceRequiresEnabledPlugin(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(context.Background(), host, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SurfaceID:        "lifecycle.activity",
	}); err == nil {
		t.Fatal("OpenSurface() expected disabled plugin error")
	}
}

func TestCallPluginMethodDispatchesCapability(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
		Params:               map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.Data == nil {
		t.Fatalf("CallPluginMethod() result missing data: %#v", result)
	}
	if capabilityAdapter.last.CapabilityID != "example.capability.echo" ||
		capabilityAdapter.last.BindingID != "echo" ||
		capabilityAdapter.last.Method != "echo.ping" ||
		capabilityAdapter.last.TargetMethod != "echo.ping" ||
		capabilityAdapter.last.PluginInstanceID != installed.PluginInstanceID ||
		capabilityAdapter.last.BridgeChannelID != "bridge_rpc" {
		t.Fatalf("capability invocation mismatch: %#v", capabilityAdapter.last)
	}
	if !audits.hasEvent("plugin.method.called") {
		t.Fatalf("missing method audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodRedactsCapabilityResponseData(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{
		"containers": []any{
			map[string]any{
				"id":    "container_1",
				"image": "redis:7",
				"env": []any{
					"PATH=/usr/bin",
					"REDIS_PASSWORD=plaintext-password",
				},
				"labels": map[string]any{
					"com.example.owner":  "platform",
					"com.example.secret": "label-secret",
				},
				"mounts": []any{
					map[string]any{"source": "/srv/cache", "target": "/cache"},
					map[string]any{"source": "/run/secrets/redis_password", "target": "/run/secrets/redis_password"},
				},
			},
		},
		"token_id":   "display_token_id",
		"secret_ref": "redis_password",
	}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	raw, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, leaked := range []string{"plaintext-password", "label-secret", "/run/secrets/redis_password"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("capability response leaked %q: %s", leaked, body)
		}
	}
	for _, kept := range []string{"PATH=/usr/bin", "platform", "/srv/cache", "display_token_id", "redis_password"} {
		if !strings.Contains(body, kept) {
			t.Fatalf("capability response dropped safe value %q: %s", kept, body)
		}
	}
}

func TestCallPluginMethodRequiresGrantedBindingPermissions(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGatewayWithoutPermissions(t, h, buildRPCFixturePackage(t), "rpc.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
	}
	if _, err := h.CallPluginMethod(context.Background(), call); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("CallPluginMethod() without grant error = %v, want ErrPermissionDenied", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called before permission grant: %d", capabilityAdapter.calls)
	}

	beforeGrant, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.GrantPermission(context.Background(), GrantPermissionRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PermissionID:     "read",
		GrantedBy:        "tester",
	}); err != nil {
		t.Fatalf("GrantPermission() error = %v", err)
	}
	afterGrant, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if afterGrant.PolicyRevision <= beforeGrant.PolicyRevision || afterGrant.RevokeEpoch != beforeGrant.RevokeEpoch {
		t.Fatalf("grant revision mismatch: before=%#v after=%#v", beforeGrant, afterGrant)
	}
	if _, err := h.CallPluginMethod(context.Background(), call); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("CallPluginMethod() with stale token error = %v, want ErrTokenRevoked", err)
	}
	_, freshGateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.activity")
	call.GatewayToken = freshGateway.GatewayToken
	if _, err := h.CallPluginMethod(context.Background(), call); err != nil {
		t.Fatalf("CallPluginMethod() after grant error = %v", err)
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("capability adapter calls = %d, want 1", capabilityAdapter.calls)
	}

	beforeRevoke, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.RevokePermission(context.Background(), RevokePermissionRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PermissionID:     "read",
		RevokedBy:        "tester",
		Reason:           "test revoke",
	}); err != nil {
		t.Fatalf("RevokePermission() error = %v", err)
	}
	afterRevoke, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if afterRevoke.PolicyRevision <= beforeRevoke.PolicyRevision || afterRevoke.RevokeEpoch <= beforeRevoke.RevokeEpoch {
		t.Fatalf("revoke revision mismatch: before=%#v after=%#v", beforeRevoke, afterRevoke)
	}
	if _, err := h.CallPluginMethod(context.Background(), call); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("CallPluginMethod() after revoke with stale token error = %v, want ErrTokenRevoked", err)
	}
	_, freshGateway = openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.activity")
	call.GatewayToken = freshGateway.GatewayToken
	if _, err := h.CallPluginMethod(context.Background(), call); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("CallPluginMethod() after revoke error = %v, want ErrPermissionDenied", err)
	}
	if !audits.hasEvent("plugin.permission.granted") || !audits.hasEvent("plugin.permission.revoked") {
		t.Fatalf("missing permission audit events: %#v", audits.events)
	}
}

func TestRevokePermissionRevokesRuntimeCapabilities(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		revokeResult: runtimeclient.RevokeResult{
			ClosedActorCount:         2,
			ClosedSocketCount:        3,
			ClosedStreamCount:        4,
			ClosedStorageHandleCount: 5,
		},
	}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
		runtimeSupervisor: runtime,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")
	if _, err := h.RevokePermission(context.Background(), RevokePermissionRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PermissionID:     "read",
		RevokedBy:        "tester",
		Reason:           "test revoke",
	}); err != nil {
		t.Fatalf("RevokePermission() error = %v", err)
	}
	updated, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.revokeCalls != 1 || runtime.lastRevokedPlugin != installed.PluginInstanceID || runtime.lastRevokeEpoch != updated.RevokeEpoch {
		t.Fatalf("runtime revoke mismatch: calls=%d plugin=%q epoch=%d updated=%#v", runtime.revokeCalls, runtime.lastRevokedPlugin, runtime.lastRevokeEpoch, updated)
	}
	if _, err := h.surfaceTokens.ValidateGatewayToken(gateway.GatewayToken, bridge.Audience{
		PluginInstanceID:     installed.PluginInstanceID,
		ActiveFingerprint:    installed.ActiveFingerprint,
		SurfaceInstanceID:    "surface_rpc",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_rpc",
	}, bridge.RevisionBinding{
		PolicyRevision:     installed.PolicyRevision,
		ManagementRevision: installed.ManagementRevision,
		RevokeEpoch:        installed.RevokeEpoch,
	}, time.Now().UTC()); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() after permission revoke error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatalf("missing runtime capability revocation audit event: %#v", audits.events)
	}
	event, ok := audits.lastEvent("plugin.runtime_capabilities.revoked")
	if !ok {
		t.Fatalf("missing runtime capability revocation audit event: %#v", audits.events)
	}
	assertAuditDetail(t, event, "closed_actor_count", 2)
	assertAuditDetail(t, event, "closed_socket_count", 3)
	assertAuditDetail(t, event, "closed_stream_count", 4)
	assertAuditDetail(t, event, "closed_storage_handle_count", 5)
}

func TestCallPluginMethodRegistersOperation(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{OperationID: "op_pull_1"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "images.pull",
		Params:               map[string]any{"image": "alpine:latest"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.OperationID != "op_pull_1" {
		t.Fatalf("operation id mismatch: %#v", result)
	}
	registered, err := h.GetOperation(context.Background(), "op_pull_1")
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if registered.PluginInstanceID != installed.PluginInstanceID ||
		registered.Method != "images.pull" ||
		registered.Effect != "execute" ||
		registered.Execution != string(manifest.MethodExecutionOperation) ||
		registered.DisableBehavior != operation.DisableBehaviorCancel ||
		registered.UninstallBehavior != operation.UninstallBehaviorCancelThenBlockDelete {
		t.Fatalf("registered operation mismatch: %#v", registered)
	}
	if !audits.hasEvent("plugin.operation.started") {
		t.Fatalf("missing operation audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodRegistersStream(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{StreamID: "stream_logs_1"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "logs.tail",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.StreamID != "stream_logs_1" || result.StreamTicket == "" || result.StreamTicketID == "" {
		t.Fatalf("CallPluginMethod() stream result mismatch: %#v", result)
	}
	if _, err := h.AppendStreamEvent(context.Background(), AppendStreamEventRequest{
		StreamID: "stream_logs_1",
		Data:     []byte("line 1"),
	}); err != nil {
		t.Fatalf("AppendStreamEvent() error = %v", err)
	}
	if _, err := h.ReadStream(context.Background(), ReadStreamRequest{StreamID: "stream_logs_1"}); !errors.Is(err, ErrStreamTicketRequired) {
		t.Fatalf("ReadStream() without ticket error = %v, want %v", err, ErrStreamTicketRequired)
	}
	streamResult, err := h.ReadStream(context.Background(), ReadStreamRequest{StreamID: "stream_logs_1", StreamTicket: result.StreamTicket})
	if err != nil {
		t.Fatalf("ReadStream() error = %v", err)
	}
	if streamResult.Record.Method != "logs.tail" || len(streamResult.Events) != 1 || string(streamResult.Events[0].Data) != "line 1" {
		t.Fatalf("stream read mismatch: %#v", streamResult)
	}
	if _, err := h.ReadStream(context.Background(), ReadStreamRequest{StreamID: "stream_logs_1", StreamTicket: result.StreamTicket}); !errors.Is(err, bridge.ErrTokenReplay) {
		t.Fatalf("ReadStream() replay error = %v, want %v", err, bridge.ErrTokenReplay)
	}
	if !audits.hasEvent("plugin.stream.started") {
		t.Fatalf("missing stream audit event: %#v", audits.events)
	}
}

func TestDisableTransitionsOpenStreamsAndRevokesStreamTickets(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{StreamID: "stream_disable_1"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.activity")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "logs.tail",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if _, err := h.AppendStreamEvent(context.Background(), AppendStreamEventRequest{
		StreamID: "stream_disable_1",
		Data:     []byte("line before disable"),
	}); err != nil {
		t.Fatalf("AppendStreamEvent() before disable error = %v", err)
	}

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy"}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}

	assertHostStreamStatus(t, h, "stream_disable_1", stream.StatusOrphanedDisabled)
	if _, err := h.AppendStreamEvent(context.Background(), AppendStreamEventRequest{
		StreamID: "stream_disable_1",
		Data:     []byte("line after disable"),
	}); !errors.Is(err, stream.ErrStreamClosed) {
		t.Fatalf("AppendStreamEvent() after disable error = %v, want %v", err, stream.ErrStreamClosed)
	}
	if _, err := h.ReadStream(context.Background(), ReadStreamRequest{
		StreamID:     "stream_disable_1",
		StreamTicket: result.StreamTicket,
	}); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ReadStream() after disable error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if !audits.hasEvent("plugin.streams.disabled_transitioned") {
		t.Fatalf("missing disabled stream transition audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodDispatchesWorkerRoute(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		result: capability.Result{Data: map[string]any{"from_worker": true}},
	}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeSupervisor:  runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params:               map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() worker error = %v", err)
	}
	if result.Data == nil || runtime.calls != 1 {
		t.Fatalf("worker result/calls mismatch: result=%#v calls=%d", result, runtime.calls)
	}
	current, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatalf("GetPlugin() after worker call error = %v", err)
	}
	assertRuntimeLeaseField(t, "lease_token", runtime.lastLease.LeaseToken != "")
	assertRuntimeLeaseField(t, "lease_id_prefix", strings.HasPrefix(runtime.lastLease.LeaseID, "lease_"))
	assertRuntimeLeaseField(t, "token_id_prefix", strings.HasPrefix(runtime.lastLease.TokenID, "rel_"))
	assertRuntimeLeaseField(t, "distinct_token_id", runtime.lastLease.TokenID != runtime.lastLease.LeaseID)
	assertRuntimeLeaseField(t, "lease_nonce", runtime.lastLease.LeaseNonce != "")
	assertRuntimeLeaseEqual(t, "plugin_id", runtime.lastLease.PluginID, current.PluginID)
	assertRuntimeLeaseEqual(t, "plugin_version", runtime.lastLease.PluginVersion, current.Version)
	assertRuntimeLeaseEqual(t, "active_fingerprint", runtime.lastLease.ActiveFingerprint, current.ActiveFingerprint)
	assertRuntimeLeaseEqual(t, "surface_instance_id", runtime.lastLease.SurfaceInstanceID, "surface_rpc")
	assertRuntimeLeaseEqual(t, "owner_session_hash", runtime.lastLease.OwnerSessionHash, "session_hash")
	assertRuntimeLeaseEqual(t, "owner_user_hash", runtime.lastLease.OwnerUserHash, "user_hash")
	assertRuntimeLeaseEqual(t, "session_channel_id_hash", runtime.lastLease.SessionChannelIDHash, "channel_hash")
	assertRuntimeLeaseEqual(t, "bridge_channel_id", runtime.lastLease.BridgeChannelID, "bridge_rpc")
	assertRuntimeLeaseEqual(t, "runtime_instance_id", runtime.lastLease.RuntimeInstanceID, "runtime_1")
	assertRuntimeLeaseEqual(t, "runtime_generation_id", runtime.lastLease.RuntimeGenerationID, "runtime_gen_1")
	assertRuntimeLeaseEqual(t, "ipc_channel_id", runtime.lastLease.IPCChannelID, "ipc_1")
	assertRuntimeLeaseEqual(t, "connection_nonce", runtime.lastLease.ConnectionNonce, "connection_nonce_1234567890")
	assertRuntimeLeaseEqual(t, "method", runtime.lastLease.Method, "worker.echo")
	assertRuntimeLeaseEqual(t, "effect", runtime.lastLease.Effect, "read")
	assertRuntimeLeaseEqual(t, "execution", runtime.lastLease.Execution, "sync")
	assertRuntimeLeaseField(t, "target_descriptor_hashes", len(runtime.lastLease.TargetDescriptorHashes) >= 4)
	assertRuntimeLeaseField(t, "memory_limit", runtime.lastLease.Limits.MemoryBytes != 0)
	assertRuntimeLeaseEqual(t, "policy_revision", runtime.lastLease.PolicyRevision, current.PolicyRevision)
	assertRuntimeLeaseEqual(t, "management_revision", runtime.lastLease.ManagementRevision, current.ManagementRevision)
	assertRuntimeLeaseEqual(t, "revoke_epoch", runtime.lastLease.RevokeEpoch, current.RevokeEpoch)
	assertRuntimeLeaseField(t, "issued_at", !runtime.lastLease.IssuedAt.IsZero())
	assertRuntimeLeaseField(t, "issued_at_unix_ms", runtime.lastLease.IssuedAtUnixMillis != 0)
	assertRuntimeLeaseEqual(t, "runtime method", runtime.lastMethod, "worker.echo")
	var payload WorkerInvocationPayload
	if err := json.Unmarshal(runtime.lastPayload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.WorkerID != "echo_worker" ||
		payload.Export != "redevplugin_worker_invoke" ||
		payload.Artifact != "workers/echo.wasm" ||
		payload.PackageHash != installed.PackageHash ||
		payload.ArtifactSHA256 == "" ||
		payload.RuntimeInstanceID != "runtime_1" ||
		payload.RuntimeGenerationID != "runtime_gen_1" ||
		payload.Params["message"] != "hello" ||
		payload.PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("worker payload mismatch: %#v", payload)
	}
	asset, err := h.adapters.Assets.ReadAsset(context.Background(), installed.PackageHash, "workers/echo.wasm")
	if err != nil {
		t.Fatal(err)
	}
	if payload.ArtifactSHA256 != asset.Entry.SHA256 {
		t.Fatalf("artifact sha256 = %s, want %s", payload.ArtifactSHA256, asset.Entry.SHA256)
	}
	if !audits.hasEvent("plugin.method.called") {
		t.Fatalf("missing method audit event: %#v", audits.events)
	}
	leaseAudit, ok := audits.lastEvent("plugin.runtime.lease.issued")
	if !ok {
		t.Fatalf("missing runtime lease audit event: %#v", audits.events)
	}
	if leaseAudit.PluginID != installed.PluginID ||
		leaseAudit.PluginInstanceID != installed.PluginInstanceID ||
		leaseAudit.SurfaceInstanceID != "surface_rpc" {
		t.Fatalf("runtime lease audit identity mismatch: %#v", leaseAudit)
	}
	assertAuditDetail(t, leaseAudit, "lease_id", runtime.lastLease.LeaseID)
	assertAuditDetail(t, leaseAudit, "token_id", runtime.lastLease.TokenID)
	assertAuditDetail(t, leaseAudit, "method", "worker.echo")
	assertAuditDetail(t, leaseAudit, "effect", "read")
	assertAuditDetail(t, leaseAudit, "execution", "sync")
	assertAuditDetail(t, leaseAudit, "runtime_instance_id", "runtime_1")
	assertAuditDetail(t, leaseAudit, "runtime_generation_id", "runtime_gen_1")
	assertAuditDetail(t, leaseAudit, "ipc_channel_id", "ipc_1")
	assertAuditDetail(t, leaseAudit, "policy_revision", current.PolicyRevision)
	assertAuditDetail(t, leaseAudit, "management_revision", current.ManagementRevision)
	assertAuditDetail(t, leaseAudit, "revoke_epoch", current.RevokeEpoch)
	assertAuditDetail(t, leaseAudit, "expires_at_unix_ms", runtime.lastLease.ExpiresAt.UnixMilli())
	if hashes, ok := leaseAudit.Details["target_descriptor_hashes"].([]string); !ok || len(hashes) < 4 {
		t.Fatalf("runtime lease audit target_descriptor_hashes mismatch: %#v", leaseAudit.Details)
	}
	if _, leaked := leaseAudit.Details["lease_token"]; leaked {
		t.Fatalf("runtime lease audit leaked cleartext token: %#v", leaseAudit.Details)
	}
}

func TestCallPluginMethodWorkerPayloadIncludesEmptyParams(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		result: capability.Result{Data: map[string]any{"from_worker": true}},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeSupervisor:  runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.activity")

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
	}); err != nil {
		t.Fatalf("CallPluginMethod() worker error = %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(runtime.lastPayload, &raw); err != nil {
		t.Fatal(err)
	}
	params, ok := raw["params"].(map[string]any)
	if !ok || len(params) != 0 {
		t.Fatalf("worker payload params = %#v, want empty object", raw["params"])
	}
}

func TestCallPluginMethodWorkerRouteRequiresRuntimeSupervisor(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.activity")

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected runtime supervisor error")
	}
}

func TestCallPluginMethodWorkerRouteFailsClosedAfterDisable(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		result: capability.Result{Data: map[string]any{"from_worker": true}},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeSupervisor:  runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.activity")

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy"}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params:               map[string]any{"message": "after disable"},
	}); err == nil {
		t.Fatal("CallPluginMethod() after disable expected fail-closed error")
	}
	if runtime.calls != 0 {
		t.Fatalf("runtime invoked after disable: calls=%d lease=%#v", runtime.calls, runtime.lastLease)
	}
}

func TestCallPluginMethodWorkerRouteFailsClosedAfterUninstall(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		result: capability.Result{Data: map[string]any{"from_worker": true}},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeSupervisor:  runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.activity")

	if _, err := h.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "worker.echo",
		Params:               map[string]any{"message": "after uninstall"},
	}); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("CallPluginMethod() after uninstall error = %v, want %v", err, registry.ErrNotFound)
	}
	if runtime.calls != 0 {
		t.Fatalf("runtime invoked after uninstall: calls=%d lease=%#v", runtime.calls, runtime.lastLease)
	}
}

func TestCallPluginMethodDispatchesCoreAction(t *testing.T) {
	coreAdapter := &recordingCoreActionAdapter{result: capability.Result{Data: map[string]any{"opened": true}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		coreActions:    coreAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionFixturePackage(t), "core.activity")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "core.open",
		Params:               map[string]any{"target": "settings"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.Data == nil {
		t.Fatalf("CallPluginMethod() result missing data: %#v", result)
	}
	if coreAdapter.last.TargetMethod != "example.open_settings" ||
		coreAdapter.last.Method != "core.open" ||
		coreAdapter.last.PluginInstanceID != installed.PluginInstanceID ||
		coreAdapter.last.Arguments["target"] != "settings" {
		t.Fatalf("core action invocation mismatch: %#v", coreAdapter.last)
	}
	if !audits.hasEvent("plugin.method.called") {
		t.Fatalf("missing method audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodCoreActionRequiresAdapter(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionFixturePackage(t), "core.activity")

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "core.open",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected missing core action adapter error")
	}
}

func TestCallPluginMethodValidatesExecutionResultContract(t *testing.T) {
	cases := []struct {
		name         string
		packageBytes []byte
		method       string
		result       capability.Result
	}{
		{
			name:         "operation requires operation id",
			packageBytes: buildOperationRPCFixturePackage(t),
			method:       "images.pull",
			result:       capability.Result{Data: map[string]any{"started": true}},
		},
		{
			name:         "sync rejects async handle",
			packageBytes: buildRPCFixturePackage(t),
			method:       "echo.ping",
			result:       capability.Result{OperationID: "op_unexpected"},
		},
		{
			name:         "subscription requires stream or operation id",
			packageBytes: buildSubscriptionRPCFixturePackage(t),
			method:       "logs.tail",
			result:       capability.Result{Data: map[string]any{"started": true}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capabilityAdapter := &recordingCapabilityAdapter{result: tc.result}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode:     true,
				localGenerated:    true,
				capabilityID:      "example.capability.echo",
				capabilityAdapter: capabilityAdapter,
			})
			installed, gateway := installEnableAndMintGateway(t, h, tc.packageBytes, surfaceIDForMethod(tc.method))
			if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
				PluginInstanceID:     installed.PluginInstanceID,
				SurfaceInstanceID:    "surface_rpc",
				SessionChannelIDHash: "channel_hash",
				OwnerSessionHash:     "session_hash",
				OwnerUserHash:        "user_hash",
				BridgeChannelID:      "bridge_rpc",
				GatewayToken:         gateway.GatewayToken,
				Method:               tc.method,
			}); err == nil {
				t.Fatal("CallPluginMethod() expected execution contract error")
			}
		})
	}
}

func TestCancelOperationRequestsCancel(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{OperationID: "op_cancel_1"}}
	operationCanceler := &recordingOperationCanceler{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		operationCanceler: operationCanceler,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.activity")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "images.pull",
	}); err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}

	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	canceled, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: "op_cancel_1", Reason: "user", Now: now})
	if err != nil {
		t.Fatalf("CancelOperation() error = %v", err)
	}
	if canceled.Status != operation.StatusCancelRequested || canceled.Reason != "user" {
		t.Fatalf("cancel operation mismatch: %#v", canceled)
	}
	if operationCanceler.calls != 1 {
		t.Fatalf("operation canceler calls = %d, want 1", operationCanceler.calls)
	}
	if operationCanceler.last.OperationID != "op_cancel_1" ||
		operationCanceler.last.PluginInstanceID != installed.PluginInstanceID ||
		operationCanceler.last.Method != "images.pull" ||
		operationCanceler.last.SurfaceInstanceID != "surface_rpc" ||
		operationCanceler.last.SessionChannelIDHash != "channel_hash" ||
		operationCanceler.last.BridgeChannelID != "bridge_rpc" ||
		operationCanceler.last.Reason != "user" ||
		!operationCanceler.last.RequestedAt.Equal(now) {
		t.Fatalf("operation canceler request mismatch: %#v", operationCanceler.last)
	}
	if !audits.hasEvent("plugin.operation.cancel_requested") {
		t.Fatalf("missing cancel audit event: %#v", audits.events)
	}
}

func TestCancelOperationReturnsDispatchFailureButKeepsCancelRequested(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{OperationID: "op_cancel_fail_1"}}
	operationCanceler := &recordingOperationCanceler{err: errors.New("runtime unavailable")}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		operationCanceler: operationCanceler,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.activity")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "images.pull",
	}); err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}

	canceled, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: "op_cancel_fail_1", Reason: "user"})
	if !errors.Is(err, ErrOperationCancelDispatchFailed) {
		t.Fatalf("CancelOperation() error = %v, want %v", err, ErrOperationCancelDispatchFailed)
	}
	if canceled.Status != operation.StatusCancelRequested {
		t.Fatalf("returned operation status = %s, want %s: %#v", canceled.Status, operation.StatusCancelRequested, canceled)
	}
	assertHostOperationStatus(t, h, "op_cancel_fail_1", operation.StatusCancelRequested)
	if operationCanceler.calls != 1 {
		t.Fatalf("operation canceler calls = %d, want 1", operationCanceler.calls)
	}
	if !audits.hasEvent("plugin.operation.cancel_requested") {
		t.Fatalf("missing cancel audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodRejectsInvalidGatewayToken(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "unreachable"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, _ := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         "plugin_gateway_token.invalid",
		Method:               "echo.ping",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected token error")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestCallPluginMethodHonorsLocalPolicyDeny(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "unreachable"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		policyDecision:    PolicyDeny,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected local policy deny")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestCallPluginMethodHonorsSecurityPolicyDeny(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "allowed"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, _ := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")
	beforePolicy, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := h.PutSecurityPolicy(context.Background(), PutSecurityPolicyRequest{
		PluginInstanceID: installed.PluginInstanceID,
		DeniedMethods:    []string{"echo.ping"},
	})
	if err != nil {
		t.Fatalf("PutSecurityPolicy() error = %v", err)
	}
	if len(policy.DeniedMethods) != 1 || policy.DeniedMethods[0] != "echo.ping" {
		t.Fatalf("policy mismatch: %#v", policy)
	}
	afterPolicy, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if afterPolicy.PolicyRevision <= beforePolicy.PolicyRevision || afterPolicy.RevokeEpoch <= beforePolicy.RevokeEpoch {
		t.Fatalf("security policy update did not bump policy/revoke revisions: before=%#v after=%#v", beforePolicy, afterPolicy)
	}
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.activity")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
	}); !errors.Is(err, security.ErrPolicyDenied) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrPolicyDenied", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called before security policy allowed it: %d", capabilityAdapter.calls)
	}

	if err := h.DeleteSecurityPolicy(context.Background(), DeleteSecurityPolicyRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("DeleteSecurityPolicy() error = %v", err)
	}
	_, gateway = openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.activity")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
	}); err != nil {
		t.Fatalf("CallPluginMethod() after policy delete error = %v", err)
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("capability adapter calls = %d, want 1", capabilityAdapter.calls)
	}
	if !audits.hasEvent("plugin.security_policy.updated") || !audits.hasEvent("plugin.security_policy.deleted") {
		t.Fatalf("missing security policy audit events: %#v", audits.events)
	}
}

func TestCallPluginMethodRequiresConfirmationForDangerousMethod(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db"},
	}

	result, err := h.CallPluginMethod(context.Background(), call)
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrConfirmationRequired", err)
	}
	if !result.ConfirmationRequired || result.RequestHash == "" {
		t.Fatalf("confirmation response mismatch: %#v", result)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}

	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	if confirmation.ConfirmationID == "" || confirmation.RequestHash != result.RequestHash {
		t.Fatalf("confirmation result mismatch: %#v vs request hash %q", confirmation, result.RequestHash)
	}
	if !audits.hasEvent("plugin.confirmation.issued") {
		t.Fatalf("missing confirmation audit event: %#v", audits.events)
	}

	call.ConfirmationID = confirmation.ConfirmationID
	confirmed, err := h.CallPluginMethod(context.Background(), call)
	if err != nil {
		t.Fatalf("CallPluginMethod() with confirmation error = %v", err)
	}
	if confirmed.Data == nil || capabilityAdapter.calls != 1 {
		t.Fatalf("confirmed call mismatch: result=%#v calls=%d", confirmed, capabilityAdapter.calls)
	}
	if !audits.hasEvent("plugin.confirmation.consumed") {
		t.Fatalf("missing consumed confirmation audit event: %#v", audits.events)
	}
}

func TestPrepareMethodConfirmationRunsRiskPreflightAndBindsPlanHash(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{OperationID: "operation_start_task", Data: map[string]any{"started": true}},
		resultsByTarget: map[string]capability.Result{
			"tasks.start.preflight": {Data: map[string]any{
				"summary":    "Start task",
				"risk_flags": []any{"executes_task"},
			}},
		},
	}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.tasks",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildMethodContractFixturePackage(t), "method_contract.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "tasks.start",
		Params:               map[string]any{"task_id": "task_1"},
	}

	result, err := h.CallPluginMethod(context.Background(), call)
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrConfirmationRequired", err)
	}
	if !result.ConfirmationRequired || result.RequestHash == "" {
		t.Fatalf("confirmation response mismatch: %#v", result)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter should not run before prepare confirmation, calls=%d", capabilityAdapter.calls)
	}

	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	if confirmation.PlanHash == "" || confirmation.RequestHash != result.RequestHash {
		t.Fatalf("confirmation plan mismatch: %#v", confirmation)
	}
	plan, ok := confirmation.Plan.(map[string]any)
	if !ok || plan["summary"] != "Start task" {
		t.Fatalf("confirmation plan = %#v", confirmation.Plan)
	}
	if capabilityAdapter.calls != 1 || capabilityAdapter.last.TargetMethod != "tasks.start.preflight" || capabilityAdapter.last.Effect != capability.EffectRead {
		t.Fatalf("preflight invocation mismatch: calls=%d last=%#v", capabilityAdapter.calls, capabilityAdapter.last)
	}
	if !audits.hasEvent("plugin.confirmation.preflighted") || !audits.hasEvent("plugin.confirmation.issued") {
		t.Fatalf("missing preflight/issued audit events: %#v", audits.events)
	}

	call.ConfirmationID = confirmation.ConfirmationID
	confirmed, err := h.CallPluginMethod(context.Background(), call)
	if err != nil {
		t.Fatalf("CallPluginMethod() with confirmation error = %v", err)
	}
	if capabilityAdapter.calls != 2 || capabilityAdapter.last.TargetMethod != "tasks.start" {
		t.Fatalf("confirmed invocation mismatch: calls=%d last=%#v", capabilityAdapter.calls, capabilityAdapter.last)
	}
	if confirmed.Data == nil {
		t.Fatalf("confirmed result missing data: %#v", confirmed)
	}
}

func TestPrepareMethodConfirmationNormalizesTypedRiskPlanAndRedactsDetails(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{OperationID: "operation_start_task", Data: map[string]any{"started": true}},
		resultsByTarget: map[string]capability.Result{
			"tasks.start.preflight": {Data: capability.RiskPlan{
				Summary:     "Start high-risk container",
				Effect:      capability.EffectExecute,
				ResourceRef: "container_hash_1",
				RiskFlags: []capability.RiskFlag{
					{ID: "container.host_network", Severity: "HIGH", Summary: "Uses host networking", RequiresAdmin: true},
				},
				Details: map[string]any{
					"env": []any{
						"PATH=/usr/bin",
						"API_TOKEN=plaintext-token",
					},
					"mounts": []any{
						map[string]any{"source": "/run/secrets/api_token", "target": "/run/secrets/api_token"},
						map[string]any{"source": "/srv/project", "target": "/workspace"},
					},
				},
			}},
		},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.tasks",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildMethodContractFixturePackage(t), "method_contract.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "tasks.start",
		Params:               map[string]any{"task_id": "task_1"},
	}

	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	plan, ok := confirmation.Plan.(capability.RiskPlan)
	if !ok {
		t.Fatalf("confirmation plan = %#v, want capability.RiskPlan", confirmation.Plan)
	}
	if plan.SchemaVersion != capability.RiskPlanSchemaVersion || plan.Effect != capability.EffectExecute {
		t.Fatalf("normalized plan mismatch: %#v", plan)
	}
	if !plan.RequiresAdmin || !plan.RequiresConfirmation || plan.RiskFlags[0].Severity != capability.RiskSeverityHigh {
		t.Fatalf("risk plan flags were not normalized: %#v", plan)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "plaintext-token") || strings.Contains(string(raw), "/run/secrets/api_token") {
		t.Fatalf("confirmation risk plan leaked sensitive detail: %s", raw)
	}
	if !strings.Contains(string(raw), "/srv/project") {
		t.Fatalf("confirmation risk plan dropped safe detail: %s", raw)
	}
}

func TestConfirmationIntentRejectsTamperedPlanHash(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	confirmationIntents := &tamperingConfirmationIntentStore{
		ConfirmationIntentStore: security.NewMemoryConfirmationIntentStore(),
		planHash:                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:       true,
		localGenerated:      true,
		capabilityID:        "example.capability.echo",
		capabilityAdapter:   capabilityAdapter,
		confirmationIntents: confirmationIntents,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatal(err)
	}

	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() expected tampered plan hash to fail token audience validation")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestDisableRevokesSurfaceTokensConfirmationIntentsAndRuntime(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
	}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	confirmationIntents := security.NewMemoryConfirmationIntentStore()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:       true,
		localGenerated:      true,
		capabilityID:        "example.capability.echo",
		capabilityAdapter:   capabilityAdapter,
		runtimeSupervisor:   runtime,
		connectivityBroker:  connectivity.NewMemoryBroker(),
		confirmationIntents: confirmationIntents,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	if listed, err := confirmationIntents.ListConfirmationIntents(context.Background(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil || len(listed) != 1 {
		t.Fatalf("stored confirmation intents before disable = %#v, err=%v", listed, err)
	}
	call.ConfirmationID = confirmation.ConfirmationID

	disabled, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy"})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if runtime.revokeCalls != 1 || runtime.lastRevokedPlugin != installed.PluginInstanceID || runtime.lastRevokeEpoch != disabled.RevokeEpoch {
		t.Fatalf("runtime revoke mismatch: calls=%d plugin=%q epoch=%d disabled=%#v", runtime.revokeCalls, runtime.lastRevokedPlugin, runtime.lastRevokeEpoch, disabled)
	}
	if _, err := h.surfaceTokens.ValidateGatewayToken(gateway.GatewayToken, bridge.Audience{
		PluginInstanceID:     installed.PluginInstanceID,
		ActiveFingerprint:    installed.ActiveFingerprint,
		SurfaceInstanceID:    "surface_rpc",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_rpc",
	}, bridge.RevisionBinding{
		PolicyRevision:     installed.PolicyRevision,
		ManagementRevision: installed.ManagementRevision,
		RevokeEpoch:        installed.RevokeEpoch,
	}, time.Now().UTC()); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() after disable error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() after disable expected fail-closed error")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter called after disabled confirmation: %d", capabilityAdapter.calls)
	}
	if listed, err := confirmationIntents.ListConfirmationIntents(context.Background(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil || len(listed) != 0 {
		t.Fatalf("stored confirmation intents after disable = %#v, err=%v", listed, err)
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatalf("missing runtime capability revocation audit event: %#v", audits.events)
	}
}

func TestDisableContinuesCleanupWhenRuntimeRevokeFails(t *testing.T) {
	ctx := context.Background()
	runtime := &recordingRuntimeSupervisor{
		health:    runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		revokeErr: errors.New("runtime pipe closed"),
	}
	connectivityBroker := connectivity.NewMemoryBroker()
	diagnostics := &diagnosticSink{}
	h, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeSupervisor:  runtime,
		connectivityBroker: connectivityBroker,
		storageBroker:      storage.NewMemoryBroker(),
		diagnostics:        diagnostics,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(ctx, connectivity.GrantRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		ActiveFingerprint:  enabled.ActiveFingerprint,
		PolicyRevision:     enabled.PolicyRevision,
		ManagementRevision: enabled.ManagementRevision,
		RevokeEpoch:        enabled.RevokeEpoch,
		ConnectorID:        "api",
		Transport:          connectivity.TransportHTTP,
		Destination:        "https://api.example.com",
	}); err != nil {
		t.Fatalf("MintConnectionGrant(before disable) error = %v", err)
	}

	disabled, err := h.DisablePlugin(ctx, DisableRequest{PluginInstanceID: enabled.PluginInstanceID, Reason: "policy"})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if runtime.revokeCalls != 1 || runtime.lastRevokeEpoch != disabled.RevokeEpoch {
		t.Fatalf("runtime revoke call mismatch: calls=%d epoch=%d disabled=%#v", runtime.revokeCalls, runtime.lastRevokeEpoch, disabled)
	}
	if len(surfaces.snapshots) != 2 || len(surfaces.snapshots[1].Surfaces) != 0 {
		t.Fatalf("disable did not clear surfaces after runtime revoke failure: %#v", surfaces.snapshots)
	}
	if _, err := connectivityBroker.MintConnectionGrant(ctx, connectivity.GrantRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		ActiveFingerprint:  enabled.ActiveFingerprint,
		PolicyRevision:     enabled.PolicyRevision,
		ManagementRevision: enabled.ManagementRevision,
		RevokeEpoch:        enabled.RevokeEpoch,
		ConnectorID:        "api",
		Transport:          connectivity.TransportHTTP,
		Destination:        "https://api.example.com",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(after disable) error = %v, want %v", err, connectivity.ErrConnectorDenied)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Type != "plugin.runtime_capabilities.revoke_failed" {
		t.Fatalf("diagnostics mismatch: %#v", diagnostics.events)
	}
}

func TestListAndInvokeIntentDispatchesCapability(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	grantDeclaredPermissions(t, h, installed)

	intents, err := h.ListIntents(context.Background(), ListIntentsRequest{IntentID: "example.echo"})
	if err != nil {
		t.Fatalf("ListIntents() error = %v", err)
	}
	if len(intents) != 1 || intents[0].IntentID != "example.echo" || intents[0].Method != "echo.ping" || intents[0].Effect != "read" {
		t.Fatalf("intent records mismatch: %#v", intents)
	}

	result, err := h.InvokeIntent(context.Background(), InvokeIntentRequest{
		IntentID:             "example.echo",
		Params:               map[string]any{"message": "from intent"},
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
	})
	if err != nil {
		t.Fatalf("InvokeIntent() error = %v", err)
	}
	if result.Data == nil || capabilityAdapter.calls != 1 || capabilityAdapter.last.Method != "echo.ping" {
		t.Fatalf("intent dispatch mismatch: result=%#v calls=%d last=%#v", result, capabilityAdapter.calls, capabilityAdapter.last)
	}
	if !audits.hasEvent("plugin.intent.invoked") {
		t.Fatalf("missing intent audit event: %#v", audits.events)
	}
}

func TestInvokeIntentRequiresPermissions(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.InvokeIntent(context.Background(), InvokeIntentRequest{
		PluginInstanceID: installed.PluginInstanceID,
		IntentID:         "example.echo",
	}); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("InvokeIntent() error = %v, want ErrPermissionDenied", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestInvokeIntentRequiresPluginInstanceWhenAmbiguous(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	first, err := ImportLocalPackageBytes(context.Background(), h, buildIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	secondBytes := buildIntentFixturePackage(t, false)
	second, err := h.ImportLocalPackage(context.Background(), ImportLocalPackageRequest{
		PackageReader:    bytes.NewReader(secondBytes),
		PackageSize:      int64(len(secondBytes)),
		PluginInstanceID: "plugini_second_intent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: first.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: second.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	grantDeclaredPermissions(t, h, first)
	grantDeclaredPermissions(t, h, second)

	if _, err := h.InvokeIntent(context.Background(), InvokeIntentRequest{IntentID: "example.echo"}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("InvokeIntent() ambiguity error = %v", err)
	}
}

func TestInvokeIntentFailsClosedForDangerousMethod(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildIntentFixturePackage(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	grantDeclaredPermissions(t, h, installed)

	result, err := h.InvokeIntent(context.Background(), InvokeIntentRequest{
		PluginInstanceID: installed.PluginInstanceID,
		IntentID:         "example.danger",
		Params:           map[string]any{"target": "db"},
	})
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("InvokeIntent() error = %v, want ErrConfirmationRequired", err)
	}
	if !result.ConfirmationRequired || result.RequestHash == "" {
		t.Fatalf("confirmation result mismatch: %#v", result)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestConfirmationIntentCannotBeReusedForDifferentParams(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.Params = map[string]any{"target": "other"}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() expected confirmation audience error")
	}
	call.Params = map[string]any{"target": "db"}
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() expected consumed confirmation intent to reject retry")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestConfirmationIntentConsumesOnceAfterSuccess(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(context.Background(), call); err != nil {
		t.Fatalf("CallPluginMethod() with confirmation error = %v", err)
	}
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() expected confirmation intent replay rejection")
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("capability adapter calls after replay = %d, want 1 before replay only", capabilityAdapter.calls)
	}
}

func TestConfirmationIntentBindsFullParamsBeyondManifestHashFieldHints(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "done"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.activity")
	call := CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "danger.run",
		Params:               map[string]any{"target": "db", "ui_note": "original"},
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.Params = map[string]any{"target": "db", "ui_note": "changed"}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() expected confirmation intent to bind full params")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestEnableEnsuresManifestStorageNamespaces(t *testing.T) {
	storageBroker := storage.NewMemoryBroker()
	host, _, _ := newTestHostWithStorage(t, true, true, storageBroker)
	installed, err := ImportLocalPackageBytes(context.Background(), host, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	namespaces, err := storageBroker.ListNamespaces(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 2 {
		t.Fatalf("namespace count = %d, want 2: %#v", len(namespaces), namespaces)
	}
	if namespaces[0].StoreID != "cache" || namespaces[0].Kind != storage.StoreKV || namespaces[0].Scope != "user" || namespaces[0].QuotaFiles != 16 {
		t.Fatalf("first namespace mismatch: %#v", namespaces[0])
	}
	if namespaces[1].StoreID != "db" || namespaces[1].Kind != storage.StoreSQLite || namespaces[1].Scope != "environment" || namespaces[1].QuotaFiles != 32 {
		t.Fatalf("second namespace mismatch: %#v", namespaces[1])
	}

	if _, err := storageBroker.PutKV(context.Background(), storage.KVPutRequest{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "cache",
		Key:              "schedule/current_location",
		Value:            []byte("Shanghai"),
	}); err != nil {
		t.Fatalf("PutKV() after enable error = %v", err)
	}
	read, err := storageBroker.GetKV(context.Background(), storage.KVGetRequest{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "cache",
		Key:              "schedule/current_location",
	})
	if err != nil {
		t.Fatalf("GetKV() after enable error = %v", err)
	}
	if string(read.Value) != "Shanghai" {
		t.Fatalf("GetKV() value = %q", string(read.Value))
	}
}

func TestMintStorageHandleGrantBindsStoreAndQuota(t *testing.T) {
	storageBroker := storage.NewMemoryBroker()
	host, _, audits := newTestHostWithStorage(t, true, true, storageBroker)
	installed, err := ImportLocalPackageBytes(context.Background(), host, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}

	now := time.Date(2026, 6, 30, 14, 0, 0, 0, time.UTC)
	result, err := host.MintStorageHandleGrant(context.Background(), MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "db",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_a",
		Now:                 now,
		TTL:                 time.Minute,
	})
	if err != nil {
		t.Fatalf("MintStorageHandleGrant() error = %v", err)
	}
	if result.Namespace.StoreID != "db" || result.Namespace.Kind != storage.StoreSQLite {
		t.Fatalf("storage namespace mismatch: %#v", result.Namespace)
	}
	record, err := host.surfaceTokens.ValidateHandleGrant(bridge.ValidateHandleGrantRequest{
		HandleGrantToken: result.HandleGrant.HandleGrantToken,
		Audience: bridge.Audience{
			PluginInstanceID:    enabled.PluginInstanceID,
			ActiveFingerprint:   enabled.ActiveFingerprint,
			RuntimeInstanceID:   "runtime_1",
			RuntimeGenerationID: "runtime_gen_1",
			RuntimeShardID:      "runtime_shard_a",
			HandleID:            "storage:db",
			Method:              "storage.sqlite",
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision:     enabled.PolicyRevision,
			ManagementRevision: enabled.ManagementRevision,
			RevokeEpoch:        enabled.RevokeEpoch,
		},
		Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("ValidateHandleGrant(storage) error = %v", err)
	}
	if record.Limits.MaxTotalBytes != result.Namespace.QuotaBytes {
		t.Fatalf("storage handle quota = %d, want %d", record.Limits.MaxTotalBytes, result.Namespace.QuotaBytes)
	}
	if !audits.hasEvent("plugin.storage.handle_grant_minted") {
		t.Fatalf("missing storage handle grant audit event: %#v", audits.events)
	}

	if _, err := host.MintStorageHandleGrant(context.Background(), MintStorageHandleGrantRequest{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "db",
	}); !errors.Is(err, bridge.ErrMissingTokenAudience) {
		t.Fatalf("MintStorageHandleGrant(missing runtime generation) error = %v, want %v", err, bridge.ErrMissingTokenAudience)
	}
	if _, err := host.MintStorageHandleGrant(context.Background(), MintStorageHandleGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		StoreID:             "missing",
		RuntimeGenerationID: "runtime_gen_1",
	}); !errors.Is(err, storage.ErrNamespaceNotFound) {
		t.Fatalf("MintStorageHandleGrant(missing store) error = %v, want %v", err, storage.ErrNamespaceNotFound)
	}
}

func TestEnableInstallsConnectivityPolicyAndMintsGrant(t *testing.T) {
	connectivityBroker := connectivity.NewMemoryBroker()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storage.NewMemoryBroker(),
		connectivityBroker: connectivityBroker,
	})
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if !audits.hasEvent("plugin.connectivity.policy_installed") {
		t.Fatalf("missing connectivity policy audit event: %#v", audits.events)
	}
	grant, err := h.MintConnectionGrant(context.Background(), MintConnectionGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		ConnectorID:         "mysql",
		Transport:           connectivity.TransportTCP,
		Destination:         "db.example.com:3306",
		RuntimeGenerationID: "runtime_gen_1",
		TTL:                 time.Minute,
	})
	if err != nil {
		t.Fatalf("MintConnectionGrant() error = %v", err)
	}
	if grant.GrantID == "" || grant.PluginInstanceID != installed.PluginInstanceID || grant.Destination.Port != 3306 {
		t.Fatalf("grant mismatch: %#v", grant)
	}
	if !audits.hasEvent("plugin.connectivity.grant_minted") {
		t.Fatalf("missing connectivity grant audit event: %#v", audits.events)
	}

	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	handle, err := h.MintNetworkHandleGrant(context.Background(), MintConnectionGrantRequest{
		PluginInstanceID:    installed.PluginInstanceID,
		ConnectorID:         "mysql",
		Transport:           connectivity.TransportTCP,
		Destination:         "db.example.com:3306",
		RuntimeInstanceID:   "runtime_1",
		RuntimeGenerationID: "runtime_gen_1",
		RuntimeShardID:      "runtime_shard_a",
		Now:                 now,
		TTL:                 time.Minute,
	})
	if err != nil {
		t.Fatalf("MintNetworkHandleGrant() error = %v", err)
	}
	if handle.ConnectionGrant.GrantID == "" || handle.HandleGrant.HandleGrantToken == "" {
		t.Fatalf("network handle grant mismatch: %#v", handle)
	}
	record, err := h.surfaceTokens.ValidateHandleGrant(bridge.ValidateHandleGrantRequest{
		HandleGrantToken: handle.HandleGrant.HandleGrantToken,
		Audience: bridge.Audience{
			PluginInstanceID:    installed.PluginInstanceID,
			ActiveFingerprint:   installed.ActiveFingerprint,
			RuntimeInstanceID:   "runtime_1",
			RuntimeGenerationID: "runtime_gen_1",
			RuntimeShardID:      "runtime_shard_a",
			HandleID:            handle.ConnectionGrant.GrantID,
			Method:              "network.tcp",
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision:     handle.ConnectionGrant.PolicyRevision,
			ManagementRevision: handle.ConnectionGrant.ManagementRevision,
			RevokeEpoch:        handle.ConnectionGrant.RevokeEpoch,
		},
		Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("ValidateHandleGrant(network) error = %v", err)
	}
	if record.Audience.HandleID != handle.ConnectionGrant.GrantID || record.Audience.RuntimeGenerationID != "runtime_gen_1" {
		t.Fatalf("network handle audience mismatch: %#v", record.Audience)
	}
	if !audits.hasEvent("plugin.connectivity.handle_grant_minted") {
		t.Fatalf("missing connectivity handle grant audit event: %#v", audits.events)
	}
	if _, err := h.GrantPermission(context.Background(), GrantPermissionRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PermissionID:     "network.audit",
		GrantedBy:        "test",
	}); err != nil {
		t.Fatalf("GrantPermission(network.audit) error = %v", err)
	}
	afterGrant, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(context.Background(), connectivity.GrantRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		ActiveFingerprint:  enabled.ActiveFingerprint,
		PolicyRevision:     enabled.PolicyRevision,
		ManagementRevision: enabled.ManagementRevision,
		RevokeEpoch:        enabled.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(stale after grant) error = %v, want %v", err, connectivity.ErrConnectorDenied)
	}
	if _, err := connectivityBroker.MintConnectionGrant(context.Background(), connectivity.GrantRequest{
		PluginInstanceID:   afterGrant.PluginInstanceID,
		ActiveFingerprint:  afterGrant.ActiveFingerprint,
		PolicyRevision:     afterGrant.PolicyRevision,
		ManagementRevision: afterGrant.ManagementRevision,
		RevokeEpoch:        afterGrant.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); err != nil {
		t.Fatalf("MintConnectionGrant(fresh after grant) error = %v", err)
	}
	if _, err := h.RevokePermission(context.Background(), RevokePermissionRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PermissionID:     "network.audit",
		RevokedBy:        "test",
		Reason:           "test",
	}); err != nil {
		t.Fatalf("RevokePermission(network.audit) error = %v", err)
	}
	afterRevoke, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(context.Background(), connectivity.GrantRequest{
		PluginInstanceID:   afterGrant.PluginInstanceID,
		ActiveFingerprint:  afterGrant.ActiveFingerprint,
		PolicyRevision:     afterGrant.PolicyRevision,
		ManagementRevision: afterGrant.ManagementRevision,
		RevokeEpoch:        afterGrant.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(stale after revoke) error = %v, want %v", err, connectivity.ErrConnectorDenied)
	}
	if _, err := connectivityBroker.MintConnectionGrant(context.Background(), connectivity.GrantRequest{
		PluginInstanceID:   afterRevoke.PluginInstanceID,
		ActiveFingerprint:  afterRevoke.ActiveFingerprint,
		PolicyRevision:     afterRevoke.PolicyRevision,
		ManagementRevision: afterRevoke.ManagementRevision,
		RevokeEpoch:        afterRevoke.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); err != nil {
		t.Fatalf("MintConnectionGrant(fresh after revoke) error = %v", err)
	}
	if _, err := h.MintNetworkHandleGrant(context.Background(), MintConnectionGrantRequest{
		PluginInstanceID: installed.PluginInstanceID,
		ConnectorID:      "mysql",
		Transport:        connectivity.TransportTCP,
		Destination:      "db.example.com:3306",
	}); !errors.Is(err, bridge.ErrMissingTokenAudience) {
		t.Fatalf("MintNetworkHandleGrant(missing runtime generation) error = %v, want %v", err, bridge.ErrMissingTokenAudience)
	}

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test"}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(context.Background(), connectivity.GrantRequest{
		PluginInstanceID:   installed.PluginInstanceID,
		ActiveFingerprint:  installed.ActiveFingerprint,
		PolicyRevision:     installed.PolicyRevision,
		ManagementRevision: installed.ManagementRevision,
		RevokeEpoch:        installed.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant() after disable error = %v, want ErrConnectorDenied", err)
	}
}

func TestRefreshEnabledPluginsRestoresRuntimeState(t *testing.T) {
	ctx := context.Background()
	h, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storage.NewMemoryBroker(),
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if len(surfaces.snapshots) == 0 {
		t.Fatal("EnablePlugin() did not publish surfaces")
	}

	restartedBroker := connectivity.NewMemoryBroker()
	restartedSurfaces := &surfaceSink{}
	restartedAudits := &auditSink{}
	restartedDiagnostics := &diagnosticSink{}
	restarted, err := New(Adapters{
		SessionResolver: fakeSessionResolver{},
		Policy: policyAdapter{
			developerMode:  true,
			localGenerated: true,
			decision:       PolicyAllow,
		},
		PackageTrustVerifier: &recordingPackageTrustVerifier{},
		Registry:             h.adapters.Registry,
		Audit:                restartedAudits,
		Diagnostics:          restartedDiagnostics,
		SurfaceCatalog:       restartedSurfaces,
		Storage:              storage.NewMemoryBroker(),
		Connectivity:         restartedBroker,
		Settings:             settings.NewMemoryStore(),
		Assets:               h.adapters.Assets,
		InstallStages:        h.adapters.InstallStages,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := restarted.MintConnectionGrant(ctx, MintConnectionGrantRequest{
		PluginInstanceID:    enabled.PluginInstanceID,
		ConnectorID:         "mysql",
		Transport:           connectivity.TransportTCP,
		Destination:         "db.example.com:3306",
		RuntimeGenerationID: "runtime_gen_1",
		TTL:                 time.Minute,
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(before refresh) error = %v, want ErrConnectorDenied", err)
	}

	refreshed, err := restarted.RefreshEnabledPlugins(ctx)
	if err != nil {
		t.Fatalf("RefreshEnabledPlugins() error = %v", err)
	}
	if len(refreshed) != 1 || refreshed[0].PluginInstanceID != enabled.PluginInstanceID {
		t.Fatalf("refreshed plugins mismatch: %#v", refreshed)
	}
	if len(restartedSurfaces.snapshots) != 1 || restartedSurfaces.snapshots[0].PluginInstanceID != enabled.PluginInstanceID || len(restartedSurfaces.snapshots[0].Surfaces) == 0 {
		t.Fatalf("surface refresh mismatch: %#v", restartedSurfaces.snapshots)
	}
	if !restartedAudits.hasEvent("plugin.runtime_state.refreshed") {
		t.Fatalf("missing runtime refresh audit: %#v", restartedAudits.events)
	}

	grant, err := restarted.MintConnectionGrant(ctx, MintConnectionGrantRequest{
		PluginInstanceID:    enabled.PluginInstanceID,
		ConnectorID:         "mysql",
		Transport:           connectivity.TransportTCP,
		Destination:         "db.example.com:3306",
		RuntimeGenerationID: "runtime_gen_1",
		TTL:                 time.Minute,
	})
	if err != nil {
		t.Fatalf("MintConnectionGrant(after refresh) error = %v", err)
	}
	if grant.PluginInstanceID != enabled.PluginInstanceID || grant.PolicyRevision != enabled.PolicyRevision {
		t.Fatalf("grant after refresh mismatch: %#v", grant)
	}
}

func TestEnableRejectsBlockedNetworkTargetBeforeStorageSideEffects(t *testing.T) {
	ctx := context.Background()
	storageBroker := storage.NewMemoryBroker()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		storageBroker:      storageBroker,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildBlockedNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); !errors.Is(err, connectivity.ErrTargetDenied) {
		t.Fatalf("EnablePlugin() error = %v, want ErrTargetDenied", err)
	}
	namespaces, err := storageBroker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("storage namespaces created despite blocked network target: %#v", namespaces)
	}
}

func TestUninstallRetainsOrDeletesStorageNamespaces(t *testing.T) {
	ctx := context.Background()
	retainBroker := storage.NewMemoryBroker()
	retainCleanup := cleanup.NewMemoryOrchestrator()
	retainedRegistry := retaineddata.NewMemoryStore()
	retainHost, _, retainAudits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  retainBroker,
		cleanup:        retainCleanup,
		retainedData:   retainedRegistry,
	})
	retainedPlugin, err := ImportLocalPackageBytes(ctx, retainHost, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retainHost.EnablePlugin(ctx, EnableRequest{PluginInstanceID: retainedPlugin.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := retainBroker.PutKV(ctx, storage.KVPutRequest{
		PluginInstanceID: retainedPlugin.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
		Value:            []byte("qa"),
	}); err != nil {
		t.Fatalf("PutKV(retain setup) error = %v", err)
	}
	if _, err := retainHost.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: retainedPlugin.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatalf("UninstallPlugin(retain) error = %v", err)
	}
	retained, err := retainBroker.ListNamespaces(ctx, retainedPlugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 2 || retained[0].State != storage.NamespaceRetained || retained[1].State != storage.NamespaceRetained {
		t.Fatalf("retained namespaces mismatch: %#v", retained)
	}
	retainedRecords, err := retainedRegistry.List(ctx, retaineddata.ListRequest{SourcePluginInstanceID: retainedPlugin.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(retainedRecords) != 1 ||
		retainedRecords[0].State != retaineddata.StateRetained ||
		!retainedRecords[0].StorageRetained ||
		retainedRecords[0].SettingsRetained ||
		retainedRecords[0].BrowserSiteRetained ||
		retainedRecords[0].UsageBytes == 0 {
		t.Fatalf("retained data registry mismatch: %#v", retainedRecords)
	}
	if !retainAudits.hasEvent("plugin.retained_data.recorded") {
		t.Fatalf("missing retained data audit event: %#v", retainAudits.events)
	}
	if _, err := retainBroker.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: retainedPlugin.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
	}); !errors.Is(err, storage.ErrNamespaceNotFound) {
		t.Fatalf("GetKV(retained inactive namespace) error = %v, want ErrNamespaceNotFound", err)
	}
	archiveRef, err := retainBroker.ExportData(ctx, storage.ExportRequest{PluginInstanceID: retainedPlugin.PluginInstanceID})
	if err != nil {
		t.Fatalf("ExportData(retained data) error = %v", err)
	}
	if err := retainBroker.ImportData(ctx, storage.ImportRequest{
		PluginInstanceID: "plugini_retained_restore",
		ArchiveRef:       archiveRef,
		DeleteExisting:   true,
	}); err != nil {
		t.Fatalf("ImportData(retained data) error = %v", err)
	}
	restoredValue, err := retainBroker.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: "plugini_retained_restore",
		StoreID:          "cache",
		Key:              "planner/filter",
	})
	if err != nil {
		t.Fatalf("GetKV(restored retained data) error = %v", err)
	}
	if string(restoredValue.Value) != "qa" {
		t.Fatalf("restored retained KV value = %q", string(restoredValue.Value))
	}
	retainExecutions, err := retainCleanup.ListExecutions(ctx, retainedPlugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if cleanupPhases(retainExecutions).contains(cleanup.PhaseDeleteData) {
		t.Fatalf("retain cleanup unexpectedly deleted data: %#v", retainExecutions)
	}
	if !retainAudits.hasEvent("plugin.cleanup.executed") {
		t.Fatalf("missing cleanup audit event: %#v", retainAudits.events)
	}

	deleteBroker := storage.NewMemoryBroker()
	deleteCleanup := cleanup.NewMemoryOrchestrator()
	deleteHost, _, deleteAudits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  deleteBroker,
		cleanup:        deleteCleanup,
	})
	deletedPlugin, err := ImportLocalPackageBytes(ctx, deleteHost, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deleteHost.EnablePlugin(ctx, EnableRequest{PluginInstanceID: deletedPlugin.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := deleteBroker.PutKV(ctx, storage.KVPutRequest{
		PluginInstanceID: deletedPlugin.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
		Value:            []byte("qa"),
	}); err != nil {
		t.Fatalf("PutKV(delete setup) error = %v", err)
	}
	if _, err := deleteHost.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: deletedPlugin.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin(delete) error = %v", err)
	}
	deleted, err := deleteBroker.ListNamespaces(ctx, deletedPlugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted namespaces still present: %#v", deleted)
	}
	if _, err := deleteBroker.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: deletedPlugin.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
	}); !errors.Is(err, storage.ErrNamespaceNotFound) {
		t.Fatalf("GetKV(deleted namespace) error = %v, want ErrNamespaceNotFound", err)
	}
	deleteExecutions, err := deleteCleanup.ListExecutions(ctx, deletedPlugin.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	deletePhases := cleanupPhases(deleteExecutions)
	if !deletePhases.contains(cleanup.PhaseTombstone) ||
		!deletePhases.contains(cleanup.PhaseRevoke) ||
		!deletePhases.contains(cleanup.PhaseDeleteData) ||
		!deletePhases.contains(cleanup.PhaseDeletePackage) ||
		!deletePhases.contains(cleanup.PhaseComplete) {
		t.Fatalf("delete cleanup phases mismatch: %#v", deleteExecutions)
	}
	if !deleteAudits.hasEvent("plugin.cleanup.executed") {
		t.Fatalf("missing delete cleanup audit event: %#v", deleteAudits.events)
	}
}

func TestDeleteRetainedDataRemovesRetainedStoragePayload(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
		retainedData:   retainedRegistry,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.PutKV(ctx, storage.KVPutRequest{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
		Value:            []byte("qa"),
	}); err != nil {
		t.Fatalf("PutKV() error = %v", err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatalf("UninstallPlugin(retain) error = %v", err)
	}
	retainedRecords, err := h.ListRetainedData(ctx, ListRetainedDataRequest{SourcePluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(retainedRecords) != 1 || retainedRecords[0].State != retaineddata.StateRetained {
		t.Fatalf("retained records mismatch: %#v", retainedRecords)
	}

	deleted, err := h.DeleteRetainedData(ctx, DeleteRetainedDataRequest{RetainedID: retainedRecords[0].RetainedID})
	if err != nil {
		t.Fatalf("DeleteRetainedData() error = %v", err)
	}
	if deleted.State != retaineddata.StateDeleted || deleted.DeletedAt == nil {
		t.Fatalf("deleted retained data mismatch: %#v", deleted)
	}
	namespaces, err := broker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("retained storage payload still present: %#v", namespaces)
	}
	if _, err := broker.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
	}); !errors.Is(err, storage.ErrNamespaceNotFound) {
		t.Fatalf("GetKV() after retained delete error = %v, want ErrNamespaceNotFound", err)
	}
	if !audits.hasEvent("plugin.retained_data.deleted") {
		t.Fatalf("missing retained data delete audit event: %#v", audits.events)
	}
}

func TestBindRetainedDataRestoresStoragePayload(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
		retainedData:   retainedRegistry,
	})
	packageBytes := buildStorageFixturePackage(t)
	source, err := ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.PutKV(ctx, storage.KVPutRequest{
		PluginInstanceID: source.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
		Value:            []byte("qa"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatal(err)
	}
	retainedRecords, err := h.ListRetainedData(ctx, ListRetainedDataRequest{SourcePluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
		PluginInstanceID: "plugini_storage_rebind_target",
	})
	if err != nil {
		t.Fatal(err)
	}

	bound, err := h.BindRetainedData(ctx, BindRetainedDataRequest{
		RetainedID:             retainedRecords[0].RetainedID,
		TargetPluginInstanceID: target.PluginInstanceID,
	})
	if err != nil {
		t.Fatalf("BindRetainedData() error = %v", err)
	}
	if bound.State != retaineddata.StateBound || bound.BoundPluginInstanceID != target.PluginInstanceID {
		t.Fatalf("bound retained record mismatch: %#v", bound)
	}
	if namespaces, err := broker.ListNamespaces(ctx, source.PluginInstanceID); err != nil {
		t.Fatal(err)
	} else if len(namespaces) != 0 {
		t.Fatalf("source retained storage still present: %#v", namespaces)
	}
	value, err := broker.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: target.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
	})
	if err != nil {
		t.Fatalf("GetKV(bound target) error = %v", err)
	}
	if string(value.Value) != "qa" {
		t.Fatalf("bound KV value = %q", string(value.Value))
	}
	if !audits.hasEvent("plugin.retained_data.bound") {
		t.Fatalf("missing retained data bound audit event: %#v", audits.events)
	}
}

func TestBindRetainedDataRestoresStoragePayloadInPlace(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
		retainedData:   retainedRegistry,
	})
	packageBytes := buildStorageFixturePackage(t)
	source, err := ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.PutKV(ctx, storage.KVPutRequest{
		PluginInstanceID: source.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
		Value:            []byte("qa"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatal(err)
	}
	retainedRecords, err := h.ListRetainedData(ctx, ListRetainedDataRequest{SourcePluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if target.PluginInstanceID != source.PluginInstanceID {
		t.Fatalf("same package reinstall should reuse default instance id: got %s want %s", target.PluginInstanceID, source.PluginInstanceID)
	}

	bound, err := h.BindRetainedData(ctx, BindRetainedDataRequest{
		RetainedID:             retainedRecords[0].RetainedID,
		TargetPluginInstanceID: target.PluginInstanceID,
	})
	if err != nil {
		t.Fatalf("BindRetainedData(in-place) error = %v", err)
	}
	if bound.State != retaineddata.StateBound || bound.BoundPluginInstanceID != target.PluginInstanceID {
		t.Fatalf("in-place bound retained record mismatch: %#v", bound)
	}
	value, err := broker.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: target.PluginInstanceID,
		StoreID:          "cache",
		Key:              "planner/filter",
	})
	if err != nil {
		t.Fatalf("GetKV(in-place bound target) error = %v", err)
	}
	if string(value.Value) != "qa" {
		t.Fatalf("in-place bound KV value = %q", string(value.Value))
	}
}

func TestBindRetainedDataRestoresSettingsWithoutSecretState(t *testing.T) {
	ctx := context.Background()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  storage.NewMemoryBroker(),
		retainedData:   retainedRegistry,
		secrets:        &recordingSecretStore{},
	})
	packageBytes := buildSettingsFixturePackage(t)
	source, err := ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.PatchPluginSettings(ctx, PatchSettingsRequest{
		PluginInstanceID: source.PluginInstanceID,
		Values:           map[string]any{"default_engine": "podman", "show_stopped": false},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.BindSecretRef(ctx, SecretBindRequest{
		PluginInstanceID: source.PluginInstanceID,
		SecretRef:        "api_token",
		Scope:            "user",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatal(err)
	}
	retainedRecords, err := h.ListRetainedData(ctx, ListRetainedDataRequest{SourcePluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
		PluginInstanceID: "plugini_settings_rebind_target",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.BindRetainedData(ctx, BindRetainedDataRequest{
		RetainedID:             retainedRecords[0].RetainedID,
		TargetPluginInstanceID: target.PluginInstanceID,
	}); err != nil {
		t.Fatalf("BindRetainedData(settings) error = %v", err)
	}
	snapshot, err := h.GetPluginSettings(ctx, GetSettingsRequest{PluginInstanceID: target.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Values["default_engine"] != "podman" || snapshot.Values["show_stopped"] != false {
		t.Fatalf("bound settings mismatch: %#v", snapshot.Values)
	}
	secret, ok := snapshot.Values["api_token"].(settings.SecretValue)
	if !ok {
		t.Fatalf("bound secret should be redacted state: %#v", snapshot.Values["api_token"])
	}
	if secret.Set {
		t.Fatalf("retained settings bind must not restore secret binding state: %#v", secret)
	}
}

func TestBindRetainedDataRejectsUnsafeTrustClass(t *testing.T) {
	ctx := context.Background()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  storage.NewMemoryBroker(),
		retainedData:   retainedRegistry,
		trustVerifier:  &recordingPackageTrustVerifier{trustState: registry.TrustVerified},
	})
	packageBytes := buildStorageFixturePackage(t)
	source, err := ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatal(err)
	}
	retainedRecords, err := h.ListRetainedData(ctx, ListRetainedDataRequest{SourcePluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.PackageTrustVerifier = nil
	target, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
		PluginInstanceID: "plugini_storage_unsigned_target",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.BindRetainedData(ctx, BindRetainedDataRequest{
		RetainedID:             retainedRecords[0].RetainedID,
		TargetPluginInstanceID: target.PluginInstanceID,
	}); err == nil {
		t.Fatal("BindRetainedData() expected trust class error")
	}
	stored, err := retainedRegistry.Get(ctx, retainedRecords[0].RetainedID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != retaineddata.StateRetained {
		t.Fatalf("retained record state changed after rejected bind: %#v", stored)
	}
}

func TestBindRetainedDataRejectsTargetActiveStorage(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
		retainedData:   retainedRegistry,
	})
	packageBytes := buildStorageFixturePackage(t)
	source, err := ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatal(err)
	}
	retainedRecords, err := h.ListRetainedData(ctx, ListRetainedDataRequest{SourcePluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
		PluginInstanceID: "plugini_storage_active_target",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: target.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.BindRetainedData(ctx, BindRetainedDataRequest{
		RetainedID:             retainedRecords[0].RetainedID,
		TargetPluginInstanceID: target.PluginInstanceID,
	}); !errors.Is(err, ErrRetainedDataBindFailed) {
		t.Fatalf("BindRetainedData() error = %v, want ErrRetainedDataBindFailed", err)
	}
	stored, err := retainedRegistry.Get(ctx, retainedRecords[0].RetainedID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != retaineddata.StateRetained {
		t.Fatalf("retained record state changed after rejected bind: %#v", stored)
	}
}

func TestCleanupExpiredRetainedDataDeletesPayloadAndMarksFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	broker := storage.NewMemoryBroker()
	browserSite := browsersite.NewMemoryStore()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
		browserSite:    browserSite,
		retainedData:   retainedRegistry,
	})

	successPluginID := "plugini_retained_expired_success"
	if err := broker.EnsureNamespace(ctx, storage.Namespace{
		PluginInstanceID: successPluginID,
		StoreID:          "cache",
		Kind:             storage.StoreKV,
		QuotaBytes:       1024,
		SchemaVersion:    1,
	}); err != nil {
		t.Fatalf("EnsureNamespace(success) error = %v", err)
	}
	if _, err := broker.PutKV(ctx, storage.KVPutRequest{
		PluginInstanceID: successPluginID,
		StoreID:          "cache",
		Key:              "retained/key",
		Value:            []byte("value"),
	}); err != nil {
		t.Fatalf("PutKV(success) error = %v", err)
	}
	if err := broker.DeleteNamespace(ctx, successPluginID, false); err != nil {
		t.Fatalf("DeleteNamespace(retain success) error = %v", err)
	}
	deleteAfter := now.Add(-time.Minute)
	successRecord, err := retainedRegistry.Retain(ctx, retaineddata.RetainRequest{
		RetainedID:             "retained_expired_success",
		SourcePluginInstanceID: successPluginID,
		PublisherID:            "example",
		PluginID:               "com.example.storage",
		Version:                "1.0.0",
		PackageHash:            "sha256:package-success",
		ManifestHash:           "sha256:manifest-success",
		StorageRetained:        true,
		DeleteAfter:            &deleteAfter,
		Now:                    now.Add(-2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Retain(success) error = %v", err)
	}

	failedPluginID := "plugini_retained_expired_failed"
	if _, err := browserSite.RegisterOrigin(ctx, browsersite.RegisterRequest{
		PluginInstanceID:  failedPluginID,
		PluginID:          "com.example.browser",
		ActiveFingerprint: "sha256:browser",
		Origin:            "https://plg-failed.sandbox.redevplugin.local",
		OwnerSessionHash:  "session_failed",
		Now:               now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("RegisterOrigin(failed) error = %v", err)
	}
	if _, err := browserSite.CleanupPluginOrigins(ctx, browsersite.CleanupRequest{
		PluginInstanceID: failedPluginID,
		DeleteData:       false,
		Reason:           "test_retain",
		Now:              now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CleanupPluginOrigins(retain failed) error = %v", err)
	}
	failedRecord, err := retainedRegistry.Retain(ctx, retaineddata.RetainRequest{
		RetainedID:             "retained_expired_failed",
		SourcePluginInstanceID: failedPluginID,
		PublisherID:            "example",
		PluginID:               "com.example.browser",
		Version:                "1.0.0",
		PackageHash:            "sha256:package-failed",
		ManifestHash:           "sha256:manifest-failed",
		BrowserSiteRetained:    true,
		DeleteAfter:            &deleteAfter,
		Now:                    now.Add(-2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Retain(failed) error = %v", err)
	}

	result, err := h.CleanupExpiredRetainedData(ctx, CleanupExpiredRetainedDataRequest{Now: now})
	if !errors.Is(err, ErrRetainedDataCleanupFailed) {
		t.Fatalf("CleanupExpiredRetainedData() error = %v, want ErrRetainedDataCleanupFailed", err)
	}
	if len(result.Deleted) != 1 || result.Deleted[0].RetainedID != successRecord.RetainedID || result.Deleted[0].State != retaineddata.StateDeleted {
		t.Fatalf("deleted cleanup result mismatch: %#v", result.Deleted)
	}
	if len(result.Failed) != 1 || result.Failed[0].RetainedID != failedRecord.RetainedID || result.Failed[0].State != retaineddata.StateDeleteFailedRetryable {
		t.Fatalf("failed cleanup result mismatch: %#v", result.Failed)
	}
	if namespaces, err := broker.ListNamespaces(ctx, successPluginID); err != nil {
		t.Fatal(err)
	} else if len(namespaces) != 0 {
		t.Fatalf("expired retained storage still present: %#v", namespaces)
	}
	storedFailed, err := retainedRegistry.Get(ctx, failedRecord.RetainedID)
	if err != nil {
		t.Fatal(err)
	}
	if storedFailed.State != retaineddata.StateDeleteFailedRetryable || storedFailed.DeleteError == "" {
		t.Fatalf("failed retained record mismatch: %#v", storedFailed)
	}
	if !audits.hasEvent("plugin.retained_data.deleted") || !audits.hasEvent("plugin.retained_data.delete_failed") {
		t.Fatalf("missing retained cleanup audit events: %#v", audits.events)
	}
}

func TestCleanupExpiredRetainedDataMaxRecordsKeepsExpiredQueue(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 11, 0, 0, 0, time.UTC)
	broker := storage.NewMemoryBroker()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
		retainedData:   retainedRegistry,
	})
	deleteAfter := now.Add(-time.Minute)
	for index, pluginInstanceID := range []string{"plugini_retained_queue_1", "plugini_retained_queue_2"} {
		if err := broker.EnsureNamespace(ctx, storage.Namespace{
			PluginInstanceID: pluginInstanceID,
			StoreID:          "cache",
			Kind:             storage.StoreKV,
			QuotaBytes:       1024,
			SchemaVersion:    1,
		}); err != nil {
			t.Fatalf("EnsureNamespace(%s) error = %v", pluginInstanceID, err)
		}
		if err := broker.DeleteNamespace(ctx, pluginInstanceID, false); err != nil {
			t.Fatalf("DeleteNamespace(retain %s) error = %v", pluginInstanceID, err)
		}
		if _, err := retainedRegistry.Retain(ctx, retaineddata.RetainRequest{
			RetainedID:             fmt.Sprintf("retained_queue_%d", index+1),
			SourcePluginInstanceID: pluginInstanceID,
			PublisherID:            "example",
			PluginID:               "com.example.queue",
			Version:                "1.0.0",
			PackageHash:            fmt.Sprintf("sha256:package-queue-%d", index+1),
			ManifestHash:           fmt.Sprintf("sha256:manifest-queue-%d", index+1),
			StorageRetained:        true,
			DeleteAfter:            &deleteAfter,
			Now:                    now.Add(time.Duration(index-2) * time.Hour),
		}); err != nil {
			t.Fatalf("Retain(%s) error = %v", pluginInstanceID, err)
		}
	}

	first, err := h.CleanupExpiredRetainedData(ctx, CleanupExpiredRetainedDataRequest{Now: now, MaxRecords: 1})
	if err != nil {
		t.Fatalf("CleanupExpiredRetainedData(first) error = %v", err)
	}
	if len(first.Deleted) != 1 || first.Deleted[0].RetainedID != "retained_queue_1" {
		t.Fatalf("first cleanup result mismatch: %#v", first)
	}
	queued, err := retainedRegistry.Get(ctx, "retained_queue_2")
	if err != nil {
		t.Fatal(err)
	}
	if queued.State != retaineddata.StateExpired {
		t.Fatalf("unprocessed retained record state = %s, want expired", queued.State)
	}

	second, err := h.CleanupExpiredRetainedData(ctx, CleanupExpiredRetainedDataRequest{Now: now.Add(time.Minute), MaxRecords: 1})
	if err != nil {
		t.Fatalf("CleanupExpiredRetainedData(second) error = %v", err)
	}
	if len(second.Deleted) != 1 || second.Deleted[0].RetainedID != "retained_queue_2" {
		t.Fatalf("second cleanup result mismatch: %#v", second)
	}
}

func TestDeleteRetainedDataRefusesActiveStoragePayload(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	broker := storage.NewMemoryBroker()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
		retainedData:   retainedRegistry,
	})
	pluginInstanceID := "plugini_retained_reactivated"
	namespace := storage.Namespace{
		PluginInstanceID: pluginInstanceID,
		StoreID:          "cache",
		Kind:             storage.StoreKV,
		QuotaBytes:       1024,
		SchemaVersion:    1,
	}
	if err := broker.EnsureNamespace(ctx, namespace); err != nil {
		t.Fatalf("EnsureNamespace(initial) error = %v", err)
	}
	if _, err := broker.PutKV(ctx, storage.KVPutRequest{
		PluginInstanceID: pluginInstanceID,
		StoreID:          "cache",
		Key:              "active/key",
		Value:            []byte("still-active"),
	}); err != nil {
		t.Fatalf("PutKV(initial) error = %v", err)
	}
	if err := broker.DeleteNamespace(ctx, pluginInstanceID, false); err != nil {
		t.Fatalf("DeleteNamespace(retain) error = %v", err)
	}
	record, err := retainedRegistry.Retain(ctx, retaineddata.RetainRequest{
		RetainedID:             "retained_reactivated",
		SourcePluginInstanceID: pluginInstanceID,
		PublisherID:            "example",
		PluginID:               "com.example.reactivated",
		Version:                "1.0.0",
		PackageHash:            "sha256:package-reactivated",
		ManifestHash:           "sha256:manifest-reactivated",
		StorageRetained:        true,
		Now:                    now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Retain() error = %v", err)
	}
	if err := broker.EnsureNamespace(ctx, namespace); err != nil {
		t.Fatalf("EnsureNamespace(reactivate) error = %v", err)
	}

	failed, err := h.DeleteRetainedData(ctx, DeleteRetainedDataRequest{RetainedID: record.RetainedID, Now: now})
	if !errors.Is(err, ErrRetainedDataCleanupFailed) {
		t.Fatalf("DeleteRetainedData() error = %v, want ErrRetainedDataCleanupFailed", err)
	}
	if failed.State != retaineddata.StateDeleteFailedRetryable || failed.DeleteError == "" {
		t.Fatalf("failed retained record mismatch: %#v", failed)
	}
	value, err := broker.GetKV(ctx, storage.KVGetRequest{
		PluginInstanceID: pluginInstanceID,
		StoreID:          "cache",
		Key:              "active/key",
	})
	if err != nil {
		t.Fatalf("GetKV(active) error = %v", err)
	}
	if string(value.Value) != "still-active" {
		t.Fatalf("active value changed: %q", string(value.Value))
	}
}

func TestUninstallRevokesSurfaceTokensAndRuntime(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		revokeResult: runtimeclient.RevokeResult{
			ClosedActorCount:         7,
			ClosedSocketCount:        8,
			ClosedStreamCount:        9,
			ClosedStorageHandleCount: 10,
		},
	}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		runtimeSupervisor: runtime,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.activity")
	uninstalled, err := h.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true})
	if err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	if runtime.revokeCalls != 2 || runtime.lastRevokedPlugin != installed.PluginInstanceID || runtime.lastRevokeEpoch != uninstalled.RevokeEpoch {
		t.Fatalf("runtime revoke mismatch: calls=%d plugin=%q epoch=%d uninstalled=%#v", runtime.revokeCalls, runtime.lastRevokedPlugin, runtime.lastRevokeEpoch, uninstalled)
	}
	if _, err := h.surfaceTokens.ValidateGatewayToken(gateway.GatewayToken, bridge.Audience{
		PluginInstanceID:     installed.PluginInstanceID,
		ActiveFingerprint:    installed.ActiveFingerprint,
		SurfaceInstanceID:    "surface_rpc",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_rpc",
	}, bridge.RevisionBinding{
		PolicyRevision:     installed.PolicyRevision,
		ManagementRevision: installed.ManagementRevision,
		RevokeEpoch:        installed.RevokeEpoch,
	}, time.Now().UTC()); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ValidateGatewayToken() after uninstall error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatalf("missing runtime capability revocation audit event: %#v", audits.events)
	}
	event, ok := audits.lastEvent("plugin.runtime_capabilities.revoked")
	if !ok {
		t.Fatalf("missing runtime capability revocation audit event: %#v", audits.events)
	}
	assertAuditDetail(t, event, "closed_actor_count", 7)
	assertAuditDetail(t, event, "closed_socket_count", 8)
	assertAuditDetail(t, event, "closed_stream_count", 9)
	assertAuditDetail(t, event, "closed_storage_handle_count", 10)
}

func TestUninstallEnabledPluginClearsSurfacesStreamsAndNetworkPolicy(t *testing.T) {
	ctx := context.Background()
	connectivityBroker := connectivity.NewMemoryBroker()
	h, surfaces, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: connectivityBroker,
		storageBroker:      storage.NewMemoryBroker(),
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if len(surfaces.snapshots) != 1 || len(surfaces.snapshots[0].Surfaces) != 1 {
		t.Fatalf("enable surface publish mismatch: %#v", surfaces.snapshots)
	}
	if _, err := connectivityBroker.MintConnectionGrant(ctx, connectivity.GrantRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		ActiveFingerprint:  enabled.ActiveFingerprint,
		PolicyRevision:     enabled.PolicyRevision,
		ManagementRevision: enabled.ManagementRevision,
		RevokeEpoch:        enabled.RevokeEpoch,
		ConnectorID:        "api",
		Transport:          connectivity.TransportHTTP,
		Destination:        "https://api.example.com",
	}); err != nil {
		t.Fatalf("MintConnectionGrant() before uninstall error = %v", err)
	}
	if _, err := h.adapters.Streams.Register(ctx, stream.RegisterRequest{
		StreamID:             "stream_uninstall_1",
		PluginID:             enabled.PluginID,
		PluginInstanceID:     enabled.PluginInstanceID,
		Method:               "network.watch",
		Execution:            string(manifest.MethodExecutionSubscription),
		SurfaceInstanceID:    "surface_network",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_network",
	}); err != nil {
		t.Fatalf("Streams.Register() error = %v", err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: enabled.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}

	if len(surfaces.snapshots) != 2 || len(surfaces.snapshots[1].Surfaces) != 0 {
		t.Fatalf("uninstall did not clear surfaces: %#v", surfaces.snapshots)
	}
	assertHostStreamStatus(t, h, "stream_uninstall_1", stream.StatusOrphanedRemoved)
	if _, err := h.AppendStreamEvent(ctx, AppendStreamEventRequest{
		StreamID: "stream_uninstall_1",
		Data:     []byte("line after uninstall"),
	}); !errors.Is(err, stream.ErrStreamClosed) {
		t.Fatalf("AppendStreamEvent() after uninstall error = %v, want %v", err, stream.ErrStreamClosed)
	}
	if _, err := connectivityBroker.MintConnectionGrant(ctx, connectivity.GrantRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		ActiveFingerprint:  enabled.ActiveFingerprint,
		PolicyRevision:     enabled.PolicyRevision,
		ManagementRevision: enabled.ManagementRevision,
		RevokeEpoch:        enabled.RevokeEpoch,
		ConnectorID:        "api",
		Transport:          connectivity.TransportHTTP,
		Destination:        "https://api.example.com",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant() after uninstall error = %v, want %v", err, connectivity.ErrConnectorDenied)
	}
	if !audits.hasEvent("plugin.streams.uninstalled_transitioned") {
		t.Fatalf("missing uninstalled stream transition audit event: %#v", audits.events)
	}
}

func TestUninstallRetainsOrDeletesBrowserSiteData(t *testing.T) {
	ctx := context.Background()
	retainBrowserSite := browsersite.NewMemoryStore()
	retainHost, _, retainAudits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		browserSite:    retainBrowserSite,
	})
	retainedPlugin, err := ImportLocalPackageBytes(ctx, retainHost, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retainHost.EnablePlugin(ctx, EnableRequest{PluginInstanceID: retainedPlugin.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := retainHost.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  retainedPlugin.PluginInstanceID,
		SurfaceID:         "lifecycle.activity",
		SurfaceInstanceID: "surface_retain_browser",
		OwnerSessionHash:  "session_retain",
		SandboxOrigin:     "https://plg-retain.sandbox.redevplugin.local",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := retainHost.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: retainedPlugin.PluginInstanceID, DeleteData: false}); err != nil {
		t.Fatalf("UninstallPlugin(retain) error = %v", err)
	}
	retainedOrigins, err := retainBrowserSite.ListOrigins(ctx, browsersite.ListRequest{PluginInstanceID: retainedPlugin.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(retainedOrigins) != 1 || retainedOrigins[0].State != browsersite.StateRetained || retainedOrigins[0].RetainedAt == nil {
		t.Fatalf("retained browser origins mismatch: %#v", retainedOrigins)
	}
	if !retainAudits.hasEvent("plugin.browser_site.retained") {
		t.Fatalf("missing retained browser site audit event: %#v", retainAudits.events)
	}

	cleaner := &recordingBrowserSiteCleaner{}
	deleteBrowserSite := browsersite.NewMemoryStore(browsersite.MemoryStoreOptions{Cleaner: cleaner})
	deleteHost, _, deleteAudits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		browserSite:    deleteBrowserSite,
	})
	deletedPlugin, err := ImportLocalPackageBytes(ctx, deleteHost, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deleteHost.EnablePlugin(ctx, EnableRequest{PluginInstanceID: deletedPlugin.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := deleteHost.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  deletedPlugin.PluginInstanceID,
		SurfaceID:         "lifecycle.activity",
		SurfaceInstanceID: "surface_delete_browser",
		OwnerSessionHash:  "session_delete",
		SandboxOrigin:     "https://plg-delete.sandbox.redevplugin.local",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := deleteHost.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: deletedPlugin.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin(delete) error = %v", err)
	}
	if len(cleaner.origins) != 1 || cleaner.origins[0] != "https://plg-delete.sandbox.redevplugin.local" {
		t.Fatalf("cleaned origins mismatch: %#v", cleaner.origins)
	}
	deletedOrigins, err := deleteBrowserSite.ListOrigins(ctx, browsersite.ListRequest{PluginInstanceID: deletedPlugin.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(deletedOrigins) != 1 || deletedOrigins[0].State != browsersite.StateCleanupComplete || deletedOrigins[0].CleanedAt == nil {
		t.Fatalf("deleted browser origins mismatch: %#v", deletedOrigins)
	}
	if !deleteAudits.hasEvent("plugin.browser_site.deleted") {
		t.Fatalf("missing deleted browser site audit event: %#v", deleteAudits.events)
	}
}

func TestUninstallDeleteDataFailsWhenBrowserSiteCleanupFails(t *testing.T) {
	ctx := context.Background()
	cleaner := &recordingBrowserSiteCleaner{err: errors.New("browser profile locked")}
	browserSite := browsersite.NewMemoryStore(browsersite.MemoryStoreOptions{Cleaner: cleaner})
	diagnostics := &diagnosticSink{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		browserSite:    browserSite,
		diagnostics:    diagnostics,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "lifecycle.activity",
		SurfaceInstanceID: "surface_cleanup_failure",
		OwnerSessionHash:  "session_failure",
		SandboxOrigin:     "https://plg-failure.sandbox.redevplugin.local",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); !errors.Is(err, browsersite.ErrCleanupFailed) {
		t.Fatalf("UninstallPlugin(delete) error = %v, want ErrCleanupFailed", err)
	}
	if _, err := h.adapters.Registry.GetPlugin(ctx, installed.PluginInstanceID); err != nil {
		t.Fatalf("plugin should remain installed after failed browser cleanup: %v", err)
	}
	origins, err := browserSite.ListOrigins(ctx, browsersite.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 1 || origins[0].State != browsersite.StateCleanupFailed || origins[0].CleanupError == "" {
		t.Fatalf("failed browser origin mismatch: %#v", origins)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Type != "plugin.browser_site.cleanup_failed" {
		t.Fatalf("diagnostic events mismatch: %#v", diagnostics.events)
	}
}

func TestUninstallDeletesFileStorageNamespaces(t *testing.T) {
	ctx := context.Background()
	broker, err := storage.NewFileBroker(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileBroker() error = %v", err)
	}
	h, _, _ := newTestHostWithStorage(t, true, true, broker)
	installed, err := ImportLocalPackageBytes(ctx, h, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	dataPath, err := broker.NamespacePath(ctx, installed.PluginInstanceID, "cache")
	if err != nil {
		t.Fatal(err)
	}
	dataFile := filepath.Join(dataPath, "preferences.json")
	if err := os.WriteFile(dataFile, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin(delete data) error = %v", err)
	}
	if _, err := os.Stat(dataFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted storage file stat error = %v, want not exist", err)
	}
	namespaces, err := broker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("deleted storage namespaces still listed: %#v", namespaces)
	}
}

func TestDisableTransitionsOperations(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	cancelOp, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{
		OperationID:      "op_disable_cancel",
		PluginID:         installed.PluginID,
		PluginInstanceID: installed.PluginInstanceID,
		Method:           "images.pull",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitOp, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{
		OperationID:      "op_disable_wait",
		PluginID:         installed.PluginID,
		PluginInstanceID: installed.PluginInstanceID,
		Method:           "sync.wait",
		DisableBehavior:  operation.DisableBehaviorWait,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy"}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	assertHostOperationStatus(t, h, cancelOp.OperationID, operation.StatusCancelRequested)
	assertHostOperationStatus(t, h, waitOp.OperationID, operation.StatusRunning)
}

func TestUninstallDeleteDataBlockedByRunningOperation(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	cleanupOrchestrator := cleanup.NewMemoryOrchestrator()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
		cleanup:        cleanupOrchestrator,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:      "op_blocks_delete",
		PluginID:         installed.PluginID,
		PluginInstanceID: installed.PluginInstanceID,
		Method:           "images.pull",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() error = %v, want ErrDeleteBlocked", err)
	}
	assertHostOperationStatus(t, h, "op_blocks_delete", operation.StatusCancelRequested)
	namespaces, err := broker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) == 0 {
		t.Fatal("storage namespaces were deleted despite blocked operation")
	}
	if !audits.hasEvent("plugin.operations.delete_blocked") {
		t.Fatalf("missing blocked audit event: %#v", audits.events)
	}
	executions, err := cleanupOrchestrator.ListExecutions(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(executions) != 0 {
		t.Fatalf("cleanup executed despite blocked operation: %#v", executions)
	}
}

func TestUninstallDeleteDataSucceedsAfterOperationCancelAck(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, _ := newTestHostWithStorage(t, true, true, broker)
	installed, err := ImportLocalPackageBytes(ctx, h, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:      "op_cancel_then_delete",
		PluginID:         installed.PluginID,
		PluginInstanceID: installed.PluginInstanceID,
		Method:           "images.pull",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() first error = %v, want ErrDeleteBlocked", err)
	}
	if _, err := h.FinishOperation(ctx, FinishOperationRequest{
		OperationID: "op_cancel_then_delete",
		Status:      operation.StatusCanceled,
		Reason:      "runtime ack",
	}); err != nil {
		t.Fatalf("FinishOperation() error = %v", err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin() retry error = %v", err)
	}
	namespaces, err := broker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("storage namespaces still present: %#v", namespaces)
	}
}

func TestUninstallForceCleanupOperationAllowsDeleteData(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, _ := newTestHostWithStorage(t, true, true, broker)
	installed, err := ImportLocalPackageBytes(ctx, h, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:       "op_force_cleanup",
		PluginID:          installed.PluginID,
		PluginInstanceID:  installed.PluginInstanceID,
		Method:            "cleanup.force",
		UninstallBehavior: operation.UninstallBehaviorForceCleanupAllowed,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	assertHostOperationStatus(t, h, "op_force_cleanup", operation.StatusOrphanedAfterUninstall)
	namespaces, err := broker.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("storage namespaces still present: %#v", namespaces)
	}
}

func TestExportImportPluginData(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, audits := newTestHostWithStorage(t, true, true, broker)
	source, err := ImportLocalPackageBytes(ctx, h, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if err := broker.SetUsage(ctx, source.PluginInstanceID, "db", 2048); err != nil {
		t.Fatal(err)
	}

	exported, err := h.ExportPluginData(ctx, ExportDataRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatalf("ExportPluginData() error = %v", err)
	}
	if err := broker.SetUsage(ctx, source.PluginInstanceID, "db", 0); err != nil {
		t.Fatal(err)
	}
	if err := h.ImportPluginData(ctx, ImportDataRequest{
		PluginInstanceID: source.PluginInstanceID,
		ArchiveRef:       exported.ArchiveRef,
		DeleteExisting:   true,
	}); err != nil {
		t.Fatalf("ImportPluginData() error = %v", err)
	}
	usage, err := broker.Usage(ctx, source.PluginInstanceID, "db")
	if err != nil {
		t.Fatal(err)
	}
	if usage.UsageBytes != 2048 {
		t.Fatalf("imported usage = %d, want 2048", usage.UsageBytes)
	}
	if !audits.hasEvent("plugin.data.exported") || !audits.hasEvent("plugin.data.imported") {
		t.Fatalf("missing data audit events: %#v", audits.events)
	}
}

func TestExportImportPluginSettingsData(t *testing.T) {
	ctx := context.Background()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  storage.NewMemoryBroker(),
		secrets:        &recordingSecretStore{},
	})
	source, err := ImportLocalPackageBytes(ctx, h, buildSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.PatchPluginSettings(ctx, PatchSettingsRequest{
		PluginInstanceID: source.PluginInstanceID,
		Values:           map[string]any{"default_engine": "podman", "show_stopped": false},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.BindSecretRef(ctx, SecretBindRequest{
		PluginInstanceID: source.PluginInstanceID,
		SecretRef:        "api_token",
		Scope:            "user",
	}); err != nil {
		t.Fatal(err)
	}

	exported, err := h.ExportPluginData(ctx, ExportDataRequest{PluginInstanceID: source.PluginInstanceID, IncludeSecrets: true})
	if err != nil {
		t.Fatalf("ExportPluginData(settings) error = %v", err)
	}
	if exported.ArchiveRef != "" {
		t.Fatalf("settings-only export should not create storage archive: %#v", exported)
	}
	if exported.SettingsArchiveRef == "" {
		t.Fatal("settings export response missing settings_archive_ref")
	}
	if _, err := h.PatchPluginSettings(ctx, PatchSettingsRequest{
		PluginInstanceID: source.PluginInstanceID,
		Values:           map[string]any{"default_engine": "docker", "show_stopped": true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.DeleteSecretRef(ctx, SecretDeleteRequest{
		PluginInstanceID: source.PluginInstanceID,
		SecretRef:        "api_token",
		Scope:            "user",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.ImportPluginData(ctx, ImportDataRequest{
		PluginInstanceID:   source.PluginInstanceID,
		SettingsArchiveRef: exported.SettingsArchiveRef,
		DeleteExisting:     true,
	}); err != nil {
		t.Fatalf("ImportPluginData(settings) error = %v", err)
	}
	imported, err := h.GetPluginSettings(ctx, GetSettingsRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if imported.Values["default_engine"] != "podman" || imported.Values["show_stopped"] != false {
		t.Fatalf("imported settings mismatch: %#v", imported.Values)
	}
	secret, ok := imported.Values["api_token"].(settings.SecretValue)
	if !ok {
		t.Fatalf("imported secret should be redacted state: %#v", imported.Values["api_token"])
	}
	if secret.Set {
		t.Fatalf("settings import must not restore secret binding state: %#v", secret)
	}
	if !audits.hasEvent("plugin.data.exported") || !audits.hasEvent("plugin.data.imported") {
		t.Fatalf("missing data audit events: %#v", audits.events)
	}
}

func TestImportPluginDataRequiresStorageDeclaration(t *testing.T) {
	ctx := context.Background()
	broker := storage.NewMemoryBroker()
	h, _, _ := newTestHostWithStorage(t, true, true, broker)
	source, err := ImportLocalPackageBytes(ctx, h, buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}
	exported, err := h.ExportPluginData(ctx, ExportDataRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}

	target, err := ImportLocalPackageBytes(ctx, h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.ImportPluginData(ctx, ImportDataRequest{
		PluginInstanceID: target.PluginInstanceID,
		ArchiveRef:       exported.ArchiveRef,
		DeleteExisting:   true,
	}); err == nil {
		t.Fatal("ImportPluginData() expected storage declaration error")
	}
}

func TestSecretLifecycleUsesAdapter(t *testing.T) {
	secrets := &recordingSecretStore{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		secrets:        secrets,
	})
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	req := SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        " api_token ",
		Scope:            "user",
	}
	if err := h.BindSecretRef(context.Background(), req); err != nil {
		t.Fatalf("BindSecretRef() error = %v", err)
	}
	if err := h.TestSecretRef(context.Background(), SecretTestRequest(req)); err != nil {
		t.Fatalf("TestSecretRef() error = %v", err)
	}
	if err := h.DeleteSecretRef(context.Background(), SecretDeleteRequest(req)); err != nil {
		t.Fatalf("DeleteSecretRef() error = %v", err)
	}
	if secrets.bind.PluginInstanceID != installed.PluginInstanceID || secrets.bind.SecretRef != "api_token" || secrets.bind.Scope != "user" {
		t.Fatalf("bind request was not normalized: %#v", secrets.bind)
	}
	if secrets.test.SecretRef != "api_token" || secrets.delete.SecretRef != "api_token" {
		t.Fatalf("secret calls mismatch: test=%#v delete=%#v", secrets.test, secrets.delete)
	}
	if !audits.hasEvent("plugin.secret.bound") || !audits.hasEvent("plugin.secret.tested") || !audits.hasEvent("plugin.secret.deleted") {
		t.Fatalf("missing secret audit events: %#v", audits.events)
	}
}

func TestSettingsLifecycleDefaultsPatchSecretsAndDelete(t *testing.T) {
	secrets := &recordingSecretStore{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		secrets:        secrets,
	})
	ctx := context.Background()
	installed, err := ImportLocalPackageBytes(ctx, h, buildSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	schema, err := h.GetSettingsSchema(ctx, GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("GetSettingsSchema() error = %v", err)
	}
	if schema.SchemaVersion != 1 || len(schema.Fields) != 3 || schema.SettingsRevision == 0 {
		t.Fatalf("settings schema mismatch: %#v", schema)
	}

	initial, err := h.GetPluginSettings(ctx, GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("GetPluginSettings() error = %v", err)
	}
	if initial.Values["default_engine"] != "docker" {
		t.Fatalf("default settings mismatch: %#v", initial)
	}
	secret, ok := initial.Values["api_token"].(settings.SecretValue)
	if !ok || secret.Set {
		t.Fatalf("secret setting should be redacted unset state: %#v", initial.Values["api_token"])
	}

	patched, err := h.PatchPluginSettings(ctx, PatchSettingsRequest{
		PluginInstanceID: installed.PluginInstanceID,
		Values:           map[string]any{"default_engine": "podman"},
	})
	if err != nil {
		t.Fatalf("PatchPluginSettings() error = %v", err)
	}
	if patched.SettingsRevision <= initial.SettingsRevision || patched.Values["default_engine"] != "podman" {
		t.Fatalf("patched settings mismatch: before=%#v after=%#v", initial, patched)
	}
	if _, err := h.PatchPluginSettings(ctx, PatchSettingsRequest{
		PluginInstanceID: installed.PluginInstanceID,
		Values:           map[string]any{"api_token": "plaintext"},
	}); !errors.Is(err, settings.ErrInvalidSetting) {
		t.Fatalf("PatchPluginSettings(secret) error = %v, want ErrInvalidSetting", err)
	}

	if err := h.BindSecretRef(ctx, SecretBindRequest{PluginInstanceID: installed.PluginInstanceID, SecretRef: "api_token", Scope: "user"}); err != nil {
		t.Fatalf("BindSecretRef() error = %v", err)
	}
	if err := h.TestSecretRef(ctx, SecretTestRequest{PluginInstanceID: installed.PluginInstanceID, SecretRef: "api_token", Scope: "user"}); err != nil {
		t.Fatalf("TestSecretRef() error = %v", err)
	}
	withSecret, err := h.GetPluginSettings(ctx, GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	secret, ok = withSecret.Values["api_token"].(settings.SecretValue)
	if !ok || !secret.Set || secret.LastTestStatus != "passed" {
		t.Fatalf("secret setting state mismatch: %#v", withSecret.Values["api_token"])
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); err != nil {
		t.Fatalf("UninstallPlugin(delete data) error = %v", err)
	}
	if secrets.deletePluginID != installed.PluginInstanceID {
		t.Fatalf("secret bindings were not deleted on uninstall delete data: %#v", secrets)
	}
	if _, err := h.adapters.Settings.Get(ctx, settings.GetRequest{PluginInstanceID: installed.PluginInstanceID}); !errors.Is(err, settings.ErrNotDeclared) {
		t.Fatalf("settings should be deleted after uninstall delete data: %v", err)
	}
	if !audits.hasEvent("plugin.settings.updated") || !audits.hasEvent("plugin.settings.deleted") || !audits.hasEvent("plugin.secrets.deleted") {
		t.Fatalf("missing settings audit events: %#v", audits.events)
	}
}

func TestSecretLifecycleValidatesRequestAndAdapter(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	withSecrets, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		secrets:        &recordingSecretStore{},
	})
	if err := withSecrets.BindSecretRef(context.Background(), SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        "token",
		Scope:            "global",
	}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("BindSecretRef() error = %v, want ErrInvalidSecretRef", err)
	}

	if err := h.BindSecretRef(context.Background(), SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        "token",
		Scope:            "user",
	}); !errors.Is(err, ErrSecretStoreRequired) {
		t.Fatalf("BindSecretRef() error = %v, want ErrSecretStoreRequired", err)
	}
	withSecretsInstalled, err := ImportLocalPackageBytes(context.Background(), withSecrets, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := withSecrets.BindSecretRef(context.Background(), SecretBindRequest{
		PluginInstanceID: withSecretsInstalled.PluginInstanceID,
		SecretRef:        "token",
		Scope:            "user",
	}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("BindSecretRef(undeclared) error = %v, want ErrInvalidSecretRef", err)
	}
}

func TestUninstallDeleteDataRequiresSecretPluginCleanup(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		secrets:        &secretStoreWithoutPluginCleanup{},
	})
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.BindSecretRef(context.Background(), SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        "api_token",
		Scope:            "user",
	}); err != nil {
		t.Fatalf("BindSecretRef() error = %v", err)
	}
	if _, err := h.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true}); err == nil || !strings.Contains(err.Error(), "secret store does not support plugin cleanup") {
		t.Fatalf("UninstallPlugin(delete data) error = %v, want secret cleanup support error", err)
	}
	if _, err := h.adapters.Settings.Get(context.Background(), settings.GetRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("settings should not be deleted when secret cleanup preflight fails: %v", err)
	}
}

func TestReportCSPViolationAppendsDiagnostic(t *testing.T) {
	diagnostics := &diagnosticSink{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		diagnostics:    diagnostics,
	})
	err := h.ReportCSPViolation(context.Background(), CSPViolationReport{
		PluginID:           "com.example.plugin",
		PluginInstanceID:   "plugin_instance",
		SurfaceID:          "activity",
		SurfaceInstanceID:  "surface_instance",
		ActiveFingerprint:  "sha256:fingerprint",
		BlockedURI:         "inline",
		EffectiveDirective: "script-src",
		LineNumber:         12,
	})
	if err != nil {
		t.Fatalf("ReportCSPViolation() error = %v", err)
	}
	if len(diagnostics.events) != 1 {
		t.Fatalf("diagnostic events = %#v", diagnostics.events)
	}
	event := diagnostics.events[0]
	if event.Type != "plugin.csp.violation" || event.Severity != "warning" || event.Message != "script-src" || event.PluginInstanceID != "plugin_instance" || event.Details["blocked_uri"] != "inline" {
		t.Fatalf("diagnostic event mismatch: %#v", event)
	}
}

func TestDefaultObservabilityStoreListsAuditAndDiagnostics(t *testing.T) {
	h, err := New(Adapters{
		SessionResolver:      fakeSessionResolver{},
		Policy:               policyAdapter{developerMode: true, localGenerated: true, decision: PolicyAllow},
		PackageTrustVerifier: &recordingPackageTrustVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatal(err)
	}

	auditEvents, err := h.ListAuditEvents(context.Background(), ListAuditEventsRequest{
		PluginInstanceID: installed.PluginInstanceID,
		Type:             "plugin.enabled",
	})
	if err != nil {
		t.Fatalf("ListAuditEvents() error = %v", err)
	}
	if len(auditEvents) != 1 || auditEvents[0].PluginID != installed.PluginID || auditEvents[0].OccurredAt.IsZero() {
		t.Fatalf("audit events mismatch: %#v", auditEvents)
	}

	if err := h.ReportCSPViolation(context.Background(), CSPViolationReport{
		PluginID:           installed.PluginID,
		PluginInstanceID:   installed.PluginInstanceID,
		SurfaceInstanceID:  "surface_default_observability",
		EffectiveDirective: "script-src",
	}); err != nil {
		t.Fatal(err)
	}
	diagnosticEvents, err := h.ListDiagnosticEvents(context.Background(), ListDiagnosticEventsRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_default_observability",
		Severity:          "warning",
	})
	if err != nil {
		t.Fatalf("ListDiagnosticEvents() error = %v", err)
	}
	if len(diagnosticEvents) != 1 || diagnosticEvents[0].Type != "plugin.csp.violation" || diagnosticEvents[0].Message != "script-src" {
		t.Fatalf("diagnostic events mismatch: %#v", diagnosticEvents)
	}
}

func newTestHost(t *testing.T, developerMode bool, localGenerated bool) (*Host, *surfaceSink, *auditSink) {
	return newTestHostWithOptions(t, testHostOptions{developerMode: developerMode, localGenerated: localGenerated})
}

func newTestHostWithStorage(t *testing.T, developerMode bool, localGenerated bool, storageBroker storage.Broker) (*Host, *surfaceSink, *auditSink) {
	return newTestHostWithOptions(t, testHostOptions{developerMode: developerMode, localGenerated: localGenerated, storageBroker: storageBroker})
}

type testHostOptions struct {
	developerMode           bool
	localGenerated          bool
	policyDecision          PolicyDecision
	trustVerifier           PackageTrustVerifier
	releaseMetadataVerifier ReleaseMetadataVerifier
	releaseSourcePolicy     ReleaseSourcePolicyResolver
	releaseArtifactResolver ReleaseArtifactResolver
	storageBroker           storage.Broker
	connectivityBroker      connectivity.Broker
	networkExecutor         connectivity.NetworkExecutor
	cleanup                 cleanup.Orchestrator
	retainedData            retaineddata.Store
	browserSite             browsersite.Store
	installStages           installstage.Store
	permissions             permissions.Store
	securityPolicy          security.PolicyStore
	confirmationIntents     security.ConfirmationIntentStore
	runtimeSupervisor       runtimeclient.Supervisor
	runtimeArtifactResolver RuntimeArtifactResolver
	secrets                 SecretStoreAdapter
	diagnostics             DiagnosticsSink
	capabilityID            string
	capabilityAdapter       capability.Adapter
	coreActions             CoreActionAdapter
	operationCanceler       OperationCanceler
}

func newTestHostWithOptions(t *testing.T, opts testHostOptions) (*Host, *surfaceSink, *auditSink) {
	t.Helper()
	surfaces := &surfaceSink{}
	audits := &auditSink{}
	capabilities := capability.NewRegistry()
	if opts.capabilityID != "" && opts.capabilityAdapter != nil {
		capabilities.Register(opts.capabilityID, opts.capabilityAdapter)
	}
	decision := opts.policyDecision
	if decision == "" {
		decision = PolicyAllow
	}
	trustVerifier := opts.trustVerifier
	if trustVerifier == nil {
		trustVerifier = &recordingPackageTrustVerifier{}
	}
	host, err := New(Adapters{
		SessionResolver: fakeSessionResolver{},
		Policy: policyAdapter{
			developerMode:  opts.developerMode,
			localGenerated: opts.localGenerated,
			decision:       decision,
		},
		PackageTrustVerifier:    trustVerifier,
		ReleaseMetadataVerifier: opts.releaseMetadataVerifier,
		ReleaseSourcePolicy:     opts.releaseSourcePolicy,
		ReleaseArtifactResolver: opts.releaseArtifactResolver,
		SurfaceCatalog:          surfaces,
		Audit:                   audits,
		Diagnostics:             opts.diagnostics,
		Storage:                 opts.storageBroker,
		Connectivity:            opts.connectivityBroker,
		NetworkExecutor:         opts.networkExecutor,
		Cleanup:                 opts.cleanup,
		RetainedData:            opts.retainedData,
		BrowserSite:             opts.browserSite,
		InstallStages:           opts.installStages,
		Permissions:             opts.permissions,
		SecurityPolicy:          opts.securityPolicy,
		ConfirmationIntents:     opts.confirmationIntents,
		RuntimeSupervisor:       opts.runtimeSupervisor,
		RuntimeArtifactResolver: opts.runtimeArtifactResolver,
		Secrets:                 opts.secrets,
		Capabilities:            capabilities,
		CoreActions:             opts.coreActions,
		OperationCanceler:       opts.operationCanceler,
	})
	if err != nil {
		t.Fatal(err)
	}
	return host, surfaces, audits
}

func buildFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), fixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Plugin</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildVersionedLifecyclePackage(t *testing.T, version string, title string) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), lifecycleManifestJSON(version, title))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>"+title+"</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildStorageFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), storageFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Storage</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildSettingsFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), settingsFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Settings</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type migrationFixtureOptions struct {
	Version            string
	SettingsSchema     int
	SettingsFrom       int
	SettingsTo         int
	SettingsReversible bool
	StorageSchema      int
	StorageFrom        int
	StorageTo          int
	StorageReversible  bool
}

func buildMigrationFixturePackage(t *testing.T, opts migrationFixtureOptions) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), migrationFixtureManifestJSON(opts))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Migration</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	return buildVersionedRPCPackage(t, "1.0.0", "RPC")
}

func buildVersionedRPCPackage(t *testing.T, version string, title string) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), rpcFixtureManifestJSON(version, title))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>"+title+"</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildDangerousRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), dangerousRPCFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Danger</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildMethodContractFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "generated_plugins", "method-contract")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildIntentFixturePackage(t *testing.T, dangerous bool) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := rpcFixtureManifestJSON("1.0.0", "Intent RPC")
	if dangerous {
		manifestJSON = dangerousRPCFixtureManifestJSON()
	}
	writeFile(t, filepath.Join(dir, "manifest.json"), addIntentToManifestJSON(t, manifestJSON, dangerous))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Intent</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildOperationRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), operationRPCFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Operation</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildSubscriptionRPCFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), subscriptionRPCFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Subscription</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildCoreActionFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), coreActionFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Core Action</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerNetworkFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerNetworkFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Network</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerNetworkSubscriptionFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerNetworkFixtureManifestJSON(), `"execution": "sync"`, `"execution": "subscription"`, 1)
	manifestJSON = strings.Replace(manifestJSON, `"route": {"kind": "worker"`, `"cancel_policy": {"cancelable": true, "disable_behavior": "orphan", "uninstall_behavior": "force_cleanup_allowed", "ack_timeout_ms": 2000}, "route": {"kind": "worker"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Network Stream</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerNetworkHostcallFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerNetworkFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Network Hostcall</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), importedHostcallWorkerWASMForTest("redevplugin.network", "http_request_demo", "redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerNetworkMemoryHostcallFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerNetworkFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Network Memory Hostcall</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), networkMemoryHostcallWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerNetworkTransportMemoryHostcallFixturePackage(t *testing.T, transport connectivity.Transport) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerNetworkTransportFixtureManifestJSON(transport))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Network Transport Memory Hostcall</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), networkTransportMemoryHostcallWorkerWASMForTest("redevplugin_worker_invoke", transport))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerStorageFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerStorageFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Storage</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), storageHostcallWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerStorageMemoryHostcallFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerStorageFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Storage Memory Hostcall</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), storageMemoryHostcallWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerStorageKVMemoryHostcallFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerStorageKVFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Storage KV Memory Hostcall</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), storageKVMemoryHostcallWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerStorageSQLiteMemoryHostcallFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerStorageSQLiteFixtureManifestJSON())
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Worker Storage SQLite Memory Hostcall</title>")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), storageSQLiteMemoryHostcallWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildNetworkFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), networkFixtureManifestJSON(false))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Network</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildBlockedNetworkFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), networkFixtureManifestJSON(true))
	writeFile(t, filepath.Join(dir, "ui", "index.html"), "<!doctype html><title>Network</title>")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeFile(t *testing.T, filename string, content string) {
	t.Helper()
	writeBytes(t, filename, []byte(content))
}

func writeBytes(t *testing.T, filename string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func addIntentToManifestJSON(t *testing.T, manifestJSON string, dangerous bool) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(manifestJSON), &doc); err != nil {
		t.Fatal(err)
	}
	intent := map[string]any{
		"intent_id":      "example.echo",
		"method":         "echo.ping",
		"payload_schema": map[string]any{"type": "object"},
	}
	if dangerous {
		intent["intent_id"] = "example.danger"
		intent["method"] = "danger.run"
	}
	doc["intents"] = []any{intent}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func minimalWorkerWASMForTest(exportName string) []byte {
	exportNameBytes := []byte(exportName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
		0x03, 0x02, 0x01, 0x00,
		0x07,
	}
	exportPayload := []byte{0x01, byte(len(exportNameBytes))}
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, 0x00)
	module = append(module, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module, 0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b)
	return module
}

func storageHostcallWorkerWASMForTest(exportName string) []byte {
	return importedHostcallWorkerWASMForTest("redevplugin.storage", "files_write_demo", exportName)
}

func importedHostcallWorkerWASMForTest(importModule string, importName string, exportName string) []byte {
	exportNameBytes := []byte(exportName)
	importModuleBytes := []byte(importModule)
	importNameBytes := []byte(importName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x07, 0x02,
		0x60, 0x00, 0x00,
		0x60, 0x00, 0x00,
		0x02,
	}
	importPayload := []byte{0x01, byte(len(importModuleBytes))}
	importPayload = append(importPayload, importModuleBytes...)
	importPayload = append(importPayload, byte(len(importNameBytes)))
	importPayload = append(importPayload, importNameBytes...)
	importPayload = append(importPayload, 0x00, 0x00)
	module = append(module, byte(len(importPayload)))
	module = append(module, importPayload...)
	module = append(module, 0x03, 0x02, 0x01, 0x01, 0x07)
	exportPayload := []byte{0x01, byte(len(exportNameBytes))}
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, 0x01)
	module = append(module, byte(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x10, 0x00, 0x0b)
	return module
}

func networkMemoryHostcallWorkerWASMForTest(exportName string) []byte {
	request := []byte(`{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"POST","path":"/v1/worker","headers":{"Content-Type":["text/plain"]},"body_base64":"aGVsbG8gZnJvbSBtZW1vcnkgaG9zdGNhbGw=","max_request_bytes":1024,"max_response_bytes":4096,"timeout_ms":1000}`)
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.network", "execute", exportName, request)
}

func networkTransportMemoryHostcallWorkerWASMForTest(exportName string, transport connectivity.Transport) []byte {
	var request []byte
	switch transport {
	case connectivity.TransportWebSocket:
		request = []byte(`{"connector_id":"stream","transport":"websocket","destination":"wss://stream.example.com","operation":"websocket_round_trip","message_type":"text","payload_base64":"aGVsbG8gd2Vic29ja2V0","max_request_bytes":1024,"max_response_bytes":4096,"timeout_ms":1000}`)
	case connectivity.TransportTCP:
		request = []byte(`{"connector_id":"mysql","transport":"tcp","destination":"db.example.com:3306","operation":"tcp_round_trip","payload_base64":"aGVsbG8gdGNw","max_request_bytes":1024,"max_response_bytes":4096,"timeout_ms":1000}`)
	case connectivity.TransportUDP:
		request = []byte(`{"connector_id":"metrics","transport":"udp","destination":"metrics.example.com:8125","operation":"udp_round_trip","payload_base64":"aGVsbG8gdWRw","max_response_bytes":4096,"timeout_ms":1000}`)
	default:
		request = []byte(`{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"POST","path":"/v1/worker","body_base64":"aGVsbG8=","max_request_bytes":1024,"max_response_bytes":4096,"timeout_ms":1000}`)
	}
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.network", "execute", exportName, request)
}

func storageMemoryHostcallWorkerWASMForTest(exportName string) []byte {
	request := []byte(`{"store_id":"workspace","operation":"write","path":"notes/from-memory.txt","data_base64":"aGVsbG8gZnJvbSBtZW1vcnkgc3RvcmFnZSBob3N0Y2FsbA==","max_bytes":0,"max_entries":0,"recursive":false}`)
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.storage", "files", exportName, request)
}

func storageKVMemoryHostcallWorkerWASMForTest(exportName string) []byte {
	request := []byte(`{"store_id":"cache","operation":"put","key":"runs/latest","value_base64":"aGVsbG8gZnJvbSBtZW1vcnkga3YgaG9zdGNhbGw=","max_bytes":0,"max_entries":0}`)
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.storage", "kv", exportName, request)
}

func storageSQLiteMemoryHostcallWorkerWASMForTest(exportName string) []byte {
	request := []byte(`{"store_id":"db","operation":"exec","database":"plugin.sqlite","sql":"CREATE TABLE IF NOT EXISTS worker_runs (id INTEGER PRIMARY KEY, note TEXT NOT NULL)","args":[],"timeout_ms":1000}`)
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.storage", "sqlite", exportName, request)
}

func importedMemoryHostcallWorkerWASMForTest(importModuleName string, importNameName string, exportName string, request []byte) []byte {
	exportNameBytes := []byte(exportName)
	importModule := []byte(importModuleName)
	importName := []byte(importNameName)
	module := []byte{
		0x00, 0x61, 0x73, 0x6d,
		0x01, 0x00, 0x00, 0x00,
		0x01, 0x0c, 0x02,
		0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
		0x60, 0x00, 0x00,
		0x02,
	}
	importPayload := []byte{0x01, byte(len(importModule))}
	importPayload = append(importPayload, importModule...)
	importPayload = append(importPayload, byte(len(importName)))
	importPayload = append(importPayload, importName...)
	importPayload = append(importPayload, 0x00, 0x00)
	module = appendLEBUint32(module, uint32(len(importPayload)))
	module = append(module, importPayload...)
	module = append(module,
		0x03, 0x02, 0x01, 0x01,
		0x05, 0x03, 0x01, 0x00, 0x01,
		0x07,
	)
	exportPayload := []byte{0x02, 0x06}
	exportPayload = append(exportPayload, []byte("memory")...)
	exportPayload = append(exportPayload, 0x02, 0x00, byte(len(exportNameBytes)))
	exportPayload = append(exportPayload, exportNameBytes...)
	exportPayload = append(exportPayload, 0x00, 0x01)
	module = appendLEBUint32(module, uint32(len(exportPayload)))
	module = append(module, exportPayload...)
	module = append(module, 0x0a)
	codePayload := []byte{0x01}
	body := []byte{
		0x00,
		0x41, 0x00,
		0x41,
	}
	body = appendLEBInt32(body, int32(len(request)))
	body = append(body, 0x41)
	body = appendLEBInt32(body, 512)
	body = append(body, 0x41)
	body = appendLEBInt32(body, 512)
	body = append(body, 0x10, 0x00, 0x1a, 0x0b)
	codePayload = appendLEBUint32(codePayload, uint32(len(body)))
	codePayload = append(codePayload, body...)
	module = appendLEBUint32(module, uint32(len(codePayload)))
	module = append(module, codePayload...)
	module = append(module, 0x0b)
	dataPayload := []byte{0x01, 0x00, 0x41, 0x00, 0x0b}
	dataPayload = appendLEBUint32(dataPayload, uint32(len(request)))
	dataPayload = append(dataPayload, request...)
	module = appendLEBUint32(module, uint32(len(dataPayload)))
	module = append(module, dataPayload...)
	return module
}

func appendLEBUint32(out []byte, value uint32) []byte {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if value == 0 {
			return out
		}
	}
}

func appendLEBInt32(out []byte, value int32) []byte {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		done := (value == 0 && b&0x40 == 0) || (value == -1 && b&0x40 != 0)
		if !done {
			b |= 0x80
		}
		out = append(out, b)
		if done {
			return out
		}
	}
}

func workerFixtureABIJSON(exports ...string) string {
	rawExports, err := json.Marshal(exports)
	if err != nil {
		panic(err)
	}
	return "{\n" +
		"  \"abi_version\": \"redevplugin-wasm-worker-v1\",\n" +
		"  \"exports\": " + string(rawExports) + ",\n" +
		"  \"imports\": [\"redevplugin.log\", \"redevplugin.storage\", \"redevplugin.network\", \"redevplugin.operation\", \"redevplugin.clock\"]\n" +
		"}\n"
}

func fixtureManifestJSON() string {
	return lifecycleManifestJSON("1.0.0", "Lifecycle")
}

func lifecycleManifestJSON(version string, title string) string {
	if title == "" {
		title = "Lifecycle"
	}
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.lifecycle",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "lifecycle.activity", "kind": "activity", "label": "Lifecycle", "entry": "ui/index.html"}
		]
	}`
}

func storageFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.storage",
			"display_name": "Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "storage.activity", "kind": "activity", "label": "Storage", "entry": "ui/index.html"}
		],
		"storage": {
			"stores": [
				{
					"store_id": "cache",
					"kind": "kv",
					"scope": "user",
					"quota_bytes": 4096,
					"quota_files": 16,
					"schema_version": 1,
					"migration": {
						"from_version": 1,
						"to_version": 1,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				},
				{
					"store_id": "db",
					"kind": "sqlite",
					"scope": "environment",
					"quota_bytes": 8192,
					"quota_files": 32,
					"schema_version": 2,
					"migration": {
						"from_version": 1,
						"to_version": 2,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				}
			]
		}
	}`
}

func settingsFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.settings",
			"display_name": "Settings",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "settings.activity", "kind": "activity", "label": "Settings", "entry": "ui/index.html"}
		],
		"settings": {
			"schema_version": 1,
			"migration": {
				"from_version": 1,
				"to_version": 1,
				"reversible": true,
				"requires_worker": false,
				"estimated_bytes": 0,
				"max_duration_ms": 0,
				"data_loss_risk": false,
				"steps_hash": "sha256:test"
			},
			"fields": [
				{"key": "default_engine", "type": "select", "scope": "user", "label": "Default engine", "default": "docker", "options": ["docker", "podman"]},
				{"key": "show_stopped", "type": "boolean", "scope": "user", "label": "Show stopped", "default": true},
				{"key": "api_token", "type": "secret", "scope": "user", "label": "API token", "secret_ref": "api_token"}
			]
		}
	}`
}

func migrationFixtureManifestJSON(opts migrationFixtureOptions) string {
	version := opts.Version
	if version == "" {
		version = "1.0.0"
	}
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.migration",
			"display_name": "Migration",
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "migration.activity", "kind": "activity", "label": "Migration", "entry": "ui/index.html"}
		],
		"storage": {
			"stores": [
				{
					"store_id": "workspace",
					"kind": "files",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": ` + strconv.Itoa(opts.StorageSchema) + `,
					"migration": {
						"from_version": ` + strconv.Itoa(opts.StorageFrom) + `,
						"to_version": ` + strconv.Itoa(opts.StorageTo) + `,
						"reversible": ` + strconv.FormatBool(opts.StorageReversible) + `,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:storage-migration"
					}
				}
			]
		},
		"settings": {
			"schema_version": ` + strconv.Itoa(opts.SettingsSchema) + `,
			"migration": {
				"from_version": ` + strconv.Itoa(opts.SettingsFrom) + `,
				"to_version": ` + strconv.Itoa(opts.SettingsTo) + `,
				"reversible": ` + strconv.FormatBool(opts.SettingsReversible) + `,
				"requires_worker": false,
				"estimated_bytes": 0,
				"max_duration_ms": 0,
				"data_loss_risk": false,
				"steps_hash": "sha256:settings-migration"
			},
			"fields": [
				{"key": "mode", "type": "select", "scope": "user", "label": "Mode", "default": "stable", "options": ["stable", "preview"]}
			]
		}
	}`
}

func rpcFixtureManifestJSON(version string, title string) string {
	if title == "" {
		title = "RPC"
	}
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.rpc",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "rpc.activity", "kind": "activity", "label": "RPC", "entry": "ui/index.html", "method": "echo.ping"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["read"]}
		],
		"methods": [
			{
				"method": "echo.ping",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "echo.ping"}
			}
		]
	}`
}

func dangerousRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.danger",
			"display_name": "Danger",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "danger.activity", "kind": "activity", "label": "Danger", "entry": "ui/index.html", "method": "danger.run"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["execute"]}
		],
		"methods": [
			{
				"method": "danger.run",
				"effect": "execute",
				"execution": "sync",
				"dangerous": true,
				"confirmation": {"mode": "required", "request_hash_fields": ["target"]},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "danger.run"}
			}
		]
	}`
}

func operationRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.operation",
			"display_name": "Operation",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "operation.activity", "kind": "activity", "label": "Operation", "entry": "ui/index.html", "method": "images.pull"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["execute"]}
		],
		"methods": [
			{
				"method": "images.pull",
				"effect": "execute",
				"execution": "operation",
				"cancel_policy": {
					"cancelable": true,
					"disable_behavior": "cancel",
					"uninstall_behavior": "cancel_then_block_delete",
					"ack_timeout_ms": 2000
				},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "images.pull"}
			}
		]
	}`
}

func subscriptionRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.subscription",
			"display_name": "Subscription",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "subscription.activity", "kind": "activity", "label": "Subscription", "entry": "ui/index.html", "method": "logs.tail"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "capability_id": "example.capability.echo", "min_capability_version": "1.0.0", "required_permissions": ["read"]}
		],
		"methods": [
			{
				"method": "logs.tail",
				"effect": "read",
				"execution": "subscription",
				"cancel_policy": {
					"cancelable": true,
					"disable_behavior": "orphan",
					"uninstall_behavior": "force_cleanup_allowed",
					"ack_timeout_ms": 2000
				},
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "logs.tail"}
			}
		]
	}`
}

func coreActionFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.core",
			"display_name": "Core Action",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "core.activity", "kind": "activity", "label": "Core", "entry": "ui/index.html", "method": "core.open"}
		],
		"methods": [
			{
				"method": "core.open",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "core_action", "action_id": "example.open_settings"}
			}
		]
	}`
}

func workerFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker",
			"display_name": "Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "worker.activity", "kind": "activity", "label": "Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v1",
				"mode": "job",
				"scope": "user",
				"memory_limit_bytes": 16777216,
				"idle_timeout_ms": 0
			}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		]
	}`
}

func workerNetworkFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.network",
			"display_name": "Worker Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "worker.activity", "kind": "activity", "label": "Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v1",
				"mode": "job",
				"scope": "user",
				"memory_limit_bytes": 16777216,
				"idle_timeout_ms": 0
			}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		],
		"network_access": {
			"connectors": [
				{"connector_id": "api", "transport": "http", "scope": "user", "destinations": ["https://api.example.com"]}
			]
		}
	}`
}

func workerNetworkTransportFixtureManifestJSON(transport connectivity.Transport) string {
	connectors := map[connectivity.Transport]string{
		connectivity.TransportWebSocket: `{"connector_id": "stream", "transport": "websocket", "scope": "user", "destinations": ["wss://stream.example.com"]}`,
		connectivity.TransportTCP:       `{"connector_id": "mysql", "transport": "tcp", "scope": "environment", "destinations": ["db.example.com:3306"]}`,
		connectivity.TransportUDP:       `{"connector_id": "metrics", "transport": "udp", "scope": "environment", "destinations": ["metrics.example.com:8125"]}`,
	}
	connector, ok := connectors[transport]
	if !ok {
		connector = `{"connector_id": "api", "transport": "http", "scope": "user", "destinations": ["https://api.example.com"]}`
	}
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.network.transport",
			"display_name": "Worker Network Transport",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "worker.activity", "kind": "activity", "label": "Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v1",
				"mode": "job",
				"scope": "user",
				"memory_limit_bytes": 16777216,
				"idle_timeout_ms": 0
			}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "read",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		],
		"network_access": {
			"connectors": [` + connector + `]
		}
	}`
}

func workerStorageFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage",
			"display_name": "Worker Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "worker.activity", "kind": "activity", "label": "Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v1",
				"mode": "job",
				"scope": "user",
				"memory_limit_bytes": 16777216,
				"idle_timeout_ms": 0
			}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "write",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		],
		"storage": {
			"stores": [
				{
					"store_id": "workspace",
					"kind": "files",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": 1,
					"migration": {
						"from_version": 1,
						"to_version": 1,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				}
			]
		}
	}`
}

func workerStorageKVFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage.kv",
			"display_name": "Worker Storage KV",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "worker.activity", "kind": "activity", "label": "Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v1",
				"mode": "job",
				"scope": "user",
				"memory_limit_bytes": 16777216,
				"idle_timeout_ms": 0
			}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "write",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		],
		"storage": {
			"stores": [
				{
					"store_id": "cache",
					"kind": "kv",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": 1,
					"migration": {
						"from_version": 1,
						"to_version": 1,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				}
			]
		}
	}`
}

func workerStorageSQLiteFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage.sqlite",
			"display_name": "Worker Storage SQLite",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "worker.activity", "kind": "activity", "label": "Worker", "entry": "ui/index.html", "method": "worker.echo"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v1",
				"mode": "job",
				"scope": "user",
				"memory_limit_bytes": 16777216,
				"idle_timeout_ms": 0
			}
		],
		"methods": [
			{
				"method": "worker.echo",
				"effect": "write",
				"execution": "sync",
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		],
		"storage": {
			"stores": [
				{
					"store_id": "db",
					"kind": "sqlite",
					"scope": "user",
					"quota_bytes": 65536,
					"schema_version": 1,
					"migration": {
						"from_version": 1,
						"to_version": 1,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				}
			]
		}
	}`
}

func networkFixtureManifestJSON(blocked bool) string {
	httpDestination := "https://api.example.com"
	if blocked {
		httpDestination = "http://localhost"
	}
	return `{
		"schema_version": "redevplugin.manifest.v1",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.network",
			"display_name": "Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v1"
		},
		"surfaces": [
			{"surface_id": "network.activity", "kind": "activity", "label": "Network", "entry": "ui/index.html"}
		],
		"storage": {
			"stores": [
				{
					"store_id": "cache",
					"kind": "kv",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": 1,
					"migration": {
						"from_version": 1,
						"to_version": 1,
						"reversible": true,
						"requires_worker": false,
						"estimated_bytes": 0,
						"max_duration_ms": 0,
						"data_loss_risk": false,
						"steps_hash": "sha256:test"
					}
				}
			]
		},
		"network_access": {
			"connectors": [
				{"connector_id": "api", "transport": "http", "scope": "user", "destinations": [` + strconv.Quote(httpDestination) + `]},
				{"connector_id": "stream", "transport": "websocket", "scope": "user", "destinations": ["wss://stream.example.com"]},
				{"connector_id": "mysql", "transport": "tcp", "scope": "environment", "destinations": ["db.example.com:3306"]},
				{"connector_id": "metrics", "transport": "udp", "scope": "environment", "destinations": ["metrics.example.com:8125"]}
			]
		}
	}`
}

func installEnableAndMintGateway(t *testing.T, h *Host, packageBytes []byte, surfaceID string) (registry.PluginRecord, bridge.GatewayTokenResult) {
	t.Helper()
	installed, _ := installEnableAndMintGatewayWithoutPermissions(t, h, packageBytes, surfaceID)
	grantDeclaredPermissions(t, h, installed)
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, surfaceID)
	return installed, gateway
}

func installEnableAndMintGatewayWithoutPermissions(t *testing.T, h *Host, packageBytes []byte, surfaceID string) (registry.PluginRecord, bridge.GatewayTokenResult) {
	t.Helper()
	ctx := context.Background()
	now := stableRecentTestNow()
	installed, err := ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now}); err != nil {
		t.Fatal(err)
	}
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, surfaceID)
	return installed, gateway
}

func openSurfaceAndMintGateway(t *testing.T, h *Host, pluginInstanceID string, surfaceID string) (bridge.SurfaceBootstrap, bridge.GatewayTokenResult) {
	t.Helper()
	ctx := context.Background()
	now := stableRecentTestNow()
	record, err := h.adapters.Registry.GetPlugin(ctx, pluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     record.PluginInstanceID,
		SurfaceID:            surfaceID,
		SurfaceInstanceID:    "surface_rpc",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ExchangeAssetTicket(ctx, ExchangeAssetTicketRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,
		Now:               now.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	handshake := bridge.Handshake{
		PluginID:          bootstrap.PluginID,
		SurfaceID:         bootstrap.SurfaceID,
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		ActiveFingerprint: bootstrap.ActiveFingerprint,
		BridgeNonce:       bootstrap.BridgeNonce,
		UIProtocolVersion: "plugin-ui-v1",
	}
	gateway, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_rpc",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_rpc"),
		Now:                       now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap, gateway
}

func stableRecentTestNow() time.Time {
	return time.Now().UTC().Add(-1 * time.Minute)
}

func grantDeclaredPermissions(t *testing.T, h *Host, record registry.PluginRecord) {
	t.Helper()
	permissionsToGrant := map[string]struct{}{}
	for _, method := range record.Manifest.Methods {
		for _, permissionID := range requiredPermissionsForMethod(record.Manifest, method) {
			permissionsToGrant[permissionID] = struct{}{}
		}
	}
	for permissionID := range permissionsToGrant {
		if _, err := h.GrantPermission(context.Background(), GrantPermissionRequest{
			PluginInstanceID: record.PluginInstanceID,
			PermissionID:     permissionID,
			GrantedBy:        "test",
		}); err != nil {
			t.Fatalf("GrantPermission(%s) error = %v", permissionID, err)
		}
	}
}

type fakeSessionResolver struct{}

func (fakeSessionResolver) ResolveSession(context.Context, string) (sessionctx.Context, error) {
	return sessionctx.Context{}, nil
}

type policyAdapter struct {
	developerMode  bool
	localGenerated bool
	decision       PolicyDecision
}

func (p policyAdapter) EvaluateLocalPolicy(context.Context, sessionctx.Context, PluginRef, manifest.MethodSpec) (PolicyDecision, error) {
	if p.decision == "" {
		return PolicyAllow, nil
	}
	return p.decision, nil
}

func (p policyAdapter) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return p.developerMode, nil
}

func (p policyAdapter) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return p.localGenerated, nil
}

type recordingPackageTrustVerifier struct {
	trustState registry.TrustState
	metadata   map[string]string
	err        error
	last       PackageTrustVerificationRequest
}

func (v *recordingPackageTrustVerifier) VerifyPackageTrust(_ context.Context, req PackageTrustVerificationRequest) (PackageTrustVerificationResult, error) {
	v.last = req
	if v.err != nil {
		return PackageTrustVerificationResult{}, v.err
	}
	trustState := v.trustState
	if trustState == "" {
		if req.LocalImport {
			if req.Package.PackageSignature != nil {
				trustState = registry.TrustVerified
			} else {
				trustState = registry.TrustUnsignedLocal
			}
		} else if req.SourcePolicySnapshot != nil {
			trustState = registry.TrustVerified
		} else {
			trustState = registry.TrustUntrusted
		}
	}
	return PackageTrustVerificationResult{
		TrustState:  trustState,
		ReasonCodes: []string{"test_verifier"},
		Metadata:    cloneStringMap(v.metadata),
	}, nil
}

type recordingReleaseArtifactResolver struct {
	artifact ResolvedPackageArtifact
	err      error
	last     ReleaseArtifactResolveRequest
	calls    int
}

type recordingReleaseMetadataVerifier struct {
	err   error
	last  ReleaseMetadataVerificationRequest
	calls int
}

func (v *recordingReleaseMetadataVerifier) VerifyReleaseMetadata(_ context.Context, req ReleaseMetadataVerificationRequest) (ReleaseMetadataVerificationResult, error) {
	v.calls++
	v.last = req
	if v.err != nil {
		return ReleaseMetadataVerificationResult{}, v.err
	}
	return ReleaseMetadataVerificationResult{Metadata: map[string]string{"key_id": req.Release.ReleaseMetadataSignature.KeyID}}, nil
}

func (v *recordingReleaseMetadataVerifier) VerifySourceRevocationEvidence(_ context.Context, req SourceRevocationEvidenceVerificationRequest) (SourceRevocationEvidenceVerificationResult, error) {
	if v.err != nil {
		return SourceRevocationEvidenceVerificationResult{}, v.err
	}
	return SourceRevocationEvidenceVerificationResult{Metadata: map[string]string{"key_id": req.RevocationEvidence.SignatureKeyID}}, nil
}

type recordingReleaseSourcePolicyResolver struct {
	snapshot SourcePolicySnapshot
	err      error
	last     ReleaseSourcePolicyRequest
	requests []ReleaseSourcePolicyRequest
	calls    int
}

func (r *recordingReleaseSourcePolicyResolver) ResolveReleaseSourcePolicy(_ context.Context, req ReleaseSourcePolicyRequest) (SourcePolicySnapshot, error) {
	r.calls++
	r.last = req
	r.requests = append(r.requests, req)
	if r.err != nil {
		return SourcePolicySnapshot{}, r.err
	}
	return r.snapshot, nil
}

func (r *recordingReleaseArtifactResolver) ResolveReleaseArtifact(_ context.Context, req ReleaseArtifactResolveRequest) (ResolvedPackageArtifact, error) {
	r.calls++
	r.last = req
	if r.err != nil {
		return ResolvedPackageArtifact{}, r.err
	}
	return r.artifact, nil
}

func resolvedArtifactForPackage(t *testing.T, ref PluginReleaseRef, pkg pluginpkg.Package, packageBytes []byte) ResolvedPackageArtifact {
	t.Helper()
	return ResolvedPackageArtifact{
		ReleaseMetadataBytes:     releaseMetadataBytesForPackage(t, ref, pkg),
		ReleaseMetadataSignature: []byte("release-metadata-signature"),
		Reader:                   bytes.NewReader(packageBytes),
		Size:                     int64(len(packageBytes)),
	}
}

func readTestPackage(t *testing.T, data []byte) pluginpkg.Package {
	t.Helper()
	pkg, err := pluginpkg.Read(context.Background(), bytes.NewReader(data), int64(len(data)), pluginpkg.DefaultReadOptions())
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func buildSignedReleasePackageBytes(t *testing.T, data []byte, keyID string) []byte {
	t.Helper()
	pkg := readTestPackage(t, data)
	pkg.PackageSignature = &pluginpkg.PackageSignature{
		SchemaVersion: pluginpkg.PackageSignatureSchemaVersion,
		Algorithm:     pluginpkg.PackageSignatureAlgorithmEd25519,
		KeyID:         keyID,
		PublisherID:   pkg.Manifest.Publisher.PublisherID,
		PluginID:      pkg.Manifest.PluginID(),
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		Signature:     "test-signature",
		SignedAt:      "2026-07-07T00:00:00Z",
	}
	var buf bytes.Buffer
	if err := pluginpkg.WritePackage(context.Background(), &buf, pkg); err != nil {
		t.Fatalf("WritePackage() error = %v", err)
	}
	return buf.Bytes()
}

func releaseRefForPackage(t *testing.T, sourceID string, pkg pluginpkg.Package) PluginReleaseRef {
	t.Helper()
	releaseMetadataRef := "plugins/" + pkg.Manifest.Publisher.PublisherID + "/" + pkg.Manifest.PluginID() + "/" + pkg.Manifest.Version() + "/release.json"
	metadataBytes := releaseMetadataBytesForPackage(t, PluginReleaseRef{
		SourceID:           sourceID,
		ReleaseMetadataRef: releaseMetadataRef,
		PublisherID:        pkg.Manifest.Publisher.PublisherID,
		PluginID:           pkg.Manifest.PluginID(),
		Version:            pkg.Manifest.Version(),
	}, pkg)
	metadataHash := sha256.Sum256(metadataBytes)
	return PluginReleaseRef{
		SourceID:              sourceID,
		ReleaseMetadataRef:    releaseMetadataRef,
		ReleaseMetadataSHA256: hex.EncodeToString(metadataHash[:]),
		PublisherID:           pkg.Manifest.Publisher.PublisherID,
		PluginID:              pkg.Manifest.PluginID(),
		Version:               pkg.Manifest.Version(),
		ExpectedHashes: PackageHashSet{
			PackageSHA256:  pkg.PackageHash,
			ManifestSHA256: pkg.ManifestHash,
			EntriesSHA256:  pkg.EntriesHash,
		},
	}
}

func releaseMetadataBytesForPackage(t *testing.T, ref PluginReleaseRef, pkg pluginpkg.Package) []byte {
	t.Helper()
	release := releaseForPackage(ref, pkg)
	return releaseMetadataBytesForRelease(t, ref, release)
}

func releaseMetadataBytesForRelease(t *testing.T, ref PluginReleaseRef, release PluginPackageRelease) []byte {
	t.Helper()
	raw, err := json.Marshal(signedReleaseMetadata{
		SchemaVersion:            "redevplugin.release_metadata.v1",
		SourceID:                 release.SourceID,
		ReleaseMetadataRef:       ref.ReleaseMetadataRef,
		PublisherID:              release.PublisherID,
		PluginID:                 release.PluginID,
		Version:                  release.Version,
		DistributionRef:          release.DistributionRef,
		Hashes:                   release.Hashes,
		ReleaseMetadataSignature: release.ReleaseMetadataSignature,
		PackageSignature:         release.PackageSignature,
		Compatibility:            release.Compatibility,
		HostRequirements:         release.HostRequirements,
		ReleaseEvidence:          release.ReleaseEvidence,
		Metadata:                 release.Metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func resolvedArtifactForRelease(t *testing.T, ref PluginReleaseRef, release PluginPackageRelease, packageBytes []byte) ResolvedPackageArtifact {
	t.Helper()
	return ResolvedPackageArtifact{
		ReleaseMetadataBytes:     releaseMetadataBytesForRelease(t, ref, release),
		ReleaseMetadataSignature: []byte("release-metadata-signature"),
		Reader:                   bytes.NewReader(packageBytes),
		Size:                     int64(len(packageBytes)),
	}
}

func installReleaseRefLifecyclePlugin(t *testing.T, opts testHostOptions) (*Host, *recordingReleaseSourcePolicyResolver, registry.PluginRecord, PluginReleaseRef) {
	t.Helper()
	ctx := context.Background()
	packageBytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"), "official")
	pkg := readTestPackage(t, packageBytes)
	ref := releaseRefForPackage(t, "official", pkg)
	sourceResolver := &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(ref)}
	if opts.releaseMetadataVerifier == nil {
		opts.releaseMetadataVerifier = &recordingReleaseMetadataVerifier{}
	}
	opts.developerMode = true
	opts.localGenerated = true
	opts.releaseSourcePolicy = sourceResolver
	opts.releaseArtifactResolver = &recordingReleaseArtifactResolver{
		artifact: resolvedArtifactForPackage(t, ref, pkg, packageBytes),
	}
	h, _, _ := newTestHostWithOptions(t, opts)
	installed, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		ReleaseRef:       ref,
		PluginInstanceID: "plugini_release_ref_policy_replay",
		Now:              stableRecentTestNow(),
	})
	if err != nil {
		t.Fatalf("InstallReleaseRef() error = %v", err)
	}
	return h, sourceResolver, installed, ref
}

func releaseForPackage(ref PluginReleaseRef, pkg pluginpkg.Package) PluginPackageRelease {
	return PluginPackageRelease{
		SourceID:    ref.SourceID,
		PublisherID: ref.PublisherID,
		PluginID:    ref.PluginID,
		Version:     ref.Version,
		DistributionRef: PackageDistributionRef{
			Distribution: PackageDistributionRegistryRef,
			ArtifactRef:  "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/plugin.redevplugin",
		},
		ReleaseMetadataSHA256: ref.ReleaseMetadataSHA256,
		ReleaseMetadataSignature: &ReleaseMetadataSignature{
			Algorithm:         "ed25519",
			KeyID:             "official",
			SignatureRef:      "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/release.json.sig",
			SourcePolicyEpoch: "1",
			RevocationEpoch:   "1",
		},
		Hashes: PackageHashSet{
			PackageSHA256:  pkg.PackageHash,
			ManifestSHA256: pkg.ManifestHash,
			EntriesSHA256:  pkg.EntriesHash,
		},
		PackageSignature: &PackageReleaseSignature{
			Algorithm:          "ed25519",
			KeyID:              "official",
			SignatureBundleRef: "plugins/" + ref.PublisherID + "/" + ref.PluginID + "/" + ref.Version + "/plugin.sigbundle",
			SourcePolicyEpoch:  "1",
			RevocationEpoch:    "1",
		},
		Compatibility: &ReleaseCompatibility{
			MinReDevPluginVersion: "0.1.0",
			MinRuntimeVersion:     "0.1.0",
			UIProtocolVersion:     "plugin-ui-v1",
		},
	}
}

func sourcePolicyForRelease(ref PluginReleaseRef) SourcePolicySnapshot {
	revocationMetadata := revocationMetadataBytesForSource(ref.SourceID, "1")
	revocationHash := sha256.Sum256(revocationMetadata)
	return SourcePolicySnapshot{
		SchemaVersion:     "redevplugin.source_policy.v1",
		SourceID:          ref.SourceID,
		SourceType:        PackageSourceRegistry,
		SourceClass:       PackageSourceClassOfficial,
		AllowedPublishers: []string{ref.PublisherID},
		TrustedKeyIDs:     []string{"official"},
		TrustedKeys: []SourcePolicyTrustedKey{{
			Algorithm:       pluginpkg.PackageSignatureAlgorithmEd25519,
			KeyID:           "official",
			PublicKeySHA256: strings.Repeat("a", 64),
			Usage:           []string{"release_metadata", "package_signature", "revocation_metadata"},
			ValidFrom:       "2026-01-01T00:00:00Z",
			ValidUntil:      "2027-01-01T00:00:00Z",
			RevocationEpoch: "1",
		}},
		RevocationEvidence: &SourcePolicyRevocationEvidence{
			MetadataRef:      "sources/" + ref.SourceID + "/revocations.json",
			MetadataSHA256:   hex.EncodeToString(revocationHash[:]),
			SignatureRef:     "sources/" + ref.SourceID + "/revocations.json.sig",
			SignatureKeyID:   "official",
			VerifiedAt:       "2026-07-07T00:00:00Z",
			ExpiresAt:        "2027-01-01T00:00:00Z",
			HighestSeenEpoch: "1",
			MetadataBytes:    revocationMetadata,
			SignatureBytes:   []byte("source-revocation-signature"),
		},
		RequireSignature: true,
		InstallPolicy:    PackageInstallAllow,
		UnsignedPolicy:   PackageUnsignedBlock,
		DowngradePolicy:  PackageDowngradeBlock,
		PolicyEpoch:      "1",
		KeyRotationEpoch: "1",
		RevocationEpoch:  "1",
		AssessedAt:       "2026-07-07T00:00:00Z",
	}
}

func revocationMetadataBytesForSource(sourceID string, epoch string) []byte {
	return revocationMetadataBytesForSourceWithRevoked(sourceID, epoch, nil)
}

func revocationMetadataBytesForSourceWithRevoked(sourceID string, epoch string, revokedKeyIDs []string) []byte {
	raw, err := json.Marshal(SourceRevocationMetadata{
		SchemaVersion:    "redevplugin.source_revocations.v1",
		SourceID:         sourceID,
		HighestSeenEpoch: epoch,
		GeneratedAt:      "2026-07-07T00:00:00Z",
		ExpiresAt:        "2027-01-01T00:00:00Z",
		RevokedKeyIDs:    revokedKeyIDs,
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func setSourcePolicyEpochs(snapshot *SourcePolicySnapshot, epoch string) {
	snapshot.PolicyEpoch = epoch
	snapshot.KeyRotationEpoch = epoch
	snapshot.RevocationEpoch = epoch
	for index := range snapshot.TrustedKeys {
		snapshot.TrustedKeys[index].RevocationEpoch = epoch
	}
	setSourcePolicyRevokedKeys(snapshot, nil)
}

func setSourcePolicyRevokedKeys(snapshot *SourcePolicySnapshot, revokedKeyIDs []string) {
	revocationMetadata := revocationMetadataBytesForSourceWithRevoked(snapshot.SourceID, snapshot.RevocationEpoch, revokedKeyIDs)
	revocationHash := sha256.Sum256(revocationMetadata)
	snapshot.RevocationEvidence.MetadataSHA256 = hex.EncodeToString(revocationHash[:])
	snapshot.RevocationEvidence.HighestSeenEpoch = snapshot.RevocationEpoch
	snapshot.RevocationEvidence.MetadataBytes = revocationMetadata
}

func setReleaseSignatureEpochs(release *PluginPackageRelease, epoch string) {
	if release.ReleaseMetadataSignature != nil {
		release.ReleaseMetadataSignature.SourcePolicyEpoch = epoch
		release.ReleaseMetadataSignature.RevocationEpoch = epoch
	}
	if release.PackageSignature != nil {
		release.PackageSignature.SourcePolicyEpoch = epoch
		release.PackageSignature.RevocationEpoch = epoch
	}
}

func setReleaseRefMetadataHash(t *testing.T, ref *PluginReleaseRef, release PluginPackageRelease) {
	t.Helper()
	metadataBytes := releaseMetadataBytesForRelease(t, *ref, release)
	metadataHash := sha256.Sum256(metadataBytes)
	ref.ReleaseMetadataSHA256 = hex.EncodeToString(metadataHash[:])
}

type surfaceSink struct {
	snapshots []SurfaceSnapshot
}

func (s *surfaceSink) PublishSurfaces(_ context.Context, snapshot SurfaceSnapshot) error {
	s.snapshots = append(s.snapshots, snapshot)
	return nil
}

type failingSurfaceSink struct {
	err       error
	snapshots []SurfaceSnapshot
}

func (s *failingSurfaceSink) PublishSurfaces(_ context.Context, snapshot SurfaceSnapshot) error {
	if s.err != nil {
		return s.err
	}
	s.snapshots = append(s.snapshots, snapshot)
	return nil
}

type auditSink struct {
	events []AuditEvent
}

func (s *auditSink) AppendPluginAudit(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func (s *auditSink) hasEvent(eventType string) bool {
	for _, event := range s.events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func (s *auditSink) lastEvent(eventType string) (AuditEvent, bool) {
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Type == eventType {
			return s.events[i], true
		}
	}
	return AuditEvent{}, false
}

func assertAuditDetail(t *testing.T, event AuditEvent, key string, want any) {
	t.Helper()
	if got := event.Details[key]; got != want {
		t.Fatalf("audit detail %s = %#v, want %#v: %#v", key, got, want, event.Details)
	}
}

func assertRuntimeLeaseField(t *testing.T, name string, ok bool) {
	t.Helper()
	if !ok {
		t.Fatalf("runtime lease field %s mismatch", name)
	}
}

func assertRuntimeLeaseEqual[T comparable](t *testing.T, name string, got T, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("runtime lease field %s = %#v, want %#v", name, got, want)
	}
}

type cleanupPhaseSet map[cleanup.Phase]struct{}

func cleanupPhases(records []cleanup.ExecutionRecord) cleanupPhaseSet {
	phases := cleanupPhaseSet{}
	for _, record := range records {
		phases[record.Phase] = struct{}{}
	}
	return phases
}

func (s cleanupPhaseSet) contains(phase cleanup.Phase) bool {
	_, ok := s[phase]
	return ok
}

type diagnosticSink struct {
	events []DiagnosticEvent
}

func (s *diagnosticSink) AppendPluginDiagnostic(_ context.Context, event DiagnosticEvent) error {
	s.events = append(s.events, event)
	return nil
}

type recordingBrowserSiteCleaner struct {
	origins []string
	err     error
}

func (c *recordingBrowserSiteCleaner) ClearOriginData(_ context.Context, origin string) error {
	c.origins = append(c.origins, origin)
	return c.err
}

type recordingCapabilityAdapter struct {
	calls           int
	last            capability.Invocation
	result          capability.Result
	resultsByTarget map[string]capability.Result
	err             error
}

type recordingCoreActionAdapter struct {
	calls  int
	last   capability.Invocation
	result capability.Result
	err    error
}

type recordingOperationCanceler struct {
	calls int
	last  OperationCancelAdapterRequest
	err   error
}

type tamperingConfirmationIntentStore struct {
	security.ConfirmationIntentStore
	planHash string
}

func (s *tamperingConfirmationIntentStore) ConsumeConfirmationIntent(ctx context.Context, req security.ConsumeConfirmationIntentRequest) (security.ConfirmationIntentRecord, error) {
	record, err := s.ConfirmationIntentStore.ConsumeConfirmationIntent(ctx, req)
	if err != nil {
		return security.ConfirmationIntentRecord{}, err
	}
	record.PlanHash = s.planHash
	return record, nil
}

type recordingSecretStore struct {
	bind           SecretBindRequest
	test           SecretTestRequest
	delete         SecretDeleteRequest
	deletePluginID string
}

type recordingRuntimeSupervisor struct {
	calls             int
	startCalls        int
	stopCalls         int
	revokeCalls       int
	startedTarget     runtimeclient.Target
	health            runtimeclient.Health
	result            capability.Result
	err               error
	revokeErr         error
	revokeResult      runtimeclient.RevokeResult
	lastLease         runtimeclient.Lease
	lastMethod        string
	lastPayload       []byte
	lastRevokedPlugin string
	lastRevokeEpoch   uint64
}

type recordingRuntimeArtifactResolver struct {
	calls  int
	target RuntimeTarget
	path   string
	err    error
}

func surfaceIDForMethod(method string) string {
	if method == "images.pull" {
		return "operation.activity"
	}
	if method == "logs.tail" {
		return "subscription.activity"
	}
	return "rpc.activity"
}

func assertHostOperationStatus(t *testing.T, h *Host, operationID string, want operation.Status) {
	t.Helper()
	record, err := h.GetOperation(context.Background(), operationID)
	if err != nil {
		t.Fatalf("GetOperation(%s) error = %v", operationID, err)
	}
	if record.Status != want {
		t.Fatalf("operation %s status = %s, want %s: %#v", operationID, record.Status, want, record)
	}
}

func assertHostStreamStatus(t *testing.T, h *Host, streamID string, want stream.Status) {
	t.Helper()
	record, err := h.adapters.Streams.Get(context.Background(), streamID)
	if err != nil {
		t.Fatalf("Streams.Get(%s) error = %v", streamID, err)
	}
	if record.Status != want {
		t.Fatalf("stream %s status = %s, want %s: %#v", streamID, record.Status, want, record)
	}
}

func (a *recordingCapabilityAdapter) InvokeCapability(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.calls++
	a.last = req
	if a.err != nil {
		return capability.Result{}, a.err
	}
	if a.resultsByTarget != nil {
		if result, ok := a.resultsByTarget[req.TargetMethod]; ok {
			return result, nil
		}
	}
	return a.result, nil
}

func (a *recordingCoreActionAdapter) InvokeCoreAction(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.calls++
	a.last = req
	if a.err != nil {
		return capability.Result{}, a.err
	}
	return a.result, nil
}

func (c *recordingOperationCanceler) RequestOperationCancel(_ context.Context, req OperationCancelAdapterRequest) error {
	c.calls++
	c.last = req
	return c.err
}

func (s *recordingSecretStore) BindSecretRef(_ context.Context, req SecretBindRequest) error {
	s.bind = req
	return nil
}

func (s *recordingSecretStore) TestSecretRef(_ context.Context, req SecretTestRequest) error {
	s.test = req
	return nil
}

func (s *recordingSecretStore) DeleteSecretRef(_ context.Context, req SecretDeleteRequest) error {
	s.delete = req
	return nil
}

func (s *recordingSecretStore) DeletePlugin(_ context.Context, pluginInstanceID string) error {
	s.deletePluginID = pluginInstanceID
	return nil
}

type secretStoreWithoutPluginCleanup struct{}

func (s *secretStoreWithoutPluginCleanup) BindSecretRef(context.Context, SecretBindRequest) error {
	return nil
}

func (s *secretStoreWithoutPluginCleanup) TestSecretRef(context.Context, SecretTestRequest) error {
	return nil
}

func (s *secretStoreWithoutPluginCleanup) DeleteSecretRef(context.Context, SecretDeleteRequest) error {
	return nil
}

func (r *recordingRuntimeSupervisor) Start(_ context.Context, target runtimeclient.Target) error {
	r.startCalls++
	r.startedTarget = target
	if r.health == (runtimeclient.Health{}) {
		r.health = runtimeclient.Health{RuntimeInstanceID: "runtime_test", RuntimeGenerationID: "runtime_gen_test", IPCChannelID: "ipc_test", ConnectionNonce: "connection_nonce_test_1234567890", Ready: true}
	}
	return nil
}

func (r *recordingRuntimeSupervisor) Stop(context.Context) error {
	r.stopCalls++
	r.health.Ready = false
	return nil
}

func (r *recordingRuntimeSupervisor) Health(context.Context) (runtimeclient.Health, error) {
	if r.health == (runtimeclient.Health{}) {
		r.health = runtimeclient.Health{RuntimeInstanceID: "runtime_test", RuntimeGenerationID: "runtime_gen_test", IPCChannelID: "ipc_test", ConnectionNonce: "connection_nonce_test_1234567890", Ready: true}
	}
	return r.health, nil
}

func (r *recordingRuntimeSupervisor) Heartbeat(context.Context) (runtimeclient.HeartbeatResult, error) {
	if r.err != nil {
		return runtimeclient.HeartbeatResult{}, r.err
	}
	if r.health == (runtimeclient.Health{}) {
		r.health = runtimeclient.Health{RuntimeInstanceID: "runtime_test", RuntimeGenerationID: "runtime_gen_test", IPCChannelID: "ipc_test", ConnectionNonce: "connection_nonce_test_1234567890", Ready: true}
	}
	return runtimeclient.HeartbeatResult{
		RuntimeGenerationID:  r.health.RuntimeGenerationID,
		RuntimeUnixNano:      time.Now().UnixNano(),
		MaxStalenessMillis:   5000,
		HostSentUnixNanoEcho: time.Now().UnixNano(),
	}, nil
}

func (r *recordingRuntimeSupervisor) InvokeWorker(_ context.Context, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
	r.calls++
	r.lastLease = lease
	r.lastMethod = method
	r.lastPayload = append([]byte(nil), payload...)
	if r.err != nil {
		return nil, r.err
	}
	return json.Marshal(r.result)
}

func (r *recordingRuntimeSupervisor) Revoke(_ context.Context, pluginInstanceID string, revokeEpoch uint64) (runtimeclient.RevokeResult, error) {
	r.revokeCalls++
	r.lastRevokedPlugin = pluginInstanceID
	r.lastRevokeEpoch = revokeEpoch
	result := r.revokeResult
	if result.PluginInstanceID == "" {
		result.PluginInstanceID = pluginInstanceID
	}
	if result.RevokeEpoch == 0 {
		result.RevokeEpoch = revokeEpoch
	}
	return result, r.revokeErr
}

func (r *recordingRuntimeArtifactResolver) RuntimePath(_ context.Context, target RuntimeTarget) (string, error) {
	r.calls++
	r.target = target
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}
