package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
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

func mustPluginStateVersion(t testing.TB, h *Host, pluginInstanceID string) uint64 {
	t.Helper()
	records, err := h.ListPlugins(context.Background())
	if err != nil {
		t.Fatalf("ListPlugins() for state version: %v", err)
	}
	for _, record := range records {
		if record.PluginInstanceID == pluginInstanceID {
			if record.ManagementRevision == 0 {
				t.Fatalf("plugin %q has zero management revision", pluginInstanceID)
			}
			return record.ManagementRevision
		}
	}
	t.Fatalf("plugin %q not found while resolving state version", pluginInstanceID)
	return 0
}

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

	enabled, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, host, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable EnableState = %s", enabled.EnableState)
	}
	if len(surfaces.snapshots) != 1 || len(surfaces.snapshots[0].Surfaces) != 1 {
		t.Fatalf("surface publish mismatch: %#v", surfaces.snapshots)
	}

	disabled, err := host.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test", PluginStateVersion: mustPluginStateVersion(t, host, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if disabled.EnableState != registry.EnableDisabled {
		t.Fatalf("disable EnableState = %s", disabled.EnableState)
	}
	if len(surfaces.snapshots) != 2 || len(surfaces.snapshots[1].Surfaces) != 0 {
		t.Fatalf("disable did not clear surfaces: %#v", surfaces.snapshots)
	}

	uninstalled, err := host.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, host, installed.PluginInstanceID)})
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

func TestManagementStateVersionFailsClosedWithoutSideEffects(t *testing.T) {
	ctx := context.Background()
	h, surfaces, audits := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(ctx, h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	initialAuditCount := len(audits.events)

	for _, stateVersion := range []uint64{0, installed.ManagementRevision + 1} {
		if _, err := h.EnablePlugin(ctx, EnableRequest{
			PluginInstanceID:   installed.PluginInstanceID,
			PluginStateVersion: stateVersion,
		}); !errors.Is(err, ErrPluginStateVersionMismatch) {
			t.Fatalf("EnablePlugin(state version %d) error = %v, want ErrPluginStateVersionMismatch", stateVersion, err)
		}
	}
	records, err := h.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].EnableState != registry.EnableDisabled || records[0].ManagementRevision != installed.ManagementRevision {
		t.Fatalf("failed enable mutated registry: %#v", records)
	}
	if len(surfaces.snapshots) != 0 || len(audits.events) != initialAuditCount {
		t.Fatalf("failed enable produced side effects: surfaces=%#v audits=%#v", surfaces.snapshots, audits.events)
	}

	enabled, err := h.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID:   installed.PluginInstanceID,
		PluginStateVersion: installed.ManagementRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     enabled.PluginInstanceID,
		PluginStateVersion:   installed.ManagementRevision,
		SurfaceID:            "lifecycle.view",
		SurfaceInstanceID:    "surface_state_version",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
	}); !errors.Is(err, ErrPluginStateVersionMismatch) {
		t.Fatalf("OpenSurface(stale) error = %v, want ErrPluginStateVersionMismatch", err)
	}
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     enabled.PluginInstanceID,
		PluginStateVersion:   enabled.ManagementRevision,
		SurfaceID:            "lifecycle.view",
		SurfaceInstanceID:    "surface_state_version",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
	}); err != nil {
		t.Fatalf("OpenSurface(current) after stale request error = %v", err)
	}

	if _, err := h.DisablePlugin(ctx, DisableRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		PluginStateVersion: installed.ManagementRevision,
		Reason:             "stale request",
	}); !errors.Is(err, ErrPluginStateVersionMismatch) {
		t.Fatalf("DisablePlugin(stale) error = %v, want ErrPluginStateVersionMismatch", err)
	}
	records, err = h.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].EnableState != registry.EnableEnabled || records[0].ManagementRevision != enabled.ManagementRevision {
		t.Fatalf("stale disable mutated registry: %#v", records)
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "rpc.view",
		SurfaceInstanceID:    "surface_update",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Now:                  now.Add(time.Second), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if _, err := h.PrepareSurface(ctx, exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second))); err != nil {
		t.Fatalf("PrepareSurface() error = %v", err)
	}
	handshake := bridge.Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		PluginStateVersion: bootstrap.PluginStateVersion,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v2",
	}
	gateway, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_update",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_update"),
		OwnerSessionHash:          bootstrap.OwnerSessionHash,
		OwnerUserHash:             bootstrap.OwnerUserHash,
		SessionChannelIDHash:      bootstrap.SessionChannelIDHash,
		Now:                       now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}

	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(v2),
		PackageSize:      int64(len(v2)),
		Now:              now.Add(4 * time.Second), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
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
		Now:              now.Add(6 * time.Second), PluginStateVersion: mustPluginStateVersion(t, h,
			updated.PluginInstanceID),
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
		PackageSize:      int64(len(other)), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
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
		PackageSize:      int64(len(v2)), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatalf("UpdateLocalPackage() migration preflight error = %v", err)
	}
	if updated.Manifest.Settings.SchemaVersion != 2 || updated.Manifest.Storage.Stores[0].SchemaVersion != 2 {
		t.Fatalf("updated schemas mismatch: settings=%#v storage=%#v", updated.Manifest.Settings, updated.Manifest.Storage)
	}
	downgraded, err := h.DowngradePlugin(ctx, DowngradeRequest{
		PluginInstanceID: updated.PluginInstanceID,
		Version:          "1.0.0", PluginStateVersion: mustPluginStateVersion(t, h,
			updated.PluginInstanceID),
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
		PackageSize:      int64(len(badV2)), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
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
		PackageSize:      int64(len(irreversibleV2)), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatalf("UpdateLocalPackage() irreversible forward migration error = %v", err)
	}
	if _, err := h.DowngradePlugin(ctx, DowngradeRequest{
		PluginInstanceID: updated.PluginInstanceID,
		Version:          "1.0.0", PluginStateVersion: mustPluginStateVersion(t, h,
			updated.PluginInstanceID),
	}); !errors.Is(err, ErrPluginMigrationPreflight) {
		t.Fatalf("DowngradePlugin() error = %v, want ErrPluginMigrationPreflight", err)
	}
}

func TestEnableRejectsUntrusted(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	pkg := readTestPackage(t, buildFixturePackage(t))
	installed, err := host.adapters.Registry.PutPlugin(context.Background(), packageRecord(pkg, registry.TrustAssessment{TrustState: registry.TrustUntrusted}, "", nil, nil), registry.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, host, installed.PluginInstanceID)}); err == nil {
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
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, host, installed.PluginInstanceID)}); err == nil {
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

func TestSourcePolicySnapshotHashExcludesAssessmentTimestamps(t *testing.T) {
	snapshot := sourcePolicyForRelease(releaseRefForPackage(t, "official", readTestPackage(t, buildFixturePackage(t))))
	firstHash, firstProjection, err := sourcePolicySnapshotProjection(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.AssessedAt = "2026-07-08T00:00:00Z"
	snapshot.RevocationEvidence.VerifiedAt = "2026-07-08T00:00:01Z"
	secondHash, secondProjection, err := sourcePolicySnapshotProjection(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatalf("source policy security hash changed with assessment timestamps: %s != %s", firstHash, secondHash)
	}
	if firstProjection["assessed_at"] == secondProjection["assessed_at"] {
		t.Fatalf("projected source policy did not retain the latest assessed_at: first=%#v second=%#v", firstProjection, secondProjection)
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}

	sourceResolver.snapshot = sourcePolicyForRelease(ref)
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "lifecycle.view",
		SurfaceInstanceID: "surface_floor_rollback", PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
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
	packageBytes := buildSignedReleasePackageBytes(t, buildRPCFixturePackage(t), "official")
	pkg := readTestPackage(t, packageBytes)
	baseRef := releaseRefForPackage(t, "official", pkg)
	verified := fixtureVerifiedCapabilityContract(t, "example.capability.echo")

	t.Run("accepts complete host capability contract pins", func(t *testing.T) {
		ref := baseRef
		release := releaseForPackage(ref, pkg)
		contractRef := verified.Pin
		release.HostRequirements = []HostRequirement{{
			HostID:         "example-host",
			MinHostVersion: "1.2.3",
			RequiredCapabilityContracts: []HostCapabilityRequirement{{
				CapabilityID:      verified.Contract.CapabilityID,
				CapabilityVersion: verified.Contract.CapabilityVersion,
				Contract:          contractRef,
			}},
		}}
		setReleaseRefMetadataHash(t, &ref, release)
		metadataVerifier := &recordingReleaseMetadataVerifier{}
		sourcePolicy := sourcePolicyForRelease(ref)
		sourcePolicy.TrustedKeyIDs = append(sourcePolicy.TrustedKeyIDs, verified.Pin.SignatureKeyID)
		sourcePolicy.TrustedKeys = append(sourcePolicy.TrustedKeys, SourcePolicyTrustedKey{
			Algorithm: pluginpkg.PackageSignatureAlgorithmEd25519, KeyID: verified.Pin.SignatureKeyID,
			PublicKeySHA256: verified.PublicKeySHA256(), Usage: []string{"host_capability_contract"},
			AllowedCapabilityPublishers: []string{verified.Pin.PublisherID},
			ValidFrom:                   "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z", RevocationEpoch: "1",
		})
		capabilities := capability.NewRegistry()
		if err := capabilities.AddContract(verified); err != nil {
			t.Fatal(err)
		}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			developerMode:           true,
			localGenerated:          true,
			releaseMetadataVerifier: metadataVerifier,
			releaseSourcePolicy:     &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicy},
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedArtifactForRelease(t, ref, release, packageBytes)},
			hostRequirements:        &fixedHostRequirementPolicy{hostID: "example-host"},
			capabilities:            capabilities,
		})

		if _, err := h.InstallReleaseRef(ctx, InstallReleaseRefRequest{ReleaseRef: ref}); err != nil {
			t.Fatalf("InstallReleaseRef() error = %v", err)
		}
		got := metadataVerifier.last.Release.HostRequirements[0].RequiredCapabilityContracts[0].Contract
		if got != verified.Pin {
			t.Fatalf("host capability contract pins were not preserved: %#v", got)
		}
	})

	t.Run("rejects incomplete host capability contract pins", func(t *testing.T) {
		ref := baseRef
		release := releaseForPackage(ref, pkg)
		contractRef := completeHostCapabilityRef()
		contractRef.GeneratedClientSHA256 = ""
		release.HostRequirements = []HostRequirement{{
			HostID: "example-host",
			RequiredCapabilityContracts: []HostCapabilityRequirement{{
				CapabilityID:      "example.capability.resources",
				CapabilityVersion: "1.0.0",
				Contract:          contractRef,
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
		contractRef := completeHostCapabilityRef()
		contractRef.SignatureSHA256 = ""
		release.HostRequirements = []HostRequirement{{
			HostID: "example-host",
			RequiredCapabilityContracts: []HostCapabilityRequirement{{
				CapabilityID:      "example.capability.resources",
				CapabilityVersion: "1.0.0",
				Contract:          contractRef,
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

func TestResolveAndVerifyExternalHostCapabilityContract(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract:                 contract,
		PublisherID:              contract.PublisherID,
		ArtifactBaseRef:          "capabilities/example/echo/v1.0.0",
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("e", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "capability-contract-key",
		SignaturePolicyEpoch:     "1",
		SignatureRevocationEpoch: "1",
		PrivateKey:               privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := releaseRefForPackage(t, "official", readTestPackage(t, buildFixturePackage(t)))
	policy := sourcePolicyForRelease(ref)
	policy.AllowedArtifactHosts = []string{"artifacts.example.com"}
	keyHash := sha256.Sum256(publicKey)
	policy.TrustedKeys = append(policy.TrustedKeys, SourcePolicyTrustedKey{
		Algorithm:                   pluginpkg.PackageSignatureAlgorithmEd25519,
		KeyID:                       bundle.Pin.SignatureKeyID,
		PublicKeySHA256:             "sha256:" + hex.EncodeToString(keyHash[:]),
		Usage:                       []string{"host_capability_contract"},
		AllowedCapabilityPublishers: []string{bundle.Pin.PublisherID},
		ValidFrom:                   "2026-01-01T00:00:00Z",
		ValidUntil:                  "2027-01-01T00:00:00Z",
		RevocationEpoch:             "1",
	})
	artifactSet := &memoryCapabilityContractArtifactSet{bundle: bundle}
	artifactResolver := &recordingCapabilityContractArtifactResolver{result: ResolvedCapabilityContractArtifact{Artifacts: artifactSet}}
	keyResolver := &recordingCapabilityContractKeyResolver{publicKey: publicKey}
	h := &Host{adapters: Adapters{
		CapabilityContractArtifacts: artifactResolver,
		CapabilityContractKeys:      keyResolver,
	}}
	verified, err := h.resolveAndVerifyCapabilityContract(context.Background(), PluginPackageRelease{
		SourceID:    ref.SourceID,
		PublisherID: ref.PublisherID,
	}, policy, HostCapabilityRequirement{
		CapabilityID:      contract.CapabilityID,
		CapabilityVersion: contract.CapabilityVersion,
		Contract:          bundle.Pin,
	})
	if err != nil {
		t.Fatalf("resolveAndVerifyCapabilityContract() error = %v", err)
	}
	if verified.Pin != bundle.Pin || artifactResolver.calls != 1 || keyResolver.calls != 1 {
		t.Fatalf("verified external contract mismatch: verified=%#v artifact=%#v key=%#v", verified.Pin, artifactResolver, keyResolver)
	}
	artifactSet.fetchChain = []CapabilityArtifactFetchHop{
		{URL: "https://artifacts.example.com/releases/start", ResolvedIP: "93.184.216.34"},
		{URL: "https://redirect.example.net/releases/final", ResolvedIP: "93.184.216.34"},
	}
	if _, err := h.resolveAndVerifyCapabilityContract(context.Background(), PluginPackageRelease{
		SourceID: ref.SourceID, PublisherID: ref.PublisherID,
	}, policy, HostCapabilityRequirement{CapabilityID: contract.CapabilityID, CapabilityVersion: contract.CapabilityVersion, Contract: bundle.Pin}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("unauthorized redirect error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestCapabilityContractArtifactFetchFailsClosed(t *testing.T) {
	verified := fixtureVerifiedCapabilityContract(t, "example.capability.echo")
	bundle, _, err := buildFixtureCapabilityBundle(verified.Contract)
	if err != nil {
		t.Fatal(err)
	}
	policy := SourcePolicySnapshot{AllowedArtifactHosts: []string{"artifacts.example.com"}}
	oversize := capabilitycontract.MaxArtifactFileBytes + 1
	wrongSize := int64(len(bundle.Files[bundle.Pin.ArtifactRef]) + 1)
	tests := []struct {
		name string
		set  *memoryCapabilityContractArtifactSet
	}{
		{name: "file URL", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "file:///tmp/contract.json", ResolvedIP: "93.184.216.34"}}}},
		{name: "unapproved host", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "https://other.example.com/contract.json", ResolvedIP: "93.184.216.34"}}}},
		{name: "private IP", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/contract.json", ResolvedIP: "127.0.0.1"}}}},
		{name: "carrier grade NAT", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/contract.json", ResolvedIP: "100.64.0.1"}}}},
		{name: "benchmark network", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/contract.json", ResolvedIP: "198.18.0.1"}}}},
		{name: "documentation network", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/contract.json", ResolvedIP: "203.0.113.10"}}}},
		{name: "IPv4 mapped carrier grade NAT", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/contract.json", ResolvedIP: "::ffff:100.64.0.1"}}}},
		{name: "IPv6 documentation network", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/contract.json", ResolvedIP: "2001:db8::10"}}}},
		{name: "path traversal", set: &memoryCapabilityContractArtifactSet{bundle: bundle, fetchChain: []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/releases/%2e%2e/contract.json", ResolvedIP: "93.184.216.34"}}}},
		{name: "media type", set: &memoryCapabilityContractArtifactSet{bundle: bundle, mediaType: "text/html"}},
		{name: "declared size mismatch", set: &memoryCapabilityContractArtifactSet{bundle: bundle, declaredSize: &wrongSize}},
		{name: "declared file too large", set: &memoryCapabilityContractArtifactSet{bundle: bundle, declaredSize: &oversize}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadCapabilityContractBundle(context.Background(), bundle.Pin, policy, ResolvedCapabilityContractArtifact{Artifacts: tc.set}); !errors.Is(err, ErrReleaseRefVerificationFailed) {
				t.Fatalf("loadCapabilityContractBundle() error = %v, want ErrReleaseRefVerificationFailed", err)
			}
		})
	}
}

func TestTrustedSourceKeyAllowsHostCapabilityContractUsage(t *testing.T) {
	ref := releaseRefForPackage(t, "official", readTestPackage(t, buildFixturePackage(t)))
	policy := sourcePolicyForRelease(ref)
	policy.TrustedKeyIDs = append(policy.TrustedKeyIDs, "capability-contract-key")
	policy.TrustedKeys = append(policy.TrustedKeys, SourcePolicyTrustedKey{
		Algorithm:                   pluginpkg.PackageSignatureAlgorithmEd25519,
		KeyID:                       "capability-contract-key",
		PublicKeySHA256:             strings.Repeat("b", 64),
		Usage:                       []string{"host_capability_contract"},
		AllowedCapabilityPublishers: []string{"example.contracts"},
		ValidFrom:                   "2026-01-01T00:00:00Z",
		ValidUntil:                  "2027-01-01T00:00:00Z",
		RevocationEpoch:             "1",
	})
	if err := validateTrustedSourceKeys(policy, time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("validateTrustedSourceKeys() rejected host capability contract usage: %v", err)
	}
}

func TestEnsureReleaseCapabilityContractsRevalidatesCachedSigningKey(t *testing.T) {
	verified := fixtureVerifiedCapabilityContract(t, "example.capability.echo")
	capabilities := capability.NewRegistry()
	if err := capabilities.AddContract(verified); err != nil {
		t.Fatal(err)
	}
	ref := releaseRefForPackage(t, "official", readTestPackage(t, buildFixturePackage(t)))
	policy := sourcePolicyForRelease(ref)
	policy.TrustedKeyIDs = append(policy.TrustedKeyIDs, verified.Pin.SignatureKeyID)
	policy.TrustedKeys = append(policy.TrustedKeys, SourcePolicyTrustedKey{
		Algorithm:                   pluginpkg.PackageSignatureAlgorithmEd25519,
		KeyID:                       verified.Pin.SignatureKeyID,
		PublicKeySHA256:             "sha256:" + verified.PublicKeySHA256(),
		Usage:                       []string{"host_capability_contract"},
		AllowedCapabilityPublishers: []string{verified.Pin.PublisherID},
		ValidFrom:                   "2026-01-01T00:00:00Z",
		ValidUntil:                  "2027-01-01T00:00:00Z",
		RevocationEpoch:             "1",
	})
	hostRequirements := &fixedHostRequirementPolicy{hostID: "example-host"}
	h := &Host{adapters: Adapters{
		HostRequirements: hostRequirements,
		Capabilities:     capabilities,
	}}
	release := PluginPackageRelease{
		SourceID:    ref.SourceID,
		PublisherID: ref.PublisherID,
		HostRequirements: []HostRequirement{{
			HostID: "example-host",
			RequiredCapabilityContracts: []HostCapabilityRequirement{{
				CapabilityID:      verified.Contract.CapabilityID,
				CapabilityVersion: verified.Contract.CapabilityVersion,
				Contract:          verified.Pin,
			}},
		}},
	}
	if _, err := h.ensureReleaseCapabilityContracts(context.Background(), release, policy); err != nil {
		t.Fatalf("ensureReleaseCapabilityContracts() initial cache hit error = %v", err)
	}
	policy.TrustedKeys[len(policy.TrustedKeys)-1].PublicKeySHA256 = strings.Repeat("b", 64)
	if _, err := h.ensureReleaseCapabilityContracts(context.Background(), release, policy); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("ensureReleaseCapabilityContracts() key mismatch error = %v, want ErrReleaseRefVerificationFailed", err)
	}
	policy.TrustedKeys[len(policy.TrustedKeys)-1].PublicKeySHA256 = verified.PublicKeySHA256()
	setSourcePolicyRevokedKeys(&policy, []string{verified.Pin.SignatureKeyID})
	if _, err := h.ensureReleaseCapabilityContracts(context.Background(), release, policy); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("ensureReleaseCapabilityContracts() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func TestReleaseHostRequirementsAreEvaluatedWithoutManifestBindings(t *testing.T) {
	policyErr := errors.New("host version is unsupported")
	hostRequirements := &fixedHostRequirementPolicy{err: policyErr}
	h := &Host{adapters: Adapters{HostRequirements: hostRequirements, Capabilities: capability.NewRegistry()}}
	release := PluginPackageRelease{
		SourceID: "official", PublisherID: "example", PluginID: "com.example.no_capabilities", Version: "1.0.0",
		HostRequirements: []HostRequirement{{HostID: "example-host", MinHostVersion: "2.0.0"}},
	}
	_, err := h.resolvePackageCapabilityPins(context.Background(), manifest.Manifest{}, packageTrustInput{
		Release: &release, SourcePolicySnapshot: &SourcePolicySnapshot{},
	})
	if !errors.Is(err, ErrReleaseRefVerificationFailed) || !strings.Contains(err.Error(), policyErr.Error()) {
		t.Fatalf("resolvePackageCapabilityPins() error = %v, want host policy rejection", err)
	}
	if hostRequirements.calls != 1 || len(hostRequirements.last.Requirements) != 1 {
		t.Fatalf("host requirement policy call mismatch: %#v", hostRequirements)
	}
}

func TestCapabilitySigningKeyRejectsPublisherOutsidePolicyScope(t *testing.T) {
	ref := releaseRefForPackage(t, "official", readTestPackage(t, buildFixturePackage(t)))
	policy := sourcePolicyForRelease(ref)
	policy.TrustedKeyIDs = append(policy.TrustedKeyIDs, "capability-contract-key")
	policy.TrustedKeys = append(policy.TrustedKeys, SourcePolicyTrustedKey{
		Algorithm: pluginpkg.PackageSignatureAlgorithmEd25519, KeyID: "capability-contract-key",
		PublicKeySHA256: strings.Repeat("b", 64), Usage: []string{"host_capability_contract"},
		AllowedCapabilityPublishers: []string{"other.publisher"},
		ValidFrom:                   "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z", RevocationEpoch: "1",
	})
	pin := completeHostCapabilityRef()
	pin.SignatureKeyID = "capability-contract-key"
	pin.SignaturePolicyEpoch = "1"
	pin.SignatureRevocationEpoch = "1"
	if _, err := validateCapabilityContractSigningKey(policy, pin, time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)); !errors.Is(err, ErrReleaseRefVerificationFailed) {
		t.Fatalf("validateCapabilityContractSigningKey() error = %v, want ErrReleaseRefVerificationFailed", err)
	}
}

func completeHostCapabilityRef() HostCapabilityContractRef {
	return HostCapabilityContractRef{
		PublisherID:              "example.contracts",
		ContractID:               "example.resources.v1",
		ContractVersion:          "1.0.0",
		ArtifactRef:              "capabilities/example/resources/v1/contract.json",
		ArtifactSHA256:           strings.Repeat("1", 64),
		ManifestRef:              "capabilities/example/resources/v1/manifest.json",
		ManifestSHA256:           strings.Repeat("2", 64),
		SignatureRef:             "capabilities/example/resources/v1/manifest.sig",
		SignatureSHA256:          strings.Repeat("6", 64),
		SignatureKeyID:           "official",
		SignaturePolicyEpoch:     "7",
		SignatureRevocationEpoch: "11",
		CompatibilityRef:         "capabilities/example/resources/v1/compatibility.json",
		CompatibilitySHA256:      strings.Repeat("3", 64),
		GeneratedClientRef:       "capabilities/example/resources/v1/client.ts",
		GeneratedClientSHA256:    strings.Repeat("4", 64),
		NoticesRef:               "capabilities/example/resources/v1/notices.json",
		NoticesSHA256:            strings.Repeat("5", 64),
	}
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

	if _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{PluginInstanceID: current.PluginInstanceID, ReleaseRef: ref, PluginStateVersion: mustPluginStateVersion(t, h, current.PluginInstanceID)}); !errors.Is(err, ErrReleaseRefPolicyDenied) {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "lifecycle.view")

	verifier.metadata = map[string]string{"trust.key_id": "official-v2"}
	v2Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2"), "official")
	v2Pkg := readTestPackage(t, v2Bytes)
	v2Ref := releaseRefForPackage(t, "official", v2Pkg)
	sourceResolver := &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v2Ref)}
	artifactResolver := &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v2Ref, v2Pkg, v2Bytes)}
	h.adapters.ReleaseSourcePolicy = sourceResolver
	h.adapters.ReleaseArtifactResolver = artifactResolver

	updated, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{PluginInstanceID: installed.PluginInstanceID, ReleaseRef: v2Ref, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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

	if _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{PluginInstanceID: enabled.PluginInstanceID, ReleaseRef: v2Ref, PluginStateVersion: mustPluginStateVersion(t, h, enabled.PluginInstanceID)}); err == nil || !strings.Contains(err.Error(), "surface catalog unavailable") {
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
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}

	verifier.metadata = map[string]string{"trust.key_id": "official-v2"}
	v2Bytes := buildSignedReleasePackageBytes(t, buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2"), "official")
	v2Pkg := readTestPackage(t, v2Bytes)
	v2Ref := releaseRefForPackage(t, "official", v2Pkg)
	h.adapters.ReleaseSourcePolicy = &recordingReleaseSourcePolicyResolver{snapshot: sourcePolicyForRelease(v2Ref)}
	h.adapters.ReleaseArtifactResolver = &recordingReleaseArtifactResolver{artifact: resolvedArtifactForPackage(t, v2Ref, v2Pkg, v2Bytes)}

	if _, err := h.UpdateReleaseRef(ctx, UpdateReleaseRefRequest{PluginInstanceID: enabled.PluginInstanceID, ReleaseRef: v2Ref, PluginStateVersion: mustPluginStateVersion(t, h, enabled.PluginInstanceID)}); err == nil || !strings.Contains(err.Error(), "runtime revoke unavailable") {
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
		PackageSize:      int64(len(nextBytes)), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
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
		Now:              now.Add(time.Minute), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
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
	first := activeFingerprintForPackage(pkg, "plugini_fingerprint", trust, nil)
	if first == "" || first != activeFingerprintForPackage(pkg, "plugini_fingerprint", trust, nil) {
		t.Fatalf("active fingerprint should be stable, got %q", first)
	}
	metadataChanged := trust
	metadataChanged.Metadata = map[string]string{"ignored": "metadata"}
	if got := activeFingerprintForPackage(pkg, "plugini_fingerprint", metadataChanged, nil); got != first {
		t.Fatalf("metadata-only trust change affected active fingerprint: got %q want %q", got, first)
	}
	for name, mutate := range map[string]func(pluginpkg.Package, registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment){
		"package_hash": func(pkg pluginpkg.Package, trust registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment) {
			pkg.PackageHash = strings.Repeat("a", 64)
			return pkg, trust
		},
		"capability_contract": func(pkg pluginpkg.Package, trust registry.TrustAssessment) (pluginpkg.Package, registry.TrustAssessment) {
			contract := pkg.Manifest.CapabilityBindings[0].Contract
			contract.ContractID = "example.extra.v1"
			contract.ArtifactSHA256 = strings.Repeat("a", 64)
			pkg.Manifest.CapabilityBindings = append(pkg.Manifest.CapabilityBindings, manifest.CapabilityBinding{BindingID: "extra", Contract: contract})
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
			if got := activeFingerprintForPackage(changedPkg, "plugini_fingerprint", changedTrust, nil); got == first {
				t.Fatalf("active fingerprint did not change for %s", name)
			}
		})
	}
}

func TestLocalInstallUsesTheManifestExactCapabilityContractPin(t *testing.T) {
	capabilities := capability.NewRegistry()
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	base := fixtureVerifiedCapabilityContract(t, "example.capability.echo")
	newerContract := base.Contract
	newerContract.ContractVersion = "1.4.0"
	newerContract.CapabilityVersion = "1.4.0"
	newer := verifyFixtureCapabilityContract(t, newerContract)
	for _, verified := range []capabilitycontract.VerifiedContract{base, newer} {
		if err := capabilities.Register(capability.Registration{Contract: verified, TargetProjector: adapter, Adapter: adapter}); err != nil {
			t.Fatal(err)
		}
	}
	h, err := New(Adapters{
		SessionResolver: fakeSessionResolver{},
		Policy:          policyAdapter{developerMode: true, localGenerated: true, decision: PolicyAllow},
		Capabilities:    capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildRPCFixturePackage(t))
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	if len(installed.CapabilityContracts) != 1 || installed.CapabilityContracts[0] != base.Pin {
		t.Fatalf("installed capability pins = %#v, want exact %#v", installed.CapabilityContracts, base.Pin)
	}
}

func TestLocalInstallRejectsCapabilityMethodAliasesThatGeneratedClientsCannotCall(t *testing.T) {
	dir := t.TempDir()
	manifestJSON := strings.Replace(rpcFixtureManifestJSON("1.0.0", "RPC"), `"method": "echo.ping"`, `"method": "plugin.echo"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "RPC")
	var packageBytes bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &packageBytes, pluginpkg.DefaultReadOptions()); err == nil || !strings.Contains(err.Error(), "must match route.target_method") {
		t.Fatalf("BuildFromDir() error = %v, want method alias rejection", err)
	}
}

func TestLocalInstallRejectsCapabilityPolicyDeclaredByPluginManifest(t *testing.T) {
	dir := t.TempDir()
	manifestJSON := strings.Replace(dangerousRPCFixtureManifestJSON(), `"method": "danger.run",`, `"method": "danger.run", "confirmation": {"mode": "required"},`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Danger")
	var packageBytes bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &packageBytes, pluginpkg.DefaultReadOptions()); err == nil || !strings.Contains(err.Error(), "derive policy and schemas from the signed capability contract") {
		t.Fatalf("BuildFromDir() error = %v, want unsigned policy rejection", err)
	}
}

func TestOpenSurfaceRejectsCurrentSourcePolicyEpochAdvance(t *testing.T) {
	ctx := context.Background()
	h, sourceResolver, installed, ref := installReleaseRefLifecyclePlugin(t, testHostOptions{})
	now := stableRecentTestNow()
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	nextPolicy := sourcePolicyForRelease(ref)
	setSourcePolicyEpochs(&nextPolicy, "2")
	sourceResolver.snapshot = nextPolicy

	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "lifecycle.view",
		SurfaceInstanceID: "surface_source_policy_advance",
		OwnerSessionHash:  "session_hash",
		OwnerUserHash:     "user_hash",
		Now:               now.Add(time.Second), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.view",
		SurfaceInstanceID:    "surface_source_policy_bridge",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		Now:                  now.Add(time.Second), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if _, err := h.PrepareSurface(ctx, exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second))); err != nil {
		t.Fatalf("PrepareSurface() error = %v", err)
	}
	nextPolicy := sourcePolicyForRelease(ref)
	setSourcePolicyEpochs(&nextPolicy, "2")
	sourceResolver.snapshot = nextPolicy
	handshake := bridge.Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		PluginStateVersion: bootstrap.PluginStateVersion,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v2",
	}

	if _, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_source_policy",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_source_policy"),
		OwnerSessionHash:          bootstrap.OwnerSessionHash,
		OwnerUserHash:             bootstrap.OwnerUserHash,
		SessionChannelIDHash:      bootstrap.SessionChannelIDHash,
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
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: stableRecentTestNow(), PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: stableRecentTestNow(), PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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
	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, PluginStateVersion: mustPluginStateVersion(t, host, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}

	bootstrap, err := host.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.view",
		SurfaceInstanceID:    "surface_lifecycle",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		Now:                  now.Add(time.Second), PluginStateVersion: mustPluginStateVersion(t, host,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if bootstrap.AssetTicket == "" || bootstrap.BridgeNonce == "" {
		t.Fatalf("bootstrap missing ticket/nonce: %#v", bootstrap)
	}

	if _, err := host.PrepareSurface(context.Background(), exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second))); err != nil {
		t.Fatalf("PrepareSurface() error = %v", err)
	}

	handshake := bridge.Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		PluginStateVersion: bootstrap.PluginStateVersion,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v2",
	}
	gateway, err := host.MintBridgeToken(context.Background(), MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_channel",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_channel"),
		OwnerSessionHash:          bootstrap.OwnerSessionHash,
		OwnerUserHash:             bootstrap.OwnerUserHash,
		SessionChannelIDHash:      bootstrap.SessionChannelIDHash,
		Now:                       now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}
	if gateway.GatewayToken == "" {
		t.Fatalf("gateway token is empty: %#v", gateway)
	}
}

func TestOpenSurfaceBindsRuntimeGenerationFromSupervisor(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{health: runtimeclient.Health{
		RuntimeInstanceID:   "runtime_surface",
		RuntimeGenerationID: "runtime_generation_surface",
		IPCChannelID:        "ipc_surface",
		ConnectionNonce:     "connection_nonce_surface_123456",
		Ready:               true,
	}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		runtimeSupervisor: runtime,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}

	bootstrap, err := h.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.view",
		SurfaceInstanceID:    "surface_runtime_generation",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		Now:                  now.Add(time.Second), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if bootstrap.RuntimeGenerationID != "runtime_generation_surface" {
		t.Fatalf("runtime generation = %q, want runtime_generation_surface", bootstrap.RuntimeGenerationID)
	}
	if !audits.hasEvent("plugin.surface.opened") {
		t.Fatalf("missing surface opened audit event: %#v", audits.events)
	}
}

func TestMintBridgeTokenRejectsSurfaceAfterRuntimeGenerationChanges(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{health: runtimeclient.Health{
		RuntimeInstanceID:   "runtime_surface",
		RuntimeGenerationID: "runtime_generation_1",
		IPCChannelID:        "ipc_surface",
		ConnectionNonce:     "connection_nonce_surface_123456",
		Ready:               true,
	}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		runtimeSupervisor: runtime,
	})
	now := stableRecentTestNow()
	installed := installAndEnablePlugin(t, h, buildFixturePackage(t))
	bootstrap, err := h.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.view",
		SurfaceInstanceID:    "surface_runtime_restart_before_bridge",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
		PluginStateVersion:   mustPluginStateVersion(t, h, installed.PluginInstanceID),
		Now:                  now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if _, err := h.PrepareSurface(context.Background(), exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second))); err != nil {
		t.Fatalf("PrepareSurface() error = %v", err)
	}
	runtime.health.RuntimeGenerationID = "runtime_generation_2"
	handshake := bridge.Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		PluginStateVersion: bootstrap.PluginStateVersion,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v2",
	}
	_, err = h.MintBridgeToken(context.Background(), MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_runtime_restart",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_runtime_restart"),
		OwnerSessionHash:          bootstrap.OwnerSessionHash,
		OwnerUserHash:             bootstrap.OwnerUserHash,
		SessionChannelIDHash:      bootstrap.SessionChannelIDHash,
		Now:                       now.Add(3 * time.Second),
	})
	if !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("MintBridgeToken() after runtime restart error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
}

func TestReadSurfaceAssetRequiresAssetSession(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := ImportLocalPackageBytes(context.Background(), h, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceID:            "lifecycle.view",
		SurfaceInstanceID:    "surface_asset",
		OwnerSessionHash:     "owner_session_hash",
		OwnerUserHash:        "owner_user_hash",
		SessionChannelIDHash: "session_channel_hash",
		Now:                  now.Add(time.Second), PluginStateVersion: mustPluginStateVersion(t, h,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession:         "not-a-session",
		AssetSessionID:       "as_invalid",
		BindingID:            "asset_invalid",
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(2 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenInvalid) {
		t.Fatalf("ReadSurfaceAsset() error = %v, want ErrTokenInvalid", err)
	}
	prepared, err := h.PrepareSurface(context.Background(), exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Document.Assets) != 1 {
		t.Fatalf("prepared assets = %#v, want one lazy asset", prepared.Document.Assets)
	}
	preparedAsset := prepared.Document.Assets[0]
	asset, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession:         prepared.AssetSession,
		AssetSessionID:       prepared.AssetSessionID,
		BindingID:            preparedAsset.BindingID,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("ReadSurfaceAsset() error = %v", err)
	}
	if string(asset.Content) != "status" || asset.Entry.Path != preparedAsset.Path || asset.Session.SurfaceInstanceID != bootstrap.SurfaceInstanceID {
		t.Fatalf("asset mismatch: session=%#v entry=%#v content=%q", asset.Session, asset.Entry, string(asset.Content))
	}
	originalAssets := h.adapters.Assets
	for _, tt := range []struct {
		name   string
		mutate func(pluginpkg.Asset) pluginpkg.Asset
	}{
		{
			name: "content digest",
			mutate: func(asset pluginpkg.Asset) pluginpkg.Asset {
				asset.Content = []byte("forged")
				return asset
			},
		},
		{
			name: "entry path",
			mutate: func(asset pluginpkg.Asset) pluginpkg.Asset {
				asset.Entry.Path = "ui/other.txt"
				return asset
			},
		},
		{
			name: "entry size",
			mutate: func(asset pluginpkg.Asset) pluginpkg.Asset {
				asset.Entry.Size++
				return asset
			},
		},
		{
			name: "entry content type",
			mutate: func(asset pluginpkg.Asset) pluginpkg.Asset {
				asset.Entry.ContentType = "application/octet-stream"
				return asset
			},
		},
	} {
		t.Run("rejects adapter "+tt.name+" mismatch", func(t *testing.T) {
			h.adapters.Assets = mutatingAssetStore{AssetStore: originalAssets, mutate: tt.mutate}
			defer func() { h.adapters.Assets = originalAssets }()
			_, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
				AssetSession:         prepared.AssetSession,
				AssetSessionID:       prepared.AssetSessionID,
				BindingID:            preparedAsset.BindingID,
				OwnerSessionHash:     bootstrap.OwnerSessionHash,
				OwnerUserHash:        bootstrap.OwnerUserHash,
				SessionChannelIDHash: bootstrap.SessionChannelIDHash,
				Now:                  now.Add(3 * time.Second),
			})
			if !errors.Is(err, bridge.ErrTokenAudience) {
				t.Fatalf("ReadSurfaceAsset() adapter mismatch error = %v, want ErrTokenAudience", err)
			}
		})
	}
	if _, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession:         prepared.AssetSession,
		AssetSessionID:       prepared.AssetSessionID,
		BindingID:            "asset_not_prepared",
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(3 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("ReadSurfaceAsset(unprepared binding) error = %v, want ErrTokenAudience", err)
	}
	if _, err := h.ReadSurfaceAsset(context.Background(), ReadSurfaceAssetRequest{
		AssetSession:         prepared.AssetSession,
		AssetSessionID:       "asset_session_other",
		BindingID:            preparedAsset.BindingID,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now.Add(3 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("ReadSurfaceAsset(wrong session id) error = %v, want ErrTokenAudience", err)
	}
}

type mutatingAssetStore struct {
	pluginpkg.AssetStore
	mutate func(pluginpkg.Asset) pluginpkg.Asset
}

func (s mutatingAssetStore) ReadAsset(ctx context.Context, packageHash string, assetPath string) (pluginpkg.Asset, error) {
	asset, err := s.AssetStore.ReadAsset(ctx, packageHash, assetPath)
	if err != nil {
		return pluginpkg.Asset{}, err
	}
	return s.mutate(asset), nil
}

func TestOpenSurfaceRequiresEnabledPlugin(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(context.Background(), host, buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.OpenSurface(context.Background(), OpenSurfaceRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SurfaceID:        "lifecycle.view", PluginStateVersion: mustPluginStateVersion(t, host,
			installed.PluginInstanceID),
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
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")

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
	if capabilityAdapter.last.Execution.CapabilityID != "example.capability.echo" ||
		capabilityAdapter.last.Execution.RouteKind != capability.RouteCapability ||
		capabilityAdapter.last.Execution.Contract == nil ||
		capabilityAdapter.last.Execution.BindingID != "echo" ||
		capabilityAdapter.last.Execution.Method != "echo.ping" ||
		capabilityAdapter.last.Execution.TargetMethod != "echo.ping" ||
		capabilityAdapter.last.Execution.PluginInstanceID != installed.PluginInstanceID ||
		capabilityAdapter.last.Execution.BridgeChannelID != "bridge_rpc" {
		t.Fatalf("capability invocation mismatch: %#v", capabilityAdapter.last)
	}
	if !audits.hasEvent("plugin.method.called") {
		t.Fatalf("missing method audit event: %#v", audits.events)
	}
}

func TestCapabilityRejectionFailsClosedWhenAuditPersistenceFails(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
	h.adapters.Audit = failingAuditSink{err: errors.New("audit store unavailable")}
	_, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "echo.ping", Params: map[string]any{"message": "hello", "unexpected": true},
	})
	if !errors.Is(err, ErrMethodRequestContract) || !errors.Is(err, ErrSecurityEventPersistence) {
		t.Fatalf("CallPluginMethod() error = %v, want request contract and persistence errors", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestCapabilityTargetProjectorMayAddHostDerivedFields(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result:       capability.Result{Data: map[string]any{"ok": true}},
		targetFields: map[string]any{"resource_id": "host-resource-1", "scope": "environment"},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
	for index := range contract.Methods {
		if contract.Methods[index].Name == "echo.ping" {
			contract.Methods[index].TargetSchema = fixtureClosedObject(map[string]any{
				"resource_id": map[string]any{"type": "string", "minLength": 1},
				"scope":       map[string]any{"type": "string", "const": "environment"},
			}, []string{"resource_id", "scope"})
		}
	}
	verified := verifyFixtureCapabilityContract(t, contract)
	if err := h.adapters.Capabilities.Register(capability.Registration{Contract: verified, TargetProjector: capabilityAdapter, Adapter: capabilityAdapter}); err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(t, rpcFixtureManifestJSON("1.0.0", "RPC"), "RPC", "echo", verified.Pin), "rpc.view")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "echo.ping", Params: map[string]any{"message": "hello"},
	}); err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if capabilityAdapter.lastTarget.TargetInput["message"] != "hello" || capabilityAdapter.last.Execution.Target.Fields["resource_id"] != "host-resource-1" {
		t.Fatalf("target projection mismatch: request=%#v execution=%#v", capabilityAdapter.lastTarget, capabilityAdapter.last.Execution.Target)
	}
}

func TestCallPluginMethodRejectsSurfaceAfterRuntimeGenerationChanges(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{health: runtimeclient.Health{
		RuntimeInstanceID:   "runtime_surface",
		RuntimeGenerationID: "runtime_generation_1",
		IPCChannelID:        "ipc_surface",
		ConnectionNonce:     "connection_nonce_surface_123456",
		Ready:               true,
	}}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		runtimeSupervisor: runtime,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
	runtime.health.RuntimeGenerationID = "runtime_generation_2"

	_, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
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
	if !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("CallPluginMethod() after runtime restart error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter calls = %d, want 0", capabilityAdapter.calls)
	}
}

func TestCallPluginMethodRejectsRequestSchemaViolationBeforeDispatch(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")

	_, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "echo.ping",
		Params:               map[string]any{"unknown": true},
	})
	if !errors.Is(err, ErrMethodRequestContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodRequestContract", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter calls = %d, want 0", capabilityAdapter.calls)
	}
}

func TestCallPluginMethodRejectsResponseSchemaViolation(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"unknown": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")

	_, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
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
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("capability adapter calls = %d, want 1", capabilityAdapter.calls)
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
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")

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
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		diagnostics:       diagnostics,
	})
	installed, gateway := installEnableAndMintGatewayWithoutPermissions(t, h, buildRPCFixturePackage(t), "rpc.view")
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
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "permission_denied" {
		t.Fatalf("missing permission rejection audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details["reason"] != "permission_denied" {
		t.Fatalf("missing permission rejection diagnostic: %#v", diagnostics.events)
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
	_, freshGateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.view")
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
	_, freshGateway = openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.view")
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
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
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
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")

	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "documents.archive",
		Params:               map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.OperationID == "" || capabilityAdapter.last.Execution.Operation == nil || result.OperationID != capabilityAdapter.last.Execution.Operation.ID() {
		t.Fatalf("operation id mismatch: %#v", result)
	}
	registered, err := h.GetOperation(context.Background(), result.OperationID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if registered.PluginInstanceID != installed.PluginInstanceID ||
		registered.Method != "documents.archive" ||
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

func TestCapabilityAdapterCannotMutateHostOwnedExecutionBinding(t *testing.T) {
	adapter := &recordingCapabilityAdapter{
		result: capability.Result{Data: map[string]any{}},
		mutateExecution: func(binding *capability.ExecutionBinding) {
			binding.Permissions.Required[0] = "tampered.permission"
			binding.Permissions.Granted[0] = "tampered.permission"
			binding.Target.Fields["document_id"] = "tampered-document"
		},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.last.Execution.Permissions.Required[0] != "tampered.permission" || adapter.last.Execution.Target.Fields["document_id"] != "tampered-document" {
		t.Fatalf("adapter mutation was not exercised: %#v", adapter.last.Execution.ExecutionBinding)
	}
	record, err := h.GetOperation(context.Background(), started.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Permissions.Required[0] != "execute" || record.Target.Fields["document_id"] != "doc-1" {
		t.Fatalf("durable execution binding was mutated by the adapter: %#v", record.ExecutionBinding)
	}
	if err := adapter.last.Execution.Operation.Complete(context.Background()); err != nil {
		t.Fatalf("Operation.Complete() error = %v", err)
	}
}

func TestCallPluginMethodRegistersStream(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")

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
	if result.StreamID == "" || capabilityAdapter.last.Execution.Stream == nil || result.StreamID != capabilityAdapter.last.Execution.Stream.ID() || result.StreamTicket == "" || result.StreamTicketID == "" || result.StreamExpiresAt == nil || result.StreamExpiresAt.IsZero() {
		t.Fatalf("CallPluginMethod() stream result mismatch: %#v", result)
	}
	if capabilityAdapter.last.Execution.StreamEventTypeName != "LogEvent" || len(capabilityAdapter.last.Execution.StreamEventSchemaSHA256) != 64 {
		t.Fatalf("signed stream contract binding mismatch: %#v", capabilityAdapter.last.Execution.ExecutionBinding)
	}
	if err := capabilityAdapter.last.Execution.Stream.Append(context.Background(), map[string]any{"unexpected": true}); err == nil || !strings.Contains(err.Error(), "signed contract") {
		t.Fatalf("Stream.Append(invalid event) error = %v, want signed event schema rejection", err)
	}
	if err := capabilityAdapter.last.Execution.Stream.Append(context.Background(), map[string]any{"line": "line 1"}); err != nil {
		t.Fatalf("Stream.Append() error = %v", err)
	}
	if _, err := h.ReadStream(context.Background(), ReadStreamRequest{StreamID: result.StreamID}); !errors.Is(err, ErrStreamTicketRequired) {
		t.Fatalf("ReadStream() without ticket error = %v, want %v", err, ErrStreamTicketRequired)
	}
	streamResult, err := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatalf("ReadStream() error = %v", err)
	}
	if streamResult.Record.Method != "logs.tail" || len(streamResult.Events) != 1 || string(streamResult.Events[0].Data) != `{"line":"line 1"}` {
		t.Fatalf("stream read mismatch: %#v", streamResult)
	}
	if streamResult.Done || streamResult.NextStreamTicket == "" || streamResult.NextStreamTicketID == "" || streamResult.NextStreamExpiresAt == nil {
		t.Fatalf("open stream did not return a renewable read credential: %#v", streamResult)
	}
	if err := capabilityAdapter.last.Execution.Stream.Append(context.Background(), map[string]any{"line": "line 2"}); err != nil {
		t.Fatalf("Stream.Append() after first read error = %v", err)
	}
	second, err := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, streamResult.NextStreamTicket))
	if err != nil {
		t.Fatalf("ReadStream() renewed read error = %v", err)
	}
	if second.Done || len(second.Events) != 1 || string(second.Events[0].Data) != `{"line":"line 2"}` || second.NextStreamTicket == "" {
		t.Fatalf("renewed stream read mismatch: %#v", second)
	}
	if err := capabilityAdapter.last.Execution.Stream.Close(context.Background()); err != nil {
		t.Fatalf("Stream.Close() error = %v", err)
	}
	final, err := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, second.NextStreamTicket))
	if err != nil {
		t.Fatalf("ReadStream() terminal read error = %v", err)
	}
	if !final.Done || final.TerminalStatus != stream.StatusClosed || final.NextStreamTicket != "" || final.NextStreamTicketID != "" || final.NextStreamExpiresAt != nil {
		t.Fatalf("terminal stream read retained a renewable credential: %#v", final)
	}
	if _, err := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, result.StreamTicket)); !errors.Is(err, bridge.ErrTokenReplay) {
		t.Fatalf("ReadStream() replay error = %v, want %v", err, bridge.ErrTokenReplay)
	}
	if !audits.hasEvent("plugin.stream.started") {
		t.Fatalf("missing stream audit event: %#v", audits.events)
	}
}

func TestReadStreamFailureKeepsCurrentTicketAndEvents(t *testing.T) {
	readFailure := errors.New("injected stream read failure")
	streams := &failFirstStreamReadStore{Store: stream.NewMemoryStore(), err: readFailure}
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter, streams: streams,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.last.Execution.Stream.Append(context.Background(), map[string]any{"line": "preserved"}); err != nil {
		t.Fatal(err)
	}
	request := scopedReadStreamRequest(result.StreamID, result.StreamTicket)
	if _, err := h.ReadStream(context.Background(), request); !errors.Is(err, readFailure) {
		t.Fatalf("ReadStream(first) error = %v, want %v", err, readFailure)
	}
	retried, err := h.ReadStream(context.Background(), request)
	if err != nil {
		t.Fatalf("ReadStream(retry) error = %v", err)
	}
	if len(retried.Events) != 1 || string(retried.Events[0].Data) != `{"line":"preserved"}` || retried.NextStreamTicket == "" {
		t.Fatalf("retry did not preserve the event and rotate the ticket: %#v", retried)
	}
}

func TestReadStreamSerializesConcurrentUseOfOneTicket(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.last.Execution.Stream.Append(context.Background(), map[string]any{"line": "once"}); err != nil {
		t.Fatal(err)
	}
	type readOutcome struct {
		result ReadStreamResult
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan readOutcome, 2)
	for range 2 {
		go func() {
			<-start
			read, readErr := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
			outcomes <- readOutcome{result: read, err: readErr}
		}()
	}
	close(start)
	first := <-outcomes
	second := <-outcomes
	results := []readOutcome{first, second}
	successes := 0
	replays := 0
	events := 0
	for _, outcome := range results {
		switch {
		case outcome.err == nil:
			successes++
			events += len(outcome.result.Events)
		case errors.Is(outcome.err, bridge.ErrTokenReplay):
			replays++
		default:
			t.Fatalf("concurrent ReadStream() error = %v", outcome.err)
		}
	}
	if successes != 1 || replays != 1 || events != 1 {
		t.Fatalf("concurrent read outcomes = %#v", results)
	}
}

func TestReadStreamLongPollRevalidatesPluginRevision(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		request := scopedReadStreamRequest(result.StreamID, result.StreamTicket)
		request.WaitTimeout = time.Second
		_, readErr := h.ReadStream(context.Background(), request)
		readDone <- readErr
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := h.DisablePlugin(context.Background(), DisableRequest{
		PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID), Reason: "policy",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, bridge.ErrTokenRevoked) {
			t.Fatalf("ReadStream() after revision change error = %v, want %v", err, bridge.ErrTokenRevoked)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long-poll stream read did not finish after plugin revision changed")
	}
}

func TestRuntimeStreamCloseCannotCompleteCanceledOperation(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.RequestCancel(context.Background(), operation.CancelRequest{OperationID: result.OperationID}); err != nil {
		t.Fatal(err)
	}
	sink, err := h.executions.streamSink(result.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	sink.lease.requestCancel(errors.New("operation cancellation requested"))
	if err := (hostRuntimeStreamSink{executions: h.executions}).CloseRuntimeStream(context.Background(), result.StreamID); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("CloseRuntimeStream() error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusCancelRequested)
}

func TestWorkerOperationCompletesWhenSynchronousRuntimeInvocationReturns(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		result: capability.Result{Data: map[string]any{"from_worker": true}},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeSupervisor: runtime})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerOperationFixturePackage(t), "worker.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "worker.echo", Params: map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OperationID == "" {
		t.Fatalf("worker operation result = %#v", result)
	}
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusCompleted)
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("worker operation retained %d execution leases after runtime return", activeLeases)
	}
}

func TestWorkerSubscriptionCompletesWhenSynchronousRuntimeInvocationReturns(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
		result: capability.Result{Data: map[string]any{"from_worker": true}},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeSupervisor: runtime})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerSubscriptionFixturePackage(t), "worker.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "worker.echo", Params: map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OperationID == "" || result.StreamID == "" || result.StreamTicket == "" {
		t.Fatalf("worker subscription result = %#v", result)
	}
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusCompleted)
	assertHostStreamStatus(t, h, result.StreamID, stream.StatusClosed)
	terminal, err := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatal(err)
	}
	if !terminal.Done || terminal.TerminalStatus != stream.StatusClosed || len(terminal.Events) != 0 || terminal.NextStreamTicket != "" {
		t.Fatalf("worker subscription terminal read = %#v", terminal)
	}
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("worker subscription retained %d execution leases after runtime return", activeLeases)
	}
}

func TestReadStreamReportsFailedTerminalStatus(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := capabilityAdapter.last.Execution.Stream.Fail(context.Background(), "runtime failed"); err != nil {
		t.Fatal(err)
	}
	terminal, err := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatal(err)
	}
	if !terminal.Done || terminal.TerminalStatus != stream.StatusFailed || len(terminal.Events) != 0 {
		t.Fatalf("failed terminal read mismatch: %#v", terminal)
	}
}

func TestReadTerminalStreamDoesNotRequireNextTicketCapacity(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	manager := bridge.NewTokenManager(bridge.TokenManagerOptions{
		MaxRecords:          4,
		MaxRecordsPerPlugin: 4,
	})
	tokens := bridge.NewSurfaceTokenService(manager, bridge.SurfaceTokenOptions{})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		surfaceTokens:     tokens,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := capabilityAdapter.last.Execution.Stream.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	terminal, err := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatalf("ReadStream() terminal read error = %v", err)
	}
	if !terminal.Done || terminal.TerminalStatus != stream.StatusClosed || terminal.NextStreamTicket != "" {
		t.Fatalf("terminal stream read = %#v", terminal)
	}
}

func TestReadTerminalStreamKeepsTicketUntilZeroPayloadEventsAreDrained(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"marker.first", "marker.second"} {
		if _, err := h.adapters.Streams.Append(context.Background(), stream.AppendRequest{StreamID: result.StreamID, Kind: kind}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.adapters.Streams.Close(context.Background(), stream.CloseRequest{StreamID: result.StreamID}); err != nil {
		t.Fatal(err)
	}

	request := scopedReadStreamRequest(result.StreamID, result.StreamTicket)
	request.MaxEvents = 1
	first, err := h.ReadStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Done || len(first.Events) != 1 || first.NextStreamTicket == "" {
		t.Fatalf("first terminal stream page = %#v", first)
	}
	request.StreamTicket = first.NextStreamTicket
	second, err := h.ReadStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Done || len(second.Events) != 1 || second.NextStreamTicket != "" {
		t.Fatalf("second terminal stream page = %#v", second)
	}
}

func TestCallPluginMethodClosesStreamWhenTicketMintFails(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	manager := bridge.NewTokenManager(bridge.TokenManagerOptions{
		MaxRecords:          4,
		MaxRecordsPerPlugin: 4,
	})
	tokens := bridge.NewSurfaceTokenService(manager, bridge.SurfaceTokenOptions{})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		surfaceTokens:     tokens,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	now := time.Now().UTC()
	if _, err := manager.Mint(bridge.MintRequest{
		Kind: bridge.TokenKindHandleGrant,
		Audience: bridge.Audience{
			PluginInstanceID:    installed.PluginInstanceID,
			ActiveFingerprint:   installed.ActiveFingerprint,
			RuntimeGenerationID: "runtime_filler",
			HandleID:            "handle_filler",
			Method:              "filler.reserve",
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision:     installed.PolicyRevision,
			ManagementRevision: installed.ManagementRevision,
			RevokeEpoch:        installed.RevokeEpoch,
		},
		Now:       now,
		ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("Mint(filler) error = %v", err)
	}

	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "logs.tail",
	}); !errors.Is(err, bridge.ErrTokenCapacity) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrTokenCapacity", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter ran before the initial stream ticket was available: calls=%d", capabilityAdapter.calls)
	}
	operations, err := h.adapters.Operations.List(context.Background(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].Status != operation.StatusFailed || operations[0].StreamID == "" {
		t.Fatalf("ticket failure did not persist the failed operation: %#v", operations)
	}
	assertHostStreamStatus(t, h, operations[0].StreamID, stream.StatusFailed)
}

func TestInitialStreamTicketFailurePersistsPartialCleanupForRestartReconciliation(t *testing.T) {
	ticketErr := bridge.ErrTokenCapacity
	finishErr := errors.New("operation terminal store unavailable")
	operationStore := &failFirstOperationFinishStore{Store: operation.NewMemoryStore(), err: finishErr}
	streamStore := stream.NewMemoryStore()
	manager := bridge.NewTokenManager(bridge.TokenManagerOptions{MaxRecords: 4, MaxRecordsPerPlugin: 4})
	tokens := bridge.NewSurfaceTokenService(manager, bridge.SurfaceTokenOptions{})
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
		operations: operationStore, streams: streamStore, surfaceTokens: tokens,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	mintHostTokenCapacityFiller(t, manager, installed)
	_, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if !errors.Is(err, ticketErr) || !errors.Is(err, finishErr) {
		t.Fatalf("CallPluginMethod() error = %v, want ticket and cleanup failures", err)
	}
	if adapter.calls != 0 {
		t.Fatalf("adapter ran before ticket issuance: calls=%d", adapter.calls)
	}
	records, err := operationStore.List(context.Background(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != operation.StatusRunning {
		t.Fatalf("partial cleanup operation state = %#v", records)
	}
	streamRecord, err := streamStore.Get(context.Background(), records[0].StreamID)
	if err != nil {
		t.Fatal(err)
	}
	if streamRecord.Status != stream.StatusFailed || !strings.Contains(streamRecord.Reason, ticketErr.Error()) {
		t.Fatalf("partial cleanup stream state = %#v", streamRecord)
	}
	restarted, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, operations: operationStore, streams: streamStore,
	})
	assertHostOperationStatus(t, restarted, records[0].OperationID, operation.StatusFailed)
}

func TestDisableTransitionsOpenStreamsAndRevokesStreamTickets(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
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
	streamSink := capabilityAdapter.last.Execution.Stream
	if streamSink == nil || streamSink.ID() != result.StreamID {
		t.Fatalf("stream sink mismatch: result=%#v invocation=%#v", result, capabilityAdapter.last)
	}
	if err := streamSink.Append(context.Background(), map[string]any{"line": "line before disable"}); err != nil {
		t.Fatalf("Stream.Append() before disable error = %v", err)
	}

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy", PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}

	assertHostStreamStatus(t, h, result.StreamID, stream.StatusOrphanedDisabled)
	if err := streamSink.Append(context.Background(), map[string]any{"line": "line after disable"}); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("Stream.Append() after disable error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
	if _, err := h.ReadStream(context.Background(), scopedReadStreamRequest(result.StreamID, result.StreamTicket)); !errors.Is(err, bridge.ErrTokenRevoked) {
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
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

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
		!strings.HasPrefix(payload.ParamsSHA256, "sha256:") ||
		payload.PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("worker payload mismatch: %#v", payload)
	}
	invocationHash, err := workerInvocationTargetHash(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !stringSliceContains(runtime.lastLease.TargetDescriptorHashes, invocationHash) {
		t.Fatalf("runtime lease does not bind worker invocation %s: %#v", invocationHash, runtime.lastLease.TargetDescriptorHashes)
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
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

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
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

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
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy", PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

	if _, err := h.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionFixturePackage(t), "core.view")

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
	if coreAdapter.last.Execution.TargetMethod != "example.open_settings" ||
		coreAdapter.last.Execution.RouteKind != capability.RouteCoreAction ||
		coreAdapter.last.Execution.Contract != nil ||
		coreAdapter.last.Execution.Permissions.Required == nil ||
		coreAdapter.last.Execution.Permissions.Granted == nil ||
		coreAdapter.last.Execution.Method != "core.open" ||
		coreAdapter.last.Execution.PluginInstanceID != installed.PluginInstanceID ||
		coreAdapter.last.Arguments["target"] != "settings" {
		t.Fatalf("core action invocation mismatch: %#v", coreAdapter.last)
	}
	if !audits.hasEvent("plugin.method.called") {
		t.Fatalf("missing method audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodCoreActionRequiresAdapter(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionFixturePackage(t), "core.view")

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

func TestDangerousWorkerAndCoreActionRoutesRequireConfirmation(t *testing.T) {
	t.Run("core action", func(t *testing.T) {
		adapter := &recordingCoreActionAdapter{result: capability.Result{Data: map[string]any{"opened": true}}}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, coreActions: adapter})
		installed, gateway := installEnableAndMintGateway(t, h, buildDangerousCoreActionFixturePackage(t), "core.view")
		call := CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
			GatewayToken: gateway.GatewayToken, Method: "core.open", Params: map[string]any{"target": "settings"},
		}
		assertDangerousRouteConfirmation(t, h, &call)
		if adapter.calls != 1 || !adapter.last.Execution.Confirmation.Confirmed {
			t.Fatalf("confirmed core action invocation = %#v calls=%d", adapter.last, adapter.calls)
		}
	})

	t.Run("worker", func(t *testing.T) {
		runtime := &recordingRuntimeSupervisor{
			health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
			result: capability.Result{Data: map[string]any{"from_worker": true}},
		}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeSupervisor: runtime})
		installed, gateway := installEnableAndMintGateway(t, h, buildDangerousWorkerFixturePackage(t), "worker.view")
		call := CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
			GatewayToken: gateway.GatewayToken, Method: "worker.echo", Params: map[string]any{"message": "hello"},
		}
		assertDangerousRouteConfirmation(t, h, &call)
		if runtime.calls != 1 {
			t.Fatalf("confirmed worker calls = %d", runtime.calls)
		}
	})
}

func assertDangerousRouteConfirmation(t *testing.T, h *Host, call *CallMethodRequest) {
	t.Helper()
	result, err := h.CallPluginMethod(context.Background(), *call)
	if !errors.Is(err, ErrConfirmationRequired) || !result.ConfirmationRequired {
		t.Fatalf("CallPluginMethod() result=%#v error=%v, want confirmation", result, err)
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(*call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(context.Background(), *call); err != nil {
		t.Fatalf("confirmed CallPluginMethod() error = %v", err)
	}
}

func TestCallPluginMethodOwnsExecutionHandles(t *testing.T) {
	cases := []struct {
		name          string
		packageBytes  []byte
		method        string
		wantOperation bool
		wantStream    bool
	}{
		{
			name:          "operation receives operation sink",
			packageBytes:  buildOperationRPCFixturePackage(t),
			method:        "documents.archive",
			wantOperation: true,
		},
		{
			name:         "sync receives no asynchronous sink",
			packageBytes: buildRPCFixturePackage(t),
			method:       "echo.ping",
		},
		{
			name:          "subscription receives operation and stream sinks",
			packageBytes:  buildSubscriptionRPCFixturePackage(t),
			method:        "logs.tail",
			wantOperation: true,
			wantStream:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode:     true,
				localGenerated:    true,
				capabilityID:      "example.capability.echo",
				capabilityAdapter: capabilityAdapter,
			})
			installed, gateway := installEnableAndMintGateway(t, h, tc.packageBytes, surfaceIDForMethod(tc.method))
			result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
				PluginInstanceID:     installed.PluginInstanceID,
				SurfaceInstanceID:    "surface_rpc",
				SessionChannelIDHash: "channel_hash",
				OwnerSessionHash:     "session_hash",
				OwnerUserHash:        "user_hash",
				BridgeChannelID:      "bridge_rpc",
				GatewayToken:         gateway.GatewayToken,
				Method:               tc.method,
			})
			if err != nil {
				t.Fatalf("CallPluginMethod() error = %v", err)
			}
			if got := capabilityAdapter.last.Execution.Operation != nil; got != tc.wantOperation {
				t.Fatalf("operation sink present = %v, want %v", got, tc.wantOperation)
			}
			if got := capabilityAdapter.last.Execution.Stream != nil; got != tc.wantStream {
				t.Fatalf("stream sink present = %v, want %v", got, tc.wantStream)
			}
			if (result.OperationID != "") != tc.wantOperation || (result.StreamID != "") != tc.wantStream {
				t.Fatalf("host-owned handle result mismatch: %#v", result)
			}
		})
	}
}

func TestSubscriptionStreamCompletionCompletesOperation(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OperationID == "" || result.StreamID == "" {
		t.Fatalf("subscription handles = %#v", result)
	}
	if err := adapter.last.Execution.Stream.Close(context.Background()); err != nil {
		t.Fatalf("Stream.Close() error = %v", err)
	}
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusCompleted)
	assertHostStreamStatus(t, h, result.StreamID, stream.StatusClosed)
}

func TestSubscriptionStreamRegistrationFailureRollsBackOperationAndLease(t *testing.T) {
	operations := operation.NewMemoryStore()
	streams := &failingStreamRegisterStore{
		Store: stream.NewMemoryStore(),
		err:   errors.New("stream registry unavailable"),
	}
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
		operations: operations, streams: streams,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	}); err == nil {
		t.Fatal("CallPluginMethod() succeeded after stream registration failed")
	}
	records, err := operations.List(context.Background(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != operation.StatusFailed {
		t.Fatalf("operation rollback mismatch: %#v", records)
	}
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("active execution leases = %d, want 0", activeLeases)
	}
}

func TestSubscriptionSetupRetainsLeaseUntilFailedOperationRollbackConverges(t *testing.T) {
	rollbackErr := errors.New("operation rollback unavailable")
	operations := &failFirstOperationFinishStore{Store: operation.NewMemoryStore(), err: rollbackErr}
	streams := &failingStreamRegisterStore{Store: stream.NewMemoryStore(), err: errors.New("stream registry unavailable")}
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
		operations: operations, streams: streams,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	}); !errors.Is(err, rollbackErr) {
		t.Fatalf("CallPluginMethod() error = %v, want rollback failure", err)
	}
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 1 {
		t.Fatalf("active execution leases = %d, want 1 until rollback repair", activeLeases)
	}
	if err := h.reconcileFailedExecutionSetups(context.Background()); err != nil {
		t.Fatalf("reconcileFailedExecutionSetups() error = %v", err)
	}
	records, err := operations.List(context.Background(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != operation.StatusFailed {
		t.Fatalf("reconciled operation state = %#v", records)
	}
	h.executions.mu.Lock()
	activeLeases = len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("active execution leases after repair = %d, want 0", activeLeases)
	}
}

func TestHostStartupReconcilesDurablePartialOperationAndStreamStates(t *testing.T) {
	for _, tc := range []struct {
		name            string
		operationStatus operation.Status
		streamStatus    stream.Status
		wantOperation   operation.Status
		wantStream      stream.Status
	}{
		{name: "operation terminal", operationStatus: operation.StatusFailed, streamStatus: stream.StatusOpen, wantOperation: operation.StatusFailed, wantStream: stream.StatusFailed},
		{name: "stream terminal", operationStatus: operation.StatusRunning, streamStatus: stream.StatusFailed, wantOperation: operation.StatusFailed, wantStream: stream.StatusFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			operationPath := filepath.Join(t.TempDir(), "operations.sqlite")
			streamPath := filepath.Join(t.TempDir(), "streams.sqlite")
			operations, err := operation.NewSQLiteStore(ctx, operationPath)
			if err != nil {
				t.Fatal(err)
			}
			streams, err := stream.NewSQLiteStore(ctx, streamPath)
			if err != nil {
				t.Fatal(err)
			}
			binding := capability.ExecutionBinding{
				InvocationID: "invoke_reconcile", AuditCorrelationID: "audit_reconcile",
				OperationID: "operation_reconcile", StreamID: "stream_reconcile",
				PluginID: "com.example.reconcile", PluginInstanceID: "plugini_reconcile",
				Method: "logs.tail", Execution: "subscription",
			}
			if _, err := operations.Register(ctx, operation.RegisterRequest{OperationID: binding.OperationID, ExecutionBinding: binding}); err != nil {
				t.Fatal(err)
			}
			if _, err := streams.Register(ctx, stream.RegisterRequest{StreamID: binding.StreamID, ExecutionBinding: binding}); err != nil {
				t.Fatal(err)
			}
			if tc.operationStatus != operation.StatusRunning {
				if _, err := operations.Finish(ctx, operation.FinishRequest{OperationID: binding.OperationID, Status: tc.operationStatus, Reason: "setup failed"}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.streamStatus != stream.StatusOpen {
				if _, err := streams.Close(ctx, stream.CloseRequest{StreamID: binding.StreamID, Status: tc.streamStatus, Reason: "setup failed"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := operations.Close(); err != nil {
				t.Fatal(err)
			}
			if err := streams.CloseDatabase(); err != nil {
				t.Fatal(err)
			}
			operations, err = operation.NewSQLiteStore(ctx, operationPath)
			if err != nil {
				t.Fatal(err)
			}
			defer operations.Close()
			streams, err = stream.NewSQLiteStore(ctx, streamPath)
			if err != nil {
				t.Fatal(err)
			}
			reopenedStreams := streams
			t.Cleanup(func() {
				if err := reopenedStreams.CloseDatabase(); err != nil {
					t.Errorf("close reopened stream store: %v", err)
				}
			})
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, operations: operations, streams: streams})
			assertHostOperationStatus(t, h, binding.OperationID, tc.wantOperation)
			assertHostStreamStatus(t, h, binding.StreamID, tc.wantStream)
			streamRecord, err := streams.Get(ctx, binding.StreamID)
			if err != nil {
				t.Fatal(err)
			}
			if streamRecord.Reason != "setup failed" {
				t.Fatalf("reconciled stream reason = %q", streamRecord.Reason)
			}
		})
	}
}

func TestHostStartupTerminatesDurableOperationsWithoutLiveOwners(t *testing.T) {
	for _, tc := range []struct {
		name          string
		requestCancel bool
		want          operation.Status
	}{
		{name: "running", want: operation.StatusFailed},
		{name: "cancel requested", requestCancel: true, want: operation.StatusCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			operationPath := filepath.Join(t.TempDir(), "operations.sqlite")
			operations, err := operation.NewSQLiteStore(ctx, operationPath)
			if err != nil {
				t.Fatal(err)
			}
			cancelable := true
			binding := capability.ExecutionBinding{
				InvocationID: "invoke_restart", AuditCorrelationID: "audit_restart", OperationID: "operation_restart",
				PluginID: "com.example.restart", PluginInstanceID: "plugini_restart", Method: "documents.archive", Execution: "operation",
			}
			if _, err := operations.Register(ctx, operation.RegisterRequest{OperationID: binding.OperationID, ExecutionBinding: binding, Cancelable: &cancelable}); err != nil {
				t.Fatal(err)
			}
			if tc.requestCancel {
				if _, err := operations.RequestCancel(ctx, operation.CancelRequest{OperationID: binding.OperationID, Reason: "user"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := operations.Close(); err != nil {
				t.Fatal(err)
			}
			operations, err = operation.NewSQLiteStore(ctx, operationPath)
			if err != nil {
				t.Fatal(err)
			}
			defer operations.Close()
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, operations: operations})
			assertHostOperationStatus(t, h, binding.OperationID, tc.want)
		})
	}
}

func TestDurableReconciliationRejectsConflictingTerminalPairs(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	binding := capability.ExecutionBinding{
		InvocationID: "invoke_conflict", AuditCorrelationID: "audit_conflict", OperationID: "operation_conflict", StreamID: "stream_conflict",
		PluginID: "com.example.conflict", PluginInstanceID: "plugini_conflict", Method: "logs.tail", Execution: "subscription",
	}
	if _, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{OperationID: binding.OperationID, ExecutionBinding: binding}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Streams.Register(context.Background(), stream.RegisterRequest{StreamID: binding.StreamID, ExecutionBinding: binding}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Finish(context.Background(), operation.FinishRequest{OperationID: binding.OperationID, Status: operation.StatusCompleted}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Streams.Close(context.Background(), stream.CloseRequest{StreamID: binding.StreamID, Status: stream.StatusFailed, Reason: "failed"}); err != nil {
		t.Fatal(err)
	}
	if err := h.reconcileDurableExecutionStates(context.Background()); !errors.Is(err, errExecutionTerminalConflict) {
		t.Fatalf("reconcileDurableExecutionStates() error = %v, want terminal conflict", err)
	}
	assertHostOperationStatus(t, h, binding.OperationID, operation.StatusCompleted)
	assertHostStreamStatus(t, h, binding.StreamID, stream.StatusFailed)
}

func TestSubscriptionTerminalWriteFailureRetainsLeaseUntilRetryConverges(t *testing.T) {
	finishErr := errors.New("operation terminal store unavailable")
	operations := &failFirstOperationFinishStore{Store: operation.NewMemoryStore(), err: finishErr}
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
		operations: operations,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.last.Execution.Stream.Close(context.Background()); !errors.Is(err, finishErr) {
		t.Fatalf("Stream.Close() error = %v, want %v", err, finishErr)
	}
	assertHostStreamStatus(t, h, result.StreamID, stream.StatusClosed)
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusRunning)
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 1 {
		t.Fatalf("active execution leases after partial terminal write = %d, want 1", activeLeases)
	}
	if err := adapter.last.Execution.Stream.Close(context.Background()); err != nil {
		t.Fatalf("Stream.Close() retry error = %v", err)
	}
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusCompleted)
	h.executions.mu.Lock()
	activeLeases = len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("active execution leases after terminal retry = %d, want 0", activeLeases)
	}
}

func TestSubscriptionLatchesOneTerminalIntentAcrossConcurrentCallers(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-start
		errs <- adapter.last.Execution.Stream.Close(context.Background())
	}()
	go func() {
		<-start
		errs <- adapter.last.Execution.Stream.Fail(context.Background(), "adapter failed")
	}()
	close(start)
	firstErr, secondErr := <-errs, <-errs
	conflicts := 0
	for _, terminalErr := range []error{firstErr, secondErr} {
		if errors.Is(terminalErr, errExecutionTerminalConflict) {
			conflicts++
		} else if terminalErr != nil {
			t.Fatalf("unexpected terminal error: %v", terminalErr)
		}
	}
	if conflicts != 1 {
		t.Fatalf("terminal conflict count = %d, errors = [%v, %v]", conflicts, firstErr, secondErr)
	}
	operationRecord, err := h.adapters.Operations.Get(context.Background(), result.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	streamRecord, err := h.adapters.Streams.Get(context.Background(), result.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	wantOperation, ok := operationStatusForStreamStatus(streamRecord.Status)
	if !ok || operationRecord.Status != wantOperation {
		t.Fatalf("terminal records diverged: operation=%#v stream=%#v", operationRecord, streamRecord)
	}
}

func TestRuntimeStreamCompletionReleasesExecutionLease(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := (hostRuntimeStreamSink{executions: h.executions}).CloseRuntimeStream(context.Background(), result.StreamID); err != nil {
		t.Fatalf("CloseRuntimeStream() error = %v", err)
	}
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusCompleted)
	assertHostStreamStatus(t, h, result.StreamID, stream.StatusClosed)
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("active execution leases = %d, want 0", activeLeases)
	}
}

func TestStreamAppendFailureReleasesReservedQuota(t *testing.T) {
	streams := &failFirstStreamAppendStore{Store: stream.NewMemoryStore(), err: errors.New("stream write unavailable")}
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
		streams: streams,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	}); err != nil {
		t.Fatal(err)
	}
	sink := adapter.last.Execution.Stream.(*hostStreamSink)
	sink.maxBytes = 20
	if err := sink.Append(context.Background(), map[string]any{"line": "a"}); !errors.Is(err, streams.err) {
		t.Fatalf("first Append() error = %v, want %v", err, streams.err)
	}
	if err := sink.Append(context.Background(), map[string]any{"line": "abc"}); err != nil {
		t.Fatalf("second Append() error = %v", err)
	}
}

func TestCancelOperationRequestsCancel(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}

	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	canceled, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user", Now: now})
	if err != nil {
		t.Fatalf("CancelOperation() error = %v", err)
	}
	if canceled.Status != operation.StatusCancelRequested || canceled.Reason != "user" {
		t.Fatalf("cancel operation mismatch: %#v", canceled)
	}
	if capabilityAdapter.cancelCalls != 1 {
		t.Fatalf("operation canceler calls = %d, want 1", capabilityAdapter.cancelCalls)
	}
	if capabilityAdapter.lastCancellation.OperationID != started.OperationID ||
		capabilityAdapter.lastCancellation.Execution.PluginInstanceID != installed.PluginInstanceID ||
		capabilityAdapter.lastCancellation.Execution.Method != "documents.archive" ||
		capabilityAdapter.lastCancellation.Execution.SurfaceInstanceID != "surface_rpc" ||
		capabilityAdapter.lastCancellation.Execution.SessionChannelIDHash != "channel_hash" ||
		capabilityAdapter.lastCancellation.Execution.BridgeChannelID != "bridge_rpc" ||
		capabilityAdapter.lastCancellation.Reason != "user" ||
		!capabilityAdapter.lastCancellation.RequestedAt.Equal(now) {
		t.Fatalf("operation canceler request mismatch: %#v", capabilityAdapter.lastCancellation)
	}
	if !audits.hasEvent("plugin.operation.cancel_requested") {
		t.Fatalf("missing cancel audit event: %#v", audits.events)
	}
}

func TestCancelOperationCanBeAcknowledgedThroughHostOwnedSink(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if _, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
		t.Fatalf("CancelOperation() error = %v", err)
	}
	select {
	case <-capabilityAdapter.invokeContext.Done():
	case <-time.After(time.Second):
		t.Fatal("capability adapter context was not canceled")
	}
	select {
	case <-capabilityAdapter.last.Execution.Operation.CancelRequested():
	case <-time.After(time.Second):
		t.Fatal("operation sink did not publish the cancel request")
	}
	if err := capabilityAdapter.last.Execution.Operation.Cancel(context.Background(), "adapter acknowledged cancellation"); err != nil {
		t.Fatalf("Operation.Cancel() error = %v", err)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusCanceled)
	if err := capabilityAdapter.last.Execution.Operation.Cancel(context.Background(), "duplicate"); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("duplicate Operation.Cancel() error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
}

func TestCancelOperationAckTimeoutForcesTerminalState(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		record, err := h.GetOperation(context.Background(), started.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if record.Status == operation.StatusCanceled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation remained %s after ack timeout", record.Status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCancelOperationAckTimeoutRetriesTerminalStoreFailure(t *testing.T) {
	finishErr := errors.New("operation terminal store unavailable")
	operations := &failFirstOperationFinishStore{Store: operation.NewMemoryStore(), err: finishErr}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
		operations: operations,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	waitForHostOperationStatus(t, h, started.OperationID, operation.StatusCanceled)
	if !operations.failedOne {
		t.Fatal("ack timeout did not exercise the terminal store failure")
	}
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("ack timeout retained %d execution leases after terminal retry", activeLeases)
	}
}

func TestDetachedCancelAckTimeoutRetriesTerminalStoreFailure(t *testing.T) {
	finishErr := errors.New("operation terminal store unavailable")
	operations := &failFirstOperationFinishStore{Store: operation.NewMemoryStore(), err: finishErr}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, operations: operations})
	cancelable := true
	operationID := "operation_detached_12345678"
	_, err := operations.Register(context.Background(), operation.RegisterRequest{
		OperationID: operationID,
		ExecutionBinding: capability.ExecutionBinding{
			InvocationID: "invoke_detached_12345678", OperationID: operationID,
			PluginID: "com.example.detached", PluginInstanceID: "plugini_detached_12345678", Method: "tasks.run",
		},
		Cancelable: &cancelable, CancelAckTimeoutMS: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: operationID, Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	waitForHostOperationStatus(t, h, operationID, operation.StatusCanceled)
	if !operations.failedOne {
		t.Fatal("detached ack timeout did not exercise the terminal store failure")
	}
}

func TestCancelOperationRejectsNonCancelableMethod(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
	for index := range contract.Methods {
		if contract.Methods[index].Name == "documents.archive" {
			cancelPolicy := *contract.Methods[index].CancelPolicy
			cancelPolicy.Cancelable = false
			cancelPolicy.AckTimeoutMS = 0
			contract.Methods[index].CancelPolicy = &cancelPolicy
		}
	}
	verified := verifyFixtureCapabilityContract(t, contract)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityContract: &verified, capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t,
		operationRPCFixtureManifestJSON(),
		"Operation",
		"echo",
		verified.Pin,
	), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: started.OperationID}); !errors.Is(err, operation.ErrNotCancelable) {
		t.Fatalf("CancelOperation() error = %v, want %v", err, operation.ErrNotCancelable)
	}
	if capabilityAdapter.cancelCalls != 0 {
		t.Fatalf("non-cancelable adapter cancel calls = %d, want 0", capabilityAdapter.cancelCalls)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusRunning)
	if err := capabilityAdapter.last.Execution.Operation.Complete(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCancelSurfaceOperationRejectsScopeMismatch(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := CancelSurfaceOperationRequest{
		OperationID: started.OperationID, SurfaceInstanceID: "surface_rpc", OwnerSessionHash: "session_hash",
		OwnerUserHash: "user_hash", SessionChannelIDHash: "channel_hash", BridgeChannelID: "bridge_rpc", Reason: "user",
	}
	tests := []struct {
		name   string
		mutate func(*CancelSurfaceOperationRequest)
	}{
		{name: "surface", mutate: func(req *CancelSurfaceOperationRequest) { req.SurfaceInstanceID = "surface_other" }},
		{name: "owner session", mutate: func(req *CancelSurfaceOperationRequest) { req.OwnerSessionHash = "session_other" }},
		{name: "owner user", mutate: func(req *CancelSurfaceOperationRequest) { req.OwnerUserHash = "user_other" }},
		{name: "session channel", mutate: func(req *CancelSurfaceOperationRequest) { req.SessionChannelIDHash = "channel_other" }},
		{name: "bridge channel", mutate: func(req *CancelSurfaceOperationRequest) { req.BridgeChannelID = "bridge_other" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			if _, err := h.CancelSurfaceOperation(context.Background(), req); !errors.Is(err, bridge.ErrTokenAudience) {
				t.Fatalf("CancelSurfaceOperation() error = %v, want %v", err, bridge.ErrTokenAudience)
			}
		})
	}
	if capabilityAdapter.cancelCalls != 0 {
		t.Fatalf("mismatched surface cancellation reached adapter %d times", capabilityAdapter.cancelCalls)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusRunning)
	if _, err := h.CancelSurfaceOperation(context.Background(), base); err != nil {
		t.Fatalf("CancelSurfaceOperation() valid scope error = %v", err)
	}
	if capabilityAdapter.cancelCalls != 1 {
		t.Fatalf("valid surface cancellation reached adapter %d times, want 1", capabilityAdapter.cancelCalls)
	}
}

func TestAsyncExecutionOutlivesSuccessfulRequestContext(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	requestContext, cancelRequest := context.WithCancel(context.Background())
	started, err := h.CallPluginMethod(requestContext, CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	cancelRequest()
	if err := capabilityAdapter.last.Execution.Operation.Complete(context.Background()); err != nil {
		t.Fatalf("Operation.Complete() after request cancellation error = %v", err)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusCompleted)
}

func TestDisableCancelsHostOwnedOperationWithoutRewritingItAsFailed(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if _, err := h.DisablePlugin(context.Background(), DisableRequest{
		PluginInstanceID:   installed.PluginInstanceID,
		PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID),
		Reason:             "disabled by owner",
	}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusCanceled)
	if err := capabilityAdapter.last.Execution.Operation.Cancel(context.Background(), "late adapter acknowledgement"); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("Operation.Cancel() after revoke error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
}

func TestCancelOperationUsesRouteLocalExecutionRegistration(t *testing.T) {
	t.Run("core action", func(t *testing.T) {
		coreAdapter := &recordingCoreActionAdapter{result: capability.Result{Data: map[string]any{"opened": true}}}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, coreActions: coreAdapter})
		installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionOperationFixturePackage(t), "core.view")
		started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
			Method: "core.open", Params: map[string]any{"target": "settings"},
		})
		if err != nil {
			t.Fatalf("CallPluginMethod() error = %v", err)
		}
		coreRecord, err := h.GetOperation(context.Background(), started.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if coreRecord.RouteKind != capability.RouteCoreAction || coreRecord.Contract != nil || coreRecord.Permissions.Required == nil || coreRecord.Permissions.Granted == nil {
			t.Fatalf("core action execution binding mismatch: %#v", coreRecord.ExecutionBinding)
		}
		if _, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
			t.Fatalf("CancelOperation() error = %v", err)
		}
		if coreAdapter.cancelCalls != 1 || coreAdapter.lastCancellation.OperationID != started.OperationID {
			t.Fatalf("core action cancellation mismatch: calls=%d request=%#v", coreAdapter.cancelCalls, coreAdapter.lastCancellation)
		}
		if err := coreAdapter.last.Execution.Operation.Cancel(context.Background(), "acknowledged"); err != nil {
			t.Fatalf("Operation.Cancel() error = %v", err)
		}
	})

	t.Run("worker", func(t *testing.T) {
		runtime := &recordingRuntimeSupervisor{
			health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
			result: capability.Result{Data: map[string]any{"from_worker": true}},
		}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeSupervisor: runtime})
		installed, gateway := installEnableAndMintGateway(t, h, buildWorkerOperationFixturePackage(t), "worker.view")
		started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
			Method: "worker.echo", Params: map[string]any{"message": "hello"},
		})
		if err != nil {
			t.Fatalf("CallPluginMethod() error = %v", err)
		}
		workerRecord, err := h.GetOperation(context.Background(), started.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if workerRecord.RouteKind != capability.RouteWorker || workerRecord.Contract != nil || workerRecord.Permissions.Required == nil || workerRecord.Permissions.Granted == nil {
			t.Fatalf("worker execution binding mismatch: %#v", workerRecord.ExecutionBinding)
		}
		if _, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
			t.Fatalf("CancelOperation() error = %v", err)
		}
		select {
		case <-runtime.invokeContext.Done():
		case <-time.After(time.Second):
			t.Fatal("worker execution context was not canceled")
		}
	})
}

func TestOperationFailurePathsCloseHostOwnedHandle(t *testing.T) {
	cases := []struct {
		name    string
		adapter *recordingCapabilityAdapter
	}{
		{name: "adapter error", adapter: &recordingCapabilityAdapter{err: errors.New("adapter failed")}},
		{name: "response schema failure", adapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"unexpected": true}}}},
		{name: "adapter panic", adapter: &recordingCapabilityAdapter{panicValue: "adapter panic"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: tc.adapter,
			})
			installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
			if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
				PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
				OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
				Method: "documents.archive",
			}); err == nil {
				t.Fatal("CallPluginMethod() expected failure")
			}
			if tc.adapter.last.Execution.Operation == nil {
				t.Fatal("adapter did not receive a Host-owned operation sink")
			}
			assertHostOperationStatus(t, h, tc.adapter.last.Execution.Operation.ID(), operation.StatusFailed)
			if err := tc.adapter.last.Execution.Operation.Complete(context.Background()); !errors.Is(err, capability.ErrExecutionRevoked) {
				t.Fatalf("Operation.Complete() after failure error = %v, want %v", err, capability.ErrExecutionRevoked)
			}
		})
	}
}

func TestCallPluginMethodRecordsNegativeAuditAndDiagnostic(t *testing.T) {
	cases := []struct {
		name       string
		adapter    *recordingCapabilityAdapter
		params     map[string]any
		wantReason string
	}{
		{name: "request schema", adapter: &recordingCapabilityAdapter{}, params: map[string]any{"unexpected": true}, wantReason: "request_contract"},
		{name: "adapter panic", adapter: &recordingCapabilityAdapter{panicValue: "panic"}, wantReason: "adapter_panic"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diagnostics := &diagnosticSink{}
			h, _, audits := newTestHostWithOptions(t, testHostOptions{
				developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: tc.adapter, diagnostics: diagnostics,
			})
			installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
			if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
				PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
				OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
				Method: "echo.ping", Params: tc.params,
			}); err == nil {
				t.Fatal("CallPluginMethod() expected rejection")
			}
			event, ok := audits.lastEvent("plugin.method.rejected")
			if !ok || event.Details["reason"] != tc.wantReason || event.Details["method"] != "echo.ping" {
				t.Fatalf("negative audit mismatch: %#v", audits.events)
			}
			if len(diagnostics.events) != 1 || diagnostics.events[0].Type != "plugin.method.rejected" || diagnostics.events[0].Details["reason"] != tc.wantReason {
				t.Fatalf("negative diagnostic mismatch: %#v", diagnostics.events)
			}
			if tc.wantReason == "request_contract" && tc.adapter.calls != 0 {
				t.Fatalf("adapter invoked after request schema rejection: %d", tc.adapter.calls)
			}
		})
	}
}

func TestCallPluginMethodValidatesPublishedBusinessErrors(t *testing.T) {
	newHost := func(t *testing.T, adapter *recordingCapabilityAdapter) (*Host, registry.PluginRecord, bridge.GatewayTokenResult, *auditSink) {
		t.Helper()
		contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
		contract.Errors = []capabilitycontract.BusinessError{{
			Code:    "DOCUMENT_NOT_FOUND",
			Message: "Document not found",
			DetailsSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []any{"document_id"},
				"properties": map[string]any{
					"document_id": map[string]any{"type": "string", "minLength": 1},
				},
			},
		}}
		verified := verifyFixtureCapabilityContract(t, contract)
		h, _, audits := newTestHostWithOptions(t, testHostOptions{
			developerMode: true, localGenerated: true, capabilityContract: &verified, capabilityAdapter: adapter,
		})
		installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
			t,
			rpcFixtureManifestJSON("1.0.0", "RPC"),
			"RPC",
			"echo",
			verified.Pin,
		), "rpc.view")
		return h, installed, gateway, audits
	}
	call := func(h *Host, installed registry.PluginRecord, gateway bridge.GatewayTokenResult) error {
		_, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
			Method: "echo.ping",
		})
		return err
	}

	t.Run("declared error", func(t *testing.T) {
		adapter := &recordingCapabilityAdapter{err: capability.NewBusinessError("DOCUMENT_NOT_FOUND", "adapter detail", map[string]any{"document_id": "doc-1"})}
		h, installed, gateway, audits := newHost(t, adapter)
		err := call(h, installed, gateway)
		var businessError *capability.BusinessError
		if !errors.As(err, &businessError) || businessError.Code != "DOCUMENT_NOT_FOUND" || businessError.Message != "Document not found" ||
			businessError.CapabilityID != "example.capability.echo" || businessError.CapabilityVersion != "1.0.0" ||
			len(businessError.DetailSchemaSHA256) != 64 || businessError.Details["document_id"] != "doc-1" {
			t.Fatalf("business error mismatch: %#v, err=%v", businessError, err)
		}
		if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "business_error" {
			t.Fatalf("missing business error audit: %#v", audits.events)
		}
	})

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "undeclared code", err: capability.NewBusinessError("UNKNOWN", "unknown", nil)},
		{name: "invalid details", err: capability.NewBusinessError("DOCUMENT_NOT_FOUND", "invalid", map[string]any{"unexpected": true})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &recordingCapabilityAdapter{err: tc.err}
			h, installed, gateway, audits := newHost(t, adapter)
			if err := call(h, installed, gateway); !errors.Is(err, ErrMethodResponseContract) {
				t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
			}
			if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "response_contract" {
				t.Fatalf("missing response-contract audit: %#v", audits.events)
			}
		})
	}
}

func TestCancelOperationReturnsDispatchFailureButKeepsCancelRequested(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}, cancellationError: errors.New("runtime unavailable")}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID:     installed.PluginInstanceID,
		SurfaceInstanceID:    "surface_rpc",
		SessionChannelIDHash: "channel_hash",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		BridgeChannelID:      "bridge_rpc",
		GatewayToken:         gateway.GatewayToken,
		Method:               "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}

	canceled, err := h.CancelOperation(context.Background(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"})
	if !errors.Is(err, ErrOperationCancelDispatchFailed) {
		t.Fatalf("CancelOperation() error = %v, want %v", err, ErrOperationCancelDispatchFailed)
	}
	if canceled.Status != operation.StatusCancelRequested {
		t.Fatalf("returned operation status = %s, want %s: %#v", canceled.Status, operation.StatusCancelRequested, canceled)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusCancelRequested)
	if capabilityAdapter.cancelCalls != 1 {
		t.Fatalf("operation canceler calls = %d, want 1", capabilityAdapter.cancelCalls)
	}
	if !audits.hasEvent("plugin.operation.cancel_requested") {
		t.Fatalf("missing cancel audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodRejectsInvalidGatewayToken(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "unreachable"}}
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		diagnostics:       diagnostics,
	})
	installed, _ := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")

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
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "token_invalid" {
		t.Fatalf("missing token rejection audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details["reason"] != "token_invalid" {
		t.Fatalf("missing token rejection diagnostic: %#v", diagnostics.events)
	}
}

func TestCallPluginMethodAuditsRemoteSessionMismatch(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "unreachable"}}
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo",
		capabilityAdapter: capabilityAdapter, diagnostics: diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_other",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "echo.ping",
	}); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("CallPluginMethod() error = %v, want %v", err, bridge.ErrTokenAudience)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "remote_mismatch" {
		t.Fatalf("missing remote mismatch audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details["reason"] != "remote_mismatch" {
		t.Fatalf("missing remote mismatch diagnostic: %#v", diagnostics.events)
	}
}

func TestCallPluginMethodAuditsTrustUnavailable(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "unreachable"}}
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo",
		capabilityAdapter: capabilityAdapter, diagnostics: diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
	record, err := h.adapters.Registry.GetPlugin(context.Background(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	record.TrustState = registry.TrustUnavailable
	record.TrustAssessment.TrustState = registry.TrustUnavailable
	if _, err := h.adapters.Registry.PutPlugin(context.Background(), record, registry.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc",
		GatewayToken: gateway.GatewayToken, Method: "echo.ping",
	}); err == nil {
		t.Fatal("CallPluginMethod() accepted a trust-unavailable plugin")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "trust_unavailable" {
		t.Fatalf("missing trust-unavailable audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details["reason"] != "trust_unavailable" {
		t.Fatalf("missing trust-unavailable diagnostic: %#v", diagnostics.events)
	}
}

func TestCallPluginMethodHonorsLocalPolicyDeny(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: "unreachable"}}
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		policyDecision:    PolicyDeny,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		diagnostics:       diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")

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
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "policy_denied" {
		t.Fatalf("missing policy rejection audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details["reason"] != "policy_denied" {
		t.Fatalf("missing policy rejection diagnostic: %#v", diagnostics.events)
	}
}

func TestCallPluginMethodHonorsSecurityPolicyDeny(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, _ := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
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
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.view")
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
	_, gateway = openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.view")
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
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		diagnostics:       diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
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
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "confirmation_required" {
		t.Fatalf("missing confirmation rejection audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details["reason"] != "confirmation_required" {
		t.Fatalf("missing confirmation rejection diagnostic: %#v", diagnostics.events)
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

func TestRejectMethodConfirmationConsumesIntentWithoutDispatch(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
	diagnostics := &diagnosticSink{}
	confirmationIntents := security.NewMemoryConfirmationIntentStore()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:       true,
		localGenerated:      true,
		capabilityID:        "example.capability.echo",
		capabilityAdapter:   capabilityAdapter,
		confirmationIntents: confirmationIntents,
		diagnostics:         diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
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

	reject := RejectMethodConfirmationRequest{
		PluginInstanceID:     call.PluginInstanceID,
		SurfaceInstanceID:    call.SurfaceInstanceID,
		SessionChannelIDHash: call.SessionChannelIDHash,
		OwnerSessionHash:     call.OwnerSessionHash,
		OwnerUserHash:        call.OwnerUserHash,
		BridgeChannelID:      call.BridgeChannelID,
		GatewayToken:         call.GatewayToken,
		ConfirmationID:       confirmation.ConfirmationID,
	}
	mismatched := reject
	mismatched.BridgeChannelID = "bridge_other"
	if _, err := h.RejectMethodConfirmation(context.Background(), mismatched); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("RejectMethodConfirmation(scope mismatch) error = %v, want ErrTokenAudience", err)
	}
	if listed, err := confirmationIntents.ListConfirmationIntents(context.Background(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil || len(listed) != 1 {
		t.Fatalf("scope mismatch consumed confirmation: listed=%#v err=%v", listed, err)
	}

	result, err := h.RejectMethodConfirmation(context.Background(), reject)
	if err != nil {
		t.Fatalf("RejectMethodConfirmation() error = %v", err)
	}
	if !result.Rejected {
		t.Fatalf("rejection result mismatch: %#v", result)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("rejected confirmation dispatched adapter %d times", capabilityAdapter.calls)
	}
	if listed, err := confirmationIntents.ListConfirmationIntents(context.Background(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil || len(listed) != 0 {
		t.Fatalf("rejected confirmation remained pending: listed=%#v err=%v", listed, err)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "confirmation_rejected" {
		t.Fatalf("confirmation rejection audit mismatch: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details["reason"] != "confirmation_rejected" {
		t.Fatalf("confirmation rejection diagnostic mismatch: %#v", diagnostics.events)
	}

	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(context.Background(), call); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("CallPluginMethod(rejected confirmation) error = %v, want ErrConfirmationInvalid", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("rejected confirmation replay dispatched adapter %d times", capabilityAdapter.calls)
	}
}

func TestPrepareMethodConfirmationRunsRiskPreflightAndBindsPlanHash(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{Data: map[string]any{"started": true}},
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
	installed, gateway := installEnableAndMintGateway(t, h, buildMethodContractFixturePackage(t), "method_contract.view")
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
	if capabilityAdapter.calls != 1 || capabilityAdapter.last.Execution.TargetMethod != "tasks.start.preflight" || capabilityAdapter.last.Execution.Effect != capability.EffectRead {
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
	if capabilityAdapter.calls != 3 || capabilityAdapter.last.Execution.TargetMethod != "tasks.start" || confirmed.OperationID == "" {
		t.Fatalf("confirmed invocation mismatch: calls=%d last=%#v", capabilityAdapter.calls, capabilityAdapter.last)
	}
	if confirmed.Data == nil {
		t.Fatalf("confirmed result missing data: %#v", confirmed)
	}
}

func TestConfirmedCapabilityRerunsPreflightAndRejectsAStalePlan(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{Data: map[string]any{"started": true}},
		resultsByTarget: map[string]capability.Result{
			"tasks.start.preflight": {Data: map[string]any{"summary": "Start task", "risk_flags": []any{"executes_task"}}},
		},
	}
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.tasks", capabilityAdapter: capabilityAdapter,
		diagnostics: diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildMethodContractFixturePackage(t), "method_contract.view")
	call := CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "tasks.start", Params: map[string]any{"task_id": "task_1"},
	}
	confirmation, err := h.PrepareMethodConfirmation(context.Background(), ConfirmMethodRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	capabilityAdapter.resultsByTarget["tasks.start.preflight"] = capability.Result{Data: map[string]any{
		"summary": "Start task after policy change", "risk_flags": []any{"executes_task", "elevated_scope"},
	}}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(context.Background(), call); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrConfirmationInvalid", err)
	}
	if capabilityAdapter.last.Execution.TargetMethod != "tasks.start.preflight" {
		t.Fatalf("stale confirmation dispatched business method: %#v", capabilityAdapter.last)
	}
	event, ok := audits.lastEvent("plugin.method.rejected")
	if !ok || event.Details["reason"] != "confirmation_invalid" {
		t.Fatalf("stale confirmation audit mismatch: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details["reason"] != "confirmation_invalid" {
		t.Fatalf("stale confirmation diagnostic mismatch: %#v", diagnostics.events)
	}
}

func TestPrepareMethodConfirmationNormalizesTypedRiskPlanAndRedactsDetails(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{Data: map[string]any{"started": true}},
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
	installed, gateway := installEnableAndMintGateway(t, h, buildMethodContractFixturePackage(t), "method_contract.view")
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
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
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
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
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

func TestConfirmationIntentRejectsChangedResolvedTargetAndCannotReplay(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result:       capability.Result{Data: map[string]any{"result": "done"}},
		targetFields: map[string]any{"target": "db"},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
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
	capabilityAdapter.targetFields = map[string]any{"target": "other"}
	if _, err := h.CallPluginMethod(context.Background(), call); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrConfirmationInvalid", err)
	}
	capabilityAdapter.targetFields = map[string]any{"target": "db"}
	if _, err := h.CallPluginMethod(context.Background(), call); err == nil {
		t.Fatal("CallPluginMethod() accepted a consumed confirmation after target restoration")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestCapabilityExecutionEnforcesConcurrentAndDurationQuota(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
	for index := range contract.Methods {
		if contract.Methods[index].Name == "documents.archive" {
			contract.Methods[index].Quota = capabilitycontract.Quota{MaxConcurrent: 1, MaxDurationMS: 20}
		}
	}
	verified := verifyFixtureCapabilityContract(t, contract)
	if err := h.adapters.Capabilities.Register(capability.Registration{Contract: verified, TargetProjector: capabilityAdapter, Adapter: capabilityAdapter}); err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t,
		operationRPCFixtureManifestJSON(),
		"Operation",
		"echo",
		verified.Pin,
	), "operation.view")
	call := CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	}
	first, err := h.CallPluginMethod(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CallPluginMethod(context.Background(), call); !errors.Is(err, capability.ErrQuotaExceeded) {
		t.Fatalf("second CallPluginMethod() error = %v, want ErrQuotaExceeded", err)
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("adapter calls = %d, want 1", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "quota_exceeded" {
		t.Fatalf("missing quota rejection audit: %#v", audits.events)
	}
	time.Sleep(40 * time.Millisecond)
	assertHostOperationStatus(t, h, first.OperationID, operation.StatusFailed)
	if err := capabilityAdapter.last.Execution.Operation.Complete(context.Background()); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("Operation.Complete() after quota expiry error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
}

func TestCapabilityExecutionRejectsSuccessReturnedAfterDurationQuota(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result:      capability.Result{Data: map[string]any{"ok": true}},
		invokeDelay: 40 * time.Millisecond,
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
	for index := range contract.Methods {
		if contract.Methods[index].Name == "echo.ping" {
			contract.Methods[index].Quota.MaxDurationMS = 10
		}
	}
	verified := verifyFixtureCapabilityContract(t, contract)
	if err := h.adapters.Capabilities.Register(capability.Registration{Contract: verified, TargetProjector: capabilityAdapter, Adapter: capabilityAdapter}); err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(t, rpcFixtureManifestJSON("1.0.0", "RPC"), "RPC", "echo", verified.Pin), "rpc.view")
	_, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "echo.ping", Params: map[string]any{"message": "hello"},
	})
	if !errors.Is(err, capability.ErrQuotaExceeded) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrQuotaExceeded", err)
	}
}

func TestDisableRevokesSurfaceTokensConfirmationIntentsAndRuntime(t *testing.T) {
	runtime := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true},
	}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
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
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
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

	disabled, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy", PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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

	disabled, err := h.DisablePlugin(ctx, DisableRequest{PluginInstanceID: enabled.PluginInstanceID, Reason: "policy", PluginStateVersion: mustPluginStateVersion(t, h, enabled.PluginInstanceID)})
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
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if result.Data == nil || capabilityAdapter.calls != 1 || capabilityAdapter.last.Execution.Method != "echo.ping" {
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
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: first.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, first.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: second.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, second.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantDeclaredPermissions(t, h, first)
	grantDeclaredPermissions(t, h, second)

	if _, err := h.InvokeIntent(context.Background(), InvokeIntentRequest{IntentID: "example.echo"}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("InvokeIntent() ambiguity error = %v", err)
	}
}

func TestInvokeIntentFailsClosedForDangerousMethod(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
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
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
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
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
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
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
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

	if _, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, host, installed.PluginInstanceID)}); err != nil {
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
	enabled, err := host.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, host, installed.PluginInstanceID)})
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
	enabled, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test", PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); !errors.Is(err, connectivity.ErrTargetDenied) {
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
	if _, err := retainHost.EnablePlugin(ctx, EnableRequest{PluginInstanceID: retainedPlugin.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, retainHost, retainedPlugin.PluginInstanceID)}); err != nil {
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
	if _, err := retainHost.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: retainedPlugin.PluginInstanceID, DeleteData: false, PluginStateVersion: mustPluginStateVersion(t, retainHost, retainedPlugin.PluginInstanceID)}); err != nil {
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
	if _, err := deleteHost.EnablePlugin(ctx, EnableRequest{PluginInstanceID: deletedPlugin.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, deleteHost, deletedPlugin.PluginInstanceID)}); err != nil {
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
	if _, err := deleteHost.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: deletedPlugin.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, deleteHost, deletedPlugin.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: false, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: source.PluginInstanceID, DeleteData: false, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: target.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, target.PluginInstanceID)}); err != nil {
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

func TestCleanupExpiredRetainedDataDeletesPayload(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	broker := storage.NewMemoryBroker()
	retainedRegistry := retaineddata.NewMemoryStore()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		storageBroker:  broker,
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

	result, err := h.CleanupExpiredRetainedData(ctx, CleanupExpiredRetainedDataRequest{Now: now})
	if err != nil {
		t.Fatalf("CleanupExpiredRetainedData() error = %v", err)
	}
	if len(result.Deleted) != 1 || result.Deleted[0].RetainedID != successRecord.RetainedID || result.Deleted[0].State != retaineddata.StateDeleted {
		t.Fatalf("deleted cleanup result mismatch: %#v", result.Deleted)
	}
	if len(result.Failed) != 0 {
		t.Fatalf("unexpected failed cleanup result: %#v", result.Failed)
	}
	if namespaces, err := broker.ListNamespaces(ctx, successPluginID); err != nil {
		t.Fatal(err)
	} else if len(namespaces) != 0 {
		t.Fatalf("expired retained storage still present: %#v", namespaces)
	}
	if !audits.hasEvent("plugin.retained_data.deleted") {
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
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
	uninstalled, err := h.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)})
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
		StreamID: "stream_uninstall_1",
		ExecutionBinding: capability.ExecutionBinding{
			PluginID:             enabled.PluginID,
			PluginInstanceID:     enabled.PluginInstanceID,
			Method:               "network.watch",
			Execution:            string(manifest.MethodExecutionSubscription),
			SurfaceInstanceID:    "surface_network",
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			SessionChannelIDHash: "channel_hash",
			BridgeChannelID:      "bridge_network",
		},
	}); err != nil {
		t.Fatalf("Streams.Register() error = %v", err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: enabled.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, enabled.PluginInstanceID)}); err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}

	if len(surfaces.snapshots) != 2 || len(surfaces.snapshots[1].Surfaces) != 0 {
		t.Fatalf("uninstall did not clear surfaces: %#v", surfaces.snapshots)
	}
	assertHostStreamStatus(t, h, "stream_uninstall_1", stream.StatusOrphanedRemoved)
	if _, err := h.adapters.Streams.Append(ctx, stream.AppendRequest{
		StreamID: "stream_uninstall_1",
		Data:     []byte("line after uninstall"),
	}); !errors.Is(err, stream.ErrStreamClosed) {
		t.Fatalf("Streams.Append() after uninstall error = %v, want %v", err, stream.ErrStreamClosed)
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
		ExecutionBinding: testExecutionBinding(installed, "documents.archive", manifest.MethodExecutionOperation),
	})
	if err != nil {
		t.Fatal(err)
	}
	waitOp, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{
		OperationID:      "op_disable_wait",
		ExecutionBinding: testExecutionBinding(installed, "sync.wait", manifest.MethodExecutionOperation),
		DisableBehavior:  operation.DisableBehaviorWait,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.DisablePlugin(context.Background(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy", PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:      "op_blocks_delete",
		ExecutionBinding: testExecutionBinding(installed, "documents.archive", manifest.MethodExecutionOperation),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); !errors.Is(err, operation.ErrDeleteBlocked) {
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

func TestUninstallDeleteDataDispatchesCancellationToLiveAdapterBeforeBlocking(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(context.Background(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", SessionChannelIDHash: "channel_hash",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(context.Background(), UninstallRequest{
		PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID),
	}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() error = %v, want ErrDeleteBlocked", err)
	}
	if capabilityAdapter.cancelCalls != 1 || capabilityAdapter.lastCancellation.OperationID != started.OperationID {
		t.Fatalf("live adapter cancellation mismatch: calls=%d request=%#v", capabilityAdapter.cancelCalls, capabilityAdapter.lastCancellation)
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:      "op_cancel_then_delete",
		ExecutionBinding: testExecutionBinding(installed, "documents.archive", manifest.MethodExecutionOperation),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() first error = %v, want ErrDeleteBlocked", err)
	}
	if _, err := h.adapters.Operations.Finish(ctx, operation.FinishRequest{
		OperationID: "op_cancel_then_delete",
		Status:      operation.StatusCanceled,
		Reason:      "runtime ack",
	}); err != nil {
		t.Fatalf("Operations.Finish() error = %v", err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:       "op_force_cleanup",
		ExecutionBinding:  testExecutionBinding(installed, "cleanup.force", manifest.MethodExecutionOperation),
		UninstallBehavior: operation.UninstallBehaviorForceCleanupAllowed,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: source.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, source.PluginInstanceID)}); err != nil {
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
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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
	if _, err := h.UninstallPlugin(context.Background(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err == nil || !strings.Contains(err.Error(), "secret store does not support plugin cleanup") {
		t.Fatalf("UninstallPlugin(delete data) error = %v, want secret cleanup support error", err)
	}
	if _, err := h.adapters.Settings.Get(context.Background(), settings.GetRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("settings should not be deleted when secret cleanup preflight fails: %v", err)
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
	if _, err := h.EnablePlugin(context.Background(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
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

	if err := h.adapters.Diagnostics.AppendPluginDiagnostic(context.Background(), DiagnosticEvent{
		Type:              "plugin.surface.renderer_error",
		Severity:          "warning",
		Message:           "renderer rejected plugin output",
		PluginID:          installed.PluginID,
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_default_observability",
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
	if len(diagnosticEvents) != 1 || diagnosticEvents[0].Type != "plugin.surface.renderer_error" || diagnosticEvents[0].Message != "renderer rejected plugin output" {
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
	installStages           installstage.Store
	permissions             permissions.Store
	securityPolicy          security.PolicyStore
	confirmationIntents     security.ConfirmationIntentStore
	operations              operation.Store
	streams                 stream.Store
	runtimeSupervisor       runtimeclient.Supervisor
	runtimeArtifactResolver RuntimeArtifactResolver
	secrets                 SecretStoreAdapter
	diagnostics             DiagnosticsSink
	hostRequirements        HostRequirementPolicy
	capabilities            *capability.Registry
	capabilityID            string
	capabilityContract      *capabilitycontract.VerifiedContract
	capabilityAdapter       interface {
		capability.Adapter
		capability.TargetProjector
	}
	coreActions   CoreActionAdapter
	surfaceTokens *bridge.SurfaceTokenService
}

type fixedHostRequirementPolicy struct {
	hostID string
	err    error
	calls  int
	last   HostRequirementSelectionRequest
}

func (p *fixedHostRequirementPolicy) SelectHostRequirement(_ context.Context, req HostRequirementSelectionRequest) (HostRequirementSelection, error) {
	p.calls++
	p.last = req
	if p.err != nil {
		return HostRequirementSelection{}, p.err
	}
	return HostRequirementSelection{HostID: p.hostID}, nil
}

func newTestHostWithOptions(t *testing.T, opts testHostOptions) (*Host, *surfaceSink, *auditSink) {
	t.Helper()
	surfaces := &surfaceSink{}
	audits := &auditSink{}
	capabilities := opts.capabilities
	if capabilities == nil {
		capabilities = capability.NewRegistry()
	}
	if opts.capabilityContract != nil {
		if opts.capabilityAdapter == nil {
			t.Fatal("custom capability contract requires an adapter")
		}
		if err := capabilities.Register(capability.Registration{Contract: *opts.capabilityContract, TargetProjector: opts.capabilityAdapter, Adapter: opts.capabilityAdapter}); err != nil {
			t.Fatal(err)
		}
	} else if opts.capabilityID != "" && opts.capabilityAdapter != nil {
		verified := fixtureVerifiedCapabilityContract(t, opts.capabilityID)
		if err := capabilities.Register(capability.Registration{Contract: verified, TargetProjector: opts.capabilityAdapter, Adapter: opts.capabilityAdapter}); err != nil {
			t.Fatal(err)
		}
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
		HostRequirements:        opts.hostRequirements,
		SurfaceCatalog:          surfaces,
		Audit:                   audits,
		Diagnostics:             opts.diagnostics,
		Storage:                 opts.storageBroker,
		Connectivity:            opts.connectivityBroker,
		NetworkExecutor:         opts.networkExecutor,
		Cleanup:                 opts.cleanup,
		RetainedData:            opts.retainedData,
		InstallStages:           opts.installStages,
		Permissions:             opts.permissions,
		SecurityPolicy:          opts.securityPolicy,
		ConfirmationIntents:     opts.confirmationIntents,
		Operations:              opts.operations,
		Streams:                 opts.streams,
		RuntimeSupervisor:       opts.runtimeSupervisor,
		RuntimeArtifactResolver: opts.runtimeArtifactResolver,
		Secrets:                 opts.secrets,
		Capabilities:            capabilities,
		CoreActions:             opts.coreActions,
		SurfaceTokens:           opts.surfaceTokens,
	})
	if err != nil {
		t.Fatal(err)
	}
	return host, surfaces, audits
}

func fixtureVerifiedCapabilityContract(t *testing.T, capabilityID string) capabilitycontract.VerifiedContract {
	t.Helper()
	contract, err := fixtureCapabilityContract(capabilityID)
	if err != nil {
		t.Fatal(err)
	}
	return verifyFixtureCapabilityContract(t, contract)
}

func fixtureCapabilityContract(capabilityID string) (capabilitycontract.Contract, error) {
	empty := fixtureClosedObject(nil, nil)
	stringField := func(required bool, name string) (map[string]any, []string) {
		requiredFields := []string(nil)
		if required {
			requiredFields = []string{name}
		}
		return fixtureClosedObject(map[string]any{name: map[string]any{"type": "string"}}, requiredFields), []string{name}
	}
	asyncPolicy := func(disable, uninstall string) *capabilitycontract.CancelPolicy {
		return &capabilitycontract.CancelPolicy{Cancelable: true, DisableBehavior: disable, UninstallBehavior: uninstall, AckTimeoutMS: 20}
	}
	base := capabilitycontract.Contract{
		SchemaVersion:     capabilitycontract.SchemaVersion,
		ContractID:        capabilityID + ".v1",
		ContractVersion:   "1.0.0",
		PublisherID:       "example.contracts",
		CapabilityID:      capabilityID,
		CapabilityVersion: "1.0.0",
		ClientName:        fixtureTypeName(capabilityID) + "Client",
	}
	switch capabilityID {
	case "example.capability.echo":
		pingRequest := fixtureClosedObject(map[string]any{"message": map[string]any{"type": "string"}}, nil)
		pingResponse := fixtureClosedObject(map[string]any{
			"ok": map[string]any{"type": "boolean"}, "pong": map[string]any{"type": "boolean"},
			"containers": map[string]any{"type": "array", "items": fixtureClosedObject(map[string]any{
				"id": map[string]any{"type": "string"}, "image": map[string]any{"type": "string"},
				"env":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"labels": fixtureClosedObject(map[string]any{"com.example.owner": map[string]any{"type": "string"}, "com.example.secret": map[string]any{"type": "string"}, "secret_token": map[string]any{"type": "string"}}, nil),
				"mounts": map[string]any{"type": "array", "items": fixtureClosedObject(map[string]any{"source": map[string]any{"type": "string"}, "target": map[string]any{"type": "string"}}, nil)},
			}, nil)},
			"token_id": map[string]any{"type": "string"}, "secret_ref": map[string]any{"type": "string"},
		}, nil)
		dangerRequest, dangerTargets := stringField(true, "target")
		dangerRequest["properties"].(map[string]any)["ui_note"] = map[string]any{"type": "string"}
		archiveRequest, archiveTargets := stringField(false, "document_id")
		base.Methods = []capabilitycontract.Method{
			fixtureContractMethod("echo.ping", "read", "sync", []string{"read"}, []string{"message"}, pingRequest, pingResponse),
			fixtureContractMethod("danger.run", "execute", "sync", []string{"execute"}, dangerTargets, dangerRequest, fixtureClosedObject(map[string]any{"result": map[string]any{"type": "string"}, "done": map[string]any{"type": "boolean"}}, nil)),
			fixtureContractMethod("documents.archive", "execute", "operation", []string{"execute"}, archiveTargets, archiveRequest, fixtureClosedObject(map[string]any{"started": map[string]any{"type": "boolean"}}, nil)),
			fixtureContractMethod("logs.tail", "read", "subscription", []string{"read"}, nil, empty, fixtureClosedObject(map[string]any{"started": map[string]any{"type": "boolean"}}, nil)),
		}
		base.Methods[1].Confirmation = &capabilitycontract.Confirmation{Mode: "required", RequestHashFields: []string{"target"}}
		base.Methods[2].CancelPolicy = asyncPolicy("cancel", "cancel_then_block_delete")
		base.Methods[3].EventTypeName = "LogEvent"
		base.Methods[3].EventSchema = fixtureClosedObject(map[string]any{"line": map[string]any{"type": "string"}}, []string{"line"})
		base.Methods[3].CancelPolicy = asyncPolicy("orphan", "force_cleanup_allowed")
	case "example.capability.tasks":
		taskRequest, taskTargets := stringField(true, "task_id")
		riskPlan := fixtureClosedObject(map[string]any{
			"schema_version": map[string]any{"type": "string"}, "summary": map[string]any{"type": "string"},
			"effect": map[string]any{"type": "string"}, "resource_ref": map[string]any{"type": "string"},
			"requires_admin": map[string]any{"type": "boolean"}, "requires_confirmation": map[string]any{"type": "boolean"},
			"risk_flags": map[string]any{"type": "array", "items": map[string]any{"oneOf": []any{map[string]any{"type": "string"}, fixtureClosedObject(map[string]any{
				"id": map[string]any{"type": "string"}, "severity": map[string]any{"type": "string"}, "summary": map[string]any{"type": "string"}, "requires_admin": map[string]any{"type": "boolean"},
			}, nil)}}},
			"details": fixtureClosedObject(map[string]any{
				"env":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"mounts": map[string]any{"type": "array", "items": fixtureClosedObject(map[string]any{"source": map[string]any{"type": "string"}, "target": map[string]any{"type": "string"}}, nil)},
			}, nil),
		}, nil)
		base.Methods = []capabilitycontract.Method{
			fixtureContractMethod("tasks.list", "read", "sync", []string{"read"}, nil, empty, empty),
			fixtureContractMethod("tasks.start.preflight", "read", "sync", []string{"read"}, taskTargets, taskRequest, riskPlan),
			fixtureContractMethod("tasks.start", "execute", "operation", []string{"execute"}, taskTargets, taskRequest, fixtureClosedObject(map[string]any{"started": map[string]any{"type": "boolean"}}, nil)),
			fixtureContractMethod("tasks.logs.tail", "read", "subscription", []string{"read"}, taskTargets, taskRequest, empty),
			fixtureContractMethod("tasks.remove", "delete", "sync", []string{"delete"}, taskTargets, taskRequest, empty),
		}
		base.Methods[1].PreflightOnly = true
		base.Methods[2].Confirmation = &capabilitycontract.Confirmation{Mode: "risk_based", PreflightMethod: "tasks.start.preflight", RequestHashFields: []string{"task_id"}, PlanHashRequired: true}
		base.Methods[2].CancelPolicy = asyncPolicy("cancel", "cancel_then_block_delete")
		base.Methods[3].EventTypeName = "TaskLogEvent"
		base.Methods[3].EventSchema = fixtureClosedObject(map[string]any{"line": map[string]any{"type": "string"}}, []string{"line"})
		base.Methods[3].CancelPolicy = asyncPolicy("orphan", "force_cleanup_allowed")
		base.Methods[4].Confirmation = &capabilitycontract.Confirmation{Mode: "required", RequestHashFields: []string{"task_id"}}
	default:
		return capabilitycontract.Contract{}, fmt.Errorf("no fixture capability contract for %q", capabilityID)
	}
	return base, nil
}

func fixtureContractMethod(name, effect, execution string, permissions, targetFields []string, requestSchema, responseSchema map[string]any) capabilitycontract.Method {
	return capabilitycontract.Method{
		Name: name, ClientMethod: fixtureClientMethodName(name), Effect: effect, Execution: execution,
		RequiredPermissions: append([]string(nil), permissions...), TargetFields: append([]string(nil), targetFields...),
		TargetSchema: fixtureTargetSchema(requestSchema, targetFields), RequestTypeName: fixtureTypeName(name) + "Request", ResponseTypeName: fixtureTypeName(name) + "Response",
		RequestSchema: cloneParams(requestSchema), ResponseSchema: cloneParams(responseSchema),
	}
}

func fixtureTargetSchema(requestSchema map[string]any, targetFields []string) map[string]any {
	requestProperties, _ := requestSchema["properties"].(map[string]any)
	properties := make(map[string]any, len(targetFields))
	for _, field := range targetFields {
		if value, ok := requestProperties[field]; ok {
			properties[field] = value
		}
	}
	requiredSet := map[string]struct{}{}
	switch required := requestSchema["required"].(type) {
	case []string:
		for _, field := range required {
			requiredSet[field] = struct{}{}
		}
	case []any:
		for _, value := range required {
			if field, ok := value.(string); ok {
				requiredSet[field] = struct{}{}
			}
		}
	}
	var required []string
	for _, field := range targetFields {
		if _, ok := requiredSet[field]; ok {
			required = append(required, field)
		}
	}
	return fixtureClosedObject(properties, required)
}

func fixtureClosedObject(properties map[string]any, required []string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	schema := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
	if len(required) > 0 {
		schema["required"] = append([]string(nil), required...)
	}
	return schema
}

func verifyFixtureCapabilityContract(t *testing.T, contract capabilitycontract.Contract) capabilitycontract.VerifiedContract {
	t.Helper()
	bundle, publicKey, err := buildFixtureCapabilityBundle(contract)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := capabilitycontract.Verify(capabilitycontract.VerifyRequest{
		Bundle:      bundle,
		ExpectedPin: bundle.Pin,
		TrustedKey: capabilitycontract.TrustedKey{
			PublisherID:     contract.PublisherID,
			KeyID:           "fixture-key",
			PublicKey:       publicKey,
			PolicyEpoch:     "1",
			RevocationEpoch: "1",
		},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func buildFixtureCapabilityBundle(contract capabilitycontract.Contract) (capabilitycontract.Bundle, ed25519.PublicKey, error) {
	contractBytes, err := json.Marshal(contract)
	if err != nil {
		return capabilitycontract.Bundle{}, nil, err
	}
	seed := sha256.Sum256(contractBytes)
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	baseRef := "capabilities/fixtures/" + strings.ReplaceAll(contract.CapabilityID, ".", "-") + "/" + contract.ContractVersion
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract:                 contract,
		PublisherID:              contract.PublisherID,
		ArtifactBaseRef:          baseRef,
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("f", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "fixture-key",
		SignaturePolicyEpoch:     "1",
		SignatureRevocationEpoch: "1",
		PrivateKey:               privateKey,
	})
	return bundle, publicKey, err
}

func fixtureCapabilityPinJSON(capabilityID string) string {
	contract, err := fixtureCapabilityContract(capabilityID)
	if err != nil {
		panic(err)
	}
	bundle, _, err := buildFixtureCapabilityBundle(contract)
	if err != nil {
		panic(err)
	}
	raw, err := json.Marshal(bundle.Pin)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func fixtureClientMethodName(method string) string {
	parts := strings.Split(method, ".")
	return parts[0] + fixtureTypeName(strings.Join(parts[1:], "."))
}

func fixtureTypeName(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
	var builder strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		builder.WriteString(strings.ToUpper(part[:1]))
		builder.WriteString(part[1:])
	}
	return builder.String()
}

func buildFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), fixtureManifestJSON())
	writeSurfaceFixture(t, dir, "Plugin")
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
	writeSurfaceFixture(t, dir, title)
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
	writeSurfaceFixture(t, dir, "Storage")
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
	writeSurfaceFixture(t, dir, "Settings")
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
	writeSurfaceFixture(t, dir, "Migration")
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
	writeSurfaceFixture(t, dir, title)
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
	writeSurfaceFixture(t, dir, "Danger")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildMethodContractFixturePackage(t *testing.T) []byte {
	t.Helper()
	source := filepath.Join("..", "..", "testdata", "generated_plugins", "method-contract")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), methodContractFixtureManifestJSON(t))
	for _, relative := range []string{"ui/index.html", "ui/assets/app.js"} {
		content, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, filepath.FromSlash(relative)), string(content))
	}
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func methodContractFixtureManifestJSON(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "generated_plugins", "method-contract", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	contract, err := fixtureCapabilityContract("example.capability.tasks")
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, err := buildFixtureCapabilityBundle(contract)
	if err != nil {
		t.Fatal(err)
	}
	document["capability_bindings"] = []any{map[string]any{"binding_id": "task_runner", "contract": bundle.Pin}}
	methods, _ := document["methods"].([]any)
	for index, rawMethod := range methods {
		method, _ := rawMethod.(map[string]any)
		methods[index] = map[string]any{"method": method["method"], "route": method["route"]}
	}
	document["methods"] = methods
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}

func buildIntentFixturePackage(t *testing.T, dangerous bool) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := rpcFixtureManifestJSON("1.0.0", "Intent RPC")
	if dangerous {
		manifestJSON = dangerousRPCFixtureManifestJSON()
	}
	writeFile(t, filepath.Join(dir, "manifest.json"), addIntentToManifestJSON(t, manifestJSON, dangerous))
	writeSurfaceFixture(t, dir, "Intent")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildCapabilityPinnedFixturePackage(
	t *testing.T,
	manifestJSON string,
	title string,
	bindingID string,
	pin capabilitycontract.Pin,
) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(manifestJSON), &document); err != nil {
		t.Fatal(err)
	}
	bindings, ok := document["capability_bindings"].([]any)
	if !ok {
		t.Fatal("fixture manifest is missing capability_bindings")
	}
	found := false
	for _, rawBinding := range bindings {
		binding, ok := rawBinding.(map[string]any)
		if !ok || binding["binding_id"] != bindingID {
			continue
		}
		binding["contract"] = pin
		found = true
		break
	}
	if !found {
		t.Fatalf("fixture manifest is missing capability binding %q", bindingID)
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), string(encoded)+"\n")
	writeSurfaceFixture(t, dir, title)
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
	writeSurfaceFixture(t, dir, "Operation")
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
	writeSurfaceFixture(t, dir, "Subscription")
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
	writeSurfaceFixture(t, dir, "Core Action")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildDangerousCoreActionFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(coreActionFixtureManifestJSON(), `"execution": "sync",`, `"execution": "sync", "dangerous": true, "confirmation": {"mode": "required", "request_hash_fields": ["target"]},`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Core Action")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildCoreActionOperationFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(coreActionFixtureManifestJSON(), `"execution": "sync"`, `"execution": "operation"`, 1)
	manifestJSON = strings.Replace(manifestJSON, `"request_schema": {`, `"cancel_policy": {"cancelable": true, "disable_behavior": "cancel", "uninstall_behavior": "cancel_then_block_delete", "ack_timeout_ms": 2000}, "request_schema": {`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Core Action")
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
	writeSurfaceFixture(t, dir, "Worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildDangerousWorkerFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerFixtureManifestJSON(), `"execution": "sync",`, `"execution": "sync", "dangerous": true, "confirmation": {"mode": "required", "request_hash_fields": ["message"]},`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerOperationFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerFixtureManifestJSON(), `"execution": "sync"`, `"execution": "operation"`, 1)
	manifestJSON = strings.Replace(manifestJSON, `"route": {"kind": "worker"`, `"cancel_policy": {"cancelable": true, "disable_behavior": "cancel", "uninstall_behavior": "cancel_then_block_delete", "ack_timeout_ms": 2000}, "route": {"kind": "worker"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerSubscriptionFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerFixtureManifestJSON(), `"execution": "sync"`, `"execution": "subscription"`, 1)
	manifestJSON = strings.Replace(manifestJSON, `"route": {"kind": "worker"`, `"cancel_policy": {"cancelable": true, "disable_behavior": "cancel", "uninstall_behavior": "cancel_then_block_delete", "ack_timeout_ms": 2000}, "route": {"kind": "worker"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Worker")
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
	writeSurfaceFixture(t, dir, "Worker Network")
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
	writeSurfaceFixture(t, dir, "Worker Network Stream")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	writeFile(t, filepath.Join(dir, "workers", "abi.json"), workerFixtureABIJSON("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), dir, &buf, pluginpkg.DefaultReadOptions()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerNetworkSubscriptionMemoryHostcallFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerNetworkFixtureManifestJSON(), `"execution": "sync"`, `"execution": "subscription"`, 1)
	manifestJSON = strings.Replace(manifestJSON, `"route": {"kind": "worker"`, `"cancel_policy": {"cancelable": true, "disable_behavior": "orphan", "uninstall_behavior": "force_cleanup_allowed", "ack_timeout_ms": 2000}, "route": {"kind": "worker"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Worker Network Stream Memory Hostcall")
	request := []byte(`{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http_stream","method":"POST","path":"/v1/worker","headers":{"Content-Type":["text/plain"]},"body_base64":"aGVsbG8gZnJvbSBtZW1vcnkgaG9zdGNhbGw=","max_request_bytes":1024,"max_response_bytes":4096,"max_chunk_bytes":4,"max_buffered_bytes":65536,"timeout_ms":1000,"content_type":"text/plain"}`)
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), importedMemoryHostcallWorkerWASMForTest("redevplugin.network", "execute", "redevplugin_worker_invoke", request))
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
	writeSurfaceFixture(t, dir, "Worker Network Hostcall")
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
	writeSurfaceFixture(t, dir, "Worker Network Memory Hostcall")
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
	writeSurfaceFixture(t, dir, "Worker Network Transport Memory Hostcall")
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
	writeSurfaceFixture(t, dir, "Worker Storage")
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
	writeSurfaceFixture(t, dir, "Worker Storage Memory Hostcall")
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
	writeSurfaceFixture(t, dir, "Worker Storage KV Memory Hostcall")
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
	writeSurfaceFixture(t, dir, "Worker Storage SQLite Memory Hostcall")
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
	writeSurfaceFixture(t, dir, "Network")
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
	writeSurfaceFixture(t, dir, "Network")
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

func writeSurfaceFixture(t *testing.T, dir string, title string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "ui", "index.html"), fixtureSurfaceHTML(title))
	writeFile(t, filepath.Join(dir, "ui", "assets", "app.js"), "void 0;")
	writeFile(t, filepath.Join(dir, "ui", "assets", "status.png"), "status")
}

func fixtureSurfaceHTML(title string) string {
	return `<!doctype html><html><head><title>` + title + `</title></head><body><main>` + title + `</main><img src="assets/status.png" alt="Status"><script type="text/redevplugin-worker" src="assets/app.js"></script></body></html>`
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.lifecycle",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "lifecycle.view", "kind": "view", "label": "Lifecycle", "entry": "ui/index.html"}
		]
	}`
}

func storageFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.storage",
			"display_name": "Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "storage.view", "kind": "view", "label": "Storage", "entry": "ui/index.html"}
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.settings",
			"display_name": "Settings",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "settings.view", "kind": "view", "label": "Settings", "entry": "ui/index.html"}
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.migration",
			"display_name": "Migration",
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "migration.view", "kind": "view", "label": "Migration", "entry": "ui/index.html"}
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.rpc",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "rpc.view", "kind": "view", "label": "RPC", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "contract": ` + fixtureCapabilityPinJSON("example.capability.echo") + `}
		],
		"methods": [
			{
				"method": "echo.ping",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "echo.ping"}
			}
		]
	}`
}

func dangerousRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.danger",
			"display_name": "Danger",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "danger.view", "kind": "view", "label": "Danger", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "contract": ` + fixtureCapabilityPinJSON("example.capability.echo") + `}
		],
		"methods": [
			{
				"method": "danger.run",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "danger.run"}
			}
		]
	}`
}

func operationRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.operation",
			"display_name": "Operation",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "operation.view", "kind": "view", "label": "Operation", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "contract": ` + fixtureCapabilityPinJSON("example.capability.echo") + `}
		],
		"methods": [
			{
				"method": "documents.archive",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "documents.archive"}
			}
		]
	}`
}

func subscriptionRPCFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.subscription",
			"display_name": "Subscription",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "subscription.view", "kind": "view", "label": "Subscription", "entry": "ui/index.html"}
		],
		"capability_bindings": [
			{"binding_id": "echo", "contract": ` + fixtureCapabilityPinJSON("example.capability.echo") + `}
		],
		"methods": [
			{
				"method": "logs.tail",
				"route": {"kind": "capability", "binding_id": "echo", "target_method": "logs.tail"}
			}
		]
	}`
}

func coreActionFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.core",
			"display_name": "Core Action",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "core.view", "kind": "view", "label": "Core", "entry": "ui/index.html"}
		],
		"methods": [
			{
				"method": "core.open",
				"effect": "read",
				"execution": "sync",
				"request_schema": {
					"type": "object",
					"additionalProperties": false,
					"properties": {"target": {"type": "string"}}
				},
				"response_schema": {
					"type": "object",
					"additionalProperties": false,
					"properties": {"opened": {"type": "boolean"}}
				},
				"route": {"kind": "core_action", "action_id": "example.open_settings"}
			}
		]
	}`
}

func workerMethodSchemasJSON() string {
	return `"request_schema": {
				"type": "object",
				"additionalProperties": false,
				"properties": {
					"message": {"type": "string"},
					"network_body_base64": {"type": "string"},
					"storage_handle_grant_token": {"type": "string"},
					"storage_store_id": {"type": "string"},
					"storage_path": {"type": "string"},
					"storage_data_base64": {"type": "string"},
					"storage_kv_handle_grant_token": {"type": "string"},
					"storage_sqlite_handle_grant_token": {"type": "string"}
				}
			},
			"response_schema": {
				"type": "object",
				"additionalProperties": false,
				"$defs": {
					"network_result": {
						"type": "object",
						"additionalProperties": false,
						"properties": {
							"ok": {"type": "boolean"},
							"status_code": {"type": "integer"},
							"connector_id": {"type": "string"},
							"grant_id": {"type": "string"},
							"destination": {
								"type": "object",
								"additionalProperties": false,
								"required": ["transport", "host", "port"],
								"properties": {
									"transport": {"type": "string"},
									"scheme": {"type": "string"},
									"host": {"type": "string"},
									"port": {"type": "integer"}
								}
							},
							"runtime_generation_id": {"type": "string"},
							"headers": {"type": "object", "additionalProperties": false, "patternProperties": {"^[!#$%&'*+.^_\u0060|~0-9A-Za-z-]+$": {"type": "array", "items": {"type": "string"}}}},
							"body_base64": {"type": "string"},
							"stream_id": {"type": "string"},
							"bytes_read": {"type": "integer"},
							"chunk_count": {"type": "integer"},
							"transport": {"type": "string"},
							"message_type": {"type": "string"},
							"payload_base64": {"type": "string"}
						}
					},
					"storage_usage": {
						"type": "object",
						"additionalProperties": false,
						"properties": {
							"plugin_instance_id": {"type": "string"},
							"store_id": {"type": "string"},
							"usage_bytes": {"type": "integer", "minimum": 0},
							"quota_bytes": {"type": "integer", "minimum": 0},
							"usage_files": {"type": "integer", "minimum": 0},
							"quota_files": {"type": "integer", "minimum": 0}
						}
					},
					"storage_file_result": {"type": "object", "additionalProperties": false, "properties": {"ok": {"type": "boolean"}, "path": {"type": "string"}, "size_bytes": {"type": "integer"}, "usage": {"$ref": "#/$defs/storage_usage"}}},
					"storage_kv_result": {"type": "object", "additionalProperties": false, "properties": {"ok": {"type": "boolean"}, "key": {"type": "string"}, "size_bytes": {"type": "integer"}, "usage": {"$ref": "#/$defs/storage_usage"}}},
					"storage_sqlite_result": {"type": "object", "additionalProperties": false, "properties": {"ok": {"type": "boolean"}, "database": {"type": "string"}, "usage": {"$ref": "#/$defs/storage_usage"}}}
				},
				"properties": {
					"from_worker": {"type": "boolean"},
					"backend": {"type": "string"},
					"transport": {"type": "string"},
					"method": {"type": "string"},
					"worker_id": {"type": "string"},
					"wasm_abi": {"type": "string"},
					"wasm_byte_len": {"type": "integer", "minimum": 0},
						"network_execute": {"$ref": "#/$defs/network_result"},
						"network_execute_http": {"$ref": "#/$defs/network_result"},
						"network_execute_websocket": {"$ref": "#/$defs/network_result"},
						"network_execute_tcp": {"$ref": "#/$defs/network_result"},
						"network_execute_udp": {"$ref": "#/$defs/network_result"},
					"stream_id": {"type": "string"},
						"storage_file": {"$ref": "#/$defs/storage_file_result"},
						"storage_kv": {"$ref": "#/$defs/storage_kv_result"},
						"storage_sqlite": {"$ref": "#/$defs/storage_sqlite_result"}
				}
			},`
}

func workerFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker",
			"display_name": "Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
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
				` + workerMethodSchemasJSON() + `
				"route": {"kind": "worker", "worker_id": "echo_worker", "export": "redevplugin_worker_invoke"}
			}
		]
	}`
}

func workerNetworkFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.network",
			"display_name": "Worker Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
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
				` + workerMethodSchemasJSON() + `
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.network.transport",
			"display_name": "Worker Network Transport",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
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
				` + workerMethodSchemasJSON() + `
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage",
			"display_name": "Worker Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
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
				` + workerMethodSchemasJSON() + `
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage.kv",
			"display_name": "Worker Storage KV",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
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
				` + workerMethodSchemasJSON() + `
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage.sqlite",
			"display_name": "Worker Storage SQLite",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
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
				` + workerMethodSchemasJSON() + `
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
		"schema_version": "redevplugin.manifest.v2",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.network",
			"display_name": "Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v2"
		},
		"surfaces": [
			{"surface_id": "network.view", "kind": "view", "label": "Network", "entry": "ui/index.html"}
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
	installed := installAndEnablePlugin(t, h, packageBytes)
	grantDeclaredPermissions(t, h, installed)
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, surfaceID)
	return installed, gateway
}

func installEnableAndMintGatewayWithoutPermissions(t *testing.T, h *Host, packageBytes []byte, surfaceID string) (registry.PluginRecord, bridge.GatewayTokenResult) {
	t.Helper()
	installed := installAndEnablePlugin(t, h, packageBytes)
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, surfaceID)
	return installed, gateway
}

func installAndEnablePlugin(t *testing.T, h *Host, packageBytes []byte) registry.PluginRecord {
	t.Helper()
	ctx := context.Background()
	now := stableRecentTestNow()
	installed, err := ImportLocalPackageBytes(ctx, h, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, PluginStateVersion: mustPluginStateVersion(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	return installed
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
		Now:                  now.Add(time.Second), PluginStateVersion: mustPluginStateVersion(t, h,
			record.PluginInstanceID),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.RuntimeGenerationID == "" {
		t.Fatal("surface bootstrap is missing runtime_generation_id")
	}
	if _, err := h.PrepareSurface(ctx, exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	handshake := bridge.Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		PluginStateVersion: bootstrap.PluginStateVersion,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v2",
	}
	gateway, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_rpc",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_rpc"),
		OwnerSessionHash:          bootstrap.OwnerSessionHash,
		OwnerUserHash:             bootstrap.OwnerUserHash,
		SessionChannelIDHash:      bootstrap.SessionChannelIDHash,
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

func exchangeAssetTicketRequestForBootstrap(bootstrap bridge.SurfaceBootstrap, now time.Time) ExchangeAssetTicketRequest {
	return ExchangeAssetTicketRequest{
		SurfaceInstanceID:    bootstrap.SurfaceInstanceID,
		AssetTicket:          bootstrap.AssetTicket,
		OwnerSessionHash:     bootstrap.OwnerSessionHash,
		OwnerUserHash:        bootstrap.OwnerUserHash,
		SessionChannelIDHash: bootstrap.SessionChannelIDHash,
		Now:                  now,
	}
}

func scopedReadStreamRequest(streamID string, streamTicket string) ReadStreamRequest {
	return ReadStreamRequest{
		StreamID:             streamID,
		StreamTicket:         streamTicket,
		SurfaceInstanceID:    "surface_rpc",
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		SessionChannelIDHash: "channel_hash",
	}
}

func mintHostTokenCapacityFiller(t *testing.T, manager *bridge.TokenManager, installed registry.PluginRecord) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := manager.Mint(bridge.MintRequest{
		Kind: bridge.TokenKindHandleGrant,
		Audience: bridge.Audience{
			PluginInstanceID: installed.PluginInstanceID, ActiveFingerprint: installed.ActiveFingerprint,
			RuntimeGenerationID: "runtime_filler", HandleID: "handle_filler", Method: "filler.reserve",
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision: installed.PolicyRevision, ManagementRevision: installed.ManagementRevision, RevokeEpoch: installed.RevokeEpoch,
		},
		Now: now, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("Mint(filler) error = %v", err)
	}
}

func grantDeclaredPermissions(t *testing.T, h *Host, record registry.PluginRecord) {
	t.Helper()
	permissionsToGrant := map[string]struct{}{}
	for _, method := range record.Manifest.Methods {
		effective, err := h.effectiveMethod(record, method)
		if err != nil {
			t.Fatal(err)
		}
		required, err := h.requiredPermissionsForMethod(record, effective)
		if err != nil {
			t.Fatal(err)
		}
		for _, permissionID := range required {
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

type recordingCapabilityContractArtifactResolver struct {
	result ResolvedCapabilityContractArtifact
	err    error
	last   CapabilityContractResolveRequest
	calls  int
}

type memoryCapabilityContractArtifactSet struct {
	bundle       capabilitycontract.Bundle
	fetchChain   []CapabilityArtifactFetchHop
	mediaType    string
	declaredSize *int64
	contentByRef map[string][]byte
}

func (s *memoryCapabilityContractArtifactSet) OpenCapabilityContractArtifact(_ context.Context, ref string) (ResolvedCapabilityContractFile, error) {
	content, ok := s.bundle.Files[ref]
	if override, exists := s.contentByRef[ref]; exists {
		content, ok = override, true
	}
	if !ok {
		return ResolvedCapabilityContractFile{}, os.ErrNotExist
	}
	mediaType := s.mediaType
	if mediaType == "" {
		var err error
		mediaType, err = capabilityArtifactMediaType(s.bundle.Pin, ref)
		if err != nil {
			return ResolvedCapabilityContractFile{}, err
		}
	}
	chain := append([]CapabilityArtifactFetchHop(nil), s.fetchChain...)
	if len(chain) == 0 {
		chain = []CapabilityArtifactFetchHop{{
			URL: "https://artifacts.example.com/" + ref, ResolvedIP: "93.184.216.34",
		}}
	}
	size := int64(len(content))
	if s.declaredSize != nil {
		size = *s.declaredSize
	}
	return ResolvedCapabilityContractFile{
		Reader: io.NopCloser(bytes.NewReader(content)), Size: size, MediaType: mediaType, FetchChain: chain,
	}, nil
}

func (r *recordingCapabilityContractArtifactResolver) ResolveCapabilityContract(_ context.Context, req CapabilityContractResolveRequest) (ResolvedCapabilityContractArtifact, error) {
	r.calls++
	r.last = req
	if r.err != nil {
		return ResolvedCapabilityContractArtifact{}, r.err
	}
	return r.result, nil
}

type recordingCapabilityContractKeyResolver struct {
	publicKey []byte
	err       error
	last      CapabilityContractKeyRequest
	calls     int
}

func (r *recordingCapabilityContractKeyResolver) ResolveCapabilityContractKey(_ context.Context, req CapabilityContractKeyRequest) ([]byte, error) {
	r.calls++
	r.last = req
	if r.err != nil {
		return nil, r.err
	}
	return append([]byte(nil), r.publicKey...), nil
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
		SchemaVersion:            "redevplugin.release_metadata.v2",
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
			UIProtocolVersion:     "plugin-ui-v2",
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
	mu     sync.Mutex
	events []AuditEvent
}

func (s *auditSink) AppendPluginAudit(_ context.Context, event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *auditSink) hasEvent(eventType string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func (s *auditSink) lastEvent(eventType string) (AuditEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

type failingAuditSink struct {
	err error
}

func (s failingAuditSink) AppendPluginAudit(context.Context, AuditEvent) error {
	return s.err
}

func (s *diagnosticSink) AppendPluginDiagnostic(_ context.Context, event DiagnosticEvent) error {
	s.events = append(s.events, event)
	return nil
}

type recordingCapabilityAdapter struct {
	calls             int
	last              capability.Invocation
	lastTarget        capability.TargetResolutionRequest
	result            capability.Result
	resultsByTarget   map[string]capability.Result
	err               error
	cancelCalls       int
	lastCancellation  capability.OperationCancellation
	cancellationError error
	invokeContext     context.Context
	panicValue        any
	invokeDelay       time.Duration
	targetFields      map[string]any
	mutateExecution   func(*capability.ExecutionBinding)
}

type failingStreamRegisterStore struct {
	stream.Store
	err error
}

func (s *failingStreamRegisterStore) Register(context.Context, stream.RegisterRequest) (stream.Record, error) {
	return stream.Record{}, s.err
}

type failFirstOperationFinishStore struct {
	operation.Store
	err       error
	failedOne bool
}

func (s *failFirstOperationFinishStore) Finish(ctx context.Context, req operation.FinishRequest) (operation.Record, error) {
	if !s.failedOne {
		s.failedOne = true
		return operation.Record{}, s.err
	}
	return s.Store.Finish(ctx, req)
}

type failFirstStreamAppendStore struct {
	stream.Store
	err       error
	failedOne bool
}

type failFirstStreamReadStore struct {
	stream.Store
	err       error
	failedOne bool
}

func (s *failFirstStreamReadStore) Read(ctx context.Context, req stream.ReadRequest) (stream.Record, []stream.Event, error) {
	if !s.failedOne {
		s.failedOne = true
		return stream.Record{}, nil, s.err
	}
	return s.Store.Read(ctx, req)
}

func (s *failFirstStreamAppendStore) Append(ctx context.Context, req stream.AppendRequest) (stream.Event, error) {
	if !s.failedOne {
		s.failedOne = true
		return stream.Event{}, s.err
	}
	return s.Store.Append(ctx, req)
}

type recordingCoreActionAdapter struct {
	calls             int
	last              capability.Invocation
	result            capability.Result
	err               error
	cancelCalls       int
	lastCancellation  capability.OperationCancellation
	cancellationError error
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
	invokeContext     context.Context
}

type recordingRuntimeArtifactResolver struct {
	calls  int
	target RuntimeTarget
	path   string
	err    error
}

func surfaceIDForMethod(method string) string {
	if method == "documents.archive" {
		return "operation.view"
	}
	if method == "logs.tail" {
		return "subscription.view"
	}
	return "rpc.view"
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

func waitForHostOperationStatus(t *testing.T, h *Host, operationID string, want operation.Status) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		record, err := h.GetOperation(context.Background(), operationID)
		if err != nil {
			t.Fatalf("GetOperation(%s) error = %v", operationID, err)
		}
		if record.Status == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation %s remained %s, want %s", operationID, record.Status, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testExecutionBinding(record registry.PluginRecord, method string, execution manifest.MethodExecutionMode) capability.ExecutionBinding {
	return capability.ExecutionBinding{
		PluginID:          record.PluginID,
		PluginInstanceID:  record.PluginInstanceID,
		PluginVersion:     record.Version,
		ActiveFingerprint: record.ActiveFingerprint,
		Method:            method,
		Execution:         string(execution),
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

func (a *recordingCapabilityAdapter) ProjectTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	a.lastTarget = req
	if a.targetFields != nil {
		return capability.TargetDescriptor{Kind: "fixture", Fields: cloneParams(a.targetFields)}, nil
	}
	return capability.TargetDescriptor{Kind: "fixture", Fields: cloneParams(req.TargetInput)}, nil
}

func (a *recordingCapabilityAdapter) Invoke(ctx context.Context, req capability.Invocation) (capability.Result, error) {
	a.calls++
	if a.mutateExecution != nil {
		a.mutateExecution(&req.Execution.ExecutionBinding)
	}
	a.last = req
	a.invokeContext = ctx
	if a.panicValue != nil {
		panic(a.panicValue)
	}
	if a.invokeDelay > 0 {
		time.Sleep(a.invokeDelay)
	}
	if a.err != nil {
		return capability.Result{}, a.err
	}
	if a.resultsByTarget != nil {
		if result, ok := a.resultsByTarget[req.Execution.TargetMethod]; ok {
			return result, nil
		}
	}
	return a.result, nil
}

func (a *recordingCapabilityAdapter) CancelOperation(_ context.Context, req capability.OperationCancellation) error {
	a.cancelCalls++
	a.lastCancellation = req
	return a.cancellationError
}

func (a *recordingCoreActionAdapter) InvokeCoreAction(_ context.Context, req capability.Invocation) (capability.Result, error) {
	a.calls++
	a.last = req
	if a.err != nil {
		return capability.Result{}, a.err
	}
	return a.result, nil
}

func (a *recordingCoreActionAdapter) ResolveCoreActionTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	return capability.TargetDescriptor{Kind: "core_action", Fields: cloneParams(req.TargetInput)}, nil
}

func (a *recordingCoreActionAdapter) CancelOperation(_ context.Context, req capability.OperationCancellation) error {
	a.cancelCalls++
	a.lastCancellation = req
	return a.cancellationError
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

func (r *recordingRuntimeSupervisor) InvokeWorker(ctx context.Context, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
	r.calls++
	r.invokeContext = ctx
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
