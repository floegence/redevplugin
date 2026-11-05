package host

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestOpenDistributionLocalInstallWithoutDeveloperPolicy(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	pkg := buildVersionedLifecyclePackage(t, "1.0.0", "Open package")
	record, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{PluginInstanceID: nextTestPluginInstanceID(t), PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg))})
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableEnabled || !registry.RunnablePluginRecord(record) {
		t.Fatalf("ordinary package is not runnable: %+v", record)
	}
	grants, err := h.ListPermissionGrants(hostTestContext(), ListPermissionGrantsRequest{PluginInstanceID: record.PluginInstanceID})
	if err != nil || len(grants) != 0 {
		t.Fatalf("install granted permissions: %+v %v", grants, err)
	}
}

func TestOpenDistributionFingerprintBindsPackageAndCapabilities(t *testing.T) {
	pkg := readTestPackage(t, buildVersionedRPCPackage(t, "1.0.0", "RPC"))
	first := activeFingerprintForPackage(pkg, "instance", nil)
	if first == "" || first != activeFingerprintForPackage(pkg, "instance", nil) {
		t.Fatal("fingerprint is not deterministic")
	}
	for _, kind := range []string{"package", "instance", "capability"} {
		changed := pkg
		instance := "instance"
		switch kind {
		case "package":
			changed.PackageHash = "sha256:" + strings.Repeat("a", 64)
		case "instance":
			instance = "another-instance"
		case "capability":
			changed.Manifest.CapabilityBindings = append(changed.Manifest.CapabilityBindings[:0:0], changed.Manifest.CapabilityBindings...)
			changed.Manifest.CapabilityBindings[0].Contract.ArtifactSHA256 = strings.Repeat("b", 64)
		}
		if first == activeFingerprintForPackage(changed, instance, nil) {
			t.Fatalf("fingerprint omitted %s", kind)
		}
	}
}

func TestOpenDistributionPackageExtraFilesAreContentBound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/manifest.json", lifecycleManifestJSON("1.0.0", "Open package"))
	writeSurfaceFixture(t, dir, "Open package")
	var first bytes.Buffer
	pkg, err := pluginpkg.BuildFromDir(context.Background(), dir, &first, pluginpkg.DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir+"/signatures/package.sig", "ordinary content with no signing semantics")
	var second bytes.Buffer
	updated, err := pluginpkg.BuildFromDir(context.Background(), dir, &second, pluginpkg.DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	if pkg.PackageHash == updated.PackageHash {
		t.Fatal("additional package bytes escaped content digest")
	}
	if string(updated.Files["signatures/package.sig"]) != "ordinary content with no signing semantics" {
		t.Fatal("ordinary archive file not retained")
	}
}

func TestOpenDistributionUpdateRequiresOriginalSourceAndImmutableVersion(t *testing.T) {
	current := registry.PluginRecord{PublisherID: "example", PluginID: "example.plugin", Version: "1.0.0", PackageHash: "one", PackageSourceProvenance: registry.PackageSourceProvenance{Kind: registry.PackageSourceGitHubRepository, GitHubRepositoryID: "10"}}
	next := current
	next.Version = "2.0.0"
	next.PackageHash = "two"
	if err := validatePackageUpdate(current, next, false); err != nil {
		t.Fatal(err)
	}
	next.PackageSourceProvenance.GitHubRepositoryID = "20"
	if err := validatePackageUpdate(current, next, false); err == nil {
		t.Fatal("different repository took over updates")
	}
	if err := validatePackageUpdate(current, next, true); err != nil {
		t.Fatal(err)
	}
	next.Version = "1.0.0"
	if err := validatePackageUpdate(current, next, true); err == nil {
		t.Fatal("same version changed contents")
	}
	next.Version = "0.9.0"
	if err := validatePackageUpdate(current, next, true); err == nil {
		t.Fatal("update silently downgraded")
	}
}

func TestOpenDistributionDirectURLsDoNotShareAuthorityByOrigin(t *testing.T) {
	a := registry.PackageSourceProvenance{Kind: registry.PackageSourcePackageURL, SourceOrigin: "https://example.com", SourceURL: "https://example.com/alice/plugin.redevplugin"}
	b := a
	b.SourceURL = "https://example.com/bob/plugin.redevplugin"
	if samePackageUpdateSource(a, b) {
		t.Fatal("shared hosting origin allowed source takeover")
	}
	if !samePackageUpdateSource(a, a) {
		t.Fatal("exact original source cannot update")
	}
	if _, err := normalizeExternalPackageIntent(ExternalPackageIntent{Action: "install", AllowSourceChange: true}); err == nil {
		t.Fatal("install accepted update-only source consent")
	}
}

func TestOpenDistributionAutomaticUpdateRequiresPreferenceSourceAndCapabilities(t *testing.T) {
	a := registry.PluginRecord{PublisherID: "example", PluginID: "example.app", Version: "1.0.0", PackageHash: "one", AutomaticUpdates: true, PackageSourceProvenance: registry.PackageSourceProvenance{Kind: registry.PackageSourceGitHubRepository, GitHubRepositoryID: "10", RepositoryURL: "https://github.com/example/app"}, SecurityCapabilitySummary: registry.SecurityCapabilitySummary{CanonicalJSON: `{"permissions":[],"methods":[],"surfaces":[]}`}}
	b := a
	b.Version = "1.1.0"
	b.PackageHash = "two"
	if err := validateAutomaticUpdate(a, b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"preference", "source", "permission", "same_version", "summary_missing"} {
		t.Run(change, func(t *testing.T) {
			current, next := a, b
			switch change {
			case "preference":
				current.AutomaticUpdates = false
			case "source":
				next.PackageSourceProvenance.GitHubRepositoryID = "20"
			case "permission":
				next.SecurityCapabilitySummary.CanonicalJSON = `{"permissions":[{"permission_id":"files.write"}],"methods":[],"surfaces":[]}`
			case "same_version":
				next.Version = current.Version
			case "summary_missing":
				current.SecurityCapabilitySummary.CanonicalJSON = ""
			}
			if err := validateAutomaticUpdate(current, next); err == nil {
				t.Fatal("unsafe automatic update accepted")
			}
		})
	}
}

func TestOpenDistributionAutomaticPreferencePersistsOnInstallation(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Original"))}
	configureExternalPackageTestModule(h, stage)
	ctx := hostTestContext()
	inspection, err := h.InspectExternalPackage(ctx, InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: ExternalPackageSource{Kind: "package_url", URL: "https://downloads.example.com/plugin.redevplugin"}})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := h.installInspectedPackage(ctx, installInspectedPackageRequest{InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{PluginInstanceID: installed.Plugin.PluginInstanceID, SurfaceID: "lifecycle.view", ExpectedManagementRevision: installed.Plugin.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	record, err := h.SetAutomaticUpdates(ctx, SetAutomaticUpdatesRequest{PluginInstanceID: installed.Plugin.PluginInstanceID, ExpectedManagementRevision: installed.Plugin.ManagementRevision, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !record.AutomaticUpdates || record.UpdateEligibility != registry.UpdateAutomaticEligible {
		t.Fatal("preference not persisted")
	}
	if record.ManagementRevision != installed.Plugin.ManagementRevision || record.RevokeEpoch != installed.Plugin.RevokeEpoch || record.ActiveFingerprint != installed.Plugin.ActiveFingerprint {
		t.Fatal("update preference changed live Surface authority")
	}
	if _, err := h.PrepareSurface(ctx, exchangeAssetTicketRequestForBootstrap(bootstrap, time.Now())); err != nil {
		t.Fatalf("preference change invalidated an open Surface: %v", err)
	}
	stage.setPackage(readTestPackage(t, buildVersionedLifecyclePackage(t, "1.1.0", "Original")))
	next, err := h.InspectPluginUpdate(ctx, InspectPluginUpdateRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	if next.UpdateEligibility.State != "automatic_eligible" {
		t.Fatalf("candidate: %+v", next.UpdateEligibility)
	}
	op, err := h.StartInspectedInstall(ctx, StartInspectedInstallRequest{RequestID: "automatic-1", InspectionID: next.InspectionID, ExpectedPackageSHA256: next.InspectedHashes.PackageSHA256, Automatic: true})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		current, err := h.GetInspectedInstall(ctx, op.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Execution.Status != "running" {
			if current.Execution.Status != "completed" {
				t.Fatalf("update failed: %+v", current)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("update timed out")
		}
		time.Sleep(time.Millisecond)
	}
	updated, err := h.getPluginRecord(ctx, record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != "1.1.0" || !updated.AutomaticUpdates || updated.ExecutionApproval.Status != registry.ExecutionApprovalPolicyApproved {
		t.Fatalf("unexpected update: %+v", updated)
	}
}

func TestOpenDistributionFailedSecondInstallPreservesSharedPackage(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	raw := buildVersionedLifecyclePackage(t, "1.0.0", "Shared")
	first, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), raw)
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.PluginData = &failingInstallCommitPluginData{PluginData: h.adapters.PluginData, err: errors.New("commit failed")}
	_, err = ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), raw)
	if err == nil {
		t.Fatal("expected failed commit")
	}
	if _, err := h.adapters.Assets.ReadAsset(hostTestContext(), first.PackageHash, "ui/index.html"); err != nil {
		t.Fatalf("failed sibling install deleted shared assets: %v", err)
	}
}

func TestOpenDistributionPreferenceChangeInvalidatesInspectedUpdate(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Original"))}
	configureExternalPackageTestModule(h, stage)
	ctx := hostTestContext()
	first, err := h.InspectExternalPackage(ctx, InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: ExternalPackageSource{Kind: "package_url", URL: "https://downloads.example.com/plugin.redevplugin"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.installInspectedPackage(ctx, installInspectedPackageRequest{InspectionID: first.InspectionID, ExpectedPackageSHA256: first.InspectedHashes.PackageSHA256})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.SetAutomaticUpdates(ctx, SetAutomaticUpdatesRequest{PluginInstanceID: result.Plugin.PluginInstanceID, ExpectedManagementRevision: result.Plugin.ManagementRevision, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	stage.setPackage(readTestPackage(t, buildVersionedLifecyclePackage(t, "1.1.0", "Original")))
	candidate, err := h.InspectPluginUpdate(ctx, InspectPluginUpdateRequest{PluginInstanceID: enabled.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.SetAutomaticUpdates(ctx, SetAutomaticUpdatesRequest{PluginInstanceID: enabled.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.StartInspectedInstall(ctx, StartInspectedInstallRequest{RequestID: "stale-automatic", InspectionID: candidate.InspectionID, ExpectedPackageSHA256: candidate.InspectedHashes.PackageSHA256, Automatic: true}); err == nil {
		t.Fatal("disabled preference accepted automatic install")
	}
	current, err := h.getPluginRecord(ctx, enabled.PluginInstanceID)
	if err != nil || current.Version != "1.0.0" || current.AutomaticUpdates {
		t.Fatalf("preference changed installation: %+v %v", current, err)
	}
	updated, err := h.installInspectedPackage(ctx, installInspectedPackageRequest{InspectionID: candidate.InspectionID, ExpectedPackageSHA256: candidate.InspectedHashes.PackageSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Plugin.AutomaticUpdates || updated.Plugin.UpdateEligibility != registry.UpdateManualOnly {
		t.Fatal("manual update restored an obsolete automatic-update preference")
	}
}

func TestOpenDistributionLocalPreviewCanExplicitlyRebuildSameVersion(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	ctx := hostTestContext()
	first, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildVersionedLifecyclePackage(t, "1.0.0", "First"))
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes := buildVersionedLifecyclePackage(t, "1.0.0", "Edited")
	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: first.PluginInstanceID, ExpectedManagementRevision: first.ManagementRevision, PackageReader: bytes.NewReader(updatedBytes), PackageSize: int64(len(updatedBytes))})
	if err != nil {
		t.Fatal(err)
	}
	if updated.PackageHash == first.PackageHash || updated.Version != first.Version || updated.AutomaticUpdates {
		t.Fatal("local rebuild was not applied explicitly")
	}
}

func TestOpenDistributionPackageAssetWaitIsCancelable(t *testing.T) {
	h, _, _ := newTestHost(t)
	raw := buildVersionedLifecyclePackage(t, "1.0.0", "Package")
	first := readTestPackage(t, raw)
	finish, err := h.preparePackageAssets(hostTestContext(), &first)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := finish(false); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(hostTestContext(), 30*time.Millisecond)
	defer cancel()
	second := readTestPackage(t, raw)
	if release, err := h.preparePackageAssets(ctx, &second); !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			_ = release(true)
		}
		t.Fatalf("waiting on shared package ignored cancellation: %v", err)
	}
	// A different package can progress while the first digest is held.
	third := readTestPackage(t, buildVersionedLifecyclePackage(t, "1.1.0", "Package"))
	release, err := h.preparePackageAssets(hostTestContext(), &third)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(false); err != nil {
		t.Fatal(err)
	}
}

func TestOpenDistributionInspectionRejectsStaleCatalogEvidence(t *testing.T) {
	for _, field := range []string{"publisher", "plugin", "version", "package", "summary", "contracts"} {
		t.Run(field, func(t *testing.T) {
			h, _, _ := newTestHost(t)
			stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Package"))}
			configureExternalPackageTestModule(h, stage)
			req := InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: ExternalPackageSource{Kind: "package_url", URL: "https://downloads.example.com/plugin.redevplugin"}}
			switch field {
			case "publisher":
				req.ExpectedPublisherID = "another-publisher"
			case "plugin":
				req.ExpectedPluginID = "another.plugin"
			case "version":
				req.ExpectedVersion = "2.0.0"
			case "package":
				req.ExpectedPackageSHA256 = "sha256:" + strings.Repeat("0", 64)
			case "summary":
				req.ExpectedSecuritySummarySHA256 = "sha256:" + strings.Repeat("0", 64)
			case "contracts":
				req.ExpectedContractSetSHA256 = "sha256:" + strings.Repeat("0", 64)
			}
			if _, err := h.InspectExternalPackage(hostTestContext(), req); !errors.Is(err, ErrExternalPackageConfirmation) {
				t.Fatalf("stale %s accepted: %v", field, err)
			}
			h.externalInspections.mu.Lock()
			retained := len(h.externalInspections.records)
			h.externalInspections.mu.Unlock()
			if retained != 0 {
				t.Fatal("rejected catalog evidence left installable inspection")
			}
			records, err := h.ListPlugins(hostTestContext())
			if err != nil || len(records) != 0 {
				t.Fatalf("inspection installed package: %v %v", records, err)
			}
		})
	}
}

func TestOpenDistributionAutomaticUpdateBindsExactNetworkAuthorization(t *testing.T) {
	current := registry.PluginRecord{PublisherID: "example", PluginID: "example.app", Version: "1.0.0", PackageHash: "one", AutomaticUpdates: true, PackageSourceProvenance: registry.PackageSourceProvenance{Kind: registry.PackageSourcePackageURL, SourceURL: "https://example.com/plugin.redevplugin"}, SecurityCapabilitySummary: registry.SecurityCapabilitySummary{CanonicalJSON: `{"network":[{"connector_id":"api","auth_declared":true,"tls_declared":true}]}`}}
	current.Manifest.NetworkAccess = &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{{ConnectorID: "api", Auth: map[string]any{"secret_ref": "original"}, TLS: map[string]any{"server_name": "api.example.com"}}}}
	for _, field := range []string{"auth", "tls", "permissions"} {
		next := current
		next.Version = "1.1.0"
		next.PackageHash = "two"
		next.Manifest.NetworkAccess = &manifest.NetworkAccessSpec{Connectors: append([]manifest.NetworkConnectorSpec(nil), current.Manifest.NetworkAccess.Connectors...)}
		switch field {
		case "auth":
			next.Manifest.NetworkAccess.Connectors[0].Auth = map[string]any{"secret_ref": "another"}
		case "tls":
			next.Manifest.NetworkAccess.Connectors[0].TLS = map[string]any{"server_name": "different.example.com"}
		case "permissions":
			next.Manifest.Permissions = []manifest.PermissionID{manifest.PermissionNetworkClient}
		}
		if err := validateAutomaticUpdate(current, next); !errors.Is(err, ErrUpdateReviewRequired) {
			t.Fatalf("changed %s automatically accepted: %v", field, err)
		}
	}
}

func TestOpenDistributionRejectedInspectionCannotCommitAfterCleanupFailure(t *testing.T) {
	for _, field := range []string{"package", "summary", "contracts"} {
		t.Run(field, func(t *testing.T) {
			h, _, _ := newTestHost(t)
			cleanupErr := errors.New("temporary cleanup failure")
			stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Package")), removeErr: cleanupErr}
			configureExternalPackageTestModule(h, stage)
			req := InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: ExternalPackageSource{Kind: "package_url", URL: "https://downloads.example.com/plugin.redevplugin"}}
			switch field {
			case "package":
				req.ExpectedPackageSHA256 = "sha256:" + strings.Repeat("0", 64)
			case "summary":
				req.ExpectedSecuritySummarySHA256 = "sha256:" + strings.Repeat("0", 64)
			case "contracts":
				req.ExpectedContractSetSHA256 = "sha256:" + strings.Repeat("0", 64)
			}
			if _, err := h.InspectExternalPackage(hostTestContext(), req); !errors.Is(err, ErrExternalPackageConfirmation) || !errors.Is(err, cleanupErr) {
				t.Fatalf("rejected inspection error = %v", err)
			}
			h.externalInspections.mu.Lock()
			var retained []externalPackagePendingInspection
			for _, pending := range h.externalInspections.records {
				retained = append(retained, pending)
			}
			h.externalInspections.mu.Unlock()
			if len(retained) != 1 {
				t.Fatalf("retained cleanup records = %d", len(retained))
			}
			pending := retained[0]
			if _, err := h.externalInspections.begin(pending.Inspection.InspectionID, pending.Scope, pending.Record.PackageHash, time.Now()); !errors.Is(err, ErrExternalPackageInspectionNotFound) {
				t.Fatalf("rejected candidate remained installable: %v", err)
			}
			stage.setRemoveError(nil)
			if err := h.removeExpiredExternalPackageInspectionArtifacts(pending.Inspection.ExpiresAt.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := h.externalInspections.get(pending.Inspection.InspectionID, pending.Scope); !errors.Is(err, ErrExternalPackageInspectionNotFound) {
				t.Fatalf("cleanup retry retained candidate: %v", err)
			}
		})
	}
}
