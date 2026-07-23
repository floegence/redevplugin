package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/runtimeclient"
	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/installstage"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/operation"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/releasetrust"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/secrets"
	"github.com/floegence/redevplugin/pkg/security"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	"github.com/floegence/redevplugin/pkg/sessionscope"
	"github.com/floegence/redevplugin/pkg/storage"
	"github.com/floegence/redevplugin/pkg/stream"
	"github.com/floegence/redevplugin/pkg/version"
)

var testPluginInstanceSequence atomic.Uint64

func mustCapabilityBusinessError(t testing.TB, code, message string, details map[string]any) *capability.BusinessError {
	t.Helper()
	businessError, err := capability.NewBusinessError(code, message, details)
	if err != nil {
		t.Fatal(err)
	}
	return businessError
}

func nextTestPluginInstanceID(t testing.TB) string {
	t.Helper()
	return fmt.Sprintf("plugini_test_%d", testPluginInstanceSequence.Add(1))
}

type responseBoundaryContainer struct {
	ID     string            `json:"id"`
	Env    []string          `json:"env"`
	Labels map[string]string `json:"labels"`
}

type responseBoundaryResult struct {
	Containers []*responseBoundaryContainer `json:"containers"`
}

type responseBoundaryBusinessContext struct {
	Entries []*responseBoundaryBusinessEntry `json:"entries"`
}

type responseBoundaryBusinessEntry struct {
	SecretToken string `json:"secret_token"`
}

type responseBoundaryJSON string

func (value responseBoundaryJSON) MarshalJSON() ([]byte, error) {
	return []byte(value), nil
}

type responseBoundaryPanicJSON struct{}

func (responseBoundaryPanicJSON) MarshalJSON() ([]byte, error) {
	panic("response marshaler panic")
}

func mustManagementRevision(t testing.TB, h *Host, pluginInstanceID string) uint64 {
	t.Helper()
	records, err := h.ListPlugins(hostTestContext())
	if err != nil {
		t.Fatalf("ListPlugins() for management revision: %v", err)
	}
	for _, record := range records {
		if record.PluginInstanceID == pluginInstanceID {
			if record.ManagementRevision == 0 {
				t.Fatalf("plugin %q has zero management revision", pluginInstanceID)
			}
			return record.ManagementRevision
		}
	}
	t.Fatalf("plugin %q not found while resolving management revision", pluginInstanceID)
	return 0
}

func mustAuthorizationRevisions(t testing.TB, h *Host, pluginInstanceID string) registry.AuthorizationRevisions {
	t.Helper()
	record, err := h.adapters.Registry.GetPlugin(hostTestContext(), pluginInstanceID)
	if err != nil {
		t.Fatalf("GetPlugin() for authorization revisions: %v", err)
	}
	return registry.AuthorizationRevisionsFromRecord(record)
}

func prepareConfirmationRequest(call CallMethodRequest) PrepareMethodConfirmationRequest {
	return PrepareMethodConfirmationRequest{
		PluginInstanceID:  call.PluginInstanceID,
		SurfaceInstanceID: call.SurfaceInstanceID,
		BridgeChannelID:   call.BridgeChannelID,
		GatewayToken:      call.GatewayToken,
		Method:            call.Method,
		Params:            call.Params,
		Now:               call.Now,
	}
}

func TestOpenRequiresCompletePlatformDependencies(t *testing.T) {
	base := func(t *testing.T) Config {
		t.Helper()
		observabilityStore := observability.NewMemoryStore()
		registryStore := registry.NewMemoryStore()
		pluginData, err := plugindata.Open(hostTestContext(), t.TempDir(), registryStore)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := pluginData.Close(); err != nil {
				t.Errorf("PluginData.Close() error = %v", err)
			}
		})
		return Config{Core: CoreAdapters{
			Policy:               policyAdapter{decision: PolicyAllow},
			Authorization:        allowAuthorizationAdapter{},
			PackageTrustVerifier: &recordingPackageTrustVerifier{},
			Registry:             registryStore,
			Audit:                observabilityStore,
			SecurityAudit:        observabilityStore,
			Diagnostics:          observabilityStore,
			SurfaceCatalog:       &surfaceSink{},
			Assets:               pluginpkg.NewMemoryAssetStore(),
			InstallStages:        installstage.NewMemoryStore(),
			SurfaceTokens:        bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{}),
			PluginData:           pluginData,
			Operations:           operation.NewMemoryStore(),
			ConfirmationIntents:  security.NewMemoryConfirmationIntentStore(),
			Streams:              stream.NewMemoryStore(),
		}}
	}

	tests := []struct {
		name  string
		clear func(*CoreAdapters)
	}{
		{name: "policy", clear: func(a *CoreAdapters) { a.Policy = nil }},
		{name: "authorization", clear: func(a *CoreAdapters) { a.Authorization = nil }},
		{name: "package trust verifier", clear: func(a *CoreAdapters) { a.PackageTrustVerifier = nil }},
		{name: "registry", clear: func(a *CoreAdapters) { a.Registry = nil }},
		{name: "audit", clear: func(a *CoreAdapters) { a.Audit = nil }},
		{name: "security audit", clear: func(a *CoreAdapters) { a.SecurityAudit = nil }},
		{name: "diagnostics", clear: func(a *CoreAdapters) { a.Diagnostics = nil }},
		{name: "assets", clear: func(a *CoreAdapters) { a.Assets = nil }},
		{name: "install stages", clear: func(a *CoreAdapters) { a.InstallStages = nil }},
		{name: "surface tokens", clear: func(a *CoreAdapters) { a.SurfaceTokens = nil }},
		{name: "plugin data", clear: func(a *CoreAdapters) { a.PluginData = nil }},
		{name: "operations", clear: func(a *CoreAdapters) { a.Operations = nil }},
		{name: "confirmation intents", clear: func(a *CoreAdapters) { a.ConfirmationIntents = nil }},
		{name: "streams", clear: func(a *CoreAdapters) { a.Streams = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := base(t)
			tt.clear(&config.Core)
			if _, err := Open(hostTestContext(), config); err == nil {
				t.Fatal("Open() accepted incomplete platform dependencies")
			}
		})
	}
}

func TestLifecycleInstallEnableDisableUninstall(t *testing.T) {
	host, surfaces, audits := newTestHost(t, true, true)
	packageBytes := buildFixturePackage(t)

	installed, err := ImportLocalPackageBytes(hostTestContext(), host, nextTestPluginInstanceID(t), packageBytes)
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
		installed.LocalImportProvenance.UnsignedPolicy != localImportUnsignedPolicy {
		t.Fatalf("local import provenance mismatch: %#v", installed.LocalImportProvenance)
	}

	enabled, err := host.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, host, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if enabled.EnableState != registry.EnableEnabled {
		t.Fatalf("enable EnableState = %s", enabled.EnableState)
	}
	if len(surfaces.snapshots) != 1 || len(surfaces.snapshots[0].Surfaces) != 1 {
		t.Fatalf("surface publish mismatch: %#v", surfaces.snapshots)
	}

	disabled, err := host.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test", ExpectedManagementRevision: mustManagementRevision(t, host, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if disabled.EnableState != registry.EnableDisabled {
		t.Fatalf("disable EnableState = %s", disabled.EnableState)
	}
	if len(surfaces.snapshots) != 2 || len(surfaces.snapshots[1].Surfaces) != 0 {
		t.Fatalf("disable did not clear surfaces: %#v", surfaces.snapshots)
	}

	_, err = host.UninstallPlugin(hostTestContext(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, host, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	if _, err := host.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID); err != registry.ErrNotFound {
		t.Fatalf("GetPlugin after uninstall error = %v", err)
	}
	for _, eventType := range []string{"plugin.installed", "plugin.enabled", "plugin.disabled", "plugin.uninstalled"} {
		if !audits.hasEvent(eventType) {
			t.Fatalf("missing audit event %q: %#v", eventType, audits.events)
		}
	}
}

func TestLocalPackageMutationsRequirePolicyBeforePackageRead(t *testing.T) {
	ctx := hostTestContext()
	packageBytes := buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle")

	for _, tc := range []struct {
		name           string
		developerMode  bool
		localGenerated bool
	}{
		{name: "developer mode disabled", developerMode: false, localGenerated: true},
		{name: "local generated plugins disabled", developerMode: true, localGenerated: false},
	} {
		t.Run("install "+tc.name, func(t *testing.T) {
			stages := installstage.NewMemoryStore()
			h, surfaces, audits := newTestHostWithOptions(t, testHostOptions{
				developerMode:  tc.developerMode,
				localGenerated: tc.localGenerated,
				installStages:  stages,
			})
			reader := &readAtProbe{reader: bytes.NewReader(packageBytes)}
			if _, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
				PluginInstanceID: nextTestPluginInstanceID(t),
				PackageReader:    reader,
				PackageSize:      int64(len(packageBytes)),
			}); !errors.Is(err, security.ErrPolicyDenied) {
				t.Fatalf("ImportLocalPackage() error = %v, want ErrPolicyDenied", err)
			}
			if reader.calls != 0 {
				t.Fatalf("policy-denied import read package %d times", reader.calls)
			}
			records, err := h.ListPlugins(ctx)
			if err != nil {
				t.Fatal(err)
			}
			stageRecords, err := stages.List(ctx, installstage.ListRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 0 || len(stageRecords) != 0 || len(surfaces.snapshots) != 0 || len(audits.events) != 0 {
				t.Fatalf("policy-denied import produced side effects: records=%#v stages=%#v surfaces=%#v audits=%#v", records, stageRecords, surfaces.snapshots, audits.events)
			}
		})
	}

	stages := installstage.NewMemoryStore()
	h, surfaces, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		installStages:  stages,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	stageRecordsBefore, err := stages.List(ctx, installstage.ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	auditCountBefore := len(audits.events)
	surfaceCountBefore := len(surfaces.snapshots)
	h.adapters.Policy = policyAdapter{developerMode: false, localGenerated: true, decision: PolicyAllow}
	nextBytes := buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle 2")
	reader := &readAtProbe{reader: bytes.NewReader(nextBytes)}
	if _, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		PackageReader:              reader,
		PackageSize:                int64(len(nextBytes)),
	}); !errors.Is(err, security.ErrPolicyDenied) {
		t.Fatalf("UpdateLocalPackage() error = %v, want ErrPolicyDenied", err)
	}
	if reader.calls != 0 {
		t.Fatalf("policy-denied update read package %d times", reader.calls)
	}
	stored, err := h.adapters.Registry.GetPlugin(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	stageRecordsAfter, err := stages.List(ctx, installstage.ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != installed.Version || stored.PackageHash != installed.PackageHash || stored.ManagementRevision != installed.ManagementRevision ||
		len(stageRecordsAfter) != len(stageRecordsBefore) || len(audits.events) != auditCountBefore || len(surfaces.snapshots) != surfaceCountBefore {
		t.Fatalf("policy-denied update produced side effects: stored=%#v stages=%#v audits=%#v surfaces=%#v", stored, stageRecordsAfter, audits.events, surfaces.snapshots)
	}
}

func TestManagementRevisionFailsClosedWithoutSideEffects(t *testing.T) {
	ctx := hostTestContext()
	h, surfaces, audits := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	initialAuditCount := len(audits.events)

	for _, managementRevision := range []uint64{0, installed.ManagementRevision + 1} {
		if _, err := h.EnablePlugin(ctx, EnableRequest{
			PluginInstanceID:           installed.PluginInstanceID,
			ExpectedManagementRevision: managementRevision,
		}); !errors.Is(err, ErrManagementRevisionMismatch) {
			t.Fatalf("EnablePlugin(management revision %d) error = %v, want ErrManagementRevisionMismatch", managementRevision, err)
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
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:           enabled.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		SurfaceID:                  "lifecycle.view",
		SurfaceInstanceID:          "surface_management_revision",
	}); !errors.Is(err, ErrManagementRevisionMismatch) {
		t.Fatalf("OpenSurface(stale) error = %v, want ErrManagementRevisionMismatch", err)
	}
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:           enabled.PluginInstanceID,
		ExpectedManagementRevision: enabled.ManagementRevision,
		SurfaceID:                  "lifecycle.view",
		SurfaceInstanceID:          "surface_management_revision",
	}); err != nil {
		t.Fatalf("OpenSurface(current) after stale request error = %v", err)
	}

	if _, err := h.DisablePlugin(ctx, DisableRequest{
		PluginInstanceID:           enabled.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
		Reason:                     "stale request",
	}); !errors.Is(err, ErrManagementRevisionMismatch) {
		t.Fatalf("DisablePlugin(stale) error = %v, want ErrManagementRevisionMismatch", err)
	}
	records, err = h.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].EnableState != registry.EnableEnabled || records[0].ManagementRevision != enabled.ManagementRevision {
		t.Fatalf("stale disable mutated registry: %#v", records)
	}
}

func TestEnableReportsUnknownOutcomeAfterRegistryCommit(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.SurfaceCatalog = &failingSurfaceSink{err: errors.New("surface catalog unavailable")}

	_, err = h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: installed.ManagementRevision,
	})
	if err == nil {
		t.Fatal("EnablePlugin() expected surface catalog error")
	}
	if got := mutation.ForError(err); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
	}
	record, getErr := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if record.EnableState != registry.EnableEnabled {
		t.Fatalf("committed enable state = %q, want %q", record.EnableState, registry.EnableEnabled)
	}
}

func TestUpdateAndDowngradeRefreshEnabledPluginAndRevokeOldTokens(t *testing.T) {
	ctx := hostTestContext()
	h, surfaces, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	v1 := buildVersionedRPCPackage(t, "1.0.0", "RPC")
	v2 := buildVersionedRPCPackage(t, "2.0.0", "RPC v2")
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), v1)
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "rpc.view",
		SurfaceInstanceID: "surface_update",

		Now: now.Add(time.Second), ExpectedManagementRevision: mustManagementRevision(t, h,
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
		ManagementRevision: bootstrap.ManagementRevision,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v5",
	}
	gateway, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_update",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_update"),

		Now: now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}

	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(v2),
		PackageSize:      int64(len(v2)),
		Now:              now.Add(4 * time.Second), ExpectedManagementRevision: mustManagementRevision(t, h,
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
		Now:              now.Add(6 * time.Second), ExpectedManagementRevision: mustManagementRevision(t, h,
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
	ctx := hostTestContext()
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	other := buildStorageFixturePackage(t)
	if _, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(other),
		PackageSize:      int64(len(other)), ExpectedManagementRevision: mustManagementRevision(t, h,
			installed.PluginInstanceID),
	}); err == nil {
		t.Fatal("UpdateLocalPackage() expected identity mismatch error")
	}
}

func TestUpdateRejectsPluginDataContractChanges(t *testing.T) {
	ctx := hostTestContext()
	h, _, _ := newTestHost(t, true, true)
	v1 := buildDataShapeFixturePackage(t, dataShapeFixtureOptions{
		Version:        "1.0.0",
		SettingsSchema: 1,
		StorageSchema:  1,
	})
	v2 := buildDataShapeFixturePackage(t, dataShapeFixtureOptions{
		Version:        "2.0.0",
		SettingsSchema: 2,
		StorageSchema:  2,
	})

	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(v2),
		PackageSize:      int64(len(v2)), ExpectedManagementRevision: mustManagementRevision(t, h,
			installed.PluginInstanceID),
	}); !errors.Is(err, ErrPluginDataContractChanged) {
		t.Fatalf("UpdateLocalPackage() error = %v, want ErrPluginDataContractChanged", err)
	}
}

func TestEnableRejectsUntrusted(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	pkg := readTestPackage(t, buildFixturePackage(t))
	installed, err := host.adapters.Registry.PutPlugin(hostTestContext(), packageRecord(pkg, registry.TrustAssessment{TrustState: registry.TrustUntrusted}, nextTestPluginInstanceID(t), nil, nil), registry.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, host, installed.PluginInstanceID)}); err == nil {
		t.Fatal("EnablePlugin() expected untrusted error")
	}
}

func TestEnableUnsignedLocalRequiresPolicy(t *testing.T) {
	host, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: false, localGenerated: true})
	pkg := readTestPackage(t, buildFixturePackage(t))
	installed, err := host.adapters.Registry.PutPlugin(hostTestContext(), packageRecord(pkg, registry.TrustAssessment{TrustState: registry.TrustUnsignedLocal}, nextTestPluginInstanceID(t), nil, nil), registry.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, host, installed.PluginInstanceID)}); err == nil {
		t.Fatal("EnablePlugin() expected policy error")
	}
	record, err := host.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableDisabledByPolicy {
		t.Fatalf("EnableState = %s", record.EnableState)
	}
}

func TestUpdateUsesVerifierCurrentRecordAndMetadata(t *testing.T) {
	ctx := hostTestContext()
	verifier := &recordingPackageTrustVerifier{trustState: registry.TrustVerified, metadata: map[string]string{"trust.key_id": "old"}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		trustVerifier:  verifier,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildVersionedLifecyclePackage(t, "1.0.0", "Lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	verifier.trustState = registry.TrustVerified
	verifier.metadata = map[string]string{"trust.key_id": "new"}
	nextBytes := buildVersionedLifecyclePackage(t, "2.0.0", "Lifecycle v2")

	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
		PluginInstanceID: installed.PluginInstanceID,
		PackageReader:    bytes.NewReader(nextBytes),
		PackageSize:      int64(len(nextBytes)), ExpectedManagementRevision: mustManagementRevision(t, h,
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
	ctx := hostTestContext()
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
		PluginInstanceID: nextTestPluginInstanceID(t),
		PackageReader:    bytes.NewReader(v1),
		PackageSize:      int64(len(v1)),
		Now:              now,
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
		Now:              now.Add(time.Minute), ExpectedManagementRevision: mustManagementRevision(t, h,
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
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilities: capabilities,
	})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildRPCFixturePackage(t))
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	if len(installed.CapabilityContracts) != 1 || installed.CapabilityContracts[0] != base.Pin {
		t.Fatalf("installed capability pins = %#v, want exact %#v", installed.CapabilityContracts, base.Pin)
	}
}

func TestPermissionRequirementsProjectVerifiedContractWithoutCapabilityAdapter(t *testing.T) {
	capabilities := capability.NewRegistry()
	verified := fixtureVerifiedCapabilityContract(t, "example.capability.echo")
	if err := capabilities.AddContract(verified); err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, capabilities: capabilities})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildRPCFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.GetPermissionRequirements(hostTestContext(), GetPermissionRequirementsRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatalf("GetPermissionRequirements() error = %v", err)
	}
	if result.PluginInstanceID != installed.PluginInstanceID || result.PluginVersion != installed.Version ||
		result.ActiveFingerprint != installed.ActiveFingerprint || result.ManagementRevision != installed.ManagementRevision {
		t.Fatalf("permission requirements identity = %#v, want active record %#v", result, installed)
	}
	if len(result.Contracts) != 1 || result.Contracts[0].ContractID != verified.Contract.ContractID ||
		result.Contracts[0].ContractSHA256 != verified.Pin.ArtifactSHA256 {
		t.Fatalf("permission requirement contracts = %#v", result.Contracts)
	}
	if len(result.Contracts[0].Methods) != 1 || result.Contracts[0].Methods[0].Method != "echo.ping" ||
		!slices.Equal(result.Contracts[0].Methods[0].RequiredPermissions, []string{"read"}) ||
		!slices.Equal(result.RequiredPermissions, []string{"read"}) {
		t.Fatalf("permission requirement methods = %#v; all = %#v", result.Contracts[0].Methods, result.RequiredPermissions)
	}
	if _, err := capabilities.Resolve(verified.Pin); !errors.Is(err, capability.ErrRegistrationMissing) {
		t.Fatalf("test unexpectedly has a concrete capability adapter: %v", err)
	}
}

func TestLocalInstallRejectsCapabilityMethodAliasesThatGeneratedClientsCannotCall(t *testing.T) {
	dir := t.TempDir()
	manifestJSON := strings.Replace(rpcFixtureManifestJSON("1.0.0", "RPC"), `"method": "echo.ping"`, `"method": "plugin.echo"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "RPC")
	var packageBytes bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &packageBytes, pluginpkg.DefaultReadLimits()); err == nil || !strings.Contains(err.Error(), "must match route.target_method") {
		t.Fatalf("BuildFromDir() error = %v, want method alias rejection", err)
	}
}

func TestLocalInstallRejectsCapabilityPolicyDeclaredByPluginManifest(t *testing.T) {
	dir := t.TempDir()
	manifestJSON := strings.Replace(dangerousRPCFixtureManifestJSON(), `"method": "danger.run",`, `"method": "danger.run", "confirmation": {"mode": "required"},`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Danger")
	var packageBytes bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &packageBytes, pluginpkg.DefaultReadLimits()); err == nil || !strings.Contains(err.Error(), "derive policy and schemas from the signed capability contract") {
		t.Fatalf("BuildFromDir() error = %v, want unsigned policy rejection", err)
	}
}

func TestUnsignedLocalPolicyFailureRevokesStorageHandleAndRuntime(t *testing.T) {
	ctx := hostTestContext()
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.revokeResult = runtimeclient.RevokeResult{ClosedStorageHandleCount: 1}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: runtime,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildWorkerStorageSQLiteMemoryHostcallFixturePackage(t))
	if err != nil {
		t.Fatalf("ImportLocalPackageBytes() error = %v", err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: stableRecentTestNow(), ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)})
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
			PluginInstanceID:     enabled.PluginInstanceID,
			ActiveFingerprint:    enabled.ActiveFingerprint,
			RuntimeInstanceID:    "runtime_1",
			RuntimeGenerationID:  "runtime_gen_1",
			RuntimeShardID:       "runtime_shard_a",
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			OwnerEnvHash:         "env_hash",
			SessionChannelIDHash: "channel_hash",
			HandleID:             "storage:db",
			Method:               "storage.sqlite",
			ResourceScope:        sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
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
	ctx := hostTestContext()
	stages := installstage.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		installStages:  stages,
		trustVerifier:  &recordingPackageTrustVerifier{err: errors.New("signature revoked")},
	})
	packageBytes := buildFixturePackage(t)
	if _, err := h.ImportLocalPackage(ctx, ImportLocalPackageRequest{
		PluginInstanceID: nextTestPluginInstanceID(t),
		PackageReader:    bytes.NewReader(packageBytes),
		PackageSize:      int64(len(packageBytes)),
	}); err == nil {
		t.Fatal("ImportLocalPackage() expected trust failure")
	}
	stageRecords, err := stages.List(ctx, installstage.ListRequest{Status: installstage.StatusFailed})
	if err != nil {
		t.Fatal(err)
	}
	if len(stageRecords) != 1 || stageRecords[0].ErrorCode != "trust_failed" || stageRecords[0].ErrorMessage != "plugin package lifecycle stage failed" {
		t.Fatalf("failed stage mismatch: %#v", stageRecords)
	}
	if strings.Contains(stageRecords[0].ErrorMessage, "signature revoked") {
		t.Fatalf("failed stage retained trust adapter cause: %#v", stageRecords[0])
	}
	if _, err := h.adapters.Registry.GetPlugin(ctx, stageRecords[0].PluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("GetPlugin() after failed install error = %v, want ErrNotFound", err)
	}
}

func TestSurfaceBridgeLifecycle(t *testing.T) {
	host, _, _ := newTestHost(t, true, true)
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := ImportLocalPackageBytes(hostTestContext(), host, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, ExpectedManagementRevision: mustManagementRevision(t, host, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}

	bootstrap, err := host.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "lifecycle.view",
		SurfaceInstanceID: "surface_lifecycle",

		Now: now.Add(time.Second), ExpectedManagementRevision: mustManagementRevision(t, host,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if bootstrap.AssetTicket == "" || bootstrap.BridgeNonce == "" {
		t.Fatalf("bootstrap missing ticket/nonce: %#v", bootstrap)
	}

	if _, err := host.PrepareSurface(hostTestContext(), exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second))); err != nil {
		t.Fatalf("PrepareSurface() error = %v", err)
	}

	handshake := bridge.Handshake{
		PluginID:           bootstrap.PluginID,
		SurfaceID:          bootstrap.SurfaceID,
		SurfaceInstanceID:  bootstrap.SurfaceInstanceID,
		ActiveFingerprint:  bootstrap.ActiveFingerprint,
		BridgeNonce:        bootstrap.BridgeNonce,
		AssetSessionNonce:  bootstrap.AssetSessionNonce,
		ManagementRevision: bootstrap.ManagementRevision,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v5",
	}
	gateway, err := host.MintBridgeToken(hostTestContext(), MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_channel",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_channel"),

		Now: now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("MintBridgeToken() error = %v", err)
	}
	if gateway.GatewayToken == "" {
		t.Fatalf("gateway token is empty: %#v", gateway)
	}
}

func TestOpenSurfaceBindsRuntimeGenerationFromSupervisor(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{
		RuntimeInstanceID:   "runtime_surface",
		RuntimeGenerationID: "runtime_generation_surface",
		IPCChannelID:        "ipc_surface",
		ConnectionNonce:     "connection_nonce_surface_123456",
		Ready:               true,
	})
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		runtimeManager:    runtime,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildWorkerFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}

	bootstrap, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "worker.view",
		SurfaceInstanceID: "surface_runtime_generation",

		Now: now.Add(time.Second), ExpectedManagementRevision: mustManagementRevision(t, h,
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
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{
		RuntimeInstanceID:   "runtime_surface",
		RuntimeGenerationID: "runtime_generation_1",
		IPCChannelID:        "ipc_surface",
		ConnectionNonce:     "connection_nonce_surface_123456",
		Ready:               true,
	})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		runtimeManager: runtime,
	})
	now := stableRecentTestNow()
	installed := installAndEnablePlugin(t, h, buildWorkerFixturePackage(t))
	bootstrap, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "worker.view",
		SurfaceInstanceID: "surface_runtime_restart_before_bridge",

		ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID),
		Now:                        now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("OpenSurface() error = %v", err)
	}
	if _, err := h.PrepareSurface(hostTestContext(), exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second))); err != nil {
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
		ManagementRevision: bootstrap.ManagementRevision,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v5",
	}
	_, err = h.MintBridgeToken(hostTestContext(), MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           "bridge_runtime_restart",
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, "bridge_runtime_restart"),

		Now: now.Add(3 * time.Second),
	})
	if !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("MintBridgeToken() after runtime restart error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
}

func TestReadSurfaceAssetRequiresAssetSession(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceID:         "lifecycle.view",
		SurfaceInstanceID: "surface_asset",

		Now: now.Add(time.Second), ExpectedManagementRevision: mustManagementRevision(t, h,
			installed.PluginInstanceID),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadSurfaceAsset(hostTestContext(), ReadSurfaceAssetRequest{
		AssetSession:   "not-a-session",
		AssetSessionID: "as_invalid",
		BindingID:      "asset_invalid",
		Now:            now.Add(2 * time.Second),
	}); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("ReadSurfaceAsset(empty surface) error = %v, want ErrActionDenied", err)
	}
	if _, err := h.ReadSurfaceAsset(hostTestContext(), ReadSurfaceAssetRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetSession:      "not-a-session",
		AssetSessionID:    "as_invalid",
		BindingID:         "asset_invalid",

		Now: now.Add(2 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenInvalid) {
		t.Fatalf("ReadSurfaceAsset() error = %v, want ErrTokenInvalid", err)
	}
	prepared, err := h.PrepareSurface(hostTestContext(), exchangeAssetTicketRequestForBootstrap(bootstrap, now.Add(2*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Document.Assets) != 1 {
		t.Fatalf("prepared assets = %#v, want one lazy asset", prepared.Document.Assets)
	}
	preparedAsset := prepared.Document.Assets[0]
	asset, err := h.ReadSurfaceAsset(hostTestContext(), ReadSurfaceAssetRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetSession:      prepared.AssetSession,
		AssetSessionID:    prepared.AssetSessionID,
		BindingID:         preparedAsset.BindingID,

		Now: now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatalf("ReadSurfaceAsset() error = %v", err)
	}
	if !bytes.Equal(asset.Content, validPNGForTest()) || asset.Entry.Path != preparedAsset.Path || asset.Session.SurfaceInstanceID != bootstrap.SurfaceInstanceID {
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
			_, err := h.ReadSurfaceAsset(hostTestContext(), ReadSurfaceAssetRequest{
				SurfaceInstanceID: bootstrap.SurfaceInstanceID,
				AssetSession:      prepared.AssetSession,
				AssetSessionID:    prepared.AssetSessionID,
				BindingID:         preparedAsset.BindingID,

				Now: now.Add(3 * time.Second),
			})
			if !errors.Is(err, bridge.ErrTokenAudience) {
				t.Fatalf("ReadSurfaceAsset() adapter mismatch error = %v, want ErrTokenAudience", err)
			}
		})
	}
	if _, err := h.ReadSurfaceAsset(hostTestContext(), ReadSurfaceAssetRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetSession:      prepared.AssetSession,
		AssetSessionID:    prepared.AssetSessionID,
		BindingID:         "asset_not_prepared",

		Now: now.Add(3 * time.Second),
	}); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("ReadSurfaceAsset(unprepared binding) error = %v, want ErrTokenAudience", err)
	}
	if _, err := h.ReadSurfaceAsset(hostTestContext(), ReadSurfaceAssetRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetSession:      prepared.AssetSession,
		AssetSessionID:    "asset_session_other",
		BindingID:         preparedAsset.BindingID,

		Now: now.Add(3 * time.Second),
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
	installed, err := ImportLocalPackageBytes(hostTestContext(), host, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.OpenSurface(hostTestContext(), OpenSurfaceRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SurfaceID:        "lifecycle.view", ExpectedManagementRevision: mustManagementRevision(t, host,
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

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "echo.ping",
		Params:          map[string]any{"message": "hello"},
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
	h.securityJournal = &hostFailingSecurityJournal{beginErr: errors.New("audit store unavailable")}
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
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
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "echo.ping", Params: map[string]any{"message": "hello"},
	}); err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if capabilityAdapter.lastTarget.TargetInput["message"] != "hello" || capabilityAdapter.last.Execution.Target.Fields["resource_id"] != "host-resource-1" {
		t.Fatalf("target projection mismatch: request=%#v execution=%#v", capabilityAdapter.lastTarget, capabilityAdapter.last.Execution.Target)
	}
}

func TestCallPluginMethodRejectsSurfaceAfterRuntimeGenerationChanges(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{
		RuntimeInstanceID:   "runtime_surface",
		RuntimeGenerationID: "runtime_generation_1",
		IPCChannelID:        "ipc_surface",
		ConnectionNonce:     "connection_nonce_surface_123456",
		Ready:               true,
	})
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
		runtimeManager:    runtime,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	runtime.health.RuntimeGenerationID = "runtime_generation_2"

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "hello"},
	})
	if !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("CallPluginMethod() after runtime restart error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if runtime.calls != 0 {
		t.Fatalf("runtime calls = %d, want 0", runtime.calls)
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

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "echo.ping",
		Params:          map[string]any{"unknown": true},
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

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "echo.ping",
		Params:          map[string]any{"message": "hello"},
	})
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("capability adapter calls = %d, want 1", capabilityAdapter.calls)
	}
}

func TestCallPluginMethodNormalizesTypedResponseBeforeRedaction(t *testing.T) {
	original := &responseBoundaryResult{Containers: []*responseBoundaryContainer{{
		ID:  "container-1",
		Env: []string{"PATH=/usr/bin", "DB_PASSWORD=adapter-secret"},
		Labels: map[string]string{
			"com.example.owner": "platform",
			"secret_token":      "adapter-token",
		},
	}}}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: original}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true,
	})
	contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
	labels := contract.Methods[0].ResponseSchema["properties"].(map[string]any)["containers"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["labels"].(map[string]any)
	labels["properties"].(map[string]any)["secret_token"].(map[string]any)["const"] = capability.ResponseRedactedValue
	verified := verifyFixtureCapabilityContract(t, contract)
	if err := h.adapters.Capabilities.Register(capability.Registration{Contract: verified, TargetProjector: capabilityAdapter, Adapter: capabilityAdapter}); err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t, rpcFixtureManifestJSON("1.0.0", "RPC"), "RPC", "echo", verified.Pin,
	), "rpc.view")

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "echo.ping",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	raw, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); strings.Contains(got, "adapter-secret") || strings.Contains(got, "adapter-token") ||
		!strings.Contains(got, capability.ResponseRedactedValue) {
		t.Fatalf("typed response was not normalized before redaction: %s", got)
	}
	if original.Containers[0].Env[1] != "DB_PASSWORD=adapter-secret" || original.Containers[0].Labels["secret_token"] != "adapter-token" {
		t.Fatalf("adapter-owned response was mutated: %#v", original)
	}
}

func TestCallPluginMethodRedactsCustomJSONRepresentation(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: responseBoundaryJSON(
		`{"containers":[{"id":"container-1","env":["DB_PASSWORD=custom-secret"]}]}`,
	)}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "echo.ping",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	raw, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); strings.Contains(got, "custom-secret") || !strings.Contains(got, capability.ResponseRedactedValue) {
		t.Fatalf("custom JSON response was not redacted: %s", got)
	}
}

func TestCallPluginMethodRejectsNonJSONValuesBeforeRedaction(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	tests := []struct {
		name  string
		value any
	}{
		{name: "channel", value: make(chan int)},
		{name: "function", value: func() {}},
		{name: "not a number", value: math.NaN()},
		{name: "cycle", value: cycle},
		{name: "marshaler panic", value: responseBoundaryPanicJSON{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"secret_token": tc.value}}}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
			})
			installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
			_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
				PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
				BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "echo.ping",
			})
			if !errors.Is(err, ErrMethodResponseContract) {
				t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
			}
			if errors.Is(err, ErrMethodAdapterPanic) {
				t.Fatalf("response normalization panic was misclassified as adapter panic: %v", err)
			}
		})
	}
}

func TestCallPluginMethodMarksMutatingResponseFailureOutcomeUnknown(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"unknown": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",
		BridgeChannelID:   "bridge_rpc",
		GatewayToken:      gateway.GatewayToken,
		Method:            "documents.archive",
	})
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
	}
	if got := mutation.ForError(err); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("capability adapter calls = %d, want 1", capabilityAdapter.calls)
	}
}

func TestCallPluginMethodMarksInvalidMutatingBusinessDetailsOutcomeUnknown(t *testing.T) {
	contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
	contract.Errors = []capabilitycontract.BusinessError{{
		Code: "ARCHIVE_FAILED", Message: "Archive failed",
		DetailsSchema: fixtureClosedObject(map[string]any{
			"password": map[string]any{"type": "string", "const": capability.ResponseRedactedValue},
		}, []string{"password"}),
	}}
	verified := verifyFixtureCapabilityContract(t, contract)
	capabilityAdapter := &recordingCapabilityAdapter{err: &mutation.Error{
		Outcome: mutation.OutcomeNotCommitted,
		Err: &capability.BusinessError{
			Code: "ARCHIVE_FAILED", Message: "adapter controlled message",
			Details: map[string]any{"password": make(chan int)},
		},
	}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	if err := h.adapters.Capabilities.Register(capability.Registration{
		Contract: verified, TargetProjector: capabilityAdapter, Adapter: capabilityAdapter,
	}); err != nil {
		t.Fatal(err)
	}
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t, operationRPCFixtureManifestJSON(), "Operation RPC", "echo", verified.Pin,
	), "operation.view")

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive",
	})
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
	}
	if got := mutation.ForError(err); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
	}
}

func TestCallPluginMethodMarksUnclassifiedMutatingAdapterFailureOutcomeUnknown(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{err: errors.New("adapter response was lost")}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",
		BridgeChannelID:   "bridge_rpc",
		GatewayToken:      gateway.GatewayToken,
		Method:            "documents.archive",
	})
	if err == nil {
		t.Fatal("CallPluginMethod() expected adapter failure")
	}
	if got := mutation.ForError(err); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
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

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "echo.ping",
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "echo.ping",
	}
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("CallPluginMethod() without grant error = %v, want ErrPermissionDenied", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called before permission grant: %d", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "permission_denied" {
		t.Fatalf("missing permission rejection audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details.Reason != "permission_denied" {
		t.Fatalf("missing permission rejection diagnostic: %#v", diagnostics.events)
	}

	beforeGrant, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		PermissionID:               "read",
		ExpectedPolicyRevision:     beforeGrant.PolicyRevision,
		ExpectedManagementRevision: beforeGrant.ManagementRevision,
		ExpectedRevokeEpoch:        beforeGrant.RevokeEpoch,
	}); err != nil {
		t.Fatalf("GrantPermission() error = %v", err)
	}
	afterGrant, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if afterGrant.PolicyRevision <= beforeGrant.PolicyRevision || afterGrant.RevokeEpoch != beforeGrant.RevokeEpoch {
		t.Fatalf("grant revision mismatch: before=%#v after=%#v", beforeGrant, afterGrant)
	}
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("CallPluginMethod() with stale token error = %v, want ErrTokenRevoked", err)
	}
	_, freshGateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.view")
	call.GatewayToken = freshGateway.GatewayToken
	if _, err := h.CallPluginMethod(hostTestContext(), call); err != nil {
		t.Fatalf("CallPluginMethod() after grant error = %v", err)
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("capability adapter calls = %d, want 1", capabilityAdapter.calls)
	}

	beforeRevoke, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.RevokePermission(hostTestContext(), RevokePermissionRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		PermissionID:               "read",
		ExpectedPolicyRevision:     beforeRevoke.PolicyRevision,
		ExpectedManagementRevision: beforeRevoke.ManagementRevision,
		ExpectedRevokeEpoch:        beforeRevoke.RevokeEpoch,
		Reason:                     "test revoke",
	}); err != nil {
		t.Fatalf("RevokePermission() error = %v", err)
	}
	afterRevoke, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if afterRevoke.PolicyRevision <= beforeRevoke.PolicyRevision || afterRevoke.RevokeEpoch <= beforeRevoke.RevokeEpoch {
		t.Fatalf("revoke revision mismatch: before=%#v after=%#v", beforeRevoke, afterRevoke)
	}
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("CallPluginMethod() after revoke with stale token error = %v, want ErrTokenRevoked", err)
	}
	_, freshGateway = openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.view")
	call.GatewayToken = freshGateway.GatewayToken
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, permissions.ErrPermissionDenied) {
		t.Fatalf("CallPluginMethod() after revoke error = %v, want ErrPermissionDenied", err)
	}
	if !audits.hasEvent("plugin.permission.granted") || !audits.hasEvent("plugin.permission.revoked") {
		t.Fatalf("missing permission audit events: %#v", audits.events)
	}
}

func TestRevokePermissionRevokesRuntimeCapabilities(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.revokeResult = runtimeclient.RevokeResult{ClosedSocketCount: 3, ClosedStreamCount: 4, ClosedStorageHandleCount: 5}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
		runtimeManager:    runtime,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	beforeGrant := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		PermissionID:               "read",
		ExpectedPolicyRevision:     beforeGrant.PolicyRevision,
		ExpectedManagementRevision: beforeGrant.ManagementRevision,
		ExpectedRevokeEpoch:        beforeGrant.RevokeEpoch,
	}); err != nil {
		t.Fatalf("GrantPermission() error = %v", err)
	}
	expected := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	if _, err := h.RevokePermission(hostTestContext(), RevokePermissionRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		PermissionID:               "read",
		ExpectedPolicyRevision:     expected.PolicyRevision,
		ExpectedManagementRevision: expected.ManagementRevision,
		ExpectedRevokeEpoch:        expected.RevokeEpoch,
		Reason:                     "test revoke",
	}); err != nil {
		t.Fatalf("RevokePermission() error = %v", err)
	}
	updated, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
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

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "documents.archive",
		Params:          map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.OperationID == "" || capabilityAdapter.last.Execution.Operation == nil || result.OperationID != capabilityAdapter.last.Execution.Operation.ID() {
		t.Fatalf("operation id mismatch: %#v", result)
	}
	registered, err := h.GetOperation(hostTestContext(), result.OperationID)
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
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.last.Execution.Permissions.Required[0] != "tampered.permission" || adapter.last.Execution.Target.Fields["document_id"] != "tampered-document" {
		t.Fatalf("adapter mutation was not exercised: %#v", adapter.last.Execution.ExecutionBinding)
	}
	record, err := h.GetOperation(hostTestContext(), started.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Permissions.Required[0] != "execute" || record.Target.Fields["document_id"] != "doc-1" {
		t.Fatalf("durable execution binding was mutated by the adapter: %#v", record.ExecutionBinding)
	}
	if err := adapter.last.Execution.Operation.Complete(hostTestContext()); err != nil {
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

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "logs.tail",
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
	if err := capabilityAdapter.last.Execution.Stream.Append(hostTestContext(), map[string]any{"unexpected": true}); err == nil || !strings.Contains(err.Error(), "signed contract") {
		t.Fatalf("Stream.Append(invalid event) error = %v, want signed event schema rejection", err)
	}
	if err := capabilityAdapter.last.Execution.Stream.Append(hostTestContext(), map[string]any{"line": "line 1"}); err != nil {
		t.Fatalf("Stream.Append() error = %v", err)
	}
	if _, err := h.ReadStream(hostTestContext(), ReadStreamRequest{StreamID: result.StreamID}); !errors.Is(err, ErrStreamTicketRequired) {
		t.Fatalf("ReadStream() without ticket error = %v, want %v", err, ErrStreamTicketRequired)
	}
	streamResult, err := h.ReadStream(hostTestContext(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatalf("ReadStream() error = %v", err)
	}
	if streamResult.Record.Method != "logs.tail" || len(streamResult.Events) != 1 || string(streamResult.Events[0].Data) != `{"line":"line 1"}` {
		t.Fatalf("stream read mismatch: %#v", streamResult)
	}
	if streamResult.Done || streamResult.DeliveryID == "" || streamResult.ReadID == "" {
		t.Fatalf("open stream did not return an acknowledgeable delivery: %#v", streamResult)
	}
	acknowledgeStreamResult(t, h, result.StreamID, result.StreamTicket, streamResult)
	if _, err := h.adapters.Streams.Append(hostTestContext(), stream.AppendRequest{StreamID: result.StreamID, Data: []byte(`{"line":"line 2"}`)}); err != nil {
		t.Fatalf("Stream.Append() after first acknowledgement error = %v", err)
	}
	secondRequest := scopedReadStreamRequest(result.StreamID, result.StreamTicket)
	secondRequest.ReadID = "read_host_test_2"
	second, err := h.ReadStream(hostTestContext(), secondRequest)
	if err != nil {
		t.Fatalf("ReadStream() renewed read error = %v", err)
	}
	if second.Done || len(second.Events) != 1 || string(second.Events[0].Data) != `{"line":"line 2"}` || second.DeliveryID == "" {
		t.Fatalf("second stream delivery mismatch: %#v", second)
	}
	acknowledgeStreamResult(t, h, result.StreamID, result.StreamTicket, second)
	if err := capabilityAdapter.last.Execution.Stream.Close(hostTestContext()); err != nil {
		t.Fatalf("Stream.Close() error = %v", err)
	}
	finalRequest := scopedReadStreamRequest(result.StreamID, result.StreamTicket)
	finalRequest.ReadID = "read_host_test_3"
	final, err := h.ReadStream(hostTestContext(), finalRequest)
	if err != nil {
		t.Fatalf("ReadStream() terminal read error = %v", err)
	}
	if !final.Done || final.TerminalStatus != stream.StatusClosed || final.DeliveryID == "" {
		t.Fatalf("terminal stream delivery mismatch: %#v", final)
	}
	acknowledgeStreamResult(t, h, result.StreamID, result.StreamTicket, final)
	if _, err := h.AcknowledgeStream(hostTestContext(), AcknowledgeStreamRequest{
		StreamID: result.StreamID, StreamTicket: result.StreamTicket,
		DeliveryID: final.DeliveryID, SurfaceInstanceID: "surface_rpc",
	}); err != nil {
		t.Fatalf("AcknowledgeStream(retry) error = %v", err)
	}
	if !audits.hasEvent("plugin.stream.started") {
		t.Fatalf("missing stream audit event: %#v", audits.events)
	}
	if !audits.hasEvent("plugin.stream.closed") {
		t.Fatalf("missing closed stream audit event: %#v", audits.events)
	}
}

func TestReadStreamFailureKeepsCurrentTicketAndEvents(t *testing.T) {
	readFailure := errors.New("injected stream read failure")
	streams := &failFirstStreamDeliverStore{Store: stream.NewMemoryStore(), err: readFailure}
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter, streams: streams,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.last.Execution.Stream.Append(hostTestContext(), map[string]any{"line": "preserved"}); err != nil {
		t.Fatal(err)
	}
	request := scopedReadStreamRequest(result.StreamID, result.StreamTicket)
	if _, err := h.ReadStream(hostTestContext(), request); !errors.Is(err, readFailure) {
		t.Fatalf("ReadStream(first) error = %v, want %v", err, readFailure)
	}
	retried, err := h.ReadStream(hostTestContext(), request)
	if err != nil {
		t.Fatalf("ReadStream(retry) error = %v", err)
	}
	if len(retried.Events) != 1 || string(retried.Events[0].Data) != `{"line":"preserved"}` || retried.DeliveryID == "" {
		t.Fatalf("retry did not preserve the event delivery: %#v", retried)
	}
}

func TestReadStreamReplaysConcurrentDelivery(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.last.Execution.Stream.Append(hostTestContext(), map[string]any{"line": "once"}); err != nil {
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
			read, readErr := h.ReadStream(hostTestContext(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
			outcomes <- readOutcome{result: read, err: readErr}
		}()
	}
	close(start)
	first := <-outcomes
	second := <-outcomes
	results := []readOutcome{first, second}
	deliveryID := ""
	for _, outcome := range results {
		if outcome.err != nil {
			t.Fatalf("concurrent ReadStream() error = %v", outcome.err)
		}
		if len(outcome.result.Events) != 1 || outcome.result.DeliveryID == "" {
			t.Fatalf("concurrent delivery = %#v", outcome.result)
		}
		if deliveryID == "" {
			deliveryID = outcome.result.DeliveryID
		} else if outcome.result.DeliveryID != deliveryID {
			t.Fatalf("concurrent deliveries differ: %#v", results)
		}
	}
}

func TestReadStreamLongPollRevalidatesPluginRevision(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		request := scopedReadStreamRequest(result.StreamID, result.StreamTicket)
		request.WaitTimeout = time.Second
		_, readErr := h.ReadStream(hostTestContext(), request)
		readDone <- readErr
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID), Reason: "policy",
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
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.RequestCancel(hostTestContext(), operation.CancelRequest{OperationID: result.OperationID}); err != nil {
		t.Fatal(err)
	}
	sink, err := h.executions.streamSink(result.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	sink.lease.requestCancel(errors.New("operation cancellation requested"))
	if err := (hostRuntimeStreamSink{executions: h.executions}).CloseRuntimeStream(hostTestContext(), result.StreamID); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("CloseRuntimeStream() error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusCancelRequested)
}

func TestWorkerOperationCompletesWhenSynchronousRuntimeInvocationReturns(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerOperationFixturePackage(t), "worker.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
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

func TestMutatingWorkerMarksRuntimeDispatchFailureOutcomeUnknown(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.err = errors.New("runtime response was lost")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime})
	installed, gateway := installEnableAndMintGateway(t, h, buildMutatingWorkerFixturePackage(t), "worker.view")

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",
		BridgeChannelID:   "bridge_rpc",
		GatewayToken:      gateway.GatewayToken,
		Method:            "worker.echo",
		Params:            map[string]any{"message": "hello"},
	})
	if err == nil {
		t.Fatal("CallPluginMethod() expected runtime failure")
	}
	if got := mutation.ForError(err); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
	}
	if runtime.calls != 1 {
		t.Fatalf("runtime calls = %d, want 1", runtime.calls)
	}
}

func TestWorkerSubscriptionCompletesWhenSynchronousRuntimeInvocationReturns(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerSubscriptionFixturePackage(t), "worker.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
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
	terminal, err := h.ReadStream(hostTestContext(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatal(err)
	}
	if !terminal.Done || terminal.TerminalStatus != stream.StatusClosed || len(terminal.Events) != 0 || terminal.DeliveryID == "" {
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
	const sensitiveCause = "runtime token secret at /Users/private/runtime.sock"
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	diagnostics := &diagnosticSink{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter, diagnostics: diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := capabilityAdapter.last.Execution.Stream.Fail(hostTestContext(), "internal", errors.New(sensitiveCause)); !errors.Is(err, capability.ErrInvalidExecutionFailure) {
		t.Fatalf("Stream.Fail(unknown code) error = %v", err)
	}
	if err := capabilityAdapter.last.Execution.Stream.Fail(hostTestContext(), capability.ExecutionFailureRuntimeFailed, nil); !errors.Is(err, capability.ErrInvalidExecutionFailure) {
		t.Fatalf("Stream.Fail(nil cause) error = %v", err)
	}
	if err := capabilityAdapter.last.Execution.Stream.Fail(hostTestContext(), capability.ExecutionFailureRuntimeFailed, errors.New(sensitiveCause)); err != nil {
		t.Fatal(err)
	}
	operationRecord, err := h.GetOperation(hostTestContext(), result.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	streamRecord, err := h.adapters.Streams.Get(hostTestContext(), result.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []struct {
		name   string
		code   capability.ExecutionFailureCode
		reason string
	}{
		{name: "operation", code: operationRecord.FailureCode, reason: operationRecord.Reason},
		{name: "stream", code: streamRecord.FailureCode, reason: streamRecord.Reason},
	} {
		if failure.code != capability.ExecutionFailureRuntimeFailed || failure.reason != capability.ExecutionFailureMessage {
			t.Fatalf("%s failure = %q/%q", failure.name, failure.code, failure.reason)
		}
	}
	encoded, err := json.Marshal(operationRecord)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), sensitiveCause) {
		t.Fatalf("public operation leaked failure cause: %s", encoded)
	}
	var failureDiagnostic *observability.DiagnosticEvent
	for index := range diagnostics.events {
		if diagnostics.events[index].Type == "plugin.execution.failed" {
			failureDiagnostic = &diagnostics.events[index]
			break
		}
	}
	if failureDiagnostic == nil || failureDiagnostic.Details.FailureCode != string(capability.ExecutionFailureRuntimeFailed) {
		t.Fatalf("execution failure diagnostic = %#v", failureDiagnostic)
	}
	failure := failureDiagnostic.Failure
	if failure.Code != observability.FailureAction || failure.Component != observability.FailureComponentExecution || failure.Operation != "execution.fail" || strings.Contains(fmt.Sprint(failureDiagnostic), sensitiveCause) {
		t.Fatalf("execution failure diagnostic cause was not redacted: %#v", failureDiagnostic)
	}
	terminal, err := h.ReadStream(hostTestContext(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
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
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := capabilityAdapter.last.Execution.Stream.Close(hostTestContext()); err != nil {
		t.Fatal(err)
	}

	terminal, err := h.ReadStream(hostTestContext(), scopedReadStreamRequest(result.StreamID, result.StreamTicket))
	if err != nil {
		t.Fatalf("ReadStream() terminal read error = %v", err)
	}
	if !terminal.Done || terminal.TerminalStatus != stream.StatusClosed || terminal.DeliveryID == "" {
		t.Fatalf("terminal stream read = %#v", terminal)
	}
}

func TestReadTerminalStreamKeepsTicketUntilZeroPayloadEventsAreDrained(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"marker.first", "marker.second"} {
		if _, err := h.adapters.Streams.Append(hostTestContext(), stream.AppendRequest{StreamID: result.StreamID, Kind: kind}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.adapters.Streams.Close(hostTestContext(), stream.CloseRequest{StreamID: result.StreamID}); err != nil {
		t.Fatal(err)
	}

	request := scopedReadStreamRequest(result.StreamID, result.StreamTicket)
	request.MaxEvents = 1
	first, err := h.ReadStream(hostTestContext(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Done || len(first.Events) != 1 || first.DeliveryID == "" {
		t.Fatalf("first terminal stream page = %#v", first)
	}
	acknowledgeStreamResult(t, h, result.StreamID, result.StreamTicket, first)
	request.ReadID = "read_host_test_2"
	second, err := h.ReadStream(hostTestContext(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Done || len(second.Events) != 1 || second.DeliveryID == "" {
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
			PluginInstanceID:     installed.PluginInstanceID,
			ActiveFingerprint:    installed.ActiveFingerprint,
			RuntimeGenerationID:  "runtime_filler",
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			OwnerEnvHash:         "env_hash",
			SessionChannelIDHash: "channel_hash",
			HandleID:             "handle_filler",
			Method:               "filler.reserve",
			ResourceScope:        sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
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

	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "logs.tail",
	}); !errors.Is(err, bridge.ErrTokenCapacity) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrTokenCapacity", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter ran before the initial stream ticket was available: calls=%d", capabilityAdapter.calls)
	}
	page, err := h.adapters.Operations.List(hostTestContext(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID, AllOwners: true})
	if err != nil {
		t.Fatal(err)
	}
	operations := page.Records
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
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if !errors.Is(err, ticketErr) || errors.Is(err, finishErr) {
		t.Fatalf("CallPluginMethod() error = %v, want stable ticket failure without raw cleanup error", err)
	}
	if adapter.calls != 0 {
		t.Fatalf("adapter ran before ticket issuance: calls=%d", adapter.calls)
	}
	page, err := operationStore.List(hostTestContext(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID, AllOwners: true})
	if err != nil {
		t.Fatal(err)
	}
	records := page.Records
	if len(records) != 1 || records[0].Status != operation.StatusRunning {
		t.Fatalf("partial cleanup operation state = %#v", records)
	}
	streamRecord, err := streamStore.Get(hostTestContext(), records[0].StreamID)
	if err != nil {
		t.Fatal(err)
	}
	if streamRecord.Status != stream.StatusFailed || streamRecord.Reason != executionFailedReason {
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
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "logs.tail",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	streamSink := capabilityAdapter.last.Execution.Stream
	if streamSink == nil || streamSink.ID() != result.StreamID {
		t.Fatalf("stream sink mismatch: result=%#v invocation=%#v", result, capabilityAdapter.last)
	}
	if err := streamSink.Append(hostTestContext(), map[string]any{"line": "line before disable"}); err != nil {
		t.Fatalf("Stream.Append() before disable error = %v", err)
	}

	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy", ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}

	assertHostStreamStatus(t, h, result.StreamID, stream.StatusOrphanedDisabled)
	if err := streamSink.Append(hostTestContext(), map[string]any{"line": "line after disable"}); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("Stream.Append() after disable error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
	if _, err := h.ReadStream(hostTestContext(), scopedReadStreamRequest(result.StreamID, result.StreamTicket)); !errors.Is(err, bridge.ErrTokenRevoked) {
		t.Fatalf("ReadStream() after disable error = %v, want %v", err, bridge.ErrTokenRevoked)
	}
	if !audits.hasEvent("plugin.streams.disabled_transitioned") {
		t.Fatalf("missing disabled stream transition audit event: %#v", audits.events)
	}
}

func TestCallPluginMethodDispatchesWorkerRoute(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeManager:     runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "hello"},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() worker error = %v", err)
	}
	if result.Data == nil || runtime.calls != 1 {
		t.Fatalf("worker result/calls mismatch: result=%#v calls=%d", result, runtime.calls)
	}
	current, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatalf("GetPlugin() after worker call error = %v", err)
	}
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
	assertRuntimeLeaseEqual(t, "owner_env_hash", runtime.lastLease.OwnerEnvHash, "env_hash")
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
	assertRuntimeLeaseField(t, "issued_at_unix_ms", runtime.lastLease.IssuedAtUnixMillis != 0)
	assertRuntimeLeaseEqual(t, "runtime method", runtime.lastMethod, "worker.echo")
	var payload workerInvocationPayload
	if err := json.Unmarshal(runtime.lastPayload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.WorkerID != "echo_worker" ||
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
	if !slices.Contains(runtime.lastLease.TargetDescriptorHashes, invocationHash) {
		t.Fatalf("runtime lease does not bind worker invocation %s: %#v", invocationHash, runtime.lastLease.TargetDescriptorHashes)
	}
	asset, err := h.adapters.Assets.ReadAsset(hostTestContext(), installed.PackageHash, "workers/echo.wasm")
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
	for _, privateKey := range []string{"lease_id", "token_id", "ipc_channel_id"} {
		if _, exists := leaseAudit.Details[privateKey]; exists {
			t.Fatalf("runtime lease audit exposed %s: %#v", privateKey, leaseAudit.Details)
		}
	}
	assertAuditDetail(t, leaseAudit, "method", "worker.echo")
	assertAuditDetail(t, leaseAudit, "effect", "read")
	assertAuditDetail(t, leaseAudit, "execution", "sync")
	assertAuditDetail(t, leaseAudit, "runtime_instance_id", "runtime_1")
	assertAuditDetail(t, leaseAudit, "runtime_generation_id", "runtime_gen_1")
	assertAuditDetail(t, leaseAudit, "policy_revision", current.PolicyRevision)
	assertAuditDetail(t, leaseAudit, "management_revision", current.ManagementRevision)
	assertAuditDetail(t, leaseAudit, "revoke_epoch", current.RevokeEpoch)
	assertAuditDetail(t, leaseAudit, "expires_at_unix_ms", runtime.lastLease.ExpiresAtUnixMillis)
	assertAuditDetail(t, leaseAudit, "target_descriptor_hashes", runtime.lastLease.TargetDescriptorHashes)
}

func TestCallPluginMethodWorkerPayloadIncludesEmptyParams(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeManager:     runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
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

func TestMarshalWorkerCanonicalJSONMatchesRuntimeContract(t *testing.T) {
	raw, err := marshalWorkerCanonicalJSON(map[string]any{
		"title": "Launch notes",
		"body":  "<script>&\u2028",
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"body":"<script>&\u2028","title":"Launch notes"}`
	if string(raw) != want {
		t.Fatalf("canonical worker JSON = %s, want %s", raw, want)
	}
}

func TestCallPluginMethodWorkerPayloadCarriesHostOnlyStorageGrants(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeManager:     runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerStorageFixturePackage(t), "worker.view")

	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "store this"},
	}); err != nil {
		t.Fatalf("CallPluginMethod() worker error = %v", err)
	}

	var payload workerInvocationPayload
	if err := json.Unmarshal(runtime.lastPayload, &payload); err != nil {
		t.Fatal(err)
	}
	grant := payload.StorageHandleGrants["workspace"]
	if !strings.HasPrefix(grant, "handle_grant.") {
		t.Fatalf("storage grant = %q, want host-minted handle grant", grant)
	}
	if payload.BrokerAccessSHA256 == "" || len(payload.BrokerAccess.Storage) != 1 || payload.BrokerAccess.Storage[0].StoreID != "workspace" {
		t.Fatalf("worker broker access = %#v hash=%q", payload.BrokerAccess, payload.BrokerAccessSHA256)
	}
	wantAccessHash, err := workerBrokerAccessHash(payload.BrokerAccess)
	if err != nil {
		t.Fatal(err)
	}
	if payload.BrokerAccessSHA256 != wantAccessHash {
		t.Fatalf("broker access hash = %q, want %q", payload.BrokerAccessSHA256, wantAccessHash)
	}
	if _, leaked := payload.Params["storage_handle_grant_token"]; leaked {
		t.Fatalf("plugin params leaked storage grant: %#v", payload.Params)
	}
	if strings.Contains(string(runtime.lastPayload), `"storage_handle_grant_token"`) {
		t.Fatalf("worker payload exposed plugin-visible grant field: %s", runtime.lastPayload)
	}
}

func TestCallPluginMethodWorkerRouteRequiresRuntimeManager(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected runtime manager error")
	}
}

func TestCallPluginMethodWorkerRouteFailsClosedAfterDisable(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeManager:     runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy", ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "after disable"},
	}); err == nil {
		t.Fatal("CallPluginMethod() after disable expected fail-closed error")
	}
	if runtime.calls != 0 {
		t.Fatalf("runtime invoked after disable: calls=%d lease=%#v", runtime.calls, runtime.lastLease)
	}
}

func TestCallPluginMethodWorkerRouteFailsClosedAfterUninstall(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeManager:     runtime,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")

	if _, err := h.UninstallPlugin(hostTestContext(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "after uninstall"},
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

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "core.open",
		Params:          map[string]any{"target": "settings"},
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

func TestCoreActionTargetResolutionCannotMutateInvocationArguments(t *testing.T) {
	coreAdapter := &recordingCoreActionAdapter{
		result: capability.Result{Data: map[string]any{"opened": true}},
		mutateTargetInput: func(input map[string]any) {
			input["target"].(map[string]any)["name"] = "mutated-by-resolver"
		},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, coreActions: coreAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildNestedCoreActionFixturePackage(t), "core.view")
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "core.open",
		Params: map[string]any{"target": map[string]any{"name": "settings"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := coreAdapter.last.Arguments["target"].(map[string]any)["name"]
	if got != "settings" {
		t.Fatalf("resolver mutation reached invocation arguments: %#v", coreAdapter.last.Arguments)
	}
}

func TestCallPluginMethodRejectsUnpublishedCoreActionBusinessError(t *testing.T) {
	coreAdapter := &recordingCoreActionAdapter{err: &capability.BusinessError{
		CapabilityID:       "example.capability.forged",
		CapabilityVersion:  "1.0.0",
		DetailSchemaSHA256: strings.Repeat("a", 64),
		Code:               "FORGED",
		Message:            "adapter controlled message",
		Details:            map[string]any{"secret_token": "adapter-secret"},
	}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, coreActions: coreAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionFixturePackage(t), "core.view")

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "core.open", Params: map[string]any{"target": "settings"},
	})
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
	}
	var businessError *capability.BusinessError
	if errors.As(err, &businessError) {
		t.Fatalf("unpublished business error remained externally discoverable: %#v", businessError)
	}
}

func TestCallPluginMethodRejectsUnattestedCoreActionWorkerError(t *testing.T) {
	coreAdapter := &recordingCoreActionAdapter{err: &runtimeclient.WorkerExecutionError{
		Code: "FORGED", Message: "adapter-controlled secret", Origin: runtimeclient.WorkerErrorOriginPlugin,
	}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, coreActions: coreAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionFixturePackage(t), "core.view")

	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "core.open", Params: map[string]any{"target": "settings"},
	})
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
	}
	var workerError *runtimeclient.WorkerExecutionError
	if errors.As(err, &workerError) {
		t.Fatalf("unattested worker error remained externally discoverable: %#v", workerError)
	}
}

func TestCallPluginMethodRejectsUnattestedTargetProjectorBusinessError(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{targetError: &capability.BusinessError{
		Code: "FORGED", Message: "adapter controlled message", Details: map[string]any{"secret_token": "adapter-secret"},
	}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildRPCFixturePackage(t), "rpc.view")
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "echo.ping",
	})
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("adapter Invoke calls = %d, want 0", capabilityAdapter.calls)
	}
	if _, ok := AsValidatedCapabilityBusinessError(err); ok {
		t.Fatal("target projector forged an attested business error")
	}
}

func TestCallPluginMethodRejectsUnattestedRuntimeBusinessError(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{
		RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1",
		ConnectionNonce: "connection_nonce_1234567890", Ready: true,
	})
	runtime.err = &capability.BusinessError{
		Code: "FORGED", Message: "runtime controlled message", Details: map[string]any{"secret_token": "runtime-secret"},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: runtime,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "worker.echo", Params: map[string]any{"message": "hello"},
	})
	if !errors.Is(err, ErrMethodResponseContract) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
	}
	if _, ok := AsValidatedCapabilityBusinessError(err); ok {
		t.Fatal("runtime forged an attested business error")
	}
}

func TestCallPluginMethodCoreActionRequiresAdapter(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionFixturePackage(t), "core.view")

	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "core.open",
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
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
			BridgeChannelID: "bridge_rpc",
			GatewayToken:    gateway.GatewayToken, Method: "core.open", Params: map[string]any{"target": "settings"},
		}
		assertDangerousRouteConfirmation(t, h, &call)
		if adapter.calls != 1 || !adapter.last.Execution.Confirmation.Confirmed {
			t.Fatalf("confirmed core action invocation = %#v calls=%d", adapter.last, adapter.calls)
		}
	})

	t.Run("worker", func(t *testing.T) {
		runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
		runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime})
		installed, gateway := installEnableAndMintGateway(t, h, buildDangerousWorkerFixturePackage(t), "worker.view")
		call := CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
			BridgeChannelID: "bridge_rpc",
			GatewayToken:    gateway.GatewayToken, Method: "worker.echo", Params: map[string]any{"message": "hello"},
		}
		assertDangerousRouteConfirmation(t, h, &call)
		if runtime.calls != 1 {
			t.Fatalf("confirmed worker calls = %d", runtime.calls)
		}
	})
}

func assertDangerousRouteConfirmation(t *testing.T, h *Host, call *CallMethodRequest) {
	t.Helper()
	result, err := h.CallPluginMethod(hostTestContext(), *call)
	if !errors.Is(err, ErrConfirmationRequired) || !result.ConfirmationRequired {
		t.Fatalf("CallPluginMethod() result=%#v error=%v, want confirmation", result, err)
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(*call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(hostTestContext(), *call); err != nil {
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
			result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
				PluginInstanceID:  installed.PluginInstanceID,
				SurfaceInstanceID: "surface_rpc",

				BridgeChannelID: "bridge_rpc",
				GatewayToken:    gateway.GatewayToken,
				Method:          tc.method,
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
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OperationID == "" || result.StreamID == "" {
		t.Fatalf("subscription handles = %#v", result)
	}
	if err := adapter.last.Execution.Stream.Close(hostTestContext()); err != nil {
		t.Fatalf("Stream.Close() error = %v", err)
	}
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusCompleted)
	assertHostStreamStatus(t, h, result.StreamID, stream.StatusClosed)
}

func TestSubscriptionRegistrationBindingsAreIsolatedBetweenStores(t *testing.T) {
	operations := &mutatingOperationRegisterStore{Store: operation.NewMemoryStore()}
	streams := &recordingStreamRegisterStore{Store: stream.NewMemoryStore()}
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
		operations: operations, streams: streams,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, mutated := streams.binding.Target.Fields["operation_store_mutation"]; mutated ||
		len(streams.binding.Permissions.Required) == 0 || streams.binding.Permissions.Required[0] == "operation.store.mutated" {
		t.Fatalf("stream store received operation-store mutation: %#v", streams.binding)
	}
	operations.retained.Target.Fields["late_operation_store_mutation"] = true
	if _, mutated := streams.binding.Target.Fields["late_operation_store_mutation"]; mutated {
		t.Fatalf("operation and stream stores retained aliased bindings: %#v", streams.binding)
	}
	storedStream, err := streams.Store.Get(hostTestContext(), result.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	if _, mutated := storedStream.Target.Fields["late_operation_store_mutation"]; mutated {
		t.Fatalf("stored stream retained operation-store binding state: %#v", storedStream.ExecutionBinding)
	}
	if _, mutated := adapter.last.Execution.Target.Fields["late_operation_store_mutation"]; mutated {
		t.Fatalf("capability adapter retained operation-store binding state: %#v", adapter.last.Execution.ExecutionBinding)
	}
	if err := adapter.last.Execution.Stream.Close(hostTestContext()); err != nil {
		t.Fatal(err)
	}
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
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	}); err == nil {
		t.Fatal("CallPluginMethod() succeeded after stream registration failed")
	}
	page, err := operations.List(hostTestContext(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID, AllOwners: true})
	if err != nil {
		t.Fatal(err)
	}
	records := page.Records
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
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	}); err == nil || errors.Is(err, rollbackErr) {
		t.Fatalf("CallPluginMethod() error = %v, want opaque rollback failure", err)
	}
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	h.executions.mu.Unlock()
	if activeLeases != 1 {
		t.Fatalf("active execution leases = %d, want 1 until rollback repair", activeLeases)
	}
	if err := h.reconcilePendingExecutionSetups(hostTestContext(), installed.PluginInstanceID); err != nil {
		t.Fatalf("reconcilePendingExecutionSetups() error = %v", err)
	}
	page, err := operations.List(hostTestContext(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID, AllOwners: true})
	if err != nil {
		t.Fatal(err)
	}
	records := page.Records
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

func TestPendingExecutionSetupReconciliationDoesNotScanDurableHistory(t *testing.T) {
	operations := &countingOperationListStore{Store: operation.NewMemoryStore()}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{operations: operations})
	operations.listCalls = 0

	if err := h.reconcilePendingExecutionSetups(hostTestContext(), "plugini_no_pending_12345678"); err != nil {
		t.Fatalf("reconcilePendingExecutionSetups() error = %v", err)
	}
	if operations.listCalls != 0 {
		t.Fatalf("durable operation list calls = %d, want 0", operations.listCalls)
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
			ctx := hostTestContext()
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
				OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
			}
			if _, err := operations.Register(ctx, operation.RegisterRequest{OperationID: binding.OperationID, ExecutionBinding: binding}); err != nil {
				t.Fatal(err)
			}
			if _, err := streams.Register(ctx, stream.RegisterRequest{StreamID: binding.StreamID, ExecutionBinding: binding}); err != nil {
				t.Fatal(err)
			}
			if tc.operationStatus != operation.StatusRunning {
				if _, err := operations.Finish(ctx, operation.FinishRequest{
					OperationID: binding.OperationID, Status: tc.operationStatus, FailureCode: capability.ExecutionFailurePlatformFailed,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.streamStatus != stream.StatusOpen {
				if _, err := streams.Close(ctx, stream.CloseRequest{
					StreamID: binding.StreamID, Status: tc.streamStatus, FailureCode: capability.ExecutionFailurePlatformFailed,
				}); err != nil {
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
			if streamRecord.Reason != capability.ExecutionFailureMessage || streamRecord.FailureCode != capability.ExecutionFailurePlatformFailed {
				t.Fatalf("reconciled stream failure = %q/%q", streamRecord.FailureCode, streamRecord.Reason)
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
			ctx := hostTestContext()
			operationPath := filepath.Join(t.TempDir(), "operations.sqlite")
			operations, err := operation.NewSQLiteStore(ctx, operationPath)
			if err != nil {
				t.Fatal(err)
			}
			cancelable := true
			binding := capability.ExecutionBinding{
				InvocationID: "invoke_restart", AuditCorrelationID: "audit_restart", OperationID: "operation_restart",
				PluginID: "com.example.restart", PluginInstanceID: "plugini_restart", Method: "documents.archive", Execution: "operation",
				OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
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

func TestHostStartupTriggersBoundedTerminalRetentionPrune(t *testing.T) {
	operations := &countingOperationPruneStore{Store: operation.NewMemoryStore()}
	streams := &countingStreamPruneStore{Store: stream.NewMemoryStore()}
	startedAt := time.Now().UTC()
	newTestHostWithOptions(t, testHostOptions{operations: operations, streams: streams})
	operationCalls, operationLast := operations.snapshot()
	streamCalls, streamLast := streams.snapshot()
	if operationCalls != 1 || streamCalls != 1 {
		t.Fatalf("startup prune calls = operations:%d streams:%d", operationCalls, streamCalls)
	}
	if operationLast.Limit != operation.DefaultPruneLimit || streamLast.Limit != stream.DefaultPruneLimit {
		t.Fatalf("startup prune limits = operations:%d streams:%d", operationLast.Limit, streamLast.Limit)
	}
	if operationLast.MaxTerminalRecordsPerPlugin != operation.DefaultMaxTerminalRecordsPerPlugin ||
		streamLast.MaxTerminalRecordsPerPlugin != stream.DefaultMaxTerminalRecordsPerPlugin {
		t.Fatalf("startup terminal caps = operations:%d streams:%d", operationLast.MaxTerminalRecordsPerPlugin, streamLast.MaxTerminalRecordsPerPlugin)
	}
	operationCutoff := startedAt.Add(-operation.DefaultTerminalRetention)
	streamCutoff := startedAt.Add(-stream.DefaultTerminalRetention)
	if operationLast.Before.Before(operationCutoff) || streamLast.Before.Before(streamCutoff) {
		t.Fatalf("startup prune cutoffs are older than the retention policy: operation=%s stream=%s", operationLast.Before, streamLast.Before)
	}
}

func TestTerminalMaintenanceCoalescesConcurrentCompletionsAndRunsAfterInterval(t *testing.T) {
	operations := &countingOperationPruneStore{Store: operation.NewMemoryStore()}
	streams := &countingStreamPruneStore{Store: stream.NewMemoryStore()}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{operations: operations, streams: streams})
	operations.reset()
	streams.reset()

	h.executions.mu.Lock()
	now := h.executions.terminalMaintenanceNext
	h.executions.mu.Unlock()
	if now.IsZero() {
		t.Fatal("startup terminal maintenance did not publish its next deadline")
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	operations.configure(nil, entered, release)
	h.maintainTerminalExecutionRecords(hostTestContext(), now)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first terminal maintenance did not enter the operation store")
	}

	const concurrentCompletions = 64
	var wg sync.WaitGroup
	for range concurrentCompletions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.maintainTerminalExecutionRecords(hostTestContext(), now.Add(2*terminalExecutionMaintenanceInterval))
		}()
	}
	wg.Wait()
	if calls, _ := operations.snapshot(); calls != 1 {
		t.Fatalf("concurrent operation prune calls = %d, want 1", calls)
	}
	if calls, _ := streams.snapshot(); calls != 0 {
		t.Fatalf("stream prune entered before the single operation prune completed: calls=%d", calls)
	}
	close(release)
	h.lifecycleWG.Wait()
	operations.configure(nil, nil, nil)

	for range 100 {
		h.maintainTerminalExecutionRecords(hostTestContext(), now.Add(terminalExecutionMaintenanceInterval-time.Nanosecond))
	}
	if calls, _ := operations.snapshot(); calls != 1 {
		t.Fatalf("high-frequency operation prune calls within interval = %d, want 1", calls)
	}
	if calls, _ := streams.snapshot(); calls != 1 {
		t.Fatalf("high-frequency stream prune calls within interval = %d, want 1", calls)
	}

	h.maintainTerminalExecutionRecords(hostTestContext(), now.Add(terminalExecutionMaintenanceInterval))
	h.lifecycleWG.Wait()
	if calls, _ := operations.snapshot(); calls != 2 {
		t.Fatalf("operation prune calls after interval = %d, want 2", calls)
	}
	if calls, _ := streams.snapshot(); calls != 2 {
		t.Fatalf("stream prune calls after interval = %d, want 2", calls)
	}
}

func TestTerminalMaintenanceFailureStillRespectsInterval(t *testing.T) {
	operations := &countingOperationPruneStore{Store: operation.NewMemoryStore()}
	streams := &countingStreamPruneStore{Store: stream.NewMemoryStore()}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{operations: operations, streams: streams})
	operations.reset()
	streams.reset()
	h.executions.mu.Lock()
	now := h.executions.terminalMaintenanceNext
	h.executions.mu.Unlock()
	if now.IsZero() {
		t.Fatal("startup terminal maintenance did not publish its next deadline")
	}
	operations.configure(errors.New("operation prune unavailable"), nil, nil)

	h.maintainTerminalExecutionRecords(hostTestContext(), now)
	h.maintainTerminalExecutionRecords(hostTestContext(), now.Add(terminalExecutionMaintenanceInterval/2))
	h.lifecycleWG.Wait()
	if calls, _ := operations.snapshot(); calls != 1 {
		t.Fatalf("failed operation prune calls within interval = %d, want 1", calls)
	}
	if calls, _ := streams.snapshot(); calls != 1 {
		t.Fatalf("stream prune calls during failed maintenance interval = %d, want 1", calls)
	}

	operations.configure(nil, nil, nil)
	h.maintainTerminalExecutionRecords(hostTestContext(), now.Add(terminalExecutionMaintenanceInterval))
	h.lifecycleWG.Wait()
	if calls, _ := operations.snapshot(); calls != 2 {
		t.Fatalf("operation prune calls after failed interval = %d, want 2", calls)
	}
	if calls, _ := streams.snapshot(); calls != 2 {
		t.Fatalf("stream prune calls after failed interval = %d, want 2", calls)
	}
}

func TestTerminalMaintenanceDoesNotBlockCompletionAndCloseCancelsIt(t *testing.T) {
	operations := &countingOperationPruneStore{Store: operation.NewMemoryStore()}
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
		operations: operations,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	operations.reset()
	h.executions.mu.Lock()
	h.executions.terminalMaintenanceNext = time.Time{}
	h.executions.mu.Unlock()
	entered := make(chan struct{}, 1)
	operations.configure(nil, entered, make(chan struct{}))
	completed := make(chan error, 1)
	go func() { completed <- adapter.last.Execution.Operation.Complete(hostTestContext()) }()
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("operation completion was blocked by terminal retention pruning")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("terminal retention pruning did not start")
	}

	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Host.Close() did not cancel and wait for terminal retention pruning")
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusCompleted)
}

func TestHostCloseWaitsForDurableExecutionSetup(t *testing.T) {
	tests := []struct {
		name          string
		packageBytes  func(*testing.T) []byte
		surfaceID     string
		method        string
		params        map[string]any
		blockStream   bool
		wantOperation operation.Status
		wantStream    stream.Status
	}{
		{
			name: "operation register", packageBytes: buildOperationRPCFixturePackage,
			surfaceID: "operation.view", method: "documents.archive", params: map[string]any{"document_id": "doc-1"},
			wantOperation: operation.StatusFailed,
		},
		{
			name: "stream register", packageBytes: buildSubscriptionRPCFixturePackage,
			surfaceID: "subscription.view", method: "logs.tail", blockStream: true,
			wantOperation: operation.StatusFailed, wantStream: stream.StatusFailed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			operationStore := operation.NewMemoryStore()
			streamStore := stream.NewMemoryStore()
			registerEntered := make(chan struct{}, 1)
			registerRelease := make(chan struct{})
			var operations operation.Store = operationStore
			var streams stream.Store = streamStore
			if tc.blockStream {
				streams = &blockingStreamRegisterStore{Store: streamStore, entered: registerEntered, release: registerRelease}
			} else {
				operations = &blockingOperationRegisterStore{Store: operationStore, entered: registerEntered, release: registerRelease}
			}
			invokeEntered := make(chan struct{}, 1)
			invokeRelease := make(chan struct{})
			adapter := &recordingCapabilityAdapter{
				result: capability.Result{Data: map[string]any{}}, invokeEntered: invokeEntered, invokeRelease: invokeRelease,
			}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: adapter,
				operations: operations, streams: streams,
			})
			installed, gateway := installEnableAndMintGateway(t, h, tc.packageBytes(t), tc.surfaceID)
			callResult := make(chan error, 1)
			go func() {
				_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
					PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
					BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: tc.method,
					Params: tc.params,
				})
				callResult <- err
			}()
			select {
			case <-registerEntered:
			case <-time.After(time.Second):
				t.Fatal("execution setup did not reach the blocked durable register")
			}

			closed := make(chan error, 1)
			go func() { closed <- h.Close() }()
			select {
			case err := <-closed:
				t.Fatalf("Host.Close() overtook durable execution setup: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			close(registerRelease)
			select {
			case <-invokeEntered:
			case <-time.After(time.Second):
				t.Fatal("capability dispatch did not start after durable setup completed")
			}
			deadline := time.Now().Add(time.Second)
			for {
				h.lifecycleMu.RLock()
				closedState := h.closed
				h.lifecycleMu.RUnlock()
				if closedState {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Host.Close() did not publish the closed lifecycle state")
				}
				time.Sleep(time.Millisecond)
			}
			close(invokeRelease)
			select {
			case err := <-callResult:
				if err == nil {
					t.Fatal("execution succeeded after Host.Close() revoked its lease")
				}
			case <-time.After(time.Second):
				t.Fatal("execution did not return after Host.Close()")
			}
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Host.Close() did not finish")
			}

			page, err := operationStore.List(hostTestContext(), operation.ListRequest{PluginInstanceID: installed.PluginInstanceID, AllOwners: true})
			if err != nil || len(page.Records) != 1 || page.Records[0].Status != tc.wantOperation {
				t.Fatalf("durable operation state = %#v, %v", page.Records, err)
			}
			if tc.wantStream != "" {
				records, err := streamStore.List(hostTestContext(), stream.ListRequest{PluginInstanceID: installed.PluginInstanceID, AllOwners: true})
				if err != nil || len(records) != 1 || records[0].Status != tc.wantStream {
					t.Fatalf("durable stream state = %#v, %v", records, err)
				}
			}
			assertNoActiveExecutionState(t, h, "host close execution setup")
		})
	}
}

func TestDurableReconciliationRejectsConflictingTerminalPairs(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	binding := capability.ExecutionBinding{
		InvocationID: "invoke_conflict", AuditCorrelationID: "audit_conflict", OperationID: "operation_conflict", StreamID: "stream_conflict",
		PluginID: "com.example.conflict", PluginInstanceID: "plugini_conflict", Method: "logs.tail", Execution: "subscription",
		OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
	}
	if _, err := h.adapters.Operations.Register(hostTestContext(), operation.RegisterRequest{OperationID: binding.OperationID, ExecutionBinding: binding}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Streams.Register(hostTestContext(), stream.RegisterRequest{StreamID: binding.StreamID, ExecutionBinding: binding}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Finish(hostTestContext(), operation.FinishRequest{OperationID: binding.OperationID, Status: operation.StatusCompleted}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Streams.Close(hostTestContext(), stream.CloseRequest{
		StreamID: binding.StreamID, Status: stream.StatusFailed, FailureCode: capability.ExecutionFailurePlatformFailed,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.reconcileDurableExecutionStates(hostTestContext()); !errors.Is(err, errExecutionTerminalConflict) {
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
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.last.Execution.Stream.Close(hostTestContext()); !errors.Is(err, finishErr) {
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
	if err := adapter.last.Execution.Stream.Close(hostTestContext()); err != nil {
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
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-start
		errs <- adapter.last.Execution.Stream.Close(hostTestContext())
	}()
	go func() {
		<-start
		errs <- adapter.last.Execution.Stream.Fail(hostTestContext(), capability.ExecutionFailureAdapterFailed, errors.New("adapter failed"))
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
	operationRecord, err := h.adapters.Operations.Get(hostTestContext(), result.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	streamRecord, err := h.adapters.Streams.Get(hostTestContext(), result.StreamID)
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
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := (hostRuntimeStreamSink{executions: h.executions}).CloseRuntimeStream(hostTestContext(), result.StreamID); err != nil {
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
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "logs.tail",
	}); err != nil {
		t.Fatal(err)
	}
	sink := adapter.last.Execution.Stream.(*hostStreamSink)
	sink.maxBytes = 20
	if err := sink.Append(hostTestContext(), map[string]any{"line": "a"}); !errors.Is(err, streams.err) {
		t.Fatalf("first Append() error = %v, want %v", err, streams.err)
	}
	if err := sink.Append(hostTestContext(), map[string]any{"line": "abc"}); err != nil {
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
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}

	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	canceled, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user", Now: now})
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

func TestCancelOperationDoesNotForwardStoreOwnedBindingToAdapter(t *testing.T) {
	operations := &retainingCancelOperationStore{Store: operation.NewMemoryStore()}
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{Data: map[string]any{}},
		mutateCancellation: func(binding *capability.ExecutionBinding) {
			binding.Target.Fields["cancel_adapter_mutation"] = true
			binding.Permissions.Required[0] = "cancel.adapter.mutated"
		},
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo",
		capabilityAdapter: capabilityAdapter, operations: operations,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "documents.archive",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := operations.retained.Target.Fields["cancel_adapter_mutation"]; ok || operations.retained.Permissions.Required[0] == "cancel.adapter.mutated" {
		t.Fatalf("cancellation adapter mutated store-owned binding: %#v", operations.retained)
	}
}

func TestOperationManagementRequiresExactOwnerScope(t *testing.T) {
	operations := operation.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{operations: operations})
	owner := operationOwnerScope(sessionctx.Context{OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash"})
	other := operation.OwnerScope{OwnerSessionHash: "session_other", OwnerUserHash: "user_other", OwnerEnvHash: "env_other", SessionChannelIDHash: "channel_other"}
	register := func(operationID string, scope operation.OwnerScope) {
		t.Helper()
		if _, err := operations.Register(context.Background(), operation.RegisterRequest{
			OperationID: operationID,
			ExecutionBinding: capability.ExecutionBinding{
				InvocationID: "invoke_" + operationID, PluginID: "com.example.plugin", PluginInstanceID: "plugini_scope",
				Method: "documents.archive", Execution: string(manifest.MethodExecutionOperation),
				OwnerSessionHash: scope.OwnerSessionHash, OwnerUserHash: scope.OwnerUserHash,
				OwnerEnvHash: scope.OwnerEnvHash, SessionChannelIDHash: scope.SessionChannelIDHash,
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	register("op_owned", owner)
	register("op_other", other)

	listed, err := h.ListOperations(hostTestContext(), ListOperationsRequest{PluginInstanceID: "plugini_scope"})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Operations) != 1 || listed.Operations[0].OperationID != "op_owned" {
		t.Fatalf("owner-scoped operations = %#v", listed.Operations)
	}
	if _, err := h.GetOperation(hostTestContext(), "op_other"); !errors.Is(err, operation.ErrNotFound) {
		t.Fatalf("cross-owner GetOperation() error = %v, want ErrNotFound", err)
	}
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: "op_other", Reason: "cross-owner"}); !errors.Is(err, operation.ErrNotFound) {
		t.Fatalf("cross-owner CancelOperation() error = %v, want ErrNotFound", err)
	}
	otherRecord, err := operations.Get(context.Background(), "op_other")
	if err != nil || otherRecord.Status != operation.StatusRunning {
		t.Fatalf("cross-owner operation changed: %#v, %v", otherRecord, err)
	}
	owned, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: "op_owned", Reason: "owner"})
	if err != nil || owned.Status != operation.StatusCancelRequested {
		t.Fatalf("owner CancelOperation() = %#v, %v", owned, err)
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
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
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
	if err := capabilityAdapter.last.Execution.Operation.Cancel(hostTestContext(), "adapter acknowledged cancellation"); err != nil {
		t.Fatalf("Operation.Cancel() error = %v", err)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusCanceled)
	if err := capabilityAdapter.last.Execution.Operation.Cancel(hostTestContext(), "duplicate"); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("duplicate Operation.Cancel() error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
}

func TestCancelOperationAckTimeoutForcesTerminalState(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		record, err := h.GetOperation(hostTestContext(), started.OperationID)
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

func TestCancelOperationAckTimeoutReleasesExecutionAfterPersistentStoreFailureAndAllowsRetry(t *testing.T) {
	finishErr := errors.New("operation terminal store unavailable")
	operations := &controlledOperationFinishStore{Store: operation.NewMemoryStore(), err: finishErr, failing: true}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
		operations: operations,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	waitForOperationFinishCalls(t, operations, 1)
	h.lifecycleWG.Wait()
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusCancelRequested)
	h.executions.mu.Lock()
	activeLeases := len(h.executions.leases)
	activePlugins := len(h.executions.leasesByPlugin)
	activeOperations := len(h.executions.operations)
	activeStreams := len(h.executions.streams)
	activeQuotas := len(h.executions.activeByQuotaKey)
	h.executions.mu.Unlock()
	if activeLeases != 0 || activePlugins != 0 || activeOperations != 0 || activeStreams != 0 || activeQuotas != 0 {
		t.Fatalf("ack timeout retained execution state: leases=%d plugins=%d operations=%d streams=%d quotas=%d", activeLeases, activePlugins, activeOperations, activeStreams, activeQuotas)
	}

	operations.setFailing(false)
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "retry"}); err != nil {
		t.Fatal(err)
	}
	waitForHostOperationStatus(t, h, started.OperationID, operation.StatusCanceled)
	h.lifecycleWG.Wait()
	if calls := operations.finishCalls(); calls != 2 {
		t.Fatalf("operation terminal writes = %d, want 2", calls)
	}
}

func TestDetachedCancelAckTimeoutStopsAfterFailureAndAllowsRetry(t *testing.T) {
	finishErr := errors.New("operation terminal store unavailable")
	operations := &controlledOperationFinishStore{Store: operation.NewMemoryStore(), err: finishErr, failing: true}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, operations: operations})
	cancelable := true
	operationID := "operation_detached_12345678"
	_, err := operations.Register(hostTestContext(), operation.RegisterRequest{
		OperationID: operationID,
		ExecutionBinding: capability.ExecutionBinding{
			InvocationID: "invoke_detached_12345678", OperationID: operationID,
			PluginID: "com.example.detached", PluginInstanceID: "plugini_detached_12345678", Method: "tasks.run",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
		},
		Cancelable: &cancelable, CancelAckTimeoutMS: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: operationID, Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	waitForOperationFinishCalls(t, operations, 1)
	h.lifecycleWG.Wait()
	assertHostOperationStatus(t, h, operationID, operation.StatusCancelRequested)
	if _, loaded := h.detachedCancelJobs.Load(operationID); loaded {
		t.Fatal("detached cancellation job remained after terminal store failure")
	}

	operations.setFailing(false)
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: operationID, Reason: "retry"}); err != nil {
		t.Fatal(err)
	}
	waitForHostOperationStatus(t, h, operationID, operation.StatusCanceled)
	h.lifecycleWG.Wait()
}

func TestHostCloseStopsDetachedCancelAckTimeout(t *testing.T) {
	operations := operation.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, operations: operations})
	cancelable := true
	operationID := "operation_detached_close_12345678"
	if _, err := operations.Register(hostTestContext(), operation.RegisterRequest{
		OperationID: operationID,
		ExecutionBinding: capability.ExecutionBinding{
			InvocationID: "invoke_detached_close_12345678", OperationID: operationID,
			PluginID: "com.example.detached", PluginInstanceID: "plugini_detached_close_12345678", Method: "tasks.run",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
		},
		Cancelable: &cancelable, CancelAckTimeoutMS: 60_000,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: operationID, Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, loaded := h.detachedCancelJobs.Load(operationID); !loaded {
		t.Fatal("detached cancellation job was not registered")
	}
	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Host.Close() did not stop the detached cancellation job")
	}
	if _, loaded := h.detachedCancelJobs.Load(operationID); loaded {
		t.Fatal("Host.Close() retained the detached cancellation job")
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
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID}); !errors.Is(err, operation.ErrNotCancelable) {
		t.Fatalf("CancelOperation() error = %v, want %v", err, operation.ErrNotCancelable)
	}
	if capabilityAdapter.cancelCalls != 0 {
		t.Fatalf("non-cancelable adapter cancel calls = %d, want 0", capabilityAdapter.cancelCalls)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusRunning)
	if err := capabilityAdapter.last.Execution.Operation.Complete(hostTestContext()); err != nil {
		t.Fatal(err)
	}
}

func TestCancelSurfaceOperationRejectsScopeMismatch(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := CancelSurfaceOperationRequest{
		OperationID: started.OperationID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", Reason: "user",
	}
	tests := []struct {
		name    string
		context func() context.Context
		mutate  func(*CancelSurfaceOperationRequest)
	}{
		{name: "surface", mutate: func(req *CancelSurfaceOperationRequest) { req.SurfaceInstanceID = "surface_other" }},
		{name: "owner session", context: func() context.Context {
			return hostTestContextWith("session_other", "user_hash", "env_hash", "channel_hash")
		}},
		{name: "owner user", context: func() context.Context {
			return hostTestContextWith("session_hash", "user_other", "env_hash", "channel_hash")
		}},
		{name: "session channel", context: func() context.Context {
			return hostTestContextWith("session_hash", "user_hash", "env_hash", "channel_other")
		}},
		{name: "bridge channel", mutate: func(req *CancelSurfaceOperationRequest) { req.BridgeChannelID = "bridge_other" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			ctx := hostTestContext()
			if tc.context != nil {
				ctx = tc.context()
			}
			if _, err := h.CancelSurfaceOperation(ctx, req); !errors.Is(err, bridge.ErrTokenAudience) {
				t.Fatalf("CancelSurfaceOperation() error = %v, want %v", err, bridge.ErrTokenAudience)
			}
		})
	}
	if capabilityAdapter.cancelCalls != 0 {
		t.Fatalf("mismatched surface cancellation reached adapter %d times", capabilityAdapter.cancelCalls)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusRunning)
	if _, err := h.CancelSurfaceOperation(hostTestContext(), base); err != nil {
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
	requestContext, cancelRequest := context.WithCancel(hostTestContext())
	started, err := h.CallPluginMethod(requestContext, CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	cancelRequest()
	if err := capabilityAdapter.last.Execution.Operation.Complete(hostTestContext()); err != nil {
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
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID),
		Reason:                     "disabled by owner",
	}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	assertHostOperationStatus(t, h, started.OperationID, operation.StatusCanceled)
	if err := capabilityAdapter.last.Execution.Operation.Cancel(hostTestContext(), "late adapter acknowledgement"); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("Operation.Cancel() after revoke error = %v, want %v", err, capability.ErrExecutionRevoked)
	}
}

func TestCancelOperationUsesRouteLocalExecutionRegistration(t *testing.T) {
	t.Run("core action", func(t *testing.T) {
		coreAdapter := &recordingCoreActionAdapter{result: capability.Result{Data: map[string]any{"opened": true}}}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, coreActions: coreAdapter})
		installed, gateway := installEnableAndMintGateway(t, h, buildCoreActionOperationFixturePackage(t), "core.view")
		started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
			BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
			Method: "core.open", Params: map[string]any{"target": "settings"},
		})
		if err != nil {
			t.Fatalf("CallPluginMethod() error = %v", err)
		}
		coreRecord, err := h.GetOperation(hostTestContext(), started.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if coreRecord.RouteKind != capability.RouteCoreAction || coreRecord.Contract != nil || coreRecord.Permissions.Required == nil || coreRecord.Permissions.Granted == nil {
			t.Fatalf("core action execution binding mismatch: %#v", coreRecord.ExecutionBinding)
		}
		if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
			t.Fatalf("CancelOperation() error = %v", err)
		}
		if coreAdapter.cancelCalls != 1 || coreAdapter.lastCancellation.OperationID != started.OperationID {
			t.Fatalf("core action cancellation mismatch: calls=%d request=%#v", coreAdapter.cancelCalls, coreAdapter.lastCancellation)
		}
		if err := coreAdapter.last.Execution.Operation.Cancel(hostTestContext(), "acknowledged"); err != nil {
			t.Fatalf("Operation.Cancel() error = %v", err)
		}
	})

	t.Run("worker", func(t *testing.T) {
		runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
		runtime.result = capability.Result{Data: map[string]any{"from_worker": true}}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime})
		installed, gateway := installEnableAndMintGateway(t, h, buildWorkerOperationFixturePackage(t), "worker.view")
		started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
			BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
			Method: "worker.echo", Params: map[string]any{"message": "hello"},
		})
		if err != nil {
			t.Fatalf("CallPluginMethod() error = %v", err)
		}
		workerRecord, err := h.GetOperation(hostTestContext(), started.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if workerRecord.RouteKind != capability.RouteWorker || workerRecord.Contract != nil || workerRecord.Permissions.Required == nil || workerRecord.Permissions.Granted == nil {
			t.Fatalf("worker execution binding mismatch: %#v", workerRecord.ExecutionBinding)
		}
		if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"}); err != nil {
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
	const sensitiveAdapterFailure = "adapter token secret at /Users/private/runtime.sock"
	cases := []struct {
		name          string
		adapter       *recordingCapabilityAdapter
		internalCause string
	}{
		{name: "adapter error", adapter: &recordingCapabilityAdapter{err: errors.New(sensitiveAdapterFailure)}, internalCause: sensitiveAdapterFailure},
		{name: "response schema failure", adapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"unexpected": true}}}},
		{name: "adapter panic", adapter: &recordingCapabilityAdapter{panicValue: "adapter panic"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diagnostics := &diagnosticSink{}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: tc.adapter, diagnostics: diagnostics,
			})
			installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
			if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
				PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
				BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
				Method: "documents.archive",
			}); err == nil {
				t.Fatal("CallPluginMethod() expected failure")
			}
			if tc.adapter.last.Execution.Operation == nil {
				t.Fatal("adapter did not receive a Host-owned operation sink")
			}
			operationID := tc.adapter.last.Execution.Operation.ID()
			assertHostOperationStatus(t, h, operationID, operation.StatusFailed)
			record, err := h.GetOperation(hostTestContext(), operationID)
			if err != nil {
				t.Fatal(err)
			}
			if record.Reason != executionFailedReason {
				t.Fatalf("durable failure reason = %q, want %q", record.Reason, executionFailedReason)
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if tc.internalCause != "" && strings.Contains(string(encoded), tc.internalCause) {
				t.Fatalf("durable operation leaked internal cause: %s", encoded)
			}
			var failureDiagnostic *observability.DiagnosticEvent
			for index := range diagnostics.events {
				if diagnostics.events[index].Type == "plugin.execution.failed" {
					failureDiagnostic = &diagnostics.events[index]
					break
				}
			}
			if failureDiagnostic == nil || failureDiagnostic.Message != executionFailedReason {
				t.Fatalf("execution failure diagnostic mismatch: %#v", diagnostics.events)
			}
			if tc.internalCause != "" {
				failure := failureDiagnostic.Failure
				if failure.Code != observability.FailureAction || failure.Component != observability.FailureComponentExecution || failure.Operation != "execution.fail" || strings.Contains(fmt.Sprint(failureDiagnostic), errRPCUnavailable.Error()) {
					t.Fatalf("execution failure retained adapter-controlled cause: %#v", failureDiagnostic)
				}
			}
			if err := tc.adapter.last.Execution.Operation.Complete(hostTestContext()); !errors.Is(err, capability.ErrExecutionRevoked) {
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
			if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
				PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
				BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
				Method: "echo.ping", Params: tc.params,
			}); err == nil {
				t.Fatal("CallPluginMethod() expected rejection")
			}
			event, ok := audits.lastEvent("plugin.method.rejected")
			if !ok || event.Details["reason"] != tc.wantReason || event.Details["method"] != "echo.ping" {
				t.Fatalf("negative audit mismatch: %#v", audits.events)
			}
			if len(diagnostics.events) != 1 || diagnostics.events[0].Type != "plugin.method.rejected" || diagnostics.events[0].Details.Reason != tc.wantReason {
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
					"context": fixtureClosedObject(map[string]any{
						"entries": map[string]any{"type": "array", "items": fixtureClosedObject(map[string]any{
							"secret_token": map[string]any{"type": "string", "const": capability.ResponseRedactedValue},
						}, []string{"secret_token"})},
					}, []string{"entries"}),
					"password": map[string]any{"type": "string", "const": capability.ResponseRedactedValue},
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
		_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
			PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
			BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
			Method: "echo.ping",
		})
		return err
	}

	t.Run("declared error", func(t *testing.T) {
		adapter := &recordingCapabilityAdapter{err: &mutation.Error{
			Outcome: mutation.OutcomeNotCommitted,
			Err:     mustCapabilityBusinessError(t, "DOCUMENT_NOT_FOUND", "adapter detail", map[string]any{"document_id": "doc-1"}),
		}}
		h, installed, gateway, audits := newHost(t, adapter)
		err := call(h, installed, gateway)
		validated, ok := AsValidatedCapabilityBusinessError(err)
		if !ok || validated.Code != "DOCUMENT_NOT_FOUND" || validated.Details["document_id"] != "doc-1" {
			t.Fatalf("validated business error mismatch: %#v, ok=%v, err=%v", validated, ok, err)
		}
		var businessError *capability.BusinessError
		if !errors.As(err, &businessError) || businessError.Code != "DOCUMENT_NOT_FOUND" || businessError.Message != "Document not found" ||
			businessError.CapabilityID != "example.capability.echo" || businessError.CapabilityVersion != "1.0.0" ||
			len(businessError.DetailSchemaSHA256) != 64 || businessError.Details["document_id"] != "doc-1" {
			t.Fatalf("business error mismatch: %#v, err=%v", businessError, err)
		}
		if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "business_error" {
			t.Fatalf("missing business error audit: %#v", audits.events)
		}
		if got := mutation.ForError(err); got != mutation.OutcomeNotCommitted {
			t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeNotCommitted)
		}
		validated.Details["document_id"] = "tampered"
		again, ok := AsValidatedCapabilityBusinessError(err)
		if !ok || again.Details["document_id"] != "doc-1" {
			t.Fatalf("validated business error accessor exposed mutable state: %#v", again)
		}
	})

	t.Run("typed details", func(t *testing.T) {
		original := &responseBoundaryBusinessContext{Entries: []*responseBoundaryBusinessEntry{{SecretToken: "adapter-secret"}}}
		adapter := &recordingCapabilityAdapter{err: &capability.BusinessError{
			Code: "DOCUMENT_NOT_FOUND", Message: "adapter detail",
			Details: map[string]any{"document_id": "doc-1", "context": original},
		}}
		h, installed, gateway, _ := newHost(t, adapter)
		err := call(h, installed, gateway)
		var businessError *capability.BusinessError
		if !errors.As(err, &businessError) || businessError.Details == nil {
			t.Fatalf("CallPluginMethod() error = %v, want declared BusinessError", err)
		}
		raw, marshalErr := json.Marshal(businessError.Details)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if got := string(raw); strings.Contains(got, "adapter-secret") || !strings.Contains(got, capability.ResponseRedactedValue) {
			t.Fatalf("typed business details were not normalized before redaction: %s", got)
		}
		if original.Entries[0].SecretToken != "adapter-secret" {
			t.Fatalf("adapter-owned business details were mutated: %#v", original)
		}
	})

	t.Run("non JSON details fail before redaction", func(t *testing.T) {
		adapter := &recordingCapabilityAdapter{err: &capability.BusinessError{
			Code: "DOCUMENT_NOT_FOUND", Message: "adapter detail",
			Details: map[string]any{"document_id": "doc-1", "password": make(chan int)},
		}}
		h, installed, gateway, _ := newHost(t, adapter)
		err := call(h, installed, gateway)
		if !errors.Is(err, ErrMethodResponseContract) {
			t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
		}
	})

	t.Run("redacted details remain within response limit", func(t *testing.T) {
		contract := fixtureVerifiedCapabilityContract(t, "example.capability.echo").Contract
		contract.Errors = []capabilitycontract.BusinessError{{
			Code:    "DETAILS_TOO_LARGE",
			Message: "Details are too large",
			DetailsSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []any{"env"},
				"properties": map[string]any{
					"env": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
			},
		}}
		verified := verifyFixtureCapabilityContract(t, contract)
		environment := make([]any, 30000)
		for index := range 30000 {
			environment[index] = "API_TOKEN="
		}
		adapter := &recordingCapabilityAdapter{err: mustCapabilityBusinessError(t,
			"DETAILS_TOO_LARGE", "adapter detail", map[string]any{"env": environment},
		)}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			developerMode: true, localGenerated: true, capabilityContract: &verified, capabilityAdapter: adapter,
		})
		installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
			t, rpcFixtureManifestJSON("1.0.0", "RPC"), "RPC", "echo", verified.Pin,
		), "rpc.view")
		err := call(h, installed, gateway)
		if !errors.Is(err, ErrMethodResponseContract) {
			t.Fatalf("CallPluginMethod() error = %v, want ErrMethodResponseContract", err)
		}
		if _, ok := AsValidatedCapabilityBusinessError(err); ok {
			t.Fatal("oversized redacted details retained a business-error attestation")
		}
	})

	t.Run("typed nil", func(t *testing.T) {
		var businessError *capability.BusinessError
		adapter := &recordingCapabilityAdapter{err: businessError}
		h, installed, gateway, _ := newHost(t, adapter)
		err := call(h, installed, gateway)
		if !errors.Is(err, ErrMethodResponseContract) || errors.Is(err, ErrMethodAdapterPanic) {
			t.Fatalf("CallPluginMethod() error = %v, want response contract failure", err)
		}
	})

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "undeclared code", err: mustCapabilityBusinessError(t, "UNKNOWN", "unknown", nil)},
		{name: "invalid details", err: mustCapabilityBusinessError(t, "DOCUMENT_NOT_FOUND", "invalid", map[string]any{"unexpected": true})},
		{name: "panicking business error As", err: panickingBusinessErrorAs{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &recordingCapabilityAdapter{err: tc.err}
			h, installed, gateway, audits := newHost(t, adapter)
			if err := call(h, installed, gateway); !errors.Is(err, ErrMethodResponseContract) || errors.Is(err, ErrMethodAdapterPanic) {
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
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "documents.archive",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}

	canceled, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: started.OperationID, Reason: "user"})
	if !errors.Is(err, ErrOperationCancelDispatchFailed) {
		t.Fatalf("CancelOperation() error = %v, want %v", err, ErrOperationCancelDispatchFailed)
	}
	if got := mutation.ForError(err); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
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

	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    "plugin_gateway_token.invalid",
		Method:          "echo.ping",
	}); err == nil {
		t.Fatal("CallPluginMethod() expected token error")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "token_invalid" {
		t.Fatalf("missing token rejection audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details.Reason != "token_invalid" {
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
	if _, err := h.CallPluginMethod(hostTestContextWith("other_session", "user_hash", "env_hash", "channel_hash"), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "echo.ping",
	}); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("CallPluginMethod() error = %v, want %v", err, bridge.ErrTokenAudience)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "remote_mismatch" {
		t.Fatalf("missing remote mismatch audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details.Reason != "remote_mismatch" {
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
	record, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	record.TrustState = registry.TrustUnavailable
	record.TrustAssessment.TrustState = registry.TrustUnavailable
	if _, err := h.adapters.Registry.PutPlugin(hostTestContext(), record, registry.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken, Method: "echo.ping",
	}); err == nil {
		t.Fatal("CallPluginMethod() accepted a trust-unavailable plugin")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "trust_unavailable" {
		t.Fatalf("missing trust-unavailable audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details.Reason != "trust_unavailable" {
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

	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "echo.ping",
	}); !errors.Is(err, security.ErrPolicyDenied) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrPolicyDenied", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "policy_denied" {
		t.Fatalf("missing policy rejection audit: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details.Reason != "policy_denied" {
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
	beforePolicy, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := h.PutSecurityPolicy(hostTestContext(), PutSecurityPolicyRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedPolicyRevision:     beforePolicy.PolicyRevision,
		ExpectedManagementRevision: beforePolicy.ManagementRevision,
		ExpectedRevokeEpoch:        beforePolicy.RevokeEpoch,
		DeniedMethods:              []string{"echo.ping"},
	})
	if err != nil {
		t.Fatalf("PutSecurityPolicy() error = %v", err)
	}
	if len(policy.Policy.DeniedMethods) != 1 || policy.Policy.DeniedMethods[0] != "echo.ping" {
		t.Fatalf("policy mismatch: %#v", policy)
	}
	afterPolicy, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if afterPolicy.PolicyRevision <= beforePolicy.PolicyRevision || afterPolicy.RevokeEpoch <= beforePolicy.RevokeEpoch {
		t.Fatalf("security policy update did not bump policy/revoke revisions: before=%#v after=%#v", beforePolicy, afterPolicy)
	}
	_, gateway := openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.view")
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "echo.ping",
	}); !errors.Is(err, security.ErrPolicyDenied) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrPolicyDenied", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called before security policy allowed it: %d", capabilityAdapter.calls)
	}

	if _, err := h.DeleteSecurityPolicy(hostTestContext(), DeleteSecurityPolicyRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedPolicyRevision:     afterPolicy.PolicyRevision,
		ExpectedManagementRevision: afterPolicy.ManagementRevision,
		ExpectedRevokeEpoch:        afterPolicy.RevokeEpoch,
	}); err != nil {
		t.Fatalf("DeleteSecurityPolicy() error = %v", err)
	}
	_, gateway = openSurfaceAndMintGateway(t, h, installed.PluginInstanceID, "rpc.view")
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "echo.ping",
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "danger.run",
		Params:          map[string]any{"target": "db"},
	}

	result, err := h.CallPluginMethod(hostTestContext(), call)
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
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details.Reason != "confirmation_required" {
		t.Fatalf("missing confirmation rejection diagnostic: %#v", diagnostics.events)
	}

	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
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
	confirmed, err := h.CallPluginMethod(hostTestContext(), call)
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "danger.run",
		Params:          map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatal(err)
	}

	reject := RejectMethodConfirmationRequest{
		PluginInstanceID:  call.PluginInstanceID,
		SurfaceInstanceID: call.SurfaceInstanceID,

		BridgeChannelID: call.BridgeChannelID,
		GatewayToken:    call.GatewayToken,
		ConfirmationID:  confirmation.ConfirmationID,
	}
	mismatched := reject
	mismatched.BridgeChannelID = "bridge_other"
	if _, err := h.RejectMethodConfirmation(hostTestContext(), mismatched); !errors.Is(err, bridge.ErrTokenAudience) {
		t.Fatalf("RejectMethodConfirmation(scope mismatch) error = %v, want ErrTokenAudience", err)
	}
	if listed, err := confirmationIntents.ListConfirmationIntents(hostTestContext(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil || len(listed) != 1 {
		t.Fatalf("scope mismatch consumed confirmation: listed=%#v err=%v", listed, err)
	}

	result, err := h.RejectMethodConfirmation(hostTestContext(), reject)
	if err != nil {
		t.Fatalf("RejectMethodConfirmation() error = %v", err)
	}
	if !result.Rejected {
		t.Fatalf("rejection result mismatch: %#v", result)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("rejected confirmation dispatched adapter %d times", capabilityAdapter.calls)
	}
	if listed, err := confirmationIntents.ListConfirmationIntents(hostTestContext(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil || len(listed) != 0 {
		t.Fatalf("rejected confirmation remained pending: listed=%#v err=%v", listed, err)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "confirmation_rejected" {
		t.Fatalf("confirmation rejection audit mismatch: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details.Reason != "confirmation_rejected" {
		t.Fatalf("confirmation rejection diagnostic mismatch: %#v", diagnostics.events)
	}

	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("CallPluginMethod(rejected confirmation) error = %v, want ErrConfirmationInvalid", err)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("rejected confirmation replay dispatched adapter %d times", capabilityAdapter.calls)
	}
}

func TestRejectMethodConfirmationReportsUnknownAfterDurableReject(t *testing.T) {
	reportErr := errors.New("audit unavailable")
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
	confirmationIntents := security.NewMemoryConfirmationIntentStore()
	audit := &switchableAuditSink{}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:       true,
		localGenerated:      true,
		capabilityID:        "example.capability.echo",
		capabilityAdapter:   capabilityAdapter,
		confirmationIntents: confirmationIntents,
		audit:               audit,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousRPCFixturePackage(t), "danger.view")
	call := CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",
		BridgeChannelID:   "bridge_rpc",
		GatewayToken:      gateway.GatewayToken,
		Method:            "danger.run",
		Params:            map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	audit.setErr(reportErr)

	result, err := h.RejectMethodConfirmation(hostTestContext(), RejectMethodConfirmationRequest{
		PluginInstanceID:  call.PluginInstanceID,
		SurfaceInstanceID: call.SurfaceInstanceID,
		BridgeChannelID:   call.BridgeChannelID,
		GatewayToken:      call.GatewayToken,
		ConfirmationID:    confirmation.ConfirmationID,
	})
	if !result.Rejected || !errors.Is(err, ErrSecurityEventPersistence) {
		t.Fatalf("RejectMethodConfirmation() result=%#v error=%v", result, err)
	}
	if outcome, ok := mutation.Explicit(err); !ok || outcome != mutation.OutcomeUnknown {
		t.Fatalf("RejectMethodConfirmation() outcome=(%q, %v), want unknown", outcome, ok)
	}
	if listed, listErr := confirmationIntents.ListConfirmationIntents(hostTestContext(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); listErr != nil || len(listed) != 0 {
		t.Fatalf("durably rejected confirmation remained pending: listed=%#v err=%v", listed, listErr)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("durably rejected confirmation dispatched adapter %d times", capabilityAdapter.calls)
	}
}

func TestPrepareMethodConfirmationRunsRiskPreflightAndBindsPlanHash(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{Data: map[string]any{"started": true}},
		resultsByTarget: map[string]capability.Result{
			"tasks.start.preflight": {Data: capability.RiskPlan{
				SchemaVersion: capability.RiskPlanSchemaVersion,
				Summary:       "Start task",
				RiskFlags: []capability.RiskFlag{{
					ID: "executes_task", Severity: capability.RiskSeverityLow, Summary: "Executes task",
				}},
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "tasks.start",
		Params:          map[string]any{"task_id": "task_1"},
	}

	result, err := h.CallPluginMethod(hostTestContext(), call)
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrConfirmationRequired", err)
	}
	if !result.ConfirmationRequired || result.RequestHash == "" {
		t.Fatalf("confirmation response mismatch: %#v", result)
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter should not run before prepare confirmation, calls=%d", capabilityAdapter.calls)
	}

	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	if confirmation.PlanHash == "" || confirmation.RequestHash != result.RequestHash {
		t.Fatalf("confirmation plan mismatch: %#v", confirmation)
	}
	plan, ok := confirmation.Plan.(capability.RiskPlan)
	if !ok || plan.SchemaVersion != capability.RiskPlanSchemaVersion || plan.Summary != "Start task" {
		t.Fatalf("confirmation plan = %#v", confirmation.Plan)
	}
	if capabilityAdapter.calls != 1 || capabilityAdapter.last.Execution.TargetMethod != "tasks.start.preflight" || capabilityAdapter.last.Execution.Effect != capability.EffectRead {
		t.Fatalf("preflight invocation mismatch: calls=%d last=%#v", capabilityAdapter.calls, capabilityAdapter.last)
	}
	if !audits.hasEvent("plugin.confirmation.preflighted") || !audits.hasEvent("plugin.confirmation.issued") {
		t.Fatalf("missing preflight/issued audit events: %#v", audits.events)
	}

	call.ConfirmationID = confirmation.ConfirmationID
	confirmed, err := h.CallPluginMethod(hostTestContext(), call)
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
			"tasks.start.preflight": {Data: capability.RiskPlan{
				SchemaVersion: capability.RiskPlanSchemaVersion, Summary: "Start task",
				RiskFlags: []capability.RiskFlag{{ID: "executes_task", Severity: capability.RiskSeverityLow, Summary: "Executes task"}},
			}},
		},
	}
	diagnostics := &diagnosticSink{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.tasks", capabilityAdapter: capabilityAdapter,
		diagnostics: diagnostics,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildMethodContractFixturePackage(t), "method_contract.view")
	call := CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "tasks.start", Params: map[string]any{"task_id": "task_1"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	capabilityAdapter.resultsByTarget["tasks.start.preflight"] = capability.Result{Data: capability.RiskPlan{
		SchemaVersion: capability.RiskPlanSchemaVersion, Summary: "Start task after policy change",
		RiskFlags: []capability.RiskFlag{
			{ID: "executes_task", Severity: capability.RiskSeverityLow, Summary: "Executes task"},
			{ID: "elevated_scope", Severity: capability.RiskSeverityHigh, Summary: "Uses elevated scope"},
		},
	}}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrConfirmationInvalid", err)
	}
	if capabilityAdapter.last.Execution.TargetMethod != "tasks.start.preflight" {
		t.Fatalf("stale confirmation dispatched business method: %#v", capabilityAdapter.last)
	}
	event, ok := audits.lastEvent("plugin.method.rejected")
	if !ok || event.Details["reason"] != "confirmation_invalid" {
		t.Fatalf("stale confirmation audit mismatch: %#v", audits.events)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Details.Reason != "confirmation_invalid" {
		t.Fatalf("stale confirmation diagnostic mismatch: %#v", diagnostics.events)
	}
}

func TestPrepareMethodConfirmationNormalizesTypedRiskPlanAndRedactsDetails(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{Data: map[string]any{"started": true}},
		resultsByTarget: map[string]capability.Result{
			"tasks.start.preflight": {Data: capability.RiskPlan{
				SchemaVersion: capability.RiskPlanSchemaVersion,
				Summary:       "Start high-risk container",
				Effect:        capability.EffectExecute,
				ResourceRef:   "container_hash_1",
				RiskFlags: []capability.RiskFlag{
					{ID: "container.host_network", Severity: capability.RiskSeverityHigh, Summary: "Uses host networking", RequiresAdmin: true},
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "tasks.start",
		Params:          map[string]any{"task_id": "task_1"},
	}

	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "danger.run",
		Params:          map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatal(err)
	}

	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(hostTestContext(), call); err == nil {
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "danger.run",
		Params:          map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.ConfirmationID = confirmation.ConfirmationID
	capabilityAdapter.targetFields = map[string]any{"target": "other"}
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrConfirmationInvalid", err)
	}
	capabilityAdapter.targetFields = map[string]any{"target": "db"}
	if _, err := h.CallPluginMethod(hostTestContext(), call); err == nil {
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
			contract.Methods[index].Quota = capabilitycontract.Quota{MaxConcurrent: 1, MaxDurationMS: 500}
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
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	}
	first, err := h.CallPluginMethod(hostTestContext(), call)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CallPluginMethod(hostTestContext(), call); !errors.Is(err, capability.ErrQuotaExceeded) {
		t.Fatalf("second CallPluginMethod() error = %v, want ErrQuotaExceeded", err)
	}
	if capabilityAdapter.calls != 1 {
		t.Fatalf("adapter calls = %d, want 1", capabilityAdapter.calls)
	}
	if event, ok := audits.lastEvent("plugin.method.rejected"); !ok || event.Details["reason"] != "quota_exceeded" {
		t.Fatalf("missing quota rejection audit: %#v", audits.events)
	}
	time.Sleep(750 * time.Millisecond)
	assertHostOperationStatus(t, h, first.OperationID, operation.StatusFailed)
	if err := capabilityAdapter.last.Execution.Operation.Complete(hostTestContext()); !errors.Is(err, capability.ErrExecutionRevoked) {
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
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "echo.ping", Params: map[string]any{"message": "hello"},
	})
	if !errors.Is(err, capability.ErrQuotaExceeded) {
		t.Fatalf("CallPluginMethod() error = %v, want ErrQuotaExceeded", err)
	}
}

func TestDurationQuotaTerminalFailureReleasesOperationExecutionAndAllowsRetry(t *testing.T) {
	finishErr := errors.New("operation terminal store unavailable")
	operations := &controlledOperationFinishStore{Store: operation.NewMemoryStore(), err: finishErr, failing: true}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	verified := fixtureVerifiedCapabilityContractWithQuotas(t, "example.capability.echo", map[string]capabilitycontract.Quota{
		"documents.archive": {MaxConcurrent: 1, MaxDurationMS: 50},
	})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, operations: operations,
		capabilityContract: &verified, capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t, operationRPCFixtureManifestJSON(), "Operation", "echo", verified.Pin,
	), "operation.view")
	call := CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	}
	first, err := h.CallPluginMethod(hostTestContext(), call)
	if err != nil {
		t.Fatal(err)
	}
	waitForOperationFinishCalls(t, operations, 1)
	h.lifecycleWG.Wait()
	assertHostOperationStatus(t, h, first.OperationID, operation.StatusRunning)
	assertNoActiveExecutionState(t, h, "duration terminal failure")

	operations.setFailing(false)
	second, err := h.CallPluginMethod(hostTestContext(), call)
	if err != nil {
		t.Fatalf("CallPluginMethod() after quota release error = %v", err)
	}
	if err := capabilityAdapter.last.Execution.Operation.Complete(hostTestContext()); err != nil {
		t.Fatalf("second Operation.Complete() error = %v", err)
	}
	assertHostOperationStatus(t, h, second.OperationID, operation.StatusCompleted)
	if _, err := h.CancelOperation(hostTestContext(), CancelOperationRequest{OperationID: first.OperationID, Reason: "retry terminal write"}); err != nil {
		t.Fatal(err)
	}
	waitForHostOperationStatus(t, h, first.OperationID, operation.StatusCanceled)
}

func TestDurationQuotaSubscriptionOperationFailureReleasesExecutionAndReconciles(t *testing.T) {
	finishErr := errors.New("operation terminal store unavailable")
	operations := &controlledOperationFinishStore{Store: operation.NewMemoryStore(), err: finishErr, failing: true}
	streams := stream.NewMemoryStore()
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	verified := fixtureVerifiedCapabilityContractWithQuotas(t, "example.capability.echo", map[string]capabilitycontract.Quota{
		"logs.tail": {MaxConcurrent: 1, MaxDurationMS: 25},
	})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, operations: operations, streams: streams,
		capabilityContract: &verified, capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t, subscriptionRPCFixtureManifestJSON(), "Subscription", "echo", verified.Pin,
	), "subscription.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitForOperationFinishCalls(t, operations, 1)
	h.lifecycleWG.Wait()
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusRunning)
	assertHostStreamStatus(t, h, result.StreamID, stream.StatusFailed)
	assertNoActiveExecutionState(t, h, "subscription operation terminal failure")

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	operations.setFailing(false)
	restarted, _, _ := newTestHostWithOptions(t, testHostOptions{operations: operations, streams: streams})
	assertHostOperationStatus(t, restarted, result.OperationID, operation.StatusFailed)
	assertHostStreamStatus(t, restarted, result.StreamID, stream.StatusFailed)
}

func TestDurationQuotaSubscriptionStreamFailureReleasesExecutionAndReconciles(t *testing.T) {
	closeErr := errors.New("stream terminal store unavailable")
	operations := operation.NewMemoryStore()
	streams := &controlledStreamCloseStore{Store: stream.NewMemoryStore(), err: closeErr, failing: true}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	verified := fixtureVerifiedCapabilityContractWithQuotas(t, "example.capability.echo", map[string]capabilitycontract.Quota{
		"logs.tail": {MaxConcurrent: 1, MaxDurationMS: 25},
	})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, operations: operations, streams: streams,
		capabilityContract: &verified, capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t, subscriptionRPCFixtureManifestJSON(), "Subscription", "echo", verified.Pin,
	), "subscription.view")
	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitForStreamCloseCalls(t, streams, 1)
	h.lifecycleWG.Wait()
	assertHostOperationStatus(t, h, result.OperationID, operation.StatusFailed)
	assertHostStreamStatus(t, h, result.StreamID, stream.StatusOpen)
	assertNoActiveExecutionState(t, h, "subscription stream terminal failure")

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	streams.setFailing(false)
	restarted, _, _ := newTestHostWithOptions(t, testHostOptions{operations: operations, streams: streams})
	assertHostOperationStatus(t, restarted, result.OperationID, operation.StatusFailed)
	assertHostStreamStatus(t, restarted, result.StreamID, stream.StatusFailed)
}

func TestDurationQuotaRejectsLateSubscriptionSuccessWithoutDuplicateTerminalWrite(t *testing.T) {
	operations := &controlledOperationFinishStore{Store: operation.NewMemoryStore()}
	streams := stream.NewMemoryStore()
	capabilityAdapter := &recordingCapabilityAdapter{
		result: capability.Result{Data: map[string]any{"started": true}}, invokeDelay: 80 * time.Millisecond,
	}
	verified := fixtureVerifiedCapabilityContractWithQuotas(t, "example.capability.echo", map[string]capabilitycontract.Quota{
		"logs.tail": {MaxConcurrent: 1, MaxDurationMS: 20},
	})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, operations: operations, streams: streams,
		capabilityContract: &verified, capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildCapabilityPinnedFixturePackage(
		t, subscriptionRPCFixtureManifestJSON(), "Subscription", "echo", verified.Pin,
	), "subscription.view")
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if !errors.Is(err, capability.ErrQuotaExceeded) {
		t.Fatalf("CallPluginMethod() error = %v, want %v", err, capability.ErrQuotaExceeded)
	}
	h.lifecycleWG.Wait()
	if calls := operations.finishCalls(); calls != 1 {
		t.Fatalf("operation terminal writes = %d, want 1", calls)
	}
	assertNoActiveExecutionState(t, h, "late subscription result")
}

func TestHostCloseCancelsDurationQuotaJobsBeforeExpiry(t *testing.T) {
	operations := &controlledOperationFinishStore{Store: operation.NewMemoryStore()}
	streams := &controlledStreamCloseStore{Store: stream.NewMemoryStore()}
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	verified := fixtureVerifiedCapabilityContractWithQuotas(t, "example.capability.echo", map[string]capabilitycontract.Quota{
		"documents.archive": {MaxConcurrent: 1, MaxDurationMS: 500},
		"logs.tail":         {MaxConcurrent: 1, MaxDurationMS: 500},
	})
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, operations: operations, streams: streams,
		capabilityContract: &verified, capabilityAdapter: capabilityAdapter,
	})
	operationPlugin, operationGateway := installEnableAndMintGatewayForAudience(t, h, buildCapabilityPinnedFixturePackage(
		t, operationRPCFixtureManifestJSON(), "Operation", "echo", verified.Pin,
	), "operation.view", "surface_operation", "bridge_operation")
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: operationPlugin.PluginInstanceID, SurfaceInstanceID: "surface_operation",
		BridgeChannelID: "bridge_operation", GatewayToken: operationGateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	}); err != nil {
		t.Fatal(err)
	}
	subscriptionPlugin, subscriptionGateway := installEnableAndMintGatewayForAudience(t, h, buildCapabilityPinnedFixturePackage(
		t, subscriptionRPCFixtureManifestJSON(), "Subscription", "echo", verified.Pin,
	), "subscription.view", "surface_subscription", "bridge_subscription")
	if _, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: subscriptionPlugin.PluginInstanceID, SurfaceInstanceID: "surface_subscription",
		BridgeChannelID: "bridge_subscription", GatewayToken: subscriptionGateway.GatewayToken, Method: "logs.tail",
	}); err != nil {
		t.Fatal(err)
	}

	closed := make(chan error, 1)
	go func() { closed <- h.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Host.Close() did not stop duration quota lifecycle jobs")
	}
	assertNoActiveExecutionState(t, h, "host close")
	operationCalls := operations.finishCalls()
	streamCalls := streams.closeCalls()
	time.Sleep(650 * time.Millisecond)
	if operations.finishCalls() != operationCalls || streams.closeCalls() != streamCalls {
		t.Fatal("duration quota terminal writes continued after Host.Close()")
	}
}

func TestDisableRevokesSurfaceTokensConfirmationIntentsAndRuntime(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"result": "done"}}}
	confirmationIntents := security.NewMemoryConfirmationIntentStore()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:       true,
		localGenerated:      true,
		capabilityID:        "example.capability.echo",
		capabilityAdapter:   capabilityAdapter,
		runtimeManager:      runtime,
		connectivityBroker:  connectivity.NewMemoryBroker(),
		confirmationIntents: confirmationIntents,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildDangerousWorkerFixturePackage(t), "worker.view")
	call := CallMethodRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "worker.echo",
		Params:          map[string]any{"message": "hello"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatalf("PrepareMethodConfirmation() error = %v", err)
	}
	if listed, err := confirmationIntents.ListConfirmationIntents(hostTestContext(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil || len(listed) != 1 {
		t.Fatalf("stored confirmation intents before disable = %#v, err=%v", listed, err)
	}
	call.ConfirmationID = confirmation.ConfirmationID

	disabled, err := h.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy", ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)})
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
	if _, err := h.CallPluginMethod(hostTestContext(), call); err == nil {
		t.Fatal("CallPluginMethod() after disable expected fail-closed error")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter called after disabled confirmation: %d", capabilityAdapter.calls)
	}
	if listed, err := confirmationIntents.ListConfirmationIntents(hostTestContext(), security.ListConfirmationIntentsRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil || len(listed) != 0 {
		t.Fatalf("stored confirmation intents after disable = %#v, err=%v", listed, err)
	}
	if !audits.hasEvent("plugin.runtime_capabilities.revoked") {
		t.Fatalf("missing runtime capability revocation audit event: %#v", audits.events)
	}
}

func TestDisableFailsClosedWhenRuntimeRevokeFails(t *testing.T) {
	ctx := hostTestContext()
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.revokeErr = &mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: errors.New("runtime pipe closed")}
	connectivityBroker := connectivity.NewMemoryBroker()
	diagnostics := &diagnosticSink{}
	h, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		runtimeManager:     runtime,
		connectivityBroker: connectivityBroker,
		diagnostics:        diagnostics,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildWorkerNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(ctx, connectivity.GrantRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		ActiveFingerprint:  enabled.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
		PolicyRevision:     enabled.PolicyRevision,
		ManagementRevision: enabled.ManagementRevision,
		RevokeEpoch:        enabled.RevokeEpoch,
		ConnectorID:        "api",
		Transport:          connectivity.TransportHTTP,
		Destination:        "https://api.example.com",
	}); err != nil {
		t.Fatalf("MintConnectionGrant(before disable) error = %v", err)
	}

	_, err = h.DisablePlugin(ctx, DisableRequest{PluginInstanceID: enabled.PluginInstanceID, Reason: "policy", ExpectedManagementRevision: mustManagementRevision(t, h, enabled.PluginInstanceID)})
	if !errors.Is(err, runtime.revokeErr) {
		t.Fatalf("DisablePlugin() error = %v, want %v", err, runtime.revokeErr)
	}
	if got := mutation.ForError(err); got != mutation.OutcomeUnknown {
		t.Fatalf("mutation.ForError() = %q, want %q", got, mutation.OutcomeUnknown)
	}
	disabled, getErr := h.adapters.Registry.GetPlugin(ctx, enabled.PluginInstanceID)
	if getErr != nil {
		t.Fatal(getErr)
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
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
		PolicyRevision:     enabled.PolicyRevision,
		ManagementRevision: enabled.ManagementRevision,
		RevokeEpoch:        enabled.RevokeEpoch,
		ConnectorID:        "api",
		Transport:          connectivity.TransportHTTP,
		Destination:        "https://api.example.com",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(after disable) error = %v, want %v", err, connectivity.ErrConnectorDenied)
	}
	if len(diagnostics.events) != 1 || diagnostics.events[0].Type != "plugin.runtime_capabilities.revoke_failed" ||
		diagnostics.events[0].MutationOutcome != mutation.OutcomeUnknown ||
		diagnostics.events[0].Failure.Operation != observability.FailureOperationRuntimeRevoke {
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
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantDeclaredPermissions(t, h, installed)

	intents, err := h.ListIntents(hostTestContext(), ListIntentsRequest{IntentID: "example.echo"})
	if err != nil {
		t.Fatalf("ListIntents() error = %v", err)
	}
	if len(intents) != 1 || intents[0].IntentID != "example.echo" || intents[0].Method != "echo.ping" || intents[0].Effect != "read" {
		t.Fatalf("intent records mismatch: %#v", intents)
	}

	result, err := h.InvokeIntent(hostTestContext(), InvokeIntentRequest{
		IntentID: "example.echo",
		Params:   map[string]any{"message": "from intent"},
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
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.InvokeIntent(hostTestContext(), InvokeIntentRequest{
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
	first, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildIntentFixturePackage(t, false))
	if err != nil {
		t.Fatal(err)
	}
	secondBytes := buildIntentFixturePackage(t, false)
	second, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PackageReader:    bytes.NewReader(secondBytes),
		PackageSize:      int64(len(secondBytes)),
		PluginInstanceID: "plugini_second_intent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: first.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, first.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: second.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, second.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantDeclaredPermissions(t, h, first)
	grantDeclaredPermissions(t, h, second)

	if _, err := h.InvokeIntent(hostTestContext(), InvokeIntentRequest{IntentID: "example.echo"}); err == nil || !errors.Is(err, ErrMethodRequestContract) {
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
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildIntentFixturePackage(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	grantDeclaredPermissions(t, h, installed)

	result, err := h.InvokeIntent(hostTestContext(), InvokeIntentRequest{
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "danger.run",
		Params:          map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.Params = map[string]any{"target": "other"}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(hostTestContext(), call); err == nil {
		t.Fatal("CallPluginMethod() expected confirmation audience error")
	}
	call.Params = map[string]any{"target": "db"}
	if _, err := h.CallPluginMethod(hostTestContext(), call); err == nil {
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "danger.run",
		Params:          map[string]any{"target": "db"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(hostTestContext(), call); err != nil {
		t.Fatalf("CallPluginMethod() with confirmation error = %v", err)
	}
	if _, err := h.CallPluginMethod(hostTestContext(), call); err == nil {
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
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_rpc",

		BridgeChannelID: "bridge_rpc",
		GatewayToken:    gateway.GatewayToken,
		Method:          "danger.run",
		Params:          map[string]any{"target": "db", "ui_note": "original"},
	}
	confirmation, err := h.PrepareMethodConfirmation(hostTestContext(), prepareConfirmationRequest(call))
	if err != nil {
		t.Fatal(err)
	}
	call.Params = map[string]any{"target": "db", "ui_note": "changed"}
	call.ConfirmationID = confirmation.ConfirmationID
	if _, err := h.CallPluginMethod(hostTestContext(), call); err == nil {
		t.Fatal("CallPluginMethod() expected confirmation intent to bind full params")
	}
	if capabilityAdapter.calls != 0 {
		t.Fatalf("capability adapter was called %d times", capabilityAdapter.calls)
	}
}

func TestStorageQuotaFilesFromManifestUsesBoundedDefault(t *testing.T) {
	if got := storageQuotaFilesFromManifest(nil); got != manifest.DefaultStoreQuotaFiles {
		t.Fatalf("storageQuotaFilesFromManifest(nil) = %d, want %d", got, manifest.DefaultStoreQuotaFiles)
	}
}

func TestMintStorageHandleGrantBindsStoreAndQuota(t *testing.T) {
	host, _, audits := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(hostTestContext(), host, nextTestPluginInstanceID(t), buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := host.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, host, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}

	now := time.Date(2026, 6, 30, 14, 0, 0, 0, time.UTC)
	result, err := host.MintStorageHandleGrant(hostTestContext(), MintStorageHandleGrantRequest{
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
			PluginInstanceID:     enabled.PluginInstanceID,
			ActiveFingerprint:    enabled.ActiveFingerprint,
			RuntimeInstanceID:    "runtime_1",
			RuntimeGenerationID:  "runtime_gen_1",
			RuntimeShardID:       "runtime_shard_a",
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			OwnerEnvHash:         "env_hash",
			SessionChannelIDHash: "channel_hash",
			HandleID:             "storage:db",
			Method:               "storage.sqlite",
			ResourceScope:        sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
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

	if _, err := host.MintStorageHandleGrant(hostTestContext(), MintStorageHandleGrantRequest{
		PluginInstanceID: installed.PluginInstanceID,
		StoreID:          "db",
	}); !errors.Is(err, bridge.ErrMissingTokenAudience) {
		t.Fatalf("MintStorageHandleGrant(missing runtime generation) error = %v, want %v", err, bridge.ErrMissingTokenAudience)
	}
	if _, err := host.MintStorageHandleGrant(hostTestContext(), MintStorageHandleGrantRequest{
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
		connectivityBroker: connectivityBroker,
	})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if !audits.hasEvent("plugin.connectivity.policy_installed") {
		t.Fatalf("missing connectivity policy audit event: %#v", audits.events)
	}
	grant, err := h.MintConnectionGrant(hostTestContext(), MintConnectionGrantRequest{
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
	if !grant.ResourceScope.Matches(sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"}) {
		t.Fatalf("grant resource scope = %#v", grant.ResourceScope)
	}
	if !audits.hasEvent("plugin.connectivity.grant_minted") {
		t.Fatalf("missing connectivity grant audit event: %#v", audits.events)
	}

	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	handle, err := h.MintNetworkHandleGrant(hostTestContext(), MintConnectionGrantRequest{
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
			PluginInstanceID:     installed.PluginInstanceID,
			ActiveFingerprint:    installed.ActiveFingerprint,
			RuntimeInstanceID:    "runtime_1",
			RuntimeGenerationID:  "runtime_gen_1",
			RuntimeShardID:       "runtime_shard_a",
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			OwnerEnvHash:         "env_hash",
			SessionChannelIDHash: "channel_hash",
			HandleID:             handle.ConnectionGrant.GrantID,
			Method:               "network.tcp",
			ResourceScope:        handle.ConnectionGrant.ResourceScope,
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
	expected := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		PermissionID:               "network.audit",
		ExpectedPolicyRevision:     expected.PolicyRevision,
		ExpectedManagementRevision: expected.ManagementRevision,
		ExpectedRevokeEpoch:        expected.RevokeEpoch,
	}); err != nil {
		t.Fatalf("GrantPermission(network.audit) error = %v", err)
	}
	afterGrant, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(hostTestContext(), connectivity.GrantRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		ActiveFingerprint:  enabled.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
		PolicyRevision:     enabled.PolicyRevision,
		ManagementRevision: enabled.ManagementRevision,
		RevokeEpoch:        enabled.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(stale after grant) error = %v, want %v", err, connectivity.ErrConnectorDenied)
	}
	if _, err := connectivityBroker.MintConnectionGrant(hostTestContext(), connectivity.GrantRequest{
		PluginInstanceID:   afterGrant.PluginInstanceID,
		ActiveFingerprint:  afterGrant.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
		PolicyRevision:     afterGrant.PolicyRevision,
		ManagementRevision: afterGrant.ManagementRevision,
		RevokeEpoch:        afterGrant.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); err != nil {
		t.Fatalf("MintConnectionGrant(fresh after grant) error = %v", err)
	}
	expected = mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
	if _, err := h.RevokePermission(hostTestContext(), RevokePermissionRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		PermissionID:               "network.audit",
		ExpectedPolicyRevision:     expected.PolicyRevision,
		ExpectedManagementRevision: expected.ManagementRevision,
		ExpectedRevokeEpoch:        expected.RevokeEpoch,
		Reason:                     "test",
	}); err != nil {
		t.Fatalf("RevokePermission(network.audit) error = %v", err)
	}
	afterRevoke, err := h.adapters.Registry.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(hostTestContext(), connectivity.GrantRequest{
		PluginInstanceID:   afterGrant.PluginInstanceID,
		ActiveFingerprint:  afterGrant.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
		PolicyRevision:     afterGrant.PolicyRevision,
		ManagementRevision: afterGrant.ManagementRevision,
		RevokeEpoch:        afterGrant.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(stale after revoke) error = %v, want %v", err, connectivity.ErrConnectorDenied)
	}
	if _, err := connectivityBroker.MintConnectionGrant(hostTestContext(), connectivity.GrantRequest{
		PluginInstanceID:   afterRevoke.PluginInstanceID,
		ActiveFingerprint:  afterRevoke.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
		PolicyRevision:     afterRevoke.PolicyRevision,
		ManagementRevision: afterRevoke.ManagementRevision,
		RevokeEpoch:        afterRevoke.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); err != nil {
		t.Fatalf("MintConnectionGrant(fresh after revoke) error = %v", err)
	}
	if _, err := h.MintNetworkHandleGrant(hostTestContext(), MintConnectionGrantRequest{
		PluginInstanceID: installed.PluginInstanceID,
		ConnectorID:      "mysql",
		Transport:        connectivity.TransportTCP,
		Destination:      "db.example.com:3306",
	}); !errors.Is(err, bridge.ErrMissingTokenAudience) {
		t.Fatalf("MintNetworkHandleGrant(missing runtime generation) error = %v, want %v", err, bridge.ErrMissingTokenAudience)
	}

	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "test", ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(hostTestContext(), connectivity.GrantRequest{
		PluginInstanceID:   installed.PluginInstanceID,
		ActiveFingerprint:  installed.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
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

func TestDisableConnectivityPolicyOnlyRemovesAuthenticatedEnvironment(t *testing.T) {
	ctxA := hostTestContextWith("session_a", "user_a", "env_a", "channel_a")
	ctxB := hostTestContextWith("session_b", "user_b", "env_b", "channel_b")
	connectivityBroker := connectivity.NewMemoryBroker()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: connectivityBroker,
	})
	packageBytes := buildNetworkFixturePackage(t)
	pluginInstanceID := nextTestPluginInstanceID(t)

	installedA, err := ImportLocalPackageBytes(ctxA, h, pluginInstanceID, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	enabledA, err := h.EnablePlugin(ctxA, EnableRequest{
		PluginInstanceID:           installedA.PluginInstanceID,
		ExpectedManagementRevision: installedA.ManagementRevision,
	})
	if err != nil {
		t.Fatalf("EnablePlugin(env A) error = %v", err)
	}
	installedB, err := ImportLocalPackageBytes(ctxB, h, pluginInstanceID, packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if installedB.PluginInstanceID != installedA.PluginInstanceID {
		t.Fatalf("plugin instance IDs differ across owners: %q, %q", installedA.PluginInstanceID, installedB.PluginInstanceID)
	}
	enabledB, err := h.EnablePlugin(ctxB, EnableRequest{
		PluginInstanceID:           installedB.PluginInstanceID,
		ExpectedManagementRevision: installedB.ManagementRevision,
	})
	if err != nil {
		t.Fatalf("EnablePlugin(env B) error = %v", err)
	}
	registerExecution := func(suffix, ownerSessionHash, ownerUserHash, ownerEnvHash, sessionChannelIDHash string) {
		t.Helper()
		binding := capability.ExecutionBinding{
			PluginID:             enabledA.PluginID,
			PluginInstanceID:     enabledA.PluginInstanceID,
			Method:               "network.watch",
			Execution:            string(manifest.MethodExecutionSubscription),
			OwnerSessionHash:     ownerSessionHash,
			OwnerUserHash:        ownerUserHash,
			OwnerEnvHash:         ownerEnvHash,
			SessionChannelIDHash: sessionChannelIDHash,
		}
		if _, err := h.adapters.Operations.Register(context.Background(), operation.RegisterRequest{
			OperationID:      "operation_" + suffix,
			ExecutionBinding: binding,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.adapters.Streams.Register(context.Background(), stream.RegisterRequest{
			StreamID:         "stream_" + suffix,
			ExecutionBinding: binding,
		}); err != nil {
			t.Fatal(err)
		}
	}
	registerExecution("env_a", "session_a", "user_a", "env_a", "channel_a")
	registerExecution("env_b", "session_b", "user_b", "env_b", "channel_b")

	mintRequest := MintConnectionGrantRequest{
		PluginInstanceID:    installedA.PluginInstanceID,
		ConnectorID:         "mysql",
		Transport:           connectivity.TransportTCP,
		Destination:         "db.example.com:3306",
		RuntimeGenerationID: "runtime_gen_1",
	}
	if _, err := h.MintConnectionGrant(ctxA, mintRequest); err != nil {
		t.Fatalf("MintConnectionGrant(env A) error = %v", err)
	}
	if _, err := h.MintConnectionGrant(ctxB, mintRequest); err != nil {
		t.Fatalf("MintConnectionGrant(env B) error = %v", err)
	}

	if _, err := h.DisablePlugin(ctxA, DisableRequest{
		PluginInstanceID:           installedA.PluginInstanceID,
		Reason:                     "test",
		ExpectedManagementRevision: enabledA.ManagementRevision,
	}); err != nil {
		t.Fatalf("DisablePlugin(env A) error = %v", err)
	}
	operationA, err := h.adapters.Operations.Get(ctxA, "operation_env_a")
	if err != nil {
		t.Fatal(err)
	}
	operationB, err := h.adapters.Operations.Get(ctxB, "operation_env_b")
	if err != nil {
		t.Fatal(err)
	}
	if operationA.Status != operation.StatusCancelRequested || operationB.Status != operation.StatusRunning {
		t.Fatalf("cross-environment operation statuses = %s, %s", operationA.Status, operationB.Status)
	}
	streamA, err := h.adapters.Streams.Get(ctxA, "stream_env_a")
	if err != nil {
		t.Fatal(err)
	}
	streamB, err := h.adapters.Streams.Get(ctxB, "stream_env_b")
	if err != nil {
		t.Fatal(err)
	}
	if streamA.Status != stream.StatusOrphanedDisabled || streamB.Status != stream.StatusOpen {
		t.Fatalf("cross-environment stream statuses = %s, %s", streamA.Status, streamB.Status)
	}
	if _, err := connectivityBroker.MintConnectionGrant(ctxA, connectivity.GrantRequest{
		PluginInstanceID:   enabledA.PluginInstanceID,
		ActiveFingerprint:  enabledA.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_a"},
		PolicyRevision:     enabledA.PolicyRevision,
		ManagementRevision: enabledA.ManagementRevision,
		RevokeEpoch:        enabledA.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); !errors.Is(err, connectivity.ErrConnectorDenied) {
		t.Fatalf("MintConnectionGrant(env A after disable) error = %v, want ErrConnectorDenied", err)
	}
	if _, err := connectivityBroker.MintConnectionGrant(ctxB, connectivity.GrantRequest{
		PluginInstanceID:   enabledB.PluginInstanceID,
		ActiveFingerprint:  enabledB.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_b"},
		PolicyRevision:     enabledB.PolicyRevision,
		ManagementRevision: enabledB.ManagementRevision,
		RevokeEpoch:        enabledB.RevokeEpoch,
		ConnectorID:        "mysql",
		Transport:          connectivity.TransportTCP,
		Destination:        "db.example.com:3306",
	}); err != nil {
		t.Fatalf("MintConnectionGrant(env B after env A disable) error = %v", err)
	}
}

func TestRefreshEnabledPluginResultIsClosed(t *testing.T) {
	for _, result := range []RefreshEnabledPluginResult{
		refreshedPluginResult("plugini_refreshed"),
		failedPluginRefreshResult("plugini_failed"),
	} {
		if _, err := json.Marshal(result); err != nil {
			t.Fatalf("json.Marshal(%#v) error = %v", result, err)
		}
	}
	for _, result := range []RefreshEnabledPluginResult{
		{},
		{PluginInstanceID: "plugini_invalid", Status: RefreshEnabledPluginStatusRefreshed, Error: &RefreshEnabledPluginPublicError{Code: security.ErrRuntimeUnavailable, Message: refreshEnabledPluginFailureMessage}},
		{PluginInstanceID: "plugini_invalid", Status: RefreshEnabledPluginStatusFailed},
		{PluginInstanceID: "plugini_invalid", Status: "unknown"},
	} {
		if _, err := json.Marshal(result); err == nil {
			t.Fatalf("json.Marshal(%#v) succeeded, want closed-union validation error", result)
		}
	}
}

func TestRefreshEnabledPluginsRestoresRuntimeState(t *testing.T) {
	ctx := hostTestContext()
	h, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: connectivity.NewMemoryBroker(),
	})
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)})
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
	restartedAuditJournal := observability.NewMemorySecurityAuditJournal()
	restarted, err := Open(hostTestContext(), Config{
		Core: CoreAdapters{
			Policy: policyAdapter{
				developerMode:  true,
				localGenerated: true,
				decision:       PolicyAllow,
			},
			Authorization:        allowAuthorizationAdapter{},
			PackageTrustVerifier: h.adapters.PackageTrustVerifier,
			Registry:             h.adapters.Registry,
			Audit:                restartedAudits,
			SecurityAudit:        restartedAuditJournal,
			Diagnostics:          restartedDiagnostics,
			SurfaceCatalog:       restartedSurfaces,
			PluginData:           h.adapters.PluginData,
			Assets:               h.adapters.Assets,
			InstallStages:        h.adapters.InstallStages,
			SurfaceTokens:        bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{}),
			Operations:           operation.NewMemoryStore(),
			ConfirmationIntents:  security.NewMemoryConfirmationIntentStore(),
			Streams:              stream.NewMemoryStore(),
			SessionLifecycle:     h.adapters.SessionLifecycle,
			SessionScopes:        h.adapters.SessionScopes,
		},
		Runtime:      &RuntimeModule{manager: newRecordingRuntimeManager()},
		Capability:   &CapabilityModule{Registry: capability.NewRegistry()},
		Connectivity: &ConnectivityModule{Broker: restartedBroker, NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})},
		Secrets:      &SecretsModule{Store: secrets.NewMemoryStore()},
		CoreAction:   &CoreActionModule{Adapter: &recordingCoreActionAdapter{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := restarted.Close(); err != nil {
			t.Errorf("restarted.Close() error = %v", err)
		}
	})

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
	if len(refreshed) != 1 || refreshed[0].PluginInstanceID != enabled.PluginInstanceID || refreshed[0].Status != RefreshEnabledPluginStatusRefreshed || refreshed[0].Error != nil {
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

func TestUninstallRevokesSurfaceTokensAndRuntime(t *testing.T) {
	runtime := newRecordingRuntimeManagerWithHealth(runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", IPCChannelID: "ipc_1", ConnectionNonce: "connection_nonce_1234567890", Ready: true})
	runtime.revokeResult = runtimeclient.RevokeResult{ClosedSocketCount: 8, ClosedStreamCount: 9, ClosedStorageHandleCount: 10}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		runtimeManager:    runtime,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildWorkerFixturePackage(t), "worker.view")
	uninstalled, err := h.UninstallPlugin(hostTestContext(), UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	if runtime.revokeCalls != 1 || runtime.lastRevokedPlugin != installed.PluginInstanceID || runtime.lastRevokeEpoch != uninstalled.RevokeEpoch {
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
	assertAuditDetail(t, event, "closed_socket_count", 8)
	assertAuditDetail(t, event, "closed_stream_count", 9)
	assertAuditDetail(t, event, "closed_storage_handle_count", 10)
}

func TestUninstallEnabledPluginClearsSurfacesStreamsAndNetworkPolicy(t *testing.T) {
	ctx := hostTestContext()
	connectivityBroker := connectivity.NewMemoryBroker()
	h, surfaces, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:      true,
		localGenerated:     true,
		connectivityBroker: connectivityBroker,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildNetworkFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)})
	if err != nil {
		t.Fatalf("EnablePlugin() error = %v", err)
	}
	if len(surfaces.snapshots) != 1 || len(surfaces.snapshots[0].Surfaces) != 1 {
		t.Fatalf("enable surface publish mismatch: %#v", surfaces.snapshots)
	}
	if _, err := connectivityBroker.MintConnectionGrant(ctx, connectivity.GrantRequest{
		PluginInstanceID:   enabled.PluginInstanceID,
		ActiveFingerprint:  enabled.ActiveFingerprint,
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
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
			OwnerEnvHash:         "env_hash",
			SessionChannelIDHash: "channel_hash",
			BridgeChannelID:      "bridge_network",
		},
	}); err != nil {
		t.Fatalf("Streams.Register() error = %v", err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: enabled.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, h, enabled.PluginInstanceID)}); err != nil {
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
		ResourceScope:      sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
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

func TestDisableTransitionsOperations(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	cancelOp, err := h.adapters.Operations.Register(hostTestContext(), operation.RegisterRequest{
		OperationID:      "op_disable_cancel",
		ExecutionBinding: testExecutionBinding(installed, "documents.archive", manifest.MethodExecutionOperation),
	})
	if err != nil {
		t.Fatal(err)
	}
	waitOp, err := h.adapters.Operations.Register(hostTestContext(), operation.RegisterRequest{
		OperationID:      "op_disable_wait",
		ExecutionBinding: testExecutionBinding(installed, "sync.wait", manifest.MethodExecutionOperation),
		DisableBehavior:  operation.DisableBehaviorWait,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: installed.PluginInstanceID, Reason: "policy", ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	assertHostOperationStatus(t, h, cancelOp.OperationID, operation.StatusCancelRequested)
	assertHostOperationStatus(t, h, waitOp.OperationID, operation.StatusRunning)
}

func TestUninstallDeleteDataBlockedByRunningOperation(t *testing.T) {
	ctx := hostTestContext()
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
	})
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:      "op_blocks_delete",
		ExecutionBinding: testExecutionBinding(installed, "documents.archive", manifest.MethodExecutionOperation),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() error = %v, want ErrDeleteBlocked", err)
	}
	assertHostOperationStatus(t, h, "op_blocks_delete", operation.StatusCancelRequested)
	namespaces, err := h.adapters.PluginData.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) == 0 {
		t.Fatal("storage namespaces were deleted despite blocked operation")
	}
	if !audits.hasEvent("plugin.operations.delete_blocked") {
		t.Fatalf("missing blocked audit event: %#v", audits.events)
	}
}

func TestUninstallDeleteDataDispatchesCancellationToLiveAdapterBeforeBlocking(t *testing.T) {
	capabilityAdapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, capabilityID: "example.capability.echo", capabilityAdapter: capabilityAdapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	started, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{"document_id": "doc-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(hostTestContext(), UninstallRequest{
		PluginInstanceID: installed.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID),
	}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() error = %v, want ErrDeleteBlocked", err)
	}
	if capabilityAdapter.cancelCalls != 1 || capabilityAdapter.lastCancellation.OperationID != started.OperationID {
		t.Fatalf("live adapter cancellation mismatch: calls=%d request=%#v", capabilityAdapter.cancelCalls, capabilityAdapter.lastCancellation)
	}
}

func TestUninstallDeleteDataSucceedsAfterOperationCancelAck(t *testing.T) {
	ctx := hostTestContext()
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:      "op_cancel_then_delete",
		ExecutionBinding: testExecutionBinding(installed, "documents.archive", manifest.MethodExecutionOperation),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); !errors.Is(err, operation.ErrDeleteBlocked) {
		t.Fatalf("UninstallPlugin() first error = %v, want ErrDeleteBlocked", err)
	}
	if _, err := h.adapters.Operations.Finish(ctx, operation.FinishRequest{
		OperationID: "op_cancel_then_delete",
		Status:      operation.StatusCanceled,
		Reason:      "runtime ack",
	}); err != nil {
		t.Fatalf("Operations.Finish() error = %v", err)
	}
	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("UninstallPlugin() retry error = %v", err)
	}
	namespaces, err := h.adapters.PluginData.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("storage namespaces still present: %#v", namespaces)
	}
}

func TestUninstallForceCleanupOperationAllowsDeleteData(t *testing.T) {
	ctx := hostTestContext()
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), buildStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapters.Operations.Register(ctx, operation.RegisterRequest{
		OperationID:       "op_force_cleanup",
		ExecutionBinding:  testExecutionBinding(installed, "cleanup.force", manifest.MethodExecutionOperation),
		UninstallBehavior: operation.UninstallBehaviorForceCleanupAllowed,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.UninstallPlugin(ctx, UninstallRequest{PluginInstanceID: installed.PluginInstanceID, DeleteData: true, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatalf("UninstallPlugin() error = %v", err)
	}
	assertHostOperationStatus(t, h, "op_force_cleanup", operation.StatusOrphanedAfterUninstall)
	namespaces, err := h.adapters.PluginData.ListNamespaces(ctx, installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("storage namespaces still present: %#v", namespaces)
	}
}

func TestSecretLifecycleUsesAdapter(t *testing.T) {
	secrets := &recordingSecretStore{}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		secrets:        secrets,
	})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	req := SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        " api_token ",
		Scope:            "user",
	}
	if err := h.BindSecretRef(hostTestContext(), req); err != nil {
		t.Fatalf("BindSecretRef() error = %v", err)
	}
	if err := h.TestSecretRef(hostTestContext(), SecretTestRequest(req)); err != nil {
		t.Fatalf("TestSecretRef() error = %v", err)
	}
	if err := h.DeleteSecretRef(hostTestContext(), SecretDeleteRequest(req)); err != nil {
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

func TestSecretRefRequiresExactDeclaredScope(t *testing.T) {
	t.Run("settings", func(t *testing.T) {
		secretStore := &recordingSecretStore{}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			developerMode: true, localGenerated: true, secrets: secretStore,
		})
		installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildSettingsFixturePackage(t))
		if err != nil {
			t.Fatal(err)
		}

		err = h.BindSecretRef(hostTestContext(), SecretBindRequest{
			PluginInstanceID: installed.PluginInstanceID,
			SecretRef:        "api_token",
			Scope:            "environment",
		})
		if !errors.Is(err, ErrInvalidSecretRef) || !errors.Is(err, ErrSecretScopeMismatch) {
			t.Fatalf("BindSecretRef(scope mismatch) error = %v, want ErrInvalidSecretRef and ErrSecretScopeMismatch", err)
		}
		if secretStore.bind != (SecretBindRequest{}) {
			t.Fatalf("scope mismatch reached secret adapter: %#v", secretStore.bind)
		}
	})

	t.Run("connector auth and tls", func(t *testing.T) {
		secretStore := &recordingSecretStore{}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			developerMode: true, localGenerated: true, secrets: secretStore,
		})
		installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildConnectorSecretFixturePackage(t))
		if err != nil {
			t.Fatal(err)
		}

		for _, req := range []SecretBindRequest{
			{PluginInstanceID: installed.PluginInstanceID, SecretRef: "database_password", Scope: "environment"},
			{PluginInstanceID: installed.PluginInstanceID, SecretRef: "client_certificate", Scope: "user"},
		} {
			if err := h.BindSecretRef(hostTestContext(), req); err != nil {
				t.Fatalf("BindSecretRef(%s, %s) error = %v", req.SecretRef, req.Scope, err)
			}
		}

		lastAccepted := secretStore.bind
		for _, req := range []SecretBindRequest{
			{PluginInstanceID: installed.PluginInstanceID, SecretRef: "database_password", Scope: "user"},
			{PluginInstanceID: installed.PluginInstanceID, SecretRef: "client_certificate", Scope: "environment"},
		} {
			if err := h.BindSecretRef(hostTestContext(), req); !errors.Is(err, ErrInvalidSecretRef) || !errors.Is(err, ErrSecretScopeMismatch) {
				t.Fatalf("BindSecretRef(%s, %s) error = %v, want ErrInvalidSecretRef and ErrSecretScopeMismatch", req.SecretRef, req.Scope, err)
			}
			if secretStore.bind != lastAccepted {
				t.Fatalf("scope mismatch reached secret adapter: got %#v want %#v", secretStore.bind, lastAccepted)
			}
		}
	})
}

func TestSecretAdapterFailureRedactsCauseAndPreservesOutcome(t *testing.T) {
	sensitive := "vault token sk-live-secret at /Users/secret/path"
	for _, test := range []struct {
		name        string
		cause       error
		wantOutcome mutation.Outcome
	}{
		{name: "unknown", cause: errors.New(sensitive), wantOutcome: mutation.OutcomeUnknown},
		{name: "not committed", cause: &mutation.Error{Outcome: mutation.OutcomeNotCommitted, Err: errors.New(sensitive)}, wantOutcome: mutation.OutcomeNotCommitted},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := secretAdapterFailure("bind", test.cause)
			if !errors.Is(err, ErrAdapterFailure) {
				t.Fatalf("secretAdapterFailure() error = %v, want ErrAdapterFailure", err)
			}
			if got := mutation.ForError(err); got != test.wantOutcome {
				t.Fatalf("secretAdapterFailure() outcome = %q, want %q", got, test.wantOutcome)
			}
			if strings.Contains(err.Error(), sensitive) || strings.Contains(err.Error(), "sk-live-secret") || strings.Contains(err.Error(), "/Users/secret/path") {
				t.Fatalf("secretAdapterFailure() leaked adapter cause: %v", err)
			}
		})
	}
}

func TestSecretStoreIsTheOnlySettingsSecretAuthorityAndExportDoesNotReadIt(t *testing.T) {
	secretStore := secrets.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, secrets: secretStore,
	})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildSettingsFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID),
	}); err != nil {
		t.Fatal(err)
	}

	settingsBefore, err := h.GetPluginSettings(hostTestContext(), GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if len(settingsBefore.SecretMetadata) != 1 || settingsBefore.SecretMetadata[0].Bound {
		t.Fatalf("initial secret metadata = %#v", settingsBefore.SecretMetadata)
	}
	secretRequest := SecretBindRequest{PluginInstanceID: installed.PluginInstanceID, SecretRef: "api_token", Scope: "user"}
	if err := h.BindSecretRef(hostTestContext(), secretRequest); err != nil {
		t.Fatal(err)
	}
	settingsAfterBind, err := h.GetPluginSettings(hostTestContext(), GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if len(settingsAfterBind.SecretMetadata) != 1 || !settingsAfterBind.SecretMetadata[0].Bound {
		t.Fatalf("bound secret metadata = %#v", settingsAfterBind.SecretMetadata)
	}
	if _, exists := settingsAfterBind.Values["api_token"]; exists {
		t.Fatalf("settings values contain secret state: %#v", settingsAfterBind.Values)
	}

	h.adapters.Secrets = &failingSecretListStore{SecretStoreAdapter: secretStore, err: errors.New("vault metadata unavailable at /Users/secret/path")}
	if _, err := h.ExportPluginData(hostTestContext(), ExportDataRequest{PluginInstanceID: installed.PluginInstanceID}); err != nil {
		t.Fatalf("ExportPluginData() read the secret authority: %v", err)
	}
	h.adapters.Secrets = secretStore
	if err := h.DeleteSecretRef(hostTestContext(), SecretDeleteRequest(secretRequest)); err != nil {
		t.Fatal(err)
	}
	settingsAfterDelete, err := h.GetPluginSettings(hostTestContext(), GetSettingsRequest{PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser})
	if err != nil {
		t.Fatal(err)
	}
	if len(settingsAfterDelete.SecretMetadata) != 1 || settingsAfterDelete.SecretMetadata[0].Bound {
		t.Fatalf("deleted secret metadata = %#v", settingsAfterDelete.SecretMetadata)
	}
}

func TestSecretLifecycleValidatesRequestAndAdapter(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	withSecrets, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:  true,
		localGenerated: true,
		secrets:        &recordingSecretStore{},
	})
	if err := withSecrets.BindSecretRef(hostTestContext(), SecretBindRequest{
		PluginInstanceID: installed.PluginInstanceID,
		SecretRef:        "token",
		Scope:            "global",
	}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("BindSecretRef() error = %v, want ErrInvalidSecretRef", err)
	}

	withSecretsInstalled, err := ImportLocalPackageBytes(hostTestContext(), withSecrets, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := withSecrets.BindSecretRef(hostTestContext(), SecretBindRequest{
		PluginInstanceID: withSecretsInstalled.PluginInstanceID,
		SecretRef:        "token",
		Scope:            "user",
	}); !errors.Is(err, ErrInvalidSecretRef) {
		t.Fatalf("BindSecretRef(undeclared) error = %v, want ErrInvalidSecretRef", err)
	}
}

func TestExplicitObservabilitySinksReceiveAuditAndScopedDiagnostics(t *testing.T) {
	audits := &auditSink{}
	diagnostics := observability.NewMemoryStore()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, audit: audits, diagnostics: diagnostics,
	})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), buildFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)}); err != nil {
		t.Fatal(err)
	}

	auditEvent, ok := audits.lastEvent("plugin.enabled")
	if !ok || auditEvent.PluginID != installed.PluginID || auditEvent.PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("audit sink event mismatch: %#v", auditEvent)
	}

	h.diagnostic(hostTestContext(), observability.DiagnosticEvent{
		Type:              "plugin.surface.renderer_error",
		Severity:          "warning",
		Message:           "plugin surface renderer failed",
		PluginID:          installed.PluginID,
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_default_observability",
		CorrelationID:     "correlation_1",
		MutationOutcome:   mutation.OutcomeCommitted,
		Details:           observability.DiagnosticDetails{Reason: "unavailable"},
	})
	if err := diagnostics.AppendPluginDiagnostic(context.Background(), observability.DiagnosticEvent{
		Type: "plugin.runtime.hostcall.failed", Severity: "warning", Message: "runtime hostcall failed",
		PluginID: installed.PluginID, PluginInstanceID: installed.PluginInstanceID,
	}); err != nil {
		t.Fatal(err)
	}
	diagnosticEvents, err := h.ListDiagnosticEvents(hostTestContext(), ListDiagnosticEventsRequest{
		PluginInstanceID:  installed.PluginInstanceID,
		SurfaceInstanceID: "surface_default_observability",
		Severity:          "warning",
	})
	if err != nil {
		t.Fatalf("ListDiagnosticEvents() error = %v", err)
	}
	if len(diagnosticEvents) != 1 || diagnosticEvents[0].Type != "plugin.surface.renderer_error" ||
		diagnosticEvents[0].Message != "plugin surface renderer failed" || diagnosticEvents[0].CorrelationID != "correlation_1" ||
		diagnosticEvents[0].MutationOutcome != mutation.OutcomeCommitted || diagnosticEvents[0].Details.Reason != "unavailable" {
		t.Fatalf("diagnostic events mismatch: %#v", diagnosticEvents)
	}
	background, err := h.ListDiagnosticEvents(hostTestContext(), ListDiagnosticEventsRequest{Type: "plugin.runtime.hostcall.failed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(background) != 0 {
		t.Fatalf("background diagnostics leaked into user scope: %#v", background)
	}
}

func TestPublicDiagnosticDetailsExplicitlyMapAllFields(t *testing.T) {
	internal := observability.DiagnosticDetails{
		OperationsDeleted: 1, StreamsDeleted: 2, InvocationID: "invocation_1", Method: "method.read",
		FailureCode: "failure_code", RuntimeProcessFailureCode: observability.RuntimeProcessWriterWriteFailed,
		OperationID: "operation_1", StreamID: "stream_1",
		RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "generation_1", RuntimeVersion: "0.5.0",
		RustIPCVersion: "rust-ipc-v6", WASMABIVersion: "wasm-abi-v1", ContractSetSHA256: version.ContractSetSHA256, RuntimeTargetOS: "linux",
		RuntimeTargetArch: "amd64", RuntimeBinarySHA256: strings.Repeat("a", 64), OS: "linux", Arch: "amd64",
		Stream: "stderr", PackageHash: "sha256:package", Artifact: "worker.wasm", PluginInstanceID: "plugin_1",
		StoreID: "store_1", Operation: "runtime.start", Hostcall: "storage.kv", Code: "PLUGIN_RUNTIME_UNAVAILABLE",
		ConnectorID: "connector_1", Transport: "tcp", RevokeEpoch: 3, StageID: "stage_1",
		Reason: "unavailable", SurfaceInstanceID: "surface_1",
	}
	want := DiagnosticDetails{
		OperationsDeleted: 1, StreamsDeleted: 2, InvocationID: "invocation_1", Method: "method.read",
		FailureCode: "failure_code", RuntimeProcessFailureCode: observability.RuntimeProcessWriterWriteFailed,
		OperationID: "operation_1", StreamID: "stream_1",
		RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "generation_1", RuntimeVersion: "0.5.0",
		RustIPCVersion: "rust-ipc-v6", WASMABIVersion: "wasm-abi-v1", ContractSetSHA256: version.ContractSetSHA256, RuntimeTargetOS: "linux",
		RuntimeTargetArch: "amd64", RuntimeBinarySHA256: strings.Repeat("a", 64), OS: "linux", Arch: "amd64",
		Stream: "stderr", PackageHash: "sha256:package", Artifact: "worker.wasm", PluginInstanceID: "plugin_1",
		StoreID: "store_1", Operation: "runtime.start", Hostcall: "storage.kv", Code: "PLUGIN_RUNTIME_UNAVAILABLE",
		ConnectorID: "connector_1", Transport: "tcp", RevokeEpoch: 3, StageID: "stage_1",
		Reason: "unavailable", SurfaceInstanceID: "surface_1",
	}
	if got := publicDiagnosticDetails(internal); !reflect.DeepEqual(got, want) {
		t.Fatalf("public diagnostic details = %#v, want %#v", got, want)
	}
}

func TestUserTriggeredDiagnosticHelpersAttachScopeAndHideInternalCause(t *testing.T) {
	const sensitive = "vault-token-super-secret at /Users/secret/path"
	diagnostics := &listingDiagnosticSink{}
	sessionScopeStore, err := sessionscope.NewMemoryStore(sessionscope.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sessionScopes, err := sessionscope.NewCoordinator(sessionScopeStore)
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{
		adapters:        normalizedAdapters{Authorization: allowAuthorizationAdapter{}, Diagnostics: diagnostics},
		securityJournal: observability.NewMemorySecurityAuditJournal(),
		sessionScopes:   sessionScopes,
	}
	record := registry.PluginRecord{
		PluginID: "com.example.plugin", PluginInstanceID: "plugini_1", ActiveFingerprint: "sha256:active",
	}

	h.reportLifecycleDiagnostic(
		hostTestContext(),
		record,
		"plugin.runtime_state.refresh_failed",
		"plugin runtime state refresh failed",
		errors.New(sensitive),
		observability.DiagnosticDetails{StageID: "refresh"},
	)
	if err := h.reportMethodRejection(hostTestContext(), record, "example.read", "surface_1", fmt.Errorf("%w: %s", permissions.ErrPermissionDenied, sensitive)); err != nil {
		t.Fatal(err)
	}
	if len(diagnostics.events) != 2 {
		t.Fatalf("diagnostic count = %d, want 2: %#v", len(diagnostics.events), diagnostics.events)
	}
	for index, event := range diagnostics.events {
		if event.OwnerSessionHash != "session_hash" || event.OwnerUserHash != "user_hash" || event.OwnerEnvHash != "env_hash" || event.SessionChannelIDHash != "channel_hash" {
			t.Fatalf("diagnostic owner scope mismatch: %#v", event)
		}
		if index == 0 {
			failure := event.Failure
			if failure.Code != observability.FailureAction || failure.Component != observability.FailureComponentLifecycle || failure.Operation != observability.FailureOperationLifecycle || strings.Contains(fmt.Sprint(event), sensitive) {
				t.Fatalf("diagnostic internal cause was not redacted: %#v", event)
			}
		}
		if index == 1 && (event.Failure.Operation != observability.FailureOperationMethodReject || event.MutationOutcome != mutation.OutcomeNotCommitted) {
			t.Fatalf("method rejection failure metadata mismatch: %#v", event)
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), sensitive) || strings.Contains(string(encoded), "internal_details") {
			t.Fatalf("diagnostic internal cause was serialized: %s", encoded)
		}
	}
	if diagnostics.events[0].Message != "plugin runtime state refresh failed" || diagnostics.events[1].Message != "plugin method was rejected" {
		t.Fatalf("diagnostic public messages are unstable: %#v", diagnostics.events)
	}
	diagnostics.events = append(diagnostics.events, observability.DiagnosticEvent{
		Type: "plugin.runtime.warning", Severity: "warning", Message: "runtime warning", OccurredAt: time.Now().UTC(),
		OwnerSessionHash: "session_other", OwnerUserHash: "user_other", OwnerEnvHash: "env_other", SessionChannelIDHash: "channel_other",
		Failure: observability.FailureFromError(observability.FailureAction, observability.FailureComponentRuntime, observability.FailureOperationRuntimeHostcall, errors.New(sensitive)),
	})
	listed, err := h.ListDiagnosticEvents(hostTestContext(), ListDiagnosticEventsRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("host diagnostic list did not filter other owner: %#v", listed)
	}
	for _, event := range listed {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), sensitive) || strings.Contains(string(encoded), "owner_session_hash") || strings.Contains(string(encoded), "internal_details") {
			t.Fatalf("host diagnostic list exposed internal fields: %s", encoded)
		}
	}
	diagnostics.events = append(diagnostics.events,
		observability.DiagnosticEvent{
			EventID: "diagnostic_wrong_plugin", Type: "plugin.method.rejected", Severity: "warning", Message: "plugin method was rejected", OccurredAt: time.Now().UTC(),
			PluginID: "com.example.other", PluginInstanceID: "plugini_other", SurfaceInstanceID: "surface_1",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
		},
		observability.DiagnosticEvent{
			EventID: "diagnostic_wrong_type", Type: "plugin.runtime.warning", Severity: "warning", Message: "runtime warning", OccurredAt: time.Now().UTC(),
			PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, SurfaceInstanceID: "surface_other",
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
		},
	)
	scoped, err := h.ListDiagnosticEvents(hostTestContext(), ListDiagnosticEventsRequest{
		PluginID: record.PluginID, PluginInstanceID: record.PluginInstanceID, SurfaceInstanceID: "surface_1",
		Type: "plugin.method.rejected", Severity: observability.DiagnosticSeverityWarning, Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || scoped[0].Type != "plugin.method.rejected" || scoped[0].PluginInstanceID != record.PluginInstanceID {
		t.Fatalf("host diagnostic list did not enforce the complete public filter: %#v", scoped)
	}
}

func newTestHost(t *testing.T, developerMode bool, localGenerated bool) (*Host, *surfaceSink, *auditSink) {
	return newTestHostWithOptions(t, testHostOptions{developerMode: developerMode, localGenerated: localGenerated})
}

type testHostOptions struct {
	developerMode           bool
	localGenerated          bool
	policyDecision          PolicyDecision
	authorization           AuthorizationAdapter
	trustVerifier           PackageTrustVerifier
	releaseTrust            *releasetrust.ServiceSet
	releaseArtifactResolver ReleaseArtifactResolver
	capabilityArtifacts     CapabilityContractArtifactResolver
	registry                registry.Store
	pluginData              PluginData
	pluginDataRoot          string
	connectivityBroker      connectivity.Broker
	networkExecutor         connectivity.NetworkExecutor
	installStages           installstage.Store
	confirmationIntents     security.ConfirmationIntentStore
	operations              operation.Store
	streams                 stream.Store
	runtimeManager          runtimeclient.Manager
	runtimeManagerFactory   func(testRuntimeManagerDependencies) (runtimeclient.Manager, error)
	withoutRuntimeManager   bool
	sessionLifecycle        SessionLifecycleAdapter
	sessionScopePath        string
	secrets                 SecretStoreAdapter
	audit                   AuditSink
	diagnostics             DiagnosticsSink
	hostRequirements        HostRequirementPolicy
	capabilities            *capability.Registry
	capabilityID            string
	capabilityContract      *capabilitycontract.VerifiedContract
	capabilityAdapter       interface {
		capability.Adapter
		capability.TargetProjector
	}
	coreActions    CoreActionAdapter
	surfaceTokens  *bridge.SurfaceTokenService
	expectCloseErr bool
}

type testRuntimeManagerDependencies struct {
	Diagnostics     DiagnosticsSink
	Assets          pluginpkg.AssetStore
	SurfaceTokens   *bridge.SurfaceTokenService
	PluginData      PluginData
	Connectivity    connectivity.Broker
	NetworkExecutor connectivity.NetworkExecutor
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
	authorization := opts.authorization
	if authorization == nil {
		authorization = allowAuthorizationAdapter{}
	}
	trustVerifier := opts.trustVerifier
	if trustVerifier == nil {
		trustVerifier = &recordingPackageTrustVerifier{}
	}
	releaseArtifactResolver := opts.releaseArtifactResolver
	hostRequirements := opts.hostRequirements
	if hostRequirements == nil {
		hostRequirements = &fixedHostRequirementPolicy{hostID: "test-host"}
	}
	capabilityArtifacts := opts.capabilityArtifacts
	if capabilityArtifacts == nil {
		capabilityArtifacts = &recordingCapabilityContractArtifactResolver{}
	}
	diagnostics := opts.diagnostics
	if diagnostics == nil {
		diagnostics = observability.NewMemoryStore()
	}
	audit := opts.audit
	if audit == nil {
		audit = audits
	}
	connectivityBroker := opts.connectivityBroker
	if connectivityBroker == nil {
		connectivityBroker = connectivity.NewMemoryBroker()
	}
	networkExecutor := opts.networkExecutor
	if networkExecutor == nil {
		networkExecutor = connectivity.NewExecutor(connectivity.ExecutorOptions{})
	}
	installStageStore := opts.installStages
	if installStageStore == nil {
		installStageStore = installstage.NewMemoryStore()
	}
	confirmationIntentStore := opts.confirmationIntents
	if confirmationIntentStore == nil {
		confirmationIntentStore = security.NewMemoryConfirmationIntentStore()
	}
	operationStore := opts.operations
	if operationStore == nil {
		operationStore = operation.NewMemoryStore()
	}
	streamStore := opts.streams
	if streamStore == nil {
		streamStore = stream.NewMemoryStore()
	}
	registryStore := opts.registry
	if registryStore == nil {
		registryStore = registry.NewMemoryStore()
	}
	pluginData := opts.pluginData
	if pluginData == nil {
		root := opts.pluginDataRoot
		if root == "" {
			root = t.TempDir()
		}
		var err error
		pluginData, err = plugindata.Open(hostTestContext(), root, registryStore)
		if err != nil {
			t.Fatal(err)
		}
	}
	secretStore := opts.secrets
	if secretStore == nil {
		secretStore = secrets.NewMemoryStore()
	}
	coreActions := opts.coreActions
	if coreActions == nil {
		coreActions = &recordingCoreActionAdapter{}
	}
	surfaceTokens := opts.surfaceTokens
	if surfaceTokens == nil {
		surfaceTokens = bridge.NewSurfaceTokenService(nil, bridge.SurfaceTokenOptions{})
	}
	assetStore := pluginpkg.NewMemoryAssetStore()
	runtimeManager := opts.runtimeManager
	if opts.runtimeManagerFactory != nil {
		if runtimeManager != nil {
			t.Fatal("runtime manager and runtime manager factory are mutually exclusive")
		}
		var err error
		runtimeManager, err = opts.runtimeManagerFactory(testRuntimeManagerDependencies{
			Diagnostics:     diagnostics,
			Assets:          assetStore,
			SurfaceTokens:   surfaceTokens,
			PluginData:      pluginData,
			Connectivity:    connectivityBroker,
			NetworkExecutor: networkExecutor,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if runtimeManager == nil && !opts.withoutRuntimeManager {
		runtimeManager = newRecordingRuntimeManager()
	}
	var runtimeModule *RuntimeModule
	if runtimeManager != nil {
		runtimeModule = &RuntimeModule{manager: runtimeManager}
	}
	securityJournal := observability.NewMemorySecurityAuditJournal()
	sessionScopePath := opts.sessionScopePath
	if sessionScopePath == "" {
		sessionScopePath = filepath.Join(t.TempDir(), "session-scopes.sqlite")
	}
	sessionScopeStore, err := sessionscope.NewSQLiteStore(
		hostTestContext(),
		sessionScopePath,
		sessionscope.StoreOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sessionScopeStore.Close() })
	sessionScopes, err := sessionscope.NewCoordinator(sessionScopeStore)
	if err != nil {
		t.Fatal(err)
	}
	sessionLifecycle := opts.sessionLifecycle
	if sessionLifecycle == nil {
		sessionLifecycle = &testSessionLifecycleAdapter{}
	}
	var releaseModule *ReleaseModule
	if opts.releaseTrust != nil || releaseArtifactResolver != nil {
		releaseModule = &ReleaseModule{
			Trust:                       opts.releaseTrust,
			ReleaseArtifactResolver:     releaseArtifactResolver,
			HostRequirements:            hostRequirements,
			CapabilityContractArtifacts: capabilityArtifacts,
		}
	}
	host, err := Open(hostTestContext(), Config{
		Core: CoreAdapters{
			Policy: policyAdapter{
				developerMode:  opts.developerMode,
				localGenerated: opts.localGenerated,
				decision:       decision,
			},
			Authorization:        authorization,
			PackageTrustVerifier: trustVerifier,
			Registry:             registryStore,
			SurfaceCatalog:       surfaces,
			Audit:                audit,
			SecurityAudit:        securityJournal,
			Diagnostics:          diagnostics,
			Assets:               assetStore,
			PluginData:           pluginData,
			InstallStages:        installStageStore,
			ConfirmationIntents:  confirmationIntentStore,
			Operations:           operationStore,
			Streams:              streamStore,
			SurfaceTokens:        surfaceTokens,
			SessionLifecycle:     sessionLifecycle,
			SessionScopes:        sessionScopes,
		},
		Release:      releaseModule,
		Runtime:      runtimeModule,
		Capability:   &CapabilityModule{Registry: capabilities},
		Connectivity: &ConnectivityModule{Broker: connectivityBroker, NetworkExecutor: networkExecutor},
		Secrets:      &SecretsModule{Store: secretStore},
		CoreAction:   &CoreActionModule{Adapter: coreActions},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := host.Close(); err != nil && !opts.expectCloseErr {
			t.Errorf("Host.Close() error = %v", err)
		} else if err == nil && opts.expectCloseErr {
			t.Error("Host.Close() error = nil, want expected test cleanup failure")
		}
	})
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

func fixtureVerifiedCapabilityContractWithQuotas(t *testing.T, capabilityID string, quotas map[string]capabilitycontract.Quota) capabilitycontract.VerifiedContract {
	t.Helper()
	contract, err := fixtureCapabilityContract(capabilityID)
	if err != nil {
		t.Fatal(err)
	}
	remaining := make(map[string]capabilitycontract.Quota, len(quotas))
	for method, quota := range quotas {
		remaining[method] = quota
	}
	for index := range contract.Methods {
		quota, ok := remaining[contract.Methods[index].Name]
		if !ok {
			continue
		}
		contract.Methods[index].Quota = quota
		delete(remaining, contract.Methods[index].Name)
	}
	if len(remaining) != 0 {
		t.Fatalf("fixture capability contract %q is missing quota methods %#v", capabilityID, remaining)
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildConnectorSecretFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := networkFixtureManifestJSON(false)
	manifestJSON = strings.Replace(
		manifestJSON,
		`"destinations": ["https://api.example.com"]}`,
		`"destinations": ["https://api.example.com"], "tls": {"client": {"secret_ref": "client_certificate"}}}`,
		1,
	)
	manifestJSON = strings.Replace(
		manifestJSON,
		`"destinations": ["db.example.com:3306"]}`,
		`"destinations": ["db.example.com:3306"], "auth": {"secret_ref": "database_password"}}`,
		1,
	)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Connector Secrets")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type dataShapeFixtureOptions struct {
	Version        string
	SettingsSchema int
	StorageSchema  int
}

func buildDataShapeFixturePackage(t *testing.T, opts dataShapeFixtureOptions) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), dataShapeFixtureManifestJSON(opts))
	writeSurfaceFixture(t, dir, "Data Shape")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildNestedCoreActionFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(coreActionFixtureManifestJSON(),
		`"properties": {"target": {"type": "string"}}`,
		`"properties": {"target": {"type": "object", "additionalProperties": false, "required": ["name"], "properties": {"name": {"type": "string"}}}}`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Core Action")
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildMutatingWorkerFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	manifestJSON := strings.Replace(workerFixtureManifestJSON(), `"effect": "read"`, `"effect": "write"`, 1)
	writeFile(t, filepath.Join(dir, "manifest.json"), manifestJSON)
	writeSurfaceFixture(t, dir, "Worker")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), importedMemoryHostcallWorkerWASMForTest("redevplugin.network", "execute", "network_execute", "redevplugin_worker_invoke", request))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildWorkerStorageFixturePackage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), workerStorageFixtureManifestJSON())
	writeSurfaceFixture(t, dir, "Worker Storage")
	writeBytes(t, filepath.Join(dir, "workers", "echo.wasm"), storageMemoryHostcallWorkerWASMForTest("redevplugin_worker_invoke"))
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	var buf bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &buf, pluginpkg.DefaultReadLimits()); err != nil {
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
	writeBytes(t, filepath.Join(dir, "ui", "assets", "status.png"), validPNGForTest())
}

func validPNGForTest() []byte {
	raw, err := hex.DecodeString("89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da6364f80f00010501012718e3660000000049454e44ae426082")
	if err != nil {
		panic(err)
	}
	return raw
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
	response := []byte(`{"ok":true,"data":{"backend":"executed wasm worker scaffold","transport":"rust runtime ipc","method":"worker.echo","worker_id":"echo_worker"}}`)
	return abiV2WorkerWASMForTest(exportName, response, nil)
}

type wasmHostcallFixture struct {
	importModule  string
	importName    string
	responseField string
	request       []byte
}

func networkMemoryHostcallWorkerWASMForTest(exportName string) []byte {
	request := []byte(`{"connector_id":"api","transport":"http","destination":"https://api.example.com","operation":"http","method":"POST","path":"/v1/worker","headers":{"Content-Type":["text/plain"]},"body_base64":"aGVsbG8gZnJvbSBtZW1vcnkgaG9zdGNhbGw=","max_request_bytes":1024,"max_response_bytes":4096,"timeout_ms":1000}`)
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.network", "execute", "network_execute", exportName, request)
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
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.network", "execute", "network_execute", exportName, request)
}

func storageMemoryHostcallWorkerWASMForTest(exportName string) []byte {
	request := []byte(`{"store_id":"workspace","operation":"write","path":"notes/from-memory.txt","data_base64":"aGVsbG8gZnJvbSBtZW1vcnkgc3RvcmFnZSBob3N0Y2FsbA==","max_bytes":0,"max_entries":0,"recursive":false}`)
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.storage", "files", "storage_file", exportName, request)
}

func storageKVMemoryHostcallWorkerWASMForTest(exportName string) []byte {
	request := []byte(`{"store_id":"cache","operation":"put","key":"runs/latest","value_base64":"aGVsbG8gZnJvbSBtZW1vcnkga3YgaG9zdGNhbGw=","max_bytes":0,"max_entries":0}`)
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.storage", "kv", "storage_kv", exportName, request)
}

func storageSQLiteMemoryHostcallWorkerWASMForTest(exportName string) []byte {
	request := []byte(`{"store_id":"db","operation":"exec","database":"plugin.sqlite","sql":"CREATE TABLE IF NOT EXISTS worker_runs (id INTEGER PRIMARY KEY, note TEXT NOT NULL)","args":[],"timeout_ms":1000}`)
	return importedMemoryHostcallWorkerWASMForTest("redevplugin.storage", "sqlite", "storage_sqlite", exportName, request)
}

func importedMemoryHostcallWorkerWASMForTest(importModule string, importName string, responseField string, exportName string, request []byte) []byte {
	return abiV2WorkerWASMForTest(exportName, nil, &wasmHostcallFixture{
		importModule:  importModule,
		importName:    importName,
		responseField: responseField,
		request:       request,
	})
}

func abiV2WorkerWASMForTest(exportName string, staticResponse []byte, hostcall *wasmHostcallFixture) []byte {
	const (
		outputPointer            = int32(64 * 1024)
		requestAllocationPointer = int32(512 * 1024)
		hostcallResponseCapacity = int32(256 * 1024)
	)
	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

	types := []byte{0x04}
	types = append(types,
		0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
		0x60, 0x01, 0x7f, 0x01, 0x7f,
		0x60, 0x02, 0x7f, 0x7f, 0x00,
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e,
	)
	module = appendWASMSection(module, 0x01, types)

	importedFunctionCount := uint32(0)
	if hostcall != nil {
		imports := []byte{0x01}
		imports = appendWASMName(imports, hostcall.importModule)
		imports = appendWASMName(imports, hostcall.importName)
		imports = append(imports, 0x00, 0x00)
		module = appendWASMSection(module, 0x02, imports)
		importedFunctionCount = 1
	}
	module = appendWASMSection(module, 0x03, []byte{0x03, 0x01, 0x02, 0x03})
	module = appendWASMSection(module, 0x05, []byte{0x01, 0x00, 0x10})

	exports := []byte{0x04}
	exports = appendWASMName(exports, "memory")
	exports = append(exports, 0x02, 0x00)
	exports = appendWASMName(exports, "redevplugin_worker_alloc")
	exports = append(exports, 0x00)
	exports = appendLEBUint32(exports, importedFunctionCount)
	exports = appendWASMName(exports, "redevplugin_worker_dealloc")
	exports = append(exports, 0x00)
	exports = appendLEBUint32(exports, importedFunctionCount+1)
	exports = appendWASMName(exports, exportName)
	exports = append(exports, 0x00)
	exports = appendLEBUint32(exports, importedFunctionCount+2)
	module = appendWASMSection(module, 0x07, exports)

	allocBody := []byte{0x00, 0x41}
	allocBody = appendLEBInt32(allocBody, requestAllocationPointer)
	allocBody = append(allocBody, 0x0b)
	deallocBody := []byte{0x00, 0x0b}
	invokeBody := []byte{0x00}
	dataSegments := make([]struct {
		offset int32
		data   []byte
	}, 0, 2)

	if hostcall == nil {
		invokeBody = appendPackedWASMResponse(invokeBody, outputPointer, nil, int32(len(staticResponse)))
		dataSegments = append(dataSegments, struct {
			offset int32
			data   []byte
		}{offset: outputPointer, data: staticResponse})
	} else {
		prefix := []byte(`{"ok":true,"data":{"` + hostcall.responseField + `":`)
		suffix := []byte(`}}`)
		invokeBody = []byte{0x01, 0x01, 0x7f, 0x41, 0x00, 0x41}
		invokeBody = appendLEBInt32(invokeBody, int32(len(hostcall.request)))
		invokeBody = append(invokeBody, 0x41)
		invokeBody = appendLEBInt32(invokeBody, outputPointer+int32(len(prefix)))
		invokeBody = append(invokeBody, 0x41)
		invokeBody = appendLEBInt32(invokeBody, hostcallResponseCapacity)
		invokeBody = append(invokeBody, 0x10, 0x00, 0x21, 0x02)
		for index, value := range suffix {
			invokeBody = append(invokeBody, 0x41)
			invokeBody = appendLEBInt32(invokeBody, outputPointer+int32(len(prefix)))
			invokeBody = append(invokeBody, 0x20, 0x02, 0x6a, 0x41)
			invokeBody = appendLEBInt32(invokeBody, int32(index))
			invokeBody = append(invokeBody, 0x6a, 0x41)
			invokeBody = appendLEBInt32(invokeBody, int32(value))
			invokeBody = append(invokeBody, 0x3a, 0x00, 0x00)
		}
		invokeBody = appendPackedWASMResponse(invokeBody, outputPointer, []byte{0x20, 0x02}, int32(len(prefix)+len(suffix)))
		dataSegments = append(dataSegments,
			struct {
				offset int32
				data   []byte
			}{offset: 0, data: hostcall.request},
			struct {
				offset int32
				data   []byte
			}{offset: outputPointer, data: prefix},
		)
	}
	invokeBody = append(invokeBody, 0x0b)
	code := []byte{0x03}
	code = appendWASMFunctionBody(code, allocBody)
	code = appendWASMFunctionBody(code, deallocBody)
	code = appendWASMFunctionBody(code, invokeBody)
	module = appendWASMSection(module, 0x0a, code)

	data := appendLEBUint32(nil, uint32(len(dataSegments)))
	for _, segment := range dataSegments {
		data = append(data, 0x00, 0x41)
		data = appendLEBInt32(data, segment.offset)
		data = append(data, 0x0b)
		data = appendLEBUint32(data, uint32(len(segment.data)))
		data = append(data, segment.data...)
	}
	return appendWASMSection(module, 0x0b, data)
}

func appendPackedWASMResponse(body []byte, responsePointer int32, dynamicLength []byte, staticLength int32) []byte {
	body = append(body, 0x41)
	body = appendLEBInt32(body, responsePointer)
	body = append(body, 0xad, 0x42, 0x20, 0x86)
	if len(dynamicLength) > 0 {
		body = append(body, dynamicLength...)
		body = append(body, 0xad, 0x41)
		body = appendLEBInt32(body, staticLength)
		body = append(body, 0xad, 0x7c)
	} else {
		body = append(body, 0x41)
		body = appendLEBInt32(body, staticLength)
		body = append(body, 0xad)
	}
	return append(body, 0x84)
}

func appendWASMSection(module []byte, sectionID byte, payload []byte) []byte {
	module = append(module, sectionID)
	module = appendLEBUint32(module, uint32(len(payload)))
	return append(module, payload...)
}

func appendWASMName(out []byte, value string) []byte {
	out = appendLEBUint32(out, uint32(len(value)))
	return append(out, value...)
}

func appendWASMFunctionBody(out []byte, body []byte) []byte {
	out = appendLEBUint32(out, uint32(len(body)))
	return append(out, body...)
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

func fixtureManifestJSON() string {
	return lifecycleManifestJSON("1.0.0", "Lifecycle")
}

func lifecycleManifestJSON(version string, title string) string {
	if title == "" {
		title = "Lifecycle"
	}
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.lifecycle",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "lifecycle.view", "kind": "view", "label": "Lifecycle", "entry": "ui/index.html"}
		]
	}`
}

func storageFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.storage",
			"display_name": "Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
					"schema_version": 1
				},
				{
					"store_id": "db",
					"kind": "sqlite",
					"scope": "environment",
					"quota_bytes": 8192,
					"quota_files": 32,
					"schema_version": 2
				}
			]
		}
	}`
}

func settingsFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.settings",
			"display_name": "Settings",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "settings.view", "kind": "view", "label": "Settings", "entry": "ui/index.html"}
		],
		"settings": {
			"schema_version": 1,
			"fields": [
				{"key": "default_engine", "type": "select", "scope": "user", "label": "Default engine", "default": "docker", "options": ["docker", "podman"]},
				{"key": "show_stopped", "type": "boolean", "scope": "user", "label": "Show stopped", "default": true},
				{"key": "api_token", "type": "secret", "scope": "user", "label": "API token", "secret_ref": "api_token"}
			]
		}
	}`
}

func dataShapeFixtureManifestJSON(opts dataShapeFixtureOptions) string {
	version := opts.Version
	if version == "" {
		version = "1.0.0"
	}
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.data-shape",
			"display_name": "Data Shape",
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "data-shape.view", "kind": "view", "label": "Data Shape", "entry": "ui/index.html"}
		],
		"storage": {
			"stores": [
				{
					"store_id": "workspace",
					"kind": "files",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": ` + strconv.Itoa(opts.StorageSchema) + `
				}
			]
		},
		"settings": {
			"schema_version": ` + strconv.Itoa(opts.SettingsSchema) + `,
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.rpc",
			"display_name": ` + strconv.Quote(title) + `,
			"version": ` + strconv.Quote(version) + `,
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.danger",
			"display_name": "Danger",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.operation",
			"display_name": "Operation",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.subscription",
			"display_name": "Subscription",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.core",
			"display_name": "Core Action",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
					"message": {"type": "string"}
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
						"storage_sqlite_result": {"type": "object", "additionalProperties": false, "properties": {"ok": {"type": "boolean"}, "database": {"type": "string"}, "rows_affected": {"type": "integer", "minimum": 0}, "last_insert_id": {"type": "integer", "minimum": 0}, "usage": {"$ref": "#/$defs/storage_usage"}}}
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker",
			"display_name": "Worker",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.0.0-dev",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v2",
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
				"route": {"kind": "worker", "worker_id": "echo_worker"}
			}
		]
	}`
}

func workerNetworkFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.network",
			"display_name": "Worker Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.0.0-dev",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v2",
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
				` + workerNetworkBrokerAccessJSON(connectivity.TransportHTTP) + `
				"route": {"kind": "worker", "worker_id": "echo_worker"}
			}
		],
		"network_access": {
			"connectors": [
				{"connector_id": "api", "transport": "http", "scope": "user", "destinations": ["https://api.example.com"]}
			]
		}
	}`
}

func workerNetworkBrokerAccessJSON(transport connectivity.Transport) string {
	switch transport {
	case connectivity.TransportWebSocket:
		return `"broker_access": {"network": [{"connector_id": "stream", "transport": "websocket", "operations": ["websocket_round_trip"]}]},`
	case connectivity.TransportTCP:
		return `"broker_access": {"network": [{"connector_id": "mysql", "transport": "tcp", "operations": ["tcp_round_trip"]}]},`
	case connectivity.TransportUDP:
		return `"broker_access": {"network": [{"connector_id": "metrics", "transport": "udp", "operations": ["udp_round_trip"]}]},`
	default:
		return `"broker_access": {"network": [{"connector_id": "api", "transport": "http", "operations": ["http", "http_stream"], "http_methods": ["GET", "POST"]}]},`
	}
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.network.transport",
			"display_name": "Worker Network Transport",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.0.0-dev",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v2",
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
				` + workerNetworkBrokerAccessJSON(transport) + `
				"route": {"kind": "worker", "worker_id": "echo_worker"}
			}
		],
		"network_access": {
			"connectors": [` + connector + `]
		}
	}`
}

func workerStorageFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage",
			"display_name": "Worker Storage",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.0.0-dev",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v2",
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
				"broker_access": {"storage": [{"store_id": "workspace", "operations": ["read", "write", "delete", "list"]}]},
				"route": {"kind": "worker", "worker_id": "echo_worker"}
			}
		],
		"storage": {
			"stores": [
				{
					"store_id": "workspace",
					"kind": "files",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": 1
				}
			]
		}
	}`
}

func workerStorageKVFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage.kv",
			"display_name": "Worker Storage KV",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.0.0-dev",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v2",
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
				"broker_access": {"storage": [{"store_id": "cache", "operations": ["get", "put", "delete", "list"]}]},
				"route": {"kind": "worker", "worker_id": "echo_worker"}
			}
		],
		"storage": {
			"stores": [
				{
					"store_id": "cache",
					"kind": "kv",
					"scope": "user",
					"quota_bytes": 4096,
					"schema_version": 1
				}
			]
		}
	}`
}

func workerStorageSQLiteFixtureManifestJSON() string {
	return `{
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.worker.storage.sqlite",
			"display_name": "Worker Storage SQLite",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.0.0-dev",
			"ui_protocol_version": "plugin-ui-v5"
		},
		"surfaces": [
			{"surface_id": "worker.view", "kind": "view", "label": "Worker", "entry": "ui/index.html"}
		],
		"workers": [
			{
				"worker_id": "echo_worker",
				"artifact": "workers/echo.wasm",
				"abi": "redevplugin-wasm-worker-v2",
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
				"broker_access": {"storage": [{"store_id": "db", "operations": ["exec", "query"]}]},
				"route": {"kind": "worker", "worker_id": "echo_worker"}
			}
		],
		"storage": {
			"stores": [
				{
					"store_id": "db",
					"kind": "sqlite",
					"scope": "user",
					"quota_bytes": 65536,
					"schema_version": 1
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
		"schema_version": "redevplugin.manifest.v5",
		"publisher": {"publisher_id": "example", "display_name": "Example"},
		"plugin": {
			"plugin_id": "com.example.network",
			"display_name": "Network",
			"version": "1.0.0",
			"api_version": "plugin-v1",
			"min_runtime_version": "0.1.0",
			"ui_protocol_version": "plugin-ui-v5"
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
					"schema_version": 1
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
	return installEnableAndMintGatewayForAudience(t, h, packageBytes, surfaceID, "surface_rpc", "bridge_rpc")
}

func installEnableAndMintGatewayForAudience(t *testing.T, h *Host, packageBytes []byte, surfaceID, surfaceInstanceID, bridgeChannelID string) (registry.PluginRecord, bridge.GatewayTokenResult) {
	t.Helper()
	installed := installAndEnablePlugin(t, h, packageBytes)
	grantDeclaredPermissions(t, h, installed)
	_, gateway := openSurfaceAndMintGatewayForAudience(t, h, installed.PluginInstanceID, surfaceID, surfaceInstanceID, bridgeChannelID)
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
	ctx := hostTestContext()
	now := stableRecentTestNow()
	installed, err := ImportLocalPackageBytes(ctx, h, nextTestPluginInstanceID(t), packageBytes)
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := h.EnablePlugin(ctx, EnableRequest{PluginInstanceID: installed.PluginInstanceID, Now: now, ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID)})
	if err != nil {
		t.Fatal(err)
	}
	return enabled
}

func openSurfaceAndMintGateway(t *testing.T, h *Host, pluginInstanceID string, surfaceID string) (bridge.SurfaceBootstrap, bridge.GatewayTokenResult) {
	t.Helper()
	return openSurfaceAndMintGatewayForAudience(t, h, pluginInstanceID, surfaceID, "surface_rpc", "bridge_rpc")
}

func openSurfaceAndMintGatewayForAudience(t *testing.T, h *Host, pluginInstanceID, surfaceID, surfaceInstanceID, bridgeChannelID string) (bridge.SurfaceBootstrap, bridge.GatewayTokenResult) {
	t.Helper()
	ctx := hostTestContext()
	now := stableRecentTestNow()
	record, err := h.adapters.Registry.GetPlugin(ctx, pluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID:  record.PluginInstanceID,
		SurfaceID:         surfaceID,
		SurfaceInstanceID: surfaceInstanceID,

		Now: now.Add(time.Second), ExpectedManagementRevision: mustManagementRevision(t, h,
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
		ManagementRevision: bootstrap.ManagementRevision,
		RevokeEpoch:        bootstrap.RevokeEpoch,
		UIProtocolVersion:  "plugin-ui-v5",
	}
	gateway, err := h.MintBridgeToken(ctx, MintBridgeTokenRequest{
		Handshake:                 handshake,
		BridgeChannelID:           bridgeChannelID,
		HandshakeTranscriptSHA256: bridge.HandshakeTranscriptSHA256(handshake, bridgeChannelID),

		Now: now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap, gateway
}

func stableRecentTestNow() time.Time {
	return time.Now().UTC().Add(-1 * time.Minute)
}

func exchangeAssetTicketRequestForBootstrap(bootstrap bridge.SurfaceBootstrap, now time.Time) PrepareSurfaceRequest {
	return PrepareSurfaceRequest{
		SurfaceInstanceID: bootstrap.SurfaceInstanceID,
		AssetTicket:       bootstrap.AssetTicket,

		Now: now,
	}
}

func scopedReadStreamRequest(streamID string, streamTicket string) ReadStreamRequest {
	return ReadStreamRequest{
		StreamID:          streamID,
		StreamTicket:      streamTicket,
		ReadID:            "read_host_test_1",
		SurfaceInstanceID: "surface_rpc",
	}
}

func acknowledgeStreamResult(t *testing.T, h *Host, streamID string, streamTicket string, result ReadStreamResult) {
	t.Helper()
	if _, err := h.AcknowledgeStream(hostTestContext(), AcknowledgeStreamRequest{
		StreamID: streamID, StreamTicket: streamTicket,
		DeliveryID: result.DeliveryID, SurfaceInstanceID: "surface_rpc",
	}); err != nil {
		t.Fatalf("AcknowledgeStream() error = %v", err)
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
			OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash",
			ResourceScope: sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
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
		expected := mustAuthorizationRevisions(t, h, record.PluginInstanceID)
		if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{
			PluginInstanceID:           record.PluginInstanceID,
			PermissionID:               permissionID,
			ExpectedPolicyRevision:     expected.PolicyRevision,
			ExpectedManagementRevision: expected.ManagementRevision,
			ExpectedRevokeEpoch:        expected.RevokeEpoch,
		}); err != nil {
			t.Fatalf("GrantPermission(%s) error = %v", permissionID, err)
		}
	}
}

func hostTestContext() context.Context {
	return hostTestContextWith("session_hash", "user_hash", "env_hash", "channel_hash")
}

func hostTestContextWith(sessionHash, userHash, envHash, channelHash string) context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash: sessionHash, OwnerUserHash: userHash,
		OwnerEnvHash: envHash, SessionChannelIDHash: channelHash,
	})
}

type readAtProbe struct {
	reader *bytes.Reader
	calls  int
}

func (r *readAtProbe) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	return r.reader.ReadAt(p, off)
}

type policyAdapter struct {
	developerMode  bool
	localGenerated bool
	decision       PolicyDecision
}

type allowAuthorizationAdapter struct{}

func (allowAuthorizationAdapter) Authorize(_ context.Context, req AuthorizationRequest) error {
	if !req.Session.Valid() || !req.Action.Valid() || !req.Target.Kind.Valid() || req.Target.Kind != req.Action.Resource() {
		return ErrActionDenied
	}
	return nil
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
	bundle         capabilitycontract.Bundle
	fetchChain     []CapabilityArtifactFetchHop
	omitFetchChain bool
	mediaType      string
	declaredSize   *int64
	contentByRef   map[string][]byte
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
	if len(chain) == 0 && !s.omitFetchChain {
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

func (r *recordingReleaseArtifactResolver) ResolveReleaseArtifact(_ context.Context, req ReleaseArtifactResolveRequest) (ResolvedPackageArtifact, error) {
	r.calls++
	r.last = req
	if r.err != nil {
		return ResolvedPackageArtifact{}, r.err
	}
	return r.artifact, nil
}

func readTestPackage(t *testing.T, data []byte) pluginpkg.Package {
	t.Helper()
	pkg, err := pluginpkg.Read(hostTestContext(), bytes.NewReader(data), int64(len(data)), pluginpkg.DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	return pkg
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
	got := event.Details[key]
	gotJSON, gotErr := normalizeAuditTestJSON(got)
	wantJSON, wantErr := normalizeAuditTestJSON(want)
	if gotErr != nil || wantErr != nil || !reflect.DeepEqual(gotJSON, wantJSON) {
		t.Fatalf("audit detail %s = %#v, want %#v: %#v", key, got, want, event.Details)
	}
}

func normalizeAuditTestJSON(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
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

type diagnosticSink struct {
	events []observability.DiagnosticEvent
}

type listingDiagnosticSink struct {
	diagnosticSink
}

type failingAuditSink struct {
	err error
}

func (s failingAuditSink) AppendPluginAudit(context.Context, AuditEvent) error {
	return s.err
}

type switchableAuditSink struct {
	mu  sync.Mutex
	err error
}

func (s *switchableAuditSink) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *switchableAuditSink) AppendPluginAudit(context.Context, AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *diagnosticSink) AppendPluginDiagnostic(_ context.Context, event observability.DiagnosticEvent) error {
	s.events = append(s.events, event)
	return nil
}

func (s *listingDiagnosticSink) ListPluginDiagnostics(context.Context, observability.ListDiagnosticRequest) ([]observability.DiagnosticEvent, error) {
	return append([]observability.DiagnosticEvent(nil), s.events...), nil
}

type recordingCapabilityAdapter struct {
	calls              int
	last               capability.Invocation
	lastTarget         capability.TargetResolutionRequest
	result             capability.Result
	resultsByTarget    map[string]capability.Result
	err                error
	cancelCalls        int
	lastCancellation   capability.OperationCancellation
	cancellationError  error
	invokeContext      context.Context
	panicValue         any
	invokeDelay        time.Duration
	invokeEntered      chan<- struct{}
	invokeRelease      <-chan struct{}
	targetFields       map[string]any
	targetError        error
	mutateExecution    func(*capability.ExecutionBinding)
	mutateCancellation func(*capability.ExecutionBinding)
}

type blockingOperationRegisterStore struct {
	operation.Store
	entered chan<- struct{}
	release <-chan struct{}
}

type mutatingOperationRegisterStore struct {
	operation.Store
	retained capability.ExecutionBinding
}

type retainingCancelOperationStore struct {
	operation.Store
	retained capability.ExecutionBinding
}

func (s *retainingCancelOperationStore) RequestCancel(ctx context.Context, req operation.CancelRequest) (operation.Record, error) {
	record, err := s.Store.RequestCancel(ctx, req)
	if err != nil {
		return operation.Record{}, err
	}
	s.retained = record.ExecutionBinding
	return record, nil
}

func (s *mutatingOperationRegisterStore) Register(ctx context.Context, req operation.RegisterRequest) (operation.Record, error) {
	s.retained = req.ExecutionBinding
	req.ExecutionBinding.Target.Fields["operation_store_mutation"] = true
	req.ExecutionBinding.Permissions.Required[0] = "operation.store.mutated"
	return s.Store.Register(ctx, req)
}

type recordingStreamRegisterStore struct {
	stream.Store
	binding capability.ExecutionBinding
}

func (s *recordingStreamRegisterStore) Register(ctx context.Context, req stream.RegisterRequest) (stream.Record, error) {
	s.binding = req.ExecutionBinding
	return s.Store.Register(ctx, req)
}

func (s *blockingOperationRegisterStore) Register(ctx context.Context, req operation.RegisterRequest) (operation.Record, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return operation.Record{}, ctx.Err()
	case <-s.release:
	}
	return s.Store.Register(ctx, req)
}

type blockingStreamRegisterStore struct {
	stream.Store
	entered chan<- struct{}
	release <-chan struct{}
}

func (s *blockingStreamRegisterStore) Register(ctx context.Context, req stream.RegisterRequest) (stream.Record, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return stream.Record{}, ctx.Err()
	case <-s.release:
	}
	return s.Store.Register(ctx, req)
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

type controlledOperationFinishStore struct {
	operation.Store
	mu      sync.Mutex
	err     error
	failing bool
	calls   int
}

type controlledStreamCloseStore struct {
	stream.Store
	mu      sync.Mutex
	err     error
	failing bool
	calls   int
}

type countingOperationListStore struct {
	operation.Store
	listCalls int
}

type countingOperationPruneStore struct {
	operation.Store
	mu         sync.Mutex
	pruneCalls int
	last       operation.PruneRequest
	err        error
	entered    chan<- struct{}
	release    <-chan struct{}
}

func (s *countingOperationPruneStore) Prune(ctx context.Context, req operation.PruneRequest) (operation.PruneResult, error) {
	s.mu.Lock()
	s.pruneCalls++
	s.last = req
	err := s.err
	entered := s.entered
	release := s.release
	s.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-ctx.Done():
			return operation.PruneResult{}, ctx.Err()
		case <-release:
		}
	}
	if err != nil {
		return operation.PruneResult{}, err
	}
	return s.Store.Prune(ctx, req)
}

func (s *countingOperationPruneStore) snapshot() (int, operation.PruneRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneCalls, s.last
}

func (s *countingOperationPruneStore) reset() {
	s.mu.Lock()
	s.pruneCalls = 0
	s.last = operation.PruneRequest{}
	s.mu.Unlock()
}

func (s *countingOperationPruneStore) configure(err error, entered chan<- struct{}, release <-chan struct{}) {
	s.mu.Lock()
	s.err = err
	s.entered = entered
	s.release = release
	s.mu.Unlock()
}

type countingStreamPruneStore struct {
	stream.Store
	mu         sync.Mutex
	pruneCalls int
	last       stream.PruneRequest
}

func (s *countingStreamPruneStore) Prune(ctx context.Context, req stream.PruneRequest) (stream.PruneResult, error) {
	s.mu.Lock()
	s.pruneCalls++
	s.last = req
	s.mu.Unlock()
	return s.Store.Prune(ctx, req)
}

func (s *countingStreamPruneStore) snapshot() (int, stream.PruneRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneCalls, s.last
}

func (s *countingStreamPruneStore) reset() {
	s.mu.Lock()
	s.pruneCalls = 0
	s.last = stream.PruneRequest{}
	s.mu.Unlock()
}

func (s *countingOperationListStore) List(ctx context.Context, req operation.ListRequest) (operation.Page, error) {
	s.listCalls++
	return s.Store.List(ctx, req)
}

func (s *failFirstOperationFinishStore) Finish(ctx context.Context, req operation.FinishRequest) (operation.Record, error) {
	if !s.failedOne {
		s.failedOne = true
		return operation.Record{}, s.err
	}
	return s.Store.Finish(ctx, req)
}

func (s *controlledOperationFinishStore) Finish(ctx context.Context, req operation.FinishRequest) (operation.Record, error) {
	s.mu.Lock()
	s.calls++
	failing := s.failing
	err := s.err
	s.mu.Unlock()
	if failing {
		return operation.Record{}, err
	}
	return s.Store.Finish(ctx, req)
}

func (s *controlledOperationFinishStore) setFailing(failing bool) {
	s.mu.Lock()
	s.failing = failing
	s.mu.Unlock()
}

func (s *controlledOperationFinishStore) finishCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *controlledStreamCloseStore) Close(ctx context.Context, req stream.CloseRequest) (stream.Record, error) {
	s.mu.Lock()
	s.calls++
	failing := s.failing
	err := s.err
	s.mu.Unlock()
	if failing {
		return stream.Record{}, err
	}
	return s.Store.Close(ctx, req)
}

func (s *controlledStreamCloseStore) setFailing(failing bool) {
	s.mu.Lock()
	s.failing = failing
	s.mu.Unlock()
}

func (s *controlledStreamCloseStore) closeCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type failFirstStreamAppendStore struct {
	stream.Store
	err       error
	failedOne bool
}

type failFirstStreamDeliverStore struct {
	stream.Store
	err       error
	failedOne bool
}

func (s *failFirstStreamDeliverStore) Deliver(ctx context.Context, req stream.DeliverRequest) (stream.Record, stream.Delivery, error) {
	if !s.failedOne {
		s.failedOne = true
		return stream.Record{}, stream.Delivery{}, s.err
	}
	return s.Store.Deliver(ctx, req)
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
	mutateTargetInput func(map[string]any)
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
	records        []secrets.Record
}

type failingSecretListStore struct {
	SecretStoreAdapter
	err error
}

func (s *failingSecretListStore) List(context.Context, secrets.ListRequest) ([]secrets.Record, error) {
	return nil, s.err
}

type recordingRuntimeManager struct {
	calls               int
	preflightCalls      int
	startCalls          int
	stopCalls           int
	revokeCalls         int
	startedTarget       runtimetarget.Target
	health              runtimeclient.Health
	descriptor          runtimeclient.RuntimeDescriptor
	bindingDescriptor   runtimeclient.RuntimeDescriptor
	result              capability.Result
	preflightErr        error
	healthErr           error
	bindErr             error
	err                 error
	startErr            error
	stopErr             error
	stopErrOnce         bool
	revokeErr           error
	revokeResult        runtimeclient.RevokeResult
	sessionRevokeErr    error
	sessionRevokeResult runtimeclient.SessionRevokeResult
	sessionRevokeCalls  int
	lastSessionRevoke   runtimeclient.SessionRevokeRequest
	lastLease           runtimeclient.Lease
	lastMethod          string
	lastPayload         []byte
	lastRevokedPlugin   string
	lastRevokeEpoch     uint64
	invokeContext       context.Context
	hostServices        runtimeclient.RuntimeHostServices
}

func newRecordingRuntimeManager() *recordingRuntimeManager {
	descriptor := hostTestRuntimeDescriptor()
	return &recordingRuntimeManager{
		descriptor: descriptor,
		health: runtimeclient.Health{
			RuntimeInstanceID:   "runtime_test",
			RuntimeGenerationID: "runtime_gen_test",
			IPCChannelID:        "ipc_test",
			ConnectionNonce:     "connection_nonce_test_1234567890",
			Descriptor:          descriptor,
			Ready:               true,
		},
	}
}

func newRecordingRuntimeManagerWithHealth(health runtimeclient.Health) *recordingRuntimeManager {
	manager := newRecordingRuntimeManager()
	health.Descriptor = manager.descriptor
	manager.health = health
	return manager
}

func hostTestRuntimeDescriptor() runtimeclient.RuntimeDescriptor {
	runtimeVersion, err := version.ParseSemVer(version.CurrentCompatibilityVersion())
	if err != nil {
		panic(err)
	}
	descriptor, err := runtimeclient.NewRuntimeDescriptor(runtimeclient.RuntimeDescriptorOptions{
		PlatformVersion: runtimeVersion, Target: runtimetarget.LinuxAMD64,
		RustIPCVersion: version.RustIPCVersion, WASMABIVersion: version.WASMABIVersion,
		ContractSetSHA256: version.ContractSetSHA256, BinarySHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		panic(err)
	}
	return descriptor
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
	record, err := h.GetOperation(hostTestContext(), operationID)
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
		record, err := h.GetOperation(hostTestContext(), operationID)
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

func waitForOperationFinishCalls(t *testing.T, store *controlledOperationFinishStore, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if store.finishCalls() >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation terminal writes = %d, want at least %d", store.finishCalls(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForStreamCloseCalls(t *testing.T, store *controlledStreamCloseStore, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if store.closeCalls() >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream terminal writes = %d, want at least %d", store.closeCalls(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertNoActiveExecutionState(t *testing.T, h *Host, label string) {
	t.Helper()
	h.executions.mu.Lock()
	defer h.executions.mu.Unlock()
	if len(h.executions.leases) != 0 || len(h.executions.leasesByPlugin) != 0 || len(h.executions.operations) != 0 ||
		len(h.executions.streams) != 0 || len(h.executions.activeByQuotaKey) != 0 || len(h.executions.setupRollbacks) != 0 {
		t.Fatalf("%s retained execution state: %#v", label, h.executions)
	}
}

func testExecutionBinding(record registry.PluginRecord, method string, execution manifest.MethodExecutionMode) capability.ExecutionBinding {
	return capability.ExecutionBinding{
		PluginID:             record.PluginID,
		PluginInstanceID:     record.PluginInstanceID,
		PluginVersion:        record.Version,
		ActiveFingerprint:    record.ActiveFingerprint,
		Method:               method,
		Execution:            string(execution),
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}
}

func assertHostStreamStatus(t *testing.T, h *Host, streamID string, want stream.Status) {
	t.Helper()
	record, err := h.adapters.Streams.Get(hostTestContext(), streamID)
	if err != nil {
		t.Fatalf("Streams.Get(%s) error = %v", streamID, err)
	}
	if record.Status != want {
		t.Fatalf("stream %s status = %s, want %s: %#v", streamID, record.Status, want, record)
	}
}

func (a *recordingCapabilityAdapter) ProjectTarget(_ context.Context, req capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	a.lastTarget = req
	if a.targetError != nil {
		return capability.TargetDescriptor{}, a.targetError
	}
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
	if a.invokeEntered != nil {
		select {
		case a.invokeEntered <- struct{}{}:
		default:
		}
	}
	if a.invokeRelease != nil {
		<-a.invokeRelease
	}
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
	if a.mutateCancellation != nil {
		a.mutateCancellation(&req.Execution.ExecutionBinding)
	}
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
	if a.mutateTargetInput != nil {
		a.mutateTargetInput(req.TargetInput)
	}
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

func (s *recordingSecretStore) List(_ context.Context, req secrets.ListRequest) ([]secrets.Record, error) {
	result := make([]secrets.Record, 0, len(s.records))
	for _, record := range s.records {
		if req.PluginInstanceID != "" && record.PluginInstanceID != req.PluginInstanceID {
			continue
		}
		if req.Scope != "" && record.Scope != req.Scope {
			continue
		}
		if req.BoundOnly && !record.Bound {
			continue
		}
		result = append(result, record)
	}
	return result, nil
}

func (r *recordingRuntimeManager) Start(_ context.Context, target runtimetarget.Target) (runtimeclient.ManagerHealth, error) {
	r.startCalls++
	r.startedTarget = target
	return r.managerHealth(), r.startErr
}

func (r *recordingRuntimeManager) Preflight(_ context.Context, target runtimetarget.Target) (runtimeclient.RuntimeDescriptor, error) {
	r.preflightCalls++
	if r.preflightErr != nil {
		return runtimeclient.RuntimeDescriptor{}, r.preflightErr
	}
	if r.descriptor.PlatformVersion().String() == "" {
		return runtimeclient.RuntimeDescriptor{}, runtimeclient.ErrRuntimeDescriptorInvalid
	}
	if r.descriptor.Target() != target {
		return runtimeclient.RuntimeDescriptor{}, runtimeclient.ErrRuntimeDescriptorMismatch
	}
	return r.descriptor, nil
}

func (r *recordingRuntimeManager) BindHostServices(services runtimeclient.RuntimeHostServices) error {
	if services.StreamSink == nil {
		return runtimeclient.ErrRuntimeHostServicesInvalid
	}
	if r.descriptor.PlatformVersion().String() == "" || r.health.Descriptor != r.descriptor {
		return runtimeclient.ErrRuntimeDescriptorInvalid
	}
	r.hostServices = services
	return nil
}

func (r *recordingRuntimeManager) Stop(context.Context) error {
	r.stopCalls++
	r.health.Ready = false
	err := r.stopErr
	if r.stopErrOnce {
		r.stopErr = nil
	}
	return err
}

func (r *recordingRuntimeManager) Health(context.Context) (runtimeclient.ManagerHealth, error) {
	if r.healthErr != nil {
		return runtimeclient.ManagerHealth{}, r.healthErr
	}
	return r.managerHealth(), nil
}

func (r *recordingRuntimeManager) managerHealth() runtimeclient.ManagerHealth {
	return runtimeclient.ManagerHealth{Ready: r.health.Ready, Descriptor: r.health.Descriptor, Shards: []runtimeclient.ShardHealth{{RuntimeShardID: "runtime_shard_00", Health: r.health}}}
}

func (r *recordingRuntimeManager) BindPlugin(context.Context, string) (runtimeclient.RuntimeBinding, error) {
	if r.bindErr != nil {
		return runtimeclient.RuntimeBinding{}, r.bindErr
	}
	descriptor := r.health.Descriptor
	if r.bindingDescriptor.PlatformVersion().String() != "" {
		descriptor = r.bindingDescriptor
	}
	return runtimeclient.RuntimeBinding{
		RuntimeShardID:      "runtime_shard_00",
		RuntimeInstanceID:   r.health.RuntimeInstanceID,
		RuntimeGenerationID: r.health.RuntimeGenerationID,
		IPCChannelID:        r.health.IPCChannelID,
		ConnectionNonce:     r.health.ConnectionNonce,
		Descriptor:          descriptor,
	}, nil
}

func (r *recordingRuntimeManager) InvokeWorker(ctx context.Context, _ runtimeclient.RuntimeBinding, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
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

func (r *recordingRuntimeManager) Revoke(_ context.Context, req runtimeclient.RevokeRequest) (runtimeclient.RevokeResult, error) {
	r.revokeCalls++
	r.lastRevokedPlugin = req.PluginInstanceID
	r.lastRevokeEpoch = req.RevokeEpoch
	result := r.revokeResult
	if !result.ResourceScope.Valid() {
		result.ResourceScope = req.ResourceScope
	}
	if result.PluginInstanceID == "" {
		result.PluginInstanceID = req.PluginInstanceID
	}
	if result.RevokeEpoch == 0 {
		result.RevokeEpoch = req.RevokeEpoch
	}
	return result, r.revokeErr
}

func (r *recordingRuntimeManager) RevokeSession(_ context.Context, req runtimeclient.SessionRevokeRequest) (runtimeclient.SessionRevokeResult, error) {
	r.sessionRevokeCalls++
	r.lastSessionRevoke = req
	result := r.sessionRevokeResult
	if result.SessionScope == (sessionctx.SessionScope{}) {
		result.SessionScope = req.SessionScope
	}
	if result.SessionRevokeSequence == 0 {
		result.SessionRevokeSequence = req.SessionRevokeSequence
	}
	return result, r.sessionRevokeErr
}
