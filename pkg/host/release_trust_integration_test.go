package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
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

func TestRefreshEnabledPluginsRestoresReleaseActivationLeaseAfterColdHostRestart(t *testing.T) {
	ctx := hostTestContext()
	registryStore := registry.NewMemoryStore()
	pluginDataRoot := t.TempDir()
	installedFixture := newHostReleaseTrustFixture(t)
	installedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(installedFixture)}
	installedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: installedFixture.ServiceSet, releaseArtifactResolver: installedResolver, registry: registryStore,
		pluginDataRoot: pluginDataRoot,
	})
	installed, err := installedHost.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(installedFixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := installedHost.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := installedHost.Close(); err != nil {
		t.Fatal(err)
	}

	restartedFixture := newHostReleaseTrustFixtureWithState(t, installedFixture)
	restartedFixture.DocumentTransport.SetBlocked(true)
	restartedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restartedFixture)}
	restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: restartedFixture.ServiceSet, releaseArtifactResolver: restartedResolver, registry: registryStore,
		pluginDataRoot: pluginDataRoot,
	})
	restartCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	refreshed, err := restartedHost.RefreshEnabledPlugins(restartCtx)
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshed) != 1 || refreshed[0].PluginInstanceID != enabled.PluginInstanceID || refreshed[0].Status != RefreshEnabledPluginStatusRefreshed || refreshed[0].Error != nil {
		t.Fatalf("refreshed plugins mismatch: %#v", refreshed)
	}
	binding := *enabled.ReleaseTrustBinding
	if _, ok := restartedHost.releaseLeases.get(enabled.PluginInstanceID, binding); !ok {
		t.Fatal("RefreshEnabledPlugins() did not restore the release activation lease")
	}
	if restartedFixture.DocumentTransport.Calls() != 0 {
		t.Fatalf("cold restart fetched %d release-trust documents, want 0", restartedFixture.DocumentTransport.Calls())
	}
	if restartedFixture.LedgerTransport.Calls() != 0 {
		t.Fatalf("cold restart fetched %d signing-ledger artifacts, want 0", restartedFixture.LedgerTransport.Calls())
	}
	if restartedResolver.calls != 0 {
		t.Fatalf("cold restart resolved %d release artifacts, want 0", restartedResolver.calls)
	}
	if _, err := restartedHost.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID: enabled.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision,
		SurfaceID: "fixture.view", SurfaceInstanceID: "surface_after_restart", Now: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("OpenSurface() after RefreshEnabledPlugins() error = %v", err)
	}
}

func TestRefreshEnabledPluginsRevalidatesLegallyAdvancedTrustStateAfterColdHostRestart(t *testing.T) {
	ctx := hostTestContext()
	registryStore := registry.NewMemoryStore()
	pluginDataRoot := t.TempDir()
	installedFixture := newHostReleaseTrustFixture(t)
	installedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust:            installedFixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(installedFixture)},
		registry:                registryStore, pluginDataRoot: pluginDataRoot,
	})
	installed, err := installedHost.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(installedFixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := installedHost.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	before := *enabled.ReleaseTrustBinding
	advanced, err := installedFixture.AdvanceTrustedTime(ctx)
	if err != nil {
		t.Fatalf("AdvanceTrustedTime() error = %v", err)
	}
	if advanced.StateSHA256() == before.VerifiedStateSHA256 {
		t.Fatal("trusted-time advancement did not produce a successor trust state")
	}
	if err := installedHost.Close(); err != nil {
		t.Fatal(err)
	}

	restartedFixture := newHostReleaseTrustFixtureWithState(t, installedFixture)
	restartedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restartedFixture)}
	restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: restartedFixture.ServiceSet, releaseArtifactResolver: restartedResolver,
		registry: registryStore, pluginDataRoot: pluginDataRoot,
	})
	if err := restartedHost.ensureReleaseActivationLease(ctx, enabled); err != nil {
		t.Fatalf("ensureReleaseActivationLease() after legal trust advancement = %v", err)
	}
	refreshed, err := restartedHost.RefreshEnabledPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshed) != 1 || refreshed[0].Status != RefreshEnabledPluginStatusRefreshed || refreshed[0].Error != nil {
		t.Fatalf("RefreshEnabledPlugins() after legal trust advancement = %#v, want successful revalidation", refreshed)
	}
	if documents, ledger := restartedFixture.DocumentTransport.Calls(), restartedFixture.LedgerTransport.Calls(); documents != 5 || ledger != 25 || restartedResolver.calls != 0 {
		t.Fatalf("legal trust advancement used unexpected remote work: documents=%d ledger=%d resolver=%d", documents, ledger, restartedResolver.calls)
	}
	after, err := registryStore.GetPlugin(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	currentDigest := sha256.Sum256(restartedFixture.StateStore.CommittedBytes())
	currentStateSHA256 := fmt.Sprintf("%x", currentDigest[:])
	if after.ReleaseTrustBinding == nil || after.ReleaseTrustBinding.VerifiedStateSHA256 != currentStateSHA256 || currentStateSHA256 == before.VerifiedStateSHA256 {
		t.Fatalf("revalidated binding = %#v, want current state digest %q", after.ReleaseTrustBinding, currentStateSHA256)
	}
	if err := registry.ValidateReleaseActivationEvidence(after); err != nil {
		t.Fatalf("revalidated activation evidence = %v", err)
	}
}

func TestRefreshEnabledPluginsConvergesWhenCurrentReleaseAssetsOmitDurableLedgerContinuity(t *testing.T) {
	ctx := hostTestContext()
	registryStore := registry.NewMemoryStore()
	pluginDataRoot := t.TempDir()
	seedFixture := newHostReleaseTrustFixture(t)
	installedFixture := newHostReleaseTrustFixtureWithOptions(t, releasetrustfixture.Options{
		GeneratedAt: seedFixture.GeneratedAt, ExpiresAt: seedFixture.ExpiresAt, UseMonotonicState: true,
	})
	installedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust:            installedFixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(installedFixture)},
		registry:                registryStore, pluginDataRoot: pluginDataRoot,
	})
	installed, err := installedHost.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(installedFixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := installedHost.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	previousStateSHA256 := enabled.ReleaseTrustBinding.VerifiedStateSHA256
	if _, err := installedFixture.AdvanceTrustedTime(ctx); err != nil {
		t.Fatal(err)
	}
	if err := installedHost.Close(); err != nil {
		t.Fatal(err)
	}

	restartedFixture := newHostReleaseTrustFixtureWithOptions(t, releasetrustfixture.Options{
		GeneratedAt: installedFixture.GeneratedAt, ExpiresAt: installedFixture.ExpiresAt,
		StateStore: installedFixture.StateStore, TrustedTime: installedFixture.TrustedTime, UseMonotonicState: true,
	})
	if err := restartedFixture.RotateSigningLedgerWithoutContinuity(); err != nil {
		t.Fatal(err)
	}
	restartedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restartedFixture)}
	restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: restartedFixture.ServiceSet, releaseArtifactResolver: restartedResolver,
		registry: registryStore, pluginDataRoot: pluginDataRoot,
	})
	if err := restartedHost.ensureReleaseActivationLease(ctx, enabled); err != nil {
		t.Fatalf("ensureReleaseActivationLease() with rotated ledger assets = %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		results, err := restartedHost.RefreshEnabledPlugins(ctx)
		if err != nil {
			t.Fatalf("RefreshEnabledPlugins() attempt %d error = %v", attempt, err)
		}
		if len(results) != 1 || results[0].Status != RefreshEnabledPluginStatusRefreshed || results[0].Error != nil {
			if len(results) == 1 && results[0].Error != nil {
				t.Fatalf("RefreshEnabledPlugins() attempt %d failed: reason=%q action=%q message=%q", attempt, results[0].Error.Reason, results[0].Error.Action, results[0].Error.Message)
			}
			t.Fatalf("RefreshEnabledPlugins() attempt %d = %#v, want converged refresh", attempt, results)
		}
	}
	after, err := registryStore.GetPlugin(ctx, enabled.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if after.EnableState != registry.EnableEnabled || after.TrustState != registry.TrustVerified {
		t.Fatalf("recovered record state = trust %q enable %q", after.TrustState, after.EnableState)
	}
	if after.ReleaseTrustBinding == nil || after.ReleaseTrustBinding.VerifiedStateSHA256 == previousStateSHA256 {
		t.Fatalf("recovered binding = %#v, want advanced durable state", after.ReleaseTrustBinding)
	}
	if err := registry.ValidateReleaseActivationEvidence(after); err != nil {
		t.Fatalf("recovered activation evidence = %v", err)
	}
	if restartedResolver.calls != 0 {
		t.Fatalf("cold recovery resolved %d package artifacts, want 0", restartedResolver.calls)
	}
	if calls := restartedFixture.LedgerTransport.Calls(); calls != 0 {
		t.Fatalf("cold recovery fetched %d signing-ledger artifacts, want 0", calls)
	}
	if _, err := restartedHost.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID: after.PluginInstanceID, ExpectedManagementRevision: after.ManagementRevision,
		SurfaceID: "fixture.view", SurfaceInstanceID: "surface_after_rotated_ledger", Now: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("OpenSurface() after converged refresh error = %v", err)
	}
}

func TestReleaseActivationRecoveryRejectsTamperedDurableCheckpointSignatures(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*releasetrust.ReleaseTrustStateV1)
	}{
		{
			name: "signing ledger checkpoint",
			mutate: func(state *releasetrust.ReleaseTrustStateV1) {
				state.SigningLedger.Checkpoint.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			},
		},
		{
			name: "trusted time checkpoint",
			mutate: func(state *releasetrust.ReleaseTrustStateV1) {
				state.TrustedTime.Checkpoint.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := hostTestContext()
			registryStore := registry.NewMemoryStore()
			pluginDataRoot := t.TempDir()
			generatedAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
			fixture := newHostReleaseTrustFixtureWithOptions(t, releasetrustfixture.Options{
				GeneratedAt: generatedAt, ExpiresAt: generatedAt.Add(24 * time.Hour), UseMonotonicState: true,
			})
			host, _, _ := newTestHostWithOptions(t, testHostOptions{
				releaseTrust: fixture.ServiceSet,
				releaseArtifactResolver: &recordingReleaseArtifactResolver{
					artifact: resolvedReleaseTrustFixture(fixture),
				},
				registry: registryStore, pluginDataRoot: pluginDataRoot,
			})
			installed, err := host.InstallReleaseRef(ctx, InstallReleaseRefRequest{
				PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			enabled, err := host.EnablePlugin(ctx, EnableRequest{
				PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			before := enabled
			if _, err := fixture.AdvanceTrustedTime(ctx); err != nil {
				t.Fatal(err)
			}
			if err := host.Close(); err != nil {
				t.Fatal(err)
			}
			var state releasetrust.ReleaseTrustStateV1
			if err := json.Unmarshal(fixture.StateStore.CommittedBytes(), &state); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(&state)
			if testCase.name == "signing ledger checkpoint" {
				checkpointBytes, err := releasecontract.CanonicalSigningLedgerCheckpoint(state.SigningLedger.Checkpoint)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(checkpointBytes)
				state.SigningLedger.CheckpointSHA256 = fmt.Sprintf("%x", digest[:])
			} else {
				checkpointBytes, err := json.Marshal(state.TrustedTime.Checkpoint)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(checkpointBytes)
				state.TrustedTime.CheckpointSHA256 = fmt.Sprintf("%x", digest[:])
			}
			raw, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			fixture.StateStore.ReplaceCommittedBytes(raw)
			stateDigest := sha256.Sum256(raw)
			fixture.StateStore.SetMonotonicDigest(fmt.Sprintf("%x", stateDigest[:]))
			restarted := newHostReleaseTrustFixtureWithOptions(t, releasetrustfixture.Options{
				GeneratedAt: fixture.GeneratedAt, ExpiresAt: fixture.ExpiresAt,
				StateStore: fixture.StateStore, TrustedTime: fixture.TrustedTime, UseMonotonicState: true,
			})
			restartedHost, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
				releaseTrust: restarted.ServiceSet,
				releaseArtifactResolver: &recordingReleaseArtifactResolver{
					artifact: resolvedReleaseTrustFixture(restarted),
				},
				registry: registryStore, pluginDataRoot: pluginDataRoot,
			})
			if err := restartedHost.ensureReleaseActivationLease(ctx, before); !errors.Is(err, releasetrust.ErrActivationRecoveryRejected) {
				t.Fatalf("ensureReleaseActivationLease() error = %v, want tampered checkpoint rejection", err)
			}
			after, err := registryStore.GetPlugin(ctx, before.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("registry record changed after rejected recovery: before=%#v after=%#v", before, after)
			}
			if len(surfaces.snapshots) != 0 {
				t.Fatalf("rejected recovery published surfaces: %#v", surfaces.snapshots)
			}
		})
	}
}

func TestConcurrentPluginsShareOneTrustAdvancementRevalidationAndMigrateEveryBinding(t *testing.T) {
	ctx := hostTestContext()
	registryStore := registry.NewMemoryStore()
	pluginDataRoot := t.TempDir()
	installedFixture := newHostReleaseTrustFixture(t)
	installedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust:            installedFixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(installedFixture)},
		registry:                registryStore, pluginDataRoot: pluginDataRoot,
	})
	enabled := make([]registry.PluginRecord, 2)
	for index := range enabled {
		installed, err := installedHost.InstallReleaseRef(ctx, InstallReleaseRefRequest{
			PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(installedFixture), Now: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		enabled[index], err = installedHost.EnablePlugin(ctx, EnableRequest{
			PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	previousState := enabled[0].ReleaseTrustBinding.VerifiedStateSHA256
	if _, err := installedFixture.AdvanceTrustedTime(ctx); err != nil {
		t.Fatal(err)
	}
	if err := installedHost.Close(); err != nil {
		t.Fatal(err)
	}

	restartedFixture := newHostReleaseTrustFixtureWithState(t, installedFixture)
	restartedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restartedFixture)}
	restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: restartedFixture.ServiceSet, releaseArtifactResolver: restartedResolver,
		registry: registryStore, pluginDataRoot: pluginDataRoot,
	})
	start := make(chan struct{})
	errs := make(chan error, len(enabled))
	var group sync.WaitGroup
	for _, record := range enabled {
		record := record
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			errs <- restartedHost.ensureReleaseActivationLease(ctx, record)
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent trust advancement recovery = %v", err)
		}
	}
	if documents, ledger := restartedFixture.DocumentTransport.Calls(), restartedFixture.LedgerTransport.Calls(); documents != 5 || ledger != 25 || restartedResolver.calls != 0 {
		t.Fatalf("shared trust advancement used unexpected work: documents=%d ledger=%d resolver=%d", documents, ledger, restartedResolver.calls)
	}
	currentDigest := sha256.Sum256(restartedFixture.StateStore.CommittedBytes())
	currentState := fmt.Sprintf("%x", currentDigest[:])
	for _, record := range enabled {
		after, err := registryStore.GetPlugin(ctx, record.PluginInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if after.ReleaseTrustBinding == nil || after.ReleaseTrustBinding.VerifiedStateSHA256 != currentState || currentState == previousState {
			t.Fatalf("plugin %q binding = %#v, want state %q", record.PluginInstanceID, after.ReleaseTrustBinding, currentState)
		}
		if err := registry.ValidateReleaseActivationEvidence(after); err != nil {
			t.Fatalf("plugin %q activation evidence = %v", record.PluginInstanceID, err)
		}
	}
}

func TestOpenSurfaceRecoversExpiredActivationLeaseFromDurableEvidence(t *testing.T) {
	ctx := hostTestContext()
	fixture := newHostReleaseTrustFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet, releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
	})
	defer h.Close()

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

	// The durable registry record and verified package evidence remain intact;
	// clearing only the in-memory lease models the five-minute lease expiry.
	h.releaseLeases.clear()
	if _, err := h.OpenSurface(ctx, OpenSurfaceRequest{
		PluginInstanceID: enabled.PluginInstanceID, ExpectedManagementRevision: enabled.ManagementRevision,
		SurfaceID: "fixture.view", SurfaceInstanceID: "surface_after_lease_expiry", Now: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("OpenSurface() after activation lease expiry = %v", err)
	}
	if _, ok := h.releaseLeases.get(enabled.PluginInstanceID, *enabled.ReleaseTrustBinding); !ok {
		t.Fatal("OpenSurface() did not reconstruct the activation lease")
	}
}

func TestExpiredActivationLeaseRecoveryIsSingleFlightAcrossConcurrentOpens(t *testing.T) {
	ctx := hostTestContext()
	fixture := newHostReleaseTrustFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet, releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
	})
	defer h.Close()

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
	h.releaseLeases.clear()
	h.verifiedReleases.clear()

	var stateLoads atomic.Int32
	fixture.StateStore.SetLoadHook(func() { stateLoads.Add(1) })
	defer fixture.StateStore.SetLoadHook(nil)
	const callers = 8
	errs := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			errs <- h.ensureReleaseActivationLease(ctx, enabled)
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent lease recovery error = %v", err)
		}
	}
	if got := stateLoads.Load(); got != 2 {
		t.Fatalf("concurrent recovery loaded durable trust state %d times, want one prepare and one final commit reread", got)
	}
}

func TestReleaseActivationLeaseRecoveryRejectsMismatchedDurableStateWithoutRegistryMutation(t *testing.T) {
	registryStore := registry.NewMemoryStore()
	installedFixture := newHostReleaseTrustFixture(t)
	resolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(installedFixture)}
	installedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: installedFixture.ServiceSet, releaseArtifactResolver: resolver, registry: registryStore,
	})
	installed, err := installedHost.InstallReleaseRef(hostTestContext(), InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(installedFixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := registryStore.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}

	restartedFixture := newHostReleaseTrustFixture(t)
	restartedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restartedFixture)}
	restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust:            restartedFixture.ServiceSet,
		releaseArtifactResolver: restartedResolver,
		registry:                registryStore,
	})
	started := time.Now()
	err = restartedHost.ensureReleaseActivationLease(context.Background(), before)
	if !errors.Is(err, releasetrust.ErrActivationRecoveryRejected) {
		t.Fatalf("ensureReleaseActivationLease() error = %v, want ErrActivationRecoveryRejected", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("release trust recovery rejection took too long: %s", time.Since(started))
	}
	if restartedFixture.DocumentTransport.Calls() != 0 || restartedFixture.LedgerTransport.Calls() != 0 || restartedResolver.calls != 0 {
		t.Fatalf("rejected recovery performed remote work: documents=%d ledger=%d resolver=%d", restartedFixture.DocumentTransport.Calls(), restartedFixture.LedgerTransport.Calls(), restartedResolver.calls)
	}
	after, err := registryStore.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("release trust timeout mutated registry record:\nbefore=%#v\nafter=%#v", before, after)
	}
}

func TestReleaseActivationLeaseRecoveryPropagatesCancellationAfterHostRestart(t *testing.T) {
	registryStore := registry.NewMemoryStore()
	installedFixture := newHostReleaseTrustFixture(t)
	installedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: installedFixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(installedFixture),
		},
		registry: registryStore,
	})
	installed, err := installedHost.InstallReleaseRef(hostTestContext(), InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(installedFixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := registryStore.GetPlugin(hostTestContext(), installed.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}

	restartedFixture := newHostReleaseTrustFixtureWithState(t, installedFixture)
	restartedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restartedFixture)}
	restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust:            restartedFixture.ServiceSet,
		releaseArtifactResolver: restartedResolver,
		registry:                registryStore,
	})
	canceled, cancel := context.WithCancel(context.Background())
	restartedFixture.StateStore.SetLoadHook(cancel)
	defer restartedFixture.StateStore.SetLoadHook(nil)
	if err := restartedHost.ensureReleaseActivationLease(canceled, before); !errors.Is(err, context.Canceled) {
		t.Fatalf("ensureReleaseActivationLease() error = %v, want context.Canceled", err)
	}
	if _, ok := restartedHost.releaseLeases.get(before.PluginInstanceID, *before.ReleaseTrustBinding); ok {
		t.Fatal("canceled recovery published an activation lease")
	}
	if restartedFixture.DocumentTransport.Calls() != 0 || restartedFixture.LedgerTransport.Calls() != 0 || restartedResolver.calls != 0 {
		t.Fatalf("canceled recovery performed remote work: documents=%d ledger=%d resolver=%d", restartedFixture.DocumentTransport.Calls(), restartedFixture.LedgerTransport.Calls(), restartedResolver.calls)
	}
}

func TestReleaseActivationLeaseRecoveryRejectsTamperedRegistryEvidence(t *testing.T) {
	ctx := hostTestContext()
	registryStore := registry.NewMemoryStore()
	pluginDataRoot := t.TempDir()
	installedFixture := newHostReleaseTrustFixture(t)
	installedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust:            installedFixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(installedFixture)},
		registry:                registryStore, pluginDataRoot: pluginDataRoot,
	})
	installed, err := installedHost.InstallReleaseRef(ctx, InstallReleaseRefRequest{
		PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(installedFixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := installedHost.EnablePlugin(ctx, EnableRequest{
		PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := installedHost.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*registry.PluginRecord)
	}{
		{name: "plugin instance", mutate: func(record *registry.PluginRecord) { record.PluginInstanceID += "_tampered" }},
		{name: "source", mutate: func(record *registry.PluginRecord) { record.ReleaseTrustBinding.SourceID += "_tampered" }},
		{name: "channel", mutate: func(record *registry.PluginRecord) { record.ReleaseTrustBinding.Channel += "_tampered" }},
		{name: "version", mutate: func(record *registry.PluginRecord) { record.ReleaseTrustBinding.Version = "9.9.9" }},
		{name: "package hash", mutate: func(record *registry.PluginRecord) {
			record.PackageHash = prefixedReleaseSHA256(strings.Repeat("a", 64))
		}},
		{name: "active fingerprint", mutate: func(record *registry.PluginRecord) {
			record.ActiveFingerprint = prefixedReleaseSHA256(strings.Repeat("b", 64))
		}},
		{name: "state digest", mutate: func(record *registry.PluginRecord) {
			record.ReleaseTrustBinding.VerifiedStateSHA256 = strings.Repeat("c", 64)
		}},
		{name: "root epoch", mutate: func(record *registry.PluginRecord) { record.ReleaseTrustBinding.RootEpoch = "2" }},
		{name: "policy epoch", mutate: func(record *registry.PluginRecord) { record.ReleaseTrustBinding.PolicyEpoch = "2" }},
		{name: "revocation epoch", mutate: func(record *registry.PluginRecord) { record.ReleaseTrustBinding.RevocationEpoch = "2" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restartedFixture := newHostReleaseTrustFixtureWithState(t, installedFixture)
			restartedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restartedFixture)}
			restartedHost, surfaces, _ := newTestHostWithOptions(t, testHostOptions{
				releaseTrust: restartedFixture.ServiceSet, releaseArtifactResolver: restartedResolver,
				registry: registryStore, pluginDataRoot: pluginDataRoot,
			})
			record := enabled
			binding := *enabled.ReleaseTrustBinding
			record.ReleaseTrustBinding = &binding
			record.Metadata = cloneStringMap(enabled.Metadata)
			tt.mutate(&record)
			if err := restartedHost.ensureReleaseActivationLease(ctx, record); !errors.Is(err, releasetrust.ErrActivationRecoveryRejected) {
				t.Fatalf("ensureReleaseActivationLease() error = %v, want ErrActivationRecoveryRejected", err)
			}
			if len(surfaces.snapshots) != 0 {
				t.Fatalf("rejected recovery published surfaces: %#v", surfaces.snapshots)
			}
			if restartedFixture.DocumentTransport.Calls() != 0 || restartedFixture.LedgerTransport.Calls() != 0 || restartedResolver.calls != 0 {
				t.Fatalf("rejected recovery performed remote work: documents=%d ledger=%d resolver=%d", restartedFixture.DocumentTransport.Calls(), restartedFixture.LedgerTransport.Calls(), restartedResolver.calls)
			}
		})
	}
}

func TestReleaseActivationLeaseRecoveryRejectsFencedExpiredAndFutureDurableState(t *testing.T) {
	t.Run("fenced", func(t *testing.T) {
		ctx := hostTestContext()
		registryStore := registry.NewMemoryStore()
		fixture := newHostReleaseTrustFixture(t)
		host, _, _ := newTestHostWithOptions(t, testHostOptions{
			releaseTrust:            fixture.ServiceSet,
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
			registry:                registryStore,
		})
		installed, err := host.InstallReleaseRef(ctx, InstallReleaseRefRequest{
			PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		record, err := registryStore.GetPlugin(ctx, installed.PluginInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		var state releasetrust.ReleaseTrustStateV1
		if err := json.Unmarshal(fixture.StateStore.CommittedBytes(), &state); err != nil {
			t.Fatal(err)
		}
		state.Channels[0].FenceGeneration = 1
		state.Channels[0].Fence = &releasetrust.ReleaseTrustFenceV1{
			Generation: 1, Reason: releasetrust.SourceFenceRestartRecovery, FencedAt: state.TrustedTime.Floor,
		}
		raw, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		fixture.StateStore.ReplaceCommittedBytes(raw)
		digest := sha256.Sum256(raw)
		record.ReleaseTrustBinding.VerifiedStateSHA256 = fmt.Sprintf("%x", digest[:])
		if err := registry.SealReleaseActivationEvidence(&record); err != nil {
			t.Fatal(err)
		}
		restarted := newHostReleaseTrustFixtureWithState(t, fixture)
		restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
			releaseTrust:            restarted.ServiceSet,
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restarted)},
			registry:                registryStore,
		})
		if err := restartedHost.ensureReleaseActivationLease(ctx, record); !errors.Is(err, releasetrust.ErrActivationRecoveryRejected) {
			t.Fatalf("ensureReleaseActivationLease() error = %v, want fenced recovery rejection", err)
		}
	})

	for _, testCase := range []struct {
		name   string
		mutate func(*registry.PluginRecord)
	}{
		{
			name: "root epoch mismatch",
			mutate: func(record *registry.PluginRecord) {
				record.ReleaseTrustBinding.RootEpoch = "2"
				record.Metadata["source.root_epoch"] = "2"
			},
		},
		{
			name: "policy epoch mismatch",
			mutate: func(record *registry.PluginRecord) {
				record.ReleaseTrustBinding.PolicyEpoch = "2"
				record.TrustAssessment.PolicyEpoch = "2"
				record.Metadata["source.policy_epoch"] = "2"
			},
		},
		{
			name: "revocation epoch mismatch",
			mutate: func(record *registry.PluginRecord) {
				record.ReleaseTrustBinding.RevocationEpoch = "2"
				record.TrustAssessment.RevocationEpoch = "2"
				record.Metadata["source.revocation_epoch"] = "2"
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := hostTestContext()
			fixture := newHostReleaseTrustFixture(t)
			registryStore := registry.NewMemoryStore()
			host, _, _ := newTestHostWithOptions(t, testHostOptions{
				releaseTrust:            fixture.ServiceSet,
				releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
				registry:                registryStore,
			})
			installed, err := host.InstallReleaseRef(ctx, InstallReleaseRefRequest{
				PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			record, err := registryStore.GetPlugin(ctx, installed.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			binding := *record.ReleaseTrustBinding
			record.ReleaseTrustBinding = &binding
			record.Metadata = cloneStringMap(record.Metadata)
			testCase.mutate(&record)
			record.ActiveFingerprint = activeFingerprintForPackage(pluginpkg.Package{
				Manifest: record.Manifest, Entries: record.PackageEntries,
				PackageHash: record.PackageHash, ManifestHash: record.ManifestHash, EntriesHash: record.EntriesHash,
			}, record.PluginInstanceID, record.TrustAssessment, record.CapabilityContracts)
			if err := registry.SealReleaseActivationEvidence(&record); err != nil {
				t.Fatal(err)
			}
			restarted := newHostReleaseTrustFixtureWithState(t, fixture)
			restartedResolver := &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restarted)}
			restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
				releaseTrust: restarted.ServiceSet, releaseArtifactResolver: restartedResolver, registry: registryStore,
			})
			err = restartedHost.ensureReleaseActivationLease(ctx, record)
			if !errors.Is(err, releasetrust.ErrActivationRecoveryRejected) || !strings.Contains(err.Error(), "trust epoch mismatch") {
				t.Fatalf("ensureReleaseActivationLease() error = %v, want trust epoch mismatch", err)
			}
			if restarted.DocumentTransport.Calls() != 0 || restarted.LedgerTransport.Calls() != 0 || restartedResolver.calls != 0 {
				t.Fatalf("epoch mismatch performed remote work: documents=%d ledger=%d resolver=%d", restarted.DocumentTransport.Calls(), restarted.LedgerTransport.Calls(), restartedResolver.calls)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		ctx := hostTestContext()
		generatedAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
		fixture := newHostReleaseTrustFixtureWithOptions(t, releasetrustfixture.Options{
			GeneratedAt: generatedAt, ExpiresAt: generatedAt.Add(90 * time.Minute),
		})
		registryStore := registry.NewMemoryStore()
		host, _, _ := newTestHostWithOptions(t, testHostOptions{
			releaseTrust:            fixture.ServiceSet,
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
			registry:                registryStore,
		})
		installed, err := host.InstallReleaseRef(ctx, InstallReleaseRefRequest{
			PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		record, err := registryStore.GetPlugin(ctx, installed.PluginInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		restarted := newHostReleaseTrustFixtureWithState(t, fixture)
		restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
			releaseTrust:            restarted.ServiceSet,
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restarted)},
			registry:                registryStore,
		})
		if err := restartedHost.ensureReleaseActivationLease(ctx, record); !errors.Is(err, releasetrust.ErrActivationLeaseExpired) {
			t.Fatalf("ensureReleaseActivationLease() error = %v, want ErrActivationLeaseExpired", err)
		}
	})

	t.Run("future schema", func(t *testing.T) {
		ctx := hostTestContext()
		fixture := newHostReleaseTrustFixture(t)
		registryStore := registry.NewMemoryStore()
		host, _, _ := newTestHostWithOptions(t, testHostOptions{
			releaseTrust:            fixture.ServiceSet,
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
			registry:                registryStore,
		})
		installed, err := host.InstallReleaseRef(ctx, InstallReleaseRefRequest{
			PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		record, err := registryStore.GetPlugin(ctx, installed.PluginInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		var state map[string]any
		if err := json.Unmarshal(fixture.StateStore.CommittedBytes(), &state); err != nil {
			t.Fatal(err)
		}
		state["schema_version"] = "redevplugin.release_trust_state.v999"
		raw, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		fixture.StateStore.ReplaceCommittedBytes(raw)
		restarted := newHostReleaseTrustFixtureWithState(t, fixture)
		restartedHost, _, _ := newTestHostWithOptions(t, testHostOptions{
			releaseTrust:            restarted.ServiceSet,
			releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(restarted)},
			registry:                registryStore,
		})
		if err := restartedHost.ensureReleaseActivationLease(ctx, record); !errors.Is(err, releasetrust.ErrInvalidReleaseTrustState) {
			t.Fatalf("ensureReleaseActivationLease() error = %v, want ErrInvalidReleaseTrustState", err)
		}
	})
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
			hostTestContext(),
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
		hostTestContext(),
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

func TestRegistryReleaseInstallVerifiesEmbeddedHostCapabilityContractBundle(t *testing.T) {
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	contract.PublisherID = "fixture.capability"
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract: contract, PublisherID: contract.PublisherID,
		ArtifactBaseRef: "capabilities/fixture/embedded/1.0.0", GeneratedAt: time.Date(2026, 7, 21, 1, 0, 0, 0, time.UTC),
		SourceCommit: "0123456789abcdef0123456789abcdef01234567", MinReDevPluginVersion: "0.6.0",
		SignatureKeyID: "fixture_signing_key", SignaturePolicyEpoch: "1", SignatureRevocationEpoch: "1",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := releasetrustfixture.New(buildHostReleasePackageWithCapability(t, bundle.Pin), releasetrustfixture.Options{
		SourceType: "registry",
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
		Artifacts: &memoryCapabilityContractArtifactSet{
			bundle: bundle, origin: CapabilityArtifactOriginHost, omitFetchChain: true,
		},
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
		t.Fatalf("verified embedded capability contracts = %#v, resolver calls = %d", installed.CapabilityContracts, capabilityResolver.calls)
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
	generatedAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	return newHostReleaseTrustFixtureWithOptions(t, releasetrustfixture.Options{
		GeneratedAt: generatedAt, ExpiresAt: generatedAt.Add(24 * time.Hour),
	})
}

func newHostReleaseTrustFixtureWithState(t *testing.T, installed *releasetrustfixture.Fixture) *releasetrustfixture.Fixture {
	t.Helper()
	return newHostReleaseTrustFixtureWithOptions(t, releasetrustfixture.Options{
		GeneratedAt: installed.GeneratedAt, ExpiresAt: installed.ExpiresAt,
		StateStore: installed.StateStore, TrustedTime: installed.TrustedTime,
	})
}

func newHostReleaseTrustFixtureWithOptions(t *testing.T, options releasetrustfixture.Options) *releasetrustfixture.Fixture {
	t.Helper()
	fixture, err := releasetrustfixture.New(buildHostReleasePackage(t), options)
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
  "schema_version": "redevplugin.manifest.v8",
  "publisher": {"publisher_id": "fixture.publisher", "display_name": "Fixture"},
  "plugin": {
    "plugin_id": "fixture.plugin",
    "display_name": "Fixture",
    "version": "1.0.0",
    "api_version": "plugin-v1",
    "min_runtime_version": "0.1.0",
    "ui_protocol_version": "plugin-ui-v7"
  },
  "presentation": {
    "default_locale": "en-US",
    "summary": "Fixture release plugin.",
    "description": ["Fixture release plugin used by the signed release integration tests."],
    "highlights": [],
    "keywords": ["fixture"],
    "localizations": []
  },
  "surfaces": [
    {"surface_id": "fixture.view", "kind": "view", "label": "Fixture", "entry": "ui/index.html"}
  ]
}`
}
