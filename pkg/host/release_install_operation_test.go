package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/externalsource"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/releasecontract"
	"github.com/floegence/redevplugin/pkg/releasetrust"
	"github.com/floegence/redevplugin/pkg/security"
)

func TestReleaseInstallOperationActivatesVerifiedOfficialReleaseWithoutPermissions(t *testing.T) {
	fixture := newHostReleaseTrustFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
	})
	ctx := hostTestContext()
	pluginInstanceID := nextTestPluginInstanceID(t)
	started, err := h.StartReleaseInstallOperation(ctx, StartReleaseInstallOperationRequest{
		RequestID:        "request_activate_official_release",
		PluginInstanceID: pluginInstanceID,
		ReleaseRef:       releaseTrustFixtureRef(fixture),
		Now:              time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.OperationID)
	if terminal.Status != registry.ReleaseInstallSucceeded || terminal.PluginRecord == nil {
		t.Fatalf("terminal operation status=%q phase=%q failure=%#v", terminal.Status, terminal.Phase, terminal.Failure)
	}
	if terminal.PluginRecord.EnableState != registry.EnableEnabled {
		t.Fatalf("enable state = %q, want %q", terminal.PluginRecord.EnableState, registry.EnableEnabled)
	}
	if terminal.Activation.Status != registry.ReleaseInstallActivationEnabled ||
		len(terminal.Activation.MissingPermissionIDs) != 0 {
		t.Fatalf("activation = %#v", terminal.Activation)
	}
}

func TestReleaseInstallOperationHonorsExplicitDisabledActivation(t *testing.T) {
	fixture := newHostReleaseTrustFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
	})
	ctx := hostTestContext()
	activate := false
	started, err := h.StartReleaseInstallOperation(ctx, StartReleaseInstallOperationRequest{
		RequestID: "request_keep_official_release_disabled", PluginInstanceID: nextTestPluginInstanceID(t),
		ReleaseRef: releaseTrustFixtureRef(fixture), ActivateAfterInstall: &activate, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.OperationID)
	if terminal.Status != registry.ReleaseInstallSucceeded || terminal.PluginRecord == nil ||
		terminal.PluginRecord.EnableState != registry.EnableDisabled ||
		terminal.Activation.Status != registry.ReleaseInstallActivationNotRequested {
		t.Fatalf("terminal operation = %#v", terminal)
	}
}

func TestReleaseInstallOperationDoesNotAutomaticallyActivateNonOfficialRelease(t *testing.T) {
	fixture, err := releasetrustfixture.New(buildHostReleasePackage(t), releasetrustfixture.Options{SourceClass: "community"})
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
	})
	ctx := hostTestContext()
	started, err := h.StartReleaseInstallOperation(ctx, StartReleaseInstallOperationRequest{
		RequestID: "request_keep_community_release_disabled", PluginInstanceID: nextTestPluginInstanceID(t),
		ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.OperationID)
	if terminal.Status != registry.ReleaseInstallSucceeded || terminal.PluginRecord == nil ||
		terminal.PluginRecord.EnableState != registry.EnableDisabled ||
		terminal.Activation.Status != registry.ReleaseInstallActivationNotRequested {
		t.Fatalf("terminal operation = %#v", terminal)
	}
}

func TestReleaseInstallOperationTerminalActivationSurvivesHostRestart(t *testing.T) {
	for _, test := range []struct {
		name             string
		withPermission   bool
		wantActivation   registry.ReleaseInstallActivationStatus
		wantEnableState  registry.EnableState
		wantMissingCount int
	}{
		{name: "enabled", wantActivation: registry.ReleaseInstallActivationEnabled, wantEnableState: registry.EnableEnabled},
		{name: "needs attention", withPermission: true, wantActivation: registry.ReleaseInstallActivationNeedsAttention, wantEnableState: registry.EnableDisabled, wantMissingCount: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var fixture *releasetrustfixture.Fixture
			var capabilityArtifacts CapabilityContractArtifactResolver
			if test.withPermission {
				var bundle capabilitycontract.Bundle
				fixture, bundle = newReleaseInstallCapabilityFixture(t)
				capabilityArtifacts = &recordingCapabilityContractArtifactResolver{result: ResolvedCapabilityContractArtifact{
					Artifacts: &memoryCapabilityContractArtifactSet{bundle: bundle},
				}}
			} else {
				fixture = newHostReleaseTrustFixture(t)
			}
			ctx := hostTestContext()
			registryPath := filepath.Join(t.TempDir(), "registry.sqlite")
			pluginDataRoot := filepath.Join(t.TempDir(), "plugin-data")
			store, err := registry.NewSQLiteStore(ctx, registryPath)
			if err != nil {
				t.Fatal(err)
			}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				registry: store, pluginDataRoot: pluginDataRoot, releaseTrust: fixture.ServiceSet,
				releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
				capabilityArtifacts:     capabilityArtifacts,
			})
			started, err := h.StartReleaseInstallOperation(ctx, StartReleaseInstallOperationRequest{
				RequestID:        "request_restart_" + strings.ReplaceAll(test.name, " ", "_"),
				PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			terminal := waitForReleaseInstallOperation(t, h, ctx, started.OperationID)
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			reopenedStore, err := registry.NewSQLiteStore(ctx, registryPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopenedStore.Close() })
			restarted, _, _ := newTestHostWithOptions(t, testHostOptions{
				registry: reopenedStore, pluginDataRoot: pluginDataRoot,
			})
			recovered, err := restarted.GetReleaseInstallOperation(ctx, terminal.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.Status != registry.ReleaseInstallSucceeded || recovered.PluginRecord == nil ||
				recovered.Activation.Status != test.wantActivation || recovered.PluginRecord.EnableState != test.wantEnableState ||
				len(recovered.Activation.MissingPermissionIDs) != test.wantMissingCount {
				t.Fatalf("recovered operation = %#v", recovered)
			}
		})
	}
}

func TestReleaseInstallOperationRequiresExplicitPermissionApprovalBeforeActivation(t *testing.T) {
	fixture, bundle := newReleaseInstallCapabilityFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
		capabilityArtifacts: &recordingCapabilityContractArtifactResolver{result: ResolvedCapabilityContractArtifact{
			Artifacts: &memoryCapabilityContractArtifactSet{bundle: bundle},
		}},
	})
	ctx := hostTestContext()
	started, err := h.StartReleaseInstallOperation(ctx, StartReleaseInstallOperationRequest{
		RequestID:        "request_official_release_missing_approval",
		PluginInstanceID: nextTestPluginInstanceID(t),
		ReleaseRef:       releaseTrustFixtureRef(fixture),
		Now:              time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.OperationID)
	if terminal.Status != registry.ReleaseInstallSucceeded || terminal.PluginRecord == nil {
		t.Fatalf("terminal operation status=%q phase=%q failure=%#v", terminal.Status, terminal.Phase, terminal.Failure)
	}
	if terminal.PluginRecord.EnableState != registry.EnableDisabled {
		t.Fatalf("enable state = %q, want %q", terminal.PluginRecord.EnableState, registry.EnableDisabled)
	}
	if terminal.Activation.Status != registry.ReleaseInstallActivationNeedsAttention ||
		terminal.Activation.NextAction != "approve_permissions" ||
		len(terminal.Activation.MissingPermissionIDs) != 1 || terminal.Activation.MissingPermissionIDs[0] != "read" {
		t.Fatalf("activation = %#v", terminal.Activation)
	}
	grants, err := h.ListPermissionGrants(ctx, ListPermissionGrantsRequest{PluginInstanceID: terminal.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("permission grants = %#v, want none", grants)
	}
}

func TestReleaseInstallOperationGrantsApprovedRequiredPermissionAndActivates(t *testing.T) {
	fixture, bundle := newReleaseInstallCapabilityFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
		capabilityArtifacts: &recordingCapabilityContractArtifactResolver{result: ResolvedCapabilityContractArtifact{
			Artifacts: &memoryCapabilityContractArtifactSet{bundle: bundle},
		}},
	})
	ctx := hostTestContext()
	started, err := h.StartReleaseInstallOperation(ctx, StartReleaseInstallOperationRequest{
		RequestID:             "request_official_release_approved",
		PluginInstanceID:      nextTestPluginInstanceID(t),
		ReleaseRef:            releaseTrustFixtureRef(fixture),
		ApprovedPermissionIDs: []string{"read"},
		Now:                   time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.OperationID)
	if terminal.Status != registry.ReleaseInstallSucceeded || terminal.PluginRecord == nil {
		t.Fatalf("terminal operation status=%q phase=%q failure=%#v", terminal.Status, terminal.Phase, terminal.Failure)
	}
	if terminal.PluginRecord.EnableState != registry.EnableEnabled || terminal.Activation.Status != registry.ReleaseInstallActivationEnabled {
		t.Fatalf("plugin=%#v activation=%#v", terminal.PluginRecord, terminal.Activation)
	}
	grants, err := h.ListPermissionGrants(ctx, ListPermissionGrantsRequest{PluginInstanceID: terminal.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].PermissionID != "read" {
		t.Fatalf("permission grants = %#v", grants)
	}
}

type recordingReleaseInstallRegistry struct {
	registry.Store
	mu     sync.Mutex
	phases []string
}

func (store *recordingReleaseInstallRegistry) UpdateReleaseInstallOperation(ctx context.Context, req registry.UpdateReleaseInstallOperationRequest) (registry.ReleaseInstallOperation, error) {
	store.mu.Lock()
	if len(store.phases) == 0 || store.phases[len(store.phases)-1] != req.Phase {
		store.phases = append(store.phases, req.Phase)
	}
	store.mu.Unlock()
	return store.Store.UpdateReleaseInstallOperation(ctx, req)
}

func (store *recordingReleaseInstallRegistry) observedPhases() []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]string(nil), store.phases...)
}

func TestReleaseInstallOperationPersistsExplainablePhaseOrder(t *testing.T) {
	fixture, bundle := newReleaseInstallCapabilityFixture(t)
	store := &recordingReleaseInstallRegistry{Store: registry.NewMemoryStore()}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		registry: store, releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
		capabilityArtifacts: &recordingCapabilityContractArtifactResolver{result: ResolvedCapabilityContractArtifact{
			Artifacts: &memoryCapabilityContractArtifactSet{bundle: bundle},
		}},
	})
	ctx := hostTestContext()
	started, err := h.StartReleaseInstallOperation(ctx, StartReleaseInstallOperationRequest{
		RequestID:             "request_explainable_phases",
		PluginInstanceID:      nextTestPluginInstanceID(t),
		ReleaseRef:            releaseTrustFixtureRef(fixture),
		ApprovedPermissionIDs: []string{"read"},
		Now:                   time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal := waitForReleaseInstallOperation(t, h, ctx, started.OperationID)
	if terminal.Status != registry.ReleaseInstallSucceeded {
		t.Fatalf("terminal failure = %#v", terminal.Failure)
	}
	want := []string{
		"fetch_trust_evidence",
		"fetch_release_evidence",
		"download_package",
		"verify_hashes",
		"verify_signatures_ledger",
		"fetch_capability_evidence",
		"commit",
		"enable",
		"complete",
	}
	if got := store.observedPhases(); !reflect.DeepEqual(got, want) {
		t.Fatalf("observed phases = %#v, want %#v", got, want)
	}
	diagnosticPhases := make([]string, 0, len(terminal.PhaseDiagnostics))
	for _, diagnostic := range terminal.PhaseDiagnostics {
		if diagnostic.Phase == "queued" {
			continue
		}
		diagnosticPhases = append(diagnosticPhases, diagnostic.Phase)
		if diagnostic.CompletedAt == nil || diagnostic.DurationMS < 0 {
			t.Fatalf("incomplete phase diagnostic = %#v", diagnostic)
		}
		if (diagnostic.Phase == "verify_hashes" || diagnostic.Phase == "verify_signatures_ledger") && diagnostic.DurationMS >= 1000 {
			t.Fatalf("pure verification phase exceeded budget: %#v", diagnostic)
		}
	}
	if !reflect.DeepEqual(diagnosticPhases, want) {
		t.Fatalf("diagnostic phases = %#v, want %#v", diagnosticPhases, want)
	}
}

func newReleaseInstallCapabilityFixture(t *testing.T) (*releasetrustfixture.Fixture, capabilitycontract.Bundle) {
	t.Helper()
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	contract.PublisherID = "fixture.capability"
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract: contract, PublisherID: contract.PublisherID,
		ArtifactBaseRef: "capabilities/fixture/install/1.0.0",
		GeneratedAt:     time.Date(2026, 7, 21, 1, 0, 0, 0, time.UTC),
		SourceCommit:    "0123456789abcdef0123456789abcdef01234567", MinReDevPluginVersion: "0.1.0",
		SignatureKeyID: "fixture_signing_key", SignaturePolicyEpoch: "1", SignatureRevocationEpoch: "1",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(hostReleaseManifestJSON()), &document); err != nil {
		t.Fatal(err)
	}
	pinBytes, err := json.Marshal(bundle.Pin)
	if err != nil {
		t.Fatal(err)
	}
	var pinDocument map[string]any
	if err := json.Unmarshal(pinBytes, &pinDocument); err != nil {
		t.Fatal(err)
	}
	document["capability_bindings"] = []any{map[string]any{"binding_id": "fixture.echo", "contract": pinDocument}}
	document["methods"] = []any{map[string]any{
		"method": "echo.ping",
		"route":  map[string]any{"kind": "capability", "binding_id": "fixture.echo", "target_method": "echo.ping"},
	}}
	manifestBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := releasetrustfixture.New(buildHostReleasePackageFromManifest(t, string(manifestBytes)), releasetrustfixture.Options{
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
	return fixture, bundle
}

func waitForReleaseInstallOperation(t *testing.T, h *Host, ctx context.Context, operationID string) registry.ReleaseInstallOperation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := h.GetReleaseInstallOperation(ctx, operationID)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Status == registry.ReleaseInstallSucceeded || operation.Status == registry.ReleaseInstallFailed {
			return operation
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("release install operation %q did not terminate", operationID)
	return registry.ReleaseInstallOperation{}
}

type failingReleaseInstallProgressRegistry struct {
	registry.Store
	err error
}

func (store failingReleaseInstallProgressRegistry) UpdateReleaseInstallOperation(context.Context, registry.UpdateReleaseInstallOperationRequest) (registry.ReleaseInstallOperation, error) {
	return registry.ReleaseInstallOperation{}, store.err
}

func TestReleaseInstallProgressTrackerPreservesPersistenceFailure(t *testing.T) {
	persistErr := errors.New("operation journal unavailable")
	h := &Host{adapters: normalizedAdapters{Registry: failingReleaseInstallProgressRegistry{Store: registry.NewMemoryStore(), err: persistErr}}}
	tracker := &releaseInstallProgressTracker{
		host: h,
		ctx:  context.Background(),
		current: registry.ReleaseInstallOperation{
			OperationID: "operation_install_example", Revision: 1,
		},
	}

	tracker.observe(ReleaseArtifactProgress{Phase: "download", ArtifactRole: "package", Completed: 1, Total: 2, Attempt: 1})
	operation, err := tracker.snapshot()
	if operation.OperationID != "operation_install_example" || !errors.Is(err, persistErr) {
		t.Fatalf("snapshot = %#v, %v; want original operation and persistence error", operation, err)
	}
}

func TestReleaseInstallFailureClassifiesReleaseTrustErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code security.ErrorCode
	}{
		{name: "verification", err: releasetrust.ErrReleaseTrustVerification, code: security.ErrReleaseRefVerificationFailed},
		{name: "expired", err: releasetrust.ErrReleaseTrustExpired, code: security.ErrReleaseRefVerificationFailed},
		{name: "rollback", err: releasetrust.ErrReleaseTrustRollback, code: security.ErrReleaseRefVerificationFailed},
		{name: "revoked", err: releasetrust.ErrReleaseTrustRevoked, code: security.ErrReleaseRefVerificationFailed},
		{name: "policy", err: releasetrust.ErrReleasePolicyDenied, code: security.ErrReleaseRefPolicyDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			boundaryErr := releaseTrustBoundaryError(test.err)
			if code := releaseInstallFailureCode(boundaryErr); code != string(test.code) {
				t.Fatalf("releaseInstallFailureCode() = %q, want %q", code, test.code)
			}
			if releaseInstallFailureRetryable(boundaryErr) {
				t.Fatal("release trust failure was marked retryable")
			}
		})
	}
}

func TestReleaseTrustBoundaryPreservesTransportAndDeadlineIdentity(t *testing.T) {
	networkErr := externalsource.NewHTTPStatusError("fetch", "https://example.test/asset", 503, 0)
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "deadline", err: errors.Join(releasetrust.ErrReleaseTrustVerification, context.DeadlineExceeded), want: context.DeadlineExceeded},
		{name: "network", err: errors.Join(releasetrust.ErrReleaseTrustVerification, networkErr), want: networkErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := releaseTrustBoundaryError(test.err)
			if !errors.Is(got, test.want) {
				t.Fatalf("releaseTrustBoundaryError() = %v, want identity %v", got, test.want)
			}
		})
	}
}
