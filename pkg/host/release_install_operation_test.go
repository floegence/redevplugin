package host

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v2/internal/testsupport/releasetrustfixture"
	"github.com/floegence/redevplugin/v2/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v2/pkg/execution"
	"github.com/floegence/redevplugin/v2/pkg/externalsource"
	"github.com/floegence/redevplugin/v2/pkg/registry"
	"github.com/floegence/redevplugin/v2/pkg/releasecontract"
	"github.com/floegence/redevplugin/v2/pkg/releasetrust"
	"github.com/floegence/redevplugin/v2/pkg/security"
)

func TestStartReleaseInstallExecutionReturnsUnifiedExecution(t *testing.T) {
	fixture := newHostReleaseTrustFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust:            fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
	})
	ctx := hostTestContext()
	started, err := h.StartReleaseInstallExecution(ctx, StartReleaseInstallExecutionRequest{
		RequestID: "request_unified_execution", PluginInstanceID: nextTestPluginInstanceID(t),
		ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if started.ID == "" || started.Kind != execution.KindOperation || started.Status != execution.StatusRunning || started.Cancelable {
		t.Fatalf("StartReleaseInstallExecution() = %#v", started)
	}
	terminal := waitForReleaseInstallOperation(t, h, ctx, started.ID)
	if terminal.Execution.Status != execution.StatusCompleted {
		t.Fatalf("release install status = %q", terminal.Execution.Status)
	}
	observed, err := h.GetExecution(ctx, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != execution.StatusCompleted || observed.Cursor == 0 {
		t.Fatalf("GetExecution() = %#v", observed)
	}
	events, err := h.EventsAfter(ctx, started.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[len(events)-1].Kind != execution.EventTerminal {
		t.Fatalf("EventsAfter() = %#v", events)
	}
}

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
	started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID:        "request_activate_official_release",
		PluginInstanceID: pluginInstanceID,
		ReleaseRef:       releaseTrustFixtureRef(fixture),
		Now:              time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
	if terminal.Execution.Status != execution.StatusCompleted || terminal.PluginRecord == nil {
		t.Fatalf("terminal operation status=%q phase=%q failure=%#v", terminal.Execution.Status, terminal.Phase, terminal.Failure)
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
	started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID: "request_keep_official_release_disabled", PluginInstanceID: nextTestPluginInstanceID(t),
		ReleaseRef: releaseTrustFixtureRef(fixture), ActivateAfterInstall: &activate, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
	if terminal.Execution.Status != execution.StatusCompleted || terminal.PluginRecord == nil ||
		terminal.PluginRecord.EnableState != registry.EnableDisabled ||
		terminal.Activation.Status != registry.ReleaseInstallActivationNotRequested {
		t.Fatalf("terminal operation = %#v", terminal)
	}
}

func TestReleaseInstallOperationAutomaticallyActivatesConfirmedNonOfficialRelease(t *testing.T) {
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
	started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID: "request_activate_community_release", PluginInstanceID: nextTestPluginInstanceID(t),
		ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
	if terminal.Execution.Status != execution.StatusCompleted || terminal.PluginRecord == nil ||
		terminal.PluginRecord.EnableState != registry.EnableEnabled ||
		terminal.Activation.Status != registry.ReleaseInstallActivationEnabled {
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
			var verified *capabilitycontract.KnownContract
			if test.withPermission {
				var value capabilitycontract.KnownContract
				fixture, value = newReleaseInstallCapabilityFixture(t)
				verified = &value
			} else {
				fixture = newHostReleaseTrustFixture(t)
			}
			ctx := hostTestContext()
			stateRoot := filepath.Join(t.TempDir(), "control-state")
			h, _, _ := newTestHostWithOptions(t, testHostOptions{
				stateRoot: stateRoot, releaseTrust: fixture.ServiceSet,
				releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
				capabilityContract:      verified,
				capabilityAdapter:       &recordingCapabilityAdapter{},
			})
			started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
				RequestID:        "request_restart_" + strings.ReplaceAll(test.name, " ", "_"),
				PluginInstanceID: nextTestPluginInstanceID(t), ReleaseRef: releaseTrustFixtureRef(fixture), Now: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, _, _ := newTestHostWithOptions(t, testHostOptions{
				stateRoot: stateRoot,
			})
			recovered, err := restarted.controlStore.Executions().GetReleaseInstall(ctx, executionOwnerScope(ctx).OwnerEnvHash, terminal.Execution.ID)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.Execution.Status != execution.StatusCompleted || recovered.PluginRecord == nil ||
				recovered.Activation.Status != test.wantActivation || recovered.PluginRecord.EnableState != test.wantEnableState ||
				len(recovered.Activation.MissingPermissionIDs) != test.wantMissingCount {
				t.Fatalf("recovered operation = %#v", recovered)
			}
		})
	}
}

func TestReleaseInstallOperationRecoversCommittedActivationAfterHostRestart(t *testing.T) {
	fixture, verified := newReleaseInstallCapabilityFixture(t)
	ctx := hostTestContext()
	stateRoot := filepath.Join(t.TempDir(), "control-state")
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		stateRoot: stateRoot, releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{artifact: resolvedReleaseTrustFixture(fixture)},
		capabilityContract:      &verified,
		capabilityAdapter:       &recordingCapabilityAdapter{},
	})
	pluginInstanceID := nextTestPluginInstanceID(t)
	ref := releaseTrustFixtureRef(fixture)
	operation, _, err := h.controlStore.Executions().StartReleaseInstall(ctx, executionOwnerScope(ctx), registry.StartReleaseInstallOperationRequest{
		RequestID: "request_recover_committed_activation", ExecutionID: "release_install_recover_committed",
		PluginInstanceID: pluginInstanceID, Release: releaseInstallIdentity(ref),
		Activation: registry.ReleaseInstallActivationRequest{Mode: registry.ReleaseInstallActivationAutomatic, ApprovedPermissionIDs: []string{"read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, release, sourcePolicy, verifiedRelease, metadata, err := h.resolveReleasePackage(
		ctx, PackageTrustActionInstall, ref, nil, pluginInstanceID, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := h.installResolvedPackage(ctx, pkg, pluginInstanceID, packageTrustInput{
		ReleaseRef: &ref, Release: &release, SourcePolicy: &sourcePolicy, VerifiedRelease: &verifiedRelease,
	}, time.Now().UTC(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if record.EnableState != registry.EnableDisabled || operation.Execution.Status != execution.StatusRunning {
		t.Fatalf("crash-window state: operation=%#v record=%#v", operation, record)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, _, _ := newTestHostWithOptions(t, testHostOptions{
		stateRoot: stateRoot, capabilityContract: &verified, capabilityAdapter: &recordingCapabilityAdapter{},
	})
	defer restarted.Close()
	recovered, err := restarted.controlStore.Executions().GetReleaseInstall(ctx, executionOwnerScope(ctx).OwnerEnvHash, operation.Execution.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Execution.Status != execution.StatusCompleted || recovered.Activation.Status != registry.ReleaseInstallActivationEnabled ||
		recovered.PluginRecord == nil || recovered.PluginRecord.EnableState != registry.EnableEnabled {
		t.Fatalf("recovered operation = %#v", recovered)
	}
	grants, err := restarted.ListPermissionGrants(ctx, ListPermissionGrantsRequest{PluginInstanceID: pluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].PermissionID != "read" {
		t.Fatalf("recovered grants = %#v", grants)
	}
}

func TestReleaseInstallOperationRequiresExplicitPermissionApprovalBeforeActivation(t *testing.T) {
	fixture, verified := newReleaseInstallCapabilityFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
		capabilityContract: &verified,
		capabilityAdapter:  &recordingCapabilityAdapter{},
	})
	ctx := hostTestContext()
	started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID:        "request_official_release_missing_approval",
		PluginInstanceID: nextTestPluginInstanceID(t),
		ReleaseRef:       releaseTrustFixtureRef(fixture),
		Now:              time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
	if terminal.Execution.Status != execution.StatusCompleted || terminal.PluginRecord == nil {
		t.Fatalf("terminal operation status=%q phase=%q failure=%#v", terminal.Execution.Status, terminal.Phase, terminal.Failure)
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
	fixture, verified := newReleaseInstallCapabilityFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
		capabilityContract: &verified,
		capabilityAdapter:  &recordingCapabilityAdapter{},
	})
	ctx := hostTestContext()
	started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID:             "request_official_release_approved",
		PluginInstanceID:      nextTestPluginInstanceID(t),
		ReleaseRef:            releaseTrustFixtureRef(fixture),
		ActivateAfterInstall:  new(true),
		ApprovedPermissionIDs: []string{"read"},
		Now:                   time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
	if terminal.Execution.Status != execution.StatusCompleted || terminal.PluginRecord == nil {
		t.Fatalf("terminal operation status=%q phase=%q failure=%#v", terminal.Execution.Status, terminal.Phase, terminal.Failure)
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

func TestInspectReleasePackageReturnsVerifiedPermissionsWithoutInstalling(t *testing.T) {
	fixture, verified := newReleaseInstallCapabilityFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
		capabilityContract: &verified,
		capabilityAdapter:  &recordingCapabilityAdapter{},
	})
	ctx := hostTestContext()
	pluginInstanceID := nextTestPluginInstanceID(t)
	inspection, err := h.InspectReleasePackage(ctx, InspectReleasePackageRequest{
		PluginInstanceID: pluginInstanceID,
		ReleaseRef:       releaseTrustFixtureRef(fixture),
		Now:              time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.PluginInstanceID != pluginInstanceID || inspection.InspectedHashes.PackageSHA256 != fixture.Package.PackageHash ||
		len(inspection.SecuritySummary.Permissions) != 1 || inspection.SecuritySummary.Permissions[0].PermissionID != "read" {
		t.Fatalf("release inspection = %#v", inspection)
	}
	if _, err := h.getPluginRecord(ctx, pluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("release inspection persisted plugin record: %v", err)
	}
}

func TestReleaseInstallOperationPersistsExplainablePhaseOrder(t *testing.T) {
	fixture, verified := newReleaseInstallCapabilityFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
		capabilityContract: &verified,
		capabilityAdapter:  &recordingCapabilityAdapter{},
	})
	ctx := hostTestContext()
	started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID:             "request_explainable_phases",
		PluginInstanceID:      nextTestPluginInstanceID(t),
		ReleaseRef:            releaseTrustFixtureRef(fixture),
		ApprovedPermissionIDs: []string{"read"},
		Now:                   time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
	if terminal.Execution.Status != execution.StatusCompleted {
		t.Fatalf("terminal failure = %#v", terminal.Failure)
	}
	want := []string{
		"fetch_trust_evidence",
		"fetch_release_evidence",
		"download_package",
		"verify_hashes",
		"verify_signatures",
		"fetch_capability_evidence",
		"commit",
		"enable",
		"complete",
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
		if (diagnostic.Phase == "verify_hashes" || diagnostic.Phase == "verify_signatures") && diagnostic.DurationMS >= 1000 {
			t.Fatalf("pure verification phase exceeded budget: %#v", diagnostic)
		}
	}
	if !reflect.DeepEqual(diagnosticPhases, want) {
		t.Fatalf("diagnostic phases = %#v, want %#v", diagnosticPhases, want)
	}
}

func newReleaseInstallCapabilityFixture(t *testing.T) (*releasetrustfixture.Fixture, capabilitycontract.KnownContract) {
	t.Helper()
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	contract.PublisherID = "fixture.capability"
	known, err := capabilitycontract.NewKnownContract(contract)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(hostReleaseManifestJSON()), &document); err != nil {
		t.Fatal(err)
	}
	pinBytes, err := json.Marshal(known.Pin)
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
				Contract: releaseCapabilityContractRef(known.Pin),
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, known
}

func waitForReleaseInstallOperation(t *testing.T, h *Host, ctx context.Context, operationID string) registry.ReleaseInstallOperation {
	t.Helper()
	var last registry.ReleaseInstallOperation
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := h.controlStore.Executions().GetReleaseInstall(ctx, executionOwnerScope(ctx).OwnerEnvHash, operationID)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Execution.Status == execution.StatusCompleted || operation.Execution.Status == execution.StatusFailed {
			return operation
		}
		last = operation
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("release install operation %q did not terminate: last=%#v", operationID, last)
	return registry.ReleaseInstallOperation{}
}

func TestReleaseInstallCapabilityFailurePersistsTerminalStateAfterProgress(t *testing.T) {
	fixture, _ := newReleaseInstallCapabilityFixture(t)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		releaseTrust: fixture.ServiceSet,
		releaseArtifactResolver: &recordingReleaseArtifactResolver{
			artifact: resolvedReleaseTrustFixture(fixture),
		},
	})
	ctx := hostTestContext()
	started, err := h.startReleaseInstallOperation(ctx, startReleaseInstallOperationRequest{
		RequestID: "request_capability_failure_terminal", PluginInstanceID: nextTestPluginInstanceID(t),
		ReleaseRef: releaseTrustFixtureRef(fixture), ActivateAfterInstall: new(false), Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	terminal := waitForReleaseInstallOperation(t, h, ctx, started.Execution.ID)
	if terminal.Execution.Status != execution.StatusFailed || terminal.Phase != "failed" || terminal.Execution.FailureCode == "" {
		t.Fatalf("capability failure did not persist a terminal execution: %#v", terminal)
	}
}

func TestReleaseInstallProgressTrackerPreservesPersistenceFailure(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	ctx := hostTestContext()
	started, _, err := h.controlStore.Executions().StartReleaseInstall(ctx, executionOwnerScope(ctx), registry.StartReleaseInstallOperationRequest{
		RequestID: "request_persistence_failure", ExecutionID: "operation_install_example", PluginInstanceID: "plugini_failure",
		Release:    registry.ReleaseInstallIdentity{SourceID: "source", Channel: "stable", ReleaseMetadataRef: "metadata.json", ReleaseMetadataSHA256: strings.Repeat("a", 64), PublisherID: "publisher", PluginID: "plugin", Version: "1.0.0", PackageSHA256: "sha256:" + strings.Repeat("b", 64), ManifestSHA256: "sha256:" + strings.Repeat("c", 64), EntriesSHA256: "sha256:" + strings.Repeat("d", 64)},
		Activation: registry.ReleaseInstallActivationRequest{Mode: registry.ReleaseInstallActivationDisabled},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.controlStore.Close(); err != nil {
		t.Fatal(err)
	}
	tracker := &releaseInstallProgressTracker{
		host:    h,
		ctx:     ctx,
		current: started,
	}

	tracker.observe(ReleaseArtifactProgress{Phase: "download", ArtifactRole: "package", Completed: 1, Total: 2, Attempt: 1})
	operation, err := tracker.snapshot()
	if operation.Execution.ID != "operation_install_example" || err == nil {
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
