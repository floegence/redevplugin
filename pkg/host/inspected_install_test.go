package host

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestInspectedInstallRecoversExactRequestAcrossSessionRenewal(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Created"))}
	configureExternalPackageTestModule(h, stage)
	ctx := hostTestContext()
	inspection, err := h.InspectUploadedExternalPackage(ctx, InspectUploadedExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Package: strings.NewReader("package"), DeclaredSize: 7})
	if err != nil {
		t.Fatal(err)
	}
	request := StartInspectedInstallRequest{RequestID: "create-install-1", InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256}
	started, err := h.StartInspectedInstall(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(3 * time.Second); ; {
		op, e := h.GetInspectedInstall(ctx, request.RequestID)
		if e != nil {
			t.Fatal(e)
		}
		if op.Execution.Status != execution.StatusRunning {
			if op.Execution.Status != execution.StatusCompleted || op.MutationOutcome != mutation.OutcomeCommitted {
				t.Fatalf("operation: %+v", op)
			}
			break
		}
		if time.Now().After(end) {
			t.Fatal("install did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	session, _ := sessionctx.FromContext(ctx)
	session.OwnerSessionHash = "renewed"
	session.SessionChannelIDHash = "new-channel"
	renewed := sessionctx.WithContext(context.Background(), session)
	again, err := h.StartInspectedInstall(renewed, request)
	if err != nil || again.Execution.ID != started.Execution.ID {
		t.Fatalf("recovery: %+v %v", again, err)
	}
	if recovered, err := h.GetExecution(renewed, started.Execution.ID); err != nil || recovered.Status != execution.StatusCompleted {
		t.Fatalf("execution recovery: %+v %v", recovered, err)
	}
	events, err := h.EventsAfter(renewed, started.Execution.ID, 0, 100)
	if err != nil || len(events) == 0 || events[len(events)-1].Kind != execution.EventTerminal {
		t.Fatalf("event recovery: %+v %v", events, err)
	}
	listed, _, err := h.ListExecutionsWithOptions(renewed, ListExecutionsOptions{OperationScope: ExecutionOperationScopePluginInstall})
	if err != nil || len(listed) != 1 || listed[0].ID != started.Execution.ID {
		t.Fatalf("list recovery: %+v %v", listed, err)
	}
	request.ExpectedPackageSHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err = h.StartInspectedInstall(renewed, request); !errors.Is(err, ErrExternalPackageConfirmation) {
		t.Fatalf("conflicting retry: %v", err)
	}
	records, err := h.ListPlugins(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("duplicate install: %d %v", len(records), err)
	}
	session.OwnerUserHash = "foreign"
	foreign := sessionctx.WithContext(context.Background(), session)
	if _, err = h.GetInspectedInstall(foreign, request.RequestID); err == nil {
		t.Fatal("foreign owner read outcome")
	}
	if _, err := h.GetExecution(foreign, started.Execution.ID); err == nil {
		t.Fatal("foreign owner read execution")
	}
	if _, err := h.EventsAfter(foreign, started.Execution.ID, 0, 100); err == nil {
		t.Fatal("foreign owner read events")
	}
}
func TestInspectedInstallReconcilesOnlyExactCommitEvidence(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Created"))}
	configureExternalPackageTestModule(h, stage)
	ctx := hostTestContext()
	session, _ := sessionctx.FromContext(ctx)
	owner := executionOwner(session)
	inspection, err := h.InspectUploadedExternalPackage(ctx, InspectUploadedExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Package: strings.NewReader("package"), DeclaredSize: 7})
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := h.controlStore.Executions().StartInspectedInstall(ctx, owner, controlstore.InspectedInstall{RequestID: "crash-after-commit", InspectionID: inspection.InspectionID, PackageSHA256: inspection.InspectedHashes.PackageSHA256, PluginID: inspection.PluginID, Version: inspection.Version, Execution: execution.Execution{PluginInstanceID: inspection.Intent.PluginInstanceID, Kind: execution.KindOperation}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.installInspectedPackage(ctx, installInspectedPackageRequest{InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256, operationEvidence: op.Execution.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.reconcileInspectedInstalls(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := h.GetInspectedInstall(ctx, op.RequestID)
	if err != nil || got.MutationOutcome != mutation.OutcomeCommitted || got.Execution.Status != execution.StatusCompleted {
		t.Fatalf("commit lost: %+v %v", got, err)
	}
	missing := op
	missing.RequestID = "not-the-same-commit"
	missing.InspectionID = "different-inspection"
	missing.Execution.ID = ""
	missing.Execution.Cursor = 0
	missing.Execution.Status = ""
	if _, _, err = h.controlStore.Executions().StartInspectedInstall(ctx, owner, missing); err != nil {
		t.Fatal(err)
	}
	if err = h.reconcileInspectedInstalls(ctx); err != nil {
		t.Fatal(err)
	}
	got, err = h.GetInspectedInstall(ctx, missing.RequestID)
	if err != nil || got.MutationOutcome != mutation.OutcomeUnknown {
		t.Fatalf("unproven commit treated as success: %+v %v", got, err)
	}
}

func TestInspectedInstallReceiptSurvivesHostRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	options := testHostOptions{stateRoot: root, productionStateOwners: true}
	h, _, _ := newTestHostWithOptions(t, options)
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Created"))}
	configureExternalPackageTestModule(h, stage)
	ctx := hostTestContext()
	session, _ := sessionctx.FromContext(ctx)
	inspection, err := h.InspectUploadedExternalPackage(ctx, InspectUploadedExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Package: strings.NewReader("package"), DeclaredSize: 7})
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := h.controlStore.Executions().StartInspectedInstall(ctx, executionOwner(session), controlstore.InspectedInstall{RequestID: "restart", InspectionID: inspection.InspectionID, PackageSHA256: inspection.InspectedHashes.PackageSHA256, PluginID: inspection.PluginID, Version: inspection.Version, Execution: execution.Execution{PluginInstanceID: inspection.Intent.PluginInstanceID, Kind: execution.KindOperation}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.installInspectedPackage(ctx, installInspectedPackageRequest{InspectionID: inspection.InspectionID, ExpectedPackageSHA256: op.PackageSHA256, operationEvidence: op.Execution.ID}); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, _, _ := newTestHostWithOptions(t, options)
	configureExternalPackageTestModule(reopened, stage)
	got, err := reopened.GetInspectedInstall(ctx, "restart")
	if err != nil || got.MutationOutcome != mutation.OutcomeCommitted {
		t.Fatalf("restart receipt: %+v %v", got, err)
	}
	again, err := reopened.StartInspectedInstall(ctx, StartInspectedInstallRequest{RequestID: op.RequestID, InspectionID: op.InspectionID, ExpectedPackageSHA256: op.PackageSHA256})
	if err != nil || again.Execution.ID != op.Execution.ID {
		t.Fatalf("replay: %+v %v", again, err)
	}
}
func TestInspectedInstallConcurrentRequestClaims(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Created"))}
	configureExternalPackageTestModule(h, stage)
	ctx := hostTestContext()
	inspection, err := h.InspectUploadedExternalPackage(ctx, InspectUploadedExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Package: strings.NewReader("package"), DeclaredSize: 7})
	if err != nil {
		t.Fatal(err)
	}
	request := StartInspectedInstallRequest{RequestID: "concurrent", InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256}
	var wg sync.WaitGroup
	results := make(chan InspectedInstallOperation, 12)
	failures := make(chan error, 12)
	for range 12 {
		wg.Go(func() {
			op, e := h.StartInspectedInstall(ctx, request)
			if e != nil {
				failures <- e
			} else {
				results <- op
			}
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Errorf("idempotent caller rejected: %v", e)
	}
	id := ""
	for op := range results {
		if id != "" && id != op.Execution.ID {
			t.Fatal("duplicate execution")
		}
		id = op.Execution.ID
	}
}

func TestInspectedInstallMissingHasPublicIdentity(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{})
	configureExternalPackageTestModule(h, &externalPackageTestStage{})
	if _, err := h.GetInspectedInstall(hostTestContext(), "never-started"); !errors.Is(err, ErrInspectedInstallNotFound) {
		t.Fatalf("missing operation: %v", err)
	}
}

func TestInspectedInstallProgressAndCommittedFailure(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "committed_cleanup_failure"}[failCleanup], func(t *testing.T) {
			h, _, _ := newTestHostWithOptions(t, testHostOptions{})
			stage := &externalPackageTestStage{pkg: readTestPackage(t, buildVersionedLifecyclePackage(t, "1.0.0", "Created"))}
			configureExternalPackageTestModule(h, stage)
			ctx := hostTestContext()
			inspection, err := h.InspectUploadedExternalPackage(ctx, InspectUploadedExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Package: strings.NewReader("package"), DeclaredSize: 7})
			if err != nil {
				t.Fatal(err)
			}
			if failCleanup {
				stage.setRemoveError(errors.New("cleanup unavailable"))
			}
			req := StartInspectedInstallRequest{RequestID: "progress", InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256}
			op, err := h.StartInspectedInstall(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			for end := time.Now().Add(3 * time.Second); op.Execution.Status == execution.StatusRunning; {
				if time.Now().After(end) {
					t.Fatal("install timed out")
				}
				time.Sleep(time.Millisecond)
				op, err = h.GetInspectedInstall(ctx, req.RequestID)
				if err != nil {
					t.Fatal(err)
				}
			}
			if op.MutationOutcome != mutation.OutcomeCommitted {
				t.Fatalf("lost commit: %+v", op)
			}
			want := execution.StatusCompleted
			if failCleanup {
				want = execution.StatusFailed
			}
			if op.Execution.Status != want {
				t.Fatalf("status: %+v", op)
			}
			events, err := h.EventsAfter(ctx, op.Execution.ID, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			var stages []string
			for _, event := range events {
				if event.Kind == execution.EventProgress {
					value := event.Payload["install_progress"].(map[string]any)
					stages = append(stages, value["stage"].(string)+":"+value["status"].(string))
				}
			}
			expected := "verify:running,verify:completed,install:running,install:completed,enable:running,enable:completed"
			if failCleanup {
				expected = strings.TrimSuffix(expected, "completed") + "failed"
			}
			if strings.Join(stages, ",") != expected {
				t.Fatalf("progress: %v", stages)
			}
			records, err := h.ListPlugins(ctx)
			if err != nil || len(records) != 1 {
				t.Fatalf("installation lost: %v %v", records, err)
			}
			again, err := h.StartInspectedInstall(ctx, req)
			if err != nil || again.Execution.ID != op.Execution.ID || again.Execution.Status != want {
				t.Fatalf("retry changed outcome: %+v %v", again, err)
			}
			stage.setRemoveError(nil)
		})
	}
}
