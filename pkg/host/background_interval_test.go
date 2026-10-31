package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

type intervalPolicyFunc func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error)

func (f intervalPolicyFunc) EvaluateBackgroundPolicy(ctx context.Context, req BackgroundPolicyRequest) (PolicyDecision, error) {
	return f(ctx, req)
}

func intervalFixture(t *testing.T) []byte { return intervalFixtureWith(t, nil) }

func intervalFixtureWith(t *testing.T, change func(map[string]any)) []byte {
	t.Helper()
	return buildBackgroundWorkerFixtureWith(t, func(raw string) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatal(err)
		}
		doc["api"].(map[string]any)["required_features"] = []string{"background.method.v1", "background.interval.v1"}
		entry := doc["background"].(map[string]any)
		entry["strategy"] = "interval"
		entry["method"] = "worker.echo"
		entry["interval_ms"] = 60000
		entry["max_runtime_ms"] = 10000
		entry["params"] = map[string]any{"message": "scheduled"}
		if change != nil {
			change(doc)
		}
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	})
}

func claimTestInterval(t *testing.T, h *Host, record registry.PluginRecord) controlstore.IntervalPlan {
	t.Helper()
	ctx := context.Background()
	if err := h.controlStore.ReconcileIntervals(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	plans, err := h.controlStore.IntervalPlans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range plans {
		if plan.PluginInstanceID == record.PluginInstanceID && plan.OwnerEnvHash == record.OwnerEnvHash {
			claim, ok, err := h.controlStore.ClaimInterval(ctx, plan, plan.NextRun)
			if err != nil || !ok {
				t.Fatalf("claim=%v %v", ok, err)
			}
			return claim
		}
	}
	t.Fatal("interval plan missing")
	return controlstore.IntervalPlan{}
}

func TestIntervalUsesBackgroundPolicyWithoutUserSession(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "allowed"}[allow], func(t *testing.T) {
			runtime := newRecordingRuntimeManager()
			runtime.result = capability.Result{Data: map[string]any{}}
			var calls atomic.Int32
			policy := intervalPolicyFunc(func(ctx context.Context, req BackgroundPolicyRequest) (PolicyDecision, error) {
				calls.Add(1)
				if req.OwnerEnvHash == "" || req.Plugin.PluginInstanceID == "" || req.Method != "worker.echo" || req.Effect != "read" || req.ManagementRevision == 0 {
					t.Errorf("incomplete policy binding: %+v", req)
				}
				if allow {
					return PolicyAllow, nil
				}
				return PolicyDeny, nil
			})
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
			record := installAndEnablePlugin(t, h, intervalFixture(t))
			claim := claimTestInterval(t, h, record)
			outcome, runErr := h.runBackgroundInterval(context.Background(), claim)
			want := "blocked"
			if allow {
				want = "success"
			}
			if outcome != want {
				t.Fatalf("outcome=%s want %s: %v", outcome, want, runErr)
			}
			if calls.Load() == 0 {
				t.Fatal("background policy not evaluated")
			}
			count := 0
			if allow {
				count = 1
			}
			if runtime.calls != count {
				t.Fatalf("runtime calls=%d want %d", runtime.calls, count)
			}
			if _, err := h.controlStore.FinishInterval(context.Background(), claim, time.Now(), outcome); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntervalNilPolicyDeniesAndRunnerCannotBypassClaim(t *testing.T) {
	runtime := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner})
	record := installAndEnablePlugin(t, h, intervalFixture(t))
	claim := claimTestInterval(t, h, record)
	if outcome, runErr := h.runBackgroundInterval(context.Background(), claim); outcome != "blocked" {
		t.Fatal(outcome, runErr)
	}
	runner, err := NewBackgroundWorkerRunner(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Start(context.Background(), backgroundOwner(record), "echo_worker"); err == nil {
		t.Fatal("unclaimed interval started")
	}
	if runtime.calls != 0 {
		t.Fatal("policy bypass")
	}
}

func TestIntervalRejectsChangedRevisionBeforeDispatch(t *testing.T) {
	runtime := newRecordingRuntimeManager()
	policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
	record := installAndEnablePlugin(t, h, intervalFixture(t))
	claim := claimTestInterval(t, h, record)
	claim.RevokeEpoch++
	if outcome, runErr := h.runBackgroundInterval(context.Background(), claim); outcome != "blocked" {
		t.Fatal(outcome, runErr)
	}
	if runtime.calls != 0 {
		t.Fatal("stale claim dispatched")
	}
}

func TestIntervalLifecycleCancelsClaimedWorkAndKeepsSibling(t *testing.T) {
	for _, action := range []string{"disable", "revoke", "uninstall", "update"} {
		t.Run(action, func(t *testing.T) {
			runtime := &intervalBlockingRuntime{recordingRuntimeManager: newRecordingRuntimeManager(), entered: make(chan string, 4), canceled: make(chan string, 4), counts: map[string]int{}}
			policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
			fixture := intervalFixture(t)
			if action == "revoke" {
				fixture = intervalFixtureWith(t, func(doc map[string]any) { doc["permissions"] = []string{"network.client"} })
			}
			record := installAndEnablePlugin(t, h, fixture)
			if action == "revoke" {
				grantDeclaredPermissions(t, h, record)
				record, _ = h.getPluginRecord(hostTestContext(), record.PluginInstanceID)
			}
			sibling := installAndEnablePlugin(t, h, intervalFixture(t))
			if err := h.controlStore.ReconcileIntervals(context.Background(), time.Now()); err != nil {
				t.Fatal(err)
			}
			plans, err := h.controlStore.IntervalPlans(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var due time.Time
			for _, plan := range plans {
				if plan.NextRun.After(due) {
					due = plan.NextRun
				}
			}
			if err := h.backgroundIntervals.tick(context.Background(), due); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				select {
				case <-runtime.entered:
				case <-time.After(3 * time.Second):
					t.Fatal("both intervals did not dispatch")
				}
			}
			// A second maintenance pass must not claim the still-running period.
			if err := h.backgroundIntervals.tick(context.Background(), due); err != nil {
				t.Fatal(err)
			}
			switch action {
			case "disable":
				_, err = h.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
			case "revoke":
				_, err = h.RevokePermission(hostTestContext(), RevokePermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: record.PolicyRevision, ExpectedManagementRevision: record.ManagementRevision, ExpectedRevokeEpoch: record.RevokeEpoch})
			case "uninstall":
				_, err = h.UninstallPlugin(hostTestContext(), UninstallRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
			case "update":
				next := intervalFixtureWith(t, func(doc map[string]any) { doc["plugin"].(map[string]any)["version"] = "1.1.0" })
				_, err = h.UpdateLocalPackage(hostTestContext(), UpdateLocalPackageRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, PackageReader: bytes.NewReader(next), PackageSize: int64(len(next))})
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case instance := <-runtime.canceled:
				if instance != record.PluginInstanceID {
					t.Fatal("sibling canceled")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("lifecycle did not cancel interval")
			}
			current, err := h.getPluginRecord(hostTestContext(), sibling.PluginInstanceID)
			if err != nil || current.EnableState != registry.EnableEnabled || current.ManagementRevision != sibling.ManagementRevision {
				t.Fatalf("sibling changed: %+v %v", current, err)
			}
			runtime.mu.Lock()
			if runtime.counts[record.PluginInstanceID] != 1 || runtime.counts[sibling.PluginInstanceID] != 1 {
				t.Errorf("duplicate claims: %v", runtime.counts)
			}
			runtime.mu.Unlock()
			select {
			case instance := <-runtime.canceled:
				t.Fatalf("unexpected sibling cancellation: %s", instance)
			default:
			}
		})
	}
}

type intervalBlockingRuntime struct {
	*recordingRuntimeManager
	mu                sync.Mutex
	entered, canceled chan string
	counts            map[string]int
}

func (r *intervalBlockingRuntime) Health(context.Context) (runtimeclient.ManagerHealth, error) {
	return r.managerHealth(), nil
}
func (r *intervalBlockingRuntime) PrewarmWorker(context.Context, runtimeclient.PrewarmWorkerRequest) error {
	return nil
}
func (r *intervalBlockingRuntime) InvokeWorker(ctx context.Context, _ runtimeclient.RuntimeBinding, lease runtimeclient.Lease, _ string, _ []byte) ([]byte, error) {
	r.mu.Lock()
	r.counts[lease.PluginInstanceID]++
	r.mu.Unlock()
	r.entered <- lease.PluginInstanceID
	<-ctx.Done()
	r.canceled <- lease.PluginInstanceID
	return nil, ctx.Err()
}

func TestIntervalHostRestartPreservesNextRunAndMarksClaimUnknown(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "host")
	assets := pluginpkg.NewMemoryAssetStore()
	policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
	options := testHostOptions{developerMode: true, localGenerated: true, stateRoot: stateRoot, assets: assets, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy}
	h, _, _ := newTestHostWithOptions(t, options)
	record := installAndEnablePlugin(t, h, intervalFixture(t))
	claim := claimTestInterval(t, h, record)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	options.openContext = context.Background()
	restarted, _, _ := newTestHostWithOptions(t, options)
	plans, err := restarted.controlStore.IntervalPlans(context.Background())
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans=%+v %v", plans, err)
	}
	if plans[0].ClaimID != "" || plans[0].Outcome != "unknown" || !plans[0].NextRun.After(time.Now()) {
		t.Fatalf("recovery=%+v", plans[0])
	}
	if outcome, _ := restarted.runBackgroundInterval(context.Background(), claim); outcome != "blocked" {
		t.Fatalf("old claim replayed: %s", outcome)
	}
	next := plans[0].NextRun
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	again, _, _ := newTestHostWithOptions(t, options)
	plans, err = again.controlStore.IntervalPlans(context.Background())
	if err != nil || len(plans) != 1 || !plans[0].NextRun.Equal(next) {
		t.Fatalf("next run reset: %+v %v", plans, err)
	}
}

func TestIntervalCancellationBeforeDispatchHasKnownOutcome(t *testing.T) {
	runtime := newRecordingRuntimeManager()
	policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
	record := installAndEnablePlugin(t, h, intervalFixture(t))
	claim := claimTestInterval(t, h, record)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, err := h.runBackgroundInterval(ctx, claim)
	if outcome != "canceled" || !errors.Is(err, context.Canceled) || runtime.calls != 0 {
		t.Fatalf("outcome=%s err=%v calls=%d", outcome, err, runtime.calls)
	}
}

func TestIntervalTimeoutAfterDispatchIsUnknown(t *testing.T) {
	runtime := &intervalBlockingRuntime{recordingRuntimeManager: newRecordingRuntimeManager(), entered: make(chan string, 4), canceled: make(chan string, 4), counts: map[string]int{}}
	policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
	record := installAndEnablePlugin(t, h, intervalFixture(t))
	claim := claimTestInterval(t, h, record)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outcome, err := h.runBackgroundInterval(ctx, claim)
	if outcome != "unknown" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("outcome=%s err=%v", outcome, err)
	}
	select {
	case <-runtime.entered:
	default:
		t.Fatal("no dispatch")
	}
	if ok, err := h.controlStore.FinishInterval(context.Background(), claim, time.Now(), outcome); err != nil || !ok {
		t.Fatal(err)
	}
	if outcome, _ := h.runBackgroundInterval(context.Background(), claim); outcome != "blocked" {
		t.Fatal("unknown invocation replayed")
	}
}

func TestIntervalLifecycleInvalidatesOldClaim(t *testing.T) {
	for _, action := range []string{"revoke", "uninstall", "update"} {
		t.Run(action, func(t *testing.T) {
			runtime := newRecordingRuntimeManager()
			runtime.result = capability.Result{Data: map[string]any{}}
			policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
			fixture := intervalFixture(t)
			if action == "revoke" {
				fixture = intervalFixtureWith(t, func(doc map[string]any) { doc["permissions"] = []string{"network.client"} })
			}
			record := installAndEnablePlugin(t, h, fixture)
			if action == "revoke" {
				grantDeclaredPermissions(t, h, record)
				record, _ = h.getPluginRecord(hostTestContext(), record.PluginInstanceID)
			}
			claim := claimTestInterval(t, h, record)
			switch action {
			case "revoke":
				// Every permission revocation advances the package's execution fence.
				_, err := h.RevokePermission(hostTestContext(), RevokePermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "network.client", ExpectedPolicyRevision: record.PolicyRevision, ExpectedManagementRevision: record.ManagementRevision, ExpectedRevokeEpoch: record.RevokeEpoch})
				if err != nil {
					t.Fatal(err)
				}
			case "uninstall":
				_, err := h.UninstallPlugin(hostTestContext(), UninstallRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
				if err != nil {
					t.Fatal(err)
				}
			case "update":
				next := intervalFixtureWith(t, func(doc map[string]any) { doc["plugin"].(map[string]any)["version"] = "1.1.0" })
				_, err := h.UpdateLocalPackage(hostTestContext(), UpdateLocalPackageRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision, PackageReader: bytes.NewReader(next), PackageSize: int64(len(next))})
				if err != nil {
					t.Fatal(err)
				}
			}
			if outcome, _ := h.runBackgroundInterval(context.Background(), claim); outcome != "blocked" {
				t.Fatalf("old invocation survived %s: %s", action, outcome)
			}
			if err := h.controlStore.ReconcileIntervals(context.Background(), time.Now()); err != nil {
				t.Fatal(err)
			}
			if ok, err := h.controlStore.FinishInterval(context.Background(), claim, time.Now(), "success"); err != nil || ok {
				t.Fatalf("old completion survived %s: %v %v", action, ok, err)
			}
			plans, err := h.controlStore.IntervalPlans(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if action == "uninstall" {
				if len(plans) != 0 {
					t.Fatal("uninstalled schedule retained")
				}
			} else {
				if len(plans) != 1 || plans[0].RevokeEpoch == claim.RevokeEpoch {
					t.Fatalf("new plan=%+v", plans)
				}
				next, ok, err := h.controlStore.ClaimInterval(context.Background(), plans[0], plans[0].NextRun)
				if err != nil || !ok {
					t.Fatal(err)
				}
				outcome, _ := h.runBackgroundInterval(context.Background(), next)
				want := "success"
				if action == "revoke" {
					want = "blocked"
				}
				if outcome != want {
					t.Fatalf("new %s outcome=%s want=%s", action, outcome, want)
				}
			}
		})
	}
}

func TestIntervalInventoryTracksDurableState(t *testing.T) {
	policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
	record := installAndEnablePlugin(t, h, intervalFixture(t))
	claim := claimTestInterval(t, h, record)
	inventory, err := h.ListPluginInventory(hostTestContext())
	if err != nil || len(inventory) != 1 {
		t.Fatal(inventory, err)
	}
	status := inventory[0].BackgroundInterval
	if status == nil || status.State != "running" || status.LastStartedAt == nil {
		t.Fatalf("running status=%+v", status)
	}
	if _, err := h.controlStore.FinishInterval(context.Background(), claim, time.Now(), "unknown"); err != nil {
		t.Fatal(err)
	}
	inventory, err = h.ListPluginInventory(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	status = inventory[0].BackgroundInterval
	if status.State != "scheduled" || status.LastOutcome != "unknown" || status.NextRunAt == nil || status.LastFinishedAt == nil {
		t.Fatalf("unknown status=%+v", status)
	}
	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	inventory, err = h.ListPluginInventory(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	status = inventory[0].BackgroundInterval
	if status.State != "stopped" || status.NextRunAt != nil {
		t.Fatalf("disabled status=%+v", status)
	}
}

func TestIntervalHostStartsWithoutSurfaceOrOnlineSession(t *testing.T) {
	runtime := &intervalBlockingRuntime{recordingRuntimeManager: newRecordingRuntimeManager(), entered: make(chan string, 4), canceled: make(chan string, 4), counts: map[string]int{}}
	policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, openContext: context.Background(), runtimeManager: runtime, backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy})
	record := installAndEnablePlugin(t, h, intervalFixtureWith(t, func(doc map[string]any) {
		entry := doc["background"].(map[string]any)
		entry["interval_ms"] = 1000
		entry["max_runtime_ms"] = 1000
	}))
	// No explicit tick, claim, surface or user session drives this invocation.
	select {
	case instance := <-runtime.entered:
		if instance != record.PluginInstanceID {
			t.Fatal(instance)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("automatic scheduler did not start")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.canceled:
	default:
		t.Fatal("Host close did not cancel work")
	}
}
