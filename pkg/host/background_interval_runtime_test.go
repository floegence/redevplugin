package host

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

func TestIntervalThroughBuiltRustRuntime(t *testing.T) {
	root := findRepoRootForHostTest(t)
	for _, args := range [][]string{{"build", "-p", "redevplugin-runtime"}, {"build", "-p", "redevplugin-interval-test-worker", "--target", "wasm32-unknown-unknown", "--release"}} {
		command := exec.Command("cargo", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
	}
	runtimePath := filepath.Join(root, "target/debug/redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}
	wasm, err := os.ReadFile(filepath.Join(root, "target/wasm32-unknown-unknown/release/redevplugin_interval_test_worker.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(t.TempDir(), "state")
	assetsPath := filepath.Join(t.TempDir(), "assets")
	policy := intervalPolicyFunc(func(context.Context, BackgroundPolicyRequest) (PolicyDecision, error) { return PolicyAllow, nil })
	var lastPlanTime time.Time
	for round := range 2 {
		assets, err := pluginpkg.NewFileAssetStore(assetsPath)
		if err != nil {
			t.Fatal(err)
		}
		h, _, _ := newTestHostWithOptions(t, testHostOptions{
			developerMode: true, localGenerated: true, stateRoot: stateRoot, assets: assets,
			openContext: context.Background(), backgroundRunnerFactory: NewBackgroundWorkerRunner, backgroundPolicy: policy,
			runtimeManagerFactory: func(deps testRuntimeManagerDependencies) (runtimeclient.Manager, error) {
				return runtimeclient.NewProcessManager(runtimeclient.ProcessManagerOptions{
					ShardCount: 1,
					Supervisor: runtimeclient.ProcessSupervisorOptions{
						Limits: runtimeclient.DefaultRuntimeLimits(), HandshakeTimeout: hostRuntimeProcessHandshakeTimeout,
						HeartbeatInterval: 2 * time.Second, MaxHeartbeatStaleness: 5 * time.Second,
						RuntimePath: runtimePath, ArtifactIdentity: hostRuntimeTestDescriptor(t, runtimePath),
						Diagnostics: deps.Diagnostics, Artifacts: runtimeArtifactProvider{assets: deps.Assets},
					},
				})
			},
		})
		scheduler := h.backgroundIntervals
		var records []registry.PluginRecord
		if round == 0 {
			for _, instance := range []string{"interval-first", "interval-sibling"} {
				bytes := buildIntervalCounterPackage(t, wasm)
				record, err := ImportLocalPackageBytes(hostTestContext(), h, instance, bytes)
				if err != nil {
					t.Fatal(err)
				}
				record, err = h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: record.PluginInstanceID, ExpectedManagementRevision: record.ManagementRevision})
				if err != nil {
					t.Fatal(err)
				}
				records = append(records, record)
			}
		} else {
			records, err = h.listPluginRecords(hostTestContext())
			if err != nil {
				t.Fatal(err)
			}
			plans, err := h.controlStore.IntervalPlans(context.Background())
			if err != nil || len(plans) != 2 {
				t.Fatalf("restart plans=%v %v", plans, err)
			}
			for _, plan := range plans {
				if plan.PluginInstanceID == "interval-first" && !plan.NextRun.Equal(lastPlanTime) {
					t.Fatal("restart reset completed plan")
				}
			}
		}
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
		if err := scheduler.tick(h.lifecycleCtx, due); err != nil {
			t.Fatal(err)
		}
		waitIntervalRuntimeCompletion(t, h, 2)
		for _, record := range records {
			if got := intervalCounter(t, h, record.PluginInstanceID); got != int64(round+1) {
				t.Fatalf("%s count=%d round=%d", record.PluginInstanceID, got, round)
			}
		}
		plans, err = h.controlStore.IntervalPlans(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, plan := range plans {
			if plan.PluginInstanceID == "interval-first" {
				lastPlanTime = plan.NextRun
			}
		}
		if round == 1 {
			first, err := h.getPluginRecord(hostTestContext(), "interval-first")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{PluginInstanceID: first.PluginInstanceID, ExpectedManagementRevision: first.ManagementRevision}); err != nil {
				t.Fatal(err)
			}
			if err := scheduler.tick(h.lifecycleCtx, due.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			waitIntervalRuntimeCompletion(t, h, 1)
			if intervalCounter(t, h, "interval-first") != 2 || intervalCounter(t, h, "interval-sibling") != 3 {
				t.Fatal("disable crossed instance boundary or replayed work")
			}
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func buildIntervalCounterPackage(t *testing.T, wasm []byte) []byte {
	t.Helper()
	m, err := manifest.Decode(bytes.NewBufferString(workerStorageFixtureManifestJSON()))
	if err != nil {
		t.Fatal(err)
	}
	m.API.RequiredFeatures = []manifest.FeatureID{manifest.FeatureBackgroundMethod, manifest.FeatureBackgroundInterval}
	m.Workers[0].Scope = "environment"
	m.Background = &manifest.BackgroundSpec{Strategy: manifest.BackgroundInterval, WorkerID: "echo_worker", Method: "worker.echo", IntervalMS: 60000, MaxRuntimeMS: 10000, Params: map[string]any{}}
	m.Storage.Stores = []manifest.StoreSpec{{StoreID: "counter", Kind: "sqlite", Scope: "environment", QuotaBytes: 1 << 20, SchemaVersion: 1}}
	m.Methods[0].BrokerAccess.Storage = []manifest.StorageBrokerAccessSpec{{StoreID: "counter", Operations: []string{"query", "exec"}}}
	raw, err := manifest.MarshalCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Interval Counter")
	writeBytes(t, filepath.Join(dir, "workers/echo.wasm"), wasm)
	var archive bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &archive, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func intervalCounter(t *testing.T, h *Host, instance string) int64 {
	t.Helper()
	session, err := sessionctx.Require(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := session.ResourceScope(sessionctx.ScopeEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.adapters.PluginData.QuerySQLite(hostTestContext(), storage.SQLiteQueryRequest{PluginInstanceID: instance, ResourceScope: scope, StoreID: "counter", SQL: "SELECT count FROM ticks WHERE id=1"})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0].Int == nil {
		t.Fatalf("count query=%+v %v", result, err)
	}
	return *result.Rows[0][0].Int
}

func waitIntervalRuntimeCompletion(t *testing.T, h *Host, count int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		plans, err := h.controlStore.IntervalPlans(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		complete := len(plans) == count
		for _, plan := range plans {
			complete = complete && plan.ClaimID == "" && plan.Outcome == "success"
		}
		if complete {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	plans, _ := h.controlStore.IntervalPlans(context.Background())
	if sink, ok := h.adapters.Diagnostics.(*observability.MemoryStore); ok {
		for _, plan := range plans {
			session := backgroundSessionContext(backgroundOwner(registry.PluginRecord{PluginInstanceID: plan.PluginInstanceID, OwnerEnvHash: plan.OwnerEnvHash}))
			events, _ := sink.ListPluginDiagnostics(context.Background(), observability.ListDiagnosticRequest{OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash, PluginInstanceID: plan.PluginInstanceID})
			t.Logf("diagnostics: %+v", events)
		}
	}
	t.Fatalf("interval did not finish: %+v", plans)
}
