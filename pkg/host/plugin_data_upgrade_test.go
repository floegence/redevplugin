package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type upgradeRuntimeManager struct {
	*recordingRuntimeManager
	convert func(context.Context, runtimeclient.Lease) error
}

func TestPluginDataUpgradeRestoresSharedVersionGeneration(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprintf("schema_%d", schema), func(t *testing.T) {
			manager := &upgradeRuntimeManager{recordingRuntimeManager: newRecordingRuntimeManager()}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: manager})
			ctx := hostTestContext()
			first, err := ImportLocalPackageBytes(ctx, h, "shared-generation", buildWorkerStorageFixturePackage(t))
			if err != nil {
				t.Fatal(err)
			}
			write := func(value string) {
				t.Helper()
				if _, err := h.WritePluginDataFile(ctx, WritePluginDataFileRequest{PluginInstanceID: first.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt", Data: []byte(value)}); err != nil {
					t.Fatal(err)
				}
			}
			update := func(current registry.PluginRecord, pkg []byte) registry.PluginRecord {
				t.Helper()
				next, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision, PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg))})
				if err != nil {
					t.Fatal(err)
				}
				return next
			}
			write("shared original")
			second := update(first, buildDataUpgradePackage(t, first.Manifest, "1.1.0", 1, nil, func(m *manifest.Manifest) { m.DataUpgrade = nil }))
			thirdPackage := buildDataUpgradePackage(t, second.Manifest, "2.0.0", schema, nil)
			current := update(second, thirdPackage)
			write("converted generation")
			for _, step := range []struct{ version, want string }{{first.Version, "shared original"}, {second.Version, "shared original"}, {"2.0.0", "converted generation"}, {first.Version, "shared original"}} {
				current, err = h.DowngradePlugin(ctx, DowngradeRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision, Version: step.version})
				if err != nil {
					t.Fatalf("restore %s: %v", step.version, err)
				}
				content, err := h.ReadPluginDataFile(ctx, ReadPluginDataFileRequest{PluginInstanceID: current.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt"})
				if err != nil || string(content.Data) != step.want {
					t.Fatalf("restored %s content: %q, want %q: %v", step.version, content.Data, step.want, err)
				}
			}

			// Updating to a previously visited package creates a fresh converted
			// generation. A later downgrade must use its most recent visit.
			current, err = h.DowngradePlugin(ctx, DowngradeRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision, Version: second.Version})
			if err != nil {
				t.Fatal(err)
			}
			current = update(current, thirdPackage)
			for _, snapshot := range current.VersionHistory {
				if snapshot.PackageHash == current.PackageHash {
					t.Fatal("active package retained a stale historical data binding")
				}
			}
			write("latest visit")
			for _, version := range []string{first.Version, "2.0.0"} {
				current, err = h.DowngradePlugin(ctx, DowngradeRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision, Version: version})
				if err != nil {
					t.Fatal(err)
				}
			}
			content, err := h.ReadPluginDataFile(ctx, ReadPluginDataFileRequest{PluginInstanceID: current.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt"})
			if err != nil || string(content.Data) != "latest visit" {
				t.Fatalf("wrong revisited data: %q %v", content.Data, err)
			}
		})
	}
}

func TestPluginDataUpgradePreservesDisabledState(t *testing.T) {
	manager := &upgradeRuntimeManager{recordingRuntimeManager: newRecordingRuntimeManager()}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: manager})
	ctx := hostTestContext()
	old, err := ImportLocalPackageBytes(ctx, h, "disabled-upgrade", buildWorkerStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	old, err = h.DisablePlugin(ctx, DisableRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: old.ManagementRevision})
	if err != nil {
		t.Fatal(err)
	}
	pkg := buildDataUpgradePackage(t, old.Manifest, "2.0.0", 2, nil)
	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: old.ManagementRevision, PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg))})
	if err != nil {
		t.Fatal(err)
	}
	if updated.EnableState != registry.EnableDisabledByUser {
		t.Fatalf("upgrade enabled plugin: %s", updated.EnableState)
	}
}

func (r *upgradeRuntimeManager) InvokeWorker(ctx context.Context, binding runtimeclient.RuntimeBinding, lease runtimeclient.Lease, method string, payload []byte) ([]byte, error) {
	if method == "data.convert" && r.convert != nil {
		if err := r.convert(ctx, lease); err != nil {
			return nil, err
		}
	}
	return json.Marshal(capability.Result{Data: map[string]any{}})
}

func buildDataUpgradePackage(t *testing.T, previous manifest.Manifest, version string, schema int, wasm []byte, customize ...func(*manifest.Manifest)) []byte {
	t.Helper()
	m, err := manifest.Decode(bytes.NewBufferString(workerStorageFixtureManifestJSON()))
	if err != nil {
		t.Fatal(err)
	}
	oldShape, err := plugindata.ShapeFromManifest(previous)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := plugindata.HashShape(oldShape)
	if err != nil {
		t.Fatal(err)
	}
	m.Plugin.Version = version
	m.Storage.Stores[0].SchemaVersion = schema
	m.API.RequiredFeatures = append(m.API.RequiredFeatures, manifest.FeatureDataUpgrade)
	m.Workers = append(m.Workers, manifest.WorkerSpec{WorkerID: "converter", Artifact: "workers/convert.wasm", Mode: manifest.WorkerModeJob, Scope: "environment", MemoryLimitBytes: 16 << 20})
	m.Methods = append(m.Methods, manifest.MethodSpec{Method: "data.convert", Effect: manifest.MethodEffectWrite, Execution: manifest.MethodExecutionSync, Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "converter"}, RequestSchema: map[string]any{"type": "object", "properties": map[string]any{"from_version": map[string]any{"type": "string"}, "to_version": map[string]any{"type": "string"}, "scope": map[string]any{"type": "string"}}, "required": []any{"from_version", "to_version", "scope"}, "additionalProperties": false}, ResponseSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}})
	m.DataUpgrade = &manifest.DataUpgradeSpec{From: []manifest.DataUpgradePredecessor{{Version: previous.Version(), ShapeSHA256: hash}}, Method: "data.convert", MaxBytes: 8 << 20, MaxRuntimeMS: 10000}
	for _, apply := range customize {
		apply(&m)
	}
	raw, err := manifest.MarshalCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Upgrade")
	writeBytes(t, filepath.Join(dir, "workers/echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	if wasm == nil {
		wasm = currentWorkerWASMForTest("redevplugin_worker_invoke", []byte(`{"ok":true,"data":{}}`), nil)
	}
	writeBytes(t, filepath.Join(dir, "workers/convert.wasm"), wasm)
	var pkg bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &pkg, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return pkg.Bytes()
}

func TestPluginDataUpgradeThroughUpdatePreservesAtomicIdentity(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail_%v", fail), func(t *testing.T) {
			manager := &upgradeRuntimeManager{recordingRuntimeManager: newRecordingRuntimeManager()}
			opts := testHostOptions{developerMode: true, localGenerated: true, runtimeManager: manager, stateRoot: filepath.Join(t.TempDir(), "state")}
			h, _, _ := newTestHostWithOptions(t, opts)
			ctx := hostTestContext()
			old, err := ImportLocalPackageBytes(ctx, h, "upgrade", buildWorkerStorageFixturePackage(t))
			if err != nil {
				t.Fatal(err)
			}
			before, _, err := h.controlStore.GetBinding(ctx, old.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.WritePluginDataFile(ctx, WritePluginDataFileRequest{PluginInstanceID: old.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt", Data: []byte("original")}); err != nil {
				t.Fatal(err)
			}
			scopes := 0
			manager.convert = func(ctx context.Context, lease runtimeclient.Lease) error {
				scopes++
				// A fresh ordinary execution must not enter after the old leases have
				// been revoked while the predecessor remains the active catalog row.
				ordinary, admissionErr := h.executions.start(hostTestContext(), executionRegistryTestBinding("during-upgrade", old.PluginInstanceID, 0), func(context.Context) error { return nil })
				if ordinary != nil {
					ordinary.finish()
				}
				if !errors.Is(admissionErr, capability.ErrExecutionRevoked) {
					return fmt.Errorf("ordinary execution admitted during upgrade: %v", admissionErr)
				}
				active, err := h.getPluginRecord(ctx, old.PluginInstanceID)
				if err != nil || active.Version != old.Version {
					t.Fatalf("published before conversion: %s %v", active.Version, err)
				}
				binding, _, err := h.controlStore.GetBinding(ctx, old.PluginInstanceID)
				if err != nil || !plugindata.SameBinding(before, binding) {
					t.Fatalf("binding changed before commit: %+v %v", binding, err)
				}
				for _, operation := range []string{"storage.files", "network.http", "process.start", "secrets.get"} {
					raw, _ := json.Marshal(map[string]any{"plugin_api": 1, "operation": operation, "arguments": map[string]any{}})
					reply, err := h.runtimeIO.Control(ctx, lease.InvocationID, raw)
					if err != nil {
						return err
					}
					var result runtimeIOControlResponse
					if err := json.Unmarshal(reply, &result); err != nil || result.OK || result.Error.Code != "PERMISSION_DENIED" {
						t.Fatalf("external operation allowed: %s %s %v", operation, reply, err)
					}
				}
				if fail {
					return errors.New("conversion failed")
				}
				if dataUpgradeExecution(ctx).scope.Kind == sessionctx.ScopeUser {
					raw, _ := json.Marshal(map[string]any{"plugin_api": 1, "operation": "data.upgrade", "arguments": map[string]any{"dataset": "output", "kind": "files", "request": map[string]any{"operation": "write", "store_id": "workspace", "path": "note.txt", "data_base64": base64.StdEncoding.EncodeToString([]byte("converted"))}}})
					reply, err := h.runtimeIO.Control(ctx, lease.InvocationID, raw)
					var result runtimeIOControlResponse
					if err != nil {
						return err
					}
					if err := json.Unmarshal(reply, &result); err != nil || !result.OK {
						return fmt.Errorf("convert write: %s: %v", reply, err)
					}
				}
				return nil
			}
			pkg := buildDataUpgradePackage(t, old.Manifest, "2.0.0", 2, nil)
			updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: old.ManagementRevision, PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg)), Now: time.Now().UTC()})
			if fail {
				if err == nil || mutation.ForError(err) != mutation.OutcomeNotCommitted {
					t.Fatalf("failed conversion outcome: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			active, readErr := h.getPluginRecord(ctx, old.PluginInstanceID)
			if readErr != nil {
				t.Fatal(readErr)
			}
			after, _, readErr := h.controlStore.GetBinding(ctx, old.PluginInstanceID)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if fail {
				if scopes != 1 || active.Version != old.Version || !plugindata.SameBinding(before, after) {
					t.Fatalf("failure changed state: calls=%d record=%s binding=%+v", scopes, active.Version, after)
				}
			} else {
				if scopes != 2 || updated.Version != "2.0.0" || active.Version != updated.Version || before.GenerationID == after.GenerationID {
					t.Fatalf("missing atomic upgrade: calls=%d record=%s binding=%+v", scopes, active.Version, after)
				}
				history, err := h.controlStore.GetPluginDataHistory(ctx, old.PluginInstanceID, before.GenerationID)
				if err != nil || history.Record.PackageHash != old.PackageHash {
					t.Fatalf("lost history: %+v %v", history, err)
				}
			}
			content, err := h.ReadPluginDataFile(ctx, ReadPluginDataFileRequest{PluginInstanceID: old.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt"})
			want := "converted"
			if fail {
				want = "original"
			}
			if err != nil || string(content.Data) != want {
				t.Fatalf("lost data: %+v %v", content, err)
			}
			if !fail {
				method, _ := manifestMethod(active.Manifest, "data.convert")
				if _, err := h.dispatchMethod(ctx, active, method, CallMethodRequest{}); !errors.Is(err, ErrMethodRequestContract) {
					t.Fatalf("ordinary converter call: %v", err)
				}
				if err := h.Close(); err != nil {
					t.Fatal(err)
				}
				opts.assets = h.adapters.Assets
				opts.runtimeManager = newRecordingRuntimeManager()
				h, _, _ = newTestHostWithOptions(t, opts)
				for _, version := range []string{old.Version, updated.Version, old.Version} {
					active, err = h.DowngradePlugin(ctx, DowngradeRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: active.ManagementRevision, Version: version, Now: time.Now().UTC()})
					if err != nil {
						t.Fatalf("restore %s: %v", version, err)
					}
					want := "original"
					if version == updated.Version {
						want = "converted"
					}
					content, err := h.ReadPluginDataFile(ctx, ReadPluginDataFileRequest{PluginInstanceID: old.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt"})
					if err != nil || string(content.Data) != want {
						t.Fatalf("restored %s content: %q %v", version, content.Data, err)
					}
					refs, _, err := h.controlStore.ListAllBindingsForMaintenance(ctx, "", 10)
					if err != nil || len(refs) != 2 || refs[0].Binding.GenerationID == refs[1].Binding.GenerationID {
						t.Fatalf("active/history references: %+v %v", refs, err)
					}
				}
			}
		})
	}
}

func TestPluginDataUpgradeExternalInstallFlow(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			manager := &upgradeRuntimeManager{recordingRuntimeManager: newRecordingRuntimeManager()}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: manager})
			ctx := hostTestContext()
			stage := &externalPackageTestStage{pkg: readTestPackage(t, buildWorkerStorageFixturePackage(t))}
			configureExternalPackageTestModule(h, stage, registry.SignatureAssessment{})
			inspect, err := h.InspectExternalPackage(ctx, InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/upgrade-v1.redevplugin"}})
			if err != nil {
				t.Fatal(err)
			}
			installed, err := h.InstallInspectedPackage(ctx, InstallInspectedPackageRequest{InspectionID: inspect.InspectionID, ExpectedPackageSHA256: inspect.InspectedHashes.PackageSHA256})
			if err != nil {
				t.Fatal(err)
			}
			current := *installed.Plugin
			if disabled {
				current, err = h.DisablePlugin(ctx, DisableRequest{PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision})
				if err != nil {
					t.Fatal(err)
				}
			}
			before, _, err := h.controlStore.GetBinding(ctx, current.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			stage.setPackage(readTestPackage(t, buildDataUpgradePackage(t, current.Manifest, "2.0.0", 2, nil)))
			inspect, err = h.InspectExternalPackage(ctx, InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "update", PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision}, Source: ExternalPackageSource{Kind: "package_url", URL: "https://plugins.example.test/upgrade-v2.redevplugin"}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := h.InstallInspectedPackage(ctx, InstallInspectedPackageRequest{InspectionID: inspect.InspectionID, ExpectedPackageSHA256: inspect.InspectedHashes.PackageSHA256})
			if err != nil {
				t.Fatal(err)
			}
			after, _, err := h.controlStore.GetBinding(ctx, current.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if result.Plugin.Version != "2.0.0" || result.Plugin.EnableState != current.EnableState || before.GenerationID == after.GenerationID {
				t.Fatalf("external upgrade identity/state mismatch: %+v", result.Plugin)
			}
		})
	}
}

func TestPluginDataUpgradeCancellationAndTimeoutRestoreAdmission(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			manager := &upgradeRuntimeManager{recordingRuntimeManager: newRecordingRuntimeManager()}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: manager})
			ctx, cancel := context.WithCancel(hostTestContext())
			defer cancel()
			old, err := ImportLocalPackageBytes(ctx, h, "cancel-upgrade", buildWorkerStorageFixturePackage(t))
			if err != nil {
				t.Fatal(err)
			}
			before, _, err := h.controlStore.GetBinding(ctx, old.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			manager.convert = func(callCtx context.Context, _ runtimeclient.Lease) error {
				calls++
				if !timeout {
					cancel()
				}
				<-callCtx.Done()
				return callCtx.Err()
			}
			pkg := buildDataUpgradePackage(t, old.Manifest, "2.0.0", 2, nil, func(m *manifest.Manifest) {
				if timeout {
					m.DataUpgrade.MaxRuntimeMS = 200
				}
			})
			_, err = h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: old.ManagementRevision, PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg))})
			if err == nil || mutation.ForError(err) != mutation.OutcomeNotCommitted || calls != 1 {
				t.Fatalf("failed conversion outcome: calls=%d %v", calls, err)
			}
			after, _, err := h.controlStore.GetBinding(hostTestContext(), old.PluginInstanceID)
			if err != nil || !plugindata.SameBinding(before, after) {
				t.Fatalf("cancellation changed data: %+v %v", after, err)
			}
			active, err := h.getPluginRecord(hostTestContext(), old.PluginInstanceID)
			if err != nil || active.PackageHash != old.PackageHash {
				t.Fatalf("cancellation changed package: %v", err)
			}
			lease, err := h.executions.start(hostTestContext(), executionRegistryTestBinding("after-cancel", old.PluginInstanceID, 0), func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			lease.finish()
			manager.convert = nil
			if _, err := h.UpdateLocalPackage(hostTestContext(), UpdateLocalPackageRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: old.ManagementRevision, PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg))}); err != nil {
				t.Fatalf("explicit retry after known failure: %v", err)
			}
		})
	}
}

func TestPluginDataUpgradeRejectsSharedInvalidRequests(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(findRepoRootForHostTest(t), "spec/plugin/data-upgrade-fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Invalid []struct {
			Name    string
			Request json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	manager := &upgradeRuntimeManager{recordingRuntimeManager: newRecordingRuntimeManager()}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true, runtimeManager: manager})
	ctx := hostTestContext()
	old, err := ImportLocalPackageBytes(ctx, h, "invalid-wire", buildWorkerStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	manager.convert = func(ctx context.Context, lease runtimeclient.Lease) error {
		for _, fixture := range fixtures.Invalid {
			reply, err := h.runtimeIO.Control(ctx, lease.InvocationID, fixture.Request)
			if err != nil {
				return err
			}
			var result runtimeIOControlResponse
			if err := json.Unmarshal(reply, &result); err != nil {
				return err
			}
			if result.OK {
				return fmt.Errorf("invalid fixture accepted: %s", fixture.Name)
			}
		}
		return nil
	}
	pkg := buildDataUpgradePackage(t, old.Manifest, "2.0.0", 2, nil)
	if _, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: old.ManagementRevision, PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg))}); err != nil {
		t.Fatal(err)
	}
}
