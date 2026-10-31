package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/runtimeclient"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/storage"
)

func TestPluginDataUpgradeThroughBuiltRustRuntime(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found; skipping built Rust runtime integration")
	}
	repo := findRepoRootForHostTest(t)
	build := exec.Command("cargo", "build", "-p", "redevplugin-runtime")
	build.Dir = repo
	build.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build runtime: %v\n%s", err, output)
	}
	runtimePath := filepath.Join(repo, "target", "debug", "redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}
	for _, tc := range []struct {
		name, request string
		allowed       bool
	}{
		{"isolated settings", `{"plugin_api":1,"operation":"data.upgrade","arguments":{"dataset":"output","kind":"settings","request":{"operation":"write","values":{}}}}`, true},
		{"network", `{"plugin_api":1,"operation":"net.http.request","arguments":{}}`, false},
		{"process", `{"plugin_api":1,"operation":"process.start","arguments":{}}`, false},
		{"selected files", `{"plugin_api":1,"operation":"fs.open","arguments":{}}`, false},
		{"secrets", `{"plugin_api":1,"operation":"secrets.get","arguments":{}}`, false},
		{"ordinary storage", `{"plugin_api":1,"operation":"storage.files","arguments":{"operation":"read","store_id":"workspace","path":"note.txt"}}`, false},
		{"input write", `{"plugin_api":1,"operation":"data.upgrade","arguments":{"dataset":"input","kind":"settings","request":{"operation":"write","values":{}}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := hostTestContext()
			h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
			supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{Limits: runtimeclient.DefaultRuntimeLimits(), HandshakeTimeout: hostRuntimeProcessHandshakeTimeout, HeartbeatInterval: 2 * time.Second, MaxHeartbeatStaleness: 5 * time.Second, RuntimePath: runtimePath, ArtifactIdentity: hostRuntimeTestDescriptor(t, runtimePath), Diagnostics: h.adapters.Diagnostics, Artifacts: runtimeArtifactProvider{assets: h.adapters.Assets}, StreamSink: hostRuntimeStreamSink{executions: h.executions}, IOBroker: h.runtimeIO})
			if err != nil {
				t.Fatal(err)
			}
			h.adapters.RuntimeManager = testProcessManager{ProcessSupervisor: supervisor}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := supervisor.Stop(ctx); err != nil {
					t.Error(err)
				}
			})
			if err := supervisor.Start(ctx, hostRuntimeTestTarget(t)); err != nil {
				t.Fatal(err)
			}
			old, err := ImportLocalPackageBytes(ctx, h, "upgrade", buildWorkerStorageFixturePackage(t))
			if err != nil {
				t.Fatal(err)
			}
			wasm := importedMemoryHostcallWorkerWASMForTest("redevplugin.io", "rdp_call_v1", "control", "redevplugin_worker_invoke", []byte(tc.request))
			pkg := buildDataUpgradePackage(t, old.Manifest, "2.0.0", 2, wasm, func(m *manifest.Manifest) {
				// Every invocation, including user scopes, must produce the exact denial
				// or successful settings response. A swallowed hostcall error fails here.
				response := map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"const": tc.allowed}}, "required": []any{"ok"}, "additionalProperties": false}
				if !tc.allowed {
					response["properties"].(map[string]any)["error"] = map[string]any{"type": "object", "properties": map[string]any{"code": map[string]any{"const": "PERMISSION_DENIED"}, "message": map[string]any{"type": "string"}, "retryable": map[string]any{"const": false}, "details": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}}, "required": []any{"code", "message", "retryable", "details"}, "additionalProperties": false}
					response["required"] = []any{"ok", "error"}
				} else {
					response["properties"].(map[string]any)["result"] = map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"const": true}}, "required": []any{"ok"}, "additionalProperties": false}
					response["required"] = []any{"ok", "result"}
				}
				m.Methods[len(m.Methods)-1].ResponseSchema = map[string]any{"type": "object", "properties": map[string]any{"control": response}, "required": []any{"control"}, "additionalProperties": false}
			})
			updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: old.ManagementRevision, PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg)), Now: time.Now().UTC()})
			if err != nil {
				t.Fatal(err)
			}
			if updated.Version != "2.0.0" {
				t.Fatalf("version: %s", updated.Version)
			}
			settings, err := h.adapters.PluginData.GetSettings(ctx, old.PluginInstanceID, sessionctx.ScopeUser)
			if err != nil {
				t.Fatal(err)
			}
			if tc.allowed && len(settings.Values) != 0 {
				t.Fatalf("settings: %+v", settings)
			}
		})
	}
}

func TestPluginDataUpgradeThroughAuthorSDK(t *testing.T) {
	root := findRepoRootForHostTest(t)
	for _, args := range [][]string{{"build", "-p", "redevplugin-runtime"}, {"build", "-p", "redevplugin-data-upgrade-test-worker", "--target", "wasm32-unknown-unknown", "--release"}} {
		command := exec.Command("cargo", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
	}
	ctx := hostTestContext()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	runtimePath := filepath.Join(root, "target/debug/redevplugin-runtime")
	if runtime.GOOS == "windows" {
		runtimePath += ".exe"
	}
	supervisor, err := runtimeclient.NewProcessSupervisor(runtimeclient.ProcessSupervisorOptions{Limits: runtimeclient.DefaultRuntimeLimits(), HandshakeTimeout: hostRuntimeProcessHandshakeTimeout, HeartbeatInterval: 2 * time.Second, MaxHeartbeatStaleness: 5 * time.Second, RuntimePath: runtimePath, ArtifactIdentity: hostRuntimeTestDescriptor(t, runtimePath), Diagnostics: h.adapters.Diagnostics, Artifacts: runtimeArtifactProvider{assets: h.adapters.Assets}, StreamSink: hostRuntimeStreamSink{executions: h.executions}, IOBroker: h.runtimeIO})
	if err != nil {
		t.Fatal(err)
	}
	h.adapters.RuntimeManager = testProcessManager{ProcessSupervisor: supervisor}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := supervisor.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := supervisor.Start(ctx, hostRuntimeTestTarget(t)); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Decode(bytes.NewBufferString(workerStorageFixtureManifestJSON()))
	if err != nil {
		t.Fatal(err)
	}
	m.Storage.Stores = append(m.Storage.Stores, manifest.StoreSpec{StoreID: "cache", Kind: "kv", Scope: "user", QuotaBytes: 1 << 20, SchemaVersion: 1}, manifest.StoreSpec{StoreID: "records", Kind: "sqlite", Scope: "user", QuotaBytes: 1 << 20, SchemaVersion: 1})
	m.Settings = &manifest.SettingsSpec{SchemaVersion: 1, Fields: []manifest.SettingFieldSpec{{Key: "count", Type: "string", Label: "Count", Scope: "user", Default: "0"}}}
	raw, err := manifest.MarshalCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "manifest.json"), string(raw))
	writeSurfaceFixture(t, dir, "Upgrade SDK")
	writeBytes(t, filepath.Join(dir, "workers/echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var archive bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(ctx, dir, &archive, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	old, err := ImportLocalPackageBytes(ctx, h, "upgrade-sdk", archive.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	contexts := []context.Context{ctx}
	second, _ := sessionctx.Require(ctx)
	second.OwnerUserHash = "upgrade-second-user"
	contexts = append(contexts, sessionctx.WithContext(ctx, second))
	for index, userCtx := range contexts {
		session, _ := sessionctx.Require(userCtx)
		scope, _ := session.ResourceScope(sessionctx.ScopeUser)
		value := fmt.Sprintf("user-%d", index)
		if _, err := h.WritePluginDataFile(userCtx, WritePluginDataFileRequest{PluginInstanceID: old.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt", Data: []byte(value)}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.adapters.PluginData.PutKV(userCtx, storage.KVPutRequest{PluginInstanceID: old.PluginInstanceID, ResourceScope: scope, StoreID: "cache", Key: "message", Value: []byte(value)}); err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{"CREATE TABLE notes(value TEXT)", fmt.Sprintf("INSERT INTO notes(value) VALUES ('%s')", value)} {
			if _, err := h.adapters.PluginData.ExecSQLite(userCtx, storage.SQLiteExecRequest{PluginInstanceID: old.PluginInstanceID, ResourceScope: scope, StoreID: "records", SQL: sql}); err != nil {
				t.Fatal(err)
			}
		}
		settings, err := h.adapters.PluginData.GetSettings(userCtx, old.PluginInstanceID, sessionctx.ScopeUser)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.adapters.PluginData.PatchSettings(userCtx, plugindata.PatchSettingsRequest{PluginInstanceID: old.PluginInstanceID, Scope: sessionctx.ScopeUser, ExpectedValuesRevision: settings.Revision, Set: map[string]json.RawMessage{"count": json.RawMessage(fmt.Sprintf("\"%d\"", index+10))}}); err != nil {
			t.Fatal(err)
		}
	}
	wasm, err := os.ReadFile(filepath.Join(root, "target/wasm32-unknown-unknown/release/redevplugin_data_upgrade_test_worker.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := buildDataUpgradePackage(t, old.Manifest, "2.0.0", 2, wasm, func(next *manifest.Manifest) {
		next.Storage.Stores = append(next.Storage.Stores, m.Storage.Stores[1:]...)
		next.Settings = &manifest.SettingsSpec{SchemaVersion: 2, Fields: []manifest.SettingFieldSpec{{Key: "count", Type: "number", Label: "Count", Scope: "user", Default: 0}}}
	})
	updated, err := h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: old.ManagementRevision, PackageReader: bytes.NewReader(pkg), PackageSize: int64(len(pkg)), Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("SDK conversion: %+v", err)
	}
	for index, userCtx := range contexts {
		session, _ := sessionctx.Require(userCtx)
		scope, _ := session.ResourceScope(sessionctx.ScopeUser)
		want := fmt.Sprintf("user-%d", index)
		file, err := h.ReadPluginDataFile(userCtx, ReadPluginDataFileRequest{PluginInstanceID: old.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt"})
		if err != nil || string(file.Data) != want+" upgraded" {
			t.Fatalf("file: %q %v", file.Data, err)
		}
		kv, err := h.adapters.PluginData.GetKV(userCtx, storage.KVGetRequest{PluginInstanceID: old.PluginInstanceID, ResourceScope: scope, StoreID: "cache", Key: "converted"})
		if err != nil || string(kv.Value) != want {
			t.Fatalf("kv: %q %v", kv.Value, err)
		}
		rows, err := h.adapters.PluginData.QuerySQLite(userCtx, storage.SQLiteQueryRequest{PluginInstanceID: old.PluginInstanceID, ResourceScope: scope, StoreID: "records", SQL: "SELECT value FROM converted"})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0].Text == nil || *rows.Rows[0][0].Text != want {
			t.Fatalf("sqlite: %+v %v", rows, err)
		}
		settings, err := h.adapters.PluginData.GetSettings(userCtx, old.PluginInstanceID, sessionctx.ScopeUser)
		if err != nil || string(settings.Values["count"]) != fmt.Sprint(index+11) {
			t.Fatalf("settings: %+v %v", settings, err)
		}
	}
	if _, err := h.DowngradePlugin(ctx, DowngradeRequest{PluginInstanceID: old.PluginInstanceID, ExpectedManagementRevision: updated.ManagementRevision, Version: old.Version}); err != nil {
		t.Fatal(err)
	}
	for index, userCtx := range contexts {
		file, err := h.ReadPluginDataFile(userCtx, ReadPluginDataFileRequest{PluginInstanceID: old.PluginInstanceID, Scope: sessionctx.ScopeUser, StoreID: "workspace", Path: "note.txt"})
		if err != nil || string(file.Data) != fmt.Sprintf("user-%d", index) {
			t.Fatalf("retained source: %q %v", file.Data, err)
		}
	}
}
