package host

import (
	"context"
	"encoding/json"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"testing"
	"time"
)

func TestWebResourcesPrivateStorageAndWindowAuthority(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	var m map[string]any
	if err := json.Unmarshal([]byte(workerStorageKVFixtureManifestJSON()), &m); err != nil {
		t.Fatal(err)
	}
	m["workers"] = []any{}
	m["methods"] = []any{}
	m["api"].(map[string]any)["required_features"] = []string{"surface.resources.v1"}
	surface := m["surfaces"].([]any)[0].(map[string]any)
	surface["surface_id"] = "lifecycle.view"
	surface["web"].(map[string]any)["storage"] = []any{map[string]any{"store_id": "cache", "operations": []string{"get", "put", "list"}}}
	raw, _ := json.Marshal(m)
	record := installAndEnablePlugin(t, h, buildCurrentLifecyclePackage(t, string(raw)))
	first, b := openTestWebSurface(t, h, record.PluginInstanceID, "surface_data_first", hostRuntimeWritableTestContext())
	second, _ := openTestWebSurface(t, h, record.PluginInstanceID, "surface_data_second", hostRuntimeWritableTestContext())
	call := func(session WebSurfaceRequest, operation string, args string) (any, error) {
		return h.WebResource(context.Background(), WebResourceRequest{WebSurfaceRequest: session, Resource: "storage.kv", Arguments: json.RawMessage(args)})
	}
	result, err := call(first, "put", `{"operation":"put","store_id":"cache","key":"draft","value_base64":"aGVsbG8="}`)
	if err != nil {
		t.Fatalf("put: %+v %v", result, err)
	}
	result, err = call(second, "get", `{"operation":"get","store_id":"cache","key":"draft"}`)
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["value_base64"] != "aGVsbG8=" {
		t.Fatalf("unexpected data: %+v", result)
	}
	readOnly, _ := sessionctx.FromContext(hostRuntimeWritableTestContext())
	readOnly.CanWrite = false
	third, _ := openTestWebSurface(t, h, record.PluginInstanceID, "surface_data_readonly", sessionctx.WithContext(context.Background(), readOnly))
	if _, err := call(third, "put", `{"operation":"put","store_id":"cache","key":"draft","value_base64":"Yg=="}`); err == nil {
		t.Fatal("read-only Surface wrote data")
	}
	if _, err := call(first, "get", `{"operation":"get","store_id":"cache","key":"draft","max_bytes":65537}`); err == nil {
		t.Fatal("unbounded read accepted")
	}
	if _, err := call(first, "get", `{"operation":"get","store_id":"cache","key":"draft","plugin_instance_id":"other"}`); err == nil {
		t.Fatal("identity injection accepted")
	}
	watchArgs, _ := json.Marshal(map[string]any{"operation": "watch", "store_id": "cache", "key": "draft", "cursor": result.(map[string]any)["etag"]})
	watchDone := make(chan error, 1)
	go func() {
		_, err := h.WebResource(context.Background(), WebResourceRequest{WebSurfaceRequest: first, Resource: "storage.kv", Arguments: watchArgs})
		watchDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		h.webSurfaces.mu.Lock()
		watching := h.webSurfaces.byOrigin[first.Origin].resourceWatches > 0
		h.webSurfaces.mu.Unlock()
		if watching {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watch did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := call(first, "delete", `{"operation":"delete","store_id":"cache","key":"draft"}`); err == nil {
		t.Fatal("undeclared delete accepted")
	}
	wrong := first
	wrong.Token = second.Token
	if _, err := call(wrong, "get", `{"operation":"get","store_id":"cache","key":"draft"}`); err == nil {
		t.Fatal("sibling token accepted")
	}
	if err := h.DisposeSurface(hostTestContext(), DisposeSurfaceRequest{SurfaceInstanceID: b.SurfaceInstanceID, BridgeNonce: b.BridgeNonce, Now: first.Now}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-watchDone:
		if err == nil {
			t.Fatal("revoked watch succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("watch prevented revocation")
	}
	if _, err := call(first, "get", `{"operation":"get","store_id":"cache","key":"draft"}`); err == nil {
		t.Fatal("closed window accepted")
	}
	if _, err := call(second, "get", `{"operation":"get","store_id":"cache","key":"draft"}`); err != nil {
		t.Fatal(err)
	}
}

func TestWebResourcesSettingsUseRevisionAndSurfaceCeiling(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	var m map[string]any
	_ = json.Unmarshal([]byte(currentSettingsManifestJSON()), &m)
	m["api"].(map[string]any)["required_features"] = []string{"surface.resources.v1"}
	m["surfaces"].([]any)[0].(map[string]any)["web"].(map[string]any)["settings"] = []string{"get", "patch"}
	raw, _ := json.Marshal(m)
	record := installAndEnablePlugin(t, h, buildCurrentLifecyclePackage(t, string(raw)))
	req, _ := openTestWebSurface(t, h, record.PluginInstanceID, "surface_settings", hostRuntimeWritableTestContext())
	call := func(args string) (any, error) {
		return h.WebResource(context.Background(), WebResourceRequest{WebSurfaceRequest: req, Resource: "settings", Arguments: json.RawMessage(args)})
	}
	before, err := call(`{"operation":"get","scope":"user"}`)
	if err != nil {
		t.Fatal(err)
	}
	revision := before.(SettingsResult).ValuesRevision
	patch, _ := json.Marshal(map[string]any{"operation": "patch", "scope": "user", "expected_values_revision": revision, "set": map[string]any{"show_stopped": false}})
	after, err := call(string(patch))
	if err != nil || after.(SettingsResult).Values["show_stopped"] != false {
		t.Fatalf("patch: %v %v", after, err)
	}
	if _, err = call(string(patch)); err == nil {
		t.Fatal("stale settings write accepted")
	}
	watch, _ := json.Marshal(map[string]any{"operation": "watch", "scope": "user"})
	snapshot, err := call(string(watch))
	if err != nil || snapshot.(map[string]any)["changed"] != true {
		t.Fatalf("snapshot: %v %v", snapshot, err)
	}
}

func TestWebResourceConcurrencyReservationReleasesExactlyOnce(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	record := installAndEnablePlugin(t, h, buildFixturePackage(t))
	req, _ := openTestWebSurface(t, h, record.PluginInstanceID, "resource_budget", hostRuntimeWritableTestContext())
	h.webSurfaces.mu.Lock()
	lifetime := h.webSurfaces.byOrigin[req.Origin].ctx
	h.webSurfaces.mu.Unlock()
	releases := []func(){}
	for i := 0; i < 16; i++ {
		release, err := h.reserveWebResource(req, lifetime)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if _, err := h.reserveWebResource(req, lifetime); err == nil {
		t.Fatal("unbounded reservation")
	}
	releases[0]()
	releases[0]()
	replacement, err := h.reserveWebResource(req, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	for _, release := range releases {
		release()
	}
	replacement()
	h.webSurfaces.mu.Lock()
	defer h.webSurfaces.mu.Unlock()
	if h.webSurfaces.activeResources != 0 || h.webSurfaces.byOrigin[req.Origin].resourceWatches != 0 {
		t.Fatal("reservation leaked")
	}
}
