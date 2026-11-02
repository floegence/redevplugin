package host

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestWebPrivateFileStreamRevokesWithoutBlockingSibling(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	var m map[string]any
	if err := json.Unmarshal([]byte(workerStorageKVFixtureManifestJSON()), &m); err != nil {
		t.Fatal(err)
	}
	m["workers"] = []any{}
	m["methods"] = []any{}
	m["api"].(map[string]any)["required_features"] = []string{"surface.resources.v1"}
	storage := m["storage"].(map[string]any)
	ns := storage["stores"].([]any)[0].(map[string]any)
	ns["kind"] = "files"
	ns["quota_bytes"] = 8 << 20
	surface := m["surfaces"].([]any)[0].(map[string]any)
	surface["surface_id"] = "lifecycle.view"
	surface["web"].(map[string]any)["storage"] = []any{map[string]any{"store_id": "cache", "operations": []string{"read", "write", "list"}}}
	raw, _ := json.Marshal(m)
	record := installAndEnablePlugin(t, h, buildCurrentLifecyclePackage(t, string(raw)))
	first, b := openTestWebSurface(t, h, record.PluginInstanceID, "surface_private_first", hostRuntimeWritableTestContext())
	second, _ := openTestWebSurface(t, h, record.PluginInstanceID, "surface_private_second", hostRuntimeWritableTestContext())
	request := WebPrivateFileRequest{WebSurfaceRequest: first, StoreID: "cache", Path: "file.bin"}
	data := bytes.Repeat([]byte("ab"), 1<<19)
	if n, err := h.TransferWebPrivateFile(context.Background(), request, bytes.NewReader(data), nil); err != nil || n != int64(len(data)) {
		t.Fatalf("write %d %v", n, err)
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	finished := make(chan error, 1)
	go func() {
		_, err := h.TransferWebPrivateFile(context.Background(), request, reader, nil)
		finished <- err
	}()
	if _, err := writer.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- h.DisposeSurface(hostTestContext(), DisposeSurfaceRequest{SurfaceInstanceID: b.SurfaceInstanceID, BridgeNonce: b.BridgeNonce, Now: first.Now})
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow upload blocked close")
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("revoked upload committed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upload did not cancel")
	}
	request.WebSurfaceRequest = second
	var output bytes.Buffer
	if _, err := h.TransferWebPrivateFile(context.Background(), request, nil, &output); err != nil || !bytes.Equal(output.Bytes(), data) {
		t.Fatalf("sibling data %v", err)
	}
	wrong := request
	wrong.Token = first.Token
	if _, err := h.TransferWebPrivateFile(context.Background(), wrong, nil, io.Discard); err == nil {
		t.Fatal("cross-window authority accepted")
	}
}
