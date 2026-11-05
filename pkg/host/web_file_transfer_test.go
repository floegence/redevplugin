package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
)

type failedTransferReader struct{ sent bool }

func (r *failedTransferReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, io.ErrUnexpectedEOF
	}
	r.sent = true
	return copy(p, "partial"), nil
}

func TestWebSelectedFileBinaryTransferAndPartialOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selected.bin")
	payload := bytes.Repeat([]byte("abc"), 50000)
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{filePicker: selectedPickerFixture{path: path}})
	var m map[string]any
	_ = json.Unmarshal([]byte(fixtureManifestJSON()), &m)
	m["permissions"] = append(m["permissions"].([]any), "fs.selected.read", "fs.selected.write")
	m["api"].(map[string]any)["required_features"] = []string{"surface.resources.v1", "fs.selected.v1"}
	raw, _ := json.Marshal(m)
	record := installAndEnablePlugin(t, h, buildCurrentLifecyclePackage(t, string(raw)))
	ctx := hostRuntimeWritableTestContext()
	web, b, token := openTestWebSurfaceGateway(t, h, record.PluginInstanceID, "surface_binary", ctx)
	sibling, _ := openTestWebSurface(t, h, record.PluginInstanceID, "surface_binary_sibling", ctx)
	surface := SurfaceFileRequest{PluginInstanceID: record.PluginInstanceID, SurfaceInstanceID: b.SurfaceInstanceID, BridgeChannelID: "bridge_" + b.SurfaceInstanceID, GatewayToken: token, Operation: "select", Arguments: json.RawMessage(`{"kind":"file","writable":true}`)}
	choice, err := h.SurfaceFile(ctx, surface)
	if err != nil || choice.Review == nil {
		t.Fatalf("select %v %+v", err, choice)
	}
	grant, err := h.ApproveFileResource(ctx, ApproveFileResourceRequest{PluginInstanceID: record.PluginInstanceID, ReviewID: choice.Review.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	surface.Operation = "fs.open"
	surface.Arguments = json.RawMessage(`{"uri":` + strconv.Quote(grant.URI) + `,"options":{"read":true,"write":true}}`)
	handle, err := h.SurfaceFile(ctx, surface)
	if err != nil {
		t.Fatal(err)
	}
	request := WebFileTransferRequest{WebSurfaceRequest: web, Handle: handle.Handle}
	var output bytes.Buffer
	if n, err := h.TransferWebFile(context.Background(), request, nil, &output); err != nil || n != int64(len(payload)) || !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("read %d %v", n, err)
	}
	bad := request
	bad.WebSurfaceRequest = sibling
	if _, err := h.TransferWebFile(context.Background(), bad, nil, io.Discard); err == nil {
		t.Fatal("sibling reused handle")
	}
	// Open another handle to start at zero without changing transfer semantics.
	surface.Operation = "fs.open"
	surface.Arguments = json.RawMessage(`{"uri":` + strconv.Quote(grant.URI) + `,"options":{"write":true}}`)
	handle, err = h.SurfaceFile(ctx, surface)
	if err != nil {
		t.Fatal(err)
	}
	request.Handle = handle.Handle
	if n, err := h.TransferWebFile(context.Background(), request, &failedTransferReader{}, nil); n != 7 || !errors.Is(err, io.ErrUnexpectedEOF) || mutation.ForError(err) != mutation.OutcomeUnknown {
		t.Fatalf("partial %d %v", n, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content[:7]) != "partial" {
		t.Fatal("partial outcome did not match persisted bytes", err)
	}
}
