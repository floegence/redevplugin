package runtimeclient

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRuntimeWireHasOneCanonicalContract(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate runtime wire test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "spec", "internal", "runtime-wire.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["internal_wire"] != float64(1) {
		t.Fatalf("internal_wire = %#v, want 1", schema["internal_wire"])
	}
	for _, retired := range []string{
		filepath.Join(root, "spec", "plugin", "ipc-v6.schema.json"),
		filepath.Join(root, "spec", "plugin", "ipc-v7.schema.json"),
		filepath.Join(root, "spec", "plugin", "ipc-v7-fixtures.json"),
	} {
		if _, err := os.Stat(retired); err == nil {
			t.Fatalf("retired wire contract still exists: %s", retired)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

func TestRuntimeFrameHeaderDoesNotCarryWireVersion(t *testing.T) {
	frame := IPCFrame{Type: IPCFrameHeartbeat, RequestID: 42, Metadata: []byte(`{"ok":true}`)}
	var encoded bytes.Buffer
	if err := WriteIPCFrame(&encoded, frame); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encoded.Bytes()[:4], []byte{0, 0, 0, 7}) || encoded.Bytes()[4] == 7 {
		t.Fatalf("frame header still carries wire version: %x", encoded.Bytes()[:8])
	}
	got, err := ReadIPCFrame(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != frame.Type || got.RequestID != frame.RequestID || !bytes.Equal(got.Metadata, frame.Metadata) {
		t.Fatalf("round trip = %#v, want %#v", got, frame)
	}
}

func TestInternalWireAppearsOnlyInHandshakeFrames(t *testing.T) {
	hello := ipcFrame{
		FrameType:           ipcFrameTypeHello,
		RequestID:           "hello:1",
		RuntimeGenerationID: "generation:1",
		Payload:             json.RawMessage(`{"internal_wire":1}`),
	}
	encoded, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"ipc_version"`)) {
		t.Fatalf("semantic frame still carries ipc_version: %s", encoded)
	}
	ordinary, err := json.Marshal(ipcFrame{FrameType: ipcFrameTypeHeartbeat, RequestID: "heartbeat:1"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ordinary, []byte(`"internal_wire"`)) || bytes.Contains(ordinary, []byte(`"ipc_version"`)) {
		t.Fatalf("ordinary frame carries wire identity: %s", ordinary)
	}
}
