package runtimeclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

type ipcV7BufferCloser struct {
	bytes.Buffer
}

func (*ipcV7BufferCloser) Close() error { return nil }

func TestSemanticIPCWriterUsesV7Framing(t *testing.T) {
	output := &ipcV7BufferCloser{}
	writer := newSemanticIPCWriteCloserV7(output)
	want := ipcFrame{
		IPCVersion:          "redevplugin.rust_ipc.v7",
		FrameType:           ipcFrameTypeHello,
		RequestID:           "runtime_gen:hello:1",
		RuntimeGenerationID: "runtime_gen",
		Payload:             json.RawMessage(`{"channel_nonce":"nonce"}`),
	}
	if err := json.NewEncoder(writer).Encode(want); err != nil {
		t.Fatal(err)
	}
	framed, err := ReadIPCFrameV7(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if framed.Type != IPCFrameHello || framed.RequestID != semanticIPCRequestID(want.RequestID) || len(framed.Body) != 0 {
		t.Fatalf("framed identity = %#v", framed)
	}
	var got ipcFrame
	if err := decodeStrictJSON(framed.Metadata, &got); err != nil {
		t.Fatal(err)
	}
	if got.RequestID != want.RequestID || got.FrameType != want.FrameType {
		t.Fatalf("semantic frame = %#v, want %#v", got, want)
	}
}

func TestSemanticIPCV7PreservesLargeLegacyHostcallResponse(t *testing.T) {
	output := &ipcV7BufferCloser{}
	writer := newSemanticIPCWriteCloserV7(output)
	payload, err := json.Marshal(map[string]any{"ok": true, "data_base64": string(bytes.Repeat([]byte("A"), 512<<10))})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(writer).Encode(ipcFrame{
		IPCVersion: "redevplugin.rust_ipc.v7", FrameType: ipcFrameTypeStorageFile,
		RequestID: "hostcall:large", ParentRequestID: "invoke:1", RuntimeGenerationID: "runtime_gen", Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(output.Bytes())
	framed, err := ReadIPCFrameV7(reader)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := readSemanticIPCBytesV7(reader, framed)
	if err != nil {
		t.Fatal(err)
	}
	if framed.Type != IPCFrameHostcallResult || !bytes.Contains(semantic, []byte(`"data_base64"`)) {
		t.Fatalf("large hostcall was not preserved: type=%d semantic=%d", framed.Type, len(semantic))
	}
}

func TestSemanticIPCV7RejectsHeaderAndMetadataIdentityMismatch(t *testing.T) {
	semantic, err := json.Marshal(ipcFrame{
		IPCVersion: "redevplugin.rust_ipc.v7", FrameType: ipcFrameTypeInvokeWorkerResult,
		RequestID: "invoke:1", RuntimeGenerationID: "runtime_gen", Payload: json.RawMessage(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := WriteIPCFrameV7(&encoded, IPCFrame{Type: IPCFrameInvokeResult, RequestID: semanticIPCRequestID("invoke:other"), Metadata: semantic}); err != nil {
		t.Fatal(err)
	}
	if _, err := readSemanticIPCFrameV7(&encoded); !errors.Is(err, ErrIPCProtocolViolation) {
		t.Fatalf("readSemanticIPCFrameV7() error = %v, want %v", err, ErrIPCProtocolViolation)
	}
}
