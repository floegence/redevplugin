package runtimeclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

type ipcBufferCloser struct {
	bytes.Buffer
}

func (*ipcBufferCloser) Close() error { return nil }

func TestSemanticIPCWriterUsesCanonicalFraming(t *testing.T) {
	output := &ipcBufferCloser{}
	writer := newSemanticIPCWriteCloser(output)
	want := ipcFrame{
		FrameType:           ipcFrameTypeHello,
		RequestID:           "runtime_gen:hello:1",
		RuntimeGenerationID: "runtime_gen",
		Payload:             json.RawMessage(`{"channel_nonce":"nonce","latitude":52.52}`),
	}
	if err := json.NewEncoder(writer).Encode(want); err != nil {
		t.Fatal(err)
	}
	framed, err := ReadIPCFrame(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if framed.Type != IPCFrameHello || framed.RequestID != semanticIPCRequestID(want.RequestID) ||
		framed.Flags != semanticIPCChunkedFlag || len(framed.Body) == 0 {
		t.Fatalf("framed identity = %#v", framed)
	}
	got, err := readHostSemanticIPCFrame(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID != want.RequestID || got.FrameType != want.FrameType {
		t.Fatalf("semantic frame = %#v, want %#v", got, want)
	}
}

func TestSemanticIPCRejectsRetiredBrokerFrames(t *testing.T) {
	retired := []string{
		"validate_handle_grant",
		"storage_file",
		"storage_kv",
		"storage_sqlite",
		"network_grant",
		"network_execute",
	}
	for _, frameType := range retired {
		t.Run(frameType+"_from_host", func(t *testing.T) {
			if _, err := hostSemanticFrameType(frameType); !errors.Is(err, ErrIPCProtocolViolation) {
				t.Fatalf("hostSemanticFrameType(%q) error = %v, want %v", frameType, err, ErrIPCProtocolViolation)
			}
		})
		t.Run(frameType+"_from_runtime", func(t *testing.T) {
			if _, err := runtimeSemanticFrameType(frameType); !errors.Is(err, ErrIPCProtocolViolation) {
				t.Fatalf("runtimeSemanticFrameType(%q) error = %v, want %v", frameType, err, ErrIPCProtocolViolation)
			}
		})
	}
}

func TestSemanticIPCRejectsHeaderAndMetadataIdentityMismatch(t *testing.T) {
	semantic, err := json.Marshal(ipcFrame{
		FrameType: ipcFrameTypeInvokeWorkerResult,
		RequestID: "invoke:1", RuntimeGenerationID: "runtime_gen", Payload: json.RawMessage(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := writeSemanticIPCFrame(&encoded, IPCFrameInvokeResult, semanticIPCRequestID("invoke:other"), semantic); err != nil {
		t.Fatal(err)
	}
	if _, err := readSemanticIPCFrame(&encoded); !errors.Is(err, ErrIPCProtocolViolation) {
		t.Fatalf("readSemanticIPCFrame() error = %v, want %v", err, ErrIPCProtocolViolation)
	}
}
