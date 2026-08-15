package runtimeclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type recordingRuntimeIOBroker struct {
	mu       sync.Mutex
	controls []string
	control  func(context.Context, string, []byte) ([]byte, error)
	reads    []string
	read     func(context.Context, string, uint64, []byte) (int, uint32, error)
	writes   []string
	seeks    []string
	closes   []string
}

func (broker *recordingRuntimeIOBroker) Control(ctx context.Context, invocationID string, raw []byte) ([]byte, error) {
	broker.mu.Lock()
	broker.controls = append(broker.controls, invocationID)
	control := broker.control
	broker.mu.Unlock()
	if control == nil {
		return []byte(`{"ok":true,"result":{}}`), nil
	}
	return control(ctx, invocationID, raw)
}

func TestRuntimeIOV7ControlUsesRawHostcallAndExactInvocation(t *testing.T) {
	request := []byte(`{"api":1,"operation":"fs.mounts","arguments":{}}`)
	broker := &recordingRuntimeIOBroker{control: func(_ context.Context, invocationID string, raw []byte) ([]byte, error) {
		if invocationID != "invoke_a" || string(raw) != string(request) {
			t.Fatalf("broker control = %q/%s", invocationID, raw)
		}
		return []byte(`{"ok":true,"result":{"mounts":[]}}`), nil
	}}
	supervisor, generation, reader, cleanup := runtimeIOV7TestHarness(t, broker, map[string]context.Context{"invoke_a": context.Background()}, 1)
	defer cleanup()
	metadata, _ := json.Marshal(runtimeIOControlRequestMetadata{InvocationID: "invoke_a", Request: request})
	if err := supervisor.dispatchRuntimeIOFrame(generation, IPCFrame{Type: IPCFrameHostcall, RequestID: 90, Metadata: metadata}); err != nil {
		t.Fatal(err)
	}
	response, err := ReadIPCFrameV7(reader)
	if err != nil {
		t.Fatal(err)
	}
	if response.Type != IPCFrameHostcallResult || response.RequestID != 90 || response.ResourceID != 0 || len(response.Body) != 0 {
		t.Fatalf("control response = %#v", response)
	}
	var result runtimeIOControlResultMetadata
	if err := decodeStrictJSON(response.Metadata, &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || string(result.Response) != `{"ok":true,"result":{"mounts":[]}}` {
		t.Fatalf("control result = %#v", result)
	}
}

func (broker *recordingRuntimeIOBroker) Read(ctx context.Context, invocationID string, handle uint64, destination []byte) (int, uint32, error) {
	broker.mu.Lock()
	broker.reads = append(broker.reads, invocationID)
	read := broker.read
	broker.mu.Unlock()
	if read == nil {
		return 0, 0, nil
	}
	return read(ctx, invocationID, handle, destination)
}

func (broker *recordingRuntimeIOBroker) Write(_ context.Context, invocationID string, _ uint64, source []byte, _ uint32) (int, error) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.writes = append(broker.writes, invocationID)
	return len(source), nil
}

func (broker *recordingRuntimeIOBroker) Seek(_ context.Context, invocationID string, _ uint64, offset int64, _ int) (int64, error) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.seeks = append(broker.seeks, invocationID)
	return offset, nil
}

func (broker *recordingRuntimeIOBroker) Close(_ context.Context, invocationID string, _ uint64) error {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.closes = append(broker.closes, invocationID)
	return nil
}

func TestRuntimeIOV7ReadUsesRawBodyAndExactInvocation(t *testing.T) {
	broker := &recordingRuntimeIOBroker{read: func(_ context.Context, invocationID string, handle uint64, destination []byte) (int, uint32, error) {
		if invocationID != "invoke_a" || handle != 41 {
			t.Fatalf("broker identity = %q/%d", invocationID, handle)
		}
		return copy(destination, []byte("data")), 1, nil
	}}
	supervisor, generation, reader, cleanup := runtimeIOV7TestHarness(t, broker, map[string]context.Context{"invoke_a": context.Background()}, 1)
	defer cleanup()
	metadata, _ := json.Marshal(runtimeIORequestMetadata{InvocationID: "invoke_a", MaxBytes: 4})
	if err := supervisor.dispatchRuntimeIOFrame(generation, IPCFrame{
		Type: IPCFrameIORead, RequestID: 91, ResourceID: 41, Metadata: metadata,
	}); err != nil {
		t.Fatal(err)
	}
	response, err := ReadIPCFrameV7(reader)
	if err != nil {
		t.Fatal(err)
	}
	if response.Type != IPCFrameIOReadResult || response.RequestID != 91 || response.ResourceID != 41 || string(response.Body) != "data" {
		t.Fatalf("I/O response = %#v", response)
	}
	var result runtimeIOResultMetadata
	if err := decodeStrictJSON(response.Metadata, &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.BytesRead != 4 || result.Flags != 1 {
		t.Fatalf("I/O result = %#v", result)
	}
}

func TestRuntimeIOV7BlockingReadDoesNotStarveAnotherInvocation(t *testing.T) {
	blocked := make(chan struct{})
	broker := &recordingRuntimeIOBroker{read: func(ctx context.Context, invocationID string, _ uint64, destination []byte) (int, uint32, error) {
		if invocationID == "invoke_a" {
			close(blocked)
			<-ctx.Done()
			return 0, 0, ctx.Err()
		}
		return copy(destination, []byte("b")), 0, nil
	}}
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	supervisor, generation, reader, cleanup := runtimeIOV7TestHarness(t, broker, map[string]context.Context{
		"invoke_a": ctxA,
		"invoke_b": context.Background(),
	}, 2)
	defer cleanup()
	metadataA, _ := json.Marshal(runtimeIORequestMetadata{InvocationID: "invoke_a", MaxBytes: 1})
	metadataB, _ := json.Marshal(runtimeIORequestMetadata{InvocationID: "invoke_b", MaxBytes: 1})
	if err := supervisor.dispatchRuntimeIOFrame(generation, IPCFrame{Type: IPCFrameIORead, RequestID: 1, ResourceID: 11, Metadata: metadataA}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("first read did not block")
	}
	if err := supervisor.dispatchRuntimeIOFrame(generation, IPCFrame{Type: IPCFrameIORead, RequestID: 2, ResourceID: 12, Metadata: metadataB}); err != nil {
		t.Fatal(err)
	}
	responseB, err := ReadIPCFrameV7(reader)
	if err != nil {
		t.Fatal(err)
	}
	if responseB.RequestID != 2 || string(responseB.Body) != "b" {
		t.Fatalf("unblocked response = %#v", responseB)
	}
	cancelA()
	responseA, err := ReadIPCFrameV7(reader)
	if err != nil {
		t.Fatal(err)
	}
	var canceled runtimeIOResultMetadata
	if err := decodeStrictJSON(responseA.Metadata, &canceled); err != nil {
		t.Fatal(err)
	}
	if responseA.RequestID != 1 || canceled.OK || canceled.Code != "CANCELED" {
		t.Fatalf("canceled response = %#v metadata=%#v", responseA, canceled)
	}
}

func TestRuntimeIOV7RejectsUnknownInvocationBeforeBroker(t *testing.T) {
	broker := &recordingRuntimeIOBroker{}
	supervisor, generation, _, cleanup := runtimeIOV7TestHarness(t, broker, nil, 1)
	defer cleanup()
	metadata, _ := json.Marshal(runtimeIORequestMetadata{InvocationID: "invoke_unknown", MaxBytes: 1})
	err := supervisor.dispatchRuntimeIOFrame(generation, IPCFrame{Type: IPCFrameIORead, RequestID: 1, ResourceID: 1, Metadata: metadata})
	if !errors.Is(err, ErrIPCProtocolViolation) {
		t.Fatalf("dispatchRuntimeIOFrame() error = %v, want %v", err, ErrIPCProtocolViolation)
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if len(broker.reads) != 0 {
		t.Fatalf("unknown invocation reached broker: %#v", broker.reads)
	}
}

func runtimeIOV7TestHarness(t *testing.T, broker RuntimeIOBroker, invocations map[string]context.Context, capacity int) (*ProcessSupervisor, *runtimeGeneration, io.Reader, func()) {
	t.Helper()
	reader, writer := io.Pipe()
	framed := newSemanticIPCWriteCloserV7(writer)
	generation := &runtimeGeneration{id: "runtime_generation", ctx: context.Background(), stdin: framed, framedStdin: framed}
	supervisor := &ProcessSupervisor{
		ioBroker: broker, ioRouteSlots: make(chan struct{}, capacity), pendingInvocations: map[string]*pendingIPCRequest{},
	}
	for invocationID, ctx := range invocations {
		invocation := &workerInvocationContext{InvocationID: invocationID}
		supervisor.pendingInvocations[invocationID] = &pendingIPCRequest{ctx: ctx, generation: generation, invocation: invocation}
	}
	cleanup := func() {
		_ = framed.Close()
		_ = reader.Close()
	}
	return supervisor, generation, reader, cleanup
}
