package runtimeclient

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadIPCFrame is the Go-side IPC parser fuzz target. The bounded line
// reader and strict JSON decoder must classify arbitrary input without a
// panic or an unbounded read.
func FuzzReadIPCFrame(f *testing.F) {
	f.Add([]byte("{}\n"))
	f.Add([]byte("{\"ipc_version\":\"rust-ipc-v4\",\"frame_type\":\"heartbeat\",\"request_id\":\"r1\",\"runtime_generation_id\":\"g1\",\"payload\":{}}\n"))
	f.Add([]byte("{\"request_id\":\"r1\",\"request_id\":\"r2\"}\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = readIPCFrame(bufio.NewReader(bytes.NewReader(input)))
	})
}

// FuzzStrictJSON ensures duplicate keys, unknown fields, trailing values and
// malformed UTF-8 are all handled as ordinary decode errors.
func FuzzStrictJSON(f *testing.F) {
	f.Add([]byte(`{"handle_grant_id":"grant_1","handle_id":"storage:db","method":"storage.kv","runtime_generation_id":"g1"}`))
	f.Add([]byte(`{"handle_grant_id":"grant_1","handle_grant_id":"grant_2"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		var value HandleGrantValidationResult
		_, _ = value, decodeStrictJSON(input, &value)
	})
}
