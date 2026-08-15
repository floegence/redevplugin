package runtimeclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/floegence/redevplugin/v2/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v2/pkg/version"
)

type testHostSemanticIPCReaderV7 struct {
	reader  io.Reader
	pending bytes.Reader
}

func (reader *testHostSemanticIPCReaderV7) Read(destination []byte) (int, error) {
	for reader.pending.Len() == 0 {
		frame, err := readHostSemanticIPCFrameV7(reader.reader)
		if err != nil {
			return 0, err
		}
		raw, err := json.Marshal(frame)
		if err != nil {
			return 0, err
		}
		raw = append(raw, '\n')
		reader.pending.Reset(raw)
	}
	return reader.pending.Read(destination)
}

type testWriterCloser struct {
	io.Writer
}

func (testWriterCloser) Close() error { return nil }

var testRuntimeTarget = runtimetarget.LinuxAMD64

func testRuntimeDescriptor(target runtimetarget.Target, digest string) RuntimeDescriptor {
	runtimeVersion, err := version.ParseSemVer(version.CurrentCompatibilityVersion())
	if err != nil {
		panic(err)
	}
	descriptor, err := NewRuntimeDescriptor(RuntimeDescriptorOptions{
		PlatformVersion: runtimeVersion, Target: target, RustIPCVersion: version.RustIPCVersion,
		WASMABIVersion: version.WASMABIVersion, ContractSetSHA256: version.ContractSetSHA256, BinarySHA256: digest,
	})
	if err != nil {
		panic(err)
	}
	return descriptor
}

func newTestProcessSupervisor(t *testing.T, options ProcessSupervisorOptions) (*ProcessSupervisor, error) {
	t.Helper()
	file, err := os.Open(options.RuntimePath)
	if err != nil {
		t.Fatalf("open test runtime executable: %v", err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		t.Fatalf("hash test runtime executable: %v", err)
	}
	options.Descriptor = testRuntimeDescriptor(testRuntimeTarget, hex.EncodeToString(hasher.Sum(nil)))
	if options.IOBroker == nil {
		options.IOBroker = testRuntimeIOBroker{}
	}
	return NewProcessSupervisor(options)
}

type testRuntimeIOBroker struct{}

func (testRuntimeIOBroker) Control(context.Context, string, []byte) ([]byte, error) {
	return nil, nil
}

func (testRuntimeIOBroker) Read(context.Context, string, uint64, []byte) (int, uint32, error) {
	return 0, 0, nil
}

func (testRuntimeIOBroker) Write(context.Context, string, uint64, []byte, uint32) (int, error) {
	return 0, nil
}

func (testRuntimeIOBroker) Seek(context.Context, string, uint64, int64, int) (int64, error) {
	return 0, nil
}

func (testRuntimeIOBroker) Close(context.Context, string, uint64) error { return nil }
