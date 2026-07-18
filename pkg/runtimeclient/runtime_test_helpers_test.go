package runtimeclient

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/version"
)

var testRuntimeTarget = runtimetarget.DarwinARM64

func testRuntimeDescriptor(target runtimetarget.Target, digest string) RuntimeDescriptor {
	runtimeVersion, err := version.ParseSemVer(version.RuntimeVersion)
	if err != nil {
		panic(err)
	}
	descriptor, err := NewRuntimeDescriptor(runtimeVersion, target, version.RustIPCVersion, version.WASMABIVersion, digest)
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
	return NewProcessSupervisor(options)
}
