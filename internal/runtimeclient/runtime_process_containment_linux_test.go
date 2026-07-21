//go:build linux

package runtimeclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"golang.org/x/sys/unix"
)

func TestRuntimeChildSpecAssemblyLayout(t *testing.T) {
	var spec runtimeChildSpec
	for name, offsets := range map[string]struct {
		got  uintptr
		want uintptr
	}{
		"executable_fd": {unsafe.Offsetof(spec.executableFD), 28},
		"execution_fd":  {unsafe.Offsetof(spec.executionFD), 32},
		"error_fd":      {unsafe.Offsetof(spec.errorFD), 36},
		"parent_pid":    {unsafe.Offsetof(spec.parentPID), 40},
		"argv":          {unsafe.Offsetof(spec.argv), 48},
		"envv":          {unsafe.Offsetof(spec.envv), 56},
		"empty_path":    {unsafe.Offsetof(spec.emptyPath), 64},
	} {
		if offsets.got != offsets.want {
			t.Fatalf("%s offset = %d, want %d", name, offsets.got, offsets.want)
		}
	}
	if got := unsafe.Sizeof(spec); got != 72 {
		t.Fatalf("runtimeChildSpec size = %d, want 72", got)
	}
}

func TestContainedRuntimeProcessExecutesSealedRuntimeAndValidatesAcknowledgement(t *testing.T) {
	runtimePath := os.Getenv("REDEVPLUGIN_CONTAINMENT_RUNTIME_PATH")
	if runtimePath == "" {
		t.Skip("REDEVPLUGIN_CONTAINMENT_RUNTIME_PATH is not set")
	}
	target := runtimetarget.LinuxAMD64
	if runtime.GOARCH == "arm64" {
		target = runtimetarget.LinuxARM64
	}
	source, err := os.Open(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	memfd, err := unix.MemfdCreate("redevplugin-runtime-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err != nil {
		t.Fatal(err)
	}
	executable := os.NewFile(uintptr(memfd), "redevplugin-runtime-test")
	defer executable.Close()
	if err := unix.Fchmod(memfd, 0o500); err != nil {
		t.Fatal(err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(executable, hasher), source); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(executable.Fd(), unix.F_ADD_SEALS, requiredRuntimeExecutableSeals); err != nil {
		t.Fatal(err)
	}
	if _, err := executable.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	executionRoot, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer executionRoot.Close()
	diagnostics := &runtimeDiagnosticSink{}
	supervisor, err := NewProcessSupervisor(ProcessSupervisorOptions{
		RuntimeExecutable:     executable,
		RuntimeExecutionRoot:  executionRoot,
		Descriptor:            testRuntimeDescriptor(target, hex.EncodeToString(hasher.Sum(nil))),
		StreamSink:            &recordingRuntimeStreamSink{},
		HandshakeTimeout:      10 * time.Second,
		HeartbeatInterval:     500 * time.Millisecond,
		MaxHeartbeatStaleness: 2 * time.Second,
		Limits:                DefaultRuntimeLimits(),
		Diagnostics:           diagnostics,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := supervisor.Start(ctx, target); err != nil {
		t.Fatalf("start contained runtime: %v; diagnostics=%#v", err, diagnostics.list(""))
	}
	health, err := supervisor.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !health.Ready || health.RuntimeInstanceID == "" || health.ConnectionNonce == "" {
		t.Fatalf("contained runtime health is incomplete: %#v", health)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := supervisor.Stop(stopCtx); err != nil {
		t.Fatalf("stop contained runtime: %v", err)
	}
}

func TestRuntimePIDFDTracksQuickExit(t *testing.T) {
	command := exec.Command("/bin/true")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("PidfdOpen() error = %v", err)
	}
	defer closeRuntimePIDFD(pidfd)
	if err := verifyRuntimePIDFD(pidfd); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	if runtimePIDFDAlive(pidfd) {
		t.Fatal("pidfd reported a reaped quick-exit process as alive")
	}
	if err := signalRuntimePIDFD(pidfd); err != nil {
		t.Fatalf("signalRuntimePIDFD() after exit error = %v", err)
	}
}

func TestRuntimePIDFDSignalsExactProcess(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "exec sleep 30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("PidfdOpen() error = %v", err)
	}
	defer closeRuntimePIDFD(pidfd)
	if !runtimePIDFDAlive(pidfd) {
		t.Fatal("pidfd did not report the running process as alive")
	}
	if err := signalRuntimePIDFD(pidfd); err != nil {
		t.Fatalf("signalRuntimePIDFD() error = %v", err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("pidfd-signalled process exited successfully")
	}
	if runtimePIDFDAlive(pidfd) {
		t.Fatal("pidfd reported the signalled and reaped process as alive")
	}
}
