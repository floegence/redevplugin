//go:build linux

package host

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCreateExecutableRuntimeMemfdPrefersExplicitExecution(t *testing.T) {
	var flags []int
	memfd, err := createExecutableRuntimeMemfd(func(name string, value int) (int, error) {
		if name != "redevplugin-runtime" {
			t.Fatalf("memfd name = %q", name)
		}
		flags = append(flags, value)
		return 41, nil
	})
	if err != nil || memfd != 41 {
		t.Fatalf("createExecutableRuntimeMemfd() = %d, %v", memfd, err)
	}
	want := []int{unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING | unix.MFD_EXEC}
	if len(flags) != len(want) || flags[0] != want[0] {
		t.Fatalf("memfd flags = %#v, want %#v", flags, want)
	}
}

func TestCreateExecutableRuntimeMemfdUsesHistoricalExecutionDefaultAfterUnknownFlag(t *testing.T) {
	var flags []int
	memfd, err := createExecutableRuntimeMemfd(func(_ string, value int) (int, error) {
		flags = append(flags, value)
		if len(flags) == 1 {
			return -1, unix.EINVAL
		}
		return 42, nil
	})
	if err != nil || memfd != 42 {
		t.Fatalf("createExecutableRuntimeMemfd() = %d, %v", memfd, err)
	}
	want := []int{
		unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING | unix.MFD_EXEC,
		unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING,
	}
	if len(flags) != len(want) || flags[0] != want[0] || flags[1] != want[1] {
		t.Fatalf("memfd flags = %#v, want %#v", flags, want)
	}
}

func TestCreateExecutableRuntimeMemfdDoesNotBypassSecurityOrMissingKernelSupport(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "policy denied", err: unix.EPERM, want: ErrRuntimeAdmissionInvalid},
		{name: "system call missing", err: unix.ENOSYS, want: ErrRuntimeAdmissionUnsupported},
		{name: "operation unsupported", err: unix.EOPNOTSUPP, want: ErrRuntimeAdmissionUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			memfd, err := createExecutableRuntimeMemfd(func(string, int) (int, error) {
				calls++
				return -1, test.err
			})
			if memfd != -1 || !errors.Is(err, test.want) {
				t.Fatalf("createExecutableRuntimeMemfd() = %d, %v, want %v", memfd, err, test.want)
			}
			if calls != 1 {
				t.Fatalf("memfd create calls = %d, want 1", calls)
			}
		})
	}
}

func TestCreateExecutableRuntimeMemfdRejectsUnavailableHistoricalMode(t *testing.T) {
	calls := 0
	memfd, err := createExecutableRuntimeMemfd(func(string, int) (int, error) {
		calls++
		return -1, unix.EINVAL
	})
	if memfd != -1 || !errors.Is(err, ErrRuntimeAdmissionUnsupported) {
		t.Fatalf("createExecutableRuntimeMemfd() = %d, %v", memfd, err)
	}
	if calls != 2 {
		t.Fatalf("memfd create calls = %d, want 2", calls)
	}
}

func TestCreateExecutableRuntimeMemfdSupportsRequiredSealsOnCurrentKernel(t *testing.T) {
	memfd, err := createExecutableRuntimeMemfd(unix.MemfdCreate)
	if err != nil {
		t.Fatalf("createExecutableRuntimeMemfd() error = %v", err)
	}
	defer unix.Close(memfd)
	if err := unix.Ftruncate(memfd, 1); err != nil {
		t.Fatalf("Ftruncate() error = %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(memfd), unix.F_ADD_SEALS, requiredRuntimeMemfdSeals); err != nil {
		t.Fatalf("F_ADD_SEALS error = %v", err)
	}
	seals, err := unix.FcntlInt(uintptr(memfd), unix.F_GET_SEALS, 0)
	if err != nil || seals&requiredRuntimeMemfdSeals != requiredRuntimeMemfdSeals {
		t.Fatalf("F_GET_SEALS = %#x, %v", seals, err)
	}
}
