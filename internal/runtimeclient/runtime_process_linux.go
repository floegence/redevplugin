//go:build linux

package runtimeclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	runtimeChildFDBase        = 64
	runtimeChildSetupExitCode = 253
)

// These runtime hooks are the same fork boundary used by package syscall. The
// runtime deliberately keeps them linkable for audited fork/exec users.
//
//go:linkname runtimeBeforeFork syscall.runtime_BeforeFork
func runtimeBeforeFork()

//go:linkname runtimeAfterFork syscall.runtime_AfterFork
func runtimeAfterFork()

type runtimeCloneArgs struct {
	flags      uint64
	pidFD      uint64
	childTID   uint64
	parentTID  uint64
	exitSignal uint64
	stack      uint64
	stackSize  uint64
	tls        uint64
	setTID     uint64
	setTIDSize uint64
	cgroup     uint64
}

type runtimeChildSpec struct {
	fds          [runtimeControlWriteFD + 1]int32
	executableFD int32
	executionFD  int32
	errorFD      int32
	parentPID    int32
	argv         uintptr
	envv         uintptr
	emptyPath    uintptr
}

type runtimePipes struct {
	eofRead          *os.File
	ipcHostWrite     *os.File
	ipcHostRead      *os.File
	diagnosticRead   *os.File
	diagnosticErr    *os.File
	controlHostWrite *os.File
	controlHostRead  *os.File
	child            [runtimeControlWriteFD + 1]*os.File
}

func launchRuntimeProcess(options runtimeProcessLaunchOptions) (*runtimeProcess, error) {
	if options.executable == nil {
		if len(options.args) != 0 || len(options.env) != 0 {
			return launchLegacyRuntimeProcess(options)
		}
		return launchFixedPathRuntimeProcess(options)
	}
	if options.executionRoot == nil {
		return nil, ErrRuntimePathRequired
	}
	return launchContainedRuntimeProcess(options)
}

func launchFixedPathRuntimeProcess(options runtimeProcessLaunchOptions) (*runtimeProcess, error) {
	pipes, err := openRuntimePipes()
	if err != nil {
		return nil, err
	}
	defer pipes.closeChild()
	defer func() {
		if err != nil {
			pipes.closeParent()
		}
	}()
	pidfd := -1
	cmd := exec.CommandContext(options.context, options.path)
	cmd.Env = containedRuntimeEnvironment()
	cmd.Stdin = pipes.child[0]
	cmd.Stdout = pipes.child[1]
	cmd.Stderr = pipes.child[2]
	cmd.ExtraFiles = []*os.File{pipes.child[3], pipes.child[4], pipes.child[5], pipes.child[6]}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
		Setpgid:   true,
		PidFD:     &pidfd,
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	pipes.closeChild()
	kill := cmd.Process.Kill
	if pidfd >= 0 {
		kill = func() error { return signalRuntimePIDFD(pidfd) }
	}
	return &runtimeProcess{
		pid:                 cmd.Process.Pid,
		pidfd:               pidfd,
		containmentRequired: true,
		containmentIdentity: fmt.Sprintf("%s:pid-%d:pidfd-%d", runtimeContainmentProfile, cmd.Process.Pid, pidfd),
		ipcIn:               pipes.ipcHostWrite,
		ipcOut:              pipes.ipcHostRead,
		diagnosticOut:       pipes.diagnosticRead,
		diagnosticErr:       pipes.diagnosticErr,
		controlIn:           pipes.controlHostWrite,
		controlOut:          pipes.controlHostRead,
		wait:                cmd.Wait,
		kill:                kill,
		alive: func() bool {
			if pidfd >= 0 {
				return runtimePIDFDAlive(pidfd)
			}
			return cmd.Process.Signal(syscall.Signal(0)) == nil
		},
	}, nil
}

func launchContainedRuntimeProcess(options runtimeProcessLaunchOptions) (_ *runtimeProcess, err error) {
	if err := options.context.Err(); err != nil {
		return nil, err
	}
	if err := verifyRuntimeExecutableFile(options.context, options.executable, options.expectedDigest); err != nil {
		return nil, err
	}
	seals, err := unix.FcntlInt(options.executable.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&requiredRuntimeExecutableSeals != requiredRuntimeExecutableSeals {
		return nil, fmt.Errorf("%w: executable memfd seals are incomplete", ErrRuntimeArtifactDigest)
	}
	pipes, err := openRuntimePipes()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			pipes.closeParent()
		}
	}()

	childFiles := make([]*os.File, 0, len(pipes.child)+3)
	for _, file := range pipes.child {
		childFiles = append(childFiles, file)
	}
	childFDs, nextFD, err := duplicateRuntimeChildFiles(childFiles, runtimeChildFDBase)
	if err != nil {
		pipes.closeChild()
		return nil, err
	}
	defer closeRuntimeFDs(childFDs)
	pipes.closeChild()
	executableFD, err := duplicateRuntimeFDAtLeast(int(options.executable.Fd()), nextFD)
	if err != nil {
		return nil, err
	}
	defer unix.Close(executableFD)
	nextFD = executableFD + 1
	executionFD, err := duplicateRuntimeFDAtLeast(int(options.executionRoot.Fd()), nextFD)
	if err != nil {
		return nil, err
	}
	defer unix.Close(executionFD)
	nextFD = executionFD + 1
	errorRead, errorWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer errorRead.Close()
	defer errorWrite.Close()
	errorFD, err := duplicateRuntimeFDAtLeast(int(errorWrite.Fd()), nextFD)
	if err != nil {
		return nil, err
	}
	defer func() {
		if errorFD >= 0 {
			_ = unix.Close(errorFD)
		}
	}()
	_ = errorWrite.Close()

	argv, err := syscall.SlicePtrFromStrings([]string{"redevplugin-runtime"})
	if err != nil {
		return nil, err
	}
	envv, err := syscall.SlicePtrFromStrings(containedRuntimeEnvironment())
	if err != nil {
		return nil, err
	}
	emptyPath := []byte{0}
	spec := &runtimeChildSpec{
		executableFD: int32(executableFD),
		executionFD:  int32(executionFD),
		errorFD:      int32(errorFD),
		parentPID:    int32(os.Getpid()),
		argv:         uintptr(unsafe.Pointer(&argv[0])),
		envv:         uintptr(unsafe.Pointer(&envv[0])),
		emptyPath:    uintptr(unsafe.Pointer(&emptyPath[0])),
	}
	for index, fd := range childFDs {
		spec.fds[index] = int32(fd)
	}
	pidfd := int32(-1)
	clone := &runtimeCloneArgs{
		flags:      unix.CLONE_PIDFD,
		pidFD:      uint64(uintptr(unsafe.Pointer(&pidfd))),
		exitSignal: uint64(unix.SIGCHLD),
	}

	runtime.LockOSThread()
	syscall.ForkLock.Lock()
	runtimeBeforeFork()
	pid, errno := rawRuntimeClone3(clone, spec)
	if pid != 0 || errno != 0 {
		runtimeAfterFork()
		syscall.ForkLock.Unlock()
		runtime.UnlockOSThread()
	}
	if errno != 0 {
		if errno == syscall.ENOSYS || errno == syscall.EINVAL || errno == syscall.EOPNOTSUPP {
			return nil, ErrRuntimeContainmentUnsupported
		}
		return nil, fmt.Errorf("clone runtime process: %w", errno)
	}
	if pid == 0 {
		panic("rawRuntimeClone3 returned in child")
	}
	if pidfd < 0 {
		return nil, ErrRuntimeContainmentUnsupported
	}
	if closeErr := unix.Close(errorFD); closeErr != nil {
		_ = signalRuntimePIDFD(int(pidfd))
		_, _ = waitRuntimePID(int(pid))
		_ = unix.Close(int(pidfd))
		return nil, fmt.Errorf("close runtime child setup descriptor: %w", closeErr)
	}
	errorFD = -1
	_ = errorWrite.Close()
	if setupErr := readRuntimeChildSetupError(options.context, errorRead); setupErr != nil {
		_ = signalRuntimePIDFD(int(pidfd))
		_, _ = waitRuntimePID(int(pid))
		_ = unix.Close(int(pidfd))
		return nil, setupErr
	}
	if err := verifyRuntimePIDFD(int(pidfd)); err != nil {
		_ = signalRuntimePIDFD(int(pidfd))
		_, _ = waitRuntimePID(int(pid))
		_ = unix.Close(int(pidfd))
		return nil, err
	}
	var executableStat unix.Stat_t
	if err := unix.Fstat(executableFD, &executableStat); err != nil {
		return nil, err
	}
	identity := fmt.Sprintf(
		"%s:pid-%d:pidfd-%d:dev-%d:ino-%d:seals-%x",
		runtimeContainmentProfile,
		pid,
		pidfd,
		executableStat.Dev,
		executableStat.Ino,
		seals,
	)
	pipes.closeChild()
	return &runtimeProcess{
		pid:                 int(pid),
		pidfd:               int(pidfd),
		containmentRequired: true,
		containmentIdentity: identity,
		ipcIn:               pipes.ipcHostWrite,
		ipcOut:              pipes.ipcHostRead,
		diagnosticOut:       pipes.diagnosticRead,
		diagnosticErr:       pipes.diagnosticErr,
		controlIn:           pipes.controlHostWrite,
		controlOut:          pipes.controlHostRead,
		wait: func() error {
			waitStatus, waitErr := waitRuntimePID(int(pid))
			if waitErr != nil {
				return waitErr
			}
			if waitStatus.Exited() && waitStatus.ExitStatus() == 0 {
				return nil
			}
			if waitStatus.Signaled() {
				return &runtimeProcessWaitError{signal: int(waitStatus.Signal())}
			}
			return &runtimeProcessWaitError{exitCode: waitStatus.ExitStatus()}
		},
		kill:  func() error { return signalRuntimePIDFD(int(pidfd)) },
		alive: func() bool { return runtimePIDFDAlive(int(pidfd)) },
	}, nil
}

func containedRuntimeEnvironment() []string {
	return []string{
		"LANG=C",
		"LC_ALL=C",
		"REDEVPLUGIN_RUNTIME_PROFILE=" + runtimeContainmentProfile,
	}
}

func openRuntimePipes() (_ *runtimePipes, err error) {
	pipes := &runtimePipes{}
	opened := make([]*os.File, 0, 14)
	defer func() {
		if err != nil {
			for _, file := range opened {
				_ = file.Close()
			}
		}
	}()
	pipe := func() (*os.File, *os.File, error) {
		read, write, pipeErr := os.Pipe()
		if pipeErr == nil {
			opened = append(opened, read, write)
		}
		return read, write, pipeErr
	}
	var eofWrite *os.File
	pipes.eofRead, eofWrite, err = pipe()
	if err != nil {
		return nil, err
	}
	_ = eofWrite.Close()
	diagnosticRead, diagnosticWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	diagnosticErr, diagnosticErrWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	ipcChildRead, ipcHostWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	ipcHostRead, ipcChildWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	controlChildRead, controlHostWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	controlHostRead, controlChildWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	pipes.ipcHostWrite = ipcHostWrite
	pipes.ipcHostRead = ipcHostRead
	pipes.diagnosticRead = diagnosticRead
	pipes.diagnosticErr = diagnosticErr
	pipes.controlHostWrite = controlHostWrite
	pipes.controlHostRead = controlHostRead
	pipes.child = [runtimeControlWriteFD + 1]*os.File{
		pipes.eofRead,
		diagnosticWrite,
		diagnosticErrWrite,
		ipcChildRead,
		ipcChildWrite,
		controlChildRead,
		controlChildWrite,
	}
	return pipes, nil
}

func (pipes *runtimePipes) closeChild() {
	if pipes == nil {
		return
	}
	for index, file := range pipes.child {
		if file != nil {
			_ = file.Close()
			pipes.child[index] = nil
		}
	}
}

func (pipes *runtimePipes) closeParent() {
	if pipes == nil {
		return
	}
	for _, file := range []*os.File{
		pipes.ipcHostWrite,
		pipes.ipcHostRead,
		pipes.diagnosticRead,
		pipes.diagnosticErr,
		pipes.controlHostWrite,
		pipes.controlHostRead,
	} {
		if file != nil {
			_ = file.Close()
		}
	}
}

func duplicateRuntimeChildFiles(files []*os.File, firstFD int) ([]int, int, error) {
	fds := make([]int, 0, len(files))
	nextFD := firstFD
	for _, file := range files {
		if file == nil {
			closeRuntimeFDs(fds)
			return nil, 0, ErrRuntimePathRequired
		}
		fd, err := duplicateRuntimeFDAtLeast(int(file.Fd()), nextFD)
		if err != nil {
			closeRuntimeFDs(fds)
			return nil, 0, err
		}
		fds = append(fds, fd)
		nextFD = fd + 1
	}
	return fds, nextFD, nil
}

func duplicateRuntimeFDAtLeast(fd, minimum int) (int, error) {
	duplicated, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, minimum)
	if err != nil {
		return -1, fmt.Errorf("duplicate runtime child descriptor: %w", err)
	}
	return duplicated, nil
}

func closeRuntimeFDs(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

func readRuntimeChildSetupError(ctx context.Context, reader *os.File) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = reader.SetReadDeadline(deadline)
	}
	var encoded [4]byte
	read, err := io.ReadFull(reader, encoded[:])
	if errors.Is(err, io.EOF) && read == 0 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("runtime child setup acknowledgement: %w", err)
	}
	errno := syscall.Errno(uintptr(encoded[0]) | uintptr(encoded[1])<<8 | uintptr(encoded[2])<<16 | uintptr(encoded[3])<<24)
	if errno == syscall.ENOSYS || errno == syscall.EINVAL || errno == syscall.EOPNOTSUPP {
		return ErrRuntimeContainmentUnsupported
	}
	return fmt.Errorf("runtime child setup: %w", errno)
}

func verifyRuntimePIDFD(pidfd int) error {
	if pidfd < 0 {
		return ErrRuntimeContainmentUnsupported
	}
	var stat unix.Stat_t
	if err := unix.Fstat(pidfd, &stat); err != nil {
		return fmt.Errorf("verify runtime pidfd: %w", err)
	}
	return nil
}

func waitRuntimePID(pid int) (unix.WaitStatus, error) {
	for {
		var status unix.WaitStatus
		_, err := unix.Wait4(pid, &status, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return status, err
	}
}

func signalRuntimePIDFD(pidfd int) error {
	err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func runtimePIDFDAlive(pidfd int) bool {
	err := unix.PidfdSendSignal(pidfd, 0, nil, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}

func closeRuntimePIDFD(pidfd int) error {
	return unix.Close(pidfd)
}

// rawRuntimeClone3 performs the only fork boundary used for admitted runtime
// capabilities. The child does not return to the Go runtime: it executes a
// fixed syscall-only trampoline and either execveat(AT_EMPTY_PATH)s the sealed
// executable or reports one errno to the parent.
func rawRuntimeClone3(clone *runtimeCloneArgs, child *runtimeChildSpec) (pid uintptr, errno syscall.Errno)

const requiredRuntimeExecutableSeals = unix.F_SEAL_FUTURE_WRITE | unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
