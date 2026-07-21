//go:build linux

package host

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const requiredRuntimeMemfdSeals = unix.F_SEAL_FUTURE_WRITE | unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

func openVerifiedExecutable(ctx context.Context, options VerifiedExecutableOptions) (*VerifiedExecutable, error) {
	if options.RootDir == nil || options.ExecutionRoot == nil || !options.RelativeName.valid() || !options.ExpectedDescriptor.valid() {
		return nil, ErrRuntimeAdmissionInvalid
	}
	if err := options.ExpectedDescriptor.CompatibleWithPlatform(); err != nil {
		return nil, err
	}
	rootFD, err := duplicateValidatedRuntimeDirectory(options.RootDir, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	executionRootFD, err := duplicateValidatedRuntimeDirectory(options.ExecutionRoot, true)
	if err != nil {
		return nil, err
	}
	executionRoot := os.NewFile(uintptr(executionRootFD), "redevplugin-runtime-execution-root")
	if executionRoot == nil {
		unix.Close(executionRootFD)
		return nil, ErrRuntimeAdmissionInvalid
	}
	closeExecutionRoot := true
	defer func() {
		if closeExecutionRoot {
			_ = executionRoot.Close()
		}
	}()

	sourceFD, err := unix.Openat(rootFD, options.RelativeName.String(), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open runtime executable", ErrRuntimeAdmissionInvalid)
	}
	source := os.NewFile(uintptr(sourceFD), options.RelativeName.String())
	if source == nil {
		unix.Close(sourceFD)
		return nil, ErrRuntimeAdmissionInvalid
	}
	defer source.Close()

	sourceStat, err := runtimeExecutableStat(sourceFD)
	if err != nil {
		return nil, err
	}
	if err := validateRuntimeExecutableMetadata(sourceStat); err != nil {
		return nil, err
	}
	if err := validateRuntimeELF(source, sourceStat.Size, options.ExpectedDescriptor.Target()); err != nil {
		return nil, err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	memfd, err := unix.MemfdCreate("redevplugin-runtime", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil, ErrRuntimeAdmissionUnsupported
		}
		return nil, fmt.Errorf("%w: create executable memfd", ErrRuntimeAdmissionInvalid)
	}
	sealed := os.NewFile(uintptr(memfd), "redevplugin-runtime-sealed")
	if sealed == nil {
		unix.Close(memfd)
		return nil, ErrRuntimeAdmissionInvalid
	}
	closeSealed := true
	defer func() {
		if closeSealed {
			_ = sealed.Close()
		}
	}()
	if err := unix.Fchmod(memfd, 0o500); err != nil {
		return nil, fmt.Errorf("%w: set executable memfd mode", ErrRuntimeAdmissionInvalid)
	}
	actualDigest, err := copyRuntimeExecutableToMemfd(ctx, sourceFD, memfd, sourceStat.Size)
	if err != nil {
		return nil, err
	}
	if actualDigest != options.ExpectedDescriptor.BinarySHA256().String() {
		return nil, fmt.Errorf("%w: binary digest mismatch", ErrRuntimeDescriptorMismatch)
	}
	if _, err := unix.FcntlInt(uintptr(memfd), unix.F_ADD_SEALS, requiredRuntimeMemfdSeals); err != nil {
		return nil, fmt.Errorf("%w: seal executable memfd", ErrRuntimeAdmissionInvalid)
	}
	seals, err := unix.FcntlInt(uintptr(memfd), unix.F_GET_SEALS, 0)
	if err != nil || seals&requiredRuntimeMemfdSeals != requiredRuntimeMemfdSeals {
		return nil, fmt.Errorf("%w: executable memfd seals are incomplete", ErrRuntimeAdmissionInvalid)
	}
	sealedStat, err := runtimeExecutableStat(memfd)
	if err != nil {
		return nil, err
	}
	if sealedStat.Size != sourceStat.Size {
		return nil, fmt.Errorf("%w: sealed executable size mismatch", ErrRuntimeAdmissionInvalid)
	}
	if err := validateRuntimeELF(sealed, sealedStat.Size, options.ExpectedDescriptor.Target()); err != nil {
		return nil, err
	}
	sealedDigest, err := hashRuntimeExecutableFD(ctx, memfd, sealedStat.Size)
	if err != nil {
		return nil, err
	}
	if sealedDigest != actualDigest {
		return nil, fmt.Errorf("%w: sealed executable digest mismatch", ErrRuntimeAdmissionInvalid)
	}

	closeSealed = false
	closeExecutionRoot = false
	return &VerifiedExecutable{
		state:         verifiedExecutableOwned,
		descriptor:    options.ExpectedDescriptor,
		executable:    sealed,
		executionRoot: executionRoot,
	}, nil
}

func duplicateValidatedRuntimeDirectory(directory *os.File, requireWrite bool) (int, error) {
	if directory == nil {
		return -1, ErrRuntimeAdmissionInvalid
	}
	fd, err := unix.FcntlInt(directory.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return -1, fmt.Errorf("%w: duplicate directory capability", ErrRuntimeAdmissionInvalid)
	}
	stat, err := runtimeExecutableStat(fd)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	mode := uint32(stat.Mode)
	if mode&unix.S_IFMT != unix.S_IFDIR || mode&(unix.S_ISUID|unix.S_ISGID) != 0 || mode&0o022 != 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: directory capability metadata", ErrRuntimeAdmissionInvalid)
	}
	euid := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != euid {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: directory capability owner", ErrRuntimeAdmissionInvalid)
	}
	required := uint32(0o500)
	if requireWrite {
		required = 0o700
	}
	if mode&required != required {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: directory capability permissions", ErrRuntimeAdmissionInvalid)
	}
	return fd, nil
}

func runtimeExecutableStat(fd int) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, fmt.Errorf("%w: stat runtime object", ErrRuntimeAdmissionInvalid)
	}
	return stat, nil
}

func validateRuntimeExecutableMetadata(stat unix.Stat_t) error {
	mode := uint32(stat.Mode)
	euid := uint32(os.Geteuid())
	if mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxRuntimeExecutableBytes ||
		mode&(unix.S_ISUID|unix.S_ISGID) != 0 || mode&0o022 != 0 || mode&0o100 == 0 || (stat.Uid != 0 && stat.Uid != euid) {
		return fmt.Errorf("%w: runtime executable metadata", ErrRuntimeAdmissionInvalid)
	}
	return nil
}

func validateRuntimeELF(file *os.File, size int64, target RuntimeAdmissionTarget) error {
	if file == nil || size <= 0 || size > maxRuntimeExecutableBytes {
		return ErrRuntimeAdmissionInvalid
	}
	parsed, err := elf.NewFile(io.NewSectionReader(file, 0, size))
	if err != nil {
		return fmt.Errorf("%w: invalid ELF", ErrRuntimeAdmissionInvalid)
	}
	defer parsed.Close()
	wantMachine := elf.EM_X86_64
	if target == RuntimeAdmissionLinuxARM64 {
		wantMachine = elf.EM_AARCH64
	}
	if parsed.Class != elf.ELFCLASS64 || parsed.ByteOrder.String() != "LittleEndian" || parsed.Machine != wantMachine || parsed.Type != elf.ET_DYN {
		return fmt.Errorf("%w: ELF target or PIE profile mismatch", ErrRuntimeAdmissionInvalid)
	}
	for _, program := range parsed.Progs {
		if program.Type == elf.PT_INTERP {
			return fmt.Errorf("%w: ELF interpreter is forbidden", ErrRuntimeAdmissionInvalid)
		}
	}
	needed, err := parsed.DynString(elf.DT_NEEDED)
	if err == nil && len(needed) != 0 {
		return fmt.Errorf("%w: dynamic dependencies are forbidden", ErrRuntimeAdmissionInvalid)
	}
	return nil
}

func copyRuntimeExecutableToMemfd(ctx context.Context, sourceFD, destinationFD int, size int64) (string, error) {
	hasher := sha256.New()
	buffer := make([]byte, 128<<10)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := int64(len(buffer))
		if remaining := size - offset; remaining < chunk {
			chunk = remaining
		}
		read, err := unix.Pread(sourceFD, buffer[:chunk], offset)
		if err != nil {
			return "", fmt.Errorf("%w: read runtime executable", ErrRuntimeAdmissionInvalid)
		}
		if read == 0 {
			return "", io.ErrUnexpectedEOF
		}
		written, err := unix.Pwrite(destinationFD, buffer[:read], offset)
		if err != nil || written != read {
			return "", fmt.Errorf("%w: copy runtime executable", ErrRuntimeAdmissionInvalid)
		}
		_, _ = hasher.Write(buffer[:read])
		offset += int64(read)
	}
	if err := unix.Ftruncate(destinationFD, size); err != nil {
		return "", fmt.Errorf("%w: finalize runtime executable", ErrRuntimeAdmissionInvalid)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func hashRuntimeExecutableFD(ctx context.Context, fd int, size int64) (string, error) {
	hasher := sha256.New()
	buffer := make([]byte, 128<<10)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := int64(len(buffer))
		if remaining := size - offset; remaining < chunk {
			chunk = remaining
		}
		read, err := unix.Pread(fd, buffer[:chunk], offset)
		if err != nil {
			return "", err
		}
		if read == 0 {
			return "", io.ErrUnexpectedEOF
		}
		_, _ = hasher.Write(buffer[:read])
		offset += int64(read)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
