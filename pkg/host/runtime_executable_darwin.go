//go:build darwin

package host

import (
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"golang.org/x/sys/unix"
)

const maxRuntimeExecutableBytes int64 = 256 << 20

func (name RuntimeBinaryName) valid() bool { return name.value == "redevplugin-runtime" }

func openVerifiedExecutable(ctx context.Context, options VerifiedExecutableOptions) (*VerifiedExecutable, error) {
	if options.RootDir == nil || options.ExecutionRoot == nil || !options.RelativeName.valid() || !options.ExpectedArtifactIdentity.valid() {
		return nil, ErrRuntimeAdmissionInvalid
	}
	if err := options.ExpectedArtifactIdentity.CompatibleWithPlatform(); err != nil {
		return nil, err
	}
	rootFD, err := duplicateValidatedDarwinRuntimeDirectory(options.RootDir, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	executionRootFD, err := duplicateValidatedDarwinRuntimeDirectory(options.ExecutionRoot, true)
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

	sourceFD, err := unix.Openat(rootFD, options.RelativeName.String(), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open runtime executable", ErrRuntimeAdmissionInvalid)
	}
	source := os.NewFile(uintptr(sourceFD), options.RelativeName.String())
	if source == nil {
		unix.Close(sourceFD)
		return nil, ErrRuntimeAdmissionInvalid
	}
	closeSource := true
	defer func() {
		if closeSource {
			_ = source.Close()
		}
	}()

	var stat unix.Stat_t
	if err := unix.Fstat(sourceFD, &stat); err != nil {
		return nil, fmt.Errorf("%w: stat runtime executable", ErrRuntimeAdmissionInvalid)
	}
	if err := validateDarwinRuntimeExecutableMetadata(stat); err != nil {
		return nil, err
	}
	if err := validateRuntimeMachO(source, stat.Size, options.ExpectedArtifactIdentity.Target()); err != nil {
		return nil, err
	}
	actualDigest, err := hashDarwinRuntimeExecutable(ctx, source, stat.Size)
	if err != nil {
		return nil, err
	}
	if actualDigest != options.ExpectedArtifactIdentity.BinarySHA256().String() {
		return nil, fmt.Errorf("%w: binary digest mismatch", ErrRuntimeArtifactIdentityMismatch)
	}

	closeSource = false
	closeExecutionRoot = false
	return &VerifiedExecutable{
		state:         verifiedExecutableOwned,
		descriptor:    options.ExpectedArtifactIdentity,
		executable:    source,
		executionRoot: executionRoot,
	}, nil
}

func duplicateValidatedDarwinRuntimeDirectory(directory *os.File, requireWrite bool) (int, error) {
	if directory == nil {
		return -1, ErrRuntimeAdmissionInvalid
	}
	fd, err := unix.FcntlInt(directory.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return -1, fmt.Errorf("%w: duplicate runtime directory", ErrRuntimeAdmissionInvalid)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: stat runtime directory", ErrRuntimeAdmissionInvalid)
	}
	mode := uint32(stat.Mode)
	required := uint32(0o500)
	if requireWrite {
		required = 0o700
	}
	if mode&unix.S_IFMT != unix.S_IFDIR || mode&(unix.S_ISUID|unix.S_ISGID) != 0 || mode&0o022 != 0 || mode&required != required || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		unix.Close(fd)
		return -1, fmt.Errorf("%w: runtime directory metadata", ErrRuntimeAdmissionInvalid)
	}
	return fd, nil
}

func validateDarwinRuntimeExecutableMetadata(stat unix.Stat_t) error {
	mode := uint32(stat.Mode)
	if mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxRuntimeExecutableBytes ||
		mode&(unix.S_ISUID|unix.S_ISGID) != 0 || mode&0o022 != 0 || mode&0o100 == 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return fmt.Errorf("%w: runtime executable metadata", ErrRuntimeAdmissionInvalid)
	}
	return nil
}

func validateRuntimeMachO(file *os.File, size int64, target runtimetarget.Target) error {
	if file == nil || size <= 0 || size > maxRuntimeExecutableBytes {
		return ErrRuntimeAdmissionInvalid
	}
	parsed, err := macho.NewFile(io.NewSectionReader(file, 0, size))
	if err != nil {
		return fmt.Errorf("%w: invalid Mach-O", ErrRuntimeAdmissionInvalid)
	}
	defer parsed.Close()
	wantCPU := macho.CpuAmd64
	if target == runtimetarget.DarwinARM64 {
		wantCPU = macho.CpuArm64
	}
	if (target != runtimetarget.DarwinAMD64 && target != runtimetarget.DarwinARM64) || parsed.Magic != macho.Magic64 || parsed.Cpu != wantCPU || parsed.Type != macho.TypeExec {
		return fmt.Errorf("%w: Mach-O target mismatch", ErrRuntimeAdmissionInvalid)
	}
	return nil
}

func hashDarwinRuntimeExecutable(ctx context.Context, file *os.File, size int64) (string, error) {
	hasher := sha256.New()
	buffer := make([]byte, 128*1024)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk := int64(len(buffer))
		if remaining := size - offset; remaining < chunk {
			chunk = remaining
		}
		read, err := file.ReadAt(buffer[:chunk], offset)
		if err != nil && err != io.EOF {
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
