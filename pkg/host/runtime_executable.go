package host

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/floegence/redevplugin/pkg/mutation"
)

const maxRuntimeExecutableBytes int64 = 256 << 20

var (
	ErrRuntimeAdmissionUnsupported = errors.New("runtime admission is unsupported on this platform")
	ErrRuntimeAdmissionInvalid     = errors.New("runtime executable admission failed")
	ErrVerifiedExecutableClosed    = errors.New("verified runtime executable is closed")
)

type MutationOutcome = mutation.Outcome

const (
	MutationOutcomeCommitted    = mutation.OutcomeCommitted
	MutationOutcomeNotCommitted = mutation.OutcomeNotCommitted
	MutationOutcomeUnknown      = mutation.OutcomeUnknown
)

type VerifiedExecutableOptions struct {
	RootDir            *os.File
	ExecutionRoot      *os.File
	RelativeName       RuntimeBinaryName
	ExpectedDescriptor RuntimeDescriptor
}

type verifiedExecutableState uint8

const (
	verifiedExecutableOwned verifiedExecutableState = iota + 1
	verifiedExecutableModuleOwned
	verifiedExecutableClosed
)

// VerifiedExecutable is an owned, sealed runtime executable capability. The
// underlying file descriptors are never exposed to callers.
type VerifiedExecutable struct {
	mu            sync.Mutex
	state         verifiedExecutableState
	descriptor    RuntimeDescriptor
	executable    *os.File
	executionRoot *os.File
}

func OpenVerifiedExecutable(ctx context.Context, options VerifiedExecutableOptions) (*VerifiedExecutable, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openVerifiedExecutable(ctx, options)
}

func (executable *VerifiedExecutable) Descriptor() RuntimeDescriptor {
	if executable == nil {
		return RuntimeDescriptor{}
	}
	executable.mu.Lock()
	defer executable.mu.Unlock()
	if executable.state == verifiedExecutableClosed {
		return RuntimeDescriptor{}
	}
	return executable.descriptor
}

func (executable *VerifiedExecutable) Close() (MutationOutcome, error) {
	if executable == nil {
		return MutationOutcomeNotCommitted, nil
	}
	executable.mu.Lock()
	defer executable.mu.Unlock()
	if executable.state == verifiedExecutableModuleOwned {
		return MutationOutcomeNotCommitted, ErrVerifiedExecutableClosed
	}
	if executable.state == verifiedExecutableClosed {
		return MutationOutcomeNotCommitted, nil
	}
	executable.state = verifiedExecutableClosed
	err := errors.Join(closeRuntimeFile(executable.executable), closeRuntimeFile(executable.executionRoot))
	executable.executable = nil
	executable.executionRoot = nil
	if err != nil {
		return MutationOutcomeUnknown, err
	}
	return MutationOutcomeCommitted, nil
}

func closeRuntimeFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Close()
}
