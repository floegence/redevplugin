//go:build linux

package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"

	"github.com/floegence/redevplugin/pkg/mutation"
	"golang.org/x/sys/unix"
)

var runtimeExecJournalIdentifier = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,256}$`)

type linuxRuntimeExecJournal struct {
	mu               sync.Mutex
	rootFD           int
	moduleID         string
	descriptorDigest string
	sequence         uint64
	closed           bool
}

type runtimeExecJournalRecord struct {
	SchemaVersion       string `json:"schema_version"`
	ModuleID            string `json:"module_id"`
	DescriptorDigest    string `json:"descriptor_digest"`
	State               string `json:"state"`
	ContainmentIdentity string `json:"containment_identity"`
	MutationOutcome     string `json:"mutation_outcome"`
}

func newRuntimeExecJournal(root *os.File, descriptor RuntimeDescriptor) (runtimeExecJournal, error) {
	if root == nil || !descriptor.valid() {
		return nil, ErrRuntimeAdmissionInvalid
	}
	rootFD, err := unix.FcntlInt(root.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: duplicate runtime execution root", ErrRuntimeAdmissionInvalid)
	}
	journal := &linuxRuntimeExecJournal{
		rootFD:           rootFD,
		moduleID:         "runtime-" + descriptor.BinarySHA256().String(),
		descriptorDigest: descriptor.BinarySHA256().String(),
	}
	if err := journal.reconcilePrevious(); err != nil {
		_ = unix.Close(rootFD)
		return nil, err
	}
	if err := journal.transition(runtimeExecJournalOpened, runtimeExecContainmentPending, mutation.OutcomeCommitted); err != nil {
		_ = journal.close()
		return nil, err
	}
	return journal, nil
}

func (journal *linuxRuntimeExecJournal) transition(state, containmentIdentity string, outcome mutation.Outcome) error {
	if journal == nil {
		return ErrRuntimeAdmissionInvalid
	}
	if !validRuntimeExecJournalState(state) || !runtimeExecJournalIdentifier.MatchString(containmentIdentity) ||
		(outcome != mutation.OutcomeCommitted && outcome != mutation.OutcomeNotCommitted && outcome != mutation.OutcomeUnknown) {
		return ErrRuntimeAdmissionInvalid
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed || journal.rootFD < 0 {
		return ErrRuntimeAdmissionInvalid
	}
	journal.sequence++
	return journal.writeLocked(runtimeExecJournalRecord{
		SchemaVersion:       runtimeExecJournalSchemaVersion,
		ModuleID:            journal.moduleID,
		DescriptorDigest:    journal.descriptorDigest,
		State:               state,
		ContainmentIdentity: containmentIdentity,
		MutationOutcome:     string(outcome),
	})
}

func (journal *linuxRuntimeExecJournal) close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed {
		return nil
	}
	journal.closed = true
	if journal.rootFD < 0 {
		return nil
	}
	err := unix.Close(journal.rootFD)
	journal.rootFD = -1
	return err
}

func (journal *linuxRuntimeExecJournal) reconcilePrevious() error {
	previous, exists, err := readRuntimeExecJournal(journal.rootFD)
	if err != nil {
		return err
	}
	if !exists || previous.State == runtimeExecJournalClosed {
		return nil
	}
	if err := journal.writeLocked(runtimeExecJournalRecord{
		SchemaVersion:       runtimeExecJournalSchemaVersion,
		ModuleID:            previous.ModuleID,
		DescriptorDigest:    previous.DescriptorDigest,
		State:               runtimeExecJournalReconcileRequired,
		ContainmentIdentity: previous.ContainmentIdentity,
		MutationOutcome:     string(mutation.OutcomeUnknown),
	}); err != nil {
		return err
	}
	return journal.writeLocked(runtimeExecJournalRecord{
		SchemaVersion:       runtimeExecJournalSchemaVersion,
		ModuleID:            previous.ModuleID,
		DescriptorDigest:    previous.DescriptorDigest,
		State:               runtimeExecJournalClosed,
		ContainmentIdentity: previous.ContainmentIdentity,
		MutationOutcome:     string(mutation.OutcomeCommitted),
	})
}

func (journal *linuxRuntimeExecJournal) writeLocked(record runtimeExecJournalRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("%w: encode runtime execution journal", ErrRuntimeAdmissionInvalid)
	}
	payload = append(payload, '\n')
	temporaryName := fmt.Sprintf(".%s.%d.%d.tmp", runtimeExecJournalFileName, os.Getpid(), journal.sequence)
	fd, err := unix.Openat(journal.rootFD, temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create runtime execution journal", ErrRuntimeAdmissionInvalid)
	}
	cleanup := true
	defer func() {
		_ = unix.Close(fd)
		if cleanup {
			_ = unix.Unlinkat(journal.rootFD, temporaryName, 0)
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("%w: chmod runtime execution journal", ErrRuntimeAdmissionInvalid)
	}
	for written := 0; written < len(payload); {
		count, writeErr := unix.Write(fd, payload[written:])
		if writeErr != nil || count <= 0 {
			return fmt.Errorf("%w: write runtime execution journal", ErrRuntimeAdmissionInvalid)
		}
		written += count
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("%w: fsync runtime execution journal", ErrRuntimeAdmissionInvalid)
	}
	if err := unix.Renameat(journal.rootFD, temporaryName, journal.rootFD, runtimeExecJournalFileName); err != nil {
		return fmt.Errorf("%w: replace runtime execution journal", ErrRuntimeAdmissionInvalid)
	}
	cleanup = false
	if err := unix.Fsync(journal.rootFD); err != nil {
		return fmt.Errorf("%w: fsync runtime execution root", ErrRuntimeAdmissionInvalid)
	}
	return nil
}

func readRuntimeExecJournal(rootFD int) (runtimeExecJournalRecord, bool, error) {
	fd, err := unix.Openat(rootFD, runtimeExecJournalFileName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return runtimeExecJournalRecord{}, false, nil
	}
	if err != nil {
		return runtimeExecJournalRecord{}, false, fmt.Errorf("%w: open runtime execution journal", ErrRuntimeAdmissionInvalid)
	}
	file := os.NewFile(uintptr(fd), runtimeExecJournalFileName)
	if file == nil {
		_ = unix.Close(fd)
		return runtimeExecJournalRecord{}, false, ErrRuntimeAdmissionInvalid
	}
	defer file.Close()
	var stat unix.Stat_t
	euid := uint32(os.Geteuid())
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 4096 || stat.Mode&0o077 != 0 || (stat.Uid != 0 && stat.Uid != euid) {
		return runtimeExecJournalRecord{}, false, ErrRuntimeAdmissionInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(payload) == 0 || len(payload) > 4096 {
		return runtimeExecJournalRecord{}, false, ErrRuntimeAdmissionInvalid
	}
	var record runtimeExecJournalRecord
	if err := decodeRuntimeExecJournal(payload, &record); err != nil || !validRuntimeExecJournalRecord(record) {
		return runtimeExecJournalRecord{}, false, ErrRuntimeAdmissionInvalid
	}
	return record, true, nil
}

func decodeRuntimeExecJournal(payload []byte, record *runtimeExecJournalRecord) error {
	if err := rejectDuplicateRuntimeExecJournalFields(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(record); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("runtime execution journal contains trailing JSON")
		}
		return err
	}
	return nil
}

func rejectDuplicateRuntimeExecJournalFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("runtime execution journal must be an object")
	}
	seen := make(map[string]struct{}, 6)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("runtime execution journal key is not a string")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate runtime execution journal field %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func validRuntimeExecJournalRecord(record runtimeExecJournalRecord) bool {
	return record.SchemaVersion == runtimeExecJournalSchemaVersion &&
		runtimeExecJournalIdentifier.MatchString(record.ModuleID) &&
		len(record.DescriptorDigest) == 64 && lowerSHA256Pattern.MatchString(record.DescriptorDigest) &&
		validRuntimeExecJournalState(record.State) &&
		runtimeExecJournalIdentifier.MatchString(record.ContainmentIdentity) &&
		(record.MutationOutcome == string(mutation.OutcomeCommitted) || record.MutationOutcome == string(mutation.OutcomeNotCommitted) || record.MutationOutcome == string(mutation.OutcomeUnknown))
}

func validRuntimeExecJournalState(state string) bool {
	switch state {
	case runtimeExecJournalOpened, runtimeExecJournalConsumed, runtimeExecJournalBound, runtimeExecJournalRunning,
		runtimeExecJournalStopping, runtimeExecJournalClosed, runtimeExecJournalReconcileRequired:
		return true
	default:
		return false
	}
}
