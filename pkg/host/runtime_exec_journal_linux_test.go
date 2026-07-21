//go:build linux

package host

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/mutation"
)

func TestRuntimeExecJournalDurablyTransitionsAndReconciles(t *testing.T) {
	directory := t.TempDir()
	root, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	descriptor := testPublicRuntimeDescriptor(t, "linux/amd64", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	journal, err := newRuntimeExecJournal(root, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.transition(runtimeExecJournalRunning, "linux-runtime-v1:pid-42:pidfd-7", mutation.OutcomeCommitted); err != nil {
		t.Fatal(err)
	}
	if err := journal.close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := newRuntimeExecJournal(root, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	raw, err := os.ReadFile(filepath.Join(directory, runtimeExecJournalFileName))
	if err != nil {
		t.Fatal(err)
	}
	var record runtimeExecJournalRecord
	if err := decodeRuntimeExecJournal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.State != runtimeExecJournalOpened || record.MutationOutcome != string(mutation.OutcomeCommitted) || record.DescriptorDigest != descriptor.BinarySHA256().String() {
		t.Fatalf("reconciled journal = %#v", record)
	}
}

func TestRuntimeExecJournalRejectsDuplicateFields(t *testing.T) {
	var record runtimeExecJournalRecord
	if err := decodeRuntimeExecJournal([]byte(`{"schema_version":"redevplugin.runtime_exec_journal.v1","schema_version":"redevplugin.runtime_exec_journal.v1"}`), &record); err == nil {
		t.Fatal("duplicate runtime journal field was accepted")
	}
}
