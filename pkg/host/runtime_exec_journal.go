package host

import (
	"errors"

	"github.com/floegence/redevplugin/pkg/mutation"
)

const (
	runtimeExecJournalSchemaVersion = "redevplugin.runtime_exec_journal.v1"
	runtimeExecJournalFileName      = "runtime-exec-v1.json"
	runtimeExecContainmentPending   = "not-started"
)

const (
	runtimeExecJournalOpened            = "opened"
	runtimeExecJournalConsumed          = "consumed"
	runtimeExecJournalBound             = "bound"
	runtimeExecJournalRunning           = "running"
	runtimeExecJournalStopping          = "stopping"
	runtimeExecJournalClosed            = "closed"
	runtimeExecJournalReconcileRequired = "reconcile_required"
)

// runtimeExecJournal is deliberately private: it records Host-observed
// containment ownership and recovery state, not a host-configurable policy.
type runtimeExecJournal interface {
	transition(state, containmentIdentity string, outcome mutation.Outcome) error
	close() error
}

func finalizeRuntimeExecJournal(journal runtimeExecJournal, containmentIdentity string, operationErr error) error {
	if journal == nil {
		return operationErr
	}
	state := runtimeExecJournalClosed
	outcome := mutation.OutcomeCommitted
	if operationErr != nil {
		state = runtimeExecJournalReconcileRequired
		outcome = mutation.OutcomeUnknown
	}
	return errors.Join(
		operationErr,
		journal.transition(state, containmentIdentity, outcome),
		journal.close(),
	)
}
