package mutation

import (
	"errors"
	"testing"
)

func TestUnknownPreservesExplicitOutcome(t *testing.T) {
	cause := errors.New("adapter failure")
	for _, outcome := range []Outcome{OutcomeNotCommitted, OutcomeUnknown} {
		explicit := &Error{Outcome: outcome, Err: cause}
		if got := Unknown(explicit); got != explicit {
			t.Fatalf("Unknown(%s) replaced explicit outcome: %v", outcome, got)
		}
	}
	if outcome := ForError(Unknown(cause)); outcome != OutcomeUnknown {
		t.Fatalf("Unknown(raw) outcome = %q, want %q", outcome, OutcomeUnknown)
	}
}

func TestCommittedOutcomeIsStable(t *testing.T) {
	if OutcomeCommitted != "committed" {
		t.Fatalf("committed outcome = %q", OutcomeCommitted)
	}
}
