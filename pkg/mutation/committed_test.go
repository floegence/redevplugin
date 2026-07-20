package mutation

import (
	"errors"
	"testing"
)

func TestCommittedOutcomeIsExplicit(t *testing.T) {
	cause := errors.New("teardown requires continuation")
	err := Committed(cause)
	if outcome, ok := Explicit(err); !ok || outcome != OutcomeCommitted {
		t.Fatalf("Explicit(Committed) = %q, %v", outcome, ok)
	}
	if got := ForError(err); got != OutcomeCommitted {
		t.Fatalf("ForError(Committed) = %q", got)
	}
}

func TestForceCommittedOverridesLaterUnknownOutcome(t *testing.T) {
	err := ForceCommitted(Unknown(errors.New("audit export failed")))
	if outcome, explicit := Explicit(err); !explicit || outcome != OutcomeCommitted {
		t.Fatalf("Explicit() = %q, %v", outcome, explicit)
	}
}
