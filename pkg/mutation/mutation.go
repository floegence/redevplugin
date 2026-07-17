package mutation

import "errors"

type Outcome string

const (
	OutcomeCommitted    Outcome = "committed"
	OutcomeNotCommitted Outcome = "not_committed"
	OutcomeUnknown      Outcome = "unknown"
)

type Error struct {
	Outcome Outcome
	Err     error
}

func (e *Error) Error() string {
	if e == nil || e.Err == nil {
		return "mutation failed"
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func Explicit(err error) (Outcome, bool) {
	var mutationErr *Error
	if errors.As(err, &mutationErr) &&
		(mutationErr.Outcome == OutcomeNotCommitted || mutationErr.Outcome == OutcomeUnknown) {
		return mutationErr.Outcome, true
	}
	return "", false
}

func ForError(err error) Outcome {
	if outcome, ok := Explicit(err); ok {
		return outcome
	}
	return OutcomeNotCommitted
}

func Unknown(err error) error {
	if err == nil {
		return nil
	}
	if _, explicit := Explicit(err); explicit {
		return err
	}
	return &Error{Outcome: OutcomeUnknown, Err: err}
}
