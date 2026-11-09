package schedule

import (
	"context"
	"errors"
	"time"
)

// Receipt describes facts observed at the target. An error never proves absence.
type Receipt struct {
	Reference string
	Outcome   string
}

// Dispatcher reauthorizes every dispatch and observation against the current
// host-owned grant. Submit uses Claim.ID as the stable downstream request ID.
// Inspect reconciles both accepted and uncertain submissions without replay.
type Dispatcher interface {
	Submit(context.Context, Claim) (Receipt, error)
	Inspect(context.Context, Claim) (Receipt, error)
}

// Run owns the bounded polling lifecycle. Submit must return an admission
// receipt promptly; long-lived work is observed through Inspect. Canceling the
// loop never asserts that work in the target has stopped.
func (s *Store) Run(ctx context.Context, d Dispatcher, report func(error)) error {
	if d == nil {
		return ErrInvalid
	}
	startup := true
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		now := time.Now().UTC()
		if err := s.step(ctx, d, now, startup); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if report != nil {
				report(err)
			}
		}
		startup = false
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
func (s *Store) step(ctx context.Context, d Dispatcher, now time.Time, startup bool) error {
	s.mu.Lock()
	cursor := s.observeCursor
	s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, "SELECT "+claimColumns+" FROM schedule_claims WHERE state IN ('accepted','unknown') AND id>? ORDER BY id LIMIT 100", cursor)
	if err != nil {
		return err
	}
	active := []Claim{}
	for rows.Next() {
		c, e := scanClaim(rows)
		if e != nil {
			err = e
			break
		}
		active = append(active, c)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.observeCursor = ""
	if len(active) == 100 {
		s.observeCursor = active[len(active)-1].ID
	}
	s.mu.Unlock()
	for _, c := range active {
		observeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		receipt, e := d.Inspect(observeCtx, c)
		cancel()
		if e != nil {
			continue
		} // Unavailable observation retains the existing fact.
		if e = s.record(ctx, c, receipt, now); e != nil {
			return e
		}
	}
	claims, err := s.Tick(ctx, now, startup, 16)
	if err != nil {
		return err
	}
	for _, c := range claims {
		submitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		receipt, e := d.Submit(submitCtx, c)
		cancel()
		if e != nil {
			receipt = Receipt{Outcome: "unknown"}
		}
		if err = s.record(ctx, c, receipt, now); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) record(ctx context.Context, c Claim, r Receipt, now time.Time) error {
	if c.Reference != "" && r.Reference != "" && c.Reference != r.Reference {
		return ErrConflict
	}
	if r.Reference != "" && c.State != "accepted" {
		if err := s.Accept(ctx, c.Owner, c.ID, r.Reference); err != nil {
			return err
		}
	}
	if r.Outcome != "" {
		return s.Resolve(ctx, c.Owner, c.ID, r.Outcome, now)
	}
	if r.Reference == "" {
		return s.Resolve(ctx, c.Owner, c.ID, "unknown", now)
	}
	return nil
}
