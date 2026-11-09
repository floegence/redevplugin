package schedule

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Store, Plan, time.Time) {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "schedule.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, Plan{ID: "plan", Owner: Owner{"builtin", "alice", "env"}, Enabled: true, Cadence: Cadence{Kind: "interval", IntervalMS: 60000}, Overlap: "latest", Missed: "latest", QueueLimit: 3, Payload: json.RawMessage(`{"version":1}`)}, time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
}
func TestStableClaimIsolationAndReceipt(t *testing.T) {
	s, p, now := fixture(t)
	ctx := t.Context()
	p, e := s.Put(ctx, p, 0, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(ctx, Owner{"builtin", "bob", "env"}, p.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	if _, e = s.Put(ctx, p, 0, now); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	claims, e := s.Tick(ctx, now.Add(time.Minute), false, 10)
	if e != nil || len(claims) != 1 {
		t.Fatal(claims, e)
	}
	c := claims[0]
	if c.ID != claimID(p, now.Add(time.Minute)) {
		t.Fatal(c)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			cs, e := s.Tick(context.Background(), now.Add(time.Minute), false, 10)
			if e != nil || len(cs) != 0 {
				t.Errorf("duplicate claim %v %v", cs, e)
			}
		})
	}
	wg.Wait()
	if e = s.Accept(ctx, p.Owner, c.ID, "run-1"); e != nil {
		t.Fatal(e)
	}
	if e = s.Accept(ctx, p.Owner, c.ID, "run-1"); e != nil {
		t.Fatal(e)
	}
	if e = s.Accept(ctx, p.Owner, c.ID, "run-2"); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e = s.Resolve(ctx, p.Owner, c.ID, "completed", now); e != nil {
		t.Fatal(e)
	}
	if e = s.Resolve(ctx, p.Owner, c.ID, "failed", now); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestRestartDoesNotReplayUncertainDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := Open(path); !errors.Is(e, ErrLocked) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatalf("exclusive open: %v", e)
	}
	_, p, now := fixture(t)
	p, e = s.Put(t.Context(), p, 0, now)
	if e != nil {
		t.Fatal(e)
	}
	cs, e := s.Tick(t.Context(), now.Add(time.Minute), false, 10)
	if e != nil || len(cs) != 1 {
		t.Fatal(cs, e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	claims, e := s.Claims(t.Context(), p.Owner, p.ID)
	if e != nil || claims[0].State != "unknown" {
		t.Fatal(claims, e)
	}
	if next, e := s.Tick(t.Context(), now.Add(4*time.Minute), true, 10); e != nil || len(next) != 0 {
		t.Fatal(next, e)
	}
	if e = s.Accept(t.Context(), p.Owner, cs[0].ID, "reconciled-run"); e != nil {
		t.Fatal(e)
	}
	if e = s.Resolve(t.Context(), p.Owner, cs[0].ID, "completed", now.Add(4*time.Minute)); e != nil {
		t.Fatal(e)
	}
	next, e := s.Tick(t.Context(), now.Add(4*time.Minute), false, 10)
	if e != nil || len(next) != 1 || !next[0].ScheduledAt.Equal(now.Add(4*time.Minute)) {
		t.Fatal(next, e)
	}
}
func TestOverlapLatestAndVersionPin(t *testing.T) {
	s, p, now := fixture(t)
	p, e := s.Put(t.Context(), p, 0, now)
	if e != nil {
		t.Fatal(e)
	}
	cs, e := s.Tick(t.Context(), now.Add(time.Minute), false, 10)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = s.Tick(t.Context(), now.Add(2*time.Minute), false, 10)
	_, _ = s.Tick(t.Context(), now.Add(3*time.Minute), false, 10)
	claims, e := s.Claims(t.Context(), p.Owner, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	queued, discarded := 0, 0
	for _, c := range claims {
		if c.State == "queued" {
			queued++
			if !c.ScheduledAt.Equal(now.Add(3 * time.Minute)) {
				t.Fatal(c)
			}
		}
		if c.State == "discarded" {
			discarded++
		}
	}
	if queued != 1 || discarded != 1 {
		t.Fatal(claims)
	}
	p.Payload = json.RawMessage(`{"version":2}`)
	p, e = s.Put(t.Context(), p, p.Revision, now.Add(3*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	claims, _ = s.Claims(t.Context(), p.Owner, p.ID)
	for _, c := range claims {
		if c.State == "queued" {
			t.Fatal(c)
		}
	}
	if e = s.Accept(t.Context(), p.Owner, cs[0].ID, "run"); e != nil {
		t.Fatal(e)
	}
	if string(cs[0].Payload) != `{"version":1}` {
		t.Fatal(cs[0])
	}
}
func TestCompletionAndPause(t *testing.T) {
	s, p, now := fixture(t)
	p.Cadence.Kind = "completion"
	p, e := s.Put(t.Context(), p, 0, now)
	if e != nil {
		t.Fatal(e)
	}
	cs, e := s.Tick(t.Context(), now.Add(time.Minute), false, 10)
	if e != nil {
		t.Fatal(e)
	}
	active, _ := s.Get(t.Context(), p.Owner, p.ID)
	if !active.NextAt.IsZero() {
		t.Fatal(active)
	}
	end := now.Add(2 * time.Hour)
	if e = s.Resolve(t.Context(), p.Owner, cs[0].ID, "completed", end); e != nil {
		t.Fatal(e)
	}
	active, _ = s.Get(t.Context(), p.Owner, p.ID)
	if !active.NextAt.Equal(end.Add(time.Minute)) {
		t.Fatal(active)
	}
	active.Enabled = false
	active, e = s.Put(t.Context(), active, active.Revision, end)
	if e != nil {
		t.Fatal(e)
	}
	if cs, e = s.Tick(t.Context(), end.Add(time.Hour), false, 10); e != nil || len(cs) != 0 {
		t.Fatal(cs, e)
	}
}
func TestQueueBoundAndMissedPolicy(t *testing.T) {
	for _, missed := range []string{"latest", "skip"} {
		t.Run(missed, func(t *testing.T) {
			s, p, now := fixture(t)
			p.Missed = missed
			p.Overlap = "queue"
			_, e := s.Put(t.Context(), p, 0, now)
			if e != nil {
				t.Fatal(e)
			}
			cs, e := s.Tick(t.Context(), now.Add(10*time.Hour), true, 10)
			if e != nil {
				t.Fatal(e)
			}
			want := 1
			if missed == "skip" {
				want = 0
			}
			if len(cs) != want {
				t.Fatal(cs)
			}
		})
	}
	s, p, now := fixture(t)
	p.Overlap = "queue"
	_, e := s.Put(t.Context(), p, 0, now)
	if e != nil {
		t.Fatal(e)
	}
	cs, e := s.Tick(t.Context(), now.Add(10*time.Hour), false, 10)
	if e != nil || len(cs) != 1 {
		t.Fatal(cs, e)
	}
	all, _ := s.Claims(t.Context(), p.Owner, p.ID)
	if len(all) != p.QueueLimit {
		t.Fatal(len(all))
	}
}
func TestCalendarDSTAndInterval(t *testing.T) {
	cases := []struct {
		at           string
		hour, minute int
		want         string
	}{
		{"2026-03-08T06:00:00Z", 2, 30, "2026-03-08T07:00:00Z"},
		{"2026-11-01T04:00:00Z", 1, 30, "2026-11-01T05:30:00Z"},
		{"2026-11-01T05:45:00Z", 1, 30, "2026-11-02T06:30:00Z"},
	}
	for _, tc := range cases {
		at, _ := time.Parse(time.RFC3339, tc.at)
		c := Cadence{Kind: "daily", Timezone: "America/New_York", Hour: tc.hour, Minute: tc.minute}
		next, e := c.Next(at)
		if e != nil || next.Format(time.RFC3339) != tc.want {
			t.Fatalf("%+v: %v %v", tc, next, e)
		}
	}
	c := Cadence{Kind: "interval", IntervalMS: 3600000}
	at, _ := time.Parse(time.RFC3339, "2026-11-01T05:30:00Z")
	next, e := c.Next(at)
	if e != nil || next.Sub(at) != time.Hour {
		t.Fatal(next, e)
	}
}

func TestRejectForeignAndDriftedStoresWithoutMutation(t *testing.T) {
	for _, kind := range []string{"foreign", "future", "drift"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.sqlite")
			db, e := sql.Open("sqlite", path)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "foreign":
				_, e = db.Exec("CREATE TABLE user_data(value TEXT); INSERT INTO user_data VALUES('preserve')")
			case "future":
				_, e = db.Exec("PRAGMA user_version=99; CREATE TABLE user_data(value TEXT)")
			case "drift":
				_, e = db.Exec(schema + " CREATE TABLE unexpected(value TEXT)")
			}
			if e != nil {
				t.Fatal(e)
			}
			_ = db.Close()
			before, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			s, e := Open(path)
			if e == nil {
				_ = s.Close()
				t.Fatal("unsupported store accepted")
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected database changed", e)
			}
		})
	}
}

type fakeDispatcher struct {
	submissions []Claim
	submitErr   error
	observed    Receipt
	inspectErr  error
}

func (d *fakeDispatcher) Submit(_ context.Context, c Claim) (Receipt, error) {
	d.submissions = append(d.submissions, c)
	return Receipt{Reference: "actual-run"}, d.submitErr
}
func (d *fakeDispatcher) Inspect(context.Context, Claim) (Receipt, error) {
	return d.observed, d.inspectErr
}
func TestRunnerReconcilesRatherThanResubmitting(t *testing.T) {
	s, p, now := fixture(t)
	_, e := s.Put(t.Context(), p, 0, now)
	if e != nil {
		t.Fatal(e)
	}
	d := &fakeDispatcher{submitErr: errors.New("connection lost"), inspectErr: errors.New("offline")}
	if e = s.step(t.Context(), d, now.Add(time.Minute), false); e != nil {
		t.Fatal(e)
	}
	if len(d.submissions) != 1 {
		t.Fatal(d.submissions)
	}
	if e = s.step(t.Context(), d, now.Add(2*time.Minute), false); e != nil {
		t.Fatal(e)
	}
	if len(d.submissions) != 1 {
		t.Fatal("uncertain dispatch replayed")
	}
	d.inspectErr = nil
	d.observed = Receipt{Reference: "actual-run"}
	if e = s.step(t.Context(), d, now.Add(2*time.Minute), false); e != nil {
		t.Fatal(e)
	}
	claims, _ := s.Claims(t.Context(), p.Owner, p.ID)
	found := false
	for _, c := range claims {
		if c.ID == d.submissions[0].ID {
			found = c.State == "accepted" && c.Reference == "actual-run"
		}
	}
	if !found {
		t.Fatal(claims)
	}
}

type fairDispatcher struct{ seen map[string]bool }

func (d *fairDispatcher) Submit(context.Context, Claim) (Receipt, error) {
	return Receipt{Outcome: "unknown"}, nil
}
func (d *fairDispatcher) Inspect(_ context.Context, c Claim) (Receipt, error) {
	d.seen[c.ID] = true
	return Receipt{}, errors.New("temporarily unavailable")
}
func TestRunnerRotatesUnresolvedObservationsWithoutStarvation(t *testing.T) {
	s, p, now := fixture(t)
	p.Enabled = false
	for i := 0; i < 125; i++ {
		p.ID = fmt.Sprintf("plan-%03d", i)
		if _, err := s.Put(t.Context(), p, 0, now); err != nil {
			t.Fatal(err)
		}
		_, err := s.db.Exec("INSERT INTO schedule_claims(id,plan_id,owner,revision,due,state,payload,reference,outcome) VALUES(?,?,?,?,?,?,?,?,?)", fmt.Sprintf("claim-%03d", i), p.ID, ownerKey(p.Owner), 1, now.UnixMilli(), "unknown", string(p.Payload), "", "")
		if err != nil {
			t.Fatal(err)
		}
	}
	d := &fairDispatcher{seen: map[string]bool{}}
	for i := 0; i < 2; i++ {
		if err := s.step(t.Context(), d, now, false); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.seen) != 125 {
		t.Fatal("later claims starved", len(d.seen))
	}
}
