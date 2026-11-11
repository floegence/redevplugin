package schedule

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store is an exclusively owned local scheduler. It stores dispatch intentions
// and receipts, never an Agent journal or a copy of plugin execution authority.
type Store struct {
	db            *sql.DB
	lock          *os.File
	mu            sync.Mutex
	observeCursor string
	closed        bool
}

const schema = `CREATE TABLE schedule_plans (id TEXT PRIMARY KEY, owner TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE schedule_claims (id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, owner TEXT NOT NULL, revision INTEGER NOT NULL, due INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('queued','dispatching','accepted','completed','unknown','discarded')), payload TEXT NOT NULL, reference TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT '', UNIQUE(plan_id,revision,due));
CREATE INDEX schedule_claims_plan ON schedule_claims(plan_id,state,due);
PRAGMA application_id=1380201288;
PRAGMA user_version=2;`

func Open(path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := lockStore(path + ".lock")
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)

	fail := func(e error) (*Store, error) { _ = db.Close(); _ = lock.Close(); return nil, e }
	if _, err = db.Exec("PRAGMA busy_timeout=3000;"); err != nil {
		return fail(err)
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version == 0 {
		var count int
		if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&count); err != nil {
			return fail(err)
		}
		if count != 0 {
			return fail(fmt.Errorf("%w: unrecognized store", ErrInvalid))
		}
		tx, e := db.Begin()
		if e != nil {
			return fail(e)
		}
		if _, e = tx.Exec(schema); e != nil {
			_ = tx.Rollback()
			return fail(e)
		}
		if e = tx.Commit(); e != nil {
			return fail(e)
		}
	} else if version != 1 && version != 2 {
		return fail(fmt.Errorf("%w: unsupported schema %d", ErrInvalid, version))
	}
	if err = verifyStore(db); err != nil {
		return fail(err)
	}
	if version == 1 {
		// Version 2 adds bounded concurrent admission. Preserve all plan and
		// claim bytes; old readers must reject the new admission semantics.
		tx, e := db.Begin()
		if e != nil {
			return fail(e)
		}
		if _, e = tx.Exec("PRAGMA user_version=2"); e != nil {
			_ = tx.Rollback()
			return fail(e)
		}
		if e = tx.Commit(); e != nil {
			return fail(e)
		}
	}
	if _, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		return fail(err)
	}
	// An interrupted dispatch may already have affected the target. Preserve the
	// request identity and require reconciliation, never automatic redelivery.
	if _, err = db.Exec("UPDATE schedule_claims SET state='unknown',outcome='dispatch_interrupted' WHERE state='dispatching'"); err != nil {
		return fail(err)
	}
	return &Store{db: db, lock: lock}, nil
}
func verifyStore(db *sql.DB) error {
	var appID, version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if err := db.QueryRow("PRAGMA application_id").Scan(&appID); err != nil {
		return err
	}
	if appID != 1380201288 {
		return fmt.Errorf("%w: store kind", ErrInvalid)
	}
	expected := map[string]bool{}
	for _, statement := range strings.Split(schema, ";") {
		statement = strings.TrimSpace(statement)
		if strings.HasPrefix(statement, "CREATE ") {
			expected[statement] = true
		}
	}
	rows, err := db.Query("SELECT sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
	if err != nil {
		return err
	}
	for rows.Next() {
		var statement string
		if err = rows.Scan(&statement); err != nil {
			break
		}
		if !expected[statement] {
			err = fmt.Errorf("%w: schema drift", ErrInvalid)
			break
		}
		delete(expected, statement)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	if len(expected) != 0 {
		return fmt.Errorf("%w: incomplete schema", ErrInvalid)
	}
	var integrity string
	if err = db.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("%w: corrupt store", ErrInvalid)
	}
	rows, err = db.Query("SELECT id,owner,revision,body FROM schedule_plans")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, owner, body string
		var revision int64
		if err = rows.Scan(&id, &owner, &revision, &body); err != nil {
			break
		}
		var p Plan
		if err = json.Unmarshal([]byte(body), &p); err != nil {
			break
		}
		if (version == 1 && (p.MaxConcurrent != 0 || p.Overlap == "allow")) || p.validate() != nil || p.ID != id || ownerKey(p.Owner) != owner || p.Revision != revision || revision < 1 {
			err = fmt.Errorf("%w: inconsistent plan", ErrInvalid)
			break
		}
	}
	return errors.Join(err, rows.Err(), rows.Close())
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.db.Close(), s.lock.Close())
}
func ownerKey(o Owner) string { b, _ := json.Marshal(o); return string(b) }
func readPlan(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, o Owner, id string) (Plan, error) {
	var raw string
	err := q.QueryRowContext(ctx, "SELECT body FROM schedule_plans WHERE id=? AND owner=?", id, ownerKey(o)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	if err = json.Unmarshal([]byte(raw), &p); err != nil {
		return Plan{}, err
	}
	return p, p.validate()
}
func (s *Store) Get(ctx context.Context, o Owner, id string) (Plan, error) {
	if !o.valid() {
		return Plan{}, ErrNotFound
	}
	return readPlan(ctx, s.db, o, id)
}
func (s *Store) List(ctx context.Context, o Owner) ([]Plan, error) {
	if !o.valid() {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, "SELECT body FROM schedule_plans WHERE owner=? ORDER BY id", ownerKey(o))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Plan{}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p Plan
		if err = json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Put increments the plan version and discards unclaimed intentions from the old
// version. Already dispatched work retains its immutable original parameters.
func (s *Store) Put(ctx context.Context, p Plan, expected int64, now time.Time) (Plan, error) {
	if err := p.validate(); err != nil || now.IsZero() || expected < 0 {
		return Plan{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Plan{}, err
	}
	defer func() { _ = tx.Rollback() }()
	old, err := readPlan(ctx, tx, p.Owner, p.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Plan{}, err
	}
	if (err == nil && old.Revision != expected) || (errors.Is(err, ErrNotFound) && expected != 0) {
		return Plan{}, ErrConflict
	}
	p.Revision = expected + 1
	p.NextAt = time.Time{}
	if p.Enabled {
		p.NextAt, err = p.Cadence.Next(now)
		if err != nil {
			return Plan{}, err
		}
	}
	raw, _ := json.Marshal(p)
	if expected == 0 {
		_, err = tx.ExecContext(ctx, "INSERT INTO schedule_plans(id,owner,revision,body) VALUES(?,?,?,?)", p.ID, ownerKey(p.Owner), p.Revision, string(raw))
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE schedule_plans SET revision=?,body=? WHERE id=? AND owner=?", p.Revision, string(raw), p.ID, ownerKey(p.Owner))
	}
	if err != nil {
		return Plan{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE schedule_claims SET state='discarded',outcome='plan_updated' WHERE plan_id=? AND state='queued'", p.ID); err != nil {
		return Plan{}, err
	}
	if err = tx.Commit(); err != nil {
		return Plan{}, err
	}
	return p, nil
}
func claimID(p Plan, due time.Time) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d", p.ID, p.Revision, due.UnixMilli())))
	return "schedule_" + hex.EncodeToString(sum[:16])
}

// Tick records due intentions and returns at most limit newly claimed dispatches.
// startup applies the missed policy after downtime. The caller reauthorizes each
// exact claim before dispatch and records a receipt with Accept or Resolve.
func (s *Store) Tick(ctx context.Context, now time.Time, startup bool, limit int) ([]Claim, error) {
	if now.IsZero() || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, "SELECT body FROM schedule_plans ORDER BY id")
	if err != nil {
		return nil, err
	}
	plans := []Plan{}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var p Plan
		if err = json.Unmarshal([]byte(raw), &p); err != nil {
			break
		}
		plans = append(plans, p)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	out := []Claim{}
	for _, p := range plans {
		if !p.Enabled {
			continue
		}
		var active, queued int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM schedule_claims WHERE plan_id=? AND state IN ('dispatching','accepted','unknown')", p.ID).Scan(&active); err != nil {
			return nil, err
		}
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM schedule_claims WHERE plan_id=? AND state='queued'", p.ID).Scan(&queued); err != nil {
			return nil, err
		}
		if !p.NextAt.IsZero() && !now.Before(p.NextAt) {
			latest, next, e := p.Cadence.Due(p.NextAt, now)
			if e != nil {
				return nil, e
			}
			due := []time.Time{latest}
			if !startup && p.Overlap == "queue" && p.Cadence.Kind != "completion" {
				due = nil
				at := p.NextAt
				for len(due) < p.QueueLimit-queued && !at.After(now) {
					due = append(due, at)
					at, e = p.Cadence.Next(at)
					if e != nil {
						return nil, e
					}
				}
			}
			if startup && p.Missed == "skip" {
				due = nil
			}
			if active >= p.capacity() && (p.Overlap == "skip" || p.Overlap == "allow") {
				due = nil
			}
			if p.Overlap == "latest" && len(due) > 0 {
				if _, err = tx.ExecContext(ctx, "UPDATE schedule_claims SET state='discarded',outcome='coalesced' WHERE plan_id=? AND state='queued'", p.ID); err != nil {
					return nil, err
				}
				queued = 0
			}
			for _, at := range due {
				if queued >= p.QueueLimit {
					break
				}
				_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO schedule_claims(id,plan_id,owner,revision,due,state,payload) VALUES(?,?,?,?,?,'queued',?)", claimID(p, at), p.ID, ownerKey(p.Owner), p.Revision, at.UnixMilli(), string(p.Payload))
				if err != nil {
					return nil, err
				}
				queued++
			}
			p.NextAt = next
			if p.Cadence.Kind == "completion" && len(due) == 0 && active == 0 {
				p.NextAt, _ = p.Cadence.Next(now)
			}
			raw, _ := json.Marshal(p)
			if _, err = tx.ExecContext(ctx, "UPDATE schedule_plans SET body=? WHERE id=?", string(raw), p.ID); err != nil {
				return nil, err
			}
		}
		for active < p.capacity() && len(out) < limit {
			c, e := scanClaim(tx.QueryRowContext(ctx, "SELECT "+claimColumns+" FROM schedule_claims WHERE plan_id=? AND state='queued' ORDER BY due,id LIMIT 1", p.ID))
			if errors.Is(e, ErrNotFound) {
				break
			}
			if e != nil {
				return nil, e
			}
			if _, err = tx.ExecContext(ctx, "UPDATE schedule_claims SET state='dispatching' WHERE id=? AND state='queued'", c.ID); err != nil {
				return nil, err
			}
			c.State = "dispatching"
			out = append(out, c)
			active++
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

const claimColumns = "id,plan_id,owner,revision,due,state,payload,reference,outcome"

func scanClaim(row interface{ Scan(...any) error }) (Claim, error) {
	var c Claim
	var owner, raw string
	var due int64
	err := row.Scan(&c.ID, &c.PlanID, &owner, &c.PlanRevision, &due, &c.State, &raw, &c.Reference, &c.Outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal([]byte(owner), &c.Owner); err != nil {
		return c, err
	}
	c.Payload = json.RawMessage(raw)
	c.ScheduledAt = time.UnixMilli(due).UTC()
	return c, nil
}
func (s *Store) Claims(ctx context.Context, o Owner, plan string) ([]Claim, error) {
	if !o.valid() {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+claimColumns+" FROM schedule_claims WHERE owner=? AND plan_id=? ORDER BY due DESC,id LIMIT 1000", ownerKey(o), plan)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Claim{}
	for rows.Next() {
		c, e := scanClaim(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Accept records an authoritative dispatch receipt. Reconciliation may call it
// after restart only with the original downstream request identity.
func (s *Store) Accept(ctx context.Context, o Owner, id, reference string) error {
	if !o.valid() || !bounded(reference, 512) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := scanClaim(s.db.QueryRowContext(ctx, "SELECT "+claimColumns+" FROM schedule_claims WHERE owner=? AND id=?", ownerKey(o), id))
	if err != nil {
		return err
	}
	if c.State == "accepted" && c.Reference == reference {
		return nil
	}
	if (c.State != "dispatching" && c.State != "unknown") || (c.Reference != "" && c.Reference != reference) {
		return ErrConflict
	}
	_, err = s.db.ExecContext(ctx, "UPDATE schedule_claims SET state='accepted',reference=?,outcome='' WHERE id=?", reference, id)
	return err
}

// Resolve preserves unknown effects as blockers. Completed/failed/not_committed
// are confirmed target outcomes, never deductions from a transport error.
func (s *Store) Resolve(ctx context.Context, o Owner, id, outcome string, now time.Time) error {
	if !o.valid() || now.IsZero() {
		return ErrInvalid
	}
	if outcome != "completed" && outcome != "failed" && outcome != "canceled" && outcome != "not_committed" && outcome != "unknown" {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	c, err := scanClaim(tx.QueryRowContext(ctx, "SELECT "+claimColumns+" FROM schedule_claims WHERE id=? AND owner=?", id, ownerKey(o)))
	if err != nil {
		return err
	}
	if c.State == "completed" {
		if c.Outcome == outcome {
			return nil
		}
		return ErrConflict
	}
	if c.State == "queued" || c.State == "discarded" {
		return ErrConflict
	}
	state := "completed"
	if outcome == "unknown" {
		state = "unknown"
	}
	if _, err = tx.ExecContext(ctx, "UPDATE schedule_claims SET state=?,outcome=? WHERE id=?", state, outcome, id); err != nil {
		return err
	}
	p, err := readPlan(ctx, tx, o, c.PlanID)
	if err != nil {
		return err
	}
	if state == "completed" && p.Enabled && p.Cadence.Kind == "completion" && p.NextAt.IsZero() {
		p.NextAt, _ = p.Cadence.Next(now)
		raw, _ := json.Marshal(p)
		if _, err = tx.ExecContext(ctx, "UPDATE schedule_plans SET body=? WHERE id=?", string(raw), p.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
