package schedule

import (
	"encoding/json"
	"strings"
	"time"
)

// Owner is supplied by the trusted host, never copied from an unverified body.
// Kind distinguishes built-in work from installed extensions; neither grants
// plugin identity or permission to use resources.
type Owner struct {
	Kind        string `json:"kind"`
	Subject     string `json:"subject"`
	Environment string `json:"environment"`
}

func (o Owner) valid() bool {
	return bounded(o.Kind, 80) && bounded(o.Subject, 256) && bounded(o.Environment, 256)
}
func bounded(s string, n int) bool {
	return s != "" && len(s) <= n && strings.TrimSpace(s) == s && !strings.ContainsRune(s, 0)
}

type Plan struct {
	ID         string  `json:"id"`
	Owner      Owner   `json:"owner"`
	Revision   int64   `json:"revision"`
	Enabled    bool    `json:"enabled"`
	Cadence    Cadence `json:"cadence"`
	Overlap    string  `json:"overlap"`
	Missed     string  `json:"missed"`
	QueueLimit int     `json:"queue_limit"`
	// MaxConcurrent bounds all unresolved dispatches, including unknown receipts.
	// Zero retains the original one-at-a-time behavior.
	MaxConcurrent int             `json:"max_concurrent,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	NextAt        time.Time       `json:"next_at"`
}

func (p Plan) validate() error {
	if !bounded(p.ID, 128) || !p.Owner.valid() || len(p.Payload) > 65536 || !json.Valid(p.Payload) || p.QueueLimit < 1 || p.QueueLimit > 100 {
		return ErrInvalid
	}
	if p.Overlap != "skip" && p.Overlap != "latest" && p.Overlap != "queue" && p.Overlap != "allow" {
		return ErrInvalid
	}
	if p.MaxConcurrent < 0 || p.MaxConcurrent > 16 || (p.Cadence.Kind == "completion" && p.capacity() != 1) {
		return ErrInvalid
	}
	if p.Missed != "skip" && p.Missed != "latest" {
		return ErrInvalid
	}
	return p.Cadence.Validate()
}

type Claim struct {
	ID           string          `json:"id"`
	PlanID       string          `json:"plan_id"`
	Owner        Owner           `json:"owner"`
	PlanRevision int64           `json:"plan_revision"`
	ScheduledAt  time.Time       `json:"scheduled_at"`
	State        string          `json:"state"`
	Payload      json.RawMessage `json:"payload"`
	Reference    string          `json:"reference,omitempty"`
	Outcome      string          `json:"outcome,omitempty"`
}

func (p Plan) capacity() int {
	if p.MaxConcurrent == 0 {
		return 1
	}
	return p.MaxConcurrent
}
