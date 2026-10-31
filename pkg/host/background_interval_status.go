package host

import (
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

// BackgroundIntervalStatus is an owner-scoped observation, never a handle that
// can claim or replay work. Enable/disable retain their existing semantics.
type BackgroundIntervalStatus struct {
	State          string     `json:"state"`
	IntervalMS     int        `json:"interval_ms"`
	MaxRuntimeMS   int        `json:"max_runtime_ms"`
	NextRunAt      *time.Time `json:"next_run_at,omitempty"`
	LastStartedAt  *time.Time `json:"last_started_at,omitempty"`
	LastFinishedAt *time.Time `json:"last_finished_at,omitempty"`
	LastOutcome    string     `json:"last_outcome,omitempty"`
}

func (h *Host) intervalStatus(record registry.PluginRecord, plans []controlstore.IntervalPlan) *BackgroundIntervalStatus {
	entry := record.Manifest.Background
	if entry == nil || entry.Strategy != manifest.BackgroundInterval {
		return nil
	}
	status := &BackgroundIntervalStatus{State: "stopped", IntervalMS: entry.IntervalMS, MaxRuntimeMS: entry.MaxRuntimeMS}
	if record.EnableState != registry.EnableEnabled {
		return status
	}
	status.State = "scheduled"
	if h.backgroundIntervals == nil || h.backgroundPolicy == nil {
		status.State = "blocked"
	}
	for _, plan := range plans {
		if !intervalRecordMatches(plan, record) {
			continue
		}
		if status.State != "blocked" {
			next := plan.NextRun
			status.NextRunAt = &next
			if plan.ClaimID != "" {
				status.State = "running"
				status.NextRunAt = nil
			} else if plan.Outcome == "blocked" {
				status.State = "blocked"
			}
		}
		if !plan.ClaimedAt.IsZero() {
			value := plan.ClaimedAt
			status.LastStartedAt = &value
		}
		if !plan.FinishedAt.IsZero() {
			value := plan.FinishedAt
			status.LastFinishedAt = &value
		}
		status.LastOutcome = plan.Outcome
		break
	}
	return status
}
