package controlstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

// IntervalPlan records scheduling, never execution authority. Every claimed
// invocation must reauthorize the installed package through the Host.
type IntervalPlan struct {
	OwnerEnvHash, PluginInstanceID, ActiveFingerprint string
	ManagementRevision, PolicyRevision, RevokeEpoch   uint64
	IntervalMS, MaxRuntimeMS                          int
	NextRun                                           time.Time
	ClaimID                                           string
	ClaimedAt, FinishedAt                             time.Time
	Outcome                                           string
}

func migrateBackgroundIntervals(ctx context.Context, q dataHistoryMigrator) error {
	if _, err := q.ExecContext(ctx, "CREATE TABLE background_intervals (owner_env_hash TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, active_fingerprint TEXT NOT NULL, management_revision INTEGER NOT NULL, policy_revision INTEGER NOT NULL, revoke_epoch INTEGER NOT NULL, interval_ms INTEGER NOT NULL CHECK(interval_ms BETWEEN 1000 AND 86400000), max_runtime_ms INTEGER NOT NULL CHECK(max_runtime_ms BETWEEN 1 AND 300000 AND max_runtime_ms<=interval_ms), next_run INTEGER NOT NULL, claim_id TEXT NOT NULL DEFAULT '', claimed_at INTEGER NOT NULL DEFAULT 0, finished_at INTEGER NOT NULL DEFAULT 0, outcome TEXT NOT NULL DEFAULT '' CHECK(outcome IN ('','success','failed','unknown','blocked','canceled')), PRIMARY KEY(owner_env_hash,plugin_instance_id), FOREIGN KEY(owner_env_hash,plugin_instance_id) REFERENCES plugin_records(owner_env_hash,plugin_instance_id) ON DELETE CASCADE)"); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, "UPDATE control_schema SET version=5 WHERE id=1 AND version=4")
	return err
}

// ReconcileIntervals derives plans from installed packages, without using a
// user session or the compilation-only startup prewarm inventory.
func (s *Store) ReconcileIntervals(ctx context.Context, now time.Time) error {
	if !s.Ready() {
		return ErrRequestsBlocked
	}
	if now.IsZero() {
		return errors.New("interval reconciliation requires time")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, "SELECT owner_env_hash,plugin_instance_id,active_fingerprint,management_revision,policy_revision,revoke_epoch,record_json FROM plugin_records WHERE state='enabled' AND deleted_at IS NULL AND json_extract(record_json,'$.manifest.background.strategy')='interval'")
	if err != nil {
		return err
	}
	var records []registry.PluginRecord
	for rows.Next() {
		var owner, instance, fingerprint, raw string
		var management, policy, epoch uint64
		if err = rows.Scan(&owner, &instance, &fingerprint, &management, &policy, &epoch, &raw); err != nil {
			break
		}
		var record registry.PluginRecord
		record, err = decodeRegistryPluginRecord([]byte(raw))
		if err != nil {
			break
		}
		if record.PluginInstanceID != instance || record.ActiveFingerprint != fingerprint || record.ManagementRevision != management || record.PolicyRevision != policy || record.RevokeEpoch != epoch || record.EnableState != registry.EnableEnabled || record.DeletedAt != nil {
			err = fmt.Errorf("%w: interval package binding is inconsistent", ErrIncompatible)
			break
		}
		record.OwnerEnvHash = owner
		if record.Manifest.Background != nil && record.Manifest.Background.Strategy == manifest.BackgroundInterval && registry.RunnablePluginRecord(record) {
			records = append(records, record)
		}
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	plans, err := readIntervalPlans(ctx, tx, "")
	if err != nil {
		return err
	}
	existing := make(map[string]IntervalPlan, len(plans))
	for _, plan := range plans {
		existing[plan.OwnerEnvHash+"\x00"+plan.PluginInstanceID] = plan
	}
	valid := make(map[string]bool, len(records))
	for _, record := range records {
		valid[record.OwnerEnvHash+"\x00"+record.PluginInstanceID] = true
		entry := record.Manifest.Background
		if current, ok := existing[record.OwnerEnvHash+"\x00"+record.PluginInstanceID]; ok && current.ActiveFingerprint == record.ActiveFingerprint && current.ManagementRevision == record.ManagementRevision && current.PolicyRevision == record.PolicyRevision && current.RevokeEpoch == record.RevokeEpoch {
			if current.IntervalMS != entry.IntervalMS || current.MaxRuntimeMS != entry.MaxRuntimeMS {
				return fmt.Errorf("%w: interval limits differ from installed package", ErrIncompatible)
			}
			continue
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO background_intervals(owner_env_hash,plugin_instance_id,active_fingerprint,management_revision,policy_revision,revoke_epoch,interval_ms,max_runtime_ms,next_run) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_env_hash,plugin_instance_id) DO UPDATE SET active_fingerprint=excluded.active_fingerprint,management_revision=excluded.management_revision,policy_revision=excluded.policy_revision,revoke_epoch=excluded.revoke_epoch,interval_ms=excluded.interval_ms,max_runtime_ms=excluded.max_runtime_ms,next_run=excluded.next_run,claim_id='',claimed_at=0,finished_at=0,outcome='' WHERE background_intervals.active_fingerprint!=excluded.active_fingerprint OR background_intervals.management_revision!=excluded.management_revision OR background_intervals.policy_revision!=excluded.policy_revision OR background_intervals.revoke_epoch!=excluded.revoke_epoch", record.OwnerEnvHash, record.PluginInstanceID, record.ActiveFingerprint, record.ManagementRevision, record.PolicyRevision, record.RevokeEpoch, entry.IntervalMS, entry.MaxRuntimeMS, now.Add(time.Duration(entry.IntervalMS)*time.Millisecond).UnixMilli())
		if err != nil {
			return err
		}
	}
	for _, plan := range plans {
		if !valid[plan.OwnerEnvHash+"\x00"+plan.PluginInstanceID] {
			if _, err := tx.ExecContext(ctx, "DELETE FROM background_intervals WHERE owner_env_hash=? AND plugin_instance_id=?", plan.OwnerEnvHash, plan.PluginInstanceID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func readIntervalPlans(ctx context.Context, q schemaReader, where string, args ...any) ([]IntervalPlan, error) {
	rows, err := q.QueryContext(ctx, "SELECT owner_env_hash,plugin_instance_id,active_fingerprint,management_revision,policy_revision,revoke_epoch,interval_ms,max_runtime_ms,next_run,claim_id,claimed_at,finished_at,outcome FROM background_intervals "+where+" ORDER BY owner_env_hash,plugin_instance_id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := make([]IntervalPlan, 0)
	for rows.Next() {
		var plan IntervalPlan
		var next, claimed, finished int64
		if err := rows.Scan(&plan.OwnerEnvHash, &plan.PluginInstanceID, &plan.ActiveFingerprint, &plan.ManagementRevision, &plan.PolicyRevision, &plan.RevokeEpoch, &plan.IntervalMS, &plan.MaxRuntimeMS, &next, &plan.ClaimID, &claimed, &finished, &plan.Outcome); err != nil {
			return nil, err
		}
		plan.NextRun = time.UnixMilli(next).UTC()
		if claimed != 0 {
			plan.ClaimedAt = time.UnixMilli(claimed).UTC()
		}
		if finished != 0 {
			plan.FinishedAt = time.UnixMilli(finished).UTC()
		}
		if err := validateIntervalPlan(plan); err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

func (s *Store) IntervalPlans(ctx context.Context) ([]IntervalPlan, error) {
	if !s.Ready() {
		return nil, ErrRequestsBlocked
	}
	return readIntervalPlans(ctx, s.db, "")
}

func (s *Store) OwnerIntervalPlans(ctx context.Context, owner string) ([]IntervalPlan, error) {
	if !s.Ready() {
		return nil, ErrRequestsBlocked
	}
	if owner == "" {
		return nil, errors.New("interval owner is required")
	}
	return readIntervalPlans(ctx, s.db, "WHERE owner_env_hash=?", owner)
}

func (s *Store) ValidateIntervalClaim(ctx context.Context, plan IntervalPlan) error {
	if !s.Ready() {
		return ErrRequestsBlocked
	}
	if plan.ClaimID == "" {
		return ErrRevisionConflict
	}
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM background_intervals WHERE owner_env_hash=? AND plugin_instance_id=? AND active_fingerprint=? AND management_revision=? AND policy_revision=? AND revoke_epoch=? AND claim_id=? AND interval_ms=? AND max_runtime_ms=?", plan.OwnerEnvHash, plan.PluginInstanceID, plan.ActiveFingerprint, plan.ManagementRevision, plan.PolicyRevision, plan.RevokeEpoch, plan.ClaimID, plan.IntervalMS, plan.MaxRuntimeMS).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func validateIntervalPlan(plan IntervalPlan) error {
	invalid := plan.OwnerEnvHash == "" || plan.PluginInstanceID == "" || plan.ActiveFingerprint == "" || plan.ManagementRevision == 0 || plan.IntervalMS < 1000 || plan.IntervalMS > 86400000 || plan.MaxRuntimeMS < 1 || plan.MaxRuntimeMS > 300000 || plan.MaxRuntimeMS > plan.IntervalMS || plan.NextRun.UnixMilli() <= 0
	if plan.ClaimID != "" {
		raw, err := hex.DecodeString(plan.ClaimID)
		invalid = invalid || err != nil || len(raw) != 24 || plan.ClaimedAt.IsZero()
	}
	switch plan.Outcome {
	case "", "success", "failed", "unknown", "blocked", "canceled":
	default:
		invalid = true
	}
	if invalid {
		return fmt.Errorf("%w: invalid durable interval state", ErrIncompatible)
	}
	return nil
}

// ClaimInterval commits one durable identity before any plugin code can run.
func (s *Store) ClaimInterval(ctx context.Context, plan IntervalPlan, now time.Time) (IntervalPlan, bool, error) {
	if !s.Ready() {
		return IntervalPlan{}, false, ErrRequestsBlocked
	}
	if now.IsZero() {
		return IntervalPlan{}, false, errors.New("interval claim requires time")
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return IntervalPlan{}, false, err
	}
	plan.ClaimID = hex.EncodeToString(nonce[:])
	plan.ClaimedAt = now
	result, err := s.db.ExecContext(ctx, "UPDATE background_intervals SET claim_id=?,claimed_at=? WHERE owner_env_hash=? AND plugin_instance_id=? AND active_fingerprint=? AND management_revision=? AND policy_revision=? AND revoke_epoch=? AND interval_ms=? AND max_runtime_ms=? AND next_run=? AND claim_id='' AND next_run<=? AND EXISTS(SELECT 1 FROM plugin_records p WHERE p.owner_env_hash=background_intervals.owner_env_hash AND p.plugin_instance_id=background_intervals.plugin_instance_id AND p.active_fingerprint=background_intervals.active_fingerprint AND p.management_revision=background_intervals.management_revision AND p.policy_revision=background_intervals.policy_revision AND p.revoke_epoch=background_intervals.revoke_epoch AND p.state='enabled' AND p.deleted_at IS NULL)", plan.ClaimID, now.UnixMilli(), plan.OwnerEnvHash, plan.PluginInstanceID, plan.ActiveFingerprint, plan.ManagementRevision, plan.PolicyRevision, plan.RevokeEpoch, plan.IntervalMS, plan.MaxRuntimeMS, plan.NextRun.UnixMilli(), now.UnixMilli())
	if err != nil {
		return IntervalPlan{}, false, err
	}
	n, err := result.RowsAffected()
	return plan, n == 1, err
}

func (s *Store) FinishInterval(ctx context.Context, plan IntervalPlan, now time.Time, outcome string) (bool, error) {
	if !s.Ready() {
		return false, ErrRequestsBlocked
	}
	if plan.ClaimID == "" || now.IsZero() {
		return false, errors.New("interval completion requires claim and time")
	}
	result, err := s.db.ExecContext(ctx, "UPDATE background_intervals SET next_run=?,claim_id='',finished_at=?,outcome=? WHERE owner_env_hash=? AND plugin_instance_id=? AND active_fingerprint=? AND management_revision=? AND policy_revision=? AND revoke_epoch=? AND claim_id=? AND interval_ms=? AND max_runtime_ms=?", now.Add(time.Duration(plan.IntervalMS)*time.Millisecond).UnixMilli(), now.UnixMilli(), outcome, plan.OwnerEnvHash, plan.PluginInstanceID, plan.ActiveFingerprint, plan.ManagementRevision, plan.PolicyRevision, plan.RevokeEpoch, plan.ClaimID, plan.IntervalMS, plan.MaxRuntimeMS)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// RecoverIntervalClaims runs once at Host startup. It never retries an
// interrupted invocation: a future period receives a different claim.
func (s *Store) RecoverIntervalClaims(ctx context.Context, now time.Time) error {
	if !s.Ready() {
		return ErrRequestsBlocked
	}
	if now.IsZero() {
		return errors.New("interval recovery requires time")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := readIntervalPlans(ctx, tx, ""); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE background_intervals SET next_run=?+interval_ms,claim_id='',finished_at=?,outcome='unknown' WHERE claim_id!=''", now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return err
	}
	return tx.Commit()
}
