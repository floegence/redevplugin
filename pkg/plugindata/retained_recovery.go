package plugindata

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"
)

var ErrRetainedRecoveryConflict = fmt.Errorf("%w: retained recovery plan no longer matches", ErrBindingConflict)

// RetainedRecoveryPlan binds both existing data generations. Ownership is supplied
// only by the authenticated Host and is never accepted from a wire payload.
type RetainedRecoveryPlan struct {
	OwnerEnvHash             string    `json:"-"`
	Source                   Binding   `json:"source"`
	Target                   Binding   `json:"target"`
	TargetManagementRevision uint64    `json:"target_management_revision"`
	TargetActiveFingerprint  string    `json:"target_active_fingerprint"`
	RetainedAt               time.Time `json:"retained_at"`
}

type RetainedRecoveryResult struct {
	Active             Binding `json:"active"`
	Retained           Binding `json:"retained"`
	ManagementRevision uint64  `json:"management_revision"`
}

// RetainedRecoveryOutcome computes the exact expected post-state without changing
// data. Reconciliation uses this same result and never repeats the exchange.
func RetainedRecoveryOutcome(plan RetainedRecoveryPlan) (RetainedRecoveryResult, error) {
	if plan.Source.PluginInstanceID == plan.Target.PluginInstanceID || plan.Source.GenerationID == plan.Target.GenerationID ||
		plan.Source.State != BindingRetained || plan.Target.State != BindingActive || plan.Source.ShapeHash != plan.Target.ShapeHash ||
		plan.Source.Revision == 0 || plan.Target.Revision == 0 || plan.TargetManagementRevision == 0 ||
		plan.Source.Revision >= 9007199254740991 || plan.Target.Revision >= 9007199254740991 || plan.TargetManagementRevision >= 9007199254740991 ||
		plan.TargetActiveFingerprint == "" || plan.RetainedAt.IsZero() || plan.Source.RetainedAt == nil ||
		plan.Target.RetainedAt != nil || plan.Target.ExpiresAt != nil ||
		plan.Source.ExpiresAt != nil && !plan.Source.ExpiresAt.After(*plan.Source.RetainedAt) {
		return RetainedRecoveryResult{}, fmt.Errorf("%w: recovery requires distinct retained and active bindings", ErrInvalidArgument)
	}
	if _, err := hex.DecodeString(plan.Source.ShapeHash); err != nil || len(plan.Source.ShapeHash) != 64 {
		return RetainedRecoveryResult{}, ErrInvalidArgument
	}
	for _, value := range []string{plan.Source.PluginInstanceID, plan.Target.PluginInstanceID, plan.Source.GenerationID, plan.Target.GenerationID} {
		if _, err := normalizeIdentifier("recovery identity", value); err != nil {
			return RetainedRecoveryResult{}, err
		}
	}
	active := cloneBinding(plan.Source)
	active.PluginInstanceID = plan.Target.PluginInstanceID
	active.Revision = plan.Target.Revision + 1
	active.State = BindingActive
	active.RetainedAt, active.ExpiresAt = nil, nil
	retained := cloneBinding(plan.Target)
	retained.PluginInstanceID = plan.Source.PluginInstanceID
	retained.Revision = plan.Source.Revision + 1
	retained.State = BindingRetained
	at := plan.RetainedAt.UTC()
	retained.RetainedAt, retained.ExpiresAt = &at, nil
	return RetainedRecoveryResult{Active: active, Retained: retained, ManagementRevision: plan.TargetManagementRevision + 1}, nil
}

// ValidateRetainedRecovery checks the exact physical generations without modifying them.
func (s *FileStore) ValidateRetainedRecovery(ctx context.Context, plan RetainedRecoveryPlan, shape Shape) error {
	release, err := s.begin()
	if err != nil {
		return err
	}
	defer release()
	environment, err := environmentScope(ctx)
	if err != nil {
		return err
	}
	if environment.OwnerEnvHash != plan.OwnerEnvHash {
		return ErrRetainedRecoveryConflict
	}
	unlock := s.locks.lockMany(scopedLockKey(environment, plan.Source.PluginInstanceID), scopedLockKey(environment, plan.Target.PluginInstanceID))
	defer unlock()
	return s.validateRetainedRecovery(ctx, plan, shape)
}

func (s *FileStore) validateRetainedRecovery(ctx context.Context, plan RetainedRecoveryPlan, shape Shape) error {
	if _, err := RetainedRecoveryOutcome(plan); err != nil {
		return err
	}
	environment, err := environmentScope(ctx)
	if err != nil {
		return err
	}
	hash, err := HashShape(shape)
	if err != nil {
		return err
	}
	if environment.OwnerEnvHash != plan.OwnerEnvHash || hash != plan.Source.ShapeHash {
		return ErrShapeMismatch
	}
	if plan.Source.ExpiresAt != nil && !plan.Source.ExpiresAt.After(s.now()) {
		return ErrRetainedRecoveryConflict
	}
	for _, expected := range []Binding{plan.Source, plan.Target} {
		actual, found, err := s.catalog.GetBinding(ctx, expected.PluginInstanceID)
		if err != nil {
			return err
		}
		if !found || !SameBinding(actual, expected) {
			return ErrRetainedRecoveryConflict
		}
		_, manifest, err := s.workspaceForBinding(environment, actual)
		if err != nil {
			return err
		}
		if manifest.ShapeHash != hash {
			return ErrShapeMismatch
		}
	}
	return nil
}

func (s *FileStore) CommitRetainedRecovery(ctx context.Context, plan RetainedRecoveryPlan, shape Shape) (RetainedRecoveryResult, error) {
	release, err := s.begin()
	if err != nil {
		return RetainedRecoveryResult{}, err
	}
	defer release()
	environment, err := environmentScope(ctx)
	if err != nil {
		return RetainedRecoveryResult{}, err
	}
	unlock := s.locks.lockMany(scopedLockKey(environment, plan.Source.PluginInstanceID), scopedLockKey(environment, plan.Target.PluginInstanceID))
	defer unlock()
	s.publicationMu.Lock()
	defer s.publicationMu.Unlock()
	if err := s.validateRetainedRecovery(ctx, plan, shape); err != nil {
		return RetainedRecoveryResult{}, err
	}
	return s.catalog.CommitRetainedRecovery(ctx, plan, shape)
}

// SameBinding compares the complete durable identity, including retention times.
func SameBinding(left, right Binding) bool {
	equalTime := func(a, b *time.Time) bool {
		if a == nil || b == nil {
			return a == b
		}
		return a.Equal(*b)
	}
	return left.PluginInstanceID == right.PluginInstanceID && left.GenerationID == right.GenerationID && left.State == right.State && left.Revision == right.Revision && left.ShapeHash == right.ShapeHash && equalTime(left.RetainedAt, right.RetainedAt) && equalTime(left.ExpiresAt, right.ExpiresAt)
}
