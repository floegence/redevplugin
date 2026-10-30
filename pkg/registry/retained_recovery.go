package registry

import (
	"context"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/plugindata"
)

func (s *MemoryStore) CommitRetainedRecovery(ctx context.Context, plan plugindata.RetainedRecoveryPlan, shape plugindata.Shape) (plugindata.RetainedRecoveryResult, error) {
	owner, err := environmentOwner(ctx)
	if err != nil {
		return plugindata.RetainedRecoveryResult{}, err
	}
	next, err := plugindata.RetainedRecoveryOutcome(plan)
	if err != nil {
		return plugindata.RetainedRecoveryResult{}, err
	}
	if owner != plan.OwnerEnvHash {
		return plugindata.RetainedRecoveryResult{}, plugindata.ErrRetainedRecoveryConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sourceKey, targetKey := environmentRecordKey(owner, plan.Source.PluginInstanceID), environmentRecordKey(owner, plan.Target.PluginInstanceID)
	source, sourceFound := s.dataBindings[sourceKey]
	targetBinding, targetFound := s.dataBindings[targetKey]
	if !sourceFound || !targetFound || !sameDataBinding(source, plan.Source) || !sameDataBinding(targetBinding, plan.Target) || source.ExpiresAt != nil && !source.ExpiresAt.After(time.Now().UTC()) {
		return plugindata.RetainedRecoveryResult{}, plugindata.ErrRetainedRecoveryConflict
	}
	sourceRecord, sourceFound := s.records[sourceKey]
	target, targetFound := s.records[targetKey]
	if !sourceFound || sourceRecord.DeletedAt == nil || !targetFound || target.DeletedAt != nil || target.EnableState != EnableDisabledByUser || target.ManagementRevision != plan.TargetManagementRevision || target.ActiveFingerprint != plan.TargetActiveFingerprint {
		return plugindata.RetainedRecoveryResult{}, plugindata.ErrRetainedRecoveryConflict
	}
	if err := validateRecordDataShape(target, targetBinding, shape); err != nil {
		return plugindata.RetainedRecoveryResult{}, err
	}
	if sourceRecord.PublisherID != target.PublisherID || sourceRecord.PluginID != target.PluginID {
		return plugindata.RetainedRecoveryResult{}, plugindata.ErrShapeMismatch
	}
	s.dataBindings[sourceKey], s.dataBindings[targetKey] = cloneDataBinding(next.Retained), cloneDataBinding(next.Active)
	target.ManagementRevision++
	target.RevokeEpoch++
	target.UpdatedAt = time.Now().UTC()
	s.records[targetKey] = target
	return next, nil
}
