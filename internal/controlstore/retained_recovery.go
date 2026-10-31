package controlstore

import (
	"context"
	"database/sql"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func (s *Store) CommitRetainedRecovery(ctx context.Context, plan plugindata.RetainedRecoveryPlan, shape plugindata.Shape) (plugindata.RetainedRecoveryResult, error) {
	owner, err := pluginDataEnvironmentOwner(ctx)
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
	readyToCommit := false
	err = s.pluginDataMutation(ctx, func(tx *sql.Tx) error {
		source, found, err := getControlDataBinding(ctx, tx, owner, plan.Source.PluginInstanceID)
		if err != nil {
			return err
		}
		if !found || !sameControlDataBinding(source, plan.Source) || source.ExpiresAt != nil && !source.ExpiresAt.After(time.Now().UTC()) {
			return plugindata.ErrRetainedRecoveryConflict
		}
		targetBinding, found, err := getControlDataBinding(ctx, tx, owner, plan.Target.PluginInstanceID)
		if err != nil {
			return err
		}
		if !found || !sameControlDataBinding(targetBinding, plan.Target) {
			return plugindata.ErrRetainedRecoveryConflict
		}
		sourceRecord, err := getControlPluginRecordIncludingDeleted(ctx, tx, owner, source.PluginInstanceID)
		if err != nil {
			return err
		}
		if sourceRecord.DeletedAt == nil {
			return plugindata.ErrRetainedRecoveryConflict
		}
		target, err := getControlPluginRecord(ctx, tx, owner, plan.Target.PluginInstanceID)
		if err != nil {
			return err
		}
		if target.EnableState != registry.EnableDisabledByUser || target.ManagementRevision != plan.TargetManagementRevision || target.ActiveFingerprint != plan.TargetActiveFingerprint {
			return plugindata.ErrRetainedRecoveryConflict
		}
		if err := validateControlRecordDataShape(target, targetBinding, shape); err != nil {
			return err
		}
		if sourceRecord.PublisherID != target.PublisherID || sourceRecord.PluginID != target.PluginID {
			return plugindata.ErrShapeMismatch
		}
		// Both generations remain referenced throughout the atomic catalog commit.
		if err := updateExactControlDataBinding(ctx, tx, owner, source, next.Retained); err != nil {
			return err
		}
		if err := updateExactControlDataBinding(ctx, tx, owner, targetBinding, next.Active); err != nil {
			return err
		}
		target.ManagementRevision++
		target.RevokeEpoch++
		target.UpdatedAt = time.Now().UTC()
		if err := persistControlPluginRecord(ctx, tx, target); err != nil {
			return err
		}
		readyToCommit = true
		return nil
	})
	if err != nil {
		if readyToCommit {
			return plugindata.RetainedRecoveryResult{}, mutation.Unknown(err)
		}
		return plugindata.RetainedRecoveryResult{}, err
	}
	return next, nil
}

// ListRetainedRecoveryCandidates resolves compatible identities from Host-owned
// records. It is only discovery; inspection revalidates both physical generations.
func (s *Store) ListRetainedRecoveryCandidates(ctx context.Context, targetID, sourceID string) ([]plugindata.Binding, error) {
	if err := s.pluginDataReady(); err != nil {
		return nil, err
	}
	owner, err := pluginDataEnvironmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT b.plugin_instance_id,b.generation_id,b.state,b.revision,b.shape_hash,b.retained_at,b.expires_at
FROM plugin_data_bindings b
JOIN plugin_records source ON source.owner_env_hash=b.owner_env_hash AND source.plugin_instance_id=b.plugin_instance_id
JOIN plugin_records target ON target.owner_env_hash=b.owner_env_hash AND target.plugin_instance_id=?
JOIN plugin_data_bindings active ON active.owner_env_hash=target.owner_env_hash AND active.plugin_instance_id=target.plugin_instance_id
WHERE b.owner_env_hash=? AND b.state='retained' AND source.deleted_at IS NOT NULL
AND target.deleted_at IS NULL AND active.state='active' AND b.shape_hash=active.shape_hash
AND source.publisher_id=target.publisher_id AND source.plugin_id=target.plugin_id
AND (b.expires_at IS NULL OR b.expires_at>?) AND (?='' OR b.plugin_instance_id=?)
ORDER BY b.retained_at DESC,b.plugin_instance_id`, targetID, owner, time.Now().UTC().UnixNano(), sourceID, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]plugindata.Binding, 0)
	for rows.Next() {
		var binding plugindata.Binding
		if err := scanControlDataBinding(rows, &binding, nil); err != nil {
			return nil, err
		}
		result = append(result, binding)
	}
	return result, rows.Err()
}
