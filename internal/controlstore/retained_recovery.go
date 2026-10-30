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
