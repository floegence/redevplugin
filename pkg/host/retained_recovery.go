package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type InspectRetainedRecoveryRequest struct {
	SourcePluginInstanceID string `json:"source_plugin_instance_id"`
	TargetPluginInstanceID string `json:"target_plugin_instance_id"`
}

type RetainedRecoveryInspection struct {
	Plan     plugindata.RetainedRecoveryPlan `json:"plan"`
	PlanHash string                          `json:"plan_hash"`
}

type RetainedRecoveryRequest = RetainedRecoveryInspection

type RetainedRecoveryStatus struct {
	State  string                             `json:"state"`
	Result *plugindata.RetainedRecoveryResult `json:"result,omitempty"`
}

func (h *Host) InspectRetainedRecovery(ctx context.Context, req InspectRetainedRecoveryRequest) (RetainedRecoveryInspection, error) {
	req.SourcePluginInstanceID, req.TargetPluginInstanceID = strings.TrimSpace(req.SourcePluginInstanceID), strings.TrimSpace(req.TargetPluginInstanceID)
	ctx, session, release, err := h.retainedRecoveryAction(ctx, ManagementActionInspectRetainedRecovery, req.SourcePluginInstanceID, req.TargetPluginInstanceID)
	if err != nil {
		return RetainedRecoveryInspection{}, err
	}
	defer release()
	unlock, err := h.lifecycleLocks.acquireWriteMany(ctx, req.SourcePluginInstanceID, req.TargetPluginInstanceID)
	if err != nil {
		return RetainedRecoveryInspection{}, err
	}
	defer unlock()
	target, err := h.getPluginRecord(ctx, req.TargetPluginInstanceID)
	if err != nil {
		return RetainedRecoveryInspection{}, err
	}
	if target.EnableState != registry.EnableDisabledByUser {
		return RetainedRecoveryInspection{}, plugindata.ErrRetainedRecoveryConflict
	}
	source, found, err := h.controlStore.GetBinding(ctx, req.SourcePluginInstanceID)
	if err != nil {
		return RetainedRecoveryInspection{}, err
	}
	if !found {
		return RetainedRecoveryInspection{}, plugindata.ErrBindingNotFound
	}
	targetBinding, found, err := h.controlStore.GetBinding(ctx, req.TargetPluginInstanceID)
	if err != nil {
		return RetainedRecoveryInspection{}, err
	}
	if !found {
		return RetainedRecoveryInspection{}, plugindata.ErrBindingNotFound
	}
	plan := plugindata.RetainedRecoveryPlan{OwnerEnvHash: session.OwnerEnvHash, Source: source, Target: targetBinding, TargetManagementRevision: target.ManagementRevision, TargetActiveFingerprint: target.ActiveFingerprint, RetainedAt: time.Now().UTC()}
	shape, err := plugindata.ShapeFromManifest(target.Manifest)
	if err != nil {
		return RetainedRecoveryInspection{}, err
	}
	if err := h.adapters.PluginData.ValidateRetainedRecovery(ctx, plan, shape); err != nil {
		return RetainedRecoveryInspection{}, err
	}
	hash, err := retainedRecoveryHash(plan, session)
	if err != nil {
		return RetainedRecoveryInspection{}, err
	}
	return RetainedRecoveryInspection{Plan: plan, PlanHash: hash}, nil
}

func (h *Host) CommitRetainedRecovery(ctx context.Context, req RetainedRecoveryRequest) (result plugindata.RetainedRecoveryResult, retErr error) {
	ctx, session, release, err := h.retainedRecoveryAction(ctx, ManagementActionCommitRetainedRecovery, req.Plan.Source.PluginInstanceID, req.Plan.Target.PluginInstanceID)
	if err != nil {
		return result, err
	}
	defer release()
	req.Plan.OwnerEnvHash = session.OwnerEnvHash
	if err := validateRetainedRecoveryHash(req, session); err != nil {
		return result, err
	}
	if req.Plan.RetainedAt.After(time.Now().UTC()) || time.Since(req.Plan.RetainedAt) > 15*time.Minute {
		return result, fmt.Errorf("%w: inspect a fresh recovery plan", plugindata.ErrRetainedRecoveryConflict)
	}
	unlock, err := h.lifecycleLocks.acquireWriteMany(ctx, req.Plan.Source.PluginInstanceID, req.Plan.Target.PluginInstanceID)
	if err != nil {
		return result, err
	}
	defer unlock()
	target, err := h.getPluginRecord(ctx, req.Plan.Target.PluginInstanceID)
	if err != nil {
		return result, err
	}
	if target.EnableState != registry.EnableDisabledByUser || target.ManagementRevision != req.Plan.TargetManagementRevision || target.ActiveFingerprint != req.Plan.TargetActiveFingerprint {
		return result, plugindata.ErrRetainedRecoveryConflict
	}
	shape, err := plugindata.ShapeFromManifest(target.Manifest)
	if err != nil {
		return result, err
	}
	audit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.retained_data.recovered", PluginID: target.PluginID, PluginInstanceID: target.PluginInstanceID, Details: map[string]any{"source_plugin_instance_id": req.Plan.Source.PluginInstanceID, "plan_hash": req.PlanHash}})
	if err != nil {
		return result, err
	}
	defer func() { retErr = audit.complete(context.WithoutCancel(ctx), retErr) }()
	result, err = h.adapters.PluginData.CommitRetainedRecovery(ctx, req.Plan, shape)
	if err != nil {
		return result, err
	}
	target.ManagementRevision = result.ManagementRevision
	target.RevokeEpoch++
	if err := h.revokePluginRuntimeCapabilities(ctx, target, time.Now().UTC()); err != nil {
		return result, mutation.Unknown(err)
	}
	return result, nil
}

// GetRetainedRecoveryStatus is a read-only reconciliation path. A repeated commit
// is deliberately rejected, so a lost response can never reverse the exchange.
func (h *Host) GetRetainedRecoveryStatus(ctx context.Context, req RetainedRecoveryRequest) (RetainedRecoveryStatus, error) {
	ctx, session, release, err := h.retainedRecoveryAction(ctx, ManagementActionGetRetainedRecoveryStatus, req.Plan.Source.PluginInstanceID, req.Plan.Target.PluginInstanceID)
	if err != nil {
		return RetainedRecoveryStatus{}, err
	}
	defer release()
	req.Plan.OwnerEnvHash = session.OwnerEnvHash
	if err := validateRetainedRecoveryHash(req, session); err != nil {
		return RetainedRecoveryStatus{}, err
	}
	unlock, err := h.lifecycleLocks.acquireWriteMany(ctx, req.Plan.Source.PluginInstanceID, req.Plan.Target.PluginInstanceID)
	if err != nil {
		return RetainedRecoveryStatus{}, err
	}
	defer unlock()
	expected, err := plugindata.RetainedRecoveryOutcome(req.Plan)
	if err != nil {
		return RetainedRecoveryStatus{}, err
	}
	source, found, err := h.controlStore.GetBinding(ctx, req.Plan.Source.PluginInstanceID)
	if err != nil {
		return RetainedRecoveryStatus{}, err
	}
	if !found {
		return RetainedRecoveryStatus{}, plugindata.ErrRetainedRecoveryConflict
	}
	target, found, err := h.controlStore.GetBinding(ctx, req.Plan.Target.PluginInstanceID)
	if err != nil {
		return RetainedRecoveryStatus{}, err
	}
	if !found {
		return RetainedRecoveryStatus{}, plugindata.ErrRetainedRecoveryConflict
	}
	record, err := h.getPluginRecord(ctx, req.Plan.Target.PluginInstanceID)
	if err != nil {
		return RetainedRecoveryStatus{}, err
	}
	if record.ActiveFingerprint != req.Plan.TargetActiveFingerprint || record.EnableState != registry.EnableDisabledByUser {
		return RetainedRecoveryStatus{}, plugindata.ErrRetainedRecoveryConflict
	}
	if plugindata.SameBinding(source, expected.Retained) && plugindata.SameBinding(target, expected.Active) && record.ManagementRevision == expected.ManagementRevision {
		return RetainedRecoveryStatus{State: "applied", Result: &expected}, nil
	}
	if plugindata.SameBinding(source, req.Plan.Source) && plugindata.SameBinding(target, req.Plan.Target) && record.ManagementRevision == req.Plan.TargetManagementRevision {
		return RetainedRecoveryStatus{State: "pending"}, nil
	}
	return RetainedRecoveryStatus{}, plugindata.ErrRetainedRecoveryConflict
}

func (h *Host) retainedRecoveryAction(ctx context.Context, action ManagementAction, source, target string) (context.Context, sessionctx.Context, func(), error) {
	if source == "" || target == "" || source == target {
		return ctx, sessionctx.Context{}, nil, plugindata.ErrInvalidArgument
	}
	return h.resourceAction(ctx, action, scopedAuthorizationTarget(ResourceRetainedData, source, sessionctx.ScopeEnvironment), scopedAuthorizationTarget(ResourcePlugin, target, sessionctx.ScopeEnvironment))
}

func retainedRecoveryHash(plan plugindata.RetainedRecoveryPlan, session sessionctx.Context) (string, error) {
	if _, err := plugindata.RetainedRecoveryOutcome(plan); err != nil {
		return "", err
	}
	// Stable resource owners allow read-only reconciliation after a Host restart.
	value := struct {
		OwnerEnvHash  string
		OwnerUserHash string
		Plan          plugindata.RetainedRecoveryPlan
	}{session.OwnerEnvHash, session.OwnerUserHash, plan}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validateRetainedRecoveryHash(req RetainedRecoveryRequest, session sessionctx.Context) error {
	actual, err := retainedRecoveryHash(req.Plan, session)
	if err != nil {
		return err
	}
	if actual != req.PlanHash {
		return fmt.Errorf("%w: recovery plan changed", plugindata.ErrRetainedRecoveryConflict)
	}
	return nil
}
