package host

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/security"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// PluginActionBlockedReason is the closed set of reasons an installed plugin
// cannot be opened. The Host computes this once from authoritative state.
type PluginActionBlockedReason string

const (
	PluginActionBlockedDisabled           PluginActionBlockedReason = "disabled"
	PluginActionBlockedPermission         PluginActionBlockedReason = "permission_required"
	PluginActionBlockedPolicy             PluginActionBlockedReason = "policy_restricted"
	PluginActionBlockedPackageInvalid     PluginActionBlockedReason = "package_invalid"
	PluginActionBlockedSignatureInvalid   PluginActionBlockedReason = "signature_invalid"
	PluginActionBlockedSignatureRevoked   PluginActionBlockedReason = "signature_revoked"
	PluginActionBlockedRuntimeUnavailable PluginActionBlockedReason = "runtime_unavailable"
	PluginActionBlockedIncompatible       PluginActionBlockedReason = "incompatible"
)

// PluginActionState is the only Host-owned action projection consumed by host
// products. UI clients may present it, but must not recompute it.
type PluginActionState struct {
	CanOpen        bool                      `json:"can_open"`
	CanEnable      bool                      `json:"can_enable"`
	CanDisable     bool                      `json:"can_disable"`
	CanUninstall   bool                      `json:"can_uninstall"`
	BlockedReason  PluginActionBlockedReason `json:"blocked_reason,omitempty"`
	RecoveryAction string                    `json:"recovery_action,omitempty"`
}

type PluginInventoryRecord struct {
	Plugin      registry.PluginRecord `json:"plugin"`
	ActionState PluginActionState     `json:"action_state"`
}

const (
	PluginRecoveryReady  = "ready"
	PluginRecoveryFailed = "failed"
)

type RecoverySnapshot struct {
	Revision int64                  `json:"revision"`
	Complete bool                   `json:"complete"`
	Results  []PluginRecoveryResult `json:"results"`
}

type PluginRecoveryResult struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	Action           string `json:"action,omitempty"`
}

func cloneRecoverySnapshot(value RecoverySnapshot) RecoverySnapshot {
	results := make([]PluginRecoveryResult, len(value.Results))
	copy(results, value.Results)
	value.Results = results
	return value
}

func (h *Host) ListPluginInventory(ctx context.Context) ([]PluginInventoryRecord, error) {
	records, err := h.ListPlugins(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]PluginInventoryRecord, len(records))
	for index, record := range records {
		result[index] = PluginInventoryRecord{Plugin: record, ActionState: h.pluginActionState(ctx, record)}
	}
	return result, nil
}

func (h *Host) publishStartupInventory(ctx context.Context) (bool, error) {
	if _, ok := sessionctx.FromContext(ctx); !ok {
		return false, nil
	}
	records, err := h.listPluginRecords(ctx)
	if err != nil {
		return false, err
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].PluginInstanceID < records[j].PluginInstanceID
	})
	hasEnabled := false
	for _, record := range records {
		if record.EnableState == registry.EnableEnabled {
			hasEnabled = true
			if err := h.publishEnabledSurfaces(ctx, record); err != nil {
				return false, err
			}
		}
	}
	return hasEnabled, nil
}

func (h *Host) pluginActionState(ctx context.Context, record registry.PluginRecord) PluginActionState {
	state := PluginActionState{CanUninstall: true}
	if record.DeletedAt != nil {
		state.CanUninstall = false
		state.BlockedReason = PluginActionBlockedPackageInvalid
		return state
	}
	switch record.SignatureAssessment.Status {
	case registry.SignatureInvalid:
		state.BlockedReason = PluginActionBlockedSignatureInvalid
	case registry.SignatureRevoked:
		state.BlockedReason = PluginActionBlockedSignatureRevoked
	case registry.SignatureUnavailable:
		state.BlockedReason = PluginActionBlockedRuntimeUnavailable
	case "":
		if !registry.RunnablePluginRecord(record) {
			state.BlockedReason = PluginActionBlockedPackageInvalid
		}
	default:
		if !registry.RunnablePluginRecord(record) {
			state.BlockedReason = PluginActionBlockedPackageInvalid
		}
	}
	if state.BlockedReason == "" && !registry.RunnablePluginRecord(record) {
		state.BlockedReason = PluginActionBlockedPackageInvalid
	}
	if state.BlockedReason == "" && record.EnableState == registry.EnableEnabled {
		state.BlockedReason = h.pluginAuthorizationBlockedReason(ctx, record)
	}
	if state.BlockedReason == "" && record.EnableState == registry.EnableEnabled {
		state.CanOpen = true
		state.CanDisable = true
		return state
	}
	if record.EnableState == registry.EnableEnabled {
		state.CanDisable = true
		state.RecoveryAction = "retry"
	} else {
		if state.BlockedReason == "" {
			state.BlockedReason = PluginActionBlockedDisabled
		}
		state.CanEnable = record.EnableState == registry.EnableDisabledByUser && state.BlockedReason == PluginActionBlockedDisabled
	}
	if state.BlockedReason == PluginActionBlockedRuntimeUnavailable ||
		state.BlockedReason == PluginActionBlockedIncompatible ||
		state.BlockedReason == PluginActionBlockedSignatureInvalid ||
		state.BlockedReason == PluginActionBlockedSignatureRevoked {
		state.RecoveryAction = "retry"
	}
	return state
}

func (h *Host) pluginAuthorizationBlockedReason(ctx context.Context, record registry.PluginRecord) PluginActionBlockedReason {
	err := h.pluginAuthorizationError(ctx, record)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, permissions.ErrPermissionDenied):
		return PluginActionBlockedPermission
	case errors.Is(err, security.ErrPolicyDenied):
		return PluginActionBlockedPolicy
	default:
		return PluginActionBlockedIncompatible
	}
}

type pluginMethodRequirement struct {
	method      string
	permissions []string
}

func (h *Host) pluginAuthorizationError(ctx context.Context, record registry.PluginRecord) error {
	methods := make([]pluginMethodRequirement, 0, len(record.Manifest.Methods))
	requiredPermissions := make([]string, 0)
	for _, declared := range record.Manifest.Methods {
		required, err := h.declaredRequiredPermissions(record, declared)
		if err != nil {
			return err
		}
		if len(required) == 0 {
			continue
		}
		methods = append(methods, pluginMethodRequirement{method: declared.Method, permissions: required})
		requiredPermissions = append(requiredPermissions, required...)
	}
	if len(methods) == 0 {
		return nil
	}
	snapshot, err := h.getAuthorizationSnapshot(ctx, record.PluginInstanceID)
	if err != nil {
		return err
	}
	granted, missing, err := permissions.Evaluate(snapshot.Grants, permissions.CheckRequest{
		PluginInstanceID: record.PluginInstanceID,
		PermissionIDs:    normalizeStringSet(requiredPermissions),
	})
	if err != nil {
		return err
	}
	if !granted {
		return fmt.Errorf("%w: %s", permissions.ErrPermissionDenied, strings.Join(missing, ", "))
	}
	for _, method := range methods {
		evaluation, err := security.Evaluate(snapshot.Policy, security.EvaluatePolicyRequest{
			PluginInstanceID:    record.PluginInstanceID,
			Method:              method.method,
			RequiredPermissions: method.permissions,
		})
		if err != nil || !evaluation.Allowed {
			if err != nil {
				return err
			}
			return fmt.Errorf("%w: method %q", security.ErrPolicyDenied, method.method)
		}
	}
	return nil
}

// RecoverEnabled reconciles enabled plugin runtime state once per Host startup
// revision. Repeated calls return the same immutable snapshot.
func (h *Host) RecoverEnabled(ctx context.Context) (RecoverySnapshot, error) {
	if _, err := h.authorizeManagement(ctx, ManagementActionRecoverEnabledPlugins, authorizationCollectionTarget(ResourceRuntime)); err != nil {
		return RecoverySnapshot{}, err
	}
	return h.recoverEnabled(ctx)
}

func (h *Host) recoverEnabled(ctx context.Context) (RecoverySnapshot, error) {
	h.recoveryMu.Lock()
	defer h.recoveryMu.Unlock()
	if h.recoverySnapshot != nil {
		return cloneRecoverySnapshot(*h.recoverySnapshot), nil
	}
	// Runtime startup is an in-memory prerequisite of recovery, not a durable
	// plugin state transition. A failed start is projected by the per-plugin
	// recovery below and never rewrites the persisted enabled intent.
	_ = h.startEnabledWorkerRuntime(ctx)
	results, err := h.refreshEnabledPlugins(ctx)
	if err != nil {
		return RecoverySnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return RecoverySnapshot{}, err
	}
	snapshot := RecoverySnapshot{Revision: h.recoveryRevision, Complete: true, Results: make([]PluginRecoveryResult, len(results))}
	for index, result := range results {
		mapped := PluginRecoveryResult{PluginInstanceID: result.PluginInstanceID}
		if result.Status == refreshEnabledPluginStatusRefreshed {
			mapped.Status = PluginRecoveryReady
		} else {
			snapshot.Complete = false
			mapped.Status = PluginRecoveryFailed
			if result.Error != nil {
				mapped.Reason = string(result.Error.Reason)
				mapped.Action = string(result.Error.Action)
			}
		}
		snapshot.Results[index] = mapped
	}
	copy := cloneRecoverySnapshot(snapshot)
	h.recoverySnapshot = &copy
	return cloneRecoverySnapshot(*h.recoverySnapshot), nil
}

func (h *Host) startEnabledWorkerRuntime(ctx context.Context) error {
	if h.adapters.RuntimeManager == nil {
		return nil
	}
	records, err := h.listPluginRecords(ctx)
	if err != nil {
		return err
	}
	hasEnabledWorker := false
	for _, record := range records {
		if record.EnableState == registry.EnableEnabled && pluginHasWorkers(record.Manifest) {
			hasEnabledWorker = true
			break
		}
	}
	if !hasEnabledWorker {
		return nil
	}

	health, healthErr := h.adapters.RuntimeManager.Health(ctx)
	if healthErr == nil && validateRuntimeManagerHealth(health, health.ArtifactIdentity) == nil {
		return nil
	}
	target := health.ArtifactIdentity.Target()
	if h.runtimeModule != nil {
		if moduleDescriptor := h.runtimeModule.ArtifactIdentity(); moduleDescriptor.PlatformVersion().String() != "" {
			target = moduleDescriptor.Target()
		}
	}
	if err := runtimetarget.Validate(target); err != nil {
		if healthErr != nil {
			return healthErr
		}
		return err
	}
	_, err = h.StartRuntime(ctx, StartRuntimeRequest{Target: target})
	return err
}

func (h *Host) RetryPluginRecovery(ctx context.Context, pluginInstanceID string) (PluginRecoveryResult, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return PluginRecoveryResult{}, fmt.Errorf("plugin_instance_id is required")
	}
	if _, err := h.authorizeManagement(ctx, ManagementActionRecoverEnabledPlugins, authorizationCollectionTarget(ResourceRuntime)); err != nil {
		return PluginRecoveryResult{}, err
	}
	record, err := h.getPluginRecord(ctx, pluginInstanceID)
	if err != nil {
		return PluginRecoveryResult{}, err
	}
	if record.EnableState != registry.EnableEnabled {
		return PluginRecoveryResult{}, ErrPluginRecoveryNotEnabled
	}
	result := PluginRecoveryResult{PluginInstanceID: pluginInstanceID, Status: PluginRecoveryReady}
	if err := h.refreshEnabledRuntimeState(ctx, record); err != nil {
		if errors.Is(err, context.Canceled) {
			return PluginRecoveryResult{}, err
		}
		reason, action, _ := classifyRefreshFailure(err)
		result.Status = PluginRecoveryFailed
		result.Reason = string(reason)
		result.Action = string(action)
	}
	h.recoveryMu.Lock()
	if h.recoverySnapshot != nil {
		for index := range h.recoverySnapshot.Results {
			if h.recoverySnapshot.Results[index].PluginInstanceID == pluginInstanceID {
				h.recoverySnapshot.Results[index] = result
			}
		}
		h.recoverySnapshot.Complete = true
		for _, item := range h.recoverySnapshot.Results {
			if item.Status != PluginRecoveryReady {
				h.recoverySnapshot.Complete = false
				break
			}
		}
	}
	h.recoveryMu.Unlock()
	return result, nil
}
