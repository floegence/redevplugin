package host

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/registry"
	"github.com/floegence/redevplugin/pkg/security"
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
	if state.BlockedReason == "" && record.EnableState == registry.EnableEnabled && pluginHasWorkers(record.Manifest) {
		if h.adapters.RuntimeManager == nil {
			state.BlockedReason = PluginActionBlockedRuntimeUnavailable
		} else if health, err := h.adapters.RuntimeManager.Health(ctx); err != nil {
			state.BlockedReason = PluginActionBlockedRuntimeUnavailable
		} else if err := validateRuntimeManagerHealth(health, health.Descriptor); err != nil {
			if errors.Is(err, ErrPluginRuntimeIncompatible) {
				state.BlockedReason = PluginActionBlockedIncompatible
			} else {
				state.BlockedReason = PluginActionBlockedRuntimeUnavailable
			}
		} else if err := validateWorkerRuntimeDescriptor(record, health.Descriptor, health.Descriptor.Target()); err != nil {
			state.BlockedReason = PluginActionBlockedIncompatible
		}
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
			switch record.EnableState {
			case registry.EnableDisabledByPolicy:
				state.BlockedReason = PluginActionBlockedPolicy
			case registry.EnableDisabledIncompatible:
				state.BlockedReason = PluginActionBlockedIncompatible
			default:
				state.BlockedReason = PluginActionBlockedDisabled
			}
		}
		state.CanEnable = state.BlockedReason == PluginActionBlockedDisabled
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
	type methodRequirement struct {
		method      string
		permissions []string
	}
	methods := make([]methodRequirement, 0, len(record.Manifest.Methods))
	requiredPermissions := make([]string, 0)
	for _, declared := range record.Manifest.Methods {
		if declared.Route.Kind != manifest.MethodRouteCapability {
			continue
		}
		binding, ok := manifestBinding(record.Manifest, declared.Route.BindingID)
		if !ok {
			return PluginActionBlockedIncompatible
		}
		contract, err := h.resolvePinnedCapabilityContract(record.CapabilityContracts, binding)
		if err != nil {
			return PluginActionBlockedIncompatible
		}
		effectiveMethod, ok := contractMethod(contract.Contract, declared.Route.TargetMethod)
		if !ok {
			return PluginActionBlockedIncompatible
		}
		required := normalizeStringSet(effectiveMethod.RequiredPermissions)
		methods = append(methods, methodRequirement{method: declared.Method, permissions: required})
		requiredPermissions = append(requiredPermissions, required...)
	}
	if len(methods) == 0 {
		return ""
	}
	snapshot, err := h.getAuthorizationSnapshot(ctx, record.PluginInstanceID)
	if err != nil {
		return PluginActionBlockedPolicy
	}
	granted, _, err := permissions.Evaluate(snapshot.Grants, permissions.CheckRequest{
		PluginInstanceID: record.PluginInstanceID,
		PermissionIDs:    normalizeStringSet(requiredPermissions),
	})
	if err != nil {
		return PluginActionBlockedPolicy
	}
	if !granted {
		return PluginActionBlockedPermission
	}
	for _, method := range methods {
		evaluation, err := security.Evaluate(snapshot.Policy, security.EvaluatePolicyRequest{
			PluginInstanceID:    record.PluginInstanceID,
			Method:              method.method,
			RequiredPermissions: method.permissions,
		})
		if err != nil || !evaluation.Allowed {
			return PluginActionBlockedPolicy
		}
	}
	return ""
}

// RecoverEnabled reconciles enabled plugin runtime state once per Host startup
// revision. Repeated calls return the same immutable snapshot.
func (h *Host) RecoverEnabled(ctx context.Context) (RecoverySnapshot, error) {
	if _, err := h.authorizeManagement(ctx, ManagementActionRecoverEnabledPlugins, authorizationCollectionTarget(ResourceRuntime)); err != nil {
		return RecoverySnapshot{}, err
	}
	h.recoveryMu.Lock()
	defer h.recoveryMu.Unlock()
	if h.recoverySnapshot != nil {
		return cloneRecoverySnapshot(*h.recoverySnapshot), nil
	}
	results, err := h.refreshEnabledPlugins(ctx)
	if err != nil {
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
