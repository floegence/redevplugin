package host

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// ErrInspectedInstallNotFound identifies an absent owner-scoped operation.
// Hosts may reconcile this outcome without depending on the internal store.
var ErrInspectedInstallNotFound = errors.New("inspected installation operation not found")

type StartInspectedInstallRequest struct {
	RequestID             string `json:"request_id"`
	InspectionID          string `json:"inspection_id"`
	ExpectedPackageSHA256 string `json:"expected_package_sha256"`
}
type InspectedInstallOperation struct {
	Execution       execution.Execution `json:"execution"`
	RequestID       string              `json:"request_id"`
	InspectionID    string              `json:"inspection_id"`
	PackageSHA256   string              `json:"package_sha256"`
	PluginID        string              `json:"plugin_id"`
	Version         string              `json:"version"`
	MutationOutcome mutation.Outcome    `json:"mutation_outcome"`
}

func inspectedInstallProjection(op controlstore.InspectedInstall) InspectedInstallOperation {
	return InspectedInstallOperation{Execution: op.Execution, RequestID: op.RequestID, InspectionID: op.InspectionID, PackageSHA256: op.PackageSHA256, PluginID: op.PluginID, Version: op.Version, MutationOutcome: op.Outcome}
}

// StartInspectedInstall accepts the exact reviewed bytes once. A repeated request
// returns its original Execution, including after session renewal or Host restart.
// It never resurrects an expired inspection or implicitly retries a failed effect.
func (h *Host) StartInspectedInstall(ctx context.Context, req StartInspectedInstallRequest) (InspectedInstallOperation, error) {
	release, err := h.ensureOpen()
	if err != nil {
		return InspectedInstallOperation{}, err
	}
	defer release()
	if err = h.requireFeature(FeatureExternalPackage); err != nil {
		return InspectedInstallOperation{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return InspectedInstallOperation{}, err
	}
	h.inspectedInstallMu.Lock()
	defer h.inspectedInstallMu.Unlock()
	owner := executionOwner(session)
	if strings.TrimSpace(req.RequestID) != req.RequestID || req.RequestID == "" || len(req.RequestID) > 160 {
		return InspectedInstallOperation{}, ErrExternalPackageRequestInvalid
	}
	old, err := h.controlStore.Executions().GetInspectedInstall(ctx, owner, req.RequestID)
	if err == nil {
		if _, err = h.authorizeManagementSession(ctx, session, ManagementActionInstallInspectedPackage, scopedAuthorizationTarget(ResourcePlugin, old.Execution.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
			return InspectedInstallOperation{}, err
		}
		if old.InspectionID != req.InspectionID || old.PackageSHA256 != req.ExpectedPackageSHA256 {
			return InspectedInstallOperation{}, ErrExternalPackageConfirmation
		}
		return inspectedInstallProjection(old), nil
	}
	if !errors.Is(err, controlstore.ErrRecordNotFound) {
		return InspectedInstallOperation{}, err
	}
	scope, err := session.SessionScope()
	if err != nil {
		return InspectedInstallOperation{}, err
	}
	pending, err := h.externalInspections.get(req.InspectionID, scope)
	if err != nil {
		return InspectedInstallOperation{}, err
	}
	if _, err = h.authorizeManagementSession(ctx, session, ManagementActionInstallInspectedPackage, scopedAuthorizationTarget(ResourcePlugin, pending.Record.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return InspectedInstallOperation{}, err
	}
	if pending.State != externalPackagePending {
		return InspectedInstallOperation{}, ErrExternalPackageInstallInProgress
	}
	if pending.Inspection.InspectedHashes.PackageSHA256 != req.ExpectedPackageSHA256 {
		return InspectedInstallOperation{}, ErrExternalPackageConfirmation
	}
	if !time.Now().Before(pending.Inspection.ExpiresAt) {
		return InspectedInstallOperation{}, ErrExternalPackageInspectionExpired
	}
	op, created, err := h.controlStore.Executions().StartInspectedInstall(ctx, owner, controlstore.InspectedInstall{RequestID: req.RequestID, InspectionID: req.InspectionID, PackageSHA256: req.ExpectedPackageSHA256, PluginID: pending.Record.PluginID, Version: pending.Record.Version, Execution: execution.Execution{PluginInstanceID: pending.Record.PluginInstanceID, Kind: execution.KindOperation}})
	if errors.Is(err, controlstore.ErrStateConflict) {
		return InspectedInstallOperation{}, ErrExternalPackageInstallInProgress
	}
	if err != nil {
		return InspectedInstallOperation{}, err
	}
	if !created {
		return inspectedInstallProjection(op), nil
	}
	if !h.startLifecycleJob(func(job context.Context) {
		job = sessionctx.WithContext(job, session)
		job, cancel := context.WithTimeout(job, 5*time.Minute)
		defer cancel()
		_, failure := h.InstallInspectedPackage(job, InstallInspectedPackageRequest{InspectionID: req.InspectionID, ExpectedPackageSHA256: req.ExpectedPackageSHA256, operationEvidence: op.Execution.ID})
		outcome := mutation.OutcomeCommitted
		code := ""
		if failure != nil {
			outcome = mutation.ForError(failure)
			code = releaseInstallFailureCode(failure)
		}
		if _, finishErr := h.controlStore.Executions().FinishInspectedInstall(context.WithoutCancel(job), owner, req.RequestID, outcome, code); finishErr != nil {
			h.diagnostic(context.WithoutCancel(job), observability.DiagnosticEvent{Type: "plugin.execution.failed", PluginInstanceID: op.Execution.PluginInstanceID, Severity: observability.DiagnosticSeverityWarning, Message: "Installation result persistence requires restart reconciliation", Details: observability.DiagnosticDetails{Operation: "inspected_install_finish"}, Failure: observability.FailureFromError(observability.FailureOwner, observability.FailureComponentLifecycle, observability.FailureOperationLifecycle, finishErr)})
		}
	}) {
		op, err = h.controlStore.Executions().FinishInspectedInstall(context.WithoutCancel(ctx), owner, req.RequestID, mutation.OutcomeNotCommitted, releaseInstallFailureInterrupted)
	}
	return inspectedInstallProjection(op), err
}
func (h *Host) GetInspectedInstall(ctx context.Context, requestID string) (InspectedInstallOperation, error) {
	release, err := h.ensureOpen()
	if err != nil {
		return InspectedInstallOperation{}, err
	}
	defer release()
	if err = h.requireFeature(FeatureExternalPackage); err != nil {
		return InspectedInstallOperation{}, err
	}
	session, err := requireUserSession(ctx)
	if err != nil {
		return InspectedInstallOperation{}, err
	}
	op, err := h.controlStore.Executions().GetInspectedInstall(ctx, executionOwner(session), requestID)
	if errors.Is(err, controlstore.ErrRecordNotFound) {
		return InspectedInstallOperation{}, ErrInspectedInstallNotFound
	}
	if err != nil {
		return InspectedInstallOperation{}, err
	}
	if _, err = h.authorizeManagementSession(ctx, session, ManagementActionGetExecution, authorizationTarget(ResourceExecution, op.Execution.ID)); err != nil {
		return InspectedInstallOperation{}, err
	}
	return inspectedInstallProjection(op), nil
}
func (h *Host) reconcileInspectedInstalls(ctx context.Context) error {
	candidates, err := h.controlStore.Executions().InspectedInstallRecovery(ctx)
	if err != nil {
		return err
	}
	for _, c := range candidates {
		outcome := mutation.OutcomeUnknown
		code := releaseInstallFailureInterrupted
		record, failure := h.controlStore.Registry().GetPlugin(ctx, c.Owner.OwnerEnvHash, c.Operation.Execution.PluginInstanceID)
		if failure == nil && inspectedInstallCommitted(c.Operation, record) {
			outcome = mutation.OutcomeCommitted
			code = ""
		}
		if _, err = h.controlStore.Executions().FinishInspectedInstall(ctx, c.Owner, c.Operation.RequestID, outcome, code); err != nil {
			return err
		}
	}
	return nil
}
func inspectedInstallCommitted(op controlstore.InspectedInstall, record registry.PluginRecord) bool {
	match := func(hash string, approval registry.ExecutionApproval) bool {
		return hash == op.PackageSHA256 && approval.EvidenceReference == op.Execution.ID && approval.Status == registry.ExecutionApprovalUserApproved
	}
	if match(record.PackageHash, record.ExecutionApproval) {
		return true
	}
	for _, v := range record.VersionHistory {
		if match(v.PackageHash, v.ExecutionApproval) {
			return true
		}
	}
	return false
}
