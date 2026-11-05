package host

import (
	"context"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/execution"
)

// Installation progress uses the same durable Event stream as its outcome.
// Downloads happen before inspection; an accepted installation reports only
// verification, commit, and activation work that it actually performs.
func (h *Host) reportInstallProgress(ctx context.Context, owner controlstore.ExecutionOwner, requestID, stage, status, failureCode string) error {
	op, err := h.controlStore.Executions().GetInspectedInstall(ctx, owner, requestID)
	if err != nil {
		return err
	}
	progress := map[string]any{"task_id": op.Execution.ID, "request_id": requestID, "stage": stage, "status": status}
	if status == "failed" {
		progress["failure_code"] = failureCode
		progress["failure_stage"] = stage
		progress["retryable"] = false
	}
	event, err := execution.NewEvent(op.Execution, op.Execution.Cursor+1, execution.EventProgress, map[string]any{"install_progress": progress})
	if err != nil {
		return err
	}
	return h.controlStore.Executions().Append(ctx, event)
}
