package host

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/internal/controlstore"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/execution"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

var ErrControlStoreRequired = errors.New("Host control store is required")

// GetExecution returns one execution only when it belongs to the exact
// authenticated session owner. Cross-owner identities are indistinguishable
// from absent records.
func (h *Host) GetExecution(ctx context.Context, id string) (execution.Execution, error) {
	id = strings.TrimSpace(id)
	authorization, err := h.authorizeManagement(ctx, ManagementActionGetExecution, authorizationTarget(ResourceExecution, id))
	if err != nil {
		return execution.Execution{}, err
	}
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return execution.Execution{}, err
	}
	defer releaseOpen()
	if h.controlStore == nil {
		return execution.Execution{}, ErrControlStoreRequired
	}
	return h.controlStore.Executions().GetOwned(ctx, id, executionOwner(authorization.session))
}

// ListExecutions returns one owner-scoped page ordered by the control store's
// durable execution identity. A zero next cursor means the page is terminal.
func (h *Host) ListExecutions(ctx context.Context, pluginInstanceID string, cursor uint64, limit int) ([]execution.Execution, uint64, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	authorization, err := h.authorizeManagement(ctx, ManagementActionListExecutions,
		authorizationCollectionTarget(ResourceExecution),
		relatedAuthorizationTargets(authorizationTarget(ResourcePlugin, pluginInstanceID))...,
	)
	if err != nil {
		return nil, 0, err
	}
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return nil, 0, err
	}
	defer releaseOpen()
	if h.controlStore == nil {
		return nil, 0, ErrControlStoreRequired
	}
	return h.controlStore.Executions().ListOwned(ctx, pluginInstanceID, executionOwner(authorization.session), cursor, limit)
}

// CancelExecution idempotently requests cancellation through the sole
// Execution state machine. reason is accepted for the command/audit boundary;
// it does not create a second durable status field.
func (h *Host) CancelExecution(ctx context.Context, id, reason string) (execution.Execution, error) {
	id = strings.TrimSpace(id)
	authorization, err := h.authorizeManagement(ctx, ManagementActionCancelExecution, authorizationTarget(ResourceExecution, id))
	if err != nil {
		return execution.Execution{}, err
	}
	ctx, releaseReservation, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return execution.Execution{}, err
	}
	defer releaseReservation()
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return execution.Execution{}, err
	}
	defer releaseOpen()
	if h.controlStore == nil {
		return execution.Execution{}, ErrControlStoreRequired
	}
	reason = strings.TrimSpace(reason)
	now := time.Now().UTC()
	owner := executionOwner(authorization.session)
	current, err := h.controlStore.Executions().GetOwned(ctx, id, owner)
	if err != nil {
		return execution.Execution{}, err
	}
	if current.Status == execution.StatusCancelRequested {
		return current, nil
	}
	current, err = h.controlStore.Executions().RequestCancelOwned(ctx, id, owner, now)
	if err != nil {
		return execution.Execution{}, err
	}
	matched, dispatchErr := h.executions.cancelOperation(ctx, capability.ExecutionCancellation{
		ExecutionID: id, Reason: reason, RequestedAt: now,
	}, errors.New("execution cancellation requested"))
	if dispatchErr != nil {
		return current, fmt.Errorf("%w: %w", ErrExecutionCancelDispatchFailed, dispatchErr)
	}
	if !matched {
		return current, nil
	}
	return h.controlStore.Executions().GetOwned(ctx, id, owner)
}

// EventsAfter returns the unified event envelope for one exact owner-bound
// execution and cursor.
func (h *Host) EventsAfter(ctx context.Context, id string, cursor uint64, limit int) ([]execution.Event, error) {
	id = strings.TrimSpace(id)
	authorization, err := h.authorizeManagement(ctx, ManagementActionListExecutionEvents, authorizationTarget(ResourceExecution, id))
	if err != nil {
		return nil, err
	}
	releaseOpen, err := h.ensureOpen()
	if err != nil {
		return nil, err
	}
	defer releaseOpen()
	if h.controlStore == nil {
		return nil, ErrControlStoreRequired
	}
	return h.controlStore.Executions().EventsAfterOwned(ctx, id, executionOwner(authorization.session), cursor, limit)
}

func executionOwner(session sessionctx.Context) controlstore.ExecutionOwner {
	return controlstore.ExecutionOwner{
		OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash,
		OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash,
	}
}
