package host

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/bridge"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

var ErrControlStoreRequired = errors.New("Host control store is required")

type ExecutionOperationScope string

const ExecutionOperationScopeReleaseInstall ExecutionOperationScope = "release_install"

type ListExecutionsOptions struct {
	PluginInstanceID string
	OperationScope   ExecutionOperationScope
	Cursor           uint64
	Limit            int
}

// GetExecution returns one execution only when it belongs to the exact
// authenticated session owner. Cross-owner identities are indistinguishable
// from absent records.
func (h *Host) GetExecution(ctx context.Context, id string) (execution.Execution, error) {
	return h.getExecution(ctx, id, nil)
}

// GetSurfaceExecution restricts the authenticated parent transport to its plugin.
func (h *Host) GetSurfaceExecution(ctx context.Context, id string, scope SurfaceExecutionScope) (execution.Execution, error) {
	return h.getExecution(ctx, id, &scope)
}

func (h *Host) getExecution(ctx context.Context, id string, scope *SurfaceExecutionScope) (execution.Execution, error) {
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
	current, err := h.controlStore.Executions().GetOwned(ctx, id, executionOwner(authorization.session))
	if err != nil {
		return execution.Execution{}, err
	}
	if err := h.authorizeSurfaceExecution(ctx, authorization.session, current, scope); err != nil {
		return execution.Execution{}, err
	}
	return current, nil
}

// ListExecutions returns one owner-scoped page ordered by the control store's
// durable execution identity. A zero next cursor means the page is terminal.
func (h *Host) ListExecutions(ctx context.Context, pluginInstanceID string, cursor uint64, limit int) ([]execution.Execution, uint64, error) {
	return h.ListExecutionsWithOptions(ctx, ListExecutionsOptions{
		PluginInstanceID: pluginInstanceID,
		Cursor:           cursor,
		Limit:            limit,
	})
}

// ListExecutionsWithOptions returns one owner-scoped page and can select the
// canonical release-install operation subset without introducing another
// execution state machine or response type.
func (h *Host) ListExecutionsWithOptions(ctx context.Context, options ListExecutionsOptions) ([]execution.Execution, uint64, error) {
	pluginInstanceID := strings.TrimSpace(options.PluginInstanceID)
	if options.OperationScope != "" && options.OperationScope != ExecutionOperationScopeReleaseInstall {
		return nil, 0, fmt.Errorf("%w: unsupported execution operation scope", ErrMethodRequestContract)
	}
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
	return h.controlStore.Executions().ListOwnedWithOperationScope(ctx, pluginInstanceID, string(options.OperationScope), executionOwner(authorization.session), options.Cursor, options.Limit)
}

// CancelExecution idempotently requests cancellation through the sole
// Execution state machine. reason is accepted for the command/audit boundary;
// it does not create a second durable status field.
func (h *Host) CancelExecution(ctx context.Context, id, reason string) (execution.Execution, error) {
	return h.cancelExecution(ctx, id, reason, nil)
}

// CancelSurfaceExecution verifies surface authority before requesting cancellation.
func (h *Host) CancelSurfaceExecution(ctx context.Context, id, reason string, scope SurfaceExecutionScope) (execution.Execution, error) {
	return h.cancelExecution(ctx, id, reason, &scope)
}

func (h *Host) cancelExecution(ctx context.Context, id, reason string, scope *SurfaceExecutionScope) (execution.Execution, error) {
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
	if err := h.authorizeSurfaceExecution(ctx, authorization.session, current, scope); err != nil {
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
	return h.eventsAfter(ctx, id, cursor, limit, nil)
}

// SurfaceEventsAfter applies the same current gateway and plugin ownership checks.
func (h *Host) SurfaceEventsAfter(ctx context.Context, id string, cursor uint64, limit int, scope SurfaceExecutionScope) ([]execution.Event, error) {
	return h.eventsAfter(ctx, id, cursor, limit, &scope)
}

func (h *Host) eventsAfter(ctx context.Context, id string, cursor uint64, limit int, scope *SurfaceExecutionScope) ([]execution.Event, error) {
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
	if scope != nil {
		current, err := h.controlStore.Executions().GetOwned(ctx, id, executionOwner(authorization.session))
		if err != nil {
			return nil, err
		}
		if err := h.authorizeSurfaceExecution(ctx, authorization.session, current, scope); err != nil {
			return nil, err
		}
	}
	return h.controlStore.Executions().EventsAfterOwned(ctx, id, executionOwner(authorization.session), cursor, limit)
}

func executionOwner(session sessionctx.Context) controlstore.ExecutionOwner {
	return controlstore.ExecutionOwner{
		OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash,
		OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash,
	}
}

// SurfaceExecutionScope is supplied by the trusted parent SDK, never the Web
// application. Credentials stay bound to the current channel and frame generation.
type SurfaceExecutionScope struct {
	PluginInstanceID  string `json:"plugin_instance_id"`
	SurfaceInstanceID string `json:"surface_instance_id"`
	BridgeChannelID   string `json:"bridge_channel_id"`
	GatewayToken      string `json:"plugin_gateway_token"`
}

func (h *Host) authorizeSurfaceExecution(ctx context.Context, session sessionctx.Context, current execution.Execution, scope *SurfaceExecutionScope) error {
	if scope == nil {
		return nil
	}
	if scope.PluginInstanceID == "" || scope.SurfaceInstanceID == "" || scope.BridgeChannelID == "" || scope.GatewayToken == "" {
		return bridge.ErrTokenAudience
	}
	if current.PluginInstanceID != scope.PluginInstanceID {
		return controlstore.ErrRecordNotFound
	}
	record, err := h.getPluginRecord(ctx, scope.PluginInstanceID)
	if err != nil {
		return err
	}
	if record.EnableState != registry.EnableEnabled {
		return controlstore.ErrRecordNotFound
	}
	if err := h.canRun(ctx, record); err != nil {
		return err
	}
	now := time.Now()
	token, err := h.surfaceTokens.ValidateSurfaceGatewayToken(bridge.ValidateSurfaceGatewayTokenRequest{
		GatewayToken: scope.GatewayToken, PluginInstanceID: record.PluginInstanceID, SurfaceInstanceID: scope.SurfaceInstanceID,
		OwnerSessionHash: session.OwnerSessionHash, OwnerUserHash: session.OwnerUserHash, OwnerEnvHash: session.OwnerEnvHash, SessionChannelIDHash: session.SessionChannelIDHash,
		BridgeChannelID: scope.BridgeChannelID, Revision: bridge.RevisionBinding{PolicyRevision: record.PolicyRevision, ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch}, Now: now,
	})
	if err != nil {
		return err
	}
	return h.requireSurfaceGeneration(scope.SurfaceInstanceID, token.Audience.RuntimeGenerationID, now)
}
