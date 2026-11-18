package authoring

import (
	"context"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/host"
)

// PreviewInspection omits browser credentials and raw build output. An empty
// instance means no applied artifact, not missing permissions. A failed read
// returns an error and must not be presented as an empty successful inspection.
type PreviewInspection struct {
	WorkspaceID      string                     `json:"workspace_id"`
	ArtifactID       string                     `json:"artifact_id"`
	Generation       uint64                     `json:"generation"`
	Capabilities     *host.CapabilityInspection `json:"capabilities,omitempty"`
	LatestRejection  *PreviewMethodRejection    `json:"latest_rejection,omitempty"`
	DiagnosticsState string                     `json:"diagnostics_state,omitempty"`
}

// An observation of a past request, never a current admission blocker.
type PreviewMethodRejection struct {
	Method       string    `json:"method"`
	Reason       string    `json:"reason"`
	BusinessCode string    `json:"business_error_code,omitempty"`
	OccurredAt   time.Time `json:"occurred_at"`
}

// Inspect observes this environment without opening/applying a preview or
// launching work. Apply/Close cannot change the selected identity during it.
func (e *Environment) Inspect(ctx context.Context) (PreviewInspection, error) {
	e.operation.Lock()
	defer e.operation.Unlock()
	if e.closed {
		return PreviewInspection{}, host.ErrHostClosed
	}
	if err := e.check(ctx); err != nil {
		return PreviewInspection{}, err
	}
	if _, err := e.host.Features(ctx); err != nil {
		return PreviewInspection{}, err
	}
	state := e.preview.Snapshot()
	result := PreviewInspection{WorkspaceID: e.workspace.ID, ArtifactID: state.ArtifactID, Generation: state.Generation}
	if state.PluginInstanceID != "" {
		inspection, err := e.host.InspectPluginCapabilities(ctx, host.GetPermissionRequirementsRequest{PluginInstanceID: state.PluginInstanceID})
		if err != nil {
			return PreviewInspection{}, err
		}
		result.Capabilities = &inspection
		result.DiagnosticsState = "available"
		events, err := e.host.ListDiagnosticEvents(ctx, host.ListDiagnosticEventsRequest{PluginInstanceID: state.PluginInstanceID, Type: "plugin.method.rejected", Limit: 1})
		if err != nil {
			result.DiagnosticsState = "unavailable"
		} else if len(events) > 0 && events[0].ActiveFingerprint == inspection.ActiveFingerprint {
			event := events[0]
			result.LatestRejection = &PreviewMethodRejection{Method: event.Details.Method, Reason: event.Details.Reason, BusinessCode: event.Details.Code, OccurredAt: event.OccurredAt}
		}
	}
	return result, nil
}
