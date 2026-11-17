package authoring

import (
	"context"

	"github.com/floegence/redevplugin/v3/pkg/host"
)

// PreviewInspection omits browser credentials and raw build output. An empty
// instance means no applied artifact, not missing permissions. A failed read
// returns an error and must not be presented as an empty successful inspection.
type PreviewInspection struct {
	WorkspaceID  string                     `json:"workspace_id"`
	ArtifactID   string                     `json:"artifact_id"`
	Generation   uint64                     `json:"generation"`
	Capabilities *host.CapabilityInspection `json:"capabilities,omitempty"`
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
	}
	return result, nil
}
