package cleanup

import "context"

type Phase string

const (
	PhaseTombstone     Phase = "tombstone"
	PhaseRevoke        Phase = "revoke"
	PhaseDeleteData    Phase = "delete_data"
	PhaseDeletePackage Phase = "delete_package"
	PhaseComplete      Phase = "complete"
)

type Plan struct {
	PluginInstanceID string  `json:"plugin_instance_id"`
	DeleteData       bool    `json:"delete_data"`
	Phases           []Phase `json:"phases"`
}

type Orchestrator interface {
	PlanUninstall(ctx context.Context, pluginInstanceID string, deleteData bool) (Plan, error)
	Execute(ctx context.Context, plan Plan) error
	ForceCleanup(ctx context.Context, pluginInstanceID string) error
}
