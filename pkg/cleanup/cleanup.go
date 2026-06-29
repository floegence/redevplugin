package cleanup

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

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

type ExecutionRecord struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	DeleteData       bool      `json:"delete_data"`
	Phase            Phase     `json:"phase"`
	ExecutedAt       time.Time `json:"executed_at"`
}

type Orchestrator interface {
	PlanUninstall(ctx context.Context, pluginInstanceID string, deleteData bool) (Plan, error)
	Execute(ctx context.Context, plan Plan) error
	ForceCleanup(ctx context.Context, pluginInstanceID string) error
}

type Inspector interface {
	ListExecutions(ctx context.Context, pluginInstanceID string) ([]ExecutionRecord, error)
}

var ErrInvalidPlan = errors.New("cleanup plan is invalid")

type MemoryOrchestrator struct {
	mu         sync.Mutex
	now        func() time.Time
	executions []ExecutionRecord
}

func NewMemoryOrchestrator() *MemoryOrchestrator {
	return &MemoryOrchestrator{now: func() time.Time { return time.Now().UTC() }}
}

func (o *MemoryOrchestrator) PlanUninstall(_ context.Context, pluginInstanceID string, deleteData bool) (Plan, error) {
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if pluginInstanceID == "" {
		return Plan{}, ErrInvalidPlan
	}
	phases := []Phase{PhaseTombstone, PhaseRevoke}
	if deleteData {
		phases = append(phases, PhaseDeleteData)
	}
	phases = append(phases, PhaseDeletePackage, PhaseComplete)
	return Plan{
		PluginInstanceID: pluginInstanceID,
		DeleteData:       deleteData,
		Phases:           phases,
	}, nil
}

func (o *MemoryOrchestrator) Execute(_ context.Context, plan Plan) error {
	if o == nil {
		return errors.New("cleanup orchestrator is nil")
	}
	if err := validatePlan(plan); err != nil {
		return err
	}
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, phase := range plan.Phases {
		o.executions = append(o.executions, ExecutionRecord{
			PluginInstanceID: plan.PluginInstanceID,
			DeleteData:       plan.DeleteData,
			Phase:            phase,
			ExecutedAt:       now,
		})
	}
	return nil
}

func (o *MemoryOrchestrator) ForceCleanup(ctx context.Context, pluginInstanceID string) error {
	plan, err := o.PlanUninstall(ctx, pluginInstanceID, true)
	if err != nil {
		return err
	}
	return o.Execute(ctx, plan)
}

func (o *MemoryOrchestrator) ListExecutions(_ context.Context, pluginInstanceID string) ([]ExecutionRecord, error) {
	if o == nil {
		return nil, errors.New("cleanup orchestrator is nil")
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	o.mu.Lock()
	defer o.mu.Unlock()
	records := make([]ExecutionRecord, 0, len(o.executions))
	for _, record := range o.executions {
		if pluginInstanceID != "" && record.PluginInstanceID != pluginInstanceID {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

func validatePlan(plan Plan) error {
	if strings.TrimSpace(plan.PluginInstanceID) == "" {
		return ErrInvalidPlan
	}
	if len(plan.Phases) == 0 {
		return ErrInvalidPlan
	}
	seen := map[Phase]struct{}{}
	for _, phase := range plan.Phases {
		if !validPhase(phase) {
			return ErrInvalidPlan
		}
		if _, ok := seen[phase]; ok {
			return ErrInvalidPlan
		}
		seen[phase] = struct{}{}
	}
	if !containsPhase(plan.Phases, PhaseTombstone) || !containsPhase(plan.Phases, PhaseRevoke) || !containsPhase(plan.Phases, PhaseDeletePackage) || !containsPhase(plan.Phases, PhaseComplete) {
		return ErrInvalidPlan
	}
	if plan.DeleteData && !containsPhase(plan.Phases, PhaseDeleteData) {
		return ErrInvalidPlan
	}
	if !plan.DeleteData && containsPhase(plan.Phases, PhaseDeleteData) {
		return ErrInvalidPlan
	}
	return nil
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhaseTombstone, PhaseRevoke, PhaseDeleteData, PhaseDeletePackage, PhaseComplete:
		return true
	default:
		return false
	}
}

func containsPhase(phases []Phase, target Phase) bool {
	for _, phase := range phases {
		if phase == target {
			return true
		}
	}
	return false
}
