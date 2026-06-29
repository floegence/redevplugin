package capability

import "context"

type Effect string

const (
	EffectRead    Effect = "read"
	EffectWrite   Effect = "write"
	EffectExecute Effect = "execute"
	EffectDelete  Effect = "delete"
	EffectAdmin   Effect = "admin"
)

type Invocation struct {
	CapabilityID     string         `json:"capability_id"`
	Method           string         `json:"method"`
	Effect           Effect         `json:"effect"`
	PluginInstanceID string         `json:"plugin_instance_id"`
	Arguments        map[string]any `json:"arguments,omitempty"`
}

type Result struct {
	Data        any    `json:"data,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	StreamID    string `json:"stream_id,omitempty"`
}

type Adapter interface {
	InvokeCapability(ctx context.Context, req Invocation) (Result, error)
}

type Registry struct {
	adapters map[string]Adapter
}

func NewRegistry() *Registry {
	return &Registry{adapters: map[string]Adapter{}}
}

func (r *Registry) Register(capabilityID string, adapter Adapter) {
	r.adapters[capabilityID] = adapter
}

func (r *Registry) Adapter(capabilityID string) (Adapter, bool) {
	adapter, ok := r.adapters[capabilityID]
	return adapter, ok
}
