package grants

import "time"

type Effect string

const (
	EffectRead    Effect = "read"
	EffectWrite   Effect = "write"
	EffectExecute Effect = "execute"
	EffectDelete  Effect = "delete"
	EffectAdmin   Effect = "admin"
)

type TargetPolicy struct {
	Scheme      string   `json:"scheme"`
	HostPattern string   `json:"host_pattern"`
	Ports       []int    `json:"ports,omitempty"`
	Effects     []Effect `json:"effects"`
}

type PolicyGrantBundle struct {
	GrantID                 string         `json:"grant_id"`
	PluginInstanceID        string         `json:"plugin_instance_id"`
	DescriptorHash          string         `json:"descriptor_hash"`
	TargetClassifierVersion string         `json:"target_classifier_version"`
	PolicyRevision          uint64         `json:"policy_revision"`
	RevokeEpoch             uint64         `json:"revoke_epoch"`
	Targets                 []TargetPolicy `json:"targets"`
	ExpiresAt               time.Time      `json:"expires_at"`
}

type HandleGrant struct {
	HandleGrantID       string    `json:"handle_grant_id"`
	GrantID             string    `json:"grant_id"`
	ResourceKind        string    `json:"resource_kind"`
	ResourceID          string    `json:"resource_id"`
	RuntimeGenerationID string    `json:"runtime_generation_id"`
	ExpiresAt           time.Time `json:"expires_at"`
}
