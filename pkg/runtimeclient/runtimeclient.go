package runtimeclient

import (
	"context"
	"time"
)

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Lease struct {
	LeaseID             string    `json:"lease_id"`
	LeaseToken          string    `json:"lease_token"`
	RuntimeGenerationID string    `json:"runtime_generation_id"`
	PluginInstanceID    string    `json:"plugin_instance_id"`
	PolicyRevision      uint64    `json:"policy_revision"`
	ManagementRevision  uint64    `json:"management_revision"`
	RevokeEpoch         uint64    `json:"revoke_epoch"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type Health struct {
	RuntimeInstanceID   string `json:"runtime_instance_id"`
	RuntimeGenerationID string `json:"runtime_generation_id"`
	Ready               bool   `json:"ready"`
}

type Supervisor interface {
	Start(ctx context.Context, target Target) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) (Health, error)
	InvokeWorker(ctx context.Context, lease Lease, method string, payload []byte) ([]byte, error)
	Revoke(ctx context.Context, pluginInstanceID string, revokeEpoch uint64) error
}
