package registry

import (
	"context"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
)

type TrustState string

const (
	TrustBundled       TrustState = "bundled"
	TrustVerified      TrustState = "verified"
	TrustUnsignedLocal TrustState = "unsigned_local"
	TrustUntrusted     TrustState = "untrusted"
	TrustBlocked       TrustState = "blocked"
)

type InstallState string

const (
	InstallStaged   InstallState = "staged"
	InstallDisabled InstallState = "disabled"
	InstallEnabled  InstallState = "enabled"
	InstallDeleting InstallState = "deleting"
)

type PluginRecord struct {
	PluginInstanceID  string            `json:"plugin_instance_id"`
	PluginID          string            `json:"plugin_id"`
	Version           string            `json:"version"`
	ActiveFingerprint string            `json:"active_fingerprint"`
	TrustState        TrustState        `json:"trust_state"`
	InstallState      InstallState      `json:"install_state"`
	Manifest          manifest.Manifest `json:"manifest"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

type Store interface {
	PutPlugin(ctx context.Context, record PluginRecord) error
	GetPlugin(ctx context.Context, pluginInstanceID string) (PluginRecord, error)
	ListPlugins(ctx context.Context) ([]PluginRecord, error)
	SetInstallState(ctx context.Context, pluginInstanceID string, state InstallState) error
	DeletePlugin(ctx context.Context, pluginInstanceID string) error
}
