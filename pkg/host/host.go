package host

import (
	"context"
	"errors"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type AuditSink interface {
	AppendPluginAudit(ctx context.Context, event AuditEvent) error
}

type DiagnosticsSink interface {
	AppendPluginDiagnostic(ctx context.Context, event DiagnosticEvent) error
}

type AuditEvent struct {
	Type             string `json:"type"`
	PluginID         string `json:"plugin_id"`
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type DiagnosticEvent struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	PluginID  string `json:"plugin_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

type PolicyAdapter interface {
	EvaluateLocalPolicy(ctx context.Context, session sessionctx.Context, plugin PluginRef, method manifest.MethodSpec) (PolicyDecision, error)
	DeveloperModeEnabled(ctx context.Context, session sessionctx.Context) (bool, error)
	LocalGeneratedPluginsEnabled(ctx context.Context, session sessionctx.Context) (bool, error)
}

type PolicyDecision string

const (
	PolicyAllow PolicyDecision = "allow"
	PolicyDeny  PolicyDecision = "deny"
)

type SecretStoreAdapter interface {
	BindSecretRef(ctx context.Context, req SecretBindRequest) error
	DeleteSecretRef(ctx context.Context, req SecretDeleteRequest) error
	TestSecretRef(ctx context.Context, req SecretTestRequest) error
}

type SecretBindRequest struct {
	PluginInstanceID string `json:"plugin_instance_id"`
	SecretRef        string `json:"secret_ref"`
	Scope            string `json:"scope"`
}

type SecretDeleteRequest = SecretBindRequest
type SecretTestRequest = SecretBindRequest

type RuntimeArtifactResolver interface {
	RuntimePath(ctx context.Context, target RuntimeTarget) (string, error)
}

type RuntimeTarget struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type SurfaceCatalogSink interface {
	PublishSurfaces(ctx context.Context, snapshot SurfaceSnapshot) error
}

type SurfaceSnapshot struct {
	PluginInstanceID string                 `json:"plugin_instance_id"`
	Surfaces         []manifest.SurfaceSpec `json:"surfaces"`
}

type PluginRef struct {
	PluginID          string `json:"plugin_id"`
	PluginInstanceID  string `json:"plugin_instance_id"`
	Version           string `json:"version"`
	ActiveFingerprint string `json:"active_fingerprint"`
}

type Adapters struct {
	SessionResolver         sessionctx.Resolver
	Policy                  PolicyAdapter
	Audit                   AuditSink
	Diagnostics             DiagnosticsSink
	Secrets                 SecretStoreAdapter
	RuntimeArtifactResolver RuntimeArtifactResolver
	SurfaceCatalog          SurfaceCatalogSink
	Capabilities            *capability.Registry
}

type Host struct {
	adapters Adapters
}

func New(adapters Adapters) (*Host, error) {
	if adapters.SessionResolver == nil {
		return nil, errors.New("session resolver is required")
	}
	if adapters.Policy == nil {
		return nil, errors.New("policy adapter is required")
	}
	if adapters.Capabilities == nil {
		adapters.Capabilities = capability.NewRegistry()
	}
	return &Host{adapters: adapters}, nil
}

func (h *Host) Capabilities() *capability.Registry {
	return h.adapters.Capabilities
}
