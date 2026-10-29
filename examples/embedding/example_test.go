// Package embedding demonstrates a minimal Host without any product imports.
package embedding

import (
	"context"
	"fmt"
	"os"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/observability"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/trust"
)

// A real product maps its authenticated session and policy at these boundaries.
// This example permits only inventory reads and cannot import or execute code.
type readOnlyPolicy struct{}

func (readOnlyPolicy) EvaluateLocalPolicy(context.Context, sessionctx.Context, host.PluginRef, manifest.MethodSpec) (host.PolicyDecision, error) {
	return host.PolicyAllow, host.ErrActionDenied
}
func (readOnlyPolicy) DeveloperModeEnabled(context.Context, sessionctx.Context) (bool, error) {
	return false, nil
}
func (readOnlyPolicy) LocalGeneratedPluginsEnabled(context.Context, sessionctx.Context) (bool, error) {
	return false, nil
}
func (readOnlyPolicy) Authorize(_ context.Context, request host.AuthorizationRequest) error {
	if request.Session.Valid() && request.Action == host.ManagementActionListPlugins {
		return nil
	}
	return host.ErrActionDenied
}

func Example_minimalHost() {
	root, err := os.MkdirTemp("", "redevplugin-embedding-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	events := observability.NewMemoryStore()
	ctx := sessionctx.WithContext(context.Background(), sessionctx.Context{OwnerSessionHash: "example-session", OwnerUserHash: "example-user", OwnerEnvHash: "example-environment", SessionChannelIDHash: "example-channel", CanRead: true})
	platform, err := host.Open(ctx, host.Config{StateRoot: root, Core: host.CoreAdapters{
		Policy: readOnlyPolicy{}, Authorization: readOnlyPolicy{},
		PackageTrustVerifier: trust.Ed25519Verifier{Keyring: trust.StaticKeyring{}},
		Audit:                events, SecurityAudit: events, Diagnostics: events, Assets: pluginpkg.NewMemoryAssetStore(),
	}})
	if err != nil {
		panic(err)
	}
	defer platform.Close()
	plugins, err := platform.ListPlugins(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("installed plugins:", len(plugins))
	// Output: installed plugins: 0
}
