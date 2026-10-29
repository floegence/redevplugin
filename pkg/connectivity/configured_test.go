package connectivity

import (
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestConfigurableConnectorNeedsExactApprovedBinding(t *testing.T) {
	policy, err := CompilePolicy(CompileRequest{PluginInstanceID: "plugin", ActiveFingerprint: "fingerprint", PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 1, Manifest: manifest.Manifest{NetworkAccess: &manifest.NetworkAccessSpec{Connectors: []manifest.NetworkConnectorSpec{{ConnectorID: "service", Transport: "http", Scope: "user", Configurable: true}}}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := connectivityTestContext("env_hash", "user_hash")
	req := GrantRequest{PluginInstanceID: "plugin", ActiveFingerprint: "fingerprint", PolicyRevision: 1, ManagementRevision: 1, RevokeEpoch: 1, ResourceScope: userResourceScope(), ConnectorID: "service", Transport: TransportHTTP, Destination: "https://api.example.com", HTTPMethod: "GET"}
	if _, err := MintConnectionGrant(ctx, policy, req); !errors.Is(err, ErrConnectorDenied) {
		t.Fatalf("unapproved configuration: %v", err)
	}
	req.Binding = &ApprovedBinding{ConnectionID: "connection", Revision: 1, Destination: "https://api.example.com", HTTPMethods: []string{"GET"}, ExpiresAt: time.Now().Add(time.Hour)}
	grant, err := MintConnectionGrant(ctx, policy, req)
	if err != nil {
		t.Fatal(err)
	}
	if grant.ConnectionID != "connection" || grant.ConnectionRevision != 1 || !grant.ResourceScope.Matches(sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"}) {
		t.Fatalf("binding lost: %+v", grant)
	}
	req.HTTPMethod = "POST"
	if _, err := MintConnectionGrant(ctx, policy, req); !errors.Is(err, ErrConnectorDenied) {
		t.Fatalf("GET approval allowed POST: %v", err)
	}
	req.HTTPMethod = "GET"
	req.Destination = "https://other.example.com"
	if _, err := MintConnectionGrant(ctx, policy, req); !errors.Is(err, ErrConnectorDenied) {
		t.Fatalf("different target accepted: %v", err)
	}
}
