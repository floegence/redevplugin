package websecurity

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestSessionContextRequiresCompleteAuthenticatedPrincipal(t *testing.T) {
	valid := sessionctx.Context{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}
	if !valid.Valid() {
		t.Fatal("complete session must be valid")
	}
	if got, err := sessionctx.Require(sessionctx.WithContext(context.Background(), valid)); err != nil || got != valid {
		t.Fatalf("session round trip = %#v, %v", got, err)
	}

	invalid := valid
	invalid.OwnerEnvHash = ""
	if invalid.Valid() {
		t.Fatal("session without environment hash must be invalid")
	}
	if _, err := sessionctx.Require(sessionctx.WithContext(context.Background(), invalid)); !errors.Is(err, sessionctx.ErrSessionRequired) {
		t.Fatalf("Require invalid session error = %v", err)
	}
}

func TestSecurityPolicyTypesRejectUnknownValues(t *testing.T) {
	if !RouteActionListPlugins.Valid() || RouteAction("plugin.unknown").Valid() {
		t.Fatal("route action validity is not closed")
	}
	if !OriginPolicyTrustedHost.Valid() || OriginPolicy("allow_any").Valid() {
		t.Fatal("origin policy validity is not closed")
	}
	if !CSRFPolicyNotRequired.Valid() || !CSRFPolicyRequired.Valid() || CSRFPolicy("optional").Valid() {
		t.Fatal("csrf policy validity is not closed")
	}
}
