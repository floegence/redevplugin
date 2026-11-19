package host

import (
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"testing"
	"time"
)

func TestCapabilityContinuationRechecksExactPublishedAuthority(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{capabilityID: "example.capability.echo", capabilityAdapter: adapter})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	b := adapter.last.Execution.ExecutionBinding
	readContext := sessionctx.WithContext(t.Context(), sessionctx.Context{OwnerSessionHash: b.OwnerSessionHash, OwnerUserHash: b.OwnerUserHash, OwnerEnvHash: b.OwnerEnvHash, SessionChannelIDHash: b.SessionChannelIDHash, CanRead: true})
	if allowed, e := h.AllowsCapabilityRead(hostTestContext(), b, b.TargetMethod); e == nil || allowed {
		t.Fatal("caller without read authority was accepted")
	}
	for _, target := range []string{"undeclared.read", b.TargetMethod} {
		if allowed, e := h.AllowsCapabilityRead(readContext, b, target); e != nil || allowed {
			t.Fatalf("optional read admitted undeclared or mutating target %q: %t %v", target, allowed, e)
		}
	}
	if err = h.ValidateCapabilityContinuation(t.Context(), b); err != nil {
		t.Fatalf("binding %+v: %v", b, err)
	}
	changed := b
	changed.ActiveFingerprint = "different"
	if err = h.ValidateCapabilityContinuation(t.Context(), changed); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatal(err)
	}
	changed = b
	changed.Revision.RevokeEpoch++
	if err = h.ValidateCapabilityContinuation(t.Context(), changed); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatal(err)
	}
	changed = b
	changed.Quota.ExpiresAt = time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	if err = h.ValidateCapabilityContinuation(t.Context(), changed); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatal(err)
	}
}
