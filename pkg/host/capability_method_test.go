package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func capabilityMethodTestHost(t *testing.T) (*Host, SurfaceMethodsRequest, capability.ExecutionBinding) {
	t.Helper()
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	empty := map[string]any{"type": "object", "additionalProperties": false}
	contract.Methods = []capabilitycontract.Method{fixtureContractMethod("agent.begin", "execute", "sync", nil, nil, empty, empty)}
	known := verifyFixtureCapabilityContract(t, contract)
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{capabilityContract: &known, capabilityAdapter: adapter})
	installed := installAndEnablePlugin(t, h, surfaceMethodsFixture(t, known))
	receiver := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "agent_surface")
	_, err = h.CallPluginMethod(surfaceMethodTestContext(), CallMethodRequest{PluginInstanceID: receiver.PluginInstanceID, SurfaceInstanceID: receiver.SurfaceInstanceID, BridgeChannelID: receiver.BridgeChannelID, GatewayToken: receiver.GatewayToken, Method: "agent.begin"})
	if err != nil {
		t.Fatal(err)
	}
	return h, receiver, adapter.last.Execution.ExecutionBinding
}

func TestCapabilityMethodUsesNativeReceiverAndConfirmation(t *testing.T) {
	h, receiver, source := capabilityMethodTestHost(t)
	ctx := surfaceMethodTestContext()
	input := CapabilityMethodRequest{Method: "document.confirm"}
	if result, err := h.InvokeCapabilityMethod(ctx, source, input); !errors.Is(err, ErrConfirmationRequired) || !result.ConfirmationRequired {
		t.Fatalf("missing confirmation: %+v %v", result, err)
	}
	confirmation, err := h.PrepareCapabilityMethodConfirmation(ctx, source, input)
	if err != nil {
		t.Fatal(err)
	}
	input.ConfirmationID = confirmation.ConfirmationID
	outcome := make(chan error, 1)
	go func() { _, err := h.InvokeCapabilityMethod(ctx, source, input); outcome <- err }()
	receiver.Operation = "claim"
	claim, err := h.SurfaceMethods(ctx, receiver)
	if err != nil || claim.Invocation == nil || claim.Invocation.Method != input.Method {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	receiver.Operation = "complete"
	receiver.InvocationID = claim.Invocation.InvocationID
	receiver.Data = map[string]any{}
	if _, err := h.SurfaceMethods(ctx, receiver); err != nil {
		t.Fatal(err)
	}
	if err := <-outcome; err != nil {
		t.Fatal(err)
	}
	if _, err := h.InvokeCapabilityMethod(ctx, source, input); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("confirmation replay: %v", err)
	}
}

func TestCapabilityMethodRejectsAuthorityChangesAndRecursiveDispatch(t *testing.T) {
	h, receiver, source := capabilityMethodTestHost(t)
	ctx := surfaceMethodTestContext()
	methods, err := h.DescribeCapabilityMethods(ctx, source, []string{"document.read", "document.apply"})
	if err != nil || len(methods) != 2 {
		t.Fatalf("method discovery: %+v %v", methods, err)
	}
	methods[0].RequestSchema["additionalProperties"] = true
	methods, err = h.DescribeCapabilityMethods(ctx, source, []string{"document.read"})
	if err != nil || methods[0].RequestSchema["additionalProperties"] != false {
		t.Fatalf("discovery mutated installed schema: %+v %v", methods, err)
	}
	if _, err := h.DescribeCapabilityMethods(ctx, source, []string{"agent.begin"}); err == nil {
		t.Fatal("capability recursion exposed as native tool")
	}
	for _, method := range []string{"agent.begin", "missing.method"} {
		if _, err := h.InvokeCapabilityMethod(ctx, source, CapabilityMethodRequest{Method: method}); !errors.Is(err, ErrMethodRequestContract) {
			t.Fatalf("method %s: %v", method, err)
		}
	}
	if _, err := h.InvokeCapabilityMethod(ctx, source, CapabilityMethodRequest{Method: "document.read", Params: map[string]any{"unexpected": true}}); !errors.Is(err, ErrMethodRequestContract) {
		t.Fatalf("schema mismatch: %v", err)
	}
	owner, _ := sessionctx.FromContext(ctx)
	owner.OwnerUserHash = "another-user"
	if _, err := h.InvokeCapabilityMethod(sessionctx.WithContext(ctx, owner), source, CapabilityMethodRequest{Method: "document.read"}); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("another owner: %v", err)
	}
	owner, _ = sessionctx.FromContext(ctx)
	owner.CanWrite = false
	if _, err := h.InvokeCapabilityMethod(sessionctx.WithContext(ctx, owner), source, CapabilityMethodRequest{Method: "document.apply"}); err == nil {
		t.Fatal("read-only session changed plugin state")
	}
	for _, alter := range []func(*capability.ExecutionBinding){
		func(b *capability.ExecutionBinding) { b.ActiveFingerprint = "replaced" },
		func(b *capability.ExecutionBinding) { b.Revision.RevokeEpoch++ },
		func(b *capability.ExecutionBinding) { b.Quota.ExpiresAt = time.Now().Add(-time.Second) },
		func(b *capability.ExecutionBinding) { b.BridgeChannelID = "different-channel" },
	} {
		changed := source
		alter(&changed)
		if _, err := h.InvokeCapabilityMethod(ctx, changed, CapabilityMethodRequest{Method: "document.read"}); err == nil {
			t.Fatalf("changed authority accepted: %+v", changed)
		}
	}
	// Closing the source receiver must not select another live plugin window.
	_ = openSurfaceMethodReceiver(t, h, receiver.PluginInstanceID, "sibling_surface")
	receiver.Operation = "close"
	if _, err := h.SurfaceMethods(ctx, receiver); err != nil {
		t.Fatal(err)
	}
	if _, err := h.InvokeCapabilityMethod(ctx, source, CapabilityMethodRequest{Method: "document.read"}); !errors.Is(err, ErrSurfaceMethodUnavailable) {
		t.Fatalf("closed target substitution: %v", err)
	}
}

func TestCapabilityMethodRetainsUnknownEffectAfterClaim(t *testing.T) {
	h, receiver, source := capabilityMethodTestHost(t)
	ctx, cancel := context.WithCancel(surfaceMethodTestContext())
	defer cancel()
	outcome := make(chan error, 1)
	go func() {
		_, err := h.InvokeCapabilityMethod(ctx, source, CapabilityMethodRequest{Method: "document.apply"})
		outcome <- err
	}()
	receiver.Operation = "claim"
	claim, err := h.SurfaceMethods(surfaceMethodTestContext(), receiver)
	if err != nil || claim.Invocation == nil {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	cancel()
	select {
	case err := <-outcome:
		if mutation.ForError(err) != mutation.OutcomeUnknown {
			t.Fatalf("effect after dispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not propagate")
	}
}
