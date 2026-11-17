package host

import (
	"context"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
)

func TestInstalledCapabilityUsesDeclaredContractAndCurrentSessionWithoutSurface(t *testing.T) {
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	empty := map[string]any{"type": "object", "additionalProperties": false}
	contract.Methods = []capabilitycontract.Method{
		fixtureContractMethod("agent.begin", "execute", "sync", []string{"fs.workspace.read"}, nil, empty, empty),
		fixtureContractMethod("agent.confirm", "execute", "sync", nil, nil, empty, empty),
	}
	contract.Methods[1].Confirmation = &capabilitycontract.Confirmation{Mode: "required"}
	known := verifyFixtureCapabilityContract(t, contract)
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{capabilityContract: &known, capabilityAdapter: adapter})
	pkg := surfaceMethodsFixtureWith(t, func(m map[string]any) { m["permissions"] = append(m["permissions"].([]any), "fs.workspace.read") }, known)
	record := installAndEnablePlugin(t, h, pkg)
	request := InstalledCapabilityRequest{PluginInstanceID: record.PluginInstanceID, Method: "agent.begin"}
	if _, err := h.CallInstalledCapability(surfaceMethodTestContext(), request); err == nil {
		t.Fatal("missing permission reached adapter")
	}
	rev := mustAuthorizationRevisions(t, h, record.PluginInstanceID)
	if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "fs.workspace.read", ExpectedPolicyRevision: rev.PolicyRevision, ExpectedManagementRevision: rev.ManagementRevision, ExpectedRevokeEpoch: rev.RevokeEpoch}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CallInstalledCapability(context.Background(), request); err == nil {
		t.Fatal("missing session reached adapter")
	}
	confirmation := request
	confirmation.Method = "agent.confirm"
	if _, err := h.CallInstalledCapability(surfaceMethodTestContext(), confirmation); err == nil {
		t.Fatalf("mandatory confirmation bypassed: %v", err)
	}
	for _, method := range []string{"document.read", "document.confirm", "missing"} {
		denied := request
		denied.Method = method
		if _, err := h.CallInstalledCapability(surfaceMethodTestContext(), denied); err == nil {
			t.Fatalf("undeclared/native route allowed: %s", method)
		}
	}
	denied := request
	denied.Params = map[string]any{"unexpected": "input"}
	if _, err := h.CallInstalledCapability(surfaceMethodTestContext(), denied); err == nil {
		t.Fatal("request contract bypassed")
	}
	if adapter.calls != 0 {
		t.Fatal("rejected call reached the capability adapter")
	}
	if _, err := h.CallInstalledCapability(surfaceMethodTestContext(), request); err != nil {
		failure, outcome, _, _ := closedRPCFailure(err)
		t.Fatalf("host call: %v sentinels=%v outcome=%v", err, failure.sentinels, outcome)
	}
	source := adapter.last.Execution.ExecutionBinding
	if err := capability.ValidateExecutionBinding(source); err != nil {
		t.Fatal(err)
	}
	if source.PluginInstanceID != record.PluginInstanceID || source.TargetMethod != "agent.begin" || source.Effect != capability.EffectExecute || source.SurfaceInstanceID != "" || source.BridgeChannelID != "" {
		t.Fatalf("incorrect hosted source: %+v", source)
	}
	if err := h.ValidateCapabilityContinuation(surfaceMethodTestContext(), source); err != nil {
		t.Fatal(err)
	}
}
