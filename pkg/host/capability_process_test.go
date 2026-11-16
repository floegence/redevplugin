package host

import (
	"context"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	processruntime "github.com/floegence/redevplugin/v3/pkg/process"
	"io"
	"testing"
	"time"
)

func capabilityProcessFixture(t *testing.T, grant bool) (*Host, capability.ExecutionBinding) {
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
	supervisor, err := processruntime.NewSupervisor(processruntime.Options{})
	if err != nil {
		t.Fatal(err)
	}
	h.processSupervisor = supervisor
	h.adapters.ProcessSupervisor = supervisor
	t.Cleanup(func() { _ = supervisor.Shutdown(context.Background()) })
	h.features[FeatureProcess] = struct{}{}
	pkg := surfaceMethodsFixtureWith(t, func(m map[string]any) {
		m["process"] = map[string]any{"resource_limits": map[string]any{"max_runtime_ms": 60000, "output_buffer_bytes": 65536}}
		api := m["api"].(map[string]any)
		api["required_features"] = append(api["required_features"].([]any), string(manifest.FeatureProcessLocal))
		m["permissions"] = append(m["permissions"].([]any), string(manifest.PermissionProcessLocal))
	}, known)
	installed := installAndEnablePlugin(t, h, pkg)
	if grant {
		rev := mustAuthorizationRevisions(t, h, installed.PluginInstanceID)
		if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{PluginInstanceID: installed.PluginInstanceID, PermissionID: "process.local", ExpectedPolicyRevision: rev.PolicyRevision, ExpectedManagementRevision: rev.ManagementRevision, ExpectedRevokeEpoch: rev.RevokeEpoch}); err != nil {
			t.Fatal(err)
		}
	}
	receiver := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "process_surface")
	if _, err := h.CallPluginMethod(surfaceMethodTestContext(), CallMethodRequest{PluginInstanceID: receiver.PluginInstanceID, SurfaceInstanceID: receiver.SurfaceInstanceID, BridgeChannelID: receiver.BridgeChannelID, GatewayToken: receiver.GatewayToken, Method: "agent.begin"}); err != nil {
		t.Fatal(err)
	}
	return h, adapter.last.Execution.ExecutionBinding
}

func TestCapabilityProcessRequiresCurrentIndependentProcessGrant(t *testing.T) {
	h, source := capabilityProcessFixture(t, false)
	if process, err := h.OpenCapabilityProcess(surfaceMethodTestContext(), source, processruntime.StartRequest{Program: "cat", ClientKey: "mcp"}); err == nil {
		process.Close()
		t.Fatal("missing process grant launched")
	}
}
func TestCapabilityProcessStreamsPreserveBytesAndCloseOnExpiry(t *testing.T) {
	h, source := capabilityProcessFixture(t, true)
	source.Quota.ExpiresAt = time.Now().UTC().Add(2 * time.Second).Truncate(time.Second)
	ctx := surfaceMethodTestContext()
	process, err := h.OpenCapabilityProcess(ctx, source, processruntime.StartRequest{Program: "cat", ClientKey: "mcp"})
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	if _, err := h.OpenCapabilityProcess(ctx, source, processruntime.StartRequest{Program: "cat", ClientKey: "mcp"}); !errors.Is(err, processruntime.ErrLaunchConflict) {
		t.Fatalf("duplicate lease: %v", err)
	}
	if _, err := process.Stdin.Write([]byte("{\"jsonrpc\":\"2.0\"}\n")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 18)
	if _, err := io.ReadFull(process.Stdout, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\"jsonrpc\":\"2.0\"}\n" {
		t.Fatalf("changed bytes: %q", data)
	}
	read := make(chan error, 1)
	go func() { _, err := process.Stdout.Read(make([]byte, 1)); read <- err }()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("expired read succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expiry did not close blocked read")
	}
	if _, err := process.Stdin.Write([]byte("late")); err == nil {
		t.Fatal("late write")
	}
}

func TestCapabilityProcessCancelAndHostCloseDrainExactLease(t *testing.T) {
	for _, mode := range []string{"cancel", "host-close", "revoke"} {
		t.Run(mode, func(t *testing.T) {
			h, source := capabilityProcessFixture(t, true)
			ctx, cancel := context.WithCancel(surfaceMethodTestContext())
			defer cancel()
			process, err := h.OpenCapabilityProcess(ctx, source, processruntime.StartRequest{Program: "cat", ClientKey: "mcp"})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cancel" {
				cancel()
			} else if mode == "revoke" {
				rev := mustAuthorizationRevisions(t, h, source.PluginInstanceID)
				if _, err := h.RevokePermission(surfaceMethodTestContext(), RevokePermissionRequest{PluginInstanceID: source.PluginInstanceID, PermissionID: "process.local", ExpectedPolicyRevision: rev.PolicyRevision, ExpectedManagementRevision: rev.ManagementRevision, ExpectedRevokeEpoch: rev.RevokeEpoch}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := h.Close(); err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				h.capabilityProcessesMu.Lock()
				count := len(h.capabilityProcesses)
				h.capabilityProcessesMu.Unlock()
				if count == 0 {
					break
				}
				select {
				case <-deadline.C:
					t.Fatal("lease not drained")
				case <-tick.C:
				}
			}
			if _, err := process.Stdin.Write([]byte("late")); err == nil {
				t.Fatal("closed lease accepted write")
			}
			if err := process.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
