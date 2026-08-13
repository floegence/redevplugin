package host

import (
	"errors"
	"reflect"
	"testing"

	"github.com/floegence/redevplugin/pkg/capability"
)

func TestListPluginInventoryReturnsAuthoritativeActionState(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	record := installAndEnablePlugin(t, h, buildFixturePackage(t))

	listed, err := h.ListPluginInventory(hostTestContext())
	if err != nil {
		t.Fatalf("ListPluginInventory() error = %v", err)
	}
	if len(listed) != 1 || listed[0].Plugin.PluginInstanceID != record.PluginInstanceID {
		t.Fatalf("ListPluginInventory() = %#v", listed)
	}
	want := PluginActionState{
		CanOpen:      true,
		CanDisable:   true,
		CanUninstall: true,
	}
	if !reflect.DeepEqual(listed[0].ActionState, want) {
		t.Fatalf("enabled action state = %#v, want %#v", listed[0].ActionState, want)
	}

	disabled, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           record.PluginInstanceID,
		ExpectedManagementRevision: record.ManagementRevision,
	})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	listed, err = h.ListPluginInventory(hostTestContext())
	if err != nil {
		t.Fatalf("ListPluginInventory() after disable error = %v", err)
	}
	want = PluginActionState{
		CanEnable:     true,
		CanUninstall:  true,
		BlockedReason: PluginActionBlockedDisabled,
	}
	if len(listed) != 1 || listed[0].Plugin.ManagementRevision != disabled.ManagementRevision || !reflect.DeepEqual(listed[0].ActionState, want) {
		t.Fatalf("disabled inventory = %#v, want action %#v", listed, want)
	}
}

func TestListPluginInventoryBlocksOpenWhenRequiredGrantIsMissing(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	record := installAndEnablePlugin(t, h, buildRPCFixturePackage(t))

	listed, err := h.ListPluginInventory(hostTestContext())
	if err != nil {
		t.Fatalf("ListPluginInventory() error = %v", err)
	}
	if len(listed) != 1 || listed[0].Plugin.PluginInstanceID != record.PluginInstanceID {
		t.Fatalf("ListPluginInventory() = %#v", listed)
	}
	if state := listed[0].ActionState; state.CanOpen || state.BlockedReason != PluginActionBlockedPermission {
		t.Fatalf("action state without required grant = %#v, want permission_required", state)
	}
}

func TestListPluginInventoryBlocksOpenWhenSecurityPolicyDeniesMethod(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		capabilityID:      "example.capability.echo",
		capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"ok": true}}},
	})
	record := installAndEnablePlugin(t, h, buildRPCFixturePackage(t))
	grantDeclaredPermissions(t, h, record)
	revisions := mustAuthorizationRevisions(t, h, record.PluginInstanceID)
	if _, err := h.PutSecurityPolicy(hostTestContext(), PutSecurityPolicyRequest{
		PluginInstanceID:           record.PluginInstanceID,
		ExpectedPolicyRevision:     revisions.PolicyRevision,
		ExpectedManagementRevision: revisions.ManagementRevision,
		ExpectedRevokeEpoch:        revisions.RevokeEpoch,
		DeniedMethods:              []string{"echo.ping"},
	}); err != nil {
		t.Fatalf("PutSecurityPolicy() error = %v", err)
	}

	listed, err := h.ListPluginInventory(hostTestContext())
	if err != nil {
		t.Fatalf("ListPluginInventory() error = %v", err)
	}
	if len(listed) != 1 || listed[0].Plugin.PluginInstanceID != record.PluginInstanceID {
		t.Fatalf("ListPluginInventory() = %#v", listed)
	}
	if state := listed[0].ActionState; state.CanOpen || state.BlockedReason != PluginActionBlockedPolicy {
		t.Fatalf("action state with denied method = %#v, want policy_restricted", state)
	}
}

func TestRecoverEnabledIsIdempotentForHostStartupRevision(t *testing.T) {
	h, surfaces, _ := newTestHost(t, true, true)
	record := installAndEnablePlugin(t, h, buildFixturePackage(t))
	surfaces.snapshots = nil

	first, err := h.RecoverEnabled(hostTestContext())
	if err != nil {
		t.Fatalf("RecoverEnabled() error = %v", err)
	}
	if !first.Complete || first.Revision != 1 || len(first.Results) != 1 ||
		first.Results[0].PluginInstanceID != record.PluginInstanceID ||
		first.Results[0].Status != PluginRecoveryReady {
		t.Fatalf("first recovery snapshot = %#v", first)
	}
	if len(surfaces.snapshots) != 1 {
		t.Fatalf("surface publications after first recovery = %d, want 1", len(surfaces.snapshots))
	}

	second, err := h.RecoverEnabled(hostTestContext())
	if err != nil {
		t.Fatalf("second RecoverEnabled() error = %v", err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("second recovery snapshot = %#v, want %#v", second, first)
	}
	if len(surfaces.snapshots) != 1 {
		t.Fatalf("idempotent recovery republished surfaces: %d", len(surfaces.snapshots))
	}
}

func TestRetryPluginRecoveryRejectsDisabledPluginWithoutCompletingSnapshot(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	record := installAndEnablePlugin(t, h, buildFixturePackage(t))

	first, err := h.RecoverEnabled(hostTestContext())
	if err != nil {
		t.Fatalf("RecoverEnabled() error = %v", err)
	}
	disabled, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           record.PluginInstanceID,
		ExpectedManagementRevision: record.ManagementRevision,
	})
	if err != nil {
		t.Fatalf("DisablePlugin() error = %v", err)
	}
	if _, err := h.RetryPluginRecovery(hostTestContext(), disabled.PluginInstanceID); !errors.Is(err, ErrPluginRecoveryNotEnabled) {
		t.Fatalf("RetryPluginRecovery() error = %v, want ErrPluginRecoveryNotEnabled", err)
	}
	after, err := h.RecoverEnabled(hostTestContext())
	if err != nil {
		t.Fatalf("RecoverEnabled() after rejected retry error = %v", err)
	}
	if !reflect.DeepEqual(after, first) {
		t.Fatalf("rejected retry changed recovery snapshot: got %#v want %#v", after, first)
	}
}
