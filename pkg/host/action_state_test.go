package host

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/internal/runtimeclient"
	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
)

type startupSurfaceSink struct {
	published chan SurfaceSnapshot
}

func (sink *startupSurfaceSink) PublishSurfaces(_ context.Context, snapshot SurfaceSnapshot) error {
	sink.published <- snapshot
	return nil
}

type blockingStartupRuntimeManager struct {
	*recordingRuntimeManager
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type blockingStartupStartManager struct {
	*recordingRuntimeManager
	started       chan struct{}
	startCanceled chan struct{}
	published     <-chan SurfaceSnapshot
	once          sync.Once
}

func (manager *blockingStartupStartManager) Start(ctx context.Context, target runtimetarget.Target) (runtimeclient.ManagerHealth, error) {
	select {
	case <-manager.published:
	default:
		return runtimeclient.ManagerHealth{}, errors.New("runtime start preceded startup inventory publication")
	}
	manager.once.Do(func() { close(manager.started) })
	<-ctx.Done()
	close(manager.startCanceled)
	return runtimeclient.ManagerHealth{}, ctx.Err()
}

func (manager *blockingStartupRuntimeManager) BindPlugin(ctx context.Context, pluginInstanceID string) (runtimeclient.RuntimeBinding, error) {
	manager.once.Do(func() { close(manager.started) })
	select {
	case <-manager.release:
	case <-ctx.Done():
		return runtimeclient.RuntimeBinding{}, ctx.Err()
	}
	return manager.recordingRuntimeManager.BindPlugin(ctx, pluginInstanceID)
}

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

func TestListPluginInventoryDoesNotMergeRuntimeReadinessIntoEnabledState(t *testing.T) {
	runtime := newRecordingRuntimeManager()
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode: true, localGenerated: true, runtimeManager: runtime,
	})
	record := installAndEnablePlugin(t, h, buildWorkerFixturePackage(t))
	runtime.healthErr = runtimeclient.ErrRuntimeNotReady

	listed, err := h.ListPluginInventory(hostTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Plugin.PluginInstanceID != record.PluginInstanceID {
		t.Fatalf("inventory = %#v", listed)
	}
	if state := listed[0].ActionState; !state.CanOpen || !state.CanDisable || state.BlockedReason != "" || state.RecoveryAction != "" {
		t.Fatalf("enabled inventory merged transient runtime readiness: %#v", state)
	}
}

func TestHostStartupPublishesInventoryBeforeBackgroundRuntimeRecovery(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "control-state")
	first, _, _ := newTestHostWithOptions(t, testHostOptions{
		stateRoot: stateRoot, developerMode: true, localGenerated: true,
	})
	installed := installAndEnablePlugin(t, first, buildWorkerFixturePackage(t))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	runtime := &blockingStartupRuntimeManager{
		recordingRuntimeManager: newRecordingRuntimeManager(),
		started:                 make(chan struct{}),
		release:                 make(chan struct{}),
	}
	surfaces := &startupSurfaceSink{published: make(chan SurfaceSnapshot, 1)}
	second, _, _ := newTestHostWithOptions(t, testHostOptions{
		stateRoot: stateRoot, developerMode: true, localGenerated: true,
		runtimeManager: runtime, surfaceCatalog: surfaces,
	})
	defer func() {
		close(runtime.release)
		_ = second
	}()

	select {
	case snapshot := <-surfaces.published:
		if snapshot.PluginInstanceID != installed.PluginInstanceID || len(snapshot.Surfaces) == 0 {
			t.Fatalf("startup surface snapshot = %#v", snapshot)
		}
	default:
		t.Fatal("Host.Open returned before publishing the persisted enabled inventory")
	}
	select {
	case <-runtime.started:
	case <-time.After(time.Second):
		t.Fatal("background runtime recovery did not start")
	}
}

func TestHostStartupStartsUnreadyRuntimeAfterInventoryAndCloseCancelsRecovery(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "control-state")
	first, _, _ := newTestHostWithOptions(t, testHostOptions{
		stateRoot: stateRoot, developerMode: true, localGenerated: true,
	})
	installAndEnablePlugin(t, first, buildWorkerFixturePackage(t))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	surfaces := &startupSurfaceSink{published: make(chan SurfaceSnapshot, 1)}
	runtime := &blockingStartupStartManager{
		recordingRuntimeManager: newRecordingRuntimeManager(),
		started:                 make(chan struct{}),
		startCanceled:           make(chan struct{}),
		published:               surfaces.published,
	}
	runtime.health.Ready = false
	second, _, _ := newTestHostWithOptions(t, testHostOptions{
		stateRoot: stateRoot, developerMode: true, localGenerated: true,
		runtimeManager: runtime, surfaceCatalog: surfaces,
	})

	select {
	case <-runtime.started:
	case <-time.After(time.Second):
		t.Fatal("background runtime start did not begin")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.startCanceled:
	case <-time.After(time.Second):
		t.Fatal("Host.Close did not cancel and await background runtime startup")
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

func TestRecoverEnabledIsIdempotentAndDoesNotRepublishStartupInventory(t *testing.T) {
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
	if len(surfaces.snapshots) != 0 {
		t.Fatalf("runtime recovery republished startup surfaces: %d", len(surfaces.snapshots))
	}

	second, err := h.RecoverEnabled(hostTestContext())
	if err != nil {
		t.Fatalf("second RecoverEnabled() error = %v", err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("second recovery snapshot = %#v, want %#v", second, first)
	}
	if len(surfaces.snapshots) != 0 {
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
