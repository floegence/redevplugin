package host

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/internal/controlstore"
	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestCapabilityAsyncExecutionUsesControlStore(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.ExecutionID == "" || result.ExecutionID != adapter.last.Execution.Events.ID() {
		t.Fatalf("execution identity mismatch: %#v", result)
	}
	executionID := adapter.last.Execution.Events.ID()

	record, err := h.GetExecution(hostTestContext(), executionID)
	if err != nil {
		t.Fatalf("GetExecution() error = %v", err)
	}
	if record.Kind != execution.KindOperation || record.Status != execution.StatusRunning || record.PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("execution record mismatch: %#v", record)
	}
	progress := capability.OperationProgress{Revision: 1, Phase: "archiving"}
	if err := adapter.last.Execution.Events.ReportProgress(hostTestContext(), progress); err != nil {
		t.Fatalf("ReportProgress() error = %v", err)
	}
	events, err := h.EventsAfter(hostTestContext(), executionID, 0, 10)
	if err != nil {
		t.Fatalf("EventsAfter(progress) error = %v", err)
	}
	if len(events) != 1 || events[0].Kind != execution.EventProgress || events[0].Sequence != 1 || events[0].Payload["phase"] != "archiving" {
		t.Fatalf("progress events mismatch: %#v", events)
	}

	if err := adapter.last.Execution.Events.Complete(hostTestContext()); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	record, err = h.GetExecution(hostTestContext(), executionID)
	if err != nil {
		t.Fatalf("GetExecution(terminal) error = %v", err)
	}
	if record.Status != execution.StatusCompleted || record.Cursor != 2 {
		t.Fatalf("terminal execution mismatch: %#v", record)
	}
	events, err = h.EventsAfter(hostTestContext(), executionID, 1, 10)
	if err != nil {
		t.Fatalf("EventsAfter(terminal) error = %v", err)
	}
	if len(events) != 1 || events[0].Kind != execution.EventTerminal || events[0].Payload["status"] != execution.StatusCompleted {
		t.Fatalf("terminal event mismatch: %#v", events)
	}
}

func TestCapabilitySubscriptionUsesControlStore(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildSubscriptionRPCFixturePackage(t), "subscription.view")

	result, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "logs.tail",
	})
	if err != nil {
		t.Fatalf("CallPluginMethod() error = %v", err)
	}
	if result.ExecutionID == "" || result.ExecutionID != adapter.last.Execution.Events.ID() {
		t.Fatalf("subscription execution identity mismatch: %#v", result)
	}
	executionID := adapter.last.Execution.Events.ID()

	record, err := h.GetExecution(hostTestContext(), executionID)
	if err != nil {
		t.Fatalf("GetExecution() error = %v", err)
	}
	if record.Kind != execution.KindSubscription || record.Status != execution.StatusRunning {
		t.Fatalf("subscription execution mismatch: %#v", record)
	}
	if err := adapter.last.Execution.Events.Append(hostTestContext(), map[string]any{"line": "line 1"}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	events, err := h.EventsAfter(hostTestContext(), executionID, 0, 10)
	if err != nil {
		t.Fatalf("EventsAfter(data) error = %v", err)
	}
	wantData := base64.StdEncoding.EncodeToString([]byte(`{"line":"line 1"}`))
	if len(events) != 1 || events[0].Kind != execution.EventData || events[0].Payload["event_type"] != "LogEvent" || events[0].Payload["data"] != wantData {
		t.Fatalf("data event mismatch: %#v", events)
	}

	if err := adapter.last.Execution.Events.Close(hostTestContext()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	record, err = h.GetExecution(hostTestContext(), executionID)
	if err != nil {
		t.Fatalf("GetExecution(terminal) error = %v", err)
	}
	if record.Status != execution.StatusCompleted || record.Cursor != 2 {
		t.Fatalf("terminal subscription mismatch: %#v", record)
	}
	events, err = h.EventsAfter(hostTestContext(), executionID, 1, 10)
	if err != nil {
		t.Fatalf("EventsAfter(terminal) error = %v", err)
	}
	if len(events) != 1 || events[0].Kind != execution.EventTerminal || events[0].Payload["status"] != execution.StatusCompleted {
		t.Fatalf("terminal event mismatch: %#v", events)
	}
}

func TestCancelExecutionDispatchesThroughLiveExecution(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		capabilityID: "example.capability.echo", capabilityAdapter: adapter,
	})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	_, err := h.CallPluginMethod(hostTestContext(), CallMethodRequest{
		PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc",
		BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken,
		Method: "documents.archive", Params: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	executionID := adapter.last.Execution.Events.ID()

	record, err := h.CancelExecution(hostTestContext(), executionID, "user")
	if err != nil {
		t.Fatalf("CancelExecution() error = %v", err)
	}
	if record.Status != execution.StatusCancelRequested || adapter.cancelCalls != 1 || adapter.lastCancellation.ExecutionID != executionID {
		t.Fatalf("cancellation dispatch mismatch: record=%#v calls=%d request=%#v", record, adapter.cancelCalls, adapter.lastCancellation)
	}
	retried, err := h.CancelExecution(hostTestContext(), executionID, "user")
	if err != nil {
		t.Fatalf("CancelExecution(retry) error = %v", err)
	}
	if retried.Status != execution.StatusCancelRequested || adapter.cancelCalls != 1 {
		t.Fatalf("cancellation retry was not idempotent: record=%#v calls=%d", retried, adapter.cancelCalls)
	}
	select {
	case <-adapter.last.Execution.Events.CancelRequested():
	default:
		t.Fatal("execution cancellation signal was not closed")
	}
	if err := adapter.last.Execution.Events.Cancel(hostTestContext(), "user"); err != nil {
		t.Fatalf("Events.Cancel() error = %v", err)
	}
	record, err = h.GetExecution(hostTestContext(), executionID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != execution.StatusCanceled {
		t.Fatalf("terminal cancellation mismatch: %#v", record)
	}
}

func TestDurableExecutionReconciliationUsesOnlyControlStore(t *testing.T) {
	stateRoot := t.TempDir()
	controlDB, err := controlstore.Open(hostTestContext(), controlstore.Config{Path: filepath.Join(stateRoot, "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	if err := controlDB.Executions().CreateOwned(hostTestContext(), execution.Execution{
		ID: "execution_control", PluginInstanceID: "plugin_control", Kind: execution.KindOperation, Cancelable: true,
	}, executionOwner(hostTestContextSession())); err != nil {
		controlDB.Close()
		t.Fatal(err)
	}
	if err := controlDB.Close(); err != nil {
		t.Fatal(err)
	}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{stateRoot: stateRoot})
	control, err := h.GetExecution(hostTestContext(), "execution_control")
	if err != nil {
		t.Fatal(err)
	}
	if control.Status != execution.StatusOrphaned {
		t.Fatalf("control execution = %#v", control)
	}
	events, err := h.EventsAfter(hostTestContext(), control.ID, 0, 10)
	if err != nil || len(events) != 1 || events[0].Kind != execution.EventTerminal || events[0].Payload["status"] != execution.StatusOrphaned {
		t.Fatalf("control execution events = %#v, %v", events, err)
	}
}

func hostTestContextSession() sessionctx.Context {
	session, _ := sessionctx.FromContext(hostTestContext())
	return session
}

func TestSurfaceExecutionCannotAccessSiblingPlugin(t *testing.T) {
	adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{"started": true}}}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{capabilityID: "example.capability.echo", capabilityAdapter: adapter})
	installed, gateway := installEnableAndMintGateway(t, h, buildOperationRPCFixturePackage(t), "operation.view")
	ctx := hostTestContext()
	result, err := h.CallPluginMethod(ctx, CallMethodRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken, Method: "documents.archive", Params: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	scope := SurfaceExecutionScope{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: "surface_rpc", BridgeChannelID: "bridge_rpc", GatewayToken: gateway.GatewayToken}
	if _, err := h.GetSurfaceExecution(ctx, result.ExecutionID, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SurfaceEventsAfter(ctx, result.ExecutionID, 0, 10, scope); err != nil {
		t.Fatal(err)
	}
	victim := execution.Execution{ID: "execution_foreign_plugin", PluginInstanceID: "plugini_other", Kind: execution.KindOperation, Cancelable: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	session := sessionctx.Context{OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash"}
	if err := h.controlStore.Executions().CreateOwned(ctx, victim, executionOwner(session)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.GetSurfaceExecution(ctx, victim.ID, scope); !errors.Is(err, controlstore.ErrRecordNotFound) {
		t.Fatalf("foreign query = %v", err)
	}
	if _, err := h.SurfaceEventsAfter(ctx, victim.ID, 0, 10, scope); !errors.Is(err, controlstore.ErrRecordNotFound) {
		t.Fatalf("foreign events = %v", err)
	}
	if _, err := h.CancelSurfaceExecution(ctx, victim.ID, "cancel", scope); !errors.Is(err, controlstore.ErrRecordNotFound) {
		t.Fatalf("foreign cancel = %v", err)
	}
	current, err := h.GetExecution(ctx, victim.ID)
	if err != nil || current.Status != execution.StatusRunning {
		t.Fatalf("foreign execution changed: %#v %v", current, err)
	}
	invalid := scope
	invalid.BridgeChannelID = "wrong-channel"
	if _, err := h.CancelSurfaceExecution(ctx, result.ExecutionID, "cancel", invalid); err == nil {
		t.Fatal("wrong channel accepted")
	}
	invalid = scope
	invalid.GatewayToken = ""
	if _, err := h.GetSurfaceExecution(ctx, result.ExecutionID, invalid); err == nil {
		t.Fatal("empty gateway accepted")
	}
	if _, err := h.CancelSurfaceExecution(ctx, result.ExecutionID, "cancel", scope); err != nil {
		t.Fatal(err)
	}
	if _, err := h.surfaceTokens.RevokePlugin(session.OwnerEnvHash, installed.PluginInstanceID, installed.RevokeEpoch+1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.GetSurfaceExecution(ctx, result.ExecutionID, scope); err == nil {
		t.Fatal("revoked gateway queried execution")
	}
	if _, err := h.SurfaceEventsAfter(ctx, result.ExecutionID, 0, 10, scope); err == nil {
		t.Fatal("revoked gateway read events")
	}
	if _, err := h.CancelSurfaceExecution(ctx, result.ExecutionID, "cancel", scope); err == nil {
		t.Fatal("revoked gateway canceled execution")
	}

}
