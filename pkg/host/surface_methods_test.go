package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func surfaceMethodsFixture(t *testing.T) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(fixtureManifestJSON()), &m); err != nil {
		t.Fatal(err)
	}
	empty := map[string]any{"type": "object", "additionalProperties": false}
	m["methods"] = []any{
		map[string]any{"method": "document.read", "effect": "read", "execution": "sync", "route": map[string]any{"kind": "surface", "surface_id": "lifecycle.view"}, "request_schema": empty, "response_schema": empty},
		map[string]any{"method": "document.apply", "effect": "write", "execution": "sync", "route": map[string]any{"kind": "surface", "surface_id": "lifecycle.view"}, "request_schema": empty, "response_schema": empty},
		map[string]any{"method": "document.confirm", "effect": "write", "execution": "sync", "dangerous": true, "confirmation": map[string]any{"mode": "required", "request_hash_fields": []string{}}, "route": map[string]any{"kind": "surface", "surface_id": "lifecycle.view"}, "request_schema": empty, "response_schema": empty},
	}
	m["methods"] = append(m["methods"].([]any), map[string]any{"method": "document.operation", "effect": "write", "execution": "operation", "cancel_policy": map[string]any{"cancelable": true, "disable_behavior": "cancel", "uninstall_behavior": "cancel_then_block_delete", "ack_timeout_ms": 2000}, "route": map[string]any{"kind": "surface", "surface_id": "lifecycle.view"}, "request_schema": empty, "response_schema": empty})
	m["intents"] = []any{map[string]any{"intent_id": "document.operation", "method": "document.operation"}, map[string]any{"intent_id": "document.read", "method": "document.read"}, map[string]any{"intent_id": "document.apply", "method": "document.apply"}, map[string]any{"intent_id": "document.confirm", "method": "document.confirm"}}
	root := t.TempDir()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "manifest.json"), string(raw))
	writeSurfaceFixture(t, root, "Document")
	var archive bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(surfaceMethodTestContext(), root, &archive, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func openSurfaceMethodReceiver(t *testing.T, h *Host, pluginID, id string) SurfaceMethodsRequest {
	t.Helper()
	_, token := openSurfaceAndMintGatewayForAudience(t, h, pluginID, "lifecycle.view", id, "bridge_"+id)
	req := SurfaceMethodsRequest{PluginInstanceID: pluginID, SurfaceInstanceID: id, BridgeChannelID: "bridge_" + id, GatewayToken: token.GatewayToken, Operation: "register", Methods: []string{"document.read", "document.apply", "document.confirm", "document.operation"}}
	result, err := h.SurfaceMethods(surfaceMethodTestContext(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.ReceiverID = result.ReceiverID
	req.Methods = nil
	return req
}

func TestSurfaceMethodsExactTargetClaimAndReceiverCAS(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, surfaceMethodsFixture(t))
	first := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "document_first")
	second := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "document_second")
	_, err := h.InvokeIntent(surfaceMethodTestContext(), InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, IntentID: "document.read"})
	if !errors.Is(err, ErrSurfaceMethodAmbiguous) {
		t.Fatalf("ambiguous target: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := h.InvokeIntent(surfaceMethodTestContext(), InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: first.SurfaceInstanceID, IntentID: "document.apply"})
		result <- err
	}()
	first.Operation = "claim"
	claim, err := h.SurfaceMethods(surfaceMethodTestContext(), first)
	if err != nil || claim.Invocation == nil {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	second.Operation = "complete"
	second.InvocationID = claim.Invocation.InvocationID
	second.Data = map[string]any{}
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), second); !errors.Is(err, ErrSurfaceMethodConflict) {
		t.Fatalf("sibling completion: %v", err)
	}
	first.Operation = "complete"
	first.InvocationID = claim.Invocation.InvocationID
	first.Data = map[string]any{}
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), first); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), first); !errors.Is(err, ErrSurfaceMethodConflict) {
		t.Fatalf("replayed result: %v", err)
	}
	old := first
	first.InvocationID = ""
	first.Data = nil
	first.Operation = "close"
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), first); err != nil {
		t.Fatal(err)
	}
	first.Operation = "register"
	first.Methods = []string{"document.read"}
	first.InvocationID = ""
	first.Data = nil
	renewed, err := h.SurfaceMethods(surfaceMethodTestContext(), first)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ReceiverID == first.ReceiverID {
		t.Fatal("navigation reused receiver")
	}
	old.InvocationID = ""
	old.Data = nil
	old.Operation = "close"
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), old); !errors.Is(err, ErrSurfaceMethodConflict) {
		t.Fatalf("late close: %v", err)
	}
	first.ReceiverID = ""
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), first); !errors.Is(err, ErrSurfaceMethodConflict) {
		t.Fatalf("late registration: %v", err)
	}
}

func TestSurfaceMethodsCancellationUnknownAfterClaimAndConfirmationGeneration(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, surfaceMethodsFixture(t))
	receiver := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "document_cancel")
	call := InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: receiver.SurfaceInstanceID, IntentID: "document.confirm"}
	approval, err := h.PrepareIntentConfirmation(surfaceMethodTestContext(), call)
	if err != nil {
		t.Fatal(err)
	}
	receiver.Operation = "register"
	receiver.Methods = []string{"document.read", "document.apply", "document.confirm"}
	fresh, err := h.SurfaceMethods(surfaceMethodTestContext(), receiver)
	if err != nil {
		t.Fatal(err)
	}
	receiver.ReceiverID = fresh.ReceiverID
	receiver.Methods = nil
	call.ConfirmationID = approval.ConfirmationID
	if _, err = h.InvokeIntent(surfaceMethodTestContext(), call); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("confirmation crossed navigation: %v", err)
	}
	ctx, cancel := context.WithCancel(surfaceMethodTestContext())
	defer cancel()
	outcome := make(chan error, 1)
	go func() {
		_, err := h.InvokeIntent(ctx, InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: receiver.SurfaceInstanceID, IntentID: "document.apply"})
		outcome <- err
	}()
	receiver.Operation = "claim"
	claim, err := h.SurfaceMethods(surfaceMethodTestContext(), receiver)
	if err != nil || claim.Invocation == nil {
		t.Fatalf("claim: %v", err)
	}
	cancel()
	select {
	case err = <-outcome:
		if mutation.ForError(err) != mutation.OutcomeUnknown {
			t.Fatalf("claimed write outcome=%s %v", mutation.ForError(err), err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not stop dispatch")
	}
	receiver.Operation = "complete"
	receiver.InvocationID = claim.Invocation.InvocationID
	receiver.Data = map[string]any{}
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), receiver); err == nil {
		t.Fatal("late result accepted")
	}
}

func surfaceMethodTestContext() context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash", CanRead: true, CanWrite: true})
}

func TestSurfaceMethodsUnregisterRejectsQueuedCallWithoutDispatch(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, surfaceMethodsFixture(t))
	req := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "document_unregister")
	result := make(chan error, 1)
	go func() {
		_, err := h.InvokeIntent(surfaceMethodTestContext(), InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, IntentID: "document.apply"})
		result <- err
	}()
	waitForSurfaceMethodQueue(t, h, req.SurfaceInstanceID)
	req.Operation = "configure"
	req.Methods = []string{"document.read"}
	if _, err := h.SurfaceMethods(surfaceMethodTestContext(), req); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrSurfaceMethodUnavailable) || mutation.ForError(err) != mutation.OutcomeNotCommitted {
			t.Fatalf("unregister: %s %v", mutation.ForError(err), err)
		}
	case <-time.After(time.Second):
		t.Fatal("unregistered queued call was not rejected")
	}
}

func waitForSurfaceMethodQueue(t *testing.T, h *Host, id string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		queued := false
		h.webSurfaces.mu.Lock()
		for _, live := range h.webSurfaces.byOrigin {
			if live.request.SurfaceInstanceID == id && live.methodReceiver != nil {
				live.methodReceiver.mu.Lock()
				queued = len(live.methodReceiver.queue) > 0
				live.methodReceiver.mu.Unlock()
			}
		}
		h.webSurfaces.mu.Unlock()
		if queued {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("method did not enter the delivery queue")
}

func TestSurfaceMethodsCancellationBeforeClaimIsNotCommitted(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, surfaceMethodsFixture(t))
	req := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "document_preclaim")
	ctx, cancel := context.WithCancel(surfaceMethodTestContext())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := h.InvokeIntent(ctx, InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, IntentID: "document.apply"})
		result <- err
	}()
	waitForSurfaceMethodQueue(t, h, req.SurfaceInstanceID)
	cancel()
	select {
	case err := <-result:
		if mutation.ForError(err) != mutation.OutcomeNotCommitted {
			t.Fatalf("cancel before claim: %s %v", mutation.ForError(err), err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not settle unclaimed invocation")
	}
	req.Operation = "claim"
	claim, err := h.SurfaceMethods(surfaceMethodTestContext(), req)
	if err != nil || claim.Invocation != nil {
		t.Fatalf("cancelled invocation delivered: %+v %v", claim, err)
	}
}

func TestSurfaceMethodsOneShotConfirmationAndResponseContract(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, surfaceMethodsFixture(t))
	req := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "document_approval")
	call := InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, IntentID: "document.confirm"}
	approval, err := h.PrepareIntentConfirmation(surfaceMethodTestContext(), call)
	if err != nil {
		t.Fatal(err)
	}
	call.ConfirmationID = approval.ConfirmationID
	result := make(chan error, 1)
	go func() { _, err := h.InvokeIntent(surfaceMethodTestContext(), call); result <- err }()
	req.Operation = "claim"
	claimed, err := h.SurfaceMethods(surfaceMethodTestContext(), req)
	if err != nil || claimed.Invocation == nil {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	req.Operation = "complete"
	req.InvocationID = claimed.Invocation.InvocationID
	req.Data = map[string]any{}
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), req); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if _, err = h.InvokeIntent(surfaceMethodTestContext(), call); !errors.Is(err, ErrConfirmationInvalid) {
		t.Fatalf("replayed approval: %v", err)
	}
	call.IntentID = "document.apply"
	call.ConfirmationID = ""
	go func() { _, err := h.InvokeIntent(surfaceMethodTestContext(), call); result <- err }()
	req.Operation = "claim"
	req.InvocationID = ""
	req.Data = nil
	claimed, err = h.SurfaceMethods(surfaceMethodTestContext(), req)
	if err != nil || claimed.Invocation == nil {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	req.Operation = "complete"
	req.InvocationID = claimed.Invocation.InvocationID
	req.Data = map[string]any{"unexpected": true}
	if _, err = h.SurfaceMethods(surfaceMethodTestContext(), req); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, ErrMethodResponseContract) || mutation.ForError(err) != mutation.OutcomeUnknown {
		t.Fatalf("invalid response after write: %s %v", mutation.ForError(err), err)
	}
}

func TestSurfaceMethodsRejectWrongOwnerAndUndeclaredMethod(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, surfaceMethodsFixture(t))
	req := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "document_owner")
	req.Operation = "configure"
	req.Methods = []string{"undeclared"}
	if _, err := h.SurfaceMethods(surfaceMethodTestContext(), req); !errors.Is(err, ErrMethodRequestContract) {
		t.Fatalf("undeclared registration: %v", err)
	}
	req.Operation = "close"
	req.Methods = nil
	wrong := sessionctx.WithContext(context.Background(), sessionctx.Context{OwnerSessionHash: "other", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash", CanRead: true, CanWrite: true})
	if _, err := h.SurfaceMethods(wrong, req); err == nil {
		t.Fatal("wrong owner closed receiver")
	}
	readonly := sessionctx.WithContext(context.Background(), sessionctx.Context{OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash", CanRead: true})
	if _, err := h.InvokeIntent(readonly, InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, IntentID: "document.apply"}); !errors.Is(err, ErrActionDenied) {
		t.Fatalf("read-only write: %v", err)
	}
	if _, err := h.SurfaceMethods(surfaceMethodTestContext(), req); err != nil {
		t.Fatal(err)
	}
}

func TestSurfaceMethodsClosedOperationRequestShapes(t *testing.T) {
	base := map[string]any{"plugin_instance_id": "plugin", "surface_instance_id": "surface", "bridge_channel_id": "bridge", "plugin_gateway_token": "token", "receiver_id": "receiver"}
	for _, operation := range []string{"register", "configure", "claim", "complete", "close"} {
		t.Run(operation, func(t *testing.T) {
			value := map[string]any{}
			for key, data := range base {
				value[key] = data
			}
			value["operation"] = operation
			if operation == "complete" {
				value["invocation_id"] = "invoke"
				value["data"] = nil
			}
			raw, _ := json.Marshal(value)
			var req SurfaceMethodsRequest
			if err := json.Unmarshal(raw, &req); err != nil {
				t.Fatal(err)
			}
			extras := map[string]any{"unknown": true}
			if operation != "complete" {
				extras["failed"] = false
				extras["data"] = nil
				extras["invocation_id"] = ""
			}
			if operation != "register" && operation != "configure" {
				extras["methods"] = []string{}
			}
			if operation != "claim" {
				extras["active_invocations"] = []string{}
			}
			for key, data := range extras {
				value[key] = data
				raw, _ = json.Marshal(value)
				if err := json.Unmarshal(raw, &req); err == nil {
					t.Fatalf("accepted foreign field %s", key)
				}
				delete(value, key)
			}
		})
	}
}

func TestSurfaceMethodsOperationCancellationUsesExecutionLifecycle(t *testing.T) {
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, surfaceMethodsFixture(t))
	req := openSurfaceMethodReceiver(t, h, installed.PluginInstanceID, "document_operation")
	result := make(chan error, 1)
	go func() {
		_, err := h.InvokeIntent(surfaceMethodTestContext(), InvokeIntentRequest{PluginInstanceID: installed.PluginInstanceID, SurfaceInstanceID: req.SurfaceInstanceID, IntentID: "document.operation"})
		result <- err
	}()
	req.Operation = "claim"
	claim, err := h.SurfaceMethods(surfaceMethodTestContext(), req)
	if err != nil || claim.Invocation == nil {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	executions, _, err := h.ListExecutions(surfaceMethodTestContext(), installed.PluginInstanceID, 0, 10)
	if err != nil || len(executions) != 1 {
		t.Fatalf("execution: %+v %v", executions, err)
	}
	if _, err := h.CancelExecution(surfaceMethodTestContext(), executions[0].ID, "user_cancel"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if mutation.ForError(err) != mutation.OutcomeUnknown {
			t.Fatalf("claimed cancellation: %s %v", mutation.ForError(err), err)
		}
	case <-time.After(time.Second):
		t.Fatal("execution cancellation did not stop dispatch")
	}
	terminal, err := h.GetExecution(surfaceMethodTestContext(), executions[0].ID)
	if err != nil || terminal.Status != execution.StatusCanceled {
		t.Fatalf("terminal: %+v %v", terminal, err)
	}
	req.ActiveInvocations = []string{claim.Invocation.InvocationID}
	canceled, err := h.SurfaceMethods(surfaceMethodTestContext(), req)
	if err != nil || len(canceled.Cancelled) != 1 || canceled.Cancelled[0] != claim.Invocation.InvocationID {
		t.Fatalf("client cancellation: %+v %v", canceled, err)
	}
}
