package operation

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreRegisterListAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	registered, err := store.Register(ctx, RegisterRequest{
		OperationID:          "op_1",
		PluginID:             "com.example.plugin",
		PluginInstanceID:     "plugin_1",
		Method:               "images.pull",
		Effect:               "execute",
		Execution:            "operation",
		SurfaceInstanceID:    "surface_1",
		SessionChannelIDHash: "session_hash",
		BridgeChannelID:      "bridge_1",
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if registered.Status != StatusRunning || registered.DisableBehavior != DisableBehaviorCancel || registered.UninstallBehavior != UninstallBehaviorCancelThenBlockDelete {
		t.Fatalf("registered operation mismatch: %#v", registered)
	}

	duplicate, err := store.Register(ctx, RegisterRequest{
		OperationID:      "op_1",
		PluginInstanceID: "plugin_1",
		Method:           "images.other",
	})
	if err != nil {
		t.Fatalf("duplicate Register() error = %v", err)
	}
	if duplicate.Method != registered.Method {
		t.Fatalf("duplicate registration changed existing record: %#v", duplicate)
	}

	got, err := store.Get(ctx, "op_1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.OperationID != "op_1" || got.PluginInstanceID != "plugin_1" {
		t.Fatalf("Get() mismatch: %#v", got)
	}

	listed, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listed) != 1 || listed[0].OperationID != "op_1" {
		t.Fatalf("List() mismatch: %#v", listed)
	}

	if _, err := store.Register(ctx, RegisterRequest{OperationID: "", PluginInstanceID: "plugin_1", Method: "x"}); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("Register() invalid error = %v, want ErrInvalidOperation", err)
	}
}

func TestMemoryStoreRequestCancel(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	registered := mustRegisterOperation(t, store, RegisterRequest{
		OperationID:      "op_cancel",
		PluginInstanceID: "plugin_1",
		Method:           "images.pull",
	})
	now := registered.CreatedAt.Add(time.Minute)

	canceled, err := store.RequestCancel(ctx, CancelRequest{
		OperationID: "op_cancel",
		Reason:      "user requested",
		Now:         now,
	})
	if err != nil {
		t.Fatalf("RequestCancel() error = %v", err)
	}
	if canceled.Status != StatusCancelRequested || canceled.CancelRequestedAt == nil || !canceled.CancelRequestedAt.Equal(now) || canceled.Reason != "user requested" {
		t.Fatalf("cancel status mismatch: %#v", canceled)
	}
}

func TestMemoryStoreFinishOperation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	registered := mustRegisterOperation(t, store, RegisterRequest{
		OperationID:      "op_finish",
		PluginInstanceID: "plugin_1",
		Method:           "images.pull",
	})
	now := registered.CreatedAt.Add(time.Minute)

	finished, err := store.Finish(ctx, FinishRequest{
		OperationID: "op_finish",
		Status:      StatusCompleted,
		Reason:      "done",
		Now:         now,
	})
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if finished.Status != StatusCompleted || finished.Reason != "done" || !finished.UpdatedAt.Equal(now) {
		t.Fatalf("finish result mismatch: %#v", finished)
	}

	unchanged, err := store.Finish(ctx, FinishRequest{
		OperationID: "op_finish",
		Status:      StatusFailed,
		Reason:      "too late",
		Now:         now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Finish() terminal error = %v", err)
	}
	if unchanged.Status != StatusCompleted || unchanged.Reason != "done" {
		t.Fatalf("terminal finish changed record: %#v", unchanged)
	}

	if _, err := store.Finish(ctx, FinishRequest{OperationID: "op_finish", Status: StatusOrphanedAfterDisable}); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("Finish() invalid status error = %v, want ErrInvalidOperation", err)
	}
}

func TestMemoryStoreDisableTransitions(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	cancelOp := mustRegisterOperation(t, store, RegisterRequest{OperationID: "op_cancel", PluginInstanceID: "plugin_1", Method: "a"})
	orphanOp := mustRegisterOperation(t, store, RegisterRequest{OperationID: "op_orphan", PluginInstanceID: "plugin_1", Method: "b", DisableBehavior: DisableBehaviorOrphan})
	waitOp := mustRegisterOperation(t, store, RegisterRequest{OperationID: "op_wait", PluginInstanceID: "plugin_1", Method: "c", DisableBehavior: DisableBehaviorWait})
	otherOp := mustRegisterOperation(t, store, RegisterRequest{OperationID: "op_other", PluginInstanceID: "plugin_2", Method: "d"})
	now := cancelOp.CreatedAt.Add(time.Minute)

	changed, err := store.MarkPluginDisabled(ctx, PluginTransitionRequest{
		PluginInstanceID: "plugin_1",
		Reason:           "disabled",
		Now:              now,
	})
	if err != nil {
		t.Fatalf("MarkPluginDisabled() error = %v", err)
	}
	if len(changed) != 2 {
		t.Fatalf("changed count = %d, want 2: %#v", len(changed), changed)
	}
	assertOperationStatus(t, store, cancelOp.OperationID, StatusCancelRequested)
	assertOperationStatus(t, store, orphanOp.OperationID, StatusOrphanedAfterDisable)
	assertOperationStatus(t, store, waitOp.OperationID, StatusRunning)
	assertOperationStatus(t, store, otherOp.OperationID, StatusRunning)
}

func TestMemoryStoreUninstallTransitions(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	cancelOp := mustRegisterOperation(t, store, RegisterRequest{OperationID: "op_cancel", PluginInstanceID: "plugin_1", Method: "a"})
	forceOp := mustRegisterOperation(t, store, RegisterRequest{
		OperationID:       "op_force",
		PluginInstanceID:  "plugin_1",
		Method:            "b",
		UninstallBehavior: UninstallBehaviorForceCleanupAllowed,
	})
	now := cancelOp.CreatedAt.Add(time.Minute)

	changed, err := store.MarkPluginUninstalled(ctx, PluginTransitionRequest{
		PluginInstanceID: "plugin_1",
		Reason:           "uninstalled",
		Now:              now,
	})
	if err != nil {
		t.Fatalf("MarkPluginUninstalled() error = %v", err)
	}
	if len(changed) != 2 {
		t.Fatalf("changed count = %d, want 2: %#v", len(changed), changed)
	}
	assertOperationStatus(t, store, cancelOp.OperationID, StatusCancelRequested)
	assertOperationStatus(t, store, forceOp.OperationID, StatusOrphanedAfterUninstall)
}

func TestMemoryStoreTransitionSkipsTerminalStatuses(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	completed := mustRegisterOperation(t, store, RegisterRequest{OperationID: "op_completed", PluginInstanceID: "plugin_1", Method: "a"})

	store.mu.Lock()
	completed.Status = StatusCompleted
	store.records[completed.OperationID] = completed
	store.mu.Unlock()

	changed, err := store.MarkPluginDisabled(ctx, PluginTransitionRequest{PluginInstanceID: "plugin_1"})
	if err != nil {
		t.Fatalf("MarkPluginDisabled() error = %v", err)
	}
	if len(changed) != 0 {
		t.Fatalf("terminal operation changed: %#v", changed)
	}
	assertOperationStatus(t, store, completed.OperationID, StatusCompleted)
}

func mustRegisterOperation(t *testing.T, store *MemoryStore, req RegisterRequest) Record {
	t.Helper()
	record, err := store.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register(%s) error = %v", req.OperationID, err)
	}
	return record
}

func assertOperationStatus(t *testing.T, store *MemoryStore, operationID string, want Status) {
	t.Helper()
	record, err := store.Get(context.Background(), operationID)
	if err != nil {
		t.Fatalf("Get(%s) error = %v", operationID, err)
	}
	if record.Status != want {
		t.Fatalf("operation %s status = %s, want %s: %#v", operationID, record.Status, want, record)
	}
}
