package operation

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRegisterListAndGet(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
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
		})
	}
}

func TestStoreRequestCancel(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
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
		})
	}
}

func TestStoreFinishOperation(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
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
		})
	}
}

func TestStoreDisableTransitions(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
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
		})
	}
}

func TestStoreUninstallTransitions(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
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
		})
	}
}

func TestStoreTransitionSkipsTerminalStatuses(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			completed := mustRegisterOperation(t, store, RegisterRequest{OperationID: "op_completed", PluginInstanceID: "plugin_1", Method: "a"})
			if _, err := store.Finish(ctx, FinishRequest{OperationID: completed.OperationID, Status: StatusCompleted, Reason: "done"}); err != nil {
				t.Fatal(err)
			}

			changed, err := store.MarkPluginDisabled(ctx, PluginTransitionRequest{PluginInstanceID: "plugin_1"})
			if err != nil {
				t.Fatalf("MarkPluginDisabled() error = %v", err)
			}
			if len(changed) != 0 {
				t.Fatalf("terminal operation changed: %#v", changed)
			}
			assertOperationStatus(t, store, completed.OperationID, StatusCompleted)
		})
	}
}

func TestSQLiteStorePersistsRecordsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "operations.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	registered := mustRegisterOperation(t, store, RegisterRequest{
		OperationID:          "op_persist",
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
	canceled, err := store.RequestCancel(ctx, CancelRequest{OperationID: registered.OperationID, Reason: "pause", Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	got, err := reopened.Get(ctx, canceled.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusCancelRequested ||
		got.Reason != "pause" ||
		got.CancelRequestedAt == nil ||
		!got.CancelRequestedAt.Equal(now.Add(time.Minute)) ||
		got.SessionChannelIDHash != "session_hash" ||
		!got.CreatedAt.Equal(now) {
		t.Fatalf("persisted operation mismatch: %#v", got)
	}
}

func TestSQLiteStoreRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "operations.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT OR REPLACE INTO plugin_operation_schema_migrations(version, applied_at) VALUES(999, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(ctx, path); err == nil {
		t.Fatal("NewSQLiteStore() accepted newer schema version")
	}
}

func mustRegisterOperation(t *testing.T, store Store, req RegisterRequest) Record {
	t.Helper()
	record, err := store.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register(%s) error = %v", req.OperationID, err)
	}
	return record
}

func assertOperationStatus(t *testing.T, store Store, operationID string, want Status) {
	t.Helper()
	record, err := store.Get(context.Background(), operationID)
	if err != nil {
		t.Fatalf("Get(%s) error = %v", operationID, err)
	}
	if record.Status != want {
		t.Fatalf("operation %s status = %s, want %s: %#v", operationID, record.Status, want, record)
	}
}

type operationStoreCase struct {
	name string
	open func(t *testing.T) Store
}

func operationStoreCases() []operationStoreCase {
	return []operationStoreCase{
		{
			name: "memory",
			open: func(t *testing.T) Store {
				t.Helper()
				return NewMemoryStore()
			},
		},
		{
			name: "sqlite",
			open: func(t *testing.T) Store {
				t.Helper()
				store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "operations.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = store.Close()
				})
				return store
			},
		},
	}
}
