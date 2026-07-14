package operation

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	_ "modernc.org/sqlite"
)

func TestStoreRegisterListAndGet(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

			registered, err := store.Register(ctx, RegisterRequest{
				OperationID: "op_1",
				ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", func(binding *capability.ExecutionBinding) {
					binding.Effect = capability.EffectExecute
					binding.SurfaceInstanceID = "surface_1"
					binding.SessionChannelIDHash = "session_hash"
					binding.BridgeChannelID = "bridge_1"
				}),
				Now: now,
			})
			if err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			if registered.Status != StatusRunning || registered.DisableBehavior != DisableBehaviorCancel || registered.UninstallBehavior != UninstallBehaviorCancelThenBlockDelete {
				t.Fatalf("registered operation mismatch: %#v", registered)
			}

			if _, err := store.Register(ctx, RegisterRequest{
				OperationID:      "op_1",
				ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.other", nil),
			}); !errors.Is(err, ErrAlreadyExists) {
				t.Fatalf("duplicate Register() error = %v, want ErrAlreadyExists", err)
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

			if _, err := store.Register(ctx, RegisterRequest{ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.invalid", nil)}); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("Register() invalid error = %v, want ErrInvalidOperation", err)
			}
		})
	}
}

func TestStoreDeepClonesExecutionBindings(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			binding := operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", nil)
			registered := mustRegisterOperation(t, store, RegisterRequest{OperationID: "op_clone", ExecutionBinding: binding})
			binding.Target.Fields["document_id"] = "mutated-input"
			registered.Target.Fields["document_id"] = "mutated-return"
			stored, err := store.Get(context.Background(), "op_clone")
			if err != nil {
				t.Fatal(err)
			}
			if got := stored.Target.Fields["document_id"]; got != "doc-1" {
				t.Fatalf("stored target was mutated through a boundary: %#v", got)
			}
			stored.Target.Fields["document_id"] = "mutated-get"
			again, err := store.Get(context.Background(), "op_clone")
			if err != nil {
				t.Fatal(err)
			}
			if got := again.Target.Fields["document_id"]; got != "doc-1" {
				t.Fatalf("Get() returned shared target state: %#v", got)
			}
			finished, err := store.Finish(context.Background(), FinishRequest{OperationID: "op_clone", Status: StatusCompleted})
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := store.Finish(context.Background(), FinishRequest{OperationID: "op_clone", Status: StatusCompleted})
			if err != nil {
				t.Fatal(err)
			}
			finished.Target.Fields["document_id"] = "mutated-finish"
			terminal.Target.Fields["document_id"] = "mutated-terminal-return"
			afterFinish, err := store.Get(context.Background(), "op_clone")
			if err != nil {
				t.Fatal(err)
			}
			if got := afterFinish.Target.Fields["document_id"]; got != "doc-1" {
				t.Fatalf("Finish() returned shared target state: %#v", got)
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
				ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", nil),
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

func TestStoreRejectsNonCancelableRequest(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			cancelable := false
			mustRegisterOperation(t, store, RegisterRequest{
				OperationID:      "op_not_cancelable",
				ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", nil),
				Cancelable:       &cancelable,
			})
			if _, err := store.RequestCancel(ctx, CancelRequest{OperationID: "op_not_cancelable"}); !errors.Is(err, ErrNotCancelable) {
				t.Fatalf("RequestCancel() error = %v, want ErrNotCancelable", err)
			}
			assertOperationStatus(t, store, "op_not_cancelable", StatusRunning)
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
				ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", nil),
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
			cancelOp := mustRegisterOperation(t, store, operationTestRegister("op_cancel", "plugin_1", "documents.cancel"))
			orphanReq := operationTestRegister("op_orphan", "plugin_1", "documents.orphan")
			orphanReq.DisableBehavior = DisableBehaviorOrphan
			orphanOp := mustRegisterOperation(t, store, orphanReq)
			waitReq := operationTestRegister("op_wait", "plugin_1", "documents.wait")
			waitReq.DisableBehavior = DisableBehaviorWait
			waitOp := mustRegisterOperation(t, store, waitReq)
			otherOp := mustRegisterOperation(t, store, operationTestRegister("op_other", "plugin_2", "documents.other"))
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
			cancelOp := mustRegisterOperation(t, store, operationTestRegister("op_cancel", "plugin_1", "documents.cancel"))
			forceOp := mustRegisterOperation(t, store, RegisterRequest{
				OperationID:       "op_force",
				ExecutionBinding:  operationTestBinding("com.example.plugin", "plugin_1", "documents.force", nil),
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
			completed := mustRegisterOperation(t, store, operationTestRegister("op_completed", "plugin_1", "documents.complete"))
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
		OperationID: "op_persist",
		ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", func(binding *capability.ExecutionBinding) {
			binding.Effect = capability.EffectExecute
			binding.SurfaceInstanceID = "surface_1"
			binding.SessionChannelIDHash = "session_hash"
			binding.BridgeChannelID = "bridge_1"
		}),
		Now: now,
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

func TestSQLiteStoreMigratesV1DataAndIndexesIdempotently(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "operations-v1.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE plugin_operation_schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`,
		`INSERT INTO plugin_operation_schema_migrations(version, applied_at) VALUES(1, 1)`,
		`CREATE TABLE plugin_operations (
			operation_id TEXT PRIMARY KEY, plugin_id TEXT NOT NULL, plugin_instance_id TEXT NOT NULL,
			method TEXT NOT NULL, effect TEXT NOT NULL, execution TEXT NOT NULL, surface_instance_id TEXT NOT NULL,
			session_channel_id_hash TEXT NOT NULL, bridge_channel_id TEXT NOT NULL, status TEXT NOT NULL,
			disable_behavior TEXT NOT NULL, uninstall_behavior TEXT NOT NULL, reason TEXT NOT NULL,
			created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, cancel_requested_at INTEGER, orphaned_at INTEGER
		)`,
		`INSERT INTO plugin_operations VALUES(
			'op_v1', 'com.example.v1', 'plugini_v1', 'documents.archive', 'execute', 'operation', 'surface_v1',
			'channel_v1', 'bridge_v1', 'running', 'cancel', 'cancel_then_block_delete', '', 100, 200, NULL, NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		store, err := NewSQLiteStore(ctx, path)
		if err != nil {
			t.Fatalf("NewSQLiteStore() migration attempt %d error = %v", attempt+1, err)
		}
		record, err := store.Get(ctx, "op_v1")
		if err != nil {
			t.Fatal(err)
		}
		if record.PluginInstanceID != "plugini_v1" || record.Method != "documents.archive" || !record.Cancelable || record.CancelAckTimeoutMS != 0 {
			t.Fatalf("migrated operation mismatch: %#v", record)
		}
		for _, indexName := range []string{"idx_plugin_operations_plugin_instance", "idx_plugin_operations_status"} {
			var count int
			if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'plugin_operations' AND name = ?`, indexName).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("index %s count = %d, want 1", indexName, count)
			}
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
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

func operationTestRegister(operationID, pluginInstanceID, method string) RegisterRequest {
	return RegisterRequest{
		OperationID:      operationID,
		ExecutionBinding: operationTestBinding("com.example.plugin", pluginInstanceID, method, nil),
	}
}

func operationTestBinding(pluginID, pluginInstanceID, method string, mutate func(*capability.ExecutionBinding)) capability.ExecutionBinding {
	binding := capability.ExecutionBinding{
		InvocationID:           "invoke_test",
		AuditCorrelationID:     "audit_test",
		PublisherID:            "example.publisher",
		PluginID:               pluginID,
		PluginInstanceID:       pluginInstanceID,
		PluginVersion:          "1.0.0",
		ActiveFingerprint:      "sha256:test",
		CapabilityID:           "example.capability.documents",
		CapabilityVersion:      "1.0.0",
		BindingID:              "documents",
		Method:                 method,
		TargetMethod:           method,
		Effect:                 capability.EffectWrite,
		Execution:              "operation",
		Target:                 capability.TargetDescriptor{Kind: "document", Fields: map[string]any{"document_id": "doc-1"}},
		TargetDescriptorSHA256: "sha256:target",
	}
	if mutate != nil {
		mutate(&binding)
	}
	return binding
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
