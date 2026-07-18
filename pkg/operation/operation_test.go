package operation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/sessionctx"
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
					binding.SessionChannelIDHash = "channel_hash"
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

			page, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1", Owner: operationTestOwnerScope()})
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if len(page.Records) != 1 || page.Records[0].OperationID != "op_1" {
				t.Fatalf("List() mismatch: %#v", page)
			}

			if _, err := store.Register(ctx, RegisterRequest{ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.invalid", nil)}); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("Register() invalid error = %v, want ErrInvalidOperation", err)
			}
		})
	}
}

func TestStoreRegisterRequiresExactOwnerScope(t *testing.T) {
	ownerFields := []struct {
		name  string
		clear func(*capability.ExecutionBinding)
	}{
		{name: "session", clear: func(binding *capability.ExecutionBinding) { binding.OwnerSessionHash = "" }},
		{name: "user", clear: func(binding *capability.ExecutionBinding) { binding.OwnerUserHash = "" }},
		{name: "environment", clear: func(binding *capability.ExecutionBinding) { binding.OwnerEnvHash = "" }},
		{name: "channel", clear: func(binding *capability.ExecutionBinding) { binding.SessionChannelIDHash = "" }},
	}
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, field := range ownerFields {
				t.Run(field.name, func(t *testing.T) {
					store := tc.open(t)
					_, err := store.Register(context.Background(), RegisterRequest{
						OperationID: "op_missing_" + field.name,
						ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", func(binding *capability.ExecutionBinding) {
							field.clear(binding)
						}),
					})
					if !errors.Is(err, ErrInvalidOperation) {
						t.Fatalf("Register() error = %v, want ErrInvalidOperation", err)
					}
				})
			}
		})
	}
}

func TestStoresRequireClosedFailureCodes(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			for _, operationID := range []string{"op_reason", "op_unknown", "op_completed", "op_valid"} {
				mustRegisterOperation(t, store, RegisterRequest{
					OperationID:      operationID,
					ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_failure", "documents.archive", nil),
				})
			}

			if _, err := store.Finish(ctx, FinishRequest{OperationID: "op_reason", Status: StatusFailed, Reason: "private adapter detail"}); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("failed reason error = %v, want ErrInvalidOperation", err)
			}
			if _, err := store.Finish(ctx, FinishRequest{OperationID: "op_unknown", Status: StatusFailed, FailureCode: "internal"}); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("unknown failure code error = %v, want ErrInvalidOperation", err)
			}
			if _, err := store.Finish(ctx, FinishRequest{OperationID: "op_completed", Status: StatusCompleted, FailureCode: capability.ExecutionFailurePlatformFailed}); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("non-failed failure code error = %v, want ErrInvalidOperation", err)
			}
			failed, err := store.Finish(ctx, FinishRequest{OperationID: "op_valid", Status: StatusFailed, FailureCode: capability.ExecutionFailureAdapterFailed})
			if err != nil {
				t.Fatal(err)
			}
			if failed.FailureCode != capability.ExecutionFailureAdapterFailed || failed.Reason != capability.ExecutionFailureMessage {
				t.Fatalf("closed failure = %#v", failed)
			}
		})
	}
}

func TestStoreListsOperationsWithOpaqueCursorPagination(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
			for index, operationID := range []string{"op_1", "op_2", "op_3"} {
				mustRegisterOperation(t, store, RegisterRequest{
					OperationID:      operationID,
					ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", nil),
					Now:              now.Add(time.Duration(min(index, 1)) * time.Second),
				})
			}

			first, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1", Owner: operationTestOwnerScope(), Limit: 2})
			if err != nil {
				t.Fatal(err)
			}
			if len(first.Records) != 2 || first.Records[0].OperationID != "op_3" || first.Records[1].OperationID != "op_2" || first.NextCursor == nil {
				t.Fatalf("first page mismatch: %#v", first)
			}
			encoded, err := EncodeCursor(first.NextCursor)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeCursor(encoded)
			if err != nil {
				t.Fatal(err)
			}
			second, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1", Owner: operationTestOwnerScope(), Cursor: decoded, Limit: 2})
			if err != nil {
				t.Fatal(err)
			}
			if len(second.Records) != 1 || second.Records[0].OperationID != "op_1" || second.NextCursor != nil {
				t.Fatalf("second page mismatch: %#v", second)
			}
			if _, err := store.List(ctx, ListRequest{AllOwners: true, Limit: MaxListLimit + 1}); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("oversized page error = %v, want ErrInvalidOperation", err)
			}
			if _, err := DecodeCursor("not-a-cursor"); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("invalid cursor error = %v, want ErrInvalidOperation", err)
			}
		})
	}
}

func TestStoreListRequiresExactOwnerScope(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			ownerA := operationTestOwnerScope()
			ownerB := OwnerScope{OwnerSessionHash: "session_other", OwnerUserHash: "user_other", OwnerEnvHash: "env_other", SessionChannelIDHash: "channel_other"}
			for _, fixture := range []struct {
				operationID string
				owner       OwnerScope
			}{
				{operationID: "op_owner_a", owner: ownerA},
				{operationID: "op_owner_b", owner: ownerB},
			} {
				mustRegisterOperation(t, store, RegisterRequest{
					OperationID: fixture.operationID,
					ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_1", "documents.archive", func(binding *capability.ExecutionBinding) {
						binding.OwnerSessionHash = fixture.owner.OwnerSessionHash
						binding.OwnerUserHash = fixture.owner.OwnerUserHash
						binding.OwnerEnvHash = fixture.owner.OwnerEnvHash
						binding.SessionChannelIDHash = fixture.owner.SessionChannelIDHash
					}),
				})
			}

			page, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1", Owner: ownerA})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Records) != 1 || page.Records[0].OperationID != "op_owner_a" {
				t.Fatalf("owner-scoped operations = %#v", page.Records)
			}
			if _, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1"}); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("unscoped List() error = %v, want ErrInvalidOperation", err)
			}
			all, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_1", AllOwners: true})
			if err != nil || len(all.Records) != 2 {
				t.Fatalf("internal all-owner List() = %#v, %v", all, err)
			}
		})
	}
}

func TestStoresPruneOnlyExpiredTerminalOperations(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
			old := now.Add(-DefaultTerminalRetention - time.Hour)
			for _, operationID := range []string{"old-terminal-a", "old-terminal-b", "recent-terminal", "old-running", "old-cancel-requested"} {
				registeredAt := old
				if operationID == "recent-terminal" {
					registeredAt = now.Add(-time.Hour)
				}
				mustRegisterOperation(t, store, RegisterRequest{
					OperationID:      operationID,
					ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_prune", "documents.archive", nil),
					Now:              registeredAt,
				})
			}
			for index, operationID := range []string{"old-terminal-a", "old-terminal-b", "recent-terminal"} {
				finishedAt := old.Add(time.Duration(index) * time.Minute)
				if operationID == "recent-terminal" {
					finishedAt = now.Add(-time.Hour)
				}
				if _, err := store.Finish(ctx, FinishRequest{OperationID: operationID, Status: StatusCompleted, Now: finishedAt}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.RequestCancel(ctx, CancelRequest{OperationID: "old-cancel-requested", Now: old}); err != nil {
				t.Fatal(err)
			}

			first, err := store.Prune(ctx, PruneRequest{Before: now.Add(-DefaultTerminalRetention), Limit: 1})
			if err != nil || first.Deleted != 1 {
				t.Fatalf("Prune(first) = %#v, %v", first, err)
			}
			if _, err := store.Get(ctx, "old-terminal-a"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("oldest terminal Get() error = %v, want ErrNotFound", err)
			}
			for _, operationID := range []string{"old-terminal-b", "recent-terminal", "old-running", "old-cancel-requested"} {
				if _, err := store.Get(ctx, operationID); err != nil {
					t.Fatalf("Get(%s) after first prune error = %v", operationID, err)
				}
			}

			second, err := store.Prune(ctx, PruneRequest{Before: now.Add(-DefaultTerminalRetention)})
			if err != nil || second.Deleted != 1 {
				t.Fatalf("Prune(second) = %#v, %v", second, err)
			}
			page, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_prune", Owner: operationTestOwnerScope()})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Records) != 3 {
				t.Fatalf("retained operations = %#v", page.Records)
			}
		})
	}
}

func TestStoresBoundRecentTerminalOperationsPerPlugin(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
			for index := 0; index < 5; index++ {
				operationID := fmt.Sprintf("op_cap_a_%d", index)
				mustRegisterOperation(t, store, operationTestRegister(operationID, "plugin_cap_a", "documents.archive"))
				record, err := store.Finish(ctx, FinishRequest{OperationID: operationID, Status: StatusCompleted, Now: now})
				if err != nil || record.TerminalAt == nil || !record.TerminalAt.Equal(now) {
					t.Fatalf("Finish(%s) terminal_at = %v, %v", operationID, record.TerminalAt, err)
				}
			}
			for index := 0; index < 2; index++ {
				operationID := fmt.Sprintf("op_cap_b_%d", index)
				mustRegisterOperation(t, store, operationTestRegister(operationID, "plugin_cap_b", "documents.archive"))
				if _, err := store.Finish(ctx, FinishRequest{OperationID: operationID, Status: StatusCompleted, Now: now}); err != nil {
					t.Fatal(err)
				}
			}

			result, err := store.Prune(ctx, PruneRequest{
				Before:                      now.Add(-DefaultTerminalRetention),
				Limit:                       MaxPruneLimit,
				MaxTerminalRecordsPerPlugin: 2,
			})
			if err != nil || result.Deleted != 3 {
				t.Fatalf("Prune(cap) = %#v, %v", result, err)
			}
			for index := 0; index < 3; index++ {
				if _, err := store.Get(ctx, fmt.Sprintf("op_cap_a_%d", index)); !errors.Is(err, ErrNotFound) {
					t.Fatalf("capped operation %d error = %v, want ErrNotFound", index, err)
				}
			}
			for _, operationID := range []string{"op_cap_a_3", "op_cap_a_4", "op_cap_b_0", "op_cap_b_1"} {
				if _, err := store.Get(ctx, operationID); err != nil {
					t.Fatalf("retained operation %s error = %v", operationID, err)
				}
			}
		})
	}
}

func TestStoresPartitionTerminalOperationRetentionByEnvironment(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			now := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
			for _, environment := range []string{"env_hash", "env_b"} {
				for index := 0; index < 2; index++ {
					operationID := fmt.Sprintf("op_%s_%d", environment, index)
					request := operationTestRegister(operationID, "plugin_shared_retention", "documents.archive")
					request.ExecutionBinding.OwnerEnvHash = environment
					request.ExecutionBinding.OwnerSessionHash = "session_" + environment
					request.ExecutionBinding.OwnerUserHash = "user_" + environment
					request.ExecutionBinding.SessionChannelIDHash = "channel_" + environment
					mustRegisterOperation(t, store, request)
					if _, err := store.Finish(ctx, FinishRequest{OperationID: operationID, Status: StatusCompleted, Now: now.Add(time.Duration(index) * time.Second)}); err != nil {
						t.Fatal(err)
					}
				}
			}

			result, err := store.Prune(ctx, PruneRequest{
				Before:                      time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
				Limit:                       MaxPruneLimit,
				MaxTerminalRecordsPerPlugin: 1,
			})
			if err != nil || result.Deleted != 2 {
				t.Fatalf("Prune(environment partitions) = %#v, %v", result, err)
			}
			page, err := store.List(ctx, ListRequest{PluginInstanceID: "plugin_shared_retention", AllOwners: true, Limit: MaxListLimit})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Records) != 2 {
				t.Fatalf("retained operations = %#v", page.Records)
			}
		})
	}
}

func TestSQLiteStoreListQueriesUseCursorIndexes(t *testing.T) {
	store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "operations.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	for _, tc := range []struct {
		name      string
		query     string
		args      []any
		wantIndex string
	}{
		{
			name:      "global",
			query:     `EXPLAIN QUERY PLAN SELECT operation_id FROM plugin_operations ORDER BY created_at DESC, operation_id DESC LIMIT ?`,
			args:      []any{DefaultListLimit + 1},
			wantIndex: "idx_plugin_operations_created",
		},
		{
			name:      "plugin",
			query:     `EXPLAIN QUERY PLAN SELECT operation_id FROM plugin_operations WHERE plugin_instance_id = ? ORDER BY created_at DESC, operation_id DESC LIMIT ?`,
			args:      []any{"plugin_1", DefaultListLimit + 1},
			wantIndex: "idx_plugin_operations_plugin_instance",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := store.db.QueryContext(context.Background(), tc.query, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan strings.Builder
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plan.WriteString(detail)
				plan.WriteByte('\n')
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan.String(), tc.wantIndex) || strings.Contains(plan.String(), "USE TEMP B-TREE") {
				t.Fatalf("query plan does not use %s without temp sorting:\n%s", tc.wantIndex, plan.String())
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
				FailureCode: capability.ExecutionFailureAdapterFailed,
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
				ResourceScope:    operationTestEnvironmentScope(),
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
				ResourceScope:    operationTestEnvironmentScope(),
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

			changed, err := store.MarkPluginDisabled(ctx, PluginTransitionRequest{PluginInstanceID: "plugin_1", ResourceScope: operationTestEnvironmentScope()})
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

func TestStoreTransitionsOnlyMatchingEnvironmentOwner(t *testing.T) {
	for _, tc := range operationStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := tc.open(t)
			environmentA := mustRegisterOperation(t, store, operationTestRegister("op_env_a", "plugin_shared", "documents.run"))
			environmentBRequest := operationTestRegister("op_env_b", "plugin_shared", "documents.run")
			environmentBRequest.ExecutionBinding.OwnerSessionHash = "session_b"
			environmentBRequest.ExecutionBinding.OwnerUserHash = "user_b"
			environmentBRequest.ExecutionBinding.OwnerEnvHash = "env_b"
			environmentBRequest.ExecutionBinding.SessionChannelIDHash = "channel_b"
			environmentB := mustRegisterOperation(t, store, environmentBRequest)

			changed, err := store.MarkPluginDisabled(ctx, PluginTransitionRequest{
				PluginInstanceID: "plugin_shared",
				ResourceScope:    operationTestEnvironmentScope(),
				Reason:           "disabled",
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(changed) != 1 || changed[0].OperationID != environmentA.OperationID {
				t.Fatalf("environment A transition = %#v", changed)
			}
			assertOperationStatus(t, store, environmentA.OperationID, StatusCancelRequested)
			assertOperationStatus(t, store, environmentB.OperationID, StatusRunning)

			changed, err = store.MarkPluginUninstalled(ctx, PluginTransitionRequest{
				PluginInstanceID: "plugin_shared",
				ResourceScope:    operationTestEnvironmentScopeFor("env_b"),
				Reason:           "uninstalled",
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(changed) != 1 || changed[0].OperationID != environmentB.OperationID {
				t.Fatalf("environment B transition = %#v", changed)
			}
			assertOperationStatus(t, store, environmentB.OperationID, StatusCancelRequested)
			if _, err := store.MarkPluginDisabled(ctx, PluginTransitionRequest{PluginInstanceID: "plugin_shared"}); !errors.Is(err, ErrInvalidOperation) {
				t.Fatalf("missing owner scope error = %v, want ErrInvalidOperation", err)
			}
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
			binding.SessionChannelIDHash = "channel_hash"
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
		got.SessionChannelIDHash != "channel_hash" ||
		!got.CreatedAt.Equal(now) {
		t.Fatalf("persisted operation mismatch: %#v", got)
	}
}

func mustRegisterOperation(t testing.TB, store Store, req RegisterRequest) Record {
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
		OwnerSessionHash:       "session_hash",
		OwnerUserHash:          "user_hash",
		OwnerEnvHash:           "env_hash",
		SessionChannelIDHash:   "channel_hash",
	}
	if mutate != nil {
		mutate(&binding)
	}
	return binding
}

func operationTestOwnerScope() OwnerScope {
	return OwnerScope{OwnerSessionHash: "session_hash", OwnerUserHash: "user_hash", OwnerEnvHash: "env_hash", SessionChannelIDHash: "channel_hash"}
}

func operationTestEnvironmentScope() sessionctx.ResourceScope {
	return operationTestEnvironmentScopeFor("env_hash")
}

func operationTestEnvironmentScopeFor(ownerEnvHash string) sessionctx.ResourceScope {
	return sessionctx.ResourceScope{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: ownerEnvHash}
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

func TestSQLiteStoreOwnerScopedReadsProceedDuringWriteTransaction(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "operations.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mustRegisterOperation(t, store, RegisterRequest{
		OperationID:      "op_concurrent_read",
		ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_concurrent_read", "documents.read", nil),
	})

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			t.Errorf("Rollback() error = %v", rollbackErr)
		}
	}()
	if _, err := tx.ExecContext(ctx, `UPDATE plugin_operations SET reason = ? WHERE operation_id = ?`, "uncommitted", "op_concurrent_read"); err != nil {
		t.Fatal(err)
	}

	readCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		page, err := store.List(readCtx, ListRequest{
			PluginInstanceID: "plugin_concurrent_read",
			Owner:            operationTestOwnerScope(),
			Limit:            10,
		})
		if err == nil && (len(page.Records) != 1 || page.Records[0].OperationID != "op_concurrent_read" || page.Records[0].Reason != "") {
			err = fmt.Errorf("owner-scoped list observed invalid snapshot: %#v", page)
		}
		results <- err
	}()
	go func() {
		record, err := store.Get(readCtx, "op_concurrent_read")
		if err == nil && (record.OperationID != "op_concurrent_read" || record.Reason != "") {
			err = fmt.Errorf("get observed invalid snapshot: %#v", record)
		}
		results <- err
	}()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkSQLiteStoreOwnerScopedParallelReadWrite(b *testing.B) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(b.TempDir(), "operations.sqlite"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	const recordCount = 64
	for index := 0; index < recordCount; index++ {
		mustRegisterOperation(b, store, RegisterRequest{
			OperationID:      fmt.Sprintf("op_parallel_%03d", index),
			ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_parallel", "documents.read", nil),
		})
	}

	var sequence atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			index := sequence.Add(1)
			if index%8 == 0 {
				_, err := store.RequestCancel(ctx, CancelRequest{
					OperationID: fmt.Sprintf("op_parallel_%03d", index%recordCount),
					Reason:      "benchmark",
				})
				if err != nil {
					b.Error(err)
				}
				continue
			}
			page, err := store.List(ctx, ListRequest{
				PluginInstanceID: "plugin_parallel",
				Owner:            operationTestOwnerScope(),
				Limit:            20,
			})
			if err != nil || len(page.Records) != 20 {
				b.Errorf("List() records=%d err=%v", len(page.Records), err)
			}
		}
	})
}

func BenchmarkMemoryStoreGet(b *testing.B) {
	store := NewMemoryStore()
	if _, err := store.Register(context.Background(), RegisterRequest{
		OperationID:      "op_memory_get",
		ExecutionBinding: operationTestBinding("com.example.plugin", "plugin_memory_get", "documents.read", nil),
	}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record, err := store.Get(context.Background(), "op_memory_get")
		if err != nil || record.OperationID == "" {
			b.Fatalf("Get() record=%#v err=%v", record, err)
		}
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
