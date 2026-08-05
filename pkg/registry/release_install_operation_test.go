package registry

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

func TestReleaseInstallOperationReplayConflictAndOwnerIsolation(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			ctx := registryTestContextFor("owner_user_a", "owner_env_a")
			req := releaseInstallOperationRequest(time.Date(2026, 8, 5, 1, 2, 3, 0, time.UTC))
			created, isNew, err := store.StartReleaseInstallOperation(ctx, req)
			if err != nil || !isNew {
				t.Fatalf("StartReleaseInstallOperation() = %#v, %t, %v", created, isNew, err)
			}
			if created.Status != ReleaseInstallQueued || created.MutationOutcome != mutation.OutcomeNotCommitted || created.Revision != 1 {
				t.Fatalf("created operation = %#v", created)
			}
			replayed, isNew, err := store.StartReleaseInstallOperation(ctx, req)
			if err != nil || isNew || replayed.OperationID != created.OperationID || replayed.RequestSHA256 != created.RequestSHA256 {
				t.Fatalf("replayed operation = %#v, %t, %v", replayed, isNew, err)
			}

			mismatch := req
			mismatch.Release.Version = "4.1.1"
			if _, _, err := store.StartReleaseInstallOperation(ctx, mismatch); !errors.Is(err, ErrReleaseInstallOperationConflict) {
				t.Fatalf("request replay mismatch error = %v", err)
			}
			duplicatePlugin := req
			duplicatePlugin.RequestID = "request_install_containers_again"
			duplicatePlugin.OperationID = "operation_install_containers_again"
			active, isNew, err := store.StartReleaseInstallOperation(ctx, duplicatePlugin)
			if err != nil || isNew || active.OperationID != created.OperationID {
				t.Fatalf("duplicate active plugin operation = %#v, %t, %v", active, isNew, err)
			}
			otherOwner := registryTestContextFor("owner_user_b", "owner_env_b")
			if _, err := store.GetReleaseInstallOperation(otherOwner, created.OperationID); !errors.Is(err, ErrReleaseInstallOperationNotFound) {
				t.Fatalf("cross-owner query error = %v", err)
			}
		})
	}
}

func TestReleaseInstallOperationProgressAndTerminalCAS(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			ctx := registryTestContext()
			req := releaseInstallOperationRequest(time.Date(2026, 8, 5, 1, 2, 3, 0, time.UTC))
			created, _, err := store.StartReleaseInstallOperation(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			running, err := store.UpdateReleaseInstallOperation(ctx, UpdateReleaseInstallOperationRequest{
				OperationID: created.OperationID, ExpectedRevision: created.Revision,
				Status: ReleaseInstallRunning, Phase: "download_package",
				Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressBytes, Completed: 262144, Total: 524288},
				Attempt:  2, RetryAfterMS: 250, MutationOutcome: mutation.OutcomeNotCommitted, Now: req.Now.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			if running.Revision != 2 || running.Progress.Completed != 262144 || running.Attempt != 2 || running.RetryAfterMS != 250 {
				t.Fatalf("running operation = %#v", running)
			}
			if _, err := store.UpdateReleaseInstallOperation(ctx, UpdateReleaseInstallOperationRequest{
				OperationID: created.OperationID, ExpectedRevision: created.Revision,
				Status: ReleaseInstallFailed, Phase: "failed", Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate},
				Attempt: 2, MutationOutcome: mutation.OutcomeNotCommitted,
				Failure: &ReleaseInstallFailure{Code: "PLUGIN_INSTALL_INTERRUPTED", Retryable: true}, Now: req.Now.Add(2 * time.Second),
			}); !errors.Is(err, ErrReleaseInstallOperationConflict) {
				t.Fatalf("stale update error = %v", err)
			}
			failed, err := store.UpdateReleaseInstallOperation(ctx, UpdateReleaseInstallOperationRequest{
				OperationID: running.OperationID, ExpectedRevision: running.Revision,
				Status: ReleaseInstallFailed, Phase: "failed", Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate},
				Attempt: 2, MutationOutcome: mutation.OutcomeNotCommitted,
				Failure: &ReleaseInstallFailure{Code: "PLUGIN_INSTALL_INTERRUPTED", Retryable: true}, Now: req.Now.Add(2 * time.Second),
			})
			if err != nil || failed.TerminalAt == nil || failed.Failure == nil || !failed.Failure.Retryable {
				t.Fatalf("failed operation = %#v, %v", failed, err)
			}
			listed, err := store.ListReleaseInstallOperations(ctx)
			if err != nil || len(listed) != 1 || listed[0].Status != ReleaseInstallFailed {
				t.Fatalf("listed operations = %#v, %v", listed, err)
			}
		})
	}
}

func TestSQLiteRegistryMigratesV2AndReconcilesReleaseInstallOperation(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	req := releaseInstallOperationRequest(time.Date(2026, 8, 5, 1, 2, 3, 0, time.UTC))
	created, _, err := store.StartReleaseInstallOperation(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateReleaseInstallOperation(ctx, UpdateReleaseInstallOperationRequest{
		OperationID: created.OperationID, ExpectedRevision: created.Revision,
		Status: ReleaseInstallRunning, Phase: "download_package",
		Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressBytes, Completed: 1, Total: 2},
		Attempt:  1, MutationOutcome: mutation.OutcomeNotCommitted, Now: req.Now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reconciled, err := reopened.GetReleaseInstallOperation(ctx, created.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != ReleaseInstallReconciling || reconciled.Phase != "reconciling" || reconciled.MutationOutcome != mutation.OutcomeUnknown || reconciled.Revision != 3 {
		t.Fatalf("reconciled operation = %#v", reconciled)
	}

	if _, err := reopened.db.ExecContext(ctx, `DROP TABLE release_install_operations`); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.db.ExecContext(ctx, `PRAGMA user_version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	var version int
	if err := migrated.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != registrySQLiteSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, registrySQLiteSchemaVersion)
	}
	if _, err := migrated.GetReleaseInstallOperation(ctx, created.OperationID); !errors.Is(err, ErrReleaseInstallOperationNotFound) {
		t.Fatalf("v2 migration synthesized operation: %v", err)
	}
}

func releaseInstallOperationRequest(now time.Time) StartReleaseInstallOperationRequest {
	return StartReleaseInstallOperationRequest{
		RequestID: "request_install_example", OperationID: "operation_install_example", PluginInstanceID: "plugini_example",
		Release: ReleaseInstallIdentity{
			SourceID: "official", Channel: "stable", ReleaseMetadataRef: "example-1.2.3",
			ReleaseMetadataSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PublisherID:           "example", PluginID: "com.example.plugin", Version: "1.2.3",
			PackageSHA256:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			ManifestSHA256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			EntriesSHA256:  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		},
		Now: now,
	}
}
