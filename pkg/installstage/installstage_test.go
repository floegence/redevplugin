package installstage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func installStageTestContext() context.Context {
	return installStageTestContextFor("owner_user_hash_test", "owner_env_hash_test")
}

func installStageTestContextFor(ownerUserHash, ownerEnvHash string) context.Context {
	return sessionctx.WithContext(context.Background(), sessionctx.Context{
		OwnerSessionHash:     "owner_session_hash_test",
		OwnerUserHash:        ownerUserHash,
		OwnerEnvHash:         ownerEnvHash,
		SessionChannelIDHash: "session_channel_id_hash_test",
	})
}

func TestStoreCreatePrepareCommitAndDelete(t *testing.T) {
	for _, tc := range storeCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := installStageTestContext()
			store := tc.open(t)
			now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
			created, err := store.Create(ctx, fixtureCreateRequest("stage_commit", now))
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if created.Status != StatusStaged || created.Action != ActionInstall || created.CreatedAt != now {
				t.Fatalf("created stage mismatch: %#v", created)
			}
			if !reflect.DeepEqual(created.ValidationSummary, map[string]string{"package_read": "ok"}) {
				t.Fatalf("validation summary mismatch: %#v", created.ValidationSummary)
			}

			preparedAt := now.Add(time.Minute)
			prepared, err := store.MarkPrepared(ctx, MarkPreparedRequest{
				StageID:       created.StageID,
				ResolvedTrust: "verified",
				ValidationSummary: map[string]string{
					"trust": "verified",
				},
				Now: preparedAt,
			})
			if err != nil {
				t.Fatalf("MarkPrepared() error = %v", err)
			}
			if prepared.Status != StatusPrepared || prepared.ResolvedTrust != "verified" || !prepared.UpdatedAt.Equal(preparedAt) {
				t.Fatalf("prepared stage mismatch: %#v", prepared)
			}
			if !reflect.DeepEqual(prepared.ValidationSummary, map[string]string{"package_read": "ok", "trust": "verified"}) {
				t.Fatalf("merged validation summary mismatch: %#v", prepared.ValidationSummary)
			}

			committedAt := now.Add(2 * time.Minute)
			committed, err := store.MarkCommitted(ctx, MarkCommittedRequest{StageID: created.StageID, Now: committedAt})
			if err != nil {
				t.Fatalf("MarkCommitted() error = %v", err)
			}
			if committed.Status != StatusCommitted || committed.FinishedAt == nil || !committed.FinishedAt.Equal(committedAt) {
				t.Fatalf("committed stage mismatch: %#v", committed)
			}

			again, err := store.MarkFailed(ctx, MarkFailedRequest{StageID: created.StageID, ErrorCode: "late_failure", Now: now.Add(3 * time.Minute)})
			if err != nil {
				t.Fatalf("MarkFailed(committed) error = %v", err)
			}
			if again.Status != StatusCommitted || again.ErrorCode != "" {
				t.Fatalf("terminal stage was modified: %#v", again)
			}

			listed, err := store.List(ctx, ListRequest{PluginInstanceID: created.PluginInstanceID})
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if len(listed) != 1 || listed[0].StageID != created.StageID {
				t.Fatalf("List() mismatch: %#v", listed)
			}
			committedOnly, err := store.List(ctx, ListRequest{Status: StatusCommitted})
			if err != nil {
				t.Fatalf("List(committed) error = %v", err)
			}
			if len(committedOnly) != 1 || committedOnly[0].Status != StatusCommitted {
				t.Fatalf("List(committed) mismatch: %#v", committedOnly)
			}
			if err := store.Delete(ctx, created.StageID); err != nil {
				t.Fatalf("Delete() error = %v", err)
			}
			if _, err := store.Get(ctx, created.StageID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get(after delete) error = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestStoreMarkFailedAndExpire(t *testing.T) {
	for _, tc := range storeCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := installStageTestContext()
			store := tc.open(t)
			now := time.Date(2026, 7, 2, 13, 0, 0, 0, time.UTC)
			failing, err := store.Create(ctx, fixtureCreateRequest("stage_fail", now))
			if err != nil {
				t.Fatal(err)
			}
			failedAt := now.Add(time.Minute)
			failed, err := store.MarkFailed(ctx, MarkFailedRequest{
				StageID:      failing.StageID,
				ErrorCode:    "trust_denied",
				ErrorMessage: "package trust verifier denied install",
				Now:          failedAt,
			})
			if err != nil {
				t.Fatalf("MarkFailed() error = %v", err)
			}
			if failed.Status != StatusFailed || failed.ErrorCode != "trust_denied" || failed.FinishedAt == nil || !failed.FinishedAt.Equal(failedAt) {
				t.Fatalf("failed stage mismatch: %#v", failed)
			}

			expiring, err := store.Create(ctx, fixtureCreateRequest("stage_expire", now))
			if err != nil {
				t.Fatal(err)
			}
			expired, err := store.ExpireBefore(ctx, now.Add(2*time.Hour))
			if err != nil {
				t.Fatalf("ExpireBefore() error = %v", err)
			}
			if len(expired) != 1 || expired[0].StageID != expiring.StageID || expired[0].Status != StatusExpired {
				t.Fatalf("ExpireBefore() mismatch: %#v", expired)
			}
			terminal, err := store.Get(ctx, failing.StageID)
			if err != nil {
				t.Fatal(err)
			}
			if terminal.Status != StatusFailed {
				t.Fatalf("ExpireBefore modified failed stage: %#v", terminal)
			}
		})
	}
}

func TestStoreRejectsInvalidRequests(t *testing.T) {
	for _, tc := range storeCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			if _, err := store.Create(installStageTestContext(), CreateRequest{}); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("Create() error = %v, want ErrInvalidStage", err)
			}
			now := time.Date(2026, 7, 2, 14, 0, 0, 0, time.UTC)
			req := fixtureCreateRequest("stage_invalid", now)
			req.ExpiresAt = now
			if _, err := store.Create(installStageTestContext(), req); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("Create(expired) error = %v, want ErrInvalidStage", err)
			}
			if _, err := store.Get(installStageTestContext(), " "); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("Get() error = %v, want ErrInvalidStage", err)
			}
			if _, err := store.MarkCommitted(installStageTestContext(), MarkCommittedRequest{}); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("MarkCommitted() error = %v, want ErrInvalidStage", err)
			}
			if _, err := store.List(installStageTestContext(), ListRequest{Status: "bad"}); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("List() error = %v, want ErrInvalidStage", err)
			}
			if err := store.Delete(installStageTestContext(), " "); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("Delete() error = %v, want ErrInvalidStage", err)
			}
			valid := fixtureCreateRequest("stage_no_session", now)
			if _, err := store.Create(context.Background(), valid); !errors.Is(err, sessionctx.ErrSessionRequired) {
				t.Fatalf("Create(no session) error = %v, want authenticated session", err)
			}
		})
	}
}

func TestNewStageID(t *testing.T) {
	first, err := NewStageID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewStageID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "stage_") || len(first) != len("stage_")+32 {
		t.Fatalf("unexpected stage ids: %q %q", first, second)
	}
}

func TestSQLiteStorePersistsAcrossOpen(t *testing.T) {
	ctx := installStageTestContext()
	path := filepath.Join(t.TempDir(), "install-stage.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 2, 15, 0, 0, 0, time.UTC)
	created, err := store.Create(ctx, fixtureCreateRequest("stage_persist", now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkPrepared(ctx, MarkPreparedRequest{
		StageID:       created.StageID,
		ResolvedTrust: "verified",
		Now:           now.Add(time.Minute),
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
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	record, err := reopened.Get(ctx, created.StageID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != StatusPrepared || record.ResolvedTrust != "verified" || !record.CreatedAt.Equal(now) {
		t.Fatalf("persisted stage mismatch: %#v", record)
	}
}

func TestStoreIsolatesEnvironmentOwners(t *testing.T) {
	for _, tc := range storeCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
			environmentA := installStageTestContextFor("owner_user_a", "owner_env_a")
			environmentB := installStageTestContextFor("owner_user_b", "owner_env_b")
			requestA := fixtureCreateRequest("stage_shared", now)
			requestB := requestA
			requestB.Version = "2.0.0"
			createdA, err := store.Create(environmentA, requestA)
			if err != nil {
				t.Fatal(err)
			}
			createdB, err := store.Create(environmentB, requestB)
			if err != nil {
				t.Fatal(err)
			}
			if createdA.OwnerEnvHash != "owner_env_a" || createdB.OwnerEnvHash != "owner_env_b" {
				t.Fatalf("owners = %q, %q", createdA.OwnerEnvHash, createdB.OwnerEnvHash)
			}
			for _, item := range []struct {
				ctx     context.Context
				version string
			}{{environmentA, "1.2.3"}, {environmentB, "2.0.0"}} {
				record, err := store.Get(item.ctx, "stage_shared")
				if err != nil {
					t.Fatal(err)
				}
				if record.Version != item.version {
					t.Fatalf("Get() version = %q, want %q", record.Version, item.version)
				}
				listed, err := store.List(item.ctx, ListRequest{})
				if err != nil {
					t.Fatal(err)
				}
				if len(listed) != 1 || listed[0].Version != item.version {
					t.Fatalf("List() = %#v", listed)
				}
			}
			expired, err := store.ExpireBefore(environmentA, now.Add(2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if len(expired) != 1 || expired[0].OwnerEnvHash != "owner_env_a" {
				t.Fatalf("ExpireBefore() = %#v", expired)
			}
			recordB, err := store.Get(environmentB, "stage_shared")
			if err != nil {
				t.Fatal(err)
			}
			if recordB.Status != StatusStaged {
				t.Fatalf("other environment status = %q", recordB.Status)
			}
		})
	}
}

func TestSQLiteStoreFailsClosedForOwnerlessRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE plugin_install_stages (stage_id TEXT PRIMARY KEY, action TEXT NOT NULL, status TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, publisher_id TEXT NOT NULL, plugin_id TEXT NOT NULL, version TEXT NOT NULL, package_hash TEXT NOT NULL, manifest_hash TEXT NOT NULL, entries_hash TEXT NOT NULL, requested_trust TEXT NOT NULL, resolved_trust TEXT NOT NULL, validation_summary_json TEXT NOT NULL, error_code TEXT NOT NULL, error_message TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, finished_at INTEGER); INSERT INTO plugin_install_stages VALUES('stage_legacy', 'install', 'staged', 'plugin_legacy', 'publisher', 'plugin', '1.0.0', 'p', 'm', 'e', '', '', '{}', '', '', 2, 1, 1, NULL)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(context.Background(), path); !errors.Is(err, sessionctx.ErrOwnerScopeMigrationRequired) {
		t.Fatalf("NewSQLiteStore() error = %v, want migration required", err)
	}
}

func TestSQLiteStoreRebuildsEmptyOwnerlessTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-empty.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE plugin_install_stages (stage_id TEXT PRIMARY KEY, action TEXT NOT NULL, status TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, publisher_id TEXT NOT NULL, plugin_id TEXT NOT NULL, version TEXT NOT NULL, package_hash TEXT NOT NULL, manifest_hash TEXT NOT NULL, entries_hash TEXT NOT NULL, requested_trust TEXT NOT NULL, resolved_trust TEXT NOT NULL, validation_summary_json TEXT NOT NULL, error_code TEXT NOT NULL, error_message TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, finished_at INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Create(installStageTestContext(), fixtureCreateRequest("stage_new", time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC))); err != nil {
		t.Fatal(err)
	}
}

type storeCase struct {
	name string
	open func(t *testing.T) Store
}

func storeCases() []storeCase {
	return []storeCase{
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
				store, err := NewSQLiteStore(installStageTestContext(), filepath.Join(t.TempDir(), "install-stage.sqlite"))
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

func fixtureCreateRequest(stageID string, now time.Time) CreateRequest {
	return CreateRequest{
		StageID:          stageID,
		Action:           ActionInstall,
		PluginInstanceID: "plugini_install",
		PublisherID:      "com.example",
		PluginID:         "com.example.install",
		Version:          "1.2.3",
		PackageHash:      "sha256:package",
		ManifestHash:     "sha256:manifest",
		EntriesHash:      "sha256:entries",
		RequestedTrust:   "verified",
		ValidationSummary: map[string]string{
			"package_read": "ok",
		},
		ExpiresAt: now.Add(time.Hour),
		Now:       now,
	}
}
