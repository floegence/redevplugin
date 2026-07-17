package installstage

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStoreCreatePrepareCommitAndDelete(t *testing.T) {
	for _, tc := range storeCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
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
			ctx := context.Background()
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
			if _, err := store.Create(context.Background(), CreateRequest{}); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("Create() error = %v, want ErrInvalidStage", err)
			}
			now := time.Date(2026, 7, 2, 14, 0, 0, 0, time.UTC)
			req := fixtureCreateRequest("stage_invalid", now)
			req.ExpiresAt = now
			if _, err := store.Create(context.Background(), req); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("Create(expired) error = %v, want ErrInvalidStage", err)
			}
			if _, err := store.Get(context.Background(), " "); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("Get() error = %v, want ErrInvalidStage", err)
			}
			if _, err := store.MarkCommitted(context.Background(), MarkCommittedRequest{}); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("MarkCommitted() error = %v, want ErrInvalidStage", err)
			}
			if _, err := store.List(context.Background(), ListRequest{Status: "bad"}); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("List() error = %v, want ErrInvalidStage", err)
			}
			if err := store.Delete(context.Background(), " "); !errors.Is(err, ErrInvalidStage) {
				t.Fatalf("Delete() error = %v, want ErrInvalidStage", err)
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
	ctx := context.Background()
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
				store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "install-stage.sqlite"))
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
