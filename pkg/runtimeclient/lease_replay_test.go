package runtimeclient

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMemoryRuntimeLeaseReplayStoreRejectsDuplicateUntilExpiry(t *testing.T) {
	store := NewMemoryRuntimeLeaseReplayStore()
	now := runtimeLeaseReplayTestNow()
	req := RuntimeLeaseReplayConsumeRequest{
		Lease:  runtimeLeaseReplayTestLease(now),
		Method: "worker.echo",
		Now:    now,
	}
	record, err := store.ConsumeRuntimeLease(context.Background(), req)
	if err != nil {
		t.Fatalf("ConsumeRuntimeLease() error = %v", err)
	}
	if record.LeaseNonceHash == "" || !strings.HasPrefix(record.LeaseNonceHash, "sha256:") {
		t.Fatalf("LeaseNonceHash = %q", record.LeaseNonceHash)
	}
	if strings.Contains(record.LeaseNonceHash, req.Lease.LeaseNonce) {
		t.Fatal("lease nonce hash exposes the clear lease nonce")
	}

	if _, err := store.ConsumeRuntimeLease(context.Background(), req); !errors.Is(err, ErrRuntimeLeaseReplay) {
		t.Fatalf("ConsumeRuntimeLease() replay error = %v, want %v", err, ErrRuntimeLeaseReplay)
	}

	expired := req
	expired.Now = now.Add(2 * time.Minute)
	expired.Lease.LeaseID = "rel_expired"
	expired.Lease.LeaseNonce = "nonce_expired"
	expired.Lease.ExpiresAt = now.Add(time.Minute)
	if _, err := store.ConsumeRuntimeLease(context.Background(), expired); !errors.Is(err, ErrRuntimeLeaseInvalid) {
		t.Fatalf("ConsumeRuntimeLease() expired error = %v, want %v", err, ErrRuntimeLeaseInvalid)
	}

	records, err := store.ListRuntimeLeaseReplays(context.Background(), RuntimeLeaseReplayListRequest{PluginInstanceID: "plugini_1"})
	if err != nil {
		t.Fatalf("ListRuntimeLeaseReplays() error = %v", err)
	}
	if len(records) != 1 || records[0].LeaseID != "rel_1" {
		t.Fatalf("records = %#v", records)
	}
}

func TestSQLiteRuntimeLeaseReplayStorePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "runtime-lease-replays.sqlite")
	now := runtimeLeaseReplayTestNow()
	store, err := NewSQLiteRuntimeLeaseReplayStore(ctx, path)
	if err != nil {
		t.Fatalf("NewSQLiteRuntimeLeaseReplayStore() error = %v", err)
	}
	req := RuntimeLeaseReplayConsumeRequest{
		Lease:  runtimeLeaseReplayTestLease(now),
		Method: "worker.echo",
		Now:    now,
	}
	if _, err := store.ConsumeRuntimeLease(ctx, req); err != nil {
		t.Fatalf("ConsumeRuntimeLease() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewSQLiteRuntimeLeaseReplayStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen NewSQLiteRuntimeLeaseReplayStore() error = %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.ConsumeRuntimeLease(ctx, req); !errors.Is(err, ErrRuntimeLeaseReplay) {
		t.Fatalf("ConsumeRuntimeLease() replay after reopen error = %v, want %v", err, ErrRuntimeLeaseReplay)
	}

	next := req
	next.Lease.LeaseID = "rel_2"
	next.Lease.LeaseNonce = "nonce_2"
	next.Now = now.Add(2 * time.Second)
	if _, err := reopened.ConsumeRuntimeLease(ctx, next); err != nil {
		t.Fatalf("ConsumeRuntimeLease(next) error = %v", err)
	}
	records, err := reopened.ListRuntimeLeaseReplays(ctx, RuntimeLeaseReplayListRequest{PluginInstanceID: "plugini_1"})
	if err != nil {
		t.Fatalf("ListRuntimeLeaseReplays() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %#v", records)
	}
}

func TestSQLiteRuntimeLeaseReplayStoreFailsClosedOnNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "runtime-lease-replays.sqlite")
	store, err := NewSQLiteRuntimeLeaseReplayStore(ctx, path)
	if err != nil {
		t.Fatalf("NewSQLiteRuntimeLeaseReplayStore() error = %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO plugin_runtime_lease_replay_schema_migrations(version, applied_at) VALUES (?, ?)`, sqliteRuntimeLeaseReplaySchemaVersion+1, runtimeLeaseReplayTestNow().UnixNano()); err != nil {
		t.Fatalf("insert newer schema marker: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := NewSQLiteRuntimeLeaseReplayStore(ctx, path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("NewSQLiteRuntimeLeaseReplayStore(newer schema) error = %v", err)
	}
}

func runtimeLeaseReplayTestNow() time.Time {
	return time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
}

func runtimeLeaseReplayTestLease(now time.Time) Lease {
	return Lease{
		LeaseID:             "rel_1",
		LeaseToken:          "runtime_execution_lease.rel_1.secret",
		LeaseNonce:          "nonce_1",
		RuntimeGenerationID: "runtime_gen_1",
		PluginInstanceID:    "plugini_1",
		Method:              "worker.echo",
		PolicyRevision:      11,
		ManagementRevision:  12,
		RevokeEpoch:         13,
		ExpiresAt:           now.Add(time.Minute),
	}
}
