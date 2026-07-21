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
	expired.Lease.ExpiresAtUnixMillis = now.Add(time.Minute).UnixMilli()
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

func runtimeLeaseReplayTestNow() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

func runtimeLeaseReplayTestLease(now time.Time) Lease {
	return Lease{
		LeaseID:             "rel_1",
		LeaseNonce:          "nonce_1",
		RuntimeGenerationID: "runtime_gen_1",
		PluginInstanceID:    "plugini_1",
		Method:              "worker.echo",
		PolicyRevision:      11,
		ManagementRevision:  12,
		RevokeEpoch:         13,
		ExpiresAtUnixMillis: now.Add(time.Minute).UnixMilli(),
	}
}
