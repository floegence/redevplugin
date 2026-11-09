package observability

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteAuditReaderPagesRetainedEventsAfterRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.sqlite")
	store, err := NewSQLiteStore(ctx, path, MemoryStoreOptions{MaxAuditEvents: 3})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"other", "install", "other", "install"} {
		if err := store.AppendPluginAudit(ctx, AuditEvent{Type: kind, OccurredAt: time.Now(), Details: map[string]any{"status": "committed"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first, err := store.ListPluginAudits(ctx, ListAuditRequest{Type: "install", Limit: 1})
	if err != nil || len(first) != 1 || first[0].Sequence != 2 {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	first[0].Event.Details["status"] = "mutated"
	second, err := store.ListPluginAudits(ctx, ListAuditRequest{Type: "install", AfterSequence: first[0].Sequence, Limit: 1})
	if err != nil || len(second) != 1 || second[0].Sequence != 4 {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	all, err := store.ListPluginAudits(ctx, ListAuditRequest{})
	if err != nil || len(all) != 3 || all[0].Event.Details["status"] != "committed" {
		t.Fatalf("all=%#v err=%v", all, err)
	}
	for _, req := range []ListAuditRequest{{AfterSequence: -1}, {Limit: -1}, {Limit: 1001}, {Type: "\ninvalid"}} {
		if _, err := store.ListPluginAudits(ctx, req); err == nil {
			t.Fatalf("accepted invalid request: %#v", req)
		}
	}
}
