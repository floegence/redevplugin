package stream

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	_ "modernc.org/sqlite"
)

func TestMemoryStoreRegisterAppendReadAndClose(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record, err := store.Register(context.Background(), RegisterRequest{
		StreamID:         "stream_1",
		ExecutionBinding: streamTestBinding("plugini_1"),
		MaxBufferedBytes: 16,
		Now:              now,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if record.Direction != DirectionRead || record.Status != StatusOpen || record.MaxBufferedBytes != 16 {
		t.Fatalf("registered record mismatch: %#v", record)
	}
	if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_1", Data: []byte("hello"), Now: now.Add(time.Second)}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_1", Data: []byte("world"), Now: now.Add(2 * time.Second)}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_1", Data: []byte("0123456789"), Now: now.Add(3 * time.Second)}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("Append() error = %v, want ErrBackpressure", err)
	}
	peekedRecord, peeked, err := store.Peek(context.Background(), ReadRequest{StreamID: "stream_1", MaxEvents: 1})
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	if len(peeked) != 1 || string(peeked[0].Data) != "hello" || peekedRecord.BufferedBytes != 10 {
		t.Fatalf("Peek() mismatch: record=%#v events=%#v", peekedRecord, peeked)
	}
	record, events, err := store.Read(context.Background(), ReadRequest{StreamID: "stream_1", MaxEvents: 1})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(events) != 1 || string(events[0].Data) != "hello" || record.BufferedBytes != 5 {
		t.Fatalf("first read mismatch: record=%#v events=%#v", record, events)
	}
	record, events, err = store.Read(context.Background(), ReadRequest{StreamID: "stream_1"})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(events) != 1 || string(events[0].Data) != "world" || record.BufferedBytes != 0 {
		t.Fatalf("second read mismatch: record=%#v events=%#v", record, events)
	}
	closed, err := store.Close(context.Background(), CloseRequest{StreamID: "stream_1", Reason: "complete", Now: now.Add(4 * time.Second)})
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closed.Status != StatusClosed || closed.Reason != "complete" || closed.ClosedAt == nil {
		t.Fatalf("closed record mismatch: %#v", closed)
	}
	if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_1", Data: []byte("late")}); !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("Append() closed error = %v, want ErrStreamClosed", err)
	}
}

func TestMemoryStoreMarksPluginTransition(t *testing.T) {
	store := NewMemoryStore()
	for _, id := range []string{"stream_a", "stream_b"} {
		if _, err := store.Register(context.Background(), RegisterRequest{
			StreamID:         id,
			ExecutionBinding: streamTestBinding("plugini_1"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Register(context.Background(), RegisterRequest{
		StreamID:         "stream_other",
		ExecutionBinding: streamTestBinding("plugini_other"),
	}); err != nil {
		t.Fatal(err)
	}
	changed, err := store.MarkPluginTransition(context.Background(), PluginTransitionRequest{
		PluginInstanceID: "plugini_1",
		Status:           StatusOrphanedDisabled,
		Reason:           "policy",
	})
	if err != nil {
		t.Fatalf("MarkPluginTransition() error = %v", err)
	}
	if len(changed) != 2 || changed[0].Status != StatusOrphanedDisabled || changed[1].Status != StatusOrphanedDisabled || changed[0].Reason != "policy" {
		t.Fatalf("changed streams mismatch: %#v", changed)
	}
	other, err := store.Get(context.Background(), "stream_other")
	if err != nil {
		t.Fatal(err)
	}
	if other.Status != StatusOpen {
		t.Fatalf("other stream status = %s", other.Status)
	}
}

func TestMemoryStoreDeepClonesExecutionBindings(t *testing.T) {
	store := NewMemoryStore()
	binding := streamTestBinding("plugini_1")
	registered, err := store.Register(context.Background(), RegisterRequest{StreamID: "stream_clone", ExecutionBinding: binding})
	if err != nil {
		t.Fatal(err)
	}
	binding.Target.Fields["workspace_id"] = "mutated-input"
	registered.Target.Fields["workspace_id"] = "mutated-return"
	stored, err := store.Get(context.Background(), "stream_clone")
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.Target.Fields["workspace_id"]; got != "workspace-1" {
		t.Fatalf("stored target was mutated through a boundary: %#v", got)
	}
	stored.Target.Fields["workspace_id"] = "mutated-get"
	again, err := store.Get(context.Background(), "stream_clone")
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Target.Fields["workspace_id"]; got != "workspace-1" {
		t.Fatalf("Get() returned shared target state: %#v", got)
	}
}

func TestMemoryStoreDeepClonesAppendedEventData(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.Register(context.Background(), RegisterRequest{
		StreamID:         "stream_event_clone",
		ExecutionBinding: streamTestBinding("plugini_1"),
	}); err != nil {
		t.Fatal(err)
	}
	event, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_event_clone", Data: []byte("original")})
	if err != nil {
		t.Fatal(err)
	}
	event.Data[0] = 'X'
	_, events, err := store.Read(context.Background(), ReadRequest{StreamID: "stream_event_clone"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || string(events[0].Data) != "original" {
		t.Fatalf("stored stream event was mutated through Append(): %#v", events)
	}
}

func TestSQLiteStorePersistsStreamsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "streams.sqlite")
	now := time.Date(2026, 7, 2, 9, 0, 0, 0, time.UTC)

	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	record, err := store.Register(ctx, RegisterRequest{
		StreamID: "stream_sqlite_1",
		ExecutionBinding: streamTestBindingWith("plugini_sqlite", func(binding *capability.ExecutionBinding) {
			binding.PluginID = "com.example.streams"
			binding.SurfaceInstanceID = "surface_1"
			binding.OwnerSessionHash = "owner_session"
			binding.OwnerUserHash = "owner_user"
			binding.SessionChannelIDHash = "channel_hash"
			binding.BridgeChannelID = "bridge_channel"
		}),
		ContentType:      "text/plain",
		MaxBufferedBytes: 32,
		Now:              now,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if record.Status != StatusOpen || record.Direction != DirectionRead || record.MaxBufferedBytes != 32 {
		t.Fatalf("registered record mismatch: %#v", record)
	}
	if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_sqlite_1", Kind: "data", Data: []byte("alpha"), Now: now.Add(time.Second)}); err != nil {
		t.Fatalf("Append(alpha) error = %v", err)
	}
	if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_sqlite_1", Kind: "data", Data: []byte("beta"), Now: now.Add(2 * time.Second)}); err != nil {
		t.Fatalf("Append(beta) error = %v", err)
	}
	if err := store.CloseDatabase(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen NewSQLiteStore() error = %v", err)
	}
	defer func() {
		if err := reopened.CloseDatabase(); err != nil {
			t.Fatalf("Close(reopened) error = %v", err)
		}
	}()
	persisted, err := reopened.Get(ctx, "stream_sqlite_1")
	if err != nil {
		t.Fatalf("Get() after reopen error = %v", err)
	}
	if persisted.PluginInstanceID != "plugini_sqlite" ||
		persisted.SurfaceInstanceID != "surface_1" ||
		persisted.OwnerSessionHash != "owner_session" ||
		persisted.BufferedBytes != int64(len("alpha")+len("beta")) {
		t.Fatalf("persisted record mismatch: %#v", persisted)
	}
	peekedRecord, peeked, err := reopened.Peek(ctx, ReadRequest{StreamID: "stream_sqlite_1", MaxEvents: 1})
	if err != nil {
		t.Fatalf("Peek() after reopen error = %v", err)
	}
	if len(peeked) != 1 || string(peeked[0].Data) != "alpha" || peekedRecord.BufferedBytes != int64(len("alpha")+len("beta")) {
		t.Fatalf("Peek() after reopen mismatch: record=%#v events=%#v", peekedRecord, peeked)
	}
	persisted, events, err := reopened.Read(ctx, ReadRequest{StreamID: "stream_sqlite_1", MaxEvents: 1})
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(events) != 1 || events[0].Sequence != 1 || string(events[0].Data) != "alpha" || persisted.BufferedBytes != int64(len("beta")) {
		t.Fatalf("first read mismatch: record=%#v events=%#v", persisted, events)
	}
	persisted, events, err = reopened.Read(ctx, ReadRequest{StreamID: "stream_sqlite_1"})
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(events) != 1 || events[0].Sequence != 2 || string(events[0].Data) != "beta" || persisted.BufferedBytes != 0 {
		t.Fatalf("second read mismatch: record=%#v events=%#v", persisted, events)
	}
	if _, events, err := reopened.Read(ctx, ReadRequest{StreamID: "stream_sqlite_1"}); err != nil || len(events) != 0 {
		t.Fatalf("Read(empty) events=%#v err=%v, want no events", events, err)
	}
}

func TestSQLiteStoreMarksPluginTransition(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer func() {
		if err := store.CloseDatabase(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()
	for _, id := range []string{"stream_a", "stream_b"} {
		if _, err := store.Register(ctx, RegisterRequest{
			StreamID:         id,
			ExecutionBinding: streamTestBinding("plugini_1"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID:         "stream_other",
		ExecutionBinding: streamTestBinding("plugini_other"),
	}); err != nil {
		t.Fatal(err)
	}
	changed, err := store.MarkPluginTransition(ctx, PluginTransitionRequest{
		PluginInstanceID: "plugini_1",
		Status:           StatusOrphanedRemoved,
		Reason:           "uninstalled",
	})
	if err != nil {
		t.Fatalf("MarkPluginTransition() error = %v", err)
	}
	if len(changed) != 2 || changed[0].StreamID != "stream_a" || changed[1].StreamID != "stream_b" || changed[0].Reason != "uninstalled" {
		t.Fatalf("changed streams mismatch: %#v", changed)
	}
	for _, streamID := range []string{"stream_a", "stream_b"} {
		if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Data: []byte("late")}); !errors.Is(err, ErrStreamClosed) {
			t.Fatalf("Append(%s) after transition error = %v, want ErrStreamClosed", streamID, err)
		}
	}
	other, err := store.Get(ctx, "stream_other")
	if err != nil {
		t.Fatal(err)
	}
	if other.Status != StatusOpen {
		t.Fatalf("other stream status = %s", other.Status)
	}
}

func TestSQLiteStoreRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "streams.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE plugin_stream_schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO plugin_stream_schema_migrations(version, applied_at) VALUES(999, 1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = NewSQLiteStore(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("NewSQLiteStore() error = %v, want newer schema", err)
	}
}

func TestSQLiteStoreMigratesV1DataEventsAndIndexesIdempotently(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "streams-v1.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE plugin_stream_schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`,
		`INSERT INTO plugin_stream_schema_migrations(version, applied_at) VALUES(1, 1)`,
		`CREATE TABLE plugin_streams (
			stream_id TEXT PRIMARY KEY, plugin_id TEXT NOT NULL, plugin_instance_id TEXT NOT NULL,
			method TEXT NOT NULL, effect TEXT NOT NULL, execution TEXT NOT NULL, surface_instance_id TEXT NOT NULL,
			owner_session_hash TEXT NOT NULL, owner_user_hash TEXT NOT NULL, session_channel_id_hash TEXT NOT NULL,
			bridge_channel_id TEXT NOT NULL, direction TEXT NOT NULL, status TEXT NOT NULL, content_type TEXT NOT NULL,
			max_buffered_bytes INTEGER NOT NULL, buffered_bytes INTEGER NOT NULL, created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL, closed_at INTEGER
		)`,
		`CREATE TABLE plugin_stream_events (
			stream_id TEXT NOT NULL, sequence INTEGER NOT NULL, kind TEXT NOT NULL, data BLOB, error TEXT NOT NULL,
			at INTEGER NOT NULL, PRIMARY KEY(stream_id, sequence),
			FOREIGN KEY(stream_id) REFERENCES plugin_streams(stream_id) ON DELETE CASCADE
		)`,
		`INSERT INTO plugin_streams VALUES(
			'stream_v1', 'com.example.v1', 'plugini_v1', 'documents.watch', 'read', 'subscription', 'surface_v1',
			'session_v1', 'user_v1', 'channel_v1', 'bridge_v1', 'read', 'open', 'application/octet-stream',
			1024, 5, 100, 200, NULL
		)`,
		`INSERT INTO plugin_stream_events VALUES('stream_v1', 1, 'event', X'68656c6c6f', '', 150)`,
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
		record, events, err := store.Peek(ctx, ReadRequest{StreamID: "stream_v1", MaxEvents: 10, MaxBytes: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if record.PluginInstanceID != "plugini_v1" || record.Method != "documents.watch" || record.Reason != "" || len(events) != 1 || string(events[0].Data) != "hello" {
			t.Fatalf("migrated stream mismatch: record=%#v events=%#v", record, events)
		}
		for _, indexName := range []string{"idx_plugin_streams_plugin_instance", "idx_plugin_streams_status", "idx_plugin_stream_events_stream_sequence"} {
			table := "plugin_streams"
			if strings.Contains(indexName, "events") {
				table = "plugin_stream_events"
			}
			var count int
			if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND name = ?`, table, indexName).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("index %s count = %d, want 1", indexName, count)
			}
		}
		if err := store.CloseDatabase(); err != nil {
			t.Fatal(err)
		}
	}
}

func streamTestBinding(pluginInstanceID string) capability.ExecutionBinding {
	return streamTestBindingWith(pluginInstanceID, nil)
}

func streamTestBindingWith(pluginInstanceID string, mutate func(*capability.ExecutionBinding)) capability.ExecutionBinding {
	binding := capability.ExecutionBinding{
		InvocationID:           "invoke_test",
		AuditCorrelationID:     "audit_test",
		PublisherID:            "example.publisher",
		PluginID:               "com.example.documents",
		PluginInstanceID:       pluginInstanceID,
		PluginVersion:          "1.0.0",
		ActiveFingerprint:      "sha256:test",
		CapabilityID:           "example.capability.documents",
		CapabilityVersion:      "1.0.0",
		BindingID:              "documents",
		Method:                 "documents.watch",
		TargetMethod:           "documents.watch",
		Effect:                 capability.EffectRead,
		Execution:              "subscription",
		Target:                 capability.TargetDescriptor{Kind: "workspace", Fields: map[string]any{"workspace_id": "workspace-1"}},
		TargetDescriptorSHA256: "sha256:target",
	}
	if mutate != nil {
		mutate(&binding)
	}
	return binding
}
