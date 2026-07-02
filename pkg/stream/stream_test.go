package stream

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestMemoryStoreRegisterAppendReadAndClose(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record, err := store.Register(context.Background(), RegisterRequest{
		StreamID:         "stream_1",
		PluginID:         "com.example",
		PluginInstanceID: "plugini_1",
		Method:           "logs.tail",
		Execution:        "subscription",
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
	closed, err := store.Close(context.Background(), CloseRequest{StreamID: "stream_1", Now: now.Add(4 * time.Second)})
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if closed.Status != StatusClosed || closed.ClosedAt == nil {
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
			PluginInstanceID: "plugini_1",
			Method:           "logs.tail",
			Execution:        "subscription",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Register(context.Background(), RegisterRequest{
		StreamID:         "stream_other",
		PluginInstanceID: "plugini_other",
		Method:           "logs.tail",
		Execution:        "subscription",
	}); err != nil {
		t.Fatal(err)
	}
	changed, err := store.MarkPluginTransition(context.Background(), PluginTransitionRequest{
		PluginInstanceID: "plugini_1",
		Status:           StatusOrphanedDisabled,
	})
	if err != nil {
		t.Fatalf("MarkPluginTransition() error = %v", err)
	}
	if len(changed) != 2 || changed[0].Status != StatusOrphanedDisabled || changed[1].Status != StatusOrphanedDisabled {
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

func TestSQLiteStorePersistsStreamsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "streams.sqlite")
	now := time.Date(2026, 7, 2, 9, 0, 0, 0, time.UTC)

	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	record, err := store.Register(ctx, RegisterRequest{
		StreamID:             "stream_sqlite_1",
		PluginID:             "com.example.streams",
		PluginInstanceID:     "plugini_sqlite",
		Method:               "logs.tail",
		Effect:               "read",
		Execution:            "subscription",
		SurfaceInstanceID:    "surface_1",
		OwnerSessionHash:     "owner_session",
		OwnerUserHash:        "owner_user",
		SessionChannelIDHash: "channel_hash",
		BridgeChannelID:      "bridge_channel",
		ContentType:          "text/plain",
		MaxBufferedBytes:     32,
		Now:                  now,
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
			PluginInstanceID: "plugini_1",
			Method:           "logs.tail",
			Execution:        "subscription",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID:         "stream_other",
		PluginInstanceID: "plugini_other",
		Method:           "logs.tail",
		Execution:        "subscription",
	}); err != nil {
		t.Fatal(err)
	}
	changed, err := store.MarkPluginTransition(ctx, PluginTransitionRequest{
		PluginInstanceID: "plugini_1",
		Status:           StatusOrphanedRemoved,
	})
	if err != nil {
		t.Fatalf("MarkPluginTransition() error = %v", err)
	}
	if len(changed) != 2 || changed[0].StreamID != "stream_a" || changed[1].StreamID != "stream_b" {
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
