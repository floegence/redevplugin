package stream

import (
	"context"
	"errors"
	"testing"
	"time"
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
